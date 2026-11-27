//! Overlays (bundles.md §6): what a shard's deltas change on top of its immutable base.
//!
//! - [`HashOverlay`]: an immutable open-addressing table keyed by the 128-bit key hash →
//!   `Upsert(value) | Tombstone`, for hot and cold domain shards and verdict sets. A tombstone
//!   skips the base; an upsert gives the value.
//! - [`RangeOverlay`]: a sorted, disjoint range table → `Upsert(value) | Tombstone`, for IP shards.
//!
//! Both are rebuilt (never mutated) when deltas touch the shard, and swapped in. Applying a delta
//! updates the set checksum in O(delta) from the current values (overlay, else base) and checks it
//! against the delta's header after every delta; a mismatch is [`OverlayError::Checksum`]: discard
//! the overlay and request the shard's base (bundles.md §5).
//!
//! **CPU** (README §2 "Bounded"; review round 1, B7). Deltas are staged ([`KeyStage`],
//! [`RangeStage`]) and the overlay is rebuilt once at the end, however many deltas were staged: a
//! boot replay or an activation that applies a shard's remaining chain costs O(ops + overlay), not
//! O(deltas × overlay). Range ops paint an interval map (O(log n) each) that one merge pass lays
//! over the previous table. Slots are picked from a keyed mix of the hash with a per-table random
//! key, so hashes a delta supplies directly (verdict sets) or crafts (keys chosen for colliding
//! low bits) can't pile up in one probe run.
//!
//! **Memory** (edge.md §17; B8). A [`HashOverlay<u64>`] slot is 24 bytes (the hash's low half,
//! its keyed mix, and the value, with the empty and tombstone markers in the value's reserved bits)
//! and the table is at most 80 % full: about [`KEY_OVERLAY_BYTES_PER_ENTRY`] (30) bytes per entry,
//! bundles.md §6's figure, which core uses to keep `overlay_budget_mib`. IPv4 range entries are 16
//! bytes, IPv6 ones 48. [`HashOverlay::memory_usage`] reports what the table holds (its slots by
//! capacity, plus the values' own heap for verdict records).
//!
//! **Misses** (review round 2, CR5). Every query probes the overlay of each hot shard for each
//! suffix of its name, and nearly all of those probes miss. Plain linear probing at 80 % load scans
//! ~13 slots (~5 cache lines) per miss. The table uses Robin Hood placement instead: each run is
//! ordered by home slot, so a lookup stops as soon as it reaches an entry closer to its own home
//! than the lookup is to the query's (or an empty slot), ~3 slots per miss at the same load. A slot
//! stores the keyed mix of the hash in place of its high half (the mix is invertible given the low
//! half, so nothing is lost), so an entry's home is one multiply away and the per-entry figure
//! stays 30 bytes. Measured (x86, release, random 128-bit hashes, 80 % load), linear probing →
//! Robin Hood: a miss 28 → 17 ns at 1 k entries, 58 → 22 ns at 50 k, 258 → 64 ns at 500 k,
//! 318 → 96 ns at 1 M (3.4 slots read per miss); hits 20 → 20, 100 → 35, 188 → 155, 219 → 155 ns;
//! the longest probe run at 1 M, 218 → 30.

use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hasher};

use crate::checksum::SetChecksum;
use crate::delta::{KeyOp, RangeOp};
use crate::hash::KeyHash;
use crate::page::PageError;
use crate::value::Value;

/// One overlay entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry<V> {
    Upsert(V),
    Tombstone,
}

/// Why a delta can't be applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OverlayError {
    /// The set checksum after the delta isn't the header's: discard the overlay and request the
    /// shard's base.
    #[error("set checksum mismatch after delta {seq} (need base)")]
    Checksum { seq: u64 },
    /// The delta's `prev_checksum` isn't the shard's current checksum (a gap in the chain).
    #[error("delta {seq} doesn't continue the chain (need base)")]
    Chain { seq: u64 },
    /// Reading the base for a current value failed (a cold page): the page error says whether the
    /// page file must be deleted and fetched again (bundles.md §4 "Reading").
    #[error("reading the base failed: {0}")]
    Base(PageError),
    /// The overlay would exceed its entry limit.
    #[error("overlay over {0} entries")]
    TooLarge(usize),
}

/// Most entries one overlay may hold: 1 Mi entries, about 30 MiB for a key overlay, twice the
/// largest default `overlay_budget_mib` (16, on UniFi; edge.md §17). A safety bound against a
/// crafted chain: core keeps each edge's total far lower by compaction (bundles.md §5).
pub const MAX_OVERLAY_ENTRIES: usize = 1 << 20;

/// Bytes per entry of a key overlay ([`HashOverlay<u64>`]): a 24-byte slot at ≤ 80 % load. Core
/// sizes overlays with this figure (bundles.md §6 "~30 B/entry").
pub const KEY_OVERLAY_BYTES_PER_ENTRY: usize = 30;

/// A value an overlay slot holds, with room for the empty and tombstone markers.
pub trait OverlayValue: Sized {
    /// What a slot stores.
    type Slot: Clone;
    /// An empty slot.
    fn empty() -> Self::Slot;
    fn is_empty(s: &Self::Slot) -> bool;
    fn pack(e: Entry<Self>) -> Self::Slot;
    /// The entry in an occupied slot.
    fn unpack(s: &Self::Slot) -> Entry<&Self>;
    /// Heap bytes the slot's value owns.
    fn heap(_s: &Self::Slot) -> usize {
        0
    }
}

const SLOT_EMPTY: u64 = u64::MAX;
const SLOT_TOMBSTONE: u64 = u64::MAX - 1;

/// Key values: the stored value's reserved top bits (never set, [`Value::DEFINED`]) leave room for
/// the two markers, so a slot is three `u64`s.
impl OverlayValue for u64 {
    type Slot = u64;
    fn empty() -> u64 {
        SLOT_EMPTY
    }
    fn is_empty(s: &u64) -> bool {
        *s == SLOT_EMPTY
    }
    fn pack(e: Entry<u64>) -> u64 {
        match e {
            Entry::Upsert(v) => v & Value::DEFINED,
            Entry::Tombstone => SLOT_TOMBSTONE,
        }
    }
    fn unpack(s: &u64) -> Entry<&u64> {
        if *s == SLOT_TOMBSTONE {
            Entry::Tombstone
        } else {
            Entry::Upsert(s)
        }
    }
}

/// One slot: the hash's low half, the keyed mix of the whole hash ([`mix`], which picks the home
/// slot and, with `lo`, gives back the high half: [`unmix_hi`]), and the stored value. Two `u64`s,
/// so the slot aligns to 8, not 16.
#[derive(Clone, Debug)]
struct Slot<S> {
    lo: u64,
    m: u64,
    s: S,
}

/// Two random 64-bit keys for a table's slot mix (std's per-process random SipHash keys; no new
/// dependency, no `unsafe`).
fn random_keys() -> (u64, u64) {
    let rs = std::collections::hash_map::RandomState::new();
    let mut a = rs.build_hasher();
    a.write_u64(0x6f76_6572_6c61_7931);
    let mut b = rs.build_hasher();
    b.write_u64(0x6f76_6572_6c61_7932);
    (a.finish(), b.finish())
}

const MIX_A: u64 = 0xbf58_476d_1ce4_e5b9;
const MIX_B: u64 = 0x94d0_49bb_1331_11eb;

/// splitmix64's finaliser (a bijection on `u64`).
fn fold(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(MIX_A);
    z = (z ^ (z >> 27)).wrapping_mul(MIX_B);
    z ^ (z >> 31)
}

/// The inverse of `x ^ (x >> s)`.
fn unxorshift(y: u64, s: u32) -> u64 {
    let mut x = y;
    let mut t = y >> s;
    while t != 0 {
        x ^= t;
        t >>= s;
    }
    x
}

/// The inverse of an odd number modulo 2^64 (Newton's iteration: 3, 6, 12, … correct bits).
const fn inverse(c: u64) -> u64 {
    const fn step(c: u64, x: u64) -> u64 {
        x.wrapping_mul(2u64.wrapping_sub(c.wrapping_mul(x)))
    }
    step(c, step(c, step(c, step(c, step(c, c)))))
}

const INV_A: u64 = inverse(MIX_A);
const INV_B: u64 = inverse(MIX_B);

/// The inverse of [`fold`].
fn unfold(z: u64) -> u64 {
    let z = unxorshift(z, 31).wrapping_mul(INV_B);
    let z = unxorshift(z, 27).wrapping_mul(INV_A);
    unxorshift(z, 30)
}

/// A keyed mix of a 128-bit hash (splitmix64's finaliser over both halves, each xored with a key).
fn mix(h: u128, k: (u64, u64)) -> u64 {
    let (lo, hi) = crate::hash::halves(h);
    fold(fold(lo ^ k.0).wrapping_add(hi ^ k.1))
}

/// The high half of the hash whose low half is `lo` and whose [`mix`] is `m`.
fn unmix_hi(lo: u64, m: u64, k: (u64, u64)) -> u64 {
    unfold(m).wrapping_sub(fold(lo ^ k.0)) ^ k.1
}

/// An immutable open-addressing table keyed by 128-bit hash.
#[derive(Clone, Debug)]
pub struct HashOverlay<V: OverlayValue> {
    slots: Vec<Slot<V::Slot>>,
    keys: (u64, u64),
    len: usize,
    heap: usize,
}

impl<V: OverlayValue> Default for HashOverlay<V> {
    fn default() -> Self {
        HashOverlay {
            slots: Vec::new(),
            keys: (0, 0),
            len: 0,
            heap: 0,
        }
    }
}

impl<V: OverlayValue + Clone> HashOverlay<V> {
    /// An empty overlay.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a table from entries (later duplicates win).
    pub fn from_entries(entries: impl IntoIterator<Item = (u128, Entry<V>)>) -> Result<Self, OverlayError> {
        let mut map: HashMap<u128, Entry<V>> = HashMap::new();
        for (h, e) in entries {
            map.insert(h, e);
            if map.len() > MAX_OVERLAY_ENTRIES {
                return Err(OverlayError::TooLarge(MAX_OVERLAY_ENTRIES));
            }
        }
        Ok(Self::from_map(map))
    }

    /// The home slot of an entry whose mix is `m`.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "(m x len) >> 64 is below len, a usize"
    )]
    fn home(&self, m: u64) -> usize {
        // A u64 times a usize fits in a u128.
        (u128::from(m).wrapping_mul(self.slots.len() as u128) >> 64) as usize
    }

    /// How far slot `i` is past home slot `home` (wrapping).
    fn distance(&self, home: usize, i: usize) -> usize {
        if i >= home {
            i.saturating_sub(home)
        } else {
            self.slots.len().saturating_sub(home).saturating_add(i)
        }
    }

    fn next(&self, i: usize) -> usize {
        if i.saturating_add(1) >= self.slots.len() {
            0
        } else {
            i.saturating_add(1)
        }
    }

    fn from_map(map: HashMap<u128, Entry<V>>) -> Self {
        if map.is_empty() {
            return Self::default();
        }
        let len = map.len();
        // At most 80 % full.
        let cap = len.saturating_add(len / 4).saturating_add(1).max(8);
        let mut t = HashOverlay {
            slots: vec![
                Slot {
                    lo: 0,
                    m: 0,
                    s: V::empty(),
                };
                cap
            ],
            keys: random_keys(),
            len,
            heap: 0,
        };
        let mut heap = 0usize;
        for (h, e) in map {
            let s = V::pack(e);
            heap = heap.saturating_add(V::heap(&s));
            // Robin Hood placement: walk from home; an entry closer to its home than the one being
            // placed is to its own gives up its slot and is placed further on.
            let mut cur = Slot {
                lo: crate::hash::halves(h).0,
                m: mix(h, t.keys),
                s,
            };
            let mut i = t.home(cur.m);
            let mut d = 0usize;
            for _ in 0..=cap {
                let resident = match t.slots.get(i) {
                    Some(slot) if V::is_empty(&slot.s) => None,
                    Some(slot) => Some(t.distance(t.home(slot.m), i)),
                    None => break,
                };
                match resident {
                    None => {
                        if let Some(slot) = t.slots.get_mut(i) {
                            *slot = cur;
                        }
                        break;
                    }
                    Some(rd) if rd < d => {
                        if let Some(slot) = t.slots.get_mut(i) {
                            std::mem::swap(slot, &mut cur);
                        }
                        d = rd;
                    }
                    Some(_) => {}
                }
                i = t.next(i);
                d = d.saturating_add(1);
            }
        }
        t.heap = heap;
        t
    }

    /// The entry for a hash. A miss stops at an empty slot or at the first entry closer to its
    /// home than the probe is to the hash's (Robin Hood order): ~3.4 slots at 80 % load where
    /// linear probing scanned ~13 (measurements in the module docs; review round 2, CR5).
    pub fn get(&self, h: u128) -> Option<Entry<&V>> {
        if self.len == 0 {
            return None;
        }
        let lo = crate::hash::halves(h).0;
        let m = mix(h, self.keys);
        let mut i = self.home(m);
        // At most 80 % full, so a probe always ends early or at an empty slot.
        for d in 0..self.slots.len() {
            let slot = self.slots.get(i)?;
            if V::is_empty(&slot.s) {
                return None;
            }
            if slot.m == m && slot.lo == lo {
                return Some(V::unpack(&slot.s));
            }
            if self.distance(self.home(slot.m), i) < d {
                return None;
            }
            i = self.next(i);
        }
        None
    }

    /// Entries held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Every entry.
    pub fn iter(&self) -> impl Iterator<Item = (u128, Entry<&V>)> {
        let k = self.keys;
        self.slots.iter().filter(|s| !V::is_empty(&s.s)).map(move |s| {
            let hi = unmix_hi(s.lo, s.m, k);
            ((u128::from(hi) << 64) | u128::from(s.lo), V::unpack(&s.s))
        })
    }

    /// Bytes held: the slots (by capacity) and the values' own heap.
    pub fn memory_usage(&self) -> usize {
        self.slots
            .capacity()
            .saturating_mul(std::mem::size_of::<Slot<V::Slot>>())
            .saturating_add(self.heap)
    }

    /// The longest probe run a hit can take (tests: a keyed mix keeps it short).
    pub fn longest_probe(&self) -> usize {
        let mut longest = 0usize;
        for (i, s) in self.slots.iter().enumerate() {
            if V::is_empty(&s.s) {
                continue;
            }
            let d = self.distance(self.home(s.m), i);
            longest = longest.max(d.saturating_add(1));
        }
        longest
    }

    /// The mean number of slots a miss reads, over every home slot (tests and measurements:
    /// review round 2, CR5).
    pub fn mean_miss_probes(&self) -> f64 {
        let cap = self.slots.len();
        if self.len == 0 || cap == 0 {
            return 0.0;
        }
        let mut total = 0usize;
        for home in 0..cap {
            let mut i = home;
            let mut n = 0usize;
            for d in 0..cap {
                n = n.saturating_add(1);
                match self.slots.get(i) {
                    Some(s) if !V::is_empty(&s.s) && self.distance(self.home(s.m), i) >= d => {}
                    _ => break,
                }
                i = self.next(i);
            }
            total = total.saturating_add(n);
        }
        total as f64 / cap as f64
    }

    /// A copy with `changes` applied (later changes win): one rebuild.
    pub fn with_changes(
        &self,
        changes: impl IntoIterator<Item = (u128, Entry<V>)>,
    ) -> Result<Self, OverlayError> {
        let mut map: HashMap<u128, Entry<V>> = HashMap::with_capacity(self.len);
        for (h, e) in self.iter() {
            let e = match e {
                Entry::Upsert(v) => Entry::Upsert(v.clone()),
                Entry::Tombstone => Entry::Tombstone,
            };
            map.insert(h, e);
        }
        for (h, e) in changes {
            map.insert(h, e);
            if map.len() > MAX_OVERLAY_ENTRIES {
                return Err(OverlayError::TooLarge(MAX_OVERLAY_ENTRIES));
            }
        }
        Ok(Self::from_map(map))
    }
}

/// Which ops of a delta to apply: all (hot), or a cold delta's upserts and deletes as two
/// separate steps (bundles.md §2 "Moves", §6 "Activation").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Every op; check `new_checksum`.
    All,
    /// The upserts only; check `mid_checksum`.
    Upserts,
    /// The deletes only (after [`Phase::Upserts`]); check `new_checksum`.
    Deletes,
}

/// Reads a key's base value (`None` when the base lacks it); an error is a failed page read.
pub type BaseLookup<'a> = &'a mut dyn FnMut(&[u8], KeyHash) -> Result<Option<Value>, PageError>;

/// Key deltas staged on top of an overlay: each delta's checksums are checked as it is staged,
/// and [`KeyStage::finish`] rebuilds the overlay once.
pub struct KeyStage<'a> {
    overlay: &'a HashOverlay<u64>,
    hash_seed: u64,
    checksum: SetChecksum,
    changes: HashMap<u128, Entry<u64>>,
}

impl<'a> KeyStage<'a> {
    /// Starts from an overlay and the checksum it stands at.
    pub fn new(overlay: &'a HashOverlay<u64>, hash_seed: u64, checksum: SetChecksum) -> Self {
        KeyStage {
            overlay,
            hash_seed,
            checksum,
            changes: HashMap::new(),
        }
    }

    /// The checksum after the deltas staged so far.
    pub fn checksum(&self) -> SetChecksum {
        self.checksum
    }

    /// Stages one delta's ops for `phase`. `prev` / `expect` are the checksums the header says hold
    /// before and after.
    pub fn apply(
        &mut self,
        ops: &[KeyOp],
        phase: Phase,
        seq: u64,
        prev: SetChecksum,
        expect: SetChecksum,
        base: BaseLookup<'_>,
    ) -> Result<(), OverlayError> {
        if self.checksum != prev {
            return Err(OverlayError::Chain { seq });
        }
        let mut cs = self.checksum;
        for op in ops {
            let is_upsert = matches!(op, KeyOp::Upsert { .. });
            match phase {
                Phase::Upserts if !is_upsert => continue,
                Phase::Deletes if is_upsert => continue,
                _ => {}
            }
            let key = op.key();
            let h = KeyHash::of(self.hash_seed, key);
            let current = match self.changes.get(&h.0) {
                Some(Entry::Upsert(v)) => Some(Value(*v)),
                Some(Entry::Tombstone) => None,
                None => match self.overlay.get(h.0) {
                    Some(Entry::Upsert(v)) => Some(Value(*v)),
                    Some(Entry::Tombstone) => None,
                    None => base(key, h).map_err(OverlayError::Base)?,
                },
            };
            if let Some(old) = current {
                cs = cs.sub_domain(key, old.0);
            }
            match op {
                KeyOp::Upsert { value, .. } => {
                    cs = cs.add_domain(key, value.0);
                    self.changes.insert(h.0, Entry::Upsert(value.0));
                }
                KeyOp::Delete { .. } => {
                    self.changes.insert(h.0, Entry::Tombstone);
                }
            }
            if self.changes.len() > MAX_OVERLAY_ENTRIES {
                return Err(OverlayError::TooLarge(MAX_OVERLAY_ENTRIES));
            }
        }
        if cs != expect {
            return Err(OverlayError::Checksum { seq });
        }
        self.checksum = cs;
        Ok(())
    }

    /// The overlay with every staged delta applied (one rebuild), and its checksum.
    pub fn finish(self) -> Result<(HashOverlay<u64>, SetChecksum), OverlayError> {
        if self.changes.is_empty() {
            return Ok((self.overlay.clone(), self.checksum));
        }
        Ok((self.overlay.with_changes(self.changes)?, self.checksum))
    }
}

/// The state a key delta applies to: the overlay, the checksum, and how to read a key's base
/// value (`None` when the base lacks it).
pub struct KeyState<'a> {
    pub overlay: &'a HashOverlay<u64>,
    pub checksum: SetChecksum,
    pub hash_seed: u64,
    pub base: BaseLookup<'a>,
}

/// Applies one domain or cold delta's ops for `phase` ([`KeyStage`] for one delta).
pub fn apply_key_ops(
    st: KeyState<'_>,
    ops: &[KeyOp],
    phase: Phase,
    seq: u64,
    prev: SetChecksum,
    expect: SetChecksum,
) -> Result<(HashOverlay<u64>, SetChecksum), OverlayError> {
    let mut stage = KeyStage::new(st.overlay, st.hash_seed, st.checksum);
    stage.apply(ops, phase, seq, prev, expect, st.base)?;
    stage.finish()
}

/// An address type for range tables (`u32` for IPv4, `u128` for IPv6).
pub trait Addr: Copy + Ord + std::fmt::Debug {
    fn from_u128(a: u128) -> Self;
    fn to_u128(self) -> u128;
}

impl Addr for u32 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "an IPv4 shard's addresses are below 2^32 by construction"
    )]
    fn from_u128(a: u128) -> Self {
        a as u32
    }
    fn to_u128(self) -> u128 {
        u128::from(self)
    }
}

impl Addr for u128 {
    fn from_u128(a: u128) -> Self {
        a
    }
    fn to_u128(self) -> u128 {
        self
    }
}

fn unpack_range(v: u64) -> Entry<u64> {
    if v == SLOT_TOMBSTONE {
        Entry::Tombstone
    } else {
        Entry::Upsert(v)
    }
}

/// A sorted, disjoint range table → `Upsert(value) | Tombstone` (the value packed as for key
/// overlays).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeOverlay<A> {
    entries: Vec<(A, A, u64)>,
}

impl<A> Default for RangeOverlay<A> {
    fn default() -> Self {
        RangeOverlay { entries: Vec::new() }
    }
}

impl<A: Addr> RangeOverlay<A> {
    pub fn new() -> Self {
        Self::default()
    }

    /// The entry covering `a`.
    pub fn get(&self, a: A) -> Option<Entry<u64>> {
        let i = self.entries.partition_point(|(f, _, _)| *f <= a);
        let (_, l, v) = self.entries.get(i.checked_sub(1)?)?;
        (a <= *l).then(|| unpack_range(*v))
    }

    /// Entries held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes held (by capacity).
    pub fn memory_usage(&self) -> usize {
        self.entries
            .capacity()
            .saturating_mul(std::mem::size_of::<(A, A, u64)>())
    }

    /// Every entry, in address order.
    pub fn entries(&self) -> impl Iterator<Item = (A, A, Entry<u64>)> + '_ {
        self.entries.iter().map(|&(a, b, v)| (a, b, unpack_range(v)))
    }
}

/// The base's value at an address.
pub type RangeBase<'a, A> = &'a dyn Fn(A) -> Option<Value>;

/// IP deltas staged on top of a range overlay: ops paint an interval map; [`RangeStage::finish`]
/// lays it over the previous table in one merge pass.
pub struct RangeStage<'a, A> {
    overlay: &'a RangeOverlay<A>,
    v4: bool,
    checksum: SetChecksum,
    /// First address → (last address, packed value); disjoint.
    staged: BTreeMap<A, (A, u64)>,
}

impl<'a, A: Addr> RangeStage<'a, A> {
    pub fn new(overlay: &'a RangeOverlay<A>, v4: bool, checksum: SetChecksum) -> Self {
        RangeStage {
            overlay,
            v4,
            checksum,
            staged: BTreeMap::new(),
        }
    }

    /// The checksum after the deltas staged so far.
    pub fn checksum(&self) -> SetChecksum {
        self.checksum
    }

    fn current(&self, a: A, base: RangeBase<'_, A>) -> Option<Value> {
        if let Some((_, &(l, v))) = self.staged.range(..=a).next_back()
            && a <= l
        {
            return match unpack_range(v) {
                Entry::Upsert(v) => Some(Value(v)),
                Entry::Tombstone => None,
            };
        }
        match self.overlay.get(a) {
            Some(Entry::Upsert(v)) => Some(Value(v)),
            Some(Entry::Tombstone) => None,
            None => base(a),
        }
    }

    /// Sets `first..=last` to `v`, cutting the staged intervals it overlaps.
    fn paint(&mut self, first: A, last: A, v: u64) {
        let (f, l) = (first.to_u128(), last.to_u128());
        // An interval starting before `first` that reaches into it.
        if let Some((&s, &(e, ev))) = self.staged.range(..first).next_back()
            && e.to_u128() >= f
        {
            self.staged.insert(s, (A::from_u128(f.saturating_sub(1)), ev));
            if e.to_u128() > l {
                self.staged.insert(A::from_u128(l.saturating_add(1)), (e, ev));
            }
        }
        // Intervals starting inside: removed, keeping the part past `last`.
        let inside: Vec<A> = self.staged.range(first..=last).map(|(k, _)| *k).collect();
        for k in inside {
            if let Some((e, ev)) = self.staged.remove(&k)
                && e.to_u128() > l
            {
                self.staged.insert(A::from_u128(l.saturating_add(1)), (e, ev));
            }
        }
        self.staged.insert(first, (last, v));
    }

    /// Stages one IP delta: its deletes (each run's value read from the current state), then its
    /// upserts. `prev` / `expect` are the header's checksums.
    pub fn apply(
        &mut self,
        ops: &[RangeOp],
        seq: u64,
        prev: SetChecksum,
        expect: SetChecksum,
        base: RangeBase<'_, A>,
    ) -> Result<(), OverlayError> {
        if self.checksum != prev {
            return Err(OverlayError::Chain { seq });
        }
        let mut cs = self.checksum;
        for op in ops {
            if let RangeOp::Delete { first, last } = *op {
                let (f, l) = (A::from_u128(first), A::from_u128(last));
                if let Some(old) = self.current(f, base) {
                    cs = cs.minus(SetChecksum::ip_entry(self.v4, first, last, old.0));
                }
                self.paint(f, l, SLOT_TOMBSTONE);
            }
        }
        for op in ops {
            if let RangeOp::Upsert { first, last, value } = *op {
                cs = cs.plus(SetChecksum::ip_entry(self.v4, first, last, value.0));
                self.paint(A::from_u128(first), A::from_u128(last), value.0 & Value::DEFINED);
            }
        }
        if self.staged.len() > MAX_OVERLAY_ENTRIES {
            return Err(OverlayError::TooLarge(MAX_OVERLAY_ENTRIES));
        }
        if cs != expect {
            return Err(OverlayError::Checksum { seq });
        }
        self.checksum = cs;
        Ok(())
    }

    /// The overlay with every staged delta laid over the previous one (one pass), and its
    /// checksum.
    pub fn finish(self) -> Result<(RangeOverlay<A>, SetChecksum), OverlayError> {
        let staged: Vec<(A, A, u64)> = self.staged.into_iter().map(|(f, (l, v))| (f, l, v)).collect();
        // The previous entries minus the staged intervals.
        let mut pieces: Vec<(A, A, u64)> = Vec::with_capacity(self.overlay.entries.len());
        let mut j = 0usize;
        for &(a, b, v) in &self.overlay.entries {
            let (mut s, e) = (a.to_u128(), b.to_u128());
            while staged.get(j).is_some_and(|x| x.1.to_u128() < s) {
                j = j.saturating_add(1);
            }
            let mut k = j;
            loop {
                match staged.get(k) {
                    Some(&(sa, sb, _)) if sa.to_u128() <= e => {
                        if sa.to_u128() > s {
                            pieces.push((A::from_u128(s), A::from_u128(sa.to_u128().saturating_sub(1)), v));
                        }
                        if sb.to_u128() >= e {
                            break;
                        }
                        s = sb.to_u128().saturating_add(1);
                        k = k.saturating_add(1);
                    }
                    _ => {
                        pieces.push((A::from_u128(s), A::from_u128(e), v));
                        break;
                    }
                }
            }
        }
        // Merge the two disjoint lists by first address.
        let mut out: Vec<(A, A, u64)> = Vec::with_capacity(pieces.len().saturating_add(staged.len()));
        let (mut p, mut q) = (pieces.into_iter().peekable(), staged.into_iter().peekable());
        loop {
            let take_p = match (p.peek(), q.peek()) {
                (Some(a), Some(b)) => a.0 < b.0,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            let next = if take_p { p.next() } else { q.next() };
            if let Some(x) = next {
                out.push(x);
            }
        }
        if out.len() > MAX_OVERLAY_ENTRIES {
            return Err(OverlayError::TooLarge(MAX_OVERLAY_ENTRIES));
        }
        out.shrink_to_fit();
        Ok((RangeOverlay { entries: out }, self.checksum))
    }
}

/// The state an IP delta applies to.
pub struct RangeState<'a, A> {
    pub overlay: &'a RangeOverlay<A>,
    pub checksum: SetChecksum,
    pub v4: bool,
    /// The base's value at an address.
    pub base: RangeBase<'a, A>,
}

/// Applies one IP delta ([`RangeStage`] for one delta): deletes (each run's value read from the
/// current state), then upserts.
pub fn apply_range_ops<A: Addr>(
    st: RangeState<'_, A>,
    ops: &[RangeOp],
    seq: u64,
    prev: SetChecksum,
    expect: SetChecksum,
) -> Result<(RangeOverlay<A>, SetChecksum), OverlayError> {
    let mut stage = RangeStage::new(st.overlay, st.v4, st.checksum);
    stage.apply(ops, seq, prev, expect, st.base)?;
    stage.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_overlay() {
        let o = HashOverlay::from_entries((0..100u128).map(|i| (i * 7919, Entry::Upsert(i as u64)))).unwrap();
        for i in 0..100u128 {
            assert_eq!(o.get(i * 7919), Some(Entry::Upsert(&(i as u64))));
        }
        assert_eq!(o.get(5), None);
        let o2 = o.with_changes([(7919, Entry::Tombstone)]).unwrap();
        assert_eq!(o2.get(7919), Some(Entry::Tombstone));
        assert_eq!(o.get(7919), Some(Entry::Upsert(&1)), "immutable");
        assert_eq!(HashOverlay::<u64>::new().get(1), None);
        // Hash 0 and the all-ones hash are ordinary keys.
        let o3 =
            HashOverlay::from_entries([(0u128, Entry::Upsert(3u64)), (u128::MAX, Entry::Tombstone)]).unwrap();
        assert_eq!(o3.get(0), Some(Entry::Upsert(&3)));
        assert_eq!(o3.get(u128::MAX), Some(Entry::Tombstone));
        assert_eq!(o3.iter().count(), 2);
    }

    /// B7 (a): hashes with identical low bits (a verdict-set delta supplies its hashes directly)
    /// don't pile into one probe run: slots come from a keyed mix of all 128 bits. Slotting by
    /// the low bits put all 20,000 in one run (20,000 probes, quadratic inserts); random slots at
    /// 80 % load give runs of a few hundred at most.
    #[test]
    fn crafted_hashes_dont_cluster() {
        let n = 20_000u128;
        let o = HashOverlay::from_entries((0..n).map(|i| (i << 64, Entry::Upsert(1u64)))).unwrap();
        assert!(o.longest_probe() < 2_000, "probe run {}", o.longest_probe());
        let o = HashOverlay::from_entries((0..n).map(|i| (i, Entry::Upsert(1u64)))).unwrap();
        assert!(o.longest_probe() < 2_000, "probe run {}", o.longest_probe());
        for i in (0..n).step_by(97) {
            assert_eq!(o.get(i), Some(Entry::Upsert(&1)));
        }
    }

    /// Review round 2, CR5: a miss reads ~3 slots at the table's 80 % load (Robin Hood order with
    /// early termination), not the ~13 plain linear probing scans; hits still find every entry,
    /// and iteration gives back every hash exactly (the slot keeps the mix, not the high half).
    #[test]
    fn misses_stop_early_and_hashes_round_trip() {
        let mut x = 0x1234_5678_9abc_def1u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for z in [0u64, 1, u64::MAX, 0x8000_0000_0000_0000, rnd(), rnd()] {
            assert_eq!(unfold(fold(z)), z);
        }
        for n in [10usize, 1_000, 50_000] {
            let hashes: Vec<u128> = (0..n)
                .map(|_| (u128::from(rnd()) << 64) | u128::from(rnd()))
                .collect();
            let o = HashOverlay::from_entries(hashes.iter().map(|&h| (h, Entry::Upsert(h as u64 & 0xff))))
                .unwrap();
            for &h in &hashes {
                assert_eq!(o.get(h), Some(Entry::Upsert(&(h as u64 & 0xff))));
            }
            for _ in 0..1_000 {
                let h = (u128::from(rnd()) << 64) | u128::from(rnd());
                assert_eq!(o.get(h), None);
            }
            let mut back: Vec<u128> = o.iter().map(|(h, _)| h).collect();
            let mut want = hashes.clone();
            back.sort_unstable();
            want.sort_unstable();
            assert_eq!(back, want);
            if n >= 1_000 {
                // Each table draws its own slot key, so one small table's miss cost varies
                // (≈ 3.4 on average at 80 % load, but a single 1,000-entry table can land
                // above 4). Judge the mean over independently keyed tables, and bound each
                // one loosely so a regression to plain linear probing (≈ 13) still fails.
                let tables = if n >= 50_000 { 4 } else { 32 };
                let mut total = o.mean_miss_probes();
                assert!(total < 8.0, "{n}: {total} slots per miss");
                for _ in 1..tables {
                    let other = HashOverlay::from_entries(
                        hashes.iter().map(|&h| (h, Entry::Upsert(h as u64 & 0xff))),
                    )
                    .unwrap();
                    let probes = other.mean_miss_probes();
                    assert!(probes < 8.0, "{n}: {probes} slots per miss");
                    total += probes;
                }
                let mean = total / f64::from(tables);
                assert!(mean < 4.0, "{n}: {mean} slots per miss on average");
            }
        }
    }

    /// B8: a key overlay holds about 30 bytes per entry (bundles.md §6), not 64–128.
    #[test]
    fn key_overlay_is_compact() {
        assert_eq!(std::mem::size_of::<Slot<u64>>(), 24);
        for n in [1_000u128, 70_000, 100_000] {
            let o = HashOverlay::from_entries(
                (0..n).map(|i| (i.wrapping_mul(0x9e37_79b9_7f4a_7c15), Entry::Upsert(1u64))),
            )
            .unwrap();
            let per = o.memory_usage() as f64 / n as f64;
            assert!(
                per <= KEY_OVERLAY_BYTES_PER_ENTRY as f64 + 0.5,
                "{n}: {per} B/entry"
            );
        }
    }

    #[test]
    fn range_overlay_splits() {
        let empty: RangeOverlay<u32> = RangeOverlay::new();
        let mut st = RangeStage::new(&empty, true, SetChecksum::ZERO);
        st.paint(10, 20, 1);
        st.paint(15, 25, SLOT_TOMBSTONE);
        st.paint(0, 5, 2);
        let (o, _) = st.finish().unwrap();
        assert_eq!(o.get(12), Some(Entry::Upsert(1)));
        assert_eq!(o.get(15), Some(Entry::Tombstone));
        assert_eq!(o.get(25), Some(Entry::Tombstone));
        assert_eq!(o.get(26), None);
        assert_eq!(o.get(3), Some(Entry::Upsert(2)));
        assert_eq!(o.len(), 3);
        // A later stage laid over it: cuts, splits and keeps what it doesn't touch.
        let mut st = RangeStage::new(&o, true, SetChecksum::ZERO);
        st.paint(12, 13, 7);
        st.paint(24, 30, 8);
        st.paint(u32::MAX - 1, u32::MAX, 9);
        let (o2, _) = st.finish().unwrap();
        let got: Vec<(u32, u32, Entry<u64>)> = o2.entries().collect();
        assert_eq!(
            got,
            vec![
                (0, 5, Entry::Upsert(2)),
                (10, 11, Entry::Upsert(1)),
                (12, 13, Entry::Upsert(7)),
                (14, 14, Entry::Upsert(1)),
                (15, 23, Entry::Tombstone),
                (24, 30, Entry::Upsert(8)),
                (u32::MAX - 1, u32::MAX, Entry::Upsert(9)),
            ]
        );
    }

    /// Painting matches a naive per-address model on random ops, with and without a previous
    /// table.
    #[test]
    fn range_stage_matches_a_naive_model() {
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut rnd = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        for _ in 0..200 {
            let mut model: Vec<Option<u64>> = vec![None; 64];
            let mut prev: RangeOverlay<u32> = RangeOverlay::new();
            for _round in 0..3 {
                let mut st = RangeStage::new(&prev, true, SetChecksum::ZERO);
                for _ in 0..rnd(6) {
                    let a = rnd(64) as u32;
                    let b = (a + rnd(10) as u32).min(63);
                    let v = if rnd(3) == 0 { SLOT_TOMBSTONE } else { rnd(5) };
                    st.paint(a, b, v);
                    for m in model.iter_mut().take(b as usize + 1).skip(a as usize) {
                        *m = Some(v);
                    }
                }
                let (o, _) = st.finish().unwrap();
                for (a, m) in model.iter().enumerate() {
                    assert_eq!(o.get(a as u32), m.map(unpack_range), "address {a}");
                }
                let e: Vec<_> = o.entries.clone();
                assert!(e.windows(2).all(|w| w[0].1 < w[1].0), "sorted, disjoint");
                prev = o;
            }
        }
    }

    /// B7 (b): a delta's range ops cost O(log n) each, not a rebuild of the table each.
    #[test]
    fn many_range_ops_are_fast() {
        let n = 200_000u128;
        let mut ops = Vec::new();
        let mut cs = SetChecksum::ZERO;
        for i in 0..n {
            let first = (45u128 << 24) | (i * 4);
            ops.push(RangeOp::Upsert {
                first,
                last: first + 1,
                value: Value(1),
            });
            cs = cs.plus(SetChecksum::ip_entry(true, first, first + 1, 1));
        }
        let empty: RangeOverlay<u32> = RangeOverlay::new();
        let base = |_a: u32| None;
        let t = std::time::Instant::now();
        let (o, _) = apply_range_ops(
            RangeState {
                overlay: &empty,
                checksum: SetChecksum::ZERO,
                v4: true,
                base: &base,
            },
            &ops,
            1,
            SetChecksum::ZERO,
            cs,
        )
        .unwrap();
        assert_eq!(o.len(), n as usize);
        // Quadratic work (the old per-op rebuild) takes minutes here; the merge takes well under a
        // second even unoptimised.
        assert!(
            t.elapsed() < std::time::Duration::from_secs(20),
            "{:?}",
            t.elapsed()
        );
        assert_eq!(std::mem::size_of::<(u32, u32, u64)>(), 16);
    }

    #[test]
    fn key_ops_check_checksums() {
        let base: HashMap<Vec<u8>, u64> = [(b"com.a".to_vec(), 1u64), (b"com.b".to_vec(), 3)]
            .into_iter()
            .collect();
        let cs0 = base
            .iter()
            .fold(SetChecksum::ZERO, |c, (k, v)| c.add_domain(k, *v));
        let ops = vec![
            KeyOp::Upsert {
                key: b"com.b".to_vec(),
                value: Value(2),
            },
            KeyOp::Upsert {
                key: b"com.c".to_vec(),
                value: Value(1),
            },
            KeyOp::Delete {
                key: b"com.a".to_vec(),
            },
        ];
        let want = SetChecksum::ZERO.add_domain(b"com.b", 2).add_domain(b"com.c", 1);
        let empty = HashOverlay::new();
        let mut lookup = |k: &[u8], _h: KeyHash| Ok(base.get(k).map(|v| Value(*v)));
        let st = KeyState {
            overlay: &empty,
            checksum: cs0,
            hash_seed: 9,
            base: &mut lookup,
        };
        let (o, cs) = apply_key_ops(st, &ops, Phase::All, 1, cs0, want).unwrap();
        assert_eq!(cs, want);
        assert_eq!(o.get(KeyHash::of(9, b"com.a").0), Some(Entry::Tombstone));
        // A wrong expectation is a checksum error; a wrong prev a chain error.
        let st = KeyState {
            overlay: &empty,
            checksum: cs0,
            hash_seed: 9,
            base: &mut lookup,
        };
        assert_eq!(
            apply_key_ops(st, &ops, Phase::All, 1, cs0, SetChecksum(5)).unwrap_err(),
            OverlayError::Checksum { seq: 1 }
        );
        let st = KeyState {
            overlay: &empty,
            checksum: cs0,
            hash_seed: 9,
            base: &mut lookup,
        };
        assert_eq!(
            apply_key_ops(st, &ops, Phase::All, 1, SetChecksum(5), want).unwrap_err(),
            OverlayError::Chain { seq: 1 }
        );
        // Two deltas staged: each checked in turn, one rebuild.
        let ops2 = vec![KeyOp::Delete {
            key: b"com.c".to_vec(),
        }];
        let want2 = want.sub_domain(b"com.c", 1);
        let mut stage = KeyStage::new(&empty, 9, cs0);
        stage.apply(&ops, Phase::All, 1, cs0, want, &mut lookup).unwrap();
        stage
            .apply(&ops2, Phase::All, 2, want, want2, &mut lookup)
            .unwrap();
        let (o, cs) = stage.finish().unwrap();
        assert_eq!(cs, want2);
        assert_eq!(o.get(KeyHash::of(9, b"com.c").0), Some(Entry::Tombstone));
        assert_eq!(o.get(KeyHash::of(9, b"com.b").0), Some(Entry::Upsert(&2)));
        let mut stage = KeyStage::new(&empty, 9, cs0);
        stage.apply(&ops, Phase::All, 1, cs0, want, &mut lookup).unwrap();
        assert_eq!(
            stage.apply(&ops2, Phase::All, 2, want, want, &mut lookup),
            Err(OverlayError::Checksum { seq: 2 })
        );
    }
}
