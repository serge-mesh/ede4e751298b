//! Shard directories (bundles.md §4 "Shards", "Cold shards"): extendible hashing over the top 8
//! bits of a key hash's high half.
//!
//! An entry `{prefix, prefix_bits, shard}` owns every directory index whose top `prefix_bits` bits
//! equal `prefix`; the entries of a directory cover the 256 indices exactly once, so each key is in
//! exactly one shard. A shard splits in two by the next hash bit when it would exceed
//! `max_shard_keys`, and two siblings merge when together they hold less than 75 % of it
//! (`max_shard_keys` 0 means one shard). New shards take numbers the bundle has never used, so a
//! shard number always names the same hash range. A shard at 8 prefix bits can't split again: it
//! grows, and [`Plan::cant_split`] lists it so core warns.
//!
//! **Reader cap** (review round 2, CR3): no shard is planned past [`MAX_SHARD_KEYS`], the most the
//! edge loads, whatever `max_shard_keys` says: the cap in effect is the smaller of the two, and
//! `max_shard_keys` 0 means one shard only while the keys fit it (past it, shards split and merge
//! by [`MAX_SHARD_KEYS`]). The writer refuses a larger shard ([`crate::domains::FstWriter`]).

use serde::{Deserialize, Serialize};

use crate::domains::MAX_SHARD_KEYS;
use crate::hash::KeyHash;

/// Directory index bits (the top byte of the high half).
pub const DIR_BITS: u8 = 8;
/// Directory entries.
pub const DIR_SIZE: usize = 256;

/// One directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ShardEntry {
    pub prefix: u32,
    pub prefix_bits: u8,
    pub shard: u32,
}

impl ShardEntry {
    /// The directory indices it owns, as a half-open range.
    pub fn index_range(&self) -> Option<(usize, usize)> {
        if self.prefix_bits > DIR_BITS || u64::from(self.prefix) >= (1u64 << self.prefix_bits) {
            return None;
        }
        let shift = u32::from(DIR_BITS.checked_sub(self.prefix_bits)?);
        let start = usize::try_from(self.prefix).ok()?.checked_shl(shift)?;
        let len = 1usize.checked_shl(shift)?;
        Some((start, start.checked_add(len)?))
    }

    /// The entry's sibling range (same prefix but the last bit), if it has one.
    pub fn sibling_prefix(&self) -> Option<u32> {
        (self.prefix_bits > 0).then_some(self.prefix ^ 1)
    }
}

/// Why a directory is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DirError {
    #[error("entry {0:?} is out of range")]
    Range(ShardEntry),
    #[error("directory index {0} is covered twice")]
    Overlap(usize),
    #[error("directory index {0} is not covered")]
    Gap(usize),
    #[error("shard {0} is listed twice")]
    DuplicateShard(u32),
    #[error("no shard {0}")]
    NoShard(u32),
    #[error("shard {0} has 8 prefix bits and can't split")]
    CantSplit(u32),
    #[error("shards {0} and {1} aren't siblings")]
    NotSiblings(u32, u32),
    #[error("shard numbers are exhausted")]
    Exhausted,
}

/// A validated directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardDir {
    /// Sorted by index range.
    entries: Vec<ShardEntry>,
    /// Directory index → position in `entries`.
    table: Box<[u16; DIR_SIZE]>,
}

impl ShardDir {
    /// One shard holding every key.
    pub fn single(shard: u32) -> ShardDir {
        ShardDir {
            entries: vec![ShardEntry {
                prefix: 0,
                prefix_bits: 0,
                shard,
            }],
            table: Box::new([0; DIR_SIZE]),
        }
    }

    /// Validates entries: each in range, covering every index exactly once, shard numbers unique.
    pub fn new(mut entries: Vec<ShardEntry>) -> Result<ShardDir, DirError> {
        if entries.len() > DIR_SIZE {
            return Err(DirError::Overlap(0));
        }
        let mut ranges = Vec::with_capacity(entries.len());
        for e in &entries {
            let r = e.index_range().ok_or(DirError::Range(*e))?;
            ranges.push((r, *e));
        }
        ranges.sort_unstable();
        let mut shards: Vec<u32> = entries.iter().map(|e| e.shard).collect();
        shards.sort_unstable();
        if let Some(w) = shards.windows(2).find(|w| w.first() == w.get(1)) {
            return Err(DirError::DuplicateShard(w.first().copied().unwrap_or(0)));
        }
        let mut table = Box::new([0u16; DIR_SIZE]);
        let mut next = 0usize;
        entries.clear();
        for (pos, ((start, end), e)) in ranges.into_iter().enumerate() {
            if start < next {
                return Err(DirError::Overlap(start));
            }
            if start > next {
                return Err(DirError::Gap(next));
            }
            let p = u16::try_from(pos).map_err(|_| DirError::Overlap(start))?;
            for slot in table.get_mut(start..end).ok_or(DirError::Range(e))? {
                *slot = p;
            }
            next = end;
            entries.push(e);
        }
        if next != DIR_SIZE {
            return Err(DirError::Gap(next));
        }
        Ok(ShardDir { entries, table })
    }

    /// The entries, sorted by the indices they own.
    pub fn entries(&self) -> &[ShardEntry] {
        &self.entries
    }

    /// The entry owning a directory index.
    pub fn entry_for_index(&self, index: u8) -> Option<&ShardEntry> {
        let pos = *self.table.get(usize::from(index))?;
        self.entries.get(usize::from(pos))
    }

    /// The position (in [`ShardDir::entries`]) of the entry owning a directory index.
    pub fn position_for_index(&self, index: u8) -> usize {
        usize::from(self.table.get(usize::from(index)).copied().unwrap_or(0))
    }

    /// The shard a key hash belongs to.
    pub fn shard_of(&self, h: KeyHash) -> u32 {
        self.entry_for_index(h.dir_index()).map_or(0, |e| e.shard)
    }

    /// The entry of shard `shard`.
    pub fn entry(&self, shard: u32) -> Option<&ShardEntry> {
        self.entries.iter().find(|e| e.shard == shard)
    }

    /// The highest shard number in use.
    pub fn max_shard(&self) -> u32 {
        self.entries.iter().map(|e| e.shard).max().unwrap_or(0)
    }

    /// Splits `shard` by the next hash bit into two new shards numbered from `next`.
    pub fn split(&self, shard: u32, next: &mut u32) -> Result<(ShardDir, [ShardEntry; 2]), DirError> {
        let e = *self.entry(shard).ok_or(DirError::NoShard(shard))?;
        if e.prefix_bits >= DIR_BITS {
            return Err(DirError::CantSplit(shard));
        }
        let bits = e.prefix_bits.saturating_add(1);
        let lo = ShardEntry {
            prefix: e.prefix.checked_shl(1).ok_or(DirError::Range(e))?,
            prefix_bits: bits,
            shard: take(next)?,
        };
        let hi = ShardEntry {
            prefix: lo.prefix | 1,
            prefix_bits: bits,
            shard: take(next)?,
        };
        let mut entries: Vec<ShardEntry> = self
            .entries
            .iter()
            .copied()
            .filter(|x| x.shard != shard)
            .collect();
        entries.push(lo);
        entries.push(hi);
        Ok((ShardDir::new(entries)?, [lo, hi]))
    }

    /// Merges two sibling shards into a new shard numbered from `next`.
    pub fn merge(&self, a: u32, b: u32, next: &mut u32) -> Result<(ShardDir, ShardEntry), DirError> {
        let ea = *self.entry(a).ok_or(DirError::NoShard(a))?;
        let eb = *self.entry(b).ok_or(DirError::NoShard(b))?;
        if ea.prefix_bits == 0 || ea.prefix_bits != eb.prefix_bits || ea.prefix ^ 1 != eb.prefix {
            return Err(DirError::NotSiblings(a, b));
        }
        let m = ShardEntry {
            prefix: ea.prefix >> 1,
            prefix_bits: ea.prefix_bits.saturating_sub(1),
            shard: take(next)?,
        };
        let mut entries: Vec<ShardEntry> = self
            .entries
            .iter()
            .copied()
            .filter(|x| x.shard != a && x.shard != b)
            .collect();
        entries.push(m);
        Ok((ShardDir::new(entries)?, m))
    }

    /// Replaces every shard with one new shard (`max_shard_keys` 0).
    pub fn collapse(&self, next: &mut u32) -> Result<(ShardDir, ShardEntry), DirError> {
        let shard = take(next)?;
        let d = ShardDir::single(shard);
        let e = *d.entries.first().ok_or(DirError::Gap(0))?;
        Ok((d, e))
    }
}

fn take(next: &mut u32) -> Result<u32, DirError> {
    let n = *next;
    *next = next.checked_add(1).ok_or(DirError::Exhausted)?;
    Ok(n)
}

/// Key counts per directory index, for planning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Histogram(pub Box<[u64; DIR_SIZE]>);

impl Default for Histogram {
    fn default() -> Self {
        Histogram(Box::new([0; DIR_SIZE]))
    }
}

impl Histogram {
    /// Counts one key.
    pub fn add(&mut self, h: KeyHash) {
        if let Some(c) = self.0.get_mut(usize::from(h.dir_index())) {
            *c = c.saturating_add(1);
        }
    }

    /// The keys an entry's range holds.
    pub fn count(&self, e: &ShardEntry) -> u64 {
        match e.index_range() {
            Some((s, t)) => self
                .0
                .get(s..t)
                .map_or(0, |v| v.iter().fold(0u64, |a, &b| a.saturating_add(b))),
            None => 0,
        }
    }
}

/// One change to a directory: the shards it removes and the new entries replacing them (a split,
/// a merge, or a collapse to one shard). Core rebuilds the new shards' bases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reshard {
    pub remove: Vec<u32>,
    pub add: Vec<ShardEntry>,
}

/// The result of [`plan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The directory after every step.
    pub dir: ShardDir,
    /// The steps, in order.
    pub steps: Vec<Reshard>,
    /// Shards over the cap that can't split again (bundles.md §4: they grow and warn).
    pub cant_split: Vec<u32>,
    /// The next unused shard number.
    pub next: u32,
}

/// Plans the splits and merges that bring every shard within `max_shard_keys` (bundles.md §4).
/// Deterministic: steps follow directory order. A split shard's children never merge back in the
/// same plan (together they exceed the cap, and merging needs less than 75 % of it).
pub fn plan(dir: &ShardDir, counts: &Histogram, max_shard_keys: u64, next: u32) -> Result<Plan, DirError> {
    let mut next = next.max(dir.max_shard().saturating_add(1));
    let mut cur = dir.clone();
    let mut steps = Vec::new();
    let total = counts.0.iter().fold(0u64, |a, &b| a.saturating_add(b));
    // The cap in effect never passes the reader's (see the module docs).
    let max_shard_keys = match max_shard_keys {
        0 if total > MAX_SHARD_KEYS => MAX_SHARD_KEYS,
        0 => 0,
        m => m.min(MAX_SHARD_KEYS),
    };
    if max_shard_keys == 0 {
        if cur.entries.len() > 1 || cur.entries.first().is_some_and(|e| e.prefix_bits != 0) {
            let remove: Vec<u32> = cur.entries.iter().map(|e| e.shard).collect();
            let (d, e) = cur.collapse(&mut next)?;
            steps.push(Reshard { remove, add: vec![e] });
            cur = d;
        }
        return Ok(Plan {
            dir: cur,
            steps,
            cant_split: Vec::new(),
            next,
        });
    }
    let mut cant_split = Vec::new();
    // Splits until every shard fits or can't split.
    loop {
        let over = cur
            .entries
            .iter()
            .find(|e| counts.count(e) > max_shard_keys && e.prefix_bits < DIR_BITS)
            .copied();
        let Some(e) = over else { break };
        let (d, add) = cur.split(e.shard, &mut next)?;
        steps.push(Reshard {
            remove: vec![e.shard],
            add: add.to_vec(),
        });
        cur = d;
    }
    for e in &cur.entries {
        if counts.count(e) > max_shard_keys {
            cant_split.push(e.shard);
        }
    }
    // Merges of siblings below 75 % of the cap, repeated while any applies.
    let threshold = max_shard_keys.saturating_mul(3) / 4;
    loop {
        let mut pair = None;
        for e in &cur.entries {
            let Some(sp) = e.sibling_prefix() else { continue };
            if e.prefix & 1 != 0 {
                continue;
            }
            let Some(s) = cur
                .entries
                .iter()
                .find(|x| x.prefix_bits == e.prefix_bits && x.prefix == sp)
            else {
                continue;
            };
            if counts.count(e).saturating_add(counts.count(s)) < threshold {
                pair = Some((e.shard, s.shard));
                break;
            }
        }
        let Some((a, b)) = pair else { break };
        let (d, m) = cur.merge(a, b, &mut next)?;
        steps.push(Reshard {
            remove: vec![a, b],
            add: vec![m],
        });
        cur = d;
    }
    Ok(Plan {
        dir: cur,
        steps,
        cant_split,
        next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        assert!(
            ShardDir::new(vec![ShardEntry {
                prefix: 0,
                prefix_bits: 0,
                shard: 0
            }])
            .is_ok()
        );
        let half = |p, s| ShardEntry {
            prefix: p,
            prefix_bits: 1,
            shard: s,
        };
        assert!(ShardDir::new(vec![half(0, 1), half(1, 2)]).is_ok());
        assert_eq!(ShardDir::new(vec![half(0, 1)]), Err(DirError::Gap(128)));
        assert!(matches!(
            ShardDir::new(vec![half(0, 1), half(1, 1)]),
            Err(DirError::DuplicateShard(1))
        ));
        assert!(matches!(
            ShardDir::new(vec![half(0, 1), half(0, 2)]),
            Err(DirError::Overlap(0))
        ));
        assert!(matches!(
            ShardDir::new(vec![ShardEntry {
                prefix: 2,
                prefix_bits: 1,
                shard: 0
            }]),
            Err(DirError::Range(_))
        ));
        assert!(
            ShardDir::new(vec![ShardEntry {
                prefix: 0,
                prefix_bits: 9,
                shard: 0
            }])
            .is_err()
        );
    }

    #[test]
    fn split_and_merge() {
        let d = ShardDir::single(0);
        let mut next = 1;
        let (d, [a, b]) = d.split(0, &mut next).unwrap();
        assert_eq!((a.shard, b.shard), (1, 2));
        assert_eq!(d.shard_of(KeyHash(0)), 1);
        assert_eq!(d.shard_of(KeyHash(u128::MAX)), 2);
        let (d2, m) = d.merge(1, 2, &mut next).unwrap();
        assert_eq!(m.shard, 3, "a merge takes a new number");
        assert_eq!(d2.entries().len(), 1);
        let (d3, _) = d.split(2, &mut next).unwrap();
        assert!(matches!(
            d3.merge(1, 5, &mut next),
            Err(DirError::NotSiblings(1, 5))
        ));
    }
}
