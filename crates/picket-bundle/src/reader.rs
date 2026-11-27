//! Loading a bundle's parts on the edge (bundles.md §6 "Loading", "Overlay per shard",
//! "Activation"; edge.md §13).
//!
//! The edge downloads and verifies each blob (BLAKE3: [`crate::head::verify_blob`]), reads it into
//! a `Vec<u8>` and builds one part at a time off the hot path: a hot shard (filter, FST, overlay),
//! a cold shard (cold filter, overlay; its page file stays on the SSD), an IP shard (base and range
//! overlay), or a segment. A part is immutable; applying a delta returns a new part sharing the
//! base (`Arc`), so the edge swaps it in with `ArcSwap` and the old one is freed when the last
//! in-flight query drops it. Every part records the head it came from and reads rich rules from
//! its own head's `rich.json` (an `Arc<RichSegment>`).
//!
//! Applying a delta checks the header (bundle, shard, base, seq), then the set checksum after
//! every delta: [`LoadError::NeedBase`] means discard the overlay and fetch the shard's base. A run
//! of a shard's chain applies with one overlay rebuild (`apply_deltas`: boot replay, or the rest of
//! a chain on activation; review round 1, B7). Cold deltas apply in two steps (upserts, later
//! deletes) so a key moving between the parts is never in neither (bundles.md §2 "Moves"). A cold
//! page that fails while a delta reads it is [`LoadError::Page`]: delete and refetch the page file.
//!
//! **Rich indices** (review round 1, B6): every index a part holds must name a set of the
//! `rich.json` it reads. A part checks at load, and when it moves to a head (`in_head`, refused
//! otherwise). A delta's upserts reference its own head's segment, so applying deltas to a hot or
//! IP shard takes that head and its `rich.json` and returns the shard already moved to them,
//! checked (review round 2, CR4): no shard ever reads one head's segment with another head's
//! indices, so none can be swapped in that way.
//!
//! **Memory** (README §2 "Bounded"; review round 2, CR2): a chain is parsed and staged one delta
//! at a time, each checked before the next is read, so applying a run of deltas holds one parsed
//! delta plus the staged changes, never the whole chain.

use std::sync::Arc;

use crate::checksum::SetChecksum;
use crate::delta::{DeltaError, KeyDelta, read_key_delta, read_range_delta};
use crate::domains::{DomainsFst, FstError};
use crate::filter::{FilterError, KeyFilter};
use crate::hash::KeyHash;
use crate::head::{
    COLD_BF8, COLD_PAGES, DOMAINS_BF8, DOMAINS_FST, HeadError, Manifest, PartKind, verify_blob,
};
use crate::ips::{IpBase, IpShardId, IpsError};
use crate::overlay::{Addr, Entry, HashOverlay, KeyStage, OverlayError, Phase, RangeOverlay, RangeStage};
use crate::page::{self, PAGE_SIZE, PageError, PageReader};
use crate::patterns::{PatternSegment, PatternsError};
use crate::rich::{RichError, RichSegment, check_rich_idx};
use crate::value::Value;

/// Why a part can't be loaded or a delta applied.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Head(#[from] HeadError),
    #[error(transparent)]
    Fst(#[from] FstError),
    #[error(transparent)]
    Filter(#[from] FilterError),
    #[error(transparent)]
    Ips(#[from] IpsError),
    #[error(transparent)]
    Patterns(#[from] PatternsError),
    #[error(transparent)]
    Rich(#[from] RichError),
    #[error(transparent)]
    Delta(#[from] DeltaError),
    #[error(transparent)]
    Page(#[from] PageError),
    /// The overlay must be discarded and the shard's base fetched (a checksum mismatch, a gap in
    /// the chain, or a delta for another base).
    #[error("need base: {0}")]
    NeedBase(String),
    #[error("{0}")]
    Mismatch(String),
}

impl From<OverlayError> for LoadError {
    fn from(e: OverlayError) -> Self {
        match e {
            // A cold page that failed while reading a current value keeps its meaning: the edge
            // deletes and refetches the page file (bundles.md §4 "Reading"; review round 1, B11).
            OverlayError::Base(p) => LoadError::Page(p),
            other => LoadError::NeedBase(other.to_string()),
        }
    }
}

/// Checks a delta header against the part it is applied to.
fn check_header(
    d: &KeyDelta,
    bundle: &str,
    part: PartKind,
    shard: u32,
    base: &str,
    seq: u64,
) -> Result<(), LoadError> {
    let h = &d.header;
    let shard_ok = match part {
        PartKind::Hot => h.shard == Some(shard) && h.cold_shard.is_none(),
        PartKind::Cold => h.cold_shard == Some(shard) && h.shard.is_none() && h.mid_checksum.is_some(),
    };
    if h.bundle != bundle || !shard_ok || h.ip_shard.is_some() {
        return Err(LoadError::Mismatch("delta is for another shard".into()));
    }
    if h.base != base || h.seq <= seq {
        return Err(LoadError::NeedBase(format!(
            "delta {} doesn't continue base {base} at seq {seq}",
            h.seq
        )));
    }
    Ok(())
}

/// A hot domain shard: filter, FST and overlay.
#[derive(Clone, Debug)]
pub struct HotShard {
    pub number: u32,
    /// The head this part came from.
    pub head: Arc<str>,
    bundle: Arc<str>,
    base_id: Arc<str>,
    hash_seed: u64,
    filter: Option<Arc<KeyFilter>>,
    fst: Arc<DomainsFst>,
    overlay: Arc<HashOverlay<u64>>,
    checksum: SetChecksum,
    seq: u64,
    rich: Arc<RichSegment>,
    /// The largest `rich_idx` the shard holds (base and overlay upserts).
    max_rich: Option<u32>,
}

/// The largest rich index among a delta's upserted values.
fn upserts_max_rich(ops: &[crate::delta::KeyOp]) -> Option<u32> {
    ops.iter()
        .filter_map(|o| match o {
            crate::delta::KeyOp::Upsert { value, .. } => value.rich_idx(),
            crate::delta::KeyOp::Delete { .. } => None,
        })
        .max()
}

/// The verified blobs of a hot shard base.
pub struct HotBaseBlobs<'a> {
    /// The base id (BLAKE3 of the manifest).
    pub base_id: &'a str,
    pub manifest: &'a [u8],
    pub fst: Vec<u8>,
    pub bf8: &'a [u8],
}

impl HotShard {
    /// Loads a hot shard base (at its base seq, no deltas yet).
    pub fn load(
        bundle: &str,
        head: Arc<str>,
        hash_seed: u64,
        base_seq: u64,
        blobs: HotBaseBlobs<'_>,
        rich: Arc<RichSegment>,
    ) -> Result<HotShard, LoadError> {
        verify_blob(blobs.manifest, blobs.base_id)?;
        let m = Manifest::from_bytes(blobs.manifest)?;
        if m.part != PartKind::Hot || m.bundle != bundle {
            return Err(LoadError::Mismatch("manifest is for another part".into()));
        }
        for (name, bytes) in [(DOMAINS_FST, blobs.fst.as_slice()), (DOMAINS_BF8, blobs.bf8)] {
            let f = m
                .file(name)
                .ok_or_else(|| LoadError::Mismatch(format!("no {name}")))?;
            verify_blob(bytes, &f.blake3)?;
        }
        let filter = KeyFilter::from_bytes(blobs.bf8)?;
        let fst = DomainsFst::from_bytes(blobs.fst, m.keys)?;
        let max_rich = fst.max_rich_idx();
        check_rich_idx(max_rich, &rich).map_err(LoadError::Mismatch)?;
        Ok(HotShard {
            number: m.shard,
            head,
            bundle: bundle.into(),
            base_id: blobs.base_id.into(),
            hash_seed,
            filter: Some(Arc::new(filter)),
            fst: Arc::new(fst),
            overlay: Arc::new(HashOverlay::new()),
            checksum: m.checksum,
            seq: base_seq,
            rich,
            max_rich,
        })
    }

    /// A new shard with one delta of head `head` applied (the overlay rebuilt; base shared); see
    /// [`HotShard::apply_deltas`].
    pub fn apply_delta(
        &self,
        delta: &[u8],
        head: Arc<str>,
        rich: Arc<RichSegment>,
    ) -> Result<HotShard, LoadError> {
        self.apply_deltas(&[delta], head, rich)
    }

    /// A new shard with a run of its chain applied in order, each delta read, its header and
    /// checksum checked and its ops staged before the next is read, and the overlay rebuilt once
    /// (boot replay, or an activation fetching the rest of a chain: review round 1, B7). The
    /// deltas are `head`'s (the head whose chain lists them; at boot, the head being loaded), and
    /// the result is part of `head`, reading `rich`, that head's `rich.json`: refused when a rich
    /// index the shard then holds names no set of it (review round 2, CR4).
    pub fn apply_deltas(
        &self,
        deltas: &[&[u8]],
        head: Arc<str>,
        rich: Arc<RichSegment>,
    ) -> Result<HotShard, LoadError> {
        let fst = self.fst.clone();
        let mut base = |k: &[u8], _h: KeyHash| -> Result<Option<Value>, PageError> { Ok(fst.get(k)) };
        let mut stage = KeyStage::new(&self.overlay, self.hash_seed, self.checksum);
        let mut seq = self.seq;
        let mut max_rich = self.max_rich;
        for delta in deltas {
            let d = read_key_delta(delta)?;
            check_header(&d, &self.bundle, PartKind::Hot, self.number, &self.base_id, seq)?;
            // Upserts reference the delta's own head's `rich.json`, checked below.
            max_rich = max_rich.max(upserts_max_rich(&d.ops));
            stage.apply(
                &d.ops,
                Phase::All,
                d.header.seq,
                d.header.prev_checksum,
                d.header.new_checksum,
                &mut base,
            )?;
            seq = d.header.seq;
        }
        check_rich_idx(max_rich, &rich).map_err(LoadError::Mismatch)?;
        let (overlay, checksum) = stage.finish()?;
        Ok(HotShard {
            overlay: Arc::new(overlay),
            checksum,
            seq,
            max_rich,
            head,
            rich,
            ..self.clone()
        })
    }

    /// The same shard, now part of head `head` with that head's `rich.json` (a head that leaves
    /// the shard unchanged moves it at once: edge.md §13). Refused when a rich index the shard
    /// holds names no set of that segment (review round 1, B6).
    pub fn in_head(&self, head: Arc<str>, rich: Arc<RichSegment>) -> Result<HotShard, LoadError> {
        check_rich_idx(self.max_rich, &rich).map_err(LoadError::Mismatch)?;
        Ok(HotShard {
            head,
            rich,
            ..self.clone()
        })
    }

    /// A key's value: overlay (a tombstone skips the base), then filter, then FST.
    pub fn get(&self, key: &[u8], h: KeyHash) -> Option<Value> {
        match self.overlay.get(h.0) {
            Some(Entry::Upsert(v)) => return Some(Value(*v)),
            Some(Entry::Tombstone) => return None,
            None => {}
        }
        if let Some(f) = &self.filter
            && !f.contains(h.low64())
        {
            return None;
        }
        self.fst.get(key)
    }

    /// The rich rules this part reads.
    pub fn rich(&self) -> &RichSegment {
        &self.rich
    }

    pub fn rich_arc(&self) -> &Arc<RichSegment> {
        &self.rich
    }

    pub fn checksum(&self) -> SetChecksum {
        self.checksum
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn base_id(&self) -> &str {
        &self.base_id
    }

    /// Bytes of the overlay (counted against `overlay_budget_mib`).
    pub fn overlay_bytes(&self) -> usize {
        self.overlay.memory_usage()
    }

    /// Bytes held: filter, FST and overlay.
    pub fn memory_usage(&self) -> usize {
        self.filter
            .as_ref()
            .map_or(0, |f| f.memory_usage())
            .saturating_add(self.fst.memory_usage())
            .saturating_add(self.overlay_bytes())
    }
}

/// What one cold probe found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColdProbe {
    Hit(Value),
    Miss,
    /// The page read failed: the cold lookup fails open and is unchecked.
    Failed(PageError),
}

/// A cold delta's deletes, waiting for the hot swap (bundles.md §2 "Moves").
#[derive(Clone, Debug)]
pub struct PendingDeletes {
    delta: KeyDelta,
}

impl PendingDeletes {
    pub fn seq(&self) -> u64 {
        self.delta.header.seq
    }
}

/// A cold shard: its filter and overlay in RAM; its page file on the SSD.
#[derive(Clone, Debug)]
pub struct ColdShard {
    pub number: u32,
    pub head: Arc<str>,
    /// Set between a delta's upserts and deletes: the head the shard is moving from.
    pub moving_from: Option<Arc<str>>,
    bundle: Arc<str>,
    base_id: Arc<str>,
    hash_seed: u64,
    filter: Arc<KeyFilter>,
    /// The page file's BLAKE3 id.
    pages_file: Arc<str>,
    page_count: u32,
    identity: u128,
    overlay: Arc<HashOverlay<u64>>,
    checksum: SetChecksum,
    seq: u64,
}

/// The verified blobs of a cold shard base held in RAM (the page file isn't loaded).
pub struct ColdBaseBlobs<'a> {
    pub base_id: &'a str,
    pub manifest: &'a [u8],
    pub bf8: &'a [u8],
}

impl ColdShard {
    /// Loads a cold shard base. `header_page` is the page file's first 4 KiB, read once to check
    /// that the file on the SSD is the manifest's.
    pub fn load(
        bundle: &str,
        head: Arc<str>,
        hash_seed: u64,
        base_seq: u64,
        blobs: ColdBaseBlobs<'_>,
        header_page: &[u8],
    ) -> Result<ColdShard, LoadError> {
        verify_blob(blobs.manifest, blobs.base_id)?;
        let m = Manifest::from_bytes(blobs.manifest)?;
        if m.part != PartKind::Cold || m.bundle != bundle {
            return Err(LoadError::Mismatch("manifest is for another part".into()));
        }
        let fb = m
            .file(COLD_BF8)
            .ok_or_else(|| LoadError::Mismatch("no cold.bf8".into()))?;
        verify_blob(blobs.bf8, &fb.blake3)?;
        let pf = m
            .file(COLD_PAGES)
            .ok_or_else(|| LoadError::Mismatch("no cold.pages".into()))?;
        let h = page::PageFileHeader::parse(header_page)?;
        if h.kind != page::PageFileKind::ColdShard
            || Some(h.page_count) != m.pages
            || h.identity != m.checksum.0
            || h.hash_seed != hash_seed
            || h.record_count != m.keys
            || h.file_len() != pf.size
        {
            return Err(LoadError::Mismatch("page file doesn't match its manifest".into()));
        }
        let filter = KeyFilter::from_bytes(blobs.bf8)?;
        Ok(ColdShard {
            number: m.shard,
            head,
            moving_from: None,
            bundle: bundle.into(),
            base_id: blobs.base_id.into(),
            hash_seed,
            filter: Arc::new(filter),
            pages_file: pf.blake3.as_str().into(),
            page_count: h.page_count,
            identity: h.identity,
            overlay: Arc::new(HashOverlay::new()),
            checksum: m.checksum,
            seq: base_seq,
        })
    }

    /// The page file's id (where the edge keeps it).
    pub fn pages_file(&self) -> &str {
        &self.pages_file
    }

    fn base_value(&self, key_hash: KeyHash, reader: &dyn PageReader) -> Result<Option<Value>, PageError> {
        if !self.filter.contains(key_hash.low64()) {
            return Ok(None);
        }
        let mut buf = [0u8; PAGE_SIZE];
        let v = page::read_record(
            reader,
            &self.pages_file,
            self.identity,
            self.page_count,
            key_hash.0,
            &mut buf,
        )?;
        match v {
            None => Ok(None),
            Some(b) => {
                let arr: [u8; 8] = b.as_slice().try_into().map_err(|_| PageError::Malformed(0))?;
                Ok(Some(Value::from_stored(u64::from_le_bytes(arr))))
            }
        }
    }

    /// One probe: the overlay, then the filter, then one page read (bundles.md §6 "Cold lookup").
    pub fn probe(&self, h: KeyHash, reader: &dyn PageReader) -> ColdProbe {
        match self.overlay.get(h.0) {
            Some(Entry::Upsert(v)) => return ColdProbe::Hit(Value(*v)),
            Some(Entry::Tombstone) => return ColdProbe::Miss,
            None => {}
        }
        match self.base_value(h, reader) {
            Ok(Some(v)) => ColdProbe::Hit(v),
            Ok(None) => ColdProbe::Miss,
            Err(e) => ColdProbe::Failed(e),
        }
    }

    /// True when the overlay or filter says the key may be here (no page read).
    pub fn may_contain(&self, h: KeyHash) -> bool {
        match self.overlay.get(h.0) {
            Some(Entry::Upsert(_)) => true,
            Some(Entry::Tombstone) => false,
            None => self.filter.contains(h.low64()),
        }
    }

    /// Stages one phase of a cold delta.
    fn stage(
        &self,
        stage: &mut KeyStage<'_>,
        d: &KeyDelta,
        phase: Phase,
        reader: &dyn PageReader,
    ) -> Result<(), LoadError> {
        let (prev, expect) = match phase {
            Phase::Upserts => (d.header.prev_checksum, d.header.mid_checksum.unwrap_or_default()),
            Phase::Deletes => (d.header.mid_checksum.unwrap_or_default(), d.header.new_checksum),
            Phase::All => (d.header.prev_checksum, d.header.new_checksum),
        };
        let mut base =
            |_k: &[u8], h: KeyHash| -> Result<Option<Value>, PageError> { self.base_value(h, reader) };
        Ok(stage.apply(&d.ops, phase, d.header.seq, prev, expect, &mut base)?)
    }

    fn apply(
        &self,
        d: &KeyDelta,
        phase: Phase,
        reader: &dyn PageReader,
    ) -> Result<(HashOverlay<u64>, SetChecksum), LoadError> {
        let mut stage = KeyStage::new(&self.overlay, self.hash_seed, self.checksum);
        self.stage(&mut stage, d, phase, reader)?;
        Ok(stage.finish()?)
    }

    /// Applies a cold delta's upserts (checking `mid_checksum`); the deletes wait until the hot
    /// swap ([`ColdShard::apply_deletes`]). Between the two the shard holds the union of the
    /// previous and the new head, `moving_from` names the previous head, and `versions` logs it as
    /// `[previous, new]`.
    pub fn apply_upserts(
        &self,
        delta: &[u8],
        new_head: Arc<str>,
        reader: &dyn PageReader,
    ) -> Result<(ColdShard, PendingDeletes), LoadError> {
        let d = read_key_delta(delta)?;
        check_header(
            &d,
            &self.bundle,
            PartKind::Cold,
            self.number,
            &self.base_id,
            self.seq,
        )?;
        let (overlay, checksum) = self.apply(&d, Phase::Upserts, reader)?;
        let moving_from = Some(self.moving_from.clone().unwrap_or_else(|| self.head.clone()));
        Ok((
            ColdShard {
                overlay: Arc::new(overlay),
                checksum,
                head: new_head,
                moving_from,
                ..self.clone()
            },
            PendingDeletes { delta: d },
        ))
    }

    /// Applies the deletes of the delta whose upserts were applied (checking `new_checksum`).
    pub fn apply_deletes(
        &self,
        pending: PendingDeletes,
        reader: &dyn PageReader,
    ) -> Result<ColdShard, LoadError> {
        let d = pending.delta;
        let (overlay, checksum) = self.apply(&d, Phase::Deletes, reader)?;
        Ok(ColdShard {
            overlay: Arc::new(overlay),
            checksum,
            seq: d.header.seq,
            moving_from: None,
            ..self.clone()
        })
    }

    /// Applies a whole cold delta (rebuilding the overlay at boot, where the order of moves no
    /// longer matters).
    pub fn apply_delta(&self, delta: &[u8], reader: &dyn PageReader) -> Result<ColdShard, LoadError> {
        self.apply_deltas(&[delta], reader)
    }

    /// Applies a run of whole cold deltas in order (each one's `mid_checksum` and `new_checksum`
    /// checked in turn), rebuilding the overlay once (boot replay: review round 1, B7).
    pub fn apply_deltas(&self, deltas: &[&[u8]], reader: &dyn PageReader) -> Result<ColdShard, LoadError> {
        let mut stage = KeyStage::new(&self.overlay, self.hash_seed, self.checksum);
        let mut seq = self.seq;
        for delta in deltas {
            let d = read_key_delta(delta)?;
            check_header(&d, &self.bundle, PartKind::Cold, self.number, &self.base_id, seq)?;
            self.stage(&mut stage, &d, Phase::Upserts, reader)?;
            self.stage(&mut stage, &d, Phase::Deletes, reader)?;
            seq = d.header.seq;
        }
        let (overlay, checksum) = stage.finish()?;
        Ok(ColdShard {
            overlay: Arc::new(overlay),
            checksum,
            seq,
            ..self.clone()
        })
    }

    /// The same shard, now part of head `head`.
    pub fn in_head(&self, head: Arc<str>) -> ColdShard {
        ColdShard { head, ..self.clone() }
    }

    pub fn checksum(&self) -> SetChecksum {
        self.checksum
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn base_id(&self) -> &str {
        &self.base_id
    }

    pub fn overlay_bytes(&self) -> usize {
        self.overlay.memory_usage()
    }

    /// Bytes held in RAM: the cold filter and the overlay.
    pub fn memory_usage(&self) -> usize {
        self.filter.memory_usage().saturating_add(self.overlay_bytes())
    }
}

#[derive(Clone, Debug)]
enum IpOverlay {
    V4(RangeOverlay<u32>),
    V6(RangeOverlay<u128>),
}

/// An IP shard: its base and range overlay.
#[derive(Clone, Debug)]
pub struct IpShard {
    pub id: IpShardId,
    pub head: Arc<str>,
    bundle: Arc<str>,
    base_id: Arc<str>,
    base: Arc<IpBase>,
    overlay: Arc<IpOverlay>,
    checksum: SetChecksum,
    seq: u64,
    rich: Arc<RichSegment>,
    /// The largest `rich_idx` the shard holds (base and overlay upserts).
    max_rich: Option<u32>,
}

impl IpShard {
    /// Loads an IP shard base (`ips.bin`, whose BLAKE3 is the base id).
    pub fn load(
        bundle: &str,
        head: Arc<str>,
        base_id: &str,
        base_seq: u64,
        bytes: &[u8],
        rich: Arc<RichSegment>,
    ) -> Result<IpShard, LoadError> {
        verify_blob(bytes, base_id)?;
        let base = IpBase::from_bytes(bytes)?;
        let max_rich = base.max_rich_idx();
        check_rich_idx(max_rich, &rich).map_err(LoadError::Mismatch)?;
        let id = base.shard();
        let overlay = if id.is_v4() {
            IpOverlay::V4(RangeOverlay::new())
        } else {
            IpOverlay::V6(RangeOverlay::new())
        };
        Ok(IpShard {
            id,
            head,
            bundle: bundle.into(),
            base_id: base_id.into(),
            checksum: base.checksum(),
            base: Arc::new(base),
            overlay: Arc::new(overlay),
            seq: base_seq,
            rich,
            max_rich,
        })
    }

    /// A new shard with one IP delta of head `head` applied; see [`IpShard::apply_deltas`].
    pub fn apply_delta(
        &self,
        delta: &[u8],
        head: Arc<str>,
        rich: Arc<RichSegment>,
    ) -> Result<IpShard, LoadError> {
        self.apply_deltas(&[delta], head, rich)
    }

    /// A new shard with a run of its chain applied in order and the range table rebuilt once:
    /// O(ops log ops + table), never O(ops × table) (review round 1, B7). Each delta is read, its
    /// header and checksum checked and its ops staged before the next is read, so the run costs
    /// one parsed delta plus the staged changes, never the whole chain parsed at once (review
    /// round 2, CR2). As for [`HotShard::apply_deltas`], the deltas are `head`'s and the result is
    /// part of `head`, reading `rich`, checked (review round 2, CR4).
    pub fn apply_deltas(
        &self,
        deltas: &[&[u8]],
        head: Arc<str>,
        rich: Arc<RichSegment>,
    ) -> Result<IpShard, LoadError> {
        let base = self.base.clone();
        let (overlay, checksum, seq, max_rich) = match &*self.overlay {
            IpOverlay::V4(o) => {
                let f = |a: u32| base.get(u128::from(a)).map(|(v, _)| v);
                let (o, c, seq, m) = self.stage_chain(o, true, deltas, &f)?;
                (IpOverlay::V4(o), c, seq, m)
            }
            IpOverlay::V6(o) => {
                let f = |a: u128| base.get(a).map(|(v, _)| v);
                let (o, c, seq, m) = self.stage_chain(o, false, deltas, &f)?;
                (IpOverlay::V6(o), c, seq, m)
            }
        };
        check_rich_idx(max_rich, &rich).map_err(LoadError::Mismatch)?;
        Ok(IpShard {
            overlay: Arc::new(overlay),
            checksum,
            seq,
            max_rich,
            head,
            rich,
            ..self.clone()
        })
    }

    /// Reads, checks and stages `deltas` one at a time on top of `overlay`; returns the rebuilt
    /// table, its checksum, the last seq and the largest rich index the shard then holds.
    fn stage_chain<A: Addr>(
        &self,
        overlay: &RangeOverlay<A>,
        v4: bool,
        deltas: &[&[u8]],
        base: &dyn Fn(A) -> Option<Value>,
    ) -> Result<(RangeOverlay<A>, SetChecksum, u64, Option<u32>), LoadError> {
        let mut st = RangeStage::new(overlay, v4, self.checksum);
        let mut seq = self.seq;
        let mut max_rich = self.max_rich;
        for delta in deltas {
            let d = read_range_delta(delta)?;
            let h = &d.header;
            if h.bundle != *self.bundle || h.ip_shard != Some(self.id) {
                return Err(LoadError::Mismatch("delta is for another IP shard".into()));
            }
            if h.base != *self.base_id || h.seq <= seq {
                return Err(LoadError::NeedBase(format!(
                    "delta {} doesn't continue the chain",
                    h.seq
                )));
            }
            let m = d
                .ops
                .iter()
                .filter_map(|o| match o {
                    crate::delta::RangeOp::Upsert { value, .. } => value.rich_idx(),
                    crate::delta::RangeOp::Delete { .. } => None,
                })
                .max();
            max_rich = max_rich.max(m);
            st.apply(&d.ops, h.seq, h.prev_checksum, h.new_checksum, base)?;
            seq = h.seq;
        }
        let (o, c) = st.finish()?;
        Ok((o, c, seq, max_rich))
    }

    /// The same shard, now part of head `head` with that head's `rich.json`; refused when a rich
    /// index it holds names no set of that segment (review round 1, B6).
    pub fn in_head(&self, head: Arc<str>, rich: Arc<RichSegment>) -> Result<IpShard, LoadError> {
        check_rich_idx(self.max_rich, &rich).map_err(LoadError::Mismatch)?;
        Ok(IpShard {
            head,
            rich,
            ..self.clone()
        })
    }

    pub fn rich_arc(&self) -> &Arc<RichSegment> {
        &self.rich
    }

    /// The value at an address (IPv4 in the low 32 bits) and whether it is an address-set hit:
    /// the overlay (a binary search: an upsert gives the value, a tombstone means no IP rule),
    /// otherwise the base.
    pub fn get(&self, addr: u128) -> Option<(Value, bool)> {
        let ov = match &*self.overlay {
            IpOverlay::V4(o) => u32::try_from(addr).ok().and_then(|a| o.get(a)),
            IpOverlay::V6(o) => o.get(addr),
        };
        match ov {
            Some(Entry::Upsert(v)) => Some((Value(v), false)),
            Some(Entry::Tombstone) => None,
            None => self.base.get(addr),
        }
    }

    pub fn rich(&self) -> &RichSegment {
        &self.rich
    }

    pub fn checksum(&self) -> SetChecksum {
        self.checksum
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn base_id(&self) -> &str {
        &self.base_id
    }

    pub fn overlay_bytes(&self) -> usize {
        match &*self.overlay {
            IpOverlay::V4(o) => o.memory_usage(),
            IpOverlay::V6(o) => o.memory_usage(),
        }
    }

    pub fn memory_usage(&self) -> usize {
        self.base.memory_usage().saturating_add(self.overlay_bytes())
    }
}

/// The patterns segment as a part: its patterns, the head it came from, and that head's rich
/// rules.
#[derive(Clone, Debug)]
pub struct PatternsPart {
    pub head: Arc<str>,
    pub patterns: Arc<PatternSegment>,
    pub rich: Arc<RichSegment>,
}

impl PatternsPart {
    /// An empty part (a head with no patterns).
    pub fn empty(head: Arc<str>) -> PatternsPart {
        PatternsPart {
            head,
            patterns: Arc::new(PatternSegment::empty()),
            rich: Arc::new(RichSegment::empty()),
        }
    }

    /// Loads `patterns.bin` within `budget` bytes of automata, reading rich rules from `rich`.
    pub fn load(
        head: Arc<str>,
        id: &str,
        bytes: &[u8],
        budget: usize,
        rich: Arc<RichSegment>,
    ) -> Result<PatternsPart, LoadError> {
        verify_blob(bytes, id)?;
        let patterns = PatternSegment::from_bytes(bytes, budget)?;
        check_rich_idx(patterns.max_rich_idx(), &rich).map_err(LoadError::Mismatch)?;
        Ok(PatternsPart {
            head,
            patterns: Arc::new(patterns),
            rich,
        })
    }

    /// The same segment, now part of head `head` with that head's `rich.json` (a head that keeps
    /// `patterns.bin` moves it at once, edge.md §13); refused when a pattern's rich set names no
    /// set of that segment (review round 1, B6).
    pub fn in_head(&self, head: Arc<str>, rich: Arc<RichSegment>) -> Result<PatternsPart, LoadError> {
        check_rich_idx(self.patterns.max_rich_idx(), &rich).map_err(LoadError::Mismatch)?;
        Ok(PatternsPart {
            head,
            patterns: self.patterns.clone(),
            rich,
        })
    }
}

/// Loads a `rich.json` segment.
pub fn load_rich(id: &str, bytes: &[u8]) -> Result<Arc<RichSegment>, LoadError> {
    verify_blob(bytes, id)?;
    Ok(Arc::new(RichSegment::from_bytes(bytes)?))
}
