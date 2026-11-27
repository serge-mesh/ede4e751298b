//! Lookup verdict sets (providers.md §4 "Verdict cache", edge.md §10, core.md §7).
//!
//! A verdict set is core's read-only copy of one lookup provider's verdicts for one cache
//! generation. Its head is `{provider, format, generation, hash_seed, base, deltas: [{seq, blake3,
//! size}]}` (plus, additively, `seq`, `checksum` and `issued_at`). The base is a page file
//! ([`crate::page`]) whose records are keyed by `xxh3_128(hash_seed, name)` with the name in log
//! text form (for the ordinary names providers see, the dotted name); deltas use the bundle delta
//! line format keyed by that hash in hex.
//!
//! **Record value** (format 1, little-endian): version `u8` (1), verdict `u8` (1 block, 2 clean,
//! 3 unknown), `obtained_at` `i64` (µs since the Unix epoch), presence flags `u8` (bit 0 score,
//! bit 1 reason), then the score (`f32`) and the reason (`u16` length + UTF-8, at most
//! [`MAX_REASON`] bytes) when present. Decoding refuses anything else.
//!
//! On the edge: the overlay in RAM, then one page read (open, `pread`, close, in a blocking
//! thread). A page failing its checksum is a miss ([`VerdictSet::lookup`] returns the error so the
//! edge refetches the file and logs `page_file_refetched`).

use std::sync::Arc;

use picket_api::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::FORMAT;
use crate::bytes::{ByteReader, is_object_id};
use crate::checksum::SetChecksum;
use crate::delta::{DeltaError, gzip, read_lines};
use crate::hash::{KeyHash, verdict_hash_seed};
use crate::head::{DeltaRef, HeadError, MAX_CHAIN, MAX_HEAD_BYTES, verify_blob};
use crate::overlay::{Entry, HashOverlay, MAX_OVERLAY_ENTRIES, OverlayError, OverlayValue};
use crate::page::{self, PAGE_SIZE, PageError, PageFileKind, PageReader, PageWriteError};
use crate::writer::Blob;

/// The longest reason a record keeps.
pub const MAX_REASON: usize = 512;

/// A verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictKind {
    Block,
    Clean,
    Unknown,
}

/// One cached verdict.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub verdict: VerdictKind,
    /// When the provider answered: microseconds in a record, chrono's default serde form in delta
    /// lines (as always: blobs are content-addressed and older edges read them).
    #[serde(with = "picket_api::time::autosi")]
    pub obtained_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Why a record can't be encoded or decoded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("verdict record is malformed")]
    Malformed,
    #[error("score isn't finite")]
    Score,
    #[error("reason is longer than {MAX_REASON} bytes")]
    Reason,
}

impl VerdictRecord {
    /// The record's value bytes (canonical, so checksums agree).
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::with_capacity(16);
        out.push(1u8);
        out.push(match self.verdict {
            VerdictKind::Block => 1,
            VerdictKind::Clean => 2,
            VerdictKind::Unknown => 3,
        });
        out.extend_from_slice(&self.obtained_at.as_microsecond().to_le_bytes());
        let mut flags = 0u8;
        if self.score.is_some() {
            flags |= 1;
        }
        if self.reason.is_some() {
            flags |= 2;
        }
        out.push(flags);
        if let Some(s) = self.score {
            if !s.is_finite() {
                return Err(RecordError::Score);
            }
            out.extend_from_slice(&s.to_le_bytes());
        }
        if let Some(r) = &self.reason {
            if r.len() > MAX_REASON {
                return Err(RecordError::Reason);
            }
            out.extend_from_slice(
                &u16::try_from(r.len())
                    .map_err(|_| RecordError::Reason)?
                    .to_le_bytes(),
            );
            out.extend_from_slice(r.as_bytes());
        }
        Ok(out)
    }

    /// Decodes a record's value bytes.
    pub fn decode(b: &[u8]) -> Result<VerdictRecord, RecordError> {
        let m = |_| RecordError::Malformed;
        let mut r = ByteReader::new(b);
        if r.u8().map_err(m)? != 1 {
            return Err(RecordError::Malformed);
        }
        let verdict = match r.u8().map_err(m)? {
            1 => VerdictKind::Block,
            2 => VerdictKind::Clean,
            3 => VerdictKind::Unknown,
            _ => return Err(RecordError::Malformed),
        };
        let us = i64::from_le_bytes(r.array().map_err(m)?);
        let obtained_at = Timestamp::from_microsecond(us).map_err(|_| RecordError::Malformed)?;
        let flags = r.u8().map_err(m)?;
        if flags & !3 != 0 {
            return Err(RecordError::Malformed);
        }
        let score = if flags & 1 != 0 {
            let s = f32::from_le_bytes(r.array().map_err(m)?);
            if !s.is_finite() {
                return Err(RecordError::Score);
            }
            Some(s)
        } else {
            None
        };
        let reason = if flags & 2 != 0 {
            let n = usize::from(r.u16().map_err(m)?);
            if n > MAX_REASON {
                return Err(RecordError::Reason);
            }
            Some(
                std::str::from_utf8(r.bytes(n).map_err(m)?)
                    .map_err(|_| RecordError::Malformed)?
                    .to_string(),
            )
        } else {
            None
        };
        if r.remaining() != 0 {
            return Err(RecordError::Malformed);
        }
        Ok(VerdictRecord {
            verdict,
            obtained_at,
            score,
            reason,
        })
    }
}

/// Verdict-set overlay slots: `None` empty, else the entry; a record's reason is its heap.
impl OverlayValue for VerdictRecord {
    type Slot = Option<Entry<VerdictRecord>>;
    fn empty() -> Self::Slot {
        None
    }
    fn is_empty(s: &Self::Slot) -> bool {
        s.is_none()
    }
    fn pack(e: Entry<VerdictRecord>) -> Self::Slot {
        Some(e)
    }
    fn unpack(s: &Self::Slot) -> Entry<&VerdictRecord> {
        match s {
            Some(Entry::Upsert(r)) => Entry::Upsert(r),
            _ => Entry::Tombstone,
        }
    }
    fn heap(s: &Self::Slot) -> usize {
        match s {
            Some(Entry::Upsert(r)) => r.reason.as_ref().map_or(0, String::capacity),
            _ => 0,
        }
    }
}

impl VerdictRecord {
    /// The record as its value bytes hold it: `obtained_at` in whole microseconds (edge.md §10's
    /// RAM-tier drop compares it with records from the base, which keep microseconds; review
    /// round 1, B12).
    pub fn canonical(&self) -> Result<VerdictRecord, RecordError> {
        VerdictRecord::decode(&self.encode()?)
    }
}

/// A verdict set's head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictHead {
    /// The lookup provider's id.
    pub provider: String,
    pub format: u32,
    /// The provider's `cache_generation` (16 hex characters).
    pub generation: String,
    pub hash_seed: u64,
    /// The base page file's id.
    pub base: String,
    pub deltas: Vec<DeltaRef>,
    /// The current seq (additive).
    #[serde(default)]
    pub seq: u64,
    /// The set checksum after the chain, which binds the head to its base and deltas: the
    /// reader always checks it (an empty set's is zero).
    #[serde(default)]
    pub checksum: SetChecksum,
    #[serde(default)]
    pub issued_at: String,
}

impl VerdictHead {
    pub fn to_blob(&self) -> Blob {
        Blob::new(serde_json::to_vec(self).unwrap_or_default())
    }

    /// Parses and validates a verdict-set head.
    pub fn from_bytes(data: &[u8]) -> Result<VerdictHead, HeadError> {
        if data.len() > MAX_HEAD_BYTES {
            return Err(HeadError::TooLarge);
        }
        let h: VerdictHead = serde_json::from_slice(data)?;
        if h.format != FORMAT {
            return Err(HeadError::Format(h.format));
        }
        if h.provider.is_empty() || h.provider.len() > 255 || !is_object_id(&h.base) {
            return Err(HeadError::Invalid("provider or base".into()));
        }
        if h.deltas.len() > MAX_CHAIN {
            return Err(HeadError::Invalid("delta chain too long".into()));
        }
        let mut prev = 0u64;
        for d in &h.deltas {
            if !is_object_id(&d.blake3) || d.seq <= prev {
                return Err(HeadError::Invalid(format!("bad delta {}", d.seq)));
            }
            prev = d.seq;
        }
        Ok(h)
    }
}

/// A verdict-set delta's header line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictDeltaHeader {
    pub provider: String,
    pub generation: String,
    pub base: String,
    pub seq: u64,
    pub prev_checksum: SetChecksum,
    pub new_checksum: SetChecksum,
    pub created_at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum VerdictOpLine {
    Upsert { key: String, value: VerdictRecord },
    Delete { key: String },
}

/// One verdict change: a name's record before and after.
#[derive(Clone, Debug, PartialEq)]
pub struct VerdictChange {
    pub hash: KeyHash,
    pub old: Option<VerdictRecord>,
    pub new: Option<VerdictRecord>,
}

/// The hash of a name in a verdict set (`name` in log text form).
pub fn name_hash(hash_seed: u64, name: &str) -> KeyHash {
    KeyHash::of(hash_seed, name.as_bytes())
}

/// Why a verdict set can't be written.
#[derive(Debug, thiserror::Error)]
pub enum VerdictWriteError {
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error(transparent)]
    Page(#[from] PageWriteError),
}

/// A written verdict-set base and its checksum.
#[derive(Clone, Debug)]
pub struct VerdictBase {
    pub blob: Blob,
    pub checksum: SetChecksum,
}

/// Writes a verdict-set base from (name hash, record) pairs.
pub fn write_base(
    provider: &str,
    generation: &str,
    records: &[(KeyHash, VerdictRecord)],
) -> Result<VerdictBase, VerdictWriteError> {
    let seed = verdict_hash_seed(provider, generation);
    let mut recs: Vec<(u128, Vec<u8>)> = Vec::with_capacity(records.len());
    let mut cs = SetChecksum::ZERO;
    for (h, r) in records {
        let v = r.encode()?;
        cs = cs.plus(SetChecksum::record_entry(h.0, &v));
        recs.push((h.0, v));
    }
    let gen_field = crate::bytes::from_hex::<8>(generation).map_or(0, u64::from_be_bytes);
    let bytes = page::write(PageFileKind::VerdictSet, cs.0, seed, gen_field, &mut recs)?;
    Ok(VerdictBase {
        blob: Blob::new(bytes),
        checksum: cs,
    })
}

/// Writes a verdict-set delta: upserts then deletes, each sorted by hash.
pub fn write_delta(
    provider: &str,
    generation: &str,
    base: &str,
    seq: u64,
    prev: SetChecksum,
    changes: &[VerdictChange],
    created_at: &str,
) -> Result<(Blob, VerdictDeltaHeader), VerdictWriteError> {
    let mut cs = prev;
    let mut ups: Vec<(KeyHash, VerdictRecord)> = Vec::new();
    let mut dels: Vec<KeyHash> = Vec::new();
    for c in changes {
        if c.old == c.new {
            continue;
        }
        if let Some(o) = &c.old {
            cs = cs.minus(SetChecksum::record_entry(c.hash.0, &o.encode()?));
        }
        match &c.new {
            Some(n) => {
                cs = cs.plus(SetChecksum::record_entry(c.hash.0, &n.encode()?));
                ups.push((c.hash, n.canonical()?));
            }
            None => dels.push(c.hash),
        }
    }
    ups.sort_by_key(|(h, _)| *h);
    dels.sort();
    let header = VerdictDeltaHeader {
        provider: provider.to_string(),
        generation: generation.to_string(),
        base: base.to_string(),
        seq,
        prev_checksum: prev,
        new_checksum: cs,
        created_at: created_at.to_string(),
    };
    let mut lines = vec![serde_json::to_vec(&header).unwrap_or_default()];
    for (h, r) in ups {
        lines.push(
            serde_json::to_vec(&VerdictOpLine::Upsert {
                key: h.to_hex(),
                value: r,
            })
            .unwrap_or_default(),
        );
    }
    for h in dels {
        lines.push(serde_json::to_vec(&VerdictOpLine::Delete { key: h.to_hex() }).unwrap_or_default());
    }
    Ok((Blob::new(gzip(&lines)), header))
}

/// A parsed verdict-set delta.
#[derive(Clone, Debug, PartialEq)]
pub struct VerdictDelta {
    pub header: VerdictDeltaHeader,
    pub ops: Vec<(KeyHash, Option<VerdictRecord>)>,
}

/// Parses a verdict-set delta.
pub fn read_delta(data: &[u8]) -> Result<VerdictDelta, DeltaError> {
    let mut header: Option<VerdictDeltaHeader> = None;
    let mut ops = Vec::new();
    read_lines(data, |n, line| {
        if header.is_none() {
            header =
                Some(serde_json::from_slice(line).map_err(|source| DeltaError::Json { line: n, source })?);
            return Ok(());
        }
        if ops.len() >= crate::delta::MAX_OPS {
            return Err(DeltaError::TooManyOps);
        }
        let op: VerdictOpLine =
            serde_json::from_slice(line).map_err(|source| DeltaError::Json { line: n, source })?;
        let (key, rec) = match op {
            // Canonical (whole microseconds), as the base and the checksums hold it.
            VerdictOpLine::Upsert { key, value } => (
                key,
                Some(value.canonical().map_err(|_| DeltaError::Op(n, "value"))?),
            ),
            VerdictOpLine::Delete { key } => (key, None),
        };
        let h = KeyHash::from_hex(&key).ok_or(DeltaError::Op(n, "key"))?;
        ops.push((h, rec));
        Ok(())
    })?;
    let header = header.ok_or(DeltaError::NoHeader)?;
    Ok(VerdictDelta { header, ops })
}

/// Why a verdict set can't be loaded or a delta applied.
#[derive(Debug, thiserror::Error)]
pub enum VerdictLoadError {
    #[error(transparent)]
    Head(#[from] HeadError),
    #[error(transparent)]
    Page(#[from] PageError),
    #[error(transparent)]
    Delta(#[from] DeltaError),
    #[error("need base: {0}")]
    NeedBase(String),
    #[error("{0}")]
    Mismatch(String),
}

impl From<OverlayError> for VerdictLoadError {
    fn from(e: OverlayError) -> Self {
        match e {
            OverlayError::Base(p) => VerdictLoadError::Page(p),
            other => VerdictLoadError::NeedBase(other.to_string()),
        }
    }
}

/// A verdict set on the edge: the overlay in RAM, the base on the SSD.
#[derive(Clone, Debug)]
pub struct VerdictSet {
    pub provider: Arc<str>,
    pub generation: Arc<str>,
    /// The head this set came from.
    pub head: Arc<str>,
    hash_seed: u64,
    base_id: Arc<str>,
    page_count: u32,
    identity: u128,
    overlay: Arc<HashOverlay<VerdictRecord>>,
    checksum: SetChecksum,
    seq: u64,
}

impl VerdictSet {
    /// Loads a verdict set's base from its head and the page file's header page.
    pub fn load(
        head_id: Arc<str>,
        head: &VerdictHead,
        header_page: &[u8],
    ) -> Result<VerdictSet, VerdictLoadError> {
        let h = page::PageFileHeader::parse(header_page)?;
        if h.kind != PageFileKind::VerdictSet || h.hash_seed != head.hash_seed {
            return Err(VerdictLoadError::Mismatch("base doesn't match its head".into()));
        }
        if head.hash_seed != verdict_hash_seed(&head.provider, &head.generation) {
            return Err(VerdictLoadError::Mismatch(
                "hash_seed doesn't match provider and generation".into(),
            ));
        }
        Ok(VerdictSet {
            provider: head.provider.as_str().into(),
            generation: head.generation.as_str().into(),
            head: head_id,
            hash_seed: head.hash_seed,
            base_id: head.base.as_str().into(),
            page_count: h.page_count,
            identity: h.identity,
            overlay: Arc::new(HashOverlay::new()),
            checksum: SetChecksum(h.identity),
            seq: 0,
        })
    }

    /// The hash of a name (log text form).
    pub fn hash(&self, name: &str) -> KeyHash {
        name_hash(self.hash_seed, name)
    }

    fn base_record(&self, h: KeyHash, reader: &dyn PageReader) -> Result<Option<Vec<u8>>, PageError> {
        let mut buf = [0u8; PAGE_SIZE];
        page::read_record(
            reader,
            &self.base_id,
            self.identity,
            self.page_count,
            h.0,
            &mut buf,
        )
    }

    /// The overlay's entry for a hash: `Some(Some(record))` an upsert, `Some(None)` a tombstone,
    /// `None` not in the overlay (read the page).
    pub fn overlay_get(&self, h: KeyHash) -> Option<Option<&VerdictRecord>> {
        match self.overlay.get(h.0)? {
            Entry::Upsert(r) => Some(Some(r)),
            Entry::Tombstone => Some(None),
        }
    }

    /// Looks a name up: the overlay, then one page read. A page failing its checksum is an
    /// error the edge treats as a miss (and refetches the file).
    pub fn lookup(&self, name: &str, reader: &dyn PageReader) -> Result<Option<VerdictRecord>, PageError> {
        self.lookup_hash(self.hash(name), reader)
    }

    /// [`VerdictSet::lookup`] by hash.
    pub fn lookup_hash(
        &self,
        h: KeyHash,
        reader: &dyn PageReader,
    ) -> Result<Option<VerdictRecord>, PageError> {
        if let Some(e) = self.overlay_get(h) {
            return Ok(e.cloned());
        }
        match self.base_record(h, reader)? {
            None => Ok(None),
            Some(b) => VerdictRecord::decode(&b)
                .map(Some)
                .map_err(|_| PageError::Malformed(0)),
        }
    }

    /// A new set with one delta applied (checksum checked; a mismatch means fetch the base).
    pub fn apply_delta(&self, delta: &[u8], reader: &dyn PageReader) -> Result<VerdictSet, VerdictLoadError> {
        self.apply_deltas(&[delta], reader)
    }

    /// A new set with a run of its chain applied in order, each delta's header and checksum
    /// checked in turn, and the overlay rebuilt once (boot replay: review round 1, B7).
    pub fn apply_deltas(
        &self,
        deltas: &[&[u8]],
        reader: &dyn PageReader,
    ) -> Result<VerdictSet, VerdictLoadError> {
        let mut cs = self.checksum;
        let mut seq = self.seq;
        let mut changes: std::collections::HashMap<u128, Entry<VerdictRecord>> =
            std::collections::HashMap::new();
        for delta in deltas {
            let d = read_delta(delta)?;
            let h = &d.header;
            if h.provider != *self.provider || h.generation != *self.generation {
                return Err(VerdictLoadError::Mismatch(
                    "delta is for another verdict set".into(),
                ));
            }
            if h.base != *self.base_id || h.seq <= seq || h.prev_checksum != cs {
                return Err(VerdictLoadError::NeedBase(format!(
                    "delta {} doesn't continue the chain",
                    h.seq
                )));
            }
            for (hash, rec) in d.ops {
                let current: Option<Vec<u8>> = match changes.get(&hash.0) {
                    Some(Entry::Upsert(r)) => r.encode().ok(),
                    Some(Entry::Tombstone) => None,
                    None => match self.overlay.get(hash.0) {
                        Some(Entry::Upsert(r)) => r.encode().ok(),
                        Some(Entry::Tombstone) => None,
                        None => self.base_record(hash, reader)?,
                    },
                };
                if let Some(old) = current {
                    cs = cs.minus(SetChecksum::record_entry(hash.0, &old));
                }
                match rec {
                    Some(r) => {
                        let v = r
                            .encode()
                            .map_err(|e| VerdictLoadError::Mismatch(e.to_string()))?;
                        cs = cs.plus(SetChecksum::record_entry(hash.0, &v));
                        changes.insert(hash.0, Entry::Upsert(r));
                    }
                    None => {
                        changes.insert(hash.0, Entry::Tombstone);
                    }
                }
                if changes.len() > MAX_OVERLAY_ENTRIES {
                    return Err(OverlayError::TooLarge(MAX_OVERLAY_ENTRIES).into());
                }
            }
            if cs != h.new_checksum {
                return Err(VerdictLoadError::NeedBase(format!(
                    "checksum mismatch after delta {}",
                    h.seq
                )));
            }
            seq = h.seq;
        }
        Ok(VerdictSet {
            overlay: Arc::new(self.overlay.with_changes(changes)?),
            checksum: cs,
            seq,
            ..self.clone()
        })
    }

    /// The same set under a new head (a head adding deltas only).
    pub fn in_head(&self, head: Arc<str>) -> VerdictSet {
        VerdictSet { head, ..self.clone() }
    }

    pub fn checksum(&self) -> SetChecksum {
        self.checksum
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The base page file's id.
    pub fn base_id(&self) -> &str {
        &self.base_id
    }

    /// Hashes the delta touches with an `obtained_at` (for dropping older RAM-tier entries on
    /// activation, edge.md §10).
    pub fn overlay_entries(&self) -> impl Iterator<Item = (u128, Option<&VerdictRecord>)> {
        self.overlay.iter().map(|(h, e)| {
            (
                h,
                match e {
                    Entry::Upsert(r) => Some(r),
                    Entry::Tombstone => None,
                },
            )
        })
    }

    /// Bytes of the overlay (counted against `overlay_budget_mib`).
    pub fn overlay_bytes(&self) -> usize {
        self.overlay.memory_usage()
    }
}

/// Loads a verdict set from its head bytes, its delta blobs and the page file (via `reader`).
pub fn load_verdict_set(
    head_bytes: &[u8],
    deltas: &dyn Fn(&str) -> Option<Vec<u8>>,
    reader: &dyn PageReader,
) -> Result<VerdictSet, VerdictLoadError> {
    let head = VerdictHead::from_bytes(head_bytes)?;
    let head_id: Arc<str> = crate::bytes::object_id(head_bytes).into();
    let mut hdr = [0u8; PAGE_SIZE];
    reader
        .read_page(&head.base, 0, &mut hdr)
        .map_err(|e| PageError::Io(e.to_string()))?;
    let set = VerdictSet::load(head_id, &head, &hdr)?;
    let mut blobs = Vec::with_capacity(head.deltas.len());
    for d in &head.deltas {
        let b = deltas(&d.blake3)
            .ok_or_else(|| VerdictLoadError::Mismatch(format!("missing delta {}", d.blake3)))?;
        verify_blob(&b, &d.blake3)?;
        blobs.push(b);
    }
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let set = if refs.is_empty() {
        set
    } else {
        set.apply_deltas(&refs, reader)?
    };
    // The head's checksum binds it to the base and chain it names, whatever its value (an empty
    // set's is zero; review round 1, B12).
    if set.checksum != head.checksum {
        return Err(VerdictLoadError::NeedBase("checksum after the chain".into()));
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::MemPages;

    fn rec(v: VerdictKind, s: Option<f32>, r: Option<&str>) -> VerdictRecord {
        VerdictRecord {
            verdict: v,
            obtained_at: Timestamp::from_microsecond(1_763_700_000_123_456).unwrap(),
            score: s,
            reason: r.map(String::from),
        }
    }

    /// Golden (F2 in verdict delta lines, F11 in record bytes; plan §5 step 1, unchanged after
    /// the move to jiff): a record holds `obtained_at` as i64 microseconds, and a delta line
    /// writes it in chrono's default serde form (0, 3 or 6 digits once canonical).
    #[test]
    fn golden_obtained_at() {
        use picket_api::time::golden::{ROWS, ts_from_nanos};
        for r in ROWS {
            let t = ts_from_nanos(r.nanos);
            let rec = VerdictRecord {
                verdict: VerdictKind::Block,
                obtained_at: t,
                score: None,
                reason: None,
            };
            let bytes = rec.encode().unwrap();
            let mut want = vec![1u8, 1];
            want.extend_from_slice(&r.unix_us.to_le_bytes());
            want.push(0);
            assert_eq!(bytes, want, "{}", r.name);
            let canonical = VerdictRecord::decode(&bytes).unwrap();
            assert_eq!(
                canonical.obtained_at,
                ts_from_nanos(i128::from(r.unix_us) * 1_000),
                "{}",
                r.name
            );
            assert_eq!(rec.canonical().unwrap(), canonical, "{}", r.name);
            let json = serde_json::to_string(&rec).unwrap();
            assert_eq!(
                json,
                format!(r#"{{"verdict":"block","obtained_at":"{}"}}"#, r.autosi),
                "{}",
                r.name
            );
            assert_eq!(
                serde_json::from_str::<VerdictRecord>(&json).unwrap(),
                rec,
                "{}",
                r.name
            );
        }
        // Whole delta lines, at whole seconds and at a fraction with a trailing zero.
        let at = |n: i128| VerdictRecord {
            verdict: VerdictKind::Clean,
            obtained_at: ts_from_nanos(n),
            score: Some(0.5),
            reason: Some("r".into()),
        };
        let changes = [
            VerdictChange {
                hash: KeyHash(1),
                old: None,
                new: Some(at(1_794_565_321_000_000_000)),
            },
            VerdictChange {
                hash: KeyHash(2),
                old: None,
                new: Some(at(1_794_565_321_120_000_789)),
            },
        ];
        let (blob, _) = write_delta(
            "p",
            "0000000000000001",
            "b",
            1,
            SetChecksum::ZERO,
            &changes,
            "2026-11-13T10:22:01.000000Z",
        )
        .unwrap();
        let mut text = String::new();
        std::io::Read::read_to_string(
            &mut flate2::read::GzDecoder::new(blob.bytes.as_slice()),
            &mut text,
        )
        .unwrap();
        let lines: Vec<&str> = text.lines().skip(1).collect();
        assert_eq!(
            lines,
            [
                r#"{"op":"upsert","key":"00000000000000000000000000000001","value":{"verdict":"clean","obtained_at":"2026-11-13T10:22:01Z","score":0.5,"reason":"r"}}"#,
                r#"{"op":"upsert","key":"00000000000000000000000000000002","value":{"verdict":"clean","obtained_at":"2026-11-13T10:22:01.120Z","score":0.5,"reason":"r"}}"#,
            ]
        );
    }

    #[test]
    fn records_roundtrip_and_refuse() {
        for r in [
            rec(VerdictKind::Block, Some(7.5), Some("malware")),
            rec(VerdictKind::Clean, None, None),
            rec(VerdictKind::Unknown, None, Some("")),
        ] {
            let b = r.encode().unwrap();
            assert_eq!(VerdictRecord::decode(&b).unwrap(), r);
        }
        assert!(rec(VerdictKind::Block, Some(f32::NAN), None).encode().is_err());
        let long = "x".repeat(MAX_REASON + 1);
        assert!(rec(VerdictKind::Block, None, Some(&long)).encode().is_err());
        assert!(VerdictRecord::decode(&[1, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(VerdictRecord::decode(&[]).is_err());
    }

    /// B12: a delta's `obtained_at` with sub-microsecond digits is held as the base and the
    /// checksums hold it, in whole microseconds.
    #[test]
    fn delta_records_are_canonical_microseconds() {
        let provider = "q9";
        let generation = "b71e4d09a2c63f58";
        let seed = verdict_hash_seed(provider, generation);
        let base = write_base(provider, generation, &[]).unwrap();
        let ns = Timestamp::new(1_763_700_000, 123_456_789).unwrap();
        let r = VerdictRecord {
            verdict: VerdictKind::Block,
            obtained_at: ns,
            score: None,
            reason: None,
        };
        let h = name_hash(seed, "x.example");
        // A delta as a writer that kept nanoseconds would send it.
        let header = VerdictDeltaHeader {
            provider: provider.into(),
            generation: generation.into(),
            base: base.blob.id.clone(),
            seq: 1,
            prev_checksum: SetChecksum::ZERO,
            new_checksum: SetChecksum::ZERO.plus(SetChecksum::record_entry(h.0, &r.encode().unwrap())),
            created_at: "t".into(),
        };
        let lines = vec![
            serde_json::to_vec(&header).unwrap(),
            serde_json::to_vec(&VerdictOpLine::Upsert {
                key: h.to_hex(),
                value: r.clone(),
            })
            .unwrap(),
        ];
        let delta = gzip(&lines);
        let pages = MemPages {
            files: [(base.blob.id.clone(), base.blob.bytes.clone())]
                .into_iter()
                .collect(),
        };
        let mut hdr = [0u8; PAGE_SIZE];
        pages.read_page(&base.blob.id, 0, &mut hdr).unwrap();
        let vh = VerdictHead {
            provider: provider.into(),
            format: FORMAT,
            generation: generation.into(),
            hash_seed: seed,
            base: base.blob.id.clone(),
            deltas: vec![],
            seq: 0,
            checksum: SetChecksum::ZERO,
            issued_at: String::new(),
        };
        let set = VerdictSet::load("h".into(), &vh, &hdr).unwrap();
        let set = set.apply_delta(&delta, &pages).unwrap();
        let got = set.lookup_hash(h, &pages).unwrap().unwrap();
        let us = Timestamp::new(1_763_700_000, 123_456_000).unwrap();
        assert_eq!(got.obtained_at, us);
        assert_eq!(set.overlay_entries().next().unwrap().1.unwrap().obtained_at, us);
        // The writer sends the canonical form too.
        let (b, _) = write_delta(
            provider,
            generation,
            &base.blob.id,
            1,
            SetChecksum::ZERO,
            &[VerdictChange {
                hash: h,
                old: None,
                new: Some(r),
            }],
            "t",
        )
        .unwrap();
        let d = read_delta(&b.bytes).unwrap();
        assert_eq!(d.ops[0].1.as_ref().unwrap().obtained_at, us);
    }

    #[test]
    fn set_with_deltas() {
        let provider = "q9";
        let generation = "b71e4d09a2c63f58";
        let seed = verdict_hash_seed(provider, generation);
        let names = ["bad.example.org", "good.example.org", "meh.example.org"];
        let base_recs = vec![
            (
                name_hash(seed, names[0]),
                rec(VerdictKind::Block, Some(9.0), Some("blocked")),
            ),
            (name_hash(seed, names[1]), rec(VerdictKind::Clean, None, None)),
        ];
        let base = write_base(provider, generation, &base_recs).unwrap();
        let (d1, d1h) = write_delta(
            provider,
            generation,
            &base.blob.id,
            1,
            base.checksum,
            &[
                VerdictChange {
                    hash: name_hash(seed, names[1]),
                    old: Some(base_recs[1].1.clone()),
                    new: None,
                },
                VerdictChange {
                    hash: name_hash(seed, names[2]),
                    old: None,
                    new: Some(rec(VerdictKind::Unknown, None, None)),
                },
            ],
            "2026-11-21T00:00:00Z",
        )
        .unwrap();
        let mut head = VerdictHead {
            provider: provider.into(),
            format: FORMAT,
            generation: generation.into(),
            hash_seed: seed,
            base: base.blob.id.clone(),
            deltas: vec![DeltaRef {
                seq: 1,
                blake3: d1.id.clone(),
                size: d1.size(),
            }],
            seq: 1,
            checksum: d1h.new_checksum,
            issued_at: String::new(),
        };
        let pages = MemPages {
            files: [(base.blob.id.clone(), base.blob.bytes.clone())]
                .into_iter()
                .collect(),
        };
        let deltas = |id: &str| (id == d1.id).then(|| d1.bytes.clone());
        let set = load_verdict_set(&head.to_blob().bytes, &deltas, &pages).unwrap();
        assert_eq!(
            set.lookup(names[0], &pages).unwrap().unwrap().verdict,
            VerdictKind::Block
        );
        assert_eq!(set.lookup(names[1], &pages).unwrap(), None, "deleted");
        assert_eq!(
            set.lookup(names[2], &pages).unwrap().unwrap().verdict,
            VerdictKind::Unknown
        );
        assert_eq!(set.lookup("other.example", &pages).unwrap(), None);
        // A wrong checksum in the head is caught, and so is a zero one: the binding is always
        // checked (review round 1, B12).
        for bad in [SetChecksum(1), SetChecksum::ZERO] {
            head.checksum = bad;
            assert!(matches!(
                load_verdict_set(&head.to_blob().bytes, &deltas, &pages),
                Err(VerdictLoadError::NeedBase(_))
            ));
        }
        // An empty set's checksum is zero, and binds as such.
        let empty = write_base(provider, generation, &[]).unwrap();
        assert_eq!(empty.checksum, SetChecksum::ZERO);
        let eh = VerdictHead {
            base: empty.blob.id.clone(),
            deltas: vec![],
            seq: 0,
            checksum: SetChecksum::ZERO,
            ..head.clone()
        };
        let ep = MemPages {
            files: [(empty.blob.id.clone(), empty.blob.bytes.clone())]
                .into_iter()
                .collect(),
        };
        assert!(load_verdict_set(&eh.to_blob().bytes, &|_: &str| None, &ep).is_ok());
        // A delta applied twice doesn't continue the chain.
        assert!(matches!(
            set.apply_delta(&d1.bytes, &pages),
            Err(VerdictLoadError::NeedBase(_))
        ));
    }
}
