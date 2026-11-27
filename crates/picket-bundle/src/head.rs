//! `head.json` and `manifest.json` (bundles.md §4), and blob verification (bundles.md §5
//! "Integrity").
//!
//! A head names everything in one bundle version: the shard directories, each hot, cold and IP
//! shard's base and delta chain, the two segments, `ip_pattern_classes`, `feed_runs` and
//! `issued_at`. Its id is the BLAKE3 of its bytes. Beyond the spec's fields it carries (additive,
//! README §2 "Compatibility") `action` (the bundle's action, which decides how a match counts),
//! `max_shard_keys`, `next_shard` / `next_cold_shard` (shard numbers are never reused) and each
//! shard's `base_seq`. A manifest describes one hot or cold shard base; the base id is the BLAKE3
//! of the manifest. JSON readers ignore unknown fields and bound sizes and counts.

use std::collections::BTreeMap;

use picket_rules::matcher::BundleAction;
use serde::{Deserialize, Serialize};

use crate::FORMAT;
use crate::bytes::{is_object_id, object_id};
use crate::checksum::SetChecksum;
use crate::ips::IpShardId;
use crate::shard_dir::{ShardDir, ShardEntry};

/// Largest head or manifest the reader accepts.
pub const MAX_HEAD_BYTES: usize = 16 * 1024 * 1024;
/// Most deltas in one shard's chain (core compacts after 1,000: bundles.md §5).
pub const MAX_CHAIN: usize = 4096;
/// The patterns segment's name.
pub const PATTERNS: &str = "patterns.bin";
/// The rich segment's name.
pub const RICH: &str = "rich.json";

/// Why a head, manifest or blob is refused.
#[derive(Debug, thiserror::Error)]
pub enum HeadError {
    #[error("larger than {MAX_HEAD_BYTES} bytes")]
    TooLarge,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("format {0} is not supported")]
    Format(u32),
    #[error("{0}")]
    Invalid(String),
    #[error("blake3 mismatch: expected {expected}, got {got}")]
    Blake3 { expected: String, got: String },
}

fn invalid(s: impl Into<String>) -> HeadError {
    HeadError::Invalid(s.into())
}

/// Verifies a blob against its id (the edge verifies every blob before activation).
pub fn verify_blob(bytes: &[u8], id: &str) -> Result<(), HeadError> {
    let got = object_id(bytes);
    if got == id {
        Ok(())
    } else {
        Err(HeadError::Blake3 {
            expected: id.to_string(),
            got,
        })
    }
}

/// One delta in a chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaRef {
    pub seq: u64,
    pub blake3: String,
    pub size: u64,
}

/// A hot or cold shard in a head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardRef {
    pub shard: u32,
    /// The base id (BLAKE3 of its manifest).
    pub base: String,
    /// The current seq: the last delta's, or the base's.
    pub seq: u64,
    /// The set checksum after the whole chain.
    pub checksum: SetChecksum,
    pub deltas: Vec<DeltaRef>,
    /// The seq the base was built at (additive).
    #[serde(default)]
    pub base_seq: u64,
}

/// An IP shard in a head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpShardRef {
    pub ip_shard: IpShardId,
    /// The base id (BLAKE3 of its `ips.bin`).
    pub base: String,
    pub seq: u64,
    pub checksum: SetChecksum,
    pub deltas: Vec<DeltaRef>,
    #[serde(default)]
    pub base_seq: u64,
}

/// The precedence classes of a bundle's IP-text patterns (rules.md §6, bundles.md §6): the rules
/// other than IP literals that can match an address's text. The edge's IPv4 fast path (a set hit
/// blocks at once) needs no `allow`, `important_allow` or `rewrite` class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpPatternClass {
    /// `@@…$important`.
    ImportantAllow,
    /// `…$important` block.
    Important,
    /// `@@`.
    Allow,
    /// Block.
    Block,
    /// `$dnsrewrite` (it would answer before a block; additive).
    Rewrite,
    /// A host-IP mapping (ranks below every network rule; additive).
    Mapping,
    /// A class a later release added: treated as able to change a decision.
    #[serde(other)]
    Unknown,
}

impl IpPatternClass {
    /// True when a pattern of this class can change a set hit's block.
    pub fn defeats_set_hit(self) -> bool {
        matches!(
            self,
            IpPatternClass::ImportantAllow
                | IpPatternClass::Allow
                | IpPatternClass::Rewrite
                | IpPatternClass::Unknown
        )
    }
}

/// `head.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub bundle: String,
    pub format: u32,
    pub hash_seed: u64,
    pub shard_dir: Vec<ShardEntry>,
    pub shards: Vec<ShardRef>,
    #[serde(default)]
    pub cold_shard_dir: Vec<ShardEntry>,
    #[serde(default)]
    pub cold_shards: Vec<ShardRef>,
    #[serde(default)]
    pub ip_shards: Vec<IpShardRef>,
    pub segments: BTreeMap<String, String>,
    #[serde(default)]
    pub ip_pattern_classes: Vec<IpPatternClass>,
    #[serde(default)]
    pub feed_runs: BTreeMap<String, u64>,
    pub issued_at: String,
    /// The bundle's action (additive; `block` when missing).
    #[serde(default = "default_action")]
    pub action: BundleAction,
    #[serde(default)]
    pub max_shard_keys: u64,
    #[serde(default)]
    pub next_shard: u32,
    #[serde(default)]
    pub next_cold_shard: u32,
}

fn default_action() -> BundleAction {
    BundleAction::Block
}

impl Head {
    /// The head's bytes (deterministic: struct field order, sorted maps).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// The head's bytes and id.
    pub fn to_blob(&self) -> (Vec<u8>, String) {
        let b = self.to_bytes();
        let id = object_id(&b);
        (b, id)
    }

    /// Parses and validates a head.
    pub fn from_bytes(data: &[u8]) -> Result<Head, HeadError> {
        if data.len() > MAX_HEAD_BYTES {
            return Err(HeadError::TooLarge);
        }
        let h: Head = serde_json::from_slice(data)?;
        h.validate()?;
        Ok(h)
    }

    /// The hot shard directory.
    pub fn dir(&self) -> Result<ShardDir, HeadError> {
        ShardDir::new(self.shard_dir.clone()).map_err(|e| invalid(format!("shard_dir: {e}")))
    }

    /// The cold shard directory (`None` without a cold part).
    pub fn cold_dir(&self) -> Result<Option<ShardDir>, HeadError> {
        if self.cold_shard_dir.is_empty() && self.cold_shards.is_empty() {
            return Ok(None);
        }
        ShardDir::new(self.cold_shard_dir.clone())
            .map(Some)
            .map_err(|e| invalid(format!("cold_shard_dir: {e}")))
    }

    /// True when the head has a cold part.
    pub fn has_cold(&self) -> bool {
        !self.cold_shards.is_empty()
    }

    /// The shard `n`.
    pub fn shard(&self, n: u32) -> Option<&ShardRef> {
        self.shards.iter().find(|s| s.shard == n)
    }

    /// The cold shard `n`.
    pub fn cold_shard(&self, n: u32) -> Option<&ShardRef> {
        self.cold_shards.iter().find(|s| s.shard == n)
    }

    /// The IP shard `id`.
    pub fn ip_shard(&self, id: IpShardId) -> Option<&IpShardRef> {
        self.ip_shards.iter().find(|s| s.ip_shard == id)
    }

    /// The segment id named `name`.
    pub fn segment(&self, name: &str) -> Option<&str> {
        self.segments.get(name).map(String::as_str)
    }

    /// True when the IPv4 fast path applies: no IP-text pattern can change a set hit.
    pub fn ip_fast_path(&self) -> bool {
        !self.ip_pattern_classes.iter().any(|c| c.defeats_set_hit())
    }

    fn validate(&self) -> Result<(), HeadError> {
        if self.format != FORMAT {
            return Err(HeadError::Format(self.format));
        }
        if self.bundle.is_empty() || self.bundle.len() > 255 {
            return Err(invalid("bundle id"));
        }
        let dir = self.dir()?;
        check_shards(&dir, &self.shards, "shards")?;
        if let Some(cd) = self.cold_dir()? {
            check_shards(&cd, &self.cold_shards, "cold_shards")?;
        }
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.ip_shards {
            if !seen.insert(s.ip_shard) {
                return Err(invalid(format!("ip shard {} listed twice", s.ip_shard)));
            }
            check_chain(&s.base, s.base_seq, s.seq, &s.deltas)?;
        }
        if self.ip_shards.len() > 257 {
            return Err(invalid("too many ip shards"));
        }
        for (name, id) in &self.segments {
            if name != PATTERNS && name != RICH {
                return Err(invalid(format!("unknown segment {name}")));
            }
            if !is_object_id(id) {
                return Err(invalid(format!("segment {name}: bad id")));
            }
        }
        if self.feed_runs.len() > 100_000 || self.ip_pattern_classes.len() > 64 {
            return Err(invalid("too many feed runs or classes"));
        }
        Ok(())
    }
}

fn check_chain(base: &str, base_seq: u64, seq: u64, deltas: &[DeltaRef]) -> Result<(), HeadError> {
    if !is_object_id(base) {
        return Err(invalid("bad base id"));
    }
    if deltas.len() > MAX_CHAIN {
        return Err(invalid("delta chain too long"));
    }
    let mut prev = base_seq;
    for d in deltas {
        if !is_object_id(&d.blake3) || d.seq <= prev {
            return Err(invalid(format!("bad delta {}", d.seq)));
        }
        prev = d.seq;
    }
    if seq != prev {
        return Err(invalid("seq doesn't end the chain"));
    }
    Ok(())
}

fn check_shards(dir: &ShardDir, shards: &[ShardRef], what: &str) -> Result<(), HeadError> {
    if shards.len() != dir.entries().len() {
        return Err(invalid(format!("{what}: directory and shard list differ")));
    }
    for s in shards {
        if dir.entry(s.shard).is_none() {
            return Err(invalid(format!(
                "{what}: shard {} isn't in the directory",
                s.shard
            )));
        }
        check_chain(&s.base, s.base_seq, s.seq, &s.deltas)?;
    }
    let mut nums: Vec<u32> = shards.iter().map(|s| s.shard).collect();
    nums.sort_unstable();
    nums.dedup();
    if nums.len() != shards.len() {
        return Err(invalid(format!("{what}: shard listed twice")));
    }
    Ok(())
}

/// Which part of a block bundle a shard is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PartKind {
    Hot,
    Cold,
}

/// A file a manifest lists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    pub blake3: String,
    pub size: u64,
}

/// `manifest.json`: one hot or cold shard base.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub bundle: String,
    pub part: PartKind,
    pub shard: u32,
    pub keys: u64,
    /// The set checksum at the base.
    pub checksum: SetChecksum,
    /// `domains.fst` and `domains.bf8`, or `cold.bf8` and `cold.pages`.
    pub files: BTreeMap<String, FileRef>,
    /// Cold: the page file's record page count (additive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<u32>,
}

/// The hot base's FST.
pub const DOMAINS_FST: &str = "domains.fst";
/// The hot base's filter.
pub const DOMAINS_BF8: &str = "domains.bf8";
/// The cold base's filter.
pub const COLD_BF8: &str = "cold.bf8";
/// The cold base's page file.
pub const COLD_PAGES: &str = "cold.pages";

impl Manifest {
    /// The manifest's bytes and id (the base id).
    pub fn to_blob(&self) -> (Vec<u8>, String) {
        let b = serde_json::to_vec(self).unwrap_or_default();
        let id = object_id(&b);
        (b, id)
    }

    /// Parses and validates a manifest.
    pub fn from_bytes(data: &[u8]) -> Result<Manifest, HeadError> {
        if data.len() > MAX_HEAD_BYTES {
            return Err(HeadError::TooLarge);
        }
        let m: Manifest = serde_json::from_slice(data)?;
        if m.format != FORMAT {
            return Err(HeadError::Format(m.format));
        }
        let names: &[&str] = match m.part {
            PartKind::Hot => &[DOMAINS_FST, DOMAINS_BF8],
            PartKind::Cold => &[COLD_BF8, COLD_PAGES],
        };
        for n in names {
            let f = m
                .files
                .get(*n)
                .ok_or_else(|| invalid(format!("manifest lacks {n}")))?;
            if !is_object_id(&f.blake3) {
                return Err(invalid(format!("{n}: bad id")));
            }
        }
        if m.files.len() != names.len() {
            return Err(invalid("manifest lists other files"));
        }
        if m.part == PartKind::Cold && m.pages.is_none_or(|p| p == 0) {
            return Err(invalid("cold manifest lacks pages"));
        }
        Ok(m)
    }

    /// The file named `name`.
    pub fn file(&self, name: &str) -> Option<&FileRef> {
        self.files.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    pub(crate) fn sample() -> Head {
        Head {
            bundle: "block-common".into(),
            format: FORMAT,
            hash_seed: 7,
            shard_dir: vec![ShardEntry {
                prefix: 0,
                prefix_bits: 0,
                shard: 0,
            }],
            shards: vec![ShardRef {
                shard: 0,
                base: id('a'),
                seq: 2,
                checksum: SetChecksum(3),
                deltas: vec![DeltaRef {
                    seq: 2,
                    blake3: id('b'),
                    size: 10,
                }],
                base_seq: 1,
            }],
            cold_shard_dir: vec![],
            cold_shards: vec![],
            ip_shards: vec![IpShardRef {
                ip_shard: IpShardId::V4(45),
                base: id('c'),
                seq: 0,
                checksum: SetChecksum(0),
                deltas: vec![],
                base_seq: 0,
            }],
            segments: [(PATTERNS.to_string(), id('d')), (RICH.to_string(), id('e'))]
                .into_iter()
                .collect(),
            ip_pattern_classes: vec![IpPatternClass::Block],
            feed_runs: [("hagezi".to_string(), 12)].into_iter().collect(),
            issued_at: "2026-11-21T00:00:00Z".into(),
            action: BundleAction::Block,
            max_shard_keys: 1_000_000,
            next_shard: 1,
            next_cold_shard: 0,
        }
    }

    #[test]
    fn roundtrip_and_ignore_unknown() {
        let h = sample();
        let (b, hid) = h.to_blob();
        assert_eq!(Head::from_bytes(&b).unwrap(), h);
        verify_blob(&b, &hid).unwrap();
        assert!(verify_blob(b"x", &hid).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        v["future_field"] = serde_json::json!(1);
        v["ip_pattern_classes"] = serde_json::json!(["block", "something_new"]);
        let h2 = Head::from_bytes(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(!h2.ip_fast_path(), "an unknown class disables the fast path");
        assert!(h.ip_fast_path());
    }

    #[test]
    fn refusals() {
        let mut h = sample();
        h.shards[0].seq = 3;
        assert!(Head::from_bytes(&h.to_bytes()).is_err(), "seq must end the chain");
        let mut h = sample();
        h.shard_dir.clear();
        assert!(Head::from_bytes(&h.to_bytes()).is_err());
        let mut h = sample();
        h.segments.insert("other".into(), id('f'));
        assert!(Head::from_bytes(&h.to_bytes()).is_err());
        let mut h = sample();
        h.format = 9;
        assert!(matches!(
            Head::from_bytes(&h.to_bytes()),
            Err(HeadError::Format(9))
        ));
        let mut h = sample();
        h.ip_shards.push(h.ip_shards[0].clone());
        assert!(Head::from_bytes(&h.to_bytes()).is_err());
    }

    #[test]
    fn manifests() {
        let m = Manifest {
            format: FORMAT,
            bundle: "b".into(),
            part: PartKind::Cold,
            shard: 1,
            keys: 2,
            checksum: SetChecksum(1),
            files: [
                (
                    COLD_BF8.to_string(),
                    FileRef {
                        blake3: id('a'),
                        size: 1,
                    },
                ),
                (
                    COLD_PAGES.to_string(),
                    FileRef {
                        blake3: id('b'),
                        size: 2,
                    },
                ),
            ]
            .into_iter()
            .collect(),
            pages: Some(1),
        };
        let (b, _) = m.to_blob();
        assert_eq!(Manifest::from_bytes(&b).unwrap(), m);
        let mut bad = m.clone();
        bad.part = PartKind::Hot;
        assert!(Manifest::from_bytes(&bad.to_blob().0).is_err());
    }
}
