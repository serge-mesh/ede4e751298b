//! `bundles/active.json` (edge.md §2, edge-unifi.md §1 "Bundles"): the active and previous head of
//! each bundle and verdict set, whether the active one is complete, the head each active part
//! came from (the `versions` entry), and the config object the edge runs with its `bundles`,
//! `verdict_sets` and `release` maps. It sits next to the bundle files and is rewritten (tmp →
//! fsync → rename) at every activation step; while files are in memory only, nothing is written.
//!
//! The record also keeps the runtime maps of the last few stored configs (`configs`): the stored
//! config files leave those fields out (edge.md §2), so a start from disk takes them from here.
//!
//! **Restart:** a complete head is loaded whole; a head recorded part-way is loaded whole when
//! every file it needs is held (loading a whole head is always consistent: no key is in neither
//! part), else its previous, complete head is. Unknown fields are kept (README §2 Compatibility).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use picket_api::logs::BundleVersion;

use crate::fsutil::{self, WriteOpts};

/// Largest `active.json` read (many bundles, each with up to 256 shards and parts).
pub const MAX_RECORD: u64 = 4 << 20;
/// How many configs' runtime maps are kept (the stored configs: edge.md §2).
pub const KEEP_CONFIGS: usize = crate::state::KEEP_CONFIGS;
/// Most bundles and verdict sets recorded (README §2 Bounded).
pub const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    pub version: u32,
    /// The config object the edge runs (its id).
    pub object: Option<String>,
    pub bundles: BTreeMap<String, String>,
    pub verdict_sets: BTreeMap<String, String>,
    pub release: Option<serde_json::Value>,
    /// The runtime maps of the configs the edge stores, newest first.
    pub configs: Vec<ConfigMaps>,
    pub heads: BTreeMap<String, BundleRecord>,
    pub sets: BTreeMap<String, SetRecord>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One stored config's runtime maps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigMaps {
    /// `config/<hash>.json`'s hash.
    pub hash: String,
    pub object: String,
    pub bundles: BTreeMap<String, String>,
    pub verdict_sets: BTreeMap<String, String>,
}

/// A bundle's heads.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BundleRecord {
    /// The head being activated, or the last one activated.
    pub active: String,
    /// The head active before it (complete), kept on disk until the active one completes and
    /// then as the previous head (edge.md §2).
    pub previous: Option<String>,
    /// Every part the active head needs is active (cold parts only with a usable SSD).
    pub complete: bool,
    /// The head each active part came from, as `versions` reports it.
    pub parts: Option<BundleVersion>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A verdict set's heads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SetRecord {
    pub active: String,
    pub previous: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Record {
    /// Reads `active.json` in `dir`. A missing file is an empty record; one that can't be read
    /// or parsed is reported and treated as empty (every file is verified anyway, and core names
    /// the heads again: edge.md §3).
    pub fn load(dir: &Path) -> Option<Record> {
        let path = dir.join("active.json");
        match fsutil::read_nofollow_bounded(&path, MAX_RECORD) {
            Ok(b) => match Self::parse(&b) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!("{} isn't valid ({e}); ignoring it", path.display());
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!("{}: {}", path.display(), crate::diag::cap(e));
                None
            }
        }
    }

    /// Parses and checks a record: ids must be BLAKE3 ids and names path-safe (the file sits on
    /// a drive UniFi owns: untrusted, README §2).
    pub fn parse(bytes: &[u8]) -> Result<Record, String> {
        let r: Record = serde_json::from_slice(bytes).map_err(|e| crate::convergence::json_error(&e))?;
        let ok_id = |s: &str| picket_api::ids::is_object_id(s);
        if r.heads.len() > MAX_ENTRIES || r.sets.len() > MAX_ENTRIES || r.configs.len() > 64 {
            return Err("too many entries".into());
        }
        for (b, h) in &r.heads {
            if !safe_name(b) || !ok_id(&h.active) || h.previous.as_deref().is_some_and(|p| !ok_id(p)) {
                return Err("bad bundle entry".into());
            }
        }
        for (p, s) in &r.sets {
            if !safe_name(p) || !ok_id(&s.active) || s.previous.as_deref().is_some_and(|x| !ok_id(x)) {
                return Err("bad verdict-set entry".into());
            }
        }
        for c in &r.configs {
            if c.bundles.iter().any(|(b, h)| !safe_name(b) || !ok_id(h))
                || c.verdict_sets.iter().any(|(p, h)| !safe_name(p) || !ok_id(h))
            {
                return Err("bad config maps".into());
            }
        }
        if r.bundles.iter().any(|(b, h)| !safe_name(b) || !ok_id(h))
            || r.verdict_sets.iter().any(|(p, h)| !safe_name(p) || !ok_id(h))
        {
            return Err("bad object maps".into());
        }
        Ok(r)
    }

    /// Writes `active.json` into `dir` (tmp → fsync → rename).
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        fsutil::create_dir_all_mode(dir, 0o750)?;
        let mut bytes = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        fsutil::atomic_write(&dir.join("active.json"), &bytes, WriteOpts::mode(0o640))
    }

    /// The runtime maps stored for config `hash`, if any.
    pub fn maps_for(&self, hash: &str) -> Option<&ConfigMaps> {
        self.configs.iter().find(|c| c.hash == hash)
    }

    /// Records `maps` as the newest config's.
    pub fn push_config(&mut self, maps: ConfigMaps) {
        self.configs.retain(|c| c.hash != maps.hash);
        self.configs.insert(0, maps);
        self.configs.truncate(KEEP_CONFIGS);
    }

    /// Notes that `bundle` is activating `head` (the first step).
    pub fn start_head(&mut self, bundle: &str, head: &str) {
        let e = self.heads.entry(bundle.to_owned()).or_default();
        if e.active == head {
            return;
        }
        // The previous head is the last complete one: a head left part-way is never a fallback.
        if e.complete && !e.active.is_empty() {
            e.previous = Some(std::mem::take(&mut e.active));
        }
        e.active = head.to_owned();
        e.complete = false;
    }

    /// Notes that `bundle`'s active head is complete.
    pub fn complete_head(&mut self, bundle: &str) {
        if let Some(e) = self.heads.get_mut(bundle) {
            e.complete = true;
        }
    }
}

/// A bundle or provider id usable as a path component.
pub fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    #[test]
    fn previous_is_the_last_complete_head() {
        let mut r = Record::default();
        r.start_head("b", &id('a'));
        assert_eq!(r.heads["b"].previous, None);
        r.complete_head("b");
        r.start_head("b", &id('b'));
        assert_eq!(r.heads["b"].previous.as_deref(), Some(id('a').as_str()));
        // `b` fails part-way; `c` replaces it: the fallback stays `a`.
        r.start_head("b", &id('c'));
        assert_eq!(r.heads["b"].previous.as_deref(), Some(id('a').as_str()));
        assert!(!r.heads["b"].complete);
    }

    #[test]
    fn parse_refuses_unsafe_names_and_ids_and_keeps_unknown_fields() {
        let good =
            serde_json::json!({"version": 1, "heads": {"b": {"active": id('a'), "x": 1}}, "future": true});
        let r = Record::parse(good.to_string().as_bytes()).unwrap();
        assert_eq!(r.extra["future"], true);
        assert_eq!(r.heads["b"].extra["x"], 1);
        let back = serde_json::to_value(&r).unwrap();
        assert_eq!(back["future"], true);
        for bad in [
            serde_json::json!({"heads": {"../x": {"active": id('a')}}}),
            serde_json::json!({"heads": {"b": {"active": "nope"}}}),
            serde_json::json!({"sets": {"p": {"active": id('a'), "previous": "../../x"}}}),
            serde_json::json!({"bundles": {"b/c": id('a')}}),
        ] {
            assert!(Record::parse(bad.to_string().as_bytes()).is_err(), "{bad}");
        }
    }
}
