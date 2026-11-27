//! `state.json` (edge.md §2): the stored configs' hashes, newest first; `ready_version`; starts
//! since the last core session; the release last rolled back from and the latest update outcome
//! with its `result_id` (§14); the request ids last applied (§13); the firmware string last run
//! on and the last self-check result (edge-unifi.md §1).
//!
//! Readers take a lock-free snapshot ([`StateStore::get`]); writers serialise through
//! [`StateStore::update`], which persists with tmp → fsync → rename before publishing.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use picket_api::session::{Applied, UpdateOutcome};
use picket_api::time::Timestamp;

use crate::fsutil::{self, WriteOpts};

/// Largest `state.json` we read.
const MAX_STATE: u64 = 1 << 20;
/// How many configs `config/` keeps (edge.md §2).
pub const KEEP_CONFIGS: usize = 3;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// `config/<hash>.json` files, newest first, at most [`KEEP_CONFIGS`].
    pub configs: Vec<StoredConfig>,
    /// The version whose listeners are bound; null from each start until then (edge.md §3).
    /// Always written, so the updater reads an explicit null.
    pub ready_version: Option<String>,
    /// Starts since the last core session (api.md §3 `starts`).
    pub starts: u32,
    /// The release last rolled back from (edge.md §14): not installed again until core offers
    /// a different one.
    pub rollback_from: Option<String>,
    /// The latest terminal update outcome (api.md §3 `update`).
    pub update: Option<UpdateOutcome>,
    /// The request ids last applied (api.md §3 `applied`).
    pub applied: Applied,
    pub firmware: FirmwareState,
    /// Fields this release doesn't know, kept as they were: an edge rolled back to N−1 and
    /// forward again keeps what N wrote (README §2 Compatibility).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One stored config: its hash (BLAKE3 of the object without the runtime fields, which is also
/// the BLAKE3 of the file's bytes) and the config object id it was stored from, which `have` and
/// `versions` report (core keeps that id's config for replay, storage.md §3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredConfig {
    pub hash: String,
    pub object: String,
}

/// Firmware bookkeeping (edge-unifi.md §1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirmwareState {
    /// The firmware string the edge last ran on with every self-check passing.
    pub last: Option<String>,
    /// The last self-check result after a firmware change, while it hasn't passed.
    pub check: Option<FirmwareCheck>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareCheck {
    pub from: Option<String>,
    pub to: String,
    pub failed: Vec<String>,
    #[serde(with = "picket_api::time::micros")]
    pub at: Timestamp,
}

/// Whether a `state.json` that failed to load is corrupt rather than unreadable for now: it
/// reads (so its content was at fault), or it is over the size limit. A permissions or I/O error
/// is no reason to start over.
fn corrupt(path: &Path) -> bool {
    match fsutil::read_bounded(path, MAX_STATE) {
        Ok(_) => true,
        Err(e) => e.kind() == std::io::ErrorKind::InvalidData,
    }
}

/// The live `state.json`.
pub struct StateStore {
    path: PathBuf,
    current: ArcSwap<State>,
    write: Mutex<()>,
}

impl StateStore {
    /// Loads `state.json` (a missing file is an empty state; an unreadable or invalid one is an
    /// error, since silently starting over would repeat applied requests).
    pub fn load(path: &Path) -> Result<Self> {
        let state = match fsutil::read_bounded(path, MAX_STATE) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| anyhow!("{} isn't valid: {}", path.display(), crate::diag::cap(e)))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(anyhow!("can't read {}: {}", path.display(), crate::diag::cap(e))),
        };
        Ok(Self::with(path, state))
    }

    /// Loads `state.json` for the service: a file that can't be parsed (it can't be torn, writes
    /// are atomic, but a disk can corrupt it) is moved aside to `state.json.bad` and the edge
    /// starts empty, as at a first install, rather than never starting. Requests may then apply
    /// once more (harmless: caches are empty after a restart), and the edge serves only once
    /// core sends its config again.
    pub fn load_or_reset(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(s) => Ok(s),
            Err(e) if corrupt(path) => {
                let aside = path.with_extension("json.bad");
                tracing::error!(
                    "{}; moving it to {} and starting empty",
                    crate::diag::cap_chain(&e),
                    aside.display()
                );
                std::fs::rename(path, &aside)
                    .map_err(|re| anyhow!("can't move {} aside: {}", path.display(), crate::diag::cap(re)))?;
                Ok(Self::with(path, State::default()))
            }
            Err(e) => Err(e),
        }
    }

    fn with(path: &Path, state: State) -> Self {
        Self {
            path: path.to_path_buf(),
            current: ArcSwap::from_pointee(state),
            write: Mutex::new(()),
        }
    }

    /// A snapshot of the state.
    pub fn get(&self) -> Arc<State> {
        self.current.load_full()
    }

    /// Applies `f` to a copy of the state, persists it, then publishes it. On a write failure
    /// nothing changes in memory either, so memory never claims what the disk doesn't hold.
    pub fn update<R>(&self, f: impl FnOnce(&mut State) -> R) -> Result<R> {
        let _guard = self.write.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = State::clone(&self.current.load());
        let r = f(&mut next);
        if *self.current.load_full() != next {
            let mut bytes = serde_json::to_vec_pretty(&next)?;
            bytes.push(b'\n');
            fsutil::atomic_write(&self.path, &bytes, WriteOpts::mode(0o640))
                .map_err(|e| anyhow!("writing {}: {}", self.path.display(), crate::diag::cap(e)))?;
            self.current.store(Arc::new(next));
        }
        Ok(r)
    }

    /// [`Self::update`] off the async worker threads (it fsyncs).
    pub async fn update_async<R: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut State) -> R + Send + 'static,
    ) -> Result<R> {
        let me = Arc::clone(self);
        tokio::task::spawn_blocking(move || me.update(f))
            .await
            .map_err(|e| anyhow!("state update task: {e}"))?
    }

    /// Startup step 1 (edge.md §3): `ready_version` null and one more start since the last
    /// session, written before `READY=1`.
    pub fn record_start(&self) -> Result<u32> {
        self.update(|s| {
            s.ready_version = None;
            s.starts = s.starts.saturating_add(1);
            s.starts
        })
    }

    /// Sets `ready_version`, the updater's readiness signal (edge.md §14). The listener manager
    /// sets it the same way, asynchronously, once listeners are bound ([`crate::dns::listeners`]).
    pub fn mark_ready(&self, version: &str) -> Result<()> {
        let v = version.to_owned();
        self.update(move |s| s.ready_version = Some(v))
    }

    /// Called once a core session is established: `starts` counts from 0 again (api.md §3).
    pub fn reset_starts(&self) -> Result<()> {
        self.update(|s| s.starts = 0)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_sets_ready_version_null_and_counts_starts() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.json");
        let s = StateStore::load(&p).unwrap();
        s.mark_ready("1.4.0").unwrap();
        assert_eq!(s.record_start().unwrap(), 1);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"ready_version\": null"), "{text}");
        drop(s);
        let s = StateStore::load(&p).unwrap();
        assert_eq!(s.record_start().unwrap(), 2);
        s.reset_starts().unwrap();
        assert_eq!(StateStore::load(&p).unwrap().get().starts, 0);
    }

    #[test]
    fn roundtrip_and_unknown_fields() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.json");
        std::fs::write(&p, br#"{"configs":[{"hash":"h","object":"o"}],"future_field":1,"applied":{"flush_dns":"0123456789abcdef"}}"#).unwrap();
        let s = StateStore::load(&p).unwrap();
        assert_eq!(s.get().configs[0].hash, "h");
        assert_eq!(s.get().applied.flush_dns.as_deref(), Some("0123456789abcdef"));
        // A field from a newer release survives this release's rewrite.
        s.update(|s| s.starts = 4).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["future_field"], 1);
        assert_eq!(v["starts"], 4);
        std::fs::write(&p, b"not json").unwrap();
        assert!(StateStore::load(&p).is_err());
        let s = StateStore::load_or_reset(&p).unwrap();
        assert_eq!(s.get().configs.len(), 0);
        assert!(p.with_extension("json.bad").exists());
        // So is one over the size limit.
        std::fs::write(&p, vec![b' '; MAX_STATE as usize + 1]).unwrap();
        let s = StateStore::load_or_reset(&p).unwrap();
        assert_eq!(s.get().starts, 0);
    }

    #[test]
    fn failed_write_changes_nothing_in_memory() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("missing-dir/state.json");
        let s = StateStore::load(&p).unwrap();
        assert!(s.update(|s| s.starts = 5).is_err());
        assert_eq!(s.get().starts, 0);
    }
}
