//! `allows.json` (edge.md §2, §12): the active temporary allows, each DNS allow with the profile
//! of its block. This store persists them, lists them, commits the bypass API's changes in one
//! write ([`AllowsStore::commit`]), ends them (revoked by core or the CLI, expired) and logs each
//! change as an `allow` record (`security` class). The rules (limits, governing profiles,
//! firewall entries) are [`crate::bypass`]'s.
//!
//! The re-checks' changes (edge.md §12: revocations, shortenings, an IP allow expanded to a
//! device's new address) and an IP allow losing an address that moved to another device
//! (edge-firewall.md §1) take effect even when the file can't be written
//! ([`AllowsStore::commit_held`]): the memory then stays authoritative (the query path, the
//! firewall and later revocations follow it) and the write is retried in the background, 1 s
//! doubling to 1 min, until the file holds it ([`AllowsStore::spawn_flush`]).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use picket_api::logs::{AllowAction, AllowKind, AllowRecord, LogRecord};
use picket_api::time::Timestamp;

use crate::fsutil::{self, WriteOpts};
use crate::logs::{LogProducer, placeholder_header};

const MAX_FILE: u64 = 16 << 20;
/// Most allows kept (50 per device by default; a bounded total over all devices).
pub const MAX_ALLOWS: usize = 50_000;
/// First and largest wait before writing a file that lags the memory again (policy choice).
const FLUSH_FIRST: Duration = Duration::from_secs(1);
const FLUSH_MAX: Duration = Duration::from_secs(60);

/// The file's shape.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowsFile {
    pub version: u32,
    pub allows: Vec<StoredAllow>,
    /// Fields this release doesn't know, kept (README §2 Compatibility).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One active temporary allow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAllow {
    pub allow_id: String,
    pub kind: AllowKind,
    /// The device (edge.md §5): its MAC; for an address with no MAC, the client whose
    /// `source_ips` hold it, else the address itself.
    pub device: String,
    /// The device's name in logs (client name, else MAC), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// The source address that created it.
    pub client: String,
    /// The blocked name (log text) or the IP.
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomains: Option<bool>,
    /// DNS allows: the block it lifts and that block's profile, time and TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(
        default,
        with = "picket_api::time::micros_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_time: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_ttl: Option<u32>,
    /// IP allows: the device addresses the firewall pair was expanded across.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(with = "picket_api::time::micros")]
    pub created_at: Timestamp,
    #[serde(with = "picket_api::time::micros")]
    pub expires_at: Timestamp,
    /// Fields this release doesn't know, kept (README §2 Compatibility).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The live store.
pub struct AllowsStore {
    path: PathBuf,
    current: ArcSwap<AllowsFile>,
    write: Mutex<()>,
    logs: LogProducer,
    /// The file lags the memory (a held commit's write failed); changed under `write`.
    dirty: AtomicBool,
    /// A [`Self::spawn_flush`] task runs.
    flushing: AtomicBool,
}

impl AllowsStore {
    /// Loads `allows.json`. A missing or unreadable file starts empty (core's revoke list is still
    /// acknowledged, edge.md §12), with a journal line for the unreadable case. One that doesn't
    /// parse is moved aside to `allows.json.bad` for inspection rather than overwritten.
    pub fn load(path: &Path, logs: LogProducer) -> Arc<Self> {
        let file = match fsutil::read_bounded(path, MAX_FILE) {
            Ok(b) => serde_json::from_slice::<AllowsFile>(&b).unwrap_or_else(|e| {
                let aside = path.with_extension("json.bad");
                tracing::warn!(
                    "{} isn't valid, moving it to {} and starting with no allows: {}",
                    path.display(),
                    aside.display(),
                    crate::diag::cap(e)
                );
                if let Err(e) = std::fs::rename(path, &aside) {
                    tracing::warn!("can't move {} aside: {}", path.display(), crate::diag::cap(e));
                }
                AllowsFile::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AllowsFile::default(),
            Err(e) => {
                tracing::warn!(
                    "can't read {}, starting with no allows: {}",
                    path.display(),
                    crate::diag::cap(e)
                );
                AllowsFile::default()
            }
        };
        Arc::new(Self {
            path: path.to_path_buf(),
            current: ArcSwap::from_pointee(file),
            write: Mutex::new(()),
            logs,
            dirty: AtomicBool::new(false),
            flushing: AtomicBool::new(false),
        })
    }

    pub fn list(&self) -> Vec<StoredAllow> {
        self.current.load().allows.clone()
    }

    /// The file as it stands, shared (the query path's temporary-allow index is rebuilt only when
    /// this changes: ladder step 1, edge.md §12).
    pub fn snapshot(&self) -> Arc<AllowsFile> {
        self.current.load_full()
    }

    /// Writes `f` (called under `write`). The file then holds everything the memory does.
    fn write_file(&self, f: &AllowsFile) -> Result<()> {
        let mut bytes = serde_json::to_vec(f)?;
        bytes.push(b'\n');
        fsutil::atomic_write(&self.path, &bytes, WriteOpts::mode(0o600))
            .map_err(|e| anyhow!("writing {}: {}", self.path.display(), crate::diag::cap(e)))?;
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    fn save(&self, f: AllowsFile) -> Result<()> {
        self.write_file(&f)?;
        self.current.store(Arc::new(f));
        Ok(())
    }

    /// Publishes a held update under `write`, retaining it in memory if the file lags.
    fn save_held(&self, f: AllowsFile) -> bool {
        let landed = match self.write_file(&f) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    "{}; the change holds in memory and the write is retried",
                    crate::diag::cap_chain(&e)
                );
                self.dirty.store(true, Ordering::Release);
                false
            }
        };
        self.current.store(Arc::new(f));
        landed
    }

    /// Adds or replaces allows and ends others in one write, logging each: `upserts` with their
    /// action (`created` or `changed`), `ends` (by id; unknown ids ignored) with `end_action`, all
    /// with `via`. Returns the ended allows. Nothing changes when the write fails.
    pub fn commit(
        &self,
        upserts: &[(StoredAllow, AllowAction)],
        ends: &[String],
        end_action: AllowAction,
        via: &str,
    ) -> Result<Vec<StoredAllow>> {
        let ups: Vec<(&StoredAllow, Option<AllowAction>)> =
            upserts.iter().map(|(a, x)| (a, Some(*x))).collect();
        self.commit_inner(&ups, ends, end_action, via, false)
            .map(|(ended, _)| ended)
    }

    /// [`Self::commit`] for changes to held allows that take effect whether or not the file can
    /// be written (edge.md §12 re-checks; edge-firewall.md §1 an address that moved): when the
    /// write fails, the memory changes anyway and the records are logged; the file follows
    /// through [`Self::spawn_flush`]. An upsert whose action is `None` changes the allow without
    /// a record (its addresses, which `allow` records don't carry). Only allows the store still
    /// holds are replaced: one that ended meanwhile stays ended. Returns the ended allows and
    /// whether the file holds the change.
    pub fn commit_held(
        &self,
        upserts: &[(StoredAllow, Option<AllowAction>)],
        ends: &[String],
        end_action: AllowAction,
        via: &str,
    ) -> Result<(Vec<StoredAllow>, bool)> {
        let ups: Vec<(&StoredAllow, Option<AllowAction>)> = upserts.iter().map(|(a, x)| (a, *x)).collect();
        self.commit_inner(&ups, ends, end_action, via, true)
    }

    fn commit_inner(
        &self,
        upserts: &[(&StoredAllow, Option<AllowAction>)],
        ends: &[String],
        end_action: AllowAction,
        via: &str,
        hold: bool,
    ) -> Result<(Vec<StoredAllow>, bool)> {
        let _g = self.write.lock().unwrap_or_else(|p| p.into_inner());
        let cur = self.current.load();
        let mut f = AllowsFile::clone(&cur);
        let (ended, kept): (Vec<StoredAllow>, Vec<StoredAllow>) =
            f.allows.drain(..).partition(|a| ends.contains(&a.allow_id));
        f.allows = kept;
        let mut applied: Vec<(&StoredAllow, Option<AllowAction>)> = Vec::with_capacity(upserts.len());
        for &(a, action) in upserts {
            if let Some(slot) = f.allows.iter_mut().find(|x| x.allow_id == a.allow_id) {
                let extra = std::mem::take(&mut slot.extra);
                *slot = a.clone();
                for (k, v) in extra {
                    slot.extra.entry(k).or_insert(v);
                }
            } else if hold {
                continue; // ended meanwhile (expired): it stays ended
            } else {
                if f.allows.len() >= MAX_ALLOWS {
                    return Err(anyhow!("allow store full"));
                }
                f.allows.push(a.clone());
            }
            applied.push((a, action));
        }
        if applied.is_empty() && ended.is_empty() {
            return Ok((vec![], true));
        }
        f.version = 1;
        let landed = if hold {
            self.save_held(f)
        } else {
            self.save(f)?;
            true
        };
        for (a, action) in applied {
            if let Some(action) = action {
                self.log(a, action, via);
            }
        }
        for a in &ended {
            self.log(a, end_action, via);
        }
        Ok((ended, landed))
    }

    /// [`Self::commit_held`] for changes that log nothing, retrying a failed write in the
    /// background ([`Self::spawn_flush`], which needs a Tokio runtime).
    pub fn change_held(self: &Arc<Self>, upserts: Vec<StoredAllow>) -> Result<()> {
        let ups: Vec<(StoredAllow, Option<AllowAction>)> = upserts.into_iter().map(|a| (a, None)).collect();
        let (_, landed) = self.commit_held(&ups, &[], AllowAction::Changed, "")?;
        if !landed {
            self.spawn_flush();
        }
        Ok(())
    }

    /// Removes a moved address from the current records selected by identity and device.
    /// Concurrent re-times, other addresses and extra fields survive; ended records stay ended.
    pub(crate) fn remove_address_held(self: &Arc<Self>, selected: &[StoredAllow], address: &str) {
        let identities: std::collections::HashSet<(&str, &str)> = selected
            .iter()
            .map(|a| (a.allow_id.as_str(), a.device.as_str()))
            .collect();
        let landed = {
            let _g = self.write.lock().unwrap_or_else(|p| p.into_inner());
            let mut f = AllowsFile::clone(&self.current.load());
            let mut changed = false;
            for a in &mut f.allows {
                if a.kind == AllowKind::Ip && identities.contains(&(a.allow_id.as_str(), a.device.as_str())) {
                    let before = a.addresses.len();
                    a.addresses.retain(|ip| ip != address);
                    changed |= before != a.addresses.len();
                }
            }
            if !changed {
                return;
            }
            f.version = 1;
            self.save_held(f)
        };
        if !landed {
            self.spawn_flush();
        }
    }

    /// Whether the file lags the memory.
    pub fn dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Writes the memory to the file if the file lags it.
    pub fn flush(&self) -> Result<()> {
        let _g = self.write.lock().unwrap_or_else(|p| p.into_inner());
        if !self.dirty() {
            return Ok(());
        }
        self.write_file(&self.current.load())
    }

    /// Retries [`Self::flush`] in the background until the file holds the memory: after 1 s,
    /// doubling to 1 min (README §2 Bounded: one task at a time, a capped interval). Any other
    /// successful write lands it too.
    pub fn spawn_flush(self: &Arc<Self>) {
        if self.flushing.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut wait = FLUSH_FIRST;
            while me.dirty() {
                tokio::time::sleep(wait).await;
                let m = Arc::clone(&me);
                match tokio::task::spawn_blocking(move || m.flush()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::warn!("{} (retried)", crate::diag::cap_chain(&e)),
                    Err(e) => tracing::warn!("writing allows.json: {e}"),
                }
                wait = (wait * 2).min(FLUSH_MAX);
            }
            tracing::info!("{} written", me.path.display());
            me.flushing.store(false, Ordering::Release);
            // A held commit that failed after the last check, before `flushing` cleared.
            if me.dirty() {
                me.spawn_flush();
            }
        });
    }

    /// Adds or replaces an allow (by `allow_id`), without a log record.
    pub fn upsert(&self, a: StoredAllow) -> Result<()> {
        let _g = self.write.lock().unwrap_or_else(|p| p.into_inner());
        let mut f = AllowsFile::clone(&self.current.load());
        if let Some(slot) = f.allows.iter_mut().find(|x| x.allow_id == a.allow_id) {
            let extra = std::mem::take(&mut slot.extra);
            *slot = a;
            // A newer release's fields on this allow survive a re-time by this one.
            for (k, v) in extra {
                slot.extra.entry(k).or_insert(v);
            }
        } else {
            if f.allows.len() >= MAX_ALLOWS {
                return Err(anyhow!("allow store full"));
            }
            f.allows.push(a);
        }
        f.version = 1;
        self.save(f)
    }

    /// Ends the listed allows the store holds, logging each as an `allow` record with `action`
    /// and `via`; unknown ids are ignored. Returns the ended allows (their firewall entries are
    /// the caller's to remove).
    pub fn end(&self, ids: &[String], action: AllowAction, via: &str) -> Result<Vec<StoredAllow>> {
        let _g = self.write.lock().unwrap_or_else(|p| p.into_inner());
        let cur = self.current.load();
        let (ended, kept): (Vec<StoredAllow>, Vec<StoredAllow>) = cur
            .allows
            .iter()
            .cloned()
            .partition(|a| ids.contains(&a.allow_id));
        if ended.is_empty() {
            return Ok(vec![]);
        }
        self.save(AllowsFile {
            version: 1,
            allows: kept,
            extra: cur.extra.clone(),
        })?;
        for a in &ended {
            self.log(a, action, via);
        }
        Ok(ended)
    }

    /// Ends the allows whose expiry has passed (`action: expired`, `via: expiry`). Callers run it
    /// only once the wall clock is synchronised (README §2 Clocks).
    pub fn expire(&self, now: Timestamp) -> Result<Vec<StoredAllow>> {
        let ids: Vec<String> = self
            .current
            .load()
            .allows
            .iter()
            .filter(|a| a.expires_at <= now)
            .map(|a| a.allow_id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(vec![]);
        }
        self.end(&ids, AllowAction::Expired, "expiry")
    }

    fn log(&self, a: &StoredAllow, action: AllowAction, via: &str) {
        self.logs.emit(LogRecord::Allow(AllowRecord {
            h: placeholder_header(),
            action,
            allow_id: a.allow_id.clone(),
            client: a.client.clone(),
            device: a.device_name.clone(),
            kind: a.kind,
            target: a.target.clone(),
            subdomains: a.subdomains,
            block_id: a.block_id.clone(),
            profile: a.profile.clone(),
            expires_at: Some(a.expires_at),
            via: via.to_owned(),
        }));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn allow(id: &str, kind: AllowKind, expires_in: i64) -> StoredAllow {
        let now = Timestamp::now();
        StoredAllow {
            allow_id: id.into(),
            kind,
            device: "aa:bb:cc:dd:ee:02".into(),
            device_name: Some("emma-tablet".into()),
            client: "192.168.1.140".into(),
            target: if kind == AllowKind::Ip {
                "100.100.100.100".into()
            } else {
                "ads.example.com".into()
            },
            subdomains: None,
            block_id: (kind == AllowKind::Dns).then(|| "k3j9q2".into()),
            profile: (kind == AllowKind::Dns).then(|| "kids".into()),
            block_time: None,
            block_ttl: None,
            addresses: vec![],
            created_at: now,
            expires_at: now + jiff::SignedDuration::from_secs(expires_in),
            extra: Default::default(),
        }
    }

    #[test]
    fn persists_ends_and_logs() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("allows.json");
        let (logs, mut rx) = LogProducer::new("b".into(), Arc::default());
        let s = AllowsStore::load(&p, logs.clone());
        s.upsert(allow("a-19", AllowKind::Ip, 3600)).unwrap();
        s.upsert(allow("a-20", AllowKind::Dns, -1)).unwrap();
        let s2 = AllowsStore::load(&p, logs.clone());
        assert_eq!(s2.list().len(), 2);
        let ended = s2
            .end(&["a-19".into(), "a-unknown".into()], AllowAction::Revoked, "core")
            .unwrap();
        assert_eq!(ended.len(), 1);
        let expired = s2.expire(Timestamp::now()).unwrap();
        assert_eq!(expired[0].allow_id, "a-20");
        assert!(AllowsStore::load(&p, logs).list().is_empty());
        let recs: Vec<serde_json::Value> = std::iter::from_fn(|| rx.rx.try_recv().ok())
            .map(|e| serde_json::from_str(&e.line).unwrap())
            .collect();
        assert_eq!(recs[0]["t"], "allow");
        assert_eq!(recs[0]["action"], "revoked");
        assert_eq!(recs[0]["via"], "core");
        assert_eq!(recs[1]["action"], "expired");
        assert_eq!(recs[1]["via"], "expiry");
    }

    /// The held path (edge.md §12 re-checks): an address change logs no record, a shortening
    /// logs `changed`, both hold in memory when the write fails, and an allow that ended
    /// meanwhile isn't brought back.
    #[test]
    fn held_changes_stay_in_memory_and_never_revive_an_ended_allow() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("allows.json");
        let (logs, mut rx) = LogProducer::new("b".into(), Arc::default());
        let s = AllowsStore::load(&p, logs);
        s.upsert(allow("a-1", AllowKind::Ip, 3600)).unwrap();
        s.upsert(allow("a-2", AllowKind::Ip, 3600)).unwrap();
        // A non-empty directory where the file goes: every write fails, even root's.
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir_all(p.join("x")).unwrap();
        let mut expanded = allow("a-1", AllowKind::Ip, 3600);
        expanded.addresses = vec!["192.168.1.141".into()];
        let mut shortened = allow("a-2", AllowKind::Ip, 600);
        shortened.addresses = vec!["192.168.1.140".into()];
        let gone = allow("a-3", AllowKind::Ip, 3600);
        let (_, landed) = s
            .commit_held(
                &[
                    (expanded, None),
                    (shortened, Some(AllowAction::Changed)),
                    (gone, Some(AllowAction::Changed)),
                ],
                &[],
                AllowAction::Revoked,
                "config",
            )
            .unwrap();
        assert!(!landed && s.dirty());
        let list = s.list();
        assert_eq!(list.len(), 2, "the ended allow stays ended");
        assert_eq!(list[0].addresses, vec!["192.168.1.141".to_owned()]);
        assert_eq!(list[1].addresses, vec!["192.168.1.140".to_owned()]);
        let recs: Vec<serde_json::Value> = std::iter::from_fn(|| rx.rx.try_recv().ok())
            .map(|e| serde_json::from_str(&e.line).unwrap())
            .collect();
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(recs[0]["allow_id"], "a-2");
        assert_eq!(recs[0]["action"], "changed");
        std::fs::remove_dir_all(&p).unwrap();
        s.flush().unwrap();
        let reloaded = AllowsStore::load(&p, LogProducer::new("b".into(), Arc::default()).0).list();
        let addrs =
            |l: &[StoredAllow]| -> Vec<Vec<String>> { l.iter().map(|a| a.addresses.clone()).collect() };
        assert_eq!(
            addrs(&reloaded),
            addrs(&list),
            "the retried write lands the memory"
        );
    }

    #[test]
    fn moved_address_removal_preserves_a_later_retime_and_other_addresses() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("allows.json");
        let (logs, _rx) = LogProducer::new("b".into(), Arc::default());
        let s = AllowsStore::load(&p, logs.clone());
        let mut original = allow("a-1", AllowKind::Ip, 3600);
        original.addresses = vec!["192.168.1.140".into(), "192.168.1.141".into()];
        s.upsert(original).unwrap();
        let selected = s.list();
        // A policy recheck lands after the move selected its records.
        let mut latest = selected[0].clone();
        latest.expires_at = Timestamp::now() + jiff::SignedDuration::from_secs(60);
        latest.addresses.push("192.168.1.142".into());
        latest.extra.insert("future".into(), serde_json::json!(true));
        s.change_held(vec![latest.clone()]).unwrap();
        s.remove_address_held(&selected, "192.168.1.140");
        let current = &s.list()[0];
        assert_eq!(
            current.expires_at, latest.expires_at,
            "the older snapshot must not extend access"
        );
        assert_eq!(current.addresses, ["192.168.1.141", "192.168.1.142"]);
        assert_eq!(current.extra, latest.extra);
        assert_eq!(
            AllowsStore::load(&p, logs).list()[0].expires_at,
            latest.expires_at
        );
        s.end(&["a-1".into()], AllowAction::Revoked, "core").unwrap();
        s.remove_address_held(&selected, "192.168.1.141");
        assert!(s.list().is_empty(), "a move must not revive a revoked allow");
    }

    #[test]
    fn unreadable_file_starts_empty() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("allows.json");
        std::fs::write(&p, b"{broken").unwrap();
        let (logs, _rx) = LogProducer::new("b".into(), Arc::default());
        assert!(AllowsStore::load(&p, logs).list().is_empty());
        assert_eq!(
            std::fs::read(p.with_extension("json.bad")).unwrap(),
            b"{broken",
            "kept for inspection"
        );
    }

    #[test]
    fn fields_from_a_newer_release_survive_a_rewrite() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("allows.json");
        let mut a = serde_json::to_value(allow("a-1", AllowKind::Dns, 3600)).unwrap();
        a["future"] = serde_json::json!({"x": 1});
        std::fs::write(
            &p,
            serde_json::json!({"version": 1, "allows": [a], "top_future": true}).to_string(),
        )
        .unwrap();
        let (logs, _rx) = LogProducer::new("b".into(), Arc::default());
        let s = AllowsStore::load(&p, logs);
        s.upsert(allow("a-2", AllowKind::Ip, 3600)).unwrap();
        s.upsert(allow("a-1", AllowKind::Dns, 7200)).unwrap();
        s.end(&["a-2".into()], AllowAction::Revoked, "cli").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["top_future"], true);
        assert_eq!(v["allows"][0]["future"]["x"], 1);
        assert_eq!(v["allows"].as_array().unwrap().len(), 1);
    }
}
