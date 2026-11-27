//! The self-update handoff (edge.md §14 step 1): download the offered release tarball and its
//! `.minisig` into `releases/<version>/`, check the tarball's BLAKE3 against the offer and the
//! minisign signature against `release_keys` (with the trusted comment naming that version and
//! this architecture), then write `releases/pending.json` (tmp → rename, only while none
//! exists). The edge never unpacks; the root updater copies, verifies again and installs.
//!
//! - **When:** on a new `release.install_now` (the foundation's rules in [`crate::update`]), when
//!   `auto_update` is on for an offer the rules allow (never a downgrade unless `rollback`, never
//!   the version last rolled back from), or from `picket-edge update`. `updates_enabled: false`
//!   disables all three.
//! - **Never in the convergence round:** the download and checks run in a background task, one
//!   at a time; the round that starts it moves on, and the task wakes convergence when it ends, so
//!   the next round records the handoff (an `install_now` id counts as applied then).
//! - **Backoff per offer** (README §2 Bounded): a download or check that fails in a way that may
//!   pass later (core unreachable, a stall, a BLAKE3 mismatch, a missing signature file) isn't
//!   tried again for 1 minute, doubling to 1 hour; auto-updates also back off (10 minutes,
//!   doubling to 6 hours) after each handoff, so an update that fails at a stage that may pass
//!   later isn't retried in a loop. Both are policy choices (flagged for the owner).
//! - A release that fails its signature check is never handed over; that offer isn't tried again
//!   until core offers another.
//! - `releases/<version>/` directories no pending handoff names are deleted (edge.md §2), by each
//!   download before it starts. **One handoff** (the service's hook) serves `install_now`,
//!   `auto_update` and `picket-edge update --install`, so one download runs at a time and none
//!   deletes another's directory mid-download; the command skips the failure backoff (it is an
//!   explicit request) but not a download in progress.
//! - **One download slot** ([`Reservation`]): the check that the slot is free and its
//!   reservation are one step under the state's lock, so two callers at the same moment (two CLI
//!   calls, a CLI call and convergence) never both start a download; only the holder frees it.
//! - **Every download runs in a task of its own**, the CLI's too: the admin socket cuts a command
//!   off at its timeout (edge.md §15) while a download may take far longer, so the command waits
//!   for at most three quarters of that budget and then answers that the download goes on
//!   ([`HandOff::Downloading`]); the task still records its outcome and frees the slot. A task
//!   that ends without an outcome (cancelled, panicked) frees the slot on drop and counts as a
//!   failed download (README §2 Bounded: nothing stays blocked until a restart).

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use tokio::sync::Notify;

use picket_api::edge_api::keys;
use picket_api::edge_config::{InstallNow, ReleaseOffer};
use picket_api::update::{Pending, compare_versions, is_release_version, parse_trusted_comment};

use crate::edge::Edge;
use crate::fsutil::{self, WriteOpts};
use crate::hooks::{HandOff, UpdateHandoff};

/// Largest tarball (picket-edge-update's own bound).
pub const MAX_TARBALL: u64 = 256 << 20;
/// Largest signature file.
pub const MAX_SIG: u64 = 64 << 10;
const AUTO_FIRST: Duration = Duration::from_secs(600);
const AUTO_MAX: Duration = Duration::from_secs(6 * 3600);
/// First and largest delay before an offer whose download or check failed is tried again.
const FAIL_FIRST: Duration = Duration::from_secs(60);
const FAIL_MAX: Duration = Duration::from_secs(3600);
/// Most refused offers remembered (README §2 Bounded).
const MAX_REFUSED: usize = 64;

/// `picket-edge-<version>-<arch>.tar.gz`.
pub fn tarball_name(version: &str, arch: &str) -> String {
    format!("picket-edge-{version}-{arch}.tar.gz")
}

/// Checks a tarball against a `.minisig` and `keys`; the signature's trusted comment must name
/// `version` and `arch` (fuzzed: core is untrusted).
pub fn verify_release(tarball: &Path, sig: &[u8], keys: &[String], version: &str, arch: &str) -> Result<()> {
    let text = std::str::from_utf8(sig).map_err(|_| anyhow!("the signature isn't text"))?;
    let sig = minisign_verify::Signature::decode(text).map_err(|e| anyhow!("signature: {e}"))?;
    let keys: Vec<minisign_verify::PublicKey> = keys
        .iter()
        .filter_map(|k| minisign_verify::PublicKey::from_base64(k.trim()).ok())
        .collect();
    if keys.is_empty() {
        bail!("no usable release_keys");
    }
    let mut last = anyhow!("no release key matches the signature");
    let mut ok = false;
    for key in &keys {
        let mut v = match key.verify_stream(&sig) {
            Ok(v) => v,
            Err(e) => {
                last = anyhow!("signature: {e}");
                continue;
            }
        };
        let mut f = std::fs::File::open(tarball).with_context(|| tarball.display().to_string())?;
        let mut buf = vec![0u8; 64 << 10];
        let mut total = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_TARBALL {
                bail!("the tarball is over {MAX_TARBALL} bytes");
            }
            v.update(&buf[..n]);
        }
        match v.finalize() {
            Ok(()) => {
                ok = true;
                break;
            }
            Err(e) => last = anyhow!("signature: {e}"),
        }
    }
    if !ok {
        return Err(last);
    }
    match parse_trusted_comment(sig.trusted_comment()) {
        Some((v, a)) if v == version && a == arch => Ok(()),
        Some((v, a)) => bail!("the signed release is picket-edge {v} {a}, not {version} {arch}"),
        None => bail!("unexpected trusted comment"),
    }
}

/// Deletes `releases/<version>/` directories no pending handoff names.
pub fn cleanup(releases: &Path) {
    let pending = fsutil::read_bounded(&releases.join("pending.json"), MAX_SIG)
        .ok()
        .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
        .map(|p| p.version);
    let Ok(rd) = std::fs::read_dir(releases) else {
        return;
    };
    for e in rd.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if e.path().is_dir() && pending.as_deref() != Some(name.as_str()) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// An offer: (version, blake3).
type Key = (String, String);

#[derive(Default)]
struct HandoffState {
    /// Offers that failed their signature check: not tried again.
    refused: HashSet<Key>,
    /// Auto-update backoff after a handoff, per offer.
    auto: HashMap<Key, (Instant, Duration)>,
    /// Backoff after a failed download or check, per offer.
    failed: HashMap<Key, (Instant, Duration)>,
    /// The download running now: its offer and the token of the [`Reservation`] holding it.
    busy: Option<(Key, u64)>,
    /// The last token handed out.
    seq: u64,
    /// The last handoff: its offer and request id.
    handed: Option<(Key, Option<String>)>,
}

impl HandoffState {
    /// Records a finished download: the handoff, a refusal or the failure backoff.
    fn record(
        &mut self,
        key: &Key,
        request_id: Option<&str>,
        auto: bool,
        r: &std::result::Result<bool, JobError>,
    ) {
        match r {
            Ok(handed) => {
                self.failed.remove(key);
                if *handed {
                    self.handed = Some((key.clone(), request_id.map(str::to_owned)));
                    if auto {
                        let delay = self
                            .auto
                            .get(key)
                            .map_or(AUTO_FIRST, |(_, d)| (*d * 2).min(AUTO_MAX));
                        self.auto.retain(|k, _| k == key);
                        self.auto.insert(key.clone(), (Instant::now() + delay, delay));
                    }
                }
            }
            Err(JobError::Refused(_)) => {
                if self.refused.len() >= MAX_REFUSED {
                    self.refused.clear();
                }
                self.refused.insert(key.clone());
            }
            Err(JobError::Retry(_)) => self.retry_later(key),
        }
    }

    /// Starts or doubles the failure backoff for `key` (one offer remembered).
    fn retry_later(&mut self, key: &Key) {
        let delay = self
            .failed
            .get(key)
            .map_or(FAIL_FIRST, |(_, d)| (*d * 2).min(FAIL_MAX));
        self.failed.retain(|k, _| k == key);
        self.failed.insert(key.clone(), (Instant::now() + delay, delay));
    }
}

fn lock_state(st: &Mutex<HandoffState>) -> std::sync::MutexGuard<'_, HandoffState> {
    st.lock().unwrap_or_else(|p| p.into_inner())
}

/// The one download slot (edge.md §14: one download at a time), taken in the same lock
/// acquisition that found it free and freed only by its holder (by token), so a job that ends
/// never frees a slot another job holds. Dropped without [`Reservation::finish`] (its task was
/// cancelled or panicked), it frees the slot and counts as a failed download, paced by the
/// backoff.
struct Reservation {
    st: Arc<Mutex<HandoffState>>,
    key: Key,
    token: u64,
    open: bool,
}

impl Reservation {
    fn free(&self, g: &mut HandoffState) {
        if g.busy.as_ref().is_some_and(|(_, t)| *t == self.token) {
            g.busy = None;
        }
    }

    /// Records the job's outcome and frees the slot.
    fn finish(mut self, request_id: Option<&str>, auto: bool, r: &std::result::Result<bool, JobError>) {
        self.open = false;
        let mut g = lock_state(&self.st);
        self.free(&mut g);
        g.record(&self.key, request_id, auto, r);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.open {
            return;
        }
        let mut g = lock_state(&self.st);
        self.free(&mut g);
        g.retry_later(&self.key);
        tracing::warn!(
            "the download of release {} ended before it finished; it is tried again after the backoff",
            self.key.0
        );
    }
}

/// Why a download failed.
enum JobError {
    /// Never handed over; not tried again until core offers another release.
    Refused(anyhow::Error),
    /// May pass later: tried again after the backoff.
    Retry(anyhow::Error),
}

impl JobError {
    fn into_inner(self) -> anyhow::Error {
        match self {
            JobError::Refused(e) | JobError::Retry(e) => e,
        }
    }
}

impl<E: Into<anyhow::Error>> From<E> for JobError {
    fn from(e: E) -> Self {
        JobError::Retry(e.into())
    }
}

/// One download, check and handoff, with everything it needs (it runs detached).
struct Job {
    key: Key,
    request_id: Option<String>,
    /// For the journal: what asked for it.
    what: String,
    rollback: bool,
    core: Arc<crate::core_client::CoreClient>,
    releases: PathBuf,
    release_keys: Vec<String>,
    arch: &'static str,
}

impl Job {
    async fn run(&self) -> std::result::Result<bool, JobError> {
        let (version, blake3) = (&self.key.0, &self.key.1);
        let releases = &self.releases;
        let pending_path = releases.join("pending.json");
        let dir = releases.join(version);
        {
            let r = releases.clone();
            let _ = tokio::task::spawn_blocking(move || cleanup(&r)).await;
        }
        fsutil::create_dir_all_mode(&dir, 0o750)?;
        let tar_path = dir.join(tarball_name(version, self.arch));
        let have = {
            let p = tar_path.clone();
            let want = blake3.clone();
            tokio::task::spawn_blocking(move || {
                crate::bundles::store::hash_file(&p).is_some_and(|h| h == want)
            })
            .await
            .unwrap_or(false)
        };
        if !have {
            let _ = std::fs::remove_file(&tar_path);
            let k = keys::release_tarball(version, self.arch);
            let downloaded = self
                .core
                .download_object(&k, &dir, blake3, MAX_TARBALL)
                .await
                .map_err(|e| anyhow!("downloading {k}: {e}"))?;
            std::fs::rename(&downloaded, &tar_path)?;
            fsutil::fsync_dir(&dir)?;
        }
        let sk = keys::release_minisig(version, self.arch);
        let sig = match self.core.get_object(&sk, None, MAX_SIG).await {
            Ok(crate::core_client::ObjectReply::Body { bytes, .. }) => bytes.to_vec(),
            Ok(_) => return Err(JobError::Retry(anyhow!("{sk}: unexpected reply"))),
            Err(e) => return Err(JobError::Retry(anyhow!("downloading {sk}: {e}"))),
        };
        let (tp, s2, ks, v, a) = (
            tar_path.clone(),
            sig.clone(),
            self.release_keys.clone(),
            version.clone(),
            self.arch.to_owned(),
        );
        let verified = tokio::task::spawn_blocking(move || verify_release(&tp, &s2, &ks, &v, &a)).await?;
        if let Err(e) = verified {
            // Never installed (edge.md §14); not tried again until core offers another release.
            let _ = std::fs::remove_dir_all(&dir);
            return Err(JobError::Refused(e.context(format!("release {version} refused"))));
        }
        fsutil::atomic_write(
            &dir.join(format!("{}.minisig", tarball_name(version, self.arch))),
            &sig,
            WriteOpts::mode(0o640),
        )?;
        if pending_path.exists() {
            return Ok(false);
        }
        let p = Pending {
            version: version.clone(),
            request_id: self.request_id.clone(),
            rollback: self.rollback,
        };
        let mut bytes = serde_json::to_vec(&p)?;
        bytes.push(b'\n');
        fsutil::atomic_write(&pending_path, &bytes, WriteOpts::mode(0o640))?;
        tracing::warn!(
            "release {version} handed to the updater{}",
            self.request_id
                .as_deref()
                .map(|i| format!(" (install_now {i})"))
                .unwrap_or_default()
        );
        Ok(true)
    }
}

/// What to do about an offer now.
enum Next {
    /// Already handed over for this request.
    Done,
    /// Nothing now (why); ask again later.
    Later(&'static str),
    /// Download it, holding the slot.
    Go(Box<Job>, Reservation),
}

/// The real handoff.
#[derive(Default)]
pub struct ReleaseHandoff {
    st: Arc<Mutex<HandoffState>>,
    /// Wakes convergence when a background download ends.
    wake: Option<Arc<Notify>>,
}

impl ReleaseHandoff {
    pub fn new() -> Self {
        Self::default()
    }

    /// A handoff that wakes convergence (`wake`) when a background download ends.
    pub fn with_wake(wake: Arc<Notify>) -> Self {
        Self {
            wake: Some(wake),
            ..Self::default()
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HandoffState> {
        lock_state(&self.st)
    }

    /// What to do about `offer` now; [`Next::Go`] holds the download slot, reserved in the same
    /// lock acquisition that found it free (edge.md §14: one download at a time). `explicit`
    /// (`picket-edge update --install`) skips the failure backoff, which only paces the
    /// automatic retries.
    fn next(
        &self,
        edge: &Edge,
        request_id: Option<&str>,
        offer: &ReleaseOffer,
        explicit: bool,
    ) -> Result<Next> {
        if !edge.local.updates_enabled {
            return Ok(Next::Later("updates_enabled is false in edge.json"));
        }
        if !is_release_version(&offer.version) || !picket_api::ids::is_object_id(&offer.blake3) {
            bail!("the offered release isn't valid");
        }
        let key = (offer.version.clone(), offer.blake3.clone());
        let releases = edge.layout.releases_dir();
        let pending_path = releases.join("pending.json");
        // Everything below runs under the lock, the `pending.json` check (a stat, and a bounded
        // read when it exists) included, so no other caller can start a download in between.
        let mut g = self.lock();
        if request_id.is_some()
            && g.handed
                .as_ref()
                .is_some_and(|(k, r)| *k == key && r.as_deref() == request_id)
        {
            return Ok(Next::Done);
        }
        if g.busy.is_some() {
            return Ok(Next::Later("a download is in progress"));
        }
        if g.refused.contains(&key) {
            return Ok(Next::Later("the offered release failed its signature check"));
        }
        if !explicit && g.failed.get(&key).is_some_and(|(at, _)| Instant::now() < *at) {
            return Ok(Next::Later("backing off after a failed download"));
        }
        if pending_path.exists() {
            // Handed over already for this request (by an earlier round or process)?
            let mine = request_id.is_some()
                && fsutil::read_bounded(&pending_path, MAX_SIG)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
                    .is_some_and(|p| p.version == offer.version && p.request_id.as_deref() == request_id);
            return Ok(if mine {
                Next::Done
            } else {
                Next::Later("another handoff is pending")
            });
        }
        let Some(core) = edge.core.load_full() else {
            return Ok(Next::Later("no core session"));
        };
        g.seq += 1;
        let token = g.seq;
        g.busy = Some((key.clone(), token));
        drop(g);
        let what = match (request_id, explicit) {
            (Some(id), _) => format!("install_now {id}"),
            (None, true) => format!("picket-edge update --install of {}", offer.version),
            (None, false) => format!("auto-update to {}", offer.version),
        };
        let slot = Reservation {
            st: Arc::clone(&self.st),
            key: key.clone(),
            token,
            open: true,
        };
        Ok(Next::Go(
            Box::new(Job {
                key,
                request_id: request_id.map(str::to_owned),
                what,
                rollback: offer.rollback,
                core,
                releases,
                release_keys: edge.local.release_keys.clone(),
                arch: crate::sysinfo::arch(),
            }),
            slot,
        ))
    }

    /// Runs `job` in a task of its own, holding `slot`: whoever waits for it (an admin command
    /// cut off at its timeout, edge.md §15) can't cancel it, and it records its outcome and wakes
    /// convergence when it ends, so the next round records an `install_now` handoff.
    fn spawn(
        &self,
        job: Box<Job>,
        slot: Reservation,
        auto: bool,
    ) -> tokio::task::JoinHandle<std::result::Result<bool, JobError>> {
        let wake = self.wake.clone();
        tokio::spawn(async move {
            let r = job.run().await;
            if let Err(JobError::Refused(e) | JobError::Retry(e)) = &r {
                tracing::warn!("{}: {}", job.what, crate::diag::cap_chain(e));
            }
            slot.finish(job.request_id.as_deref(), auto, &r);
            if let Some(w) = wake {
                w.notify_one();
            }
            r
        })
    }

    /// Downloads, verifies and hands a release to the updater (`picket-edge update
    /// --install`), waiting for at most three quarters of the admin command's budget:
    /// [`HandOff::Done`] once `pending.json` names it; [`HandOff::Downloading`] when the download
    /// goes on past that (it still hands the release over when it ends); [`HandOff::Later`] when
    /// another handoff is pending, there is no core session, the offer was refused or a download
    /// is in progress.
    pub async fn hand_off_release(&self, edge: &Edge, offer: &ReleaseOffer) -> Result<HandOff> {
        let (job, slot) = match self.next(edge, None, offer, true)? {
            Next::Done => return Ok(HandOff::Done),
            Next::Later(why) => return Ok(HandOff::Later(why)),
            Next::Go(j, s) => (j, s),
        };
        let task = self.spawn(job, slot, false);
        let budget = edge.admin.timeout();
        match tokio::time::timeout(budget - budget / 4, task).await {
            Ok(Ok(Ok(true))) => Ok(HandOff::Done),
            Ok(Ok(Ok(false))) => Ok(HandOff::Later("another handoff is pending")),
            Ok(Ok(Err(e))) => Err(e.into_inner()),
            Ok(Err(e)) => Err(anyhow!("the download task ended: {e}")),
            Err(_) => Ok(HandOff::Downloading),
        }
    }

    /// Starts the download in the background (convergence never waits for it). `Ok(true)` once
    /// a handoff for this request has happened.
    fn start(&self, edge: &Edge, request_id: Option<&str>, offer: &ReleaseOffer, auto: bool) -> Result<bool> {
        match self.next(edge, request_id, offer, false)? {
            Next::Done => Ok(true),
            Next::Later(_) => Ok(false),
            Next::Go(job, slot) => {
                drop(self.spawn(job, slot, auto));
                Ok(false)
            }
        }
    }
}

/// Whether `auto_update` installs `offer` now (edge.md §14 When).
pub fn auto_due(edge: &Edge, offer: &ReleaseOffer, rollback_from: Option<&str>) -> bool {
    offer.auto_update
        && edge.local.updates_enabled
        && is_release_version(&offer.version)
        && offer.version != picket_api::VERSION
        && rollback_from != Some(offer.version.as_str())
        && (offer.rollback
            || compare_versions(&offer.version, picket_api::VERSION) == Some(std::cmp::Ordering::Greater))
}

#[async_trait]
impl UpdateHandoff for ReleaseHandoff {
    async fn hand_off(&self, edge: &Edge, req: &InstallNow, offer: &ReleaseOffer) -> Result<bool> {
        self.start(edge, Some(&req.id), offer, false)
    }

    async fn auto_update(&self, edge: &Edge, offer: &ReleaseOffer) -> Result<bool> {
        let key = (offer.version.clone(), offer.blake3.clone());
        if self
            .lock()
            .auto
            .get(&key)
            .is_some_and(|(next, _)| Instant::now() < *next)
        {
            return Ok(false);
        }
        self.start(edge, None, offer, true)
    }

    async fn hand_off_now(&self, edge: &Edge, offer: &ReleaseOffer) -> Result<HandOff> {
        self.hand_off_release(edge, offer).await
    }
}

/// `picket-edge update`: what is offered, and with `install`, hand it over now.
pub async fn update_command(edge: &Edge, install: bool) -> Result<serde_json::Value> {
    let offer = edge.active().config.as_ref().and_then(|c| c.release.clone());
    let state = edge.state.get();
    let mut v = serde_json::json!({
        "running": picket_api::VERSION,
        "offered": offer.as_ref().map(|o| o.version.clone()),
        "updates_enabled": edge.local.updates_enabled,
        "pending": edge.layout.releases_dir().join("pending.json").exists(),
    });
    let Some(offer) = offer else {
        v["installable"] = false.into();
        v["reason"] = "core offers no release".into();
        return Ok(v);
    };
    let reason = if !edge.local.updates_enabled {
        Some("updates_enabled is false in edge.json")
    } else if offer.version == picket_api::VERSION {
        Some("already running the offered release")
    } else if state.rollback_from.as_deref() == Some(offer.version.as_str()) {
        Some("the offered release was rolled back from")
    } else if !offer.rollback
        && compare_versions(&offer.version, picket_api::VERSION) != Some(std::cmp::Ordering::Greater)
    {
        Some("the offered release is older")
    } else {
        None
    };
    v["installable"] = reason.is_none().into();
    if let Some(r) = reason {
        v["reason"] = r.into();
    }
    if install && reason.is_none() {
        // The service's handoff, never one of its own: two jobs would each delete the other's
        // `releases/<version>/` mid-download (edge.md §2, §14).
        let h = edge.hooks.handoff();
        match h.hand_off_now(edge, &offer).await? {
            HandOff::Done => v["handed_off"] = true.into(),
            HandOff::Downloading => {
                v["handed_off"] = false.into();
                v["downloading"] = true.into();
                v["reason"] = "started, still downloading: the release is handed over when the download \
                               ends"
                    .into();
            }
            HandOff::Later(why) => {
                v["handed_off"] = false.into();
                v["reason"] = why.into();
            }
        }
    }
    Ok(v)
}

/// The path of the pending handoff file.
pub fn pending_path(edge: &Edge) -> PathBuf {
    edge.layout.releases_dir().join("pending.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        ("9.9.9".to_owned(), "b".repeat(64))
    }

    fn reserve(st: &Arc<Mutex<HandoffState>>, key: &Key) -> Reservation {
        let mut g = lock_state(st);
        g.seq += 1;
        g.busy = Some((key.clone(), g.seq));
        Reservation {
            st: Arc::clone(st),
            key: key.clone(),
            token: g.seq,
            open: true,
        }
    }

    /// A job whose task ends without an outcome (cancelled, panicked) frees the slot and backs
    /// off like a failed download, rather than blocking every later handoff (edge.md §14).
    #[test]
    fn a_dropped_reservation_frees_the_slot_and_backs_off() {
        let st = Arc::new(Mutex::new(HandoffState::default()));
        drop(reserve(&st, &key()));
        let g = lock_state(&st);
        assert!(g.busy.is_none());
        assert!(g.failed.contains_key(&key()), "paced like a failed download");
    }

    /// Only the holder frees the slot: a job that ends never frees one another job holds.
    #[test]
    fn only_the_holder_frees_the_slot() {
        let st = Arc::new(Mutex::new(HandoffState::default()));
        let first = reserve(&st, &key());
        let second = reserve(&st, &key());
        first.finish(None, false, &Ok(true));
        assert_eq!(lock_state(&st).busy, Some((key(), second.token)));
        second.finish(None, false, &Ok(true));
        let g = lock_state(&st);
        assert!(g.busy.is_none());
        assert!(g.failed.is_empty(), "finished jobs don't back off");
    }
}
