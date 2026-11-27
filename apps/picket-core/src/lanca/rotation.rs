//! LAN CA rotation (core.md §11 `lanca.zones`: "Changing it means a new CA root, trusted again on
//! every device"; security.md §2).
//!
//! **A rotation** is a `PUT settings` whose `lanca.zones` names other zones than the current
//! root's and whose `lanca.rotate_from` names the current root's fingerprint ([`rotate`]). Other
//! zones without it are refused (`422`, by the route), so a stale form (an old tab's "keep my
//! changes") can't make a root nobody asked for, and a `rotate_from` that is no longer the current
//! root is refused (`409`, code [`ROOT_CHANGED`]; a `null` one counts as left out). The rotation
//! runs as a task of its own that holds the rotation lock and its staged root from the first check
//! to the last step, so a caller that goes away (a closed tab, a proxy timeout) only stops waiting:
//!
//! 1. Checked before anything changes: the wall clock is synchronised (`503` otherwise: the new
//!    root and the certificates it signs carry dates, and nothing repairs a root dated in the
//!    future, README §2 Clocks); no previous root is still in use (`409`, code `conflict`, naming
//!    the edges, so core never trusts more than the current root and one previous root); every
//!    name in use is under the new zones (managed listener names and `web.names` must be,
//!    core.md §2: `422` naming those the change would orphan); then the whole patch against the
//!    whole model, as any settings save (`422`).
//! 2. The new root is generated and staged in `lanca/next-<hex>/ca.{key,crt}` (directory 0700,
//!    files 0600, each fsync'd), the directory named by the root's fingerprint, so the staged files
//!    of two roots can never be mixed. The clock is checked again right before the root is dated
//!    (`503`): it may have stopped being synchronised while the checks waited.
//! 3. One `core.db` transaction checks again, writes the settings and the roots (`lanca_roots`:
//!    the old root retired, the new one current) and journals both. Its commit is the rotation's
//!    commit point; a refusal removes the staged root, so a rejected request changes nothing.
//! 4. On the writer, right after the commit, before the new settings are published: that root's
//!    staged files are renamed into `lanca/ca.{key,crt}` (key first), its staging directory is
//!    removed, and the running core switches to the new root, keeping the old one as a previous
//!    root. Then the settings and the config generation are published, so every edge's config
//!    object names the new root (`EdgeConfig.lanca_root`) and each edge replaces its managed
//!    listener certificates (edge.md §5; an offline edge when it reconnects). The managed web
//!    certificate is re-issued under the new root on a synchronised clock (if the clock stopped
//!    being synchronised meanwhile, the minute refresh re-issues it once it is,
//!    `web::refresh_web_cert`), and a `lanca` UI event ([`LancaEvent`]) says the root changed.
//!
//! **Recovery** ([`open`], at start, before anything signs): a stop at any point leaves the old
//! root or the new one, never a mix. Only the staging directory of the root the committed current
//! row names is renamed into place (whatever of it is still there); every other staged root is
//! discarded.
//!
//! **Previous roots** stay trusted by core's own TLS to edge DoH listeners (the DNSSEC validator,
//! core.md §8) until every assigned managed listener reports a certificate from the current root.
//! Each edge reports, in `hello` and every heartbeat, the root that signed the certificate each of
//! its managed listeners serves now (`cert_roots`, api.md §3); core keeps the last report per edge
//! and listener (`lanca_served`, [`record_served`]: a change at once, then at most one write per
//! heartbeat storage window, the newest report last). So an edge that is offline, failed to store a
//! certificate core signed, never got the response, or crashed before installing it keeps the
//! previous root in use, as does a listener that has reported no certificate yet. While a previous
//! root is kept, each edge's stored report that changes sends a `lanca_served` UI event
//! (coalesced). [`prune`] drops a previous root once no listener needs it (after each report that
//! changes, each config change, and every few minutes), with a `lanca` `previous_dropped` UI event.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

use super::{CA_CERT, CA_KEY, LanCa, PreviousRoot, lanca_dir, name_under_zones, same_zones};
use crate::config::model::{EntityKind, Model};
use crate::config::{Actor, journal, store};
use crate::db::Db;
use crate::error::{CoreError, CoreResult};
use crate::settings::Settings;
use crate::state::SharedState;

/// A rotation stages its new root in `lanca/` under this prefix and the hex of the root's
/// fingerprint ([`staging_dir`]).
pub const NEXT_PREFIX: &str = "next-";
/// How often [`prune`] runs without a nudge.
pub const PRUNE_EVERY: Duration = Duration::from_secs(600);
/// Most edges a refusal names (README §2 Bounded); the rest are counted.
const MAX_NAMED: usize = 10;
/// The error code (`409`) of a rotation asked for from a root that is no longer the current one
/// (`lanca.rotate_from` stale: another change replaced it), so the UI can tell it from the `409`
/// `conflict` while a previous root is still in use (module docs; api.md §2 error shape).
pub const ROOT_CHANGED: &str = "lanca_root_changed";

/// Points where a test stops a rotation as a crash would ([`Runtime::fail_at`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The new key is staged, its certificate isn't.
    KeyStaged,
    /// The new root is staged; the settings transaction hasn't run.
    Staged,
    /// The transaction committed; nothing is renamed yet.
    Committed,
    /// `ca.key` is the new key, `ca.crt` still the old certificate.
    KeyPromoted,
    /// Both files are in place; the staging directory remains.
    Promoted,
    /// The running core uses the new root; the web certificate isn't re-issued yet.
    Switched,
}

/// Every [`Step`], in order.
pub const STEPS: &[Step] = &[
    Step::KeyStaged,
    Step::Staged,
    Step::Committed,
    Step::KeyPromoted,
    Step::Promoted,
    Step::Switched,
];

/// The LAN CA's runtime state: one rotation (or prune) at a time, one web-certificate issue at a
/// time, the prune task's nudge, and the `cert_roots` stored and pending per edge.
#[derive(Default)]
pub struct Runtime {
    lock: tokio::sync::Mutex<()>,
    fail: Mutex<Option<Step>>,
    wake: tokio::sync::Notify,
    /// Held while the managed web certificate is checked, issued, written and swapped in
    /// (`web::managed_web_cert`, `web::refresh_web_cert`), so two issues never interleave their
    /// writes of `lanca/web.{key,crt}`.
    web_cert: Mutex<()>,
    /// Edge id → its `cert_roots` stored and pending ([`record_served`]). At most one entry per
    /// edge; [`prune`] drops those of edges that no longer exist.
    served: Mutex<HashMap<String, Served>>,
}

/// One edge's `cert_roots` ([`record_served`]).
#[derive(Default)]
struct Served {
    /// What `lanca_served` holds for the edge (updated on the writer after each commit), so an
    /// unchanged report costs no write. None: nothing stored since start.
    stored: Option<BTreeMap<String, String>>,
    /// When the last heartbeat report was written, on the monotonic clock (README §2 Clocks).
    written: Option<tokio::time::Instant>,
    /// The newest heartbeat report not written yet, with its session: written at the end of the
    /// window.
    pending: Option<(u64, BTreeMap<String, String>)>,
    /// A task waits for the end of the window to write `pending`.
    scheduled: bool,
}

impl Runtime {
    /// Tests: stop the next rotations at `step` as a crash would (nothing after it runs, nothing
    /// is cleaned up).
    pub fn fail_at(&self, step: Option<Step>) {
        if let Ok(mut g) = self.fail.lock() {
            *g = step;
        }
    }

    fn failing(&self, step: Step) -> bool {
        self.fail.lock().is_ok_and(|g| *g == Some(step))
    }

    /// Asks the prune task to look again (what an edge serves changed).
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// The managed web certificate's lock (above). Blocking: taken on blocking threads only.
    pub fn web_cert_lock(&self) -> MutexGuard<'_, ()> {
        self.web_cert.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn served(&self) -> MutexGuard<'_, HashMap<String, Served>> {
        self.served.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn stopped(step: Step) -> CoreError {
    CoreError::Other(anyhow::anyhow!("the rotation stopped after {step:?} (test)"))
}

/// The refusal while the wall clock isn't synchronised (module docs, steps 1–2).
fn unsynchronised() -> CoreError {
    CoreError::Unavailable(
        "the wall clock isn't synchronised yet: a new LAN CA root and the certificates it signs \
         carry dates, and a root dated in the future would leave every certificate invalid \
         (README §2 Clocks). Try again once the clock is synchronised"
            .into(),
    )
}

// ---------------------------------------------------------------------------------------------
// Roots and their use

/// One `lanca_roots` row.
#[derive(Clone, Debug)]
struct RootRow {
    fingerprint: String,
    cert_pem: String,
    zones: Vec<String>,
    created_at: String,
    retired_at: Option<String>,
}

fn read_roots(conn: &Connection) -> Result<Vec<RootRow>> {
    let mut st = conn.prepare(
        "SELECT fingerprint, cert_pem, zones_json, created_at, retired_at FROM lanca_roots
         ORDER BY created_at DESC, fingerprint",
    )?;
    let rows = st
        .query_map([], |r| {
            Ok(RootRow {
                fingerprint: r.get(0)?,
                cert_pem: r.get(1)?,
                zones: serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or_default(),
                created_at: r.get(3)?,
                retired_at: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn current_fingerprint(conn: &Connection) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT fingerprint FROM lanca_roots WHERE retired_at IS NULL",
            [],
            |r| r.get(0),
        )
        .optional()?)
}

/// The zones of the root `core.db` names as current (the restore checks a document against them
/// inside its transaction, core.md §2). None before the first start.
pub fn current_zones(conn: &Connection) -> Result<Option<Vec<String>>> {
    Ok(conn
        .query_row(
            "SELECT zones_json FROM lanca_roots WHERE retired_at IS NULL",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(|z| serde_json::from_str(&z).unwrap_or_default()))
}

/// An edge whose assigned managed listeners haven't all reported a certificate from the current
/// root: while one exists, the previous root stays in use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RootUser {
    pub edge_id: String,
    pub edge_name: String,
    /// The edge's assigned managed listeners that haven't reported a certificate from the current
    /// root: their last report (hello or heartbeat `cert_roots`) names the previous root, another
    /// one, or no certificate at all.
    pub listeners: Vec<String>,
    /// Whether the edge has a session now. An online edge asks for new certificates within
    /// moments of a rotation and reports them right after; an offline one when it reconnects.
    pub online: bool,
}

/// Which listeners still keep the previous root in use.
struct Usage {
    roots: Vec<RootRow>,
    /// The edges whose assigned managed listeners haven't all reported a certificate from the
    /// current root (module docs, Previous roots).
    pending: Vec<RootUser>,
    /// Edges with `lanca_served` rows that no longer exist.
    gone: Vec<String>,
}

impl Usage {
    fn previous(&self) -> impl Iterator<Item = &RootRow> {
        self.roots.iter().filter(|r| r.retired_at.is_some())
    }

    /// True while a previous root is kept and a listener may still serve a certificate from it.
    fn in_use(&self) -> bool {
        !self.pending.is_empty() && self.previous().next().is_some()
    }
}

fn usage(conn: &Connection) -> Result<Usage> {
    let roots = read_roots(conn)?;
    let current = roots
        .iter()
        .find(|r| r.retired_at.is_none())
        .map(|r| r.fingerprint.clone());
    // The assigned managed listeners, with their edges' names.
    let mut managed: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut st = conn.prepare(
        "SELECT le.edge_id, le.listener_id, l.tls_json, e.name FROM listener_edges le
         JOIN listeners l ON l.id = le.listener_id JOIN edges e ON e.id = le.edge_id",
    )?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (edge, listener, tls, name) in rows {
        let is_managed = tls
            .and_then(|t| serde_json::from_str::<picket_api::edge_config::ListenerTls>(&t).ok())
            .is_some_and(|t| t.managed.is_some());
        if is_managed {
            managed.insert((edge, listener), name);
        }
    }
    let mut st = conn.prepare("SELECT edge_id, listener_id, root FROM lanca_served")?;
    let served: BTreeMap<(String, String), String> = st
        .query_map([], |r| Ok(((r.get(0)?, r.get(1)?), r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut pending: BTreeMap<String, RootUser> = BTreeMap::new();
    for ((edge, listener), name) in managed {
        let on_current = current
            .as_ref()
            .is_some_and(|c| served.get(&(edge.clone(), listener.clone())) == Some(c));
        if on_current {
            continue;
        }
        pending
            .entry(edge.clone())
            .or_insert_with(|| RootUser {
                edge_id: edge,
                edge_name: name,
                listeners: Vec::new(),
                online: false,
            })
            .listeners
            .push(listener);
    }
    let mut st = conn
        .prepare("SELECT DISTINCT edge_id FROM lanca_served WHERE edge_id NOT IN (SELECT id FROM edges)")?;
    let gone = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Usage {
        roots,
        pending: pending.into_values().collect(),
        gone,
    })
}

/// Stores what `edge` reports its managed listeners serve (`cert_roots` in the `hello`, `fresh`,
/// and every heartbeat of session `sid`, api.md §3) and nudges [`prune`] (module docs, Previous
/// roots). A `hello` is always stored. A heartbeat that reports what is stored costs no write; one
/// that changes it is written at once when no heartbeat report was written in the last heartbeat
/// storage window (`edges::hub::HEARTBEAT_STORE_EVERY`), so the report right after a new
/// certificate lands promptly, and otherwise at the end of that window, then only the newest
/// report: an edge's reports cost at most one write per window however fast they change (README
/// §2 Bounded). The report replaces the edge's rows: a listener it leaves out holds no
/// certificate core knows the root of.
pub async fn record_served(
    state: &SharedState,
    edge: &str,
    sid: u64,
    roots: &BTreeMap<String, String>,
    fresh: bool,
) -> CoreResult<()> {
    let window = state.edges.hub.heartbeat_interval();
    let now = tokio::time::Instant::now();
    let deferred_to = {
        let mut served = state.lanca_rt.served();
        let e = served.entry(edge.to_string()).or_default();
        if fresh {
            // A new session's report replaces whatever an older one left pending.
            e.pending = None;
            None
        } else if e.stored.as_ref() == Some(roots) {
            // Back to what is stored: nothing left to write.
            e.pending = None;
            return Ok(());
        } else if let Some(end) = e.written.map(|w| w + window).filter(|end| now < *end) {
            e.pending = Some((sid, roots.clone()));
            if e.scheduled {
                return Ok(());
            }
            e.scheduled = true;
            Some(end)
        } else {
            // Newer than anything pending: a task still waking for the window's end finds
            // nothing older to write after it.
            e.written = Some(now);
            e.pending = None;
            None
        }
    };
    match deferred_to {
        None => store_served(state, edge.to_string(), sid, roots.clone()).await,
        Some(end) => {
            write_pending_at(state, edge.to_string(), end);
            Ok(())
        }
    }
}

/// Writes `edge`'s pending report ([`record_served`]) at `end`, the end of its window. One task per
/// edge at a time (`Served::scheduled`); it stops with core.
fn write_pending_at(state: &SharedState, edge: String, end: tokio::time::Instant) {
    let state = state.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = state.shutdown.cancelled() => return,
            _ = tokio::time::sleep_until(end) => {}
        }
        let pending = {
            let mut served = state.lanca_rt.served();
            let Some(e) = served.get_mut(&edge) else {
                return;
            };
            e.scheduled = false;
            let p = e.pending.take();
            if p.is_some() {
                e.written = Some(tokio::time::Instant::now());
            }
            p
        };
        if let Some((sid, roots)) = pending
            && let Err(e) = store_served(&state, edge.clone(), sid, roots).await
        {
            // The next report that differs from what is stored tries again.
            tracing::warn!(edge = %edge, error = %e, "cannot store the roots of the edge's listener certificates");
        }
    });
}

/// Replaces `edge`'s `lanca_served` rows with `roots` while session `sid` is the edge's, and
/// nudges [`prune`] when it did. Rows that changed while a previous root is kept (a rotation in
/// progress) send a `lanca_served` UI event (coalesced, `web::events::LancaServedEvent`), so the
/// UI sees the edges move to the current root without polling.
async fn store_served(
    state: &SharedState,
    edge: String,
    sid: u64,
    roots: BTreeMap<String, String>,
) -> CoreResult<()> {
    let st = state.clone();
    let wrote = state
        .db
        .write(move |c| {
            if !st.edges.hub.is_current(&edge, sid) {
                return Ok::<_, CoreError>(false);
            }
            let tx = c.transaction()?;
            let before: BTreeMap<String, String> = tx
                .prepare("SELECT listener_id, root FROM lanca_served WHERE edge_id = ?1")?
                .query_map([&edge], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            let changed = before != roots;
            tx.execute("DELETE FROM lanca_served WHERE edge_id = ?1", [&edge])?;
            let now = crate::util::now_ts();
            for (listener, root) in &roots {
                tx.execute(
                    "INSERT INTO lanca_served (edge_id, listener_id, root, reported_at) VALUES (?1, ?2, ?3, ?4)",
                    params![edge, listener, root, now],
                )?;
            }
            tx.commit()?;
            // On the writer, right after the commit: the cache never names rows not stored, and
            // the UI's note follows commit order (`web::events` module docs).
            if changed && !st.lanca.load().previous.is_empty() {
                st.events.coalesced().lanca_served(&edge);
            }
            st.lanca_rt.served().entry(edge).or_default().stored = Some(roots);
            Ok(true)
        })
        .await?;
    if wrote {
        state.lanca_rt.wake();
    }
    Ok(())
}

/// The refusal while a previous root is in use (module docs, step 1).
fn in_use_refusal(u: &Usage, online: &dyn Fn(&str) -> bool) -> Option<CoreError> {
    if !u.in_use() {
        return None;
    }
    let root = u.previous().next()?;
    let mut named: Vec<String> = u
        .pending
        .iter()
        .take(MAX_NAMED)
        .map(|e| {
            let state = if online(&e.edge_id) { "" } else { "; offline" };
            format!("{} ({}{state})", e.edge_name, e.listeners.join(", "))
        })
        .collect();
    if u.pending.len() > MAX_NAMED {
        named.push(format!("{} more", u.pending.len() - MAX_NAMED));
    }
    Some(CoreError::Conflict(format!(
        "the previous LAN CA root {} (zones {}) is still in use: edges {} haven't reported listener \
         certificates from the current root yet. Another lanca.zones change waits until they have: \
         an online edge asks for them within moments and reports them right after, an offline one \
         when it reconnects; removing the listener from an edge, or the edge, also ends its use",
        root.fingerprint,
        root.zones.join(", "),
        named.join(", ")
    )))
}

/// The names in use that `new`'s zones wouldn't cover: managed listener names and `web.names`
/// (core.md §2).
fn orphans(m: &Model, new: &Settings) -> Vec<String> {
    let zones = &new.lanca.zones;
    let mut out = Vec::new();
    for l in m.listeners.values() {
        if let Some(n) = l.tls.as_ref().and_then(|t| t.managed.as_ref())
            && !name_under_zones(n, zones)
        {
            out.push(format!("{n} (listener {})", l.id));
        }
    }
    for n in &new.web.names {
        if !name_under_zones(n, zones) {
            out.push(format!("{n} (web.names)"));
        }
    }
    out
}

/// The checks before a rotation changes anything (module docs, step 1). `patch` holds the new
/// zones.
fn precheck(conn: &Connection, patch: &Value, online: &dyn Fn(&str) -> bool) -> CoreResult<()> {
    let u = usage(conn)?;
    if let Some(e) = in_use_refusal(&u, online) {
        return Err(e);
    }
    let before = store::load_model(conn)?;
    let (new, _) = crate::settings::apply_patch(&before.settings, patch, true)
        .map_err(|e| CoreError::Invalid(format!("{e:#}")))?;
    let lost = orphans(&before, &new);
    if !lost.is_empty() {
        return Err(CoreError::Invalid(format!(
            "lanca.zones {} would orphan names in use: {}. Managed listener names and web.names must \
             be under lanca.zones (core.md §2): rename them first, or move in two steps: widen \
             lanca.zones to hold both zones, rename, then narrow it (each change is a new root)",
            new.lanca.zones.join(", "),
            lost.join(", ")
        )));
    }
    let mut after = before.clone();
    after.settings = new;
    store::check(&before, &after)
}

// ---------------------------------------------------------------------------------------------
// Files

/// Where a rotation stages root `fingerprint` (module docs, step 2): `lanca/next-<hex>`.
pub fn staging_dir(dir: &Path, fingerprint: &str) -> PathBuf {
    let hex = fingerprint
        .strip_prefix(picket_api::ids::FP_PREFIX)
        .unwrap_or(fingerprint);
    dir.join(format!("{NEXT_PREFIX}{hex}"))
}

/// Writes `ca` to its staging directory (module docs, step 2). False: a test stopped it.
fn stage(dir: &Path, ca: &LanCa, rt: &Runtime) -> Result<bool> {
    let next = staging_dir(dir, &ca.fingerprint());
    if fs::symlink_metadata(&next).is_ok() {
        // Only a stop of a rotation to this very root could leave it (its key is random).
        fs::remove_dir_all(&next).with_context(|| format!("remove {}", next.display()))?;
    }
    fs::create_dir(&next).with_context(|| format!("create {}", next.display()))?;
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(&next, fs::Permissions::from_mode(0o700))?;
    crate::util::fsync_dir(dir)?;
    crate::util::write_atomic(&next.join(CA_KEY), ca.key_pem().as_bytes(), 0o600)?;
    if rt.failing(Step::KeyStaged) {
        return Ok(false);
    }
    crate::util::write_atomic(&next.join(CA_CERT), ca.cert_pem.as_bytes(), 0o600)?;
    Ok(!rt.failing(Step::Staged))
}

/// Renames what is still in `staged` into place: the key, then the certificate, each fsync'd
/// (module docs, step 4). False: a test stopped it after the key.
fn promote(dir: &Path, staged: &Path, rt: Option<&Runtime>) -> Result<bool> {
    let key = staged.join(CA_KEY);
    if fs::symlink_metadata(&key).is_ok() {
        fs::rename(&key, dir.join(CA_KEY)).context("rename the staged ca.key")?;
        crate::util::fsync_dir(dir)?;
    }
    if rt.is_some_and(|r| r.failing(Step::KeyPromoted)) {
        return Ok(false);
    }
    let crt = staged.join(CA_CERT);
    if fs::symlink_metadata(&crt).is_ok() {
        fs::rename(&crt, dir.join(CA_CERT)).context("rename the staged ca.crt")?;
        crate::util::fsync_dir(dir)?;
    }
    Ok(true)
}

/// Removes a staging directory and what is left in it.
fn remove_staged(dir: &Path, staged: &Path) -> Result<()> {
    if fs::symlink_metadata(staged).is_ok() {
        fs::remove_dir_all(staged).with_context(|| format!("remove {}", staged.display()))?;
        crate::util::fsync_dir(dir)?;
    }
    Ok(())
}

/// The fingerprint of the certificate staged in `staged`, if one is there and parses.
fn staged_fingerprint(staged: &Path) -> Option<String> {
    let pem = fs::read_to_string(staged.join(CA_CERT)).ok()?;
    let der = crate::identity::pem_to_der(&pem, "CERTIFICATE").ok()?;
    Some(picket_api::ids::cert_fingerprint(&der))
}

/// Finishes or discards the rotations a stop interrupted (module docs, Recovery). `committed` is
/// the current root `core.db` names: only its staging directory is put in place, and only when
/// the certificate still staged there (if any is left) is that root.
fn recover(dir: &Path, committed: Option<&str>) -> Result<()> {
    let ours = committed.map(|c| staging_dir(dir, c));
    let mut staged: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("next"))
        .map(|e| e.path())
        .collect();
    staged.sort();
    for s in staged {
        let finish = ours.as_deref() == Some(s.as_path())
            && staged_fingerprint(&s).is_none_or(|fp| Some(fp.as_str()) == committed);
        if finish {
            tracing::warn!(root = ?committed, "finishing a LAN CA rotation a stop interrupted");
            promote(dir, &s, None)?;
        } else {
            tracing::warn!(staged = %s.display(), "discarding a LAN CA root staged by a rotation that never committed");
        }
        remove_staged(dir, &s)?;
    }
    Ok(())
}

/// Opens the LAN CA at start: recovers an interrupted rotation, loads the current root, records
/// it in `lanca_roots` on first start, and loads the previous roots still kept (module docs).
pub async fn open(data_dir: &Path, db: &Db) -> Result<LanCa> {
    let dir = lanca_dir(data_dir);
    db.write(move |c| -> Result<LanCa> {
        let committed = current_fingerprint(c)?;
        recover(&dir, committed.as_deref())?;
        let mut ca = LanCa::load(&dir)?;
        let fp = ca.fingerprint();
        let tx = c.transaction()?;
        if committed.as_deref() != Some(fp.as_str()) {
            if let Some(other) = &committed {
                // Only a hand-edited data directory gets here: the files hold the key, so their
                // root signs; the other stays trusted while edges use it.
                tracing::warn!(files = %fp, db = %other, "lanca/ca.crt isn't the root core.db names; the files' root applies");
            }
            let now = crate::util::now_ts();
            tx.execute(
                "UPDATE lanca_roots SET retired_at = ?1 WHERE retired_at IS NULL",
                [&now],
            )?;
            tx.execute(
                "INSERT INTO lanca_roots (fingerprint, cert_pem, zones_json, created_at, retired_at)
                 VALUES (?1, ?2, ?3, ?4, NULL)
                 ON CONFLICT (fingerprint) DO UPDATE SET retired_at = NULL",
                params![fp, ca.cert_pem, serde_json::to_string(ca.zones())?, now],
            )?;
        }
        ca.previous = read_roots(&tx)?
            .into_iter()
            .filter(|r| r.retired_at.is_some())
            .map(|r| PreviousRoot {
                fingerprint: r.fingerprint,
                cert_pem: r.cert_pem,
            })
            .collect();
        tx.commit()?;
        Ok(ca)
    })
    .await
}

// ---------------------------------------------------------------------------------------------
// The rotation

/// Changes `lanca.zones` to `zones` (normalized, and other than the current root's), applying the
/// rest of the settings `patch` with them, when `from` is the current root's fingerprint (module
/// docs, A rotation). Runs in a task of its own that holds the rotation lock and the staged root
/// to the end; dropping this future only stops the wait.
pub async fn rotate(
    state: &SharedState,
    zones: Vec<String>,
    patch: Value,
    from: String,
    actor: Actor,
) -> CoreResult<Settings> {
    let st = state.clone();
    tokio::spawn(async move { rotate_owned(&st, zones, patch, from, actor).await })
        .await
        .map_err(|e| CoreError::Other(anyhow::anyhow!("the rotation stopped: {e}")))?
}

/// The rotation itself ([`rotate`]), holding the lock throughout.
async fn rotate_owned(
    state: &SharedState,
    zones: Vec<String>,
    mut patch: Value,
    from: String,
    actor: Actor,
) -> CoreResult<Settings> {
    let rt = &state.lanca_rt;
    let _serial = rt.lock.lock().await;
    let old = state.lanca.load_full();
    if same_zones(old.zones(), &zones) {
        // A rotation to these zones finished meanwhile: the rest of the patch is a plain save.
        if patch.as_object().is_some_and(|p| p.is_empty()) {
            return Ok(state.config.settings().as_ref().clone());
        }
        return state.config.patch_settings(patch, actor).await;
    }
    let old_fp = old.fingerprint();
    if from != old_fp {
        return Err(CoreError::ConflictCode(
            ROOT_CHANGED,
            format!(
                "lanca.rotate_from names {from}, but the LAN CA root is {old_fp} (zones {}) now: \
                 another change replaced it. Reload the settings and decide again",
                old.zones().join(", ")
            ),
        ));
    }
    if !state.clock.synced() {
        return Err(unsynchronised());
    }
    let Some(obj) = patch.as_object_mut() else {
        return Err(CoreError::Invalid("settings are a JSON object".into()));
    };
    obj.remove("lanca.zones");
    match obj.get_mut("lanca").and_then(Value::as_object_mut) {
        Some(l) => {
            l.insert("zones".into(), serde_json::json!(zones));
        }
        None => {
            obj.insert("lanca".into(), serde_json::json!({ "zones": zones }));
        }
    }

    // 1. Checks, before anything changes.
    let p = patch.clone();
    let st = state.clone();
    state
        .db
        .read(move |c| precheck(c, &p, &|e| st.edges.hub.session(e).is_some()))
        .await?;

    // 2. The new root, staged in a directory of its own. The clock is checked again right before
    //    the root is dated: it may have stopped being synchronised while the checks waited for a
    //    reader (README §2 Clocks).
    let dir = lanca_dir(&state.data_dir);
    let (ca, staged) = {
        let st = state.clone();
        let dir = dir.clone();
        let zones = zones.clone();
        tokio::task::spawn_blocking(move || -> CoreResult<(LanCa, bool)> {
            if !st.clock.synced() {
                return Err(unsynchronised());
            }
            let name = format!(
                "Picket LAN CA {} {}",
                picket_api::ids::short_id(&st.marker.instance_id),
                crate::util::utc_minute(&jiff::Timestamp::now())
            );
            let ca = LanCa::generate(&zones, &name)?;
            let staged = stage(&dir, &ca, &st.lanca_rt)?;
            Ok((ca, staged))
        })
        .await
        .map_err(|e| CoreError::Other(anyhow::anyhow!("staging the new root: {e}")))??
    };
    if !staged {
        return Err(stopped(if rt.failing(Step::KeyStaged) {
            Step::KeyStaged
        } else {
            Step::Staged
        }));
    }

    // 3. The commit point, and 4. the switch on the writer right after it.
    let new_fp = ca.fingerprint();
    let staged_dir = staging_dir(&dir, &new_fp);
    let committed = {
        let st = state.clone();
        let st2 = state.clone();
        let dir = dir.clone();
        let staged_dir = staged_dir.clone();
        let (new_fp, old_fp) = (new_fp.clone(), old_fp.clone());
        let new_pem = ca.cert_pem.clone();
        let new_zones = ca.zones().to_vec();
        let old_root = PreviousRoot {
            fingerprint: old_fp.clone(),
            cert_pem: old.cert_pem.clone(),
        };
        state
            .config
            .change_settings(
                move |tx| {
                    if current_fingerprint(tx)?.as_deref() != Some(old_fp.as_str()) {
                        return Err(CoreError::ConflictCode(
                            ROOT_CHANGED,
                            "the LAN CA root changed during the rotation; reload the settings".into(),
                        ));
                    }
                    let u = usage(tx)?;
                    if let Some(e) = in_use_refusal(&u, &|e| st.edges.hub.session(e).is_some()) {
                        return Err(e);
                    }
                    // The check made sure no previous root is in use: they all go.
                    for r in u.previous() {
                        tx.execute("DELETE FROM lanca_roots WHERE fingerprint = ?1", [&r.fingerprint])?;
                    }
                    let new = store::apply_settings(tx, &patch, &actor, true)?;
                    if !same_zones(&new.lanca.zones, &new_zones) {
                        return Err(CoreError::Invalid("lanca.zones changed during the rotation".into()));
                    }
                    let now = crate::util::now_ts();
                    tx.execute(
                        "UPDATE lanca_roots SET retired_at = ?1 WHERE retired_at IS NULL",
                        [&now],
                    )?;
                    tx.execute(
                        "INSERT INTO lanca_roots (fingerprint, cert_pem, zones_json, created_at, retired_at)
                         VALUES (?1, ?2, ?3, ?4, NULL)",
                        params![
                            new_fp,
                            new_pem,
                            serde_json::to_string(&new_zones).map_err(anyhow::Error::from)?,
                            now
                        ],
                    )?;
                    journal::record(
                        tx,
                        actor.ip.as_deref(),
                        &actor.source,
                        EntityKind::Settings,
                        "lanca",
                        &serde_json::json!({"op": "rotate_root", "from": old_fp, "to": new_fp, "zones": new_zones}),
                    )?;
                    Ok(new)
                },
                move |_| {
                    let rt = &st2.lanca_rt;
                    if rt.failing(Step::Committed) {
                        return false;
                    }
                    match promote(&dir, &staged_dir, Some(rt)) {
                        Ok(false) => return false,
                        Ok(true) => {
                            if rt.failing(Step::Promoted) {
                                return false;
                            }
                            if let Err(e) = remove_staged(&dir, &staged_dir) {
                                tracing::warn!(error = %format!("{e:#}"), "cannot remove the staged LAN CA root");
                            }
                        }
                        Err(e) => tracing::error!(
                            error = %format!("{e:#}"),
                            "the new LAN CA root is committed but not in place; the next start finishes it"
                        ),
                    }
                    let mut ca = ca;
                    ca.previous = vec![old_root];
                    st2.lanca.store(Arc::new(ca));
                    true
                },
            )
            .await
    };
    let new = match committed {
        Ok((new, true)) => new,
        Ok((_, false)) => {
            return Err(stopped(if rt.failing(Step::Committed) {
                Step::Committed
            } else if rt.failing(Step::KeyPromoted) {
                Step::KeyPromoted
            } else {
                Step::Promoted
            }));
        }
        Err(e) => {
            // Refused (or failed) before the commit: the staged root goes, unless core.db names
            // it after all (an error after the commit), in which case the next start finishes it.
            let fp = new_fp.clone();
            let ours = state
                .db
                .read(move |c| Ok::<_, CoreError>(current_fingerprint(c)?.as_deref() == Some(fp.as_str())))
                .await
                .unwrap_or(true);
            if !ours {
                let d = dir.clone();
                if let Err(e) = tokio::task::spawn_blocking(move || remove_staged(&d, &staged_dir))
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|r| r)
                {
                    tracing::warn!(error = %format!("{e:#}"), "cannot remove the staged LAN CA root");
                }
            }
            return Err(e);
        }
    };
    tracing::info!(from = %old_fp, to = %new_fp, zones = ?new.lanca.zones, "rotated the LAN CA root");
    if rt.failing(Step::Switched) {
        return Err(stopped(Step::Switched));
    }
    // The web certificate comes from the new root (core.md §11), issued only on a synchronised
    // clock (README §2 Clocks): `refresh_web_cert` checks it right before signing.
    let st = state.clone();
    match tokio::task::spawn_blocking(move || crate::web::refresh_web_cert(&st)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            tracing::warn!(error = %format!("{e:#}"), "cannot re-issue the web certificate; retried every minute")
        }
        Err(e) => tracing::warn!(error = %e, "web certificate task failed"),
    }
    event(state, LancaEventKind::Rotated, &new_fp, &old_fp, &new_fp);
    rt.wake();
    Ok(new)
}

// ---------------------------------------------------------------------------------------------
// Previous roots

/// Drops the previous roots no listener needs any more and the reports of edges that no longer
/// exist, and gives the running core the previous roots it still trusts (module docs).
pub async fn prune(state: &SharedState) -> CoreResult<()> {
    let _serial = state.lanca_rt.lock.lock().await;
    let st = state.clone();
    let (kept, dropped) = state
        .db
        .write(move |c| {
            let state = &st;
            let u = usage(c)?;
            let unused: Vec<&RootRow> = if u.in_use() {
                Vec::new()
            } else {
                u.previous().collect()
            };
            if !unused.is_empty() || !u.gone.is_empty() {
                let tx = c.transaction()?;
                for r in &unused {
                    tx.execute("DELETE FROM lanca_roots WHERE fingerprint = ?1", [&r.fingerprint])?;
                    tracing::info!(root = %r.fingerprint, "every listener serves a certificate from the current LAN CA root; dropped the previous one");
                }
                for e in &u.gone {
                    tx.execute("DELETE FROM lanca_served WHERE edge_id = ?1", [e])?;
                }
                tx.commit()?;
            }
            // The cache follows: no entry for an edge that no longer exists (README §2 Bounded),
            // including one whose last report named no listener.
            let edges: std::collections::HashSet<String> = c
                .prepare("SELECT id FROM edges")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            state.lanca_rt.served().retain(|e, _| edges.contains(e));
            let dropped: Vec<String> = unused.iter().map(|r| r.fingerprint.clone()).collect();
            let kept: Vec<PreviousRoot> = u
                .previous()
                .filter(|r| !dropped.contains(&r.fingerprint))
                .map(|r| PreviousRoot {
                    fingerprint: r.fingerprint.clone(),
                    cert_pem: r.cert_pem.clone(),
                })
                .collect();
            Ok::<_, CoreError>((kept, dropped))
        })
        .await?;
    let cur = state.lanca.load_full();
    if cur.previous != kept {
        let mut ca = (*cur).clone();
        ca.previous = kept;
        state.lanca.store(Arc::new(ca));
    }
    let current = state.lanca.load().fingerprint();
    for root in &dropped {
        event(state, LancaEventKind::PreviousDropped, root, root, &current);
    }
    Ok(())
}

/// The prune task (module docs, Previous roots): at start, after each report that changes, each
/// config change, and every [`PRUNE_EVERY`].
pub fn spawn(state: &SharedState) {
    let st = state.clone();
    tokio::spawn(async move {
        let mut cfg = st.config.subscribe();
        let mut every = tokio::time::interval(PRUNE_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        every.tick().await;
        loop {
            if let Err(e) = prune(&st).await {
                tracing::warn!(error = %e, "cannot drop unused LAN CA roots; retrying");
            }
            tokio::select! {
                _ = st.shutdown.cancelled() => return,
                r = cfg.changed() => if r.is_err() { return },
                _ = st.lanca_rt.wake.notified() => {}
                _ = every.tick() => {}
            }
        }
    });
}

// ---------------------------------------------------------------------------------------------
// The view and the event

/// What a `lanca` UI event reports (api.md §7; the spec is silent on the event, so it follows the
/// other events' style).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LancaEventKind {
    /// A `lanca.zones` change made `root` the current root and `previous` a previous root, which
    /// stays in use until every listener reports a certificate from the current one (`can_rotate`
    /// false; `lanca_served` events follow the edges' progress).
    Rotated,
    /// No listener needs the previous root `root` (= `previous`) any more, so core stopped
    /// trusting it (`can_rotate` true again): the rotation has finished.
    PreviousDropped,
}

/// A `lanca` UI event's data (api.md §7): the LAN CA's roots changed; refetch `GET settings`.
/// A `rotated` event goes out before the rotating `PUT settings` is answered, so the tab that
/// rotated can see it (and its refetch) first.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LancaEvent {
    pub event: LancaEventKind,
    /// The root the event is about: the new current root (`rotated`) or the previous root dropped
    /// (`previous_dropped`).
    pub root: String,
    /// The previous root: the one the rotation replaced (`rotated`), or the one dropped
    /// (`previous_dropped`, the same as `root`).
    pub previous: String,
    /// The current root's fingerprint.
    pub current: String,
}

fn event(state: &SharedState, event: LancaEventKind, root: &str, previous: &str, current: &str) {
    let ev = LancaEvent {
        event,
        root: root.into(),
        previous: previous.into(),
        current: current.into(),
    };
    if let Ok(data) = serde_json::to_value(ev) {
        state.events.send("lanca", data);
    }
}

/// The LAN CA in `GET` and `PUT settings` (core.md §11, §12): its zones and root, and the state of
/// the last rotation.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LancaView {
    /// `lanca.zones`: the zones the current root signs names under.
    pub zones: Vec<String>,
    /// The current root's fingerprint: `SHA256:` and the hex SHA-256 of its certificate, as
    /// browsers show it. A rotation names it in `lanca.rotate_from` (`PUT settings`).
    pub fingerprint: String,
    /// When the current root was made (at `init`, or by the last `lanca.zones` change).
    pub created_at: Option<String>,
    /// The current root's download path (also on the plain-HTTP port when set).
    pub download: String,
    /// Previous roots still in use: core keeps trusting them until every assigned managed listener
    /// reports a certificate from the current root, then drops them (a `lanca` `previous_dropped`
    /// UI event; `lanca_served` events tell of the edges' progress meanwhile). Changing
    /// `lanca.zones` is refused (409, code `conflict`) while this isn't empty.
    pub previous: Vec<PreviousRootView>,
    /// True when no previous root is in use, so `lanca.zones` can change (once the clock is
    /// synchronised: `clock_synced`).
    pub can_rotate: bool,
    /// Whether core's wall clock is synchronised: a rotation is refused (503) until it is (README
    /// §2 Clocks).
    pub clock_synced: bool,
}

/// A previous root still in use.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct PreviousRootView {
    pub fingerprint: String,
    pub zones: Vec<String>,
    pub created_at: String,
    /// When a `lanca.zones` change replaced it.
    pub retired_at: String,
    /// The edges whose assigned managed listeners haven't reported a certificate from the current
    /// root yet.
    pub edges: Vec<RootUser>,
}

/// The view (above).
pub async fn view(state: &SharedState) -> CoreResult<LancaView> {
    let ca = state.lanca.load_full();
    let u = state.db.read(|c| Ok::<_, CoreError>(usage(c)?)).await?;
    let fp = ca.fingerprint();
    let created_at = u
        .roots
        .iter()
        .find(|r| r.fingerprint == fp)
        .map(|r| r.created_at.clone());
    let edges: Vec<RootUser> = u
        .pending
        .iter()
        .map(|e| RootUser {
            online: state.edges.hub.session(&e.edge_id).is_some(),
            ..e.clone()
        })
        .collect();
    let previous: Vec<PreviousRootView> = if u.in_use() {
        u.previous()
            .map(|r| PreviousRootView {
                fingerprint: r.fingerprint.clone(),
                zones: r.zones.clone(),
                created_at: r.created_at.clone(),
                retired_at: r.retired_at.clone().unwrap_or_default(),
                edges: edges.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(LancaView {
        zones: ca.zones().to_vec(),
        fingerprint: fp,
        created_at,
        download: "/lanca/ca.crt".into(),
        can_rotate: previous.is_empty(),
        clock_synced: state.clock.synced(),
        previous,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca(zones: &[&str]) -> LanCa {
        LanCa::generate(&zones.iter().map(|z| z.to_string()).collect::<Vec<_>>(), "t").unwrap()
    }

    fn write(dir: &Path, ca: &LanCa) {
        crate::util::write_atomic(&dir.join(CA_KEY), ca.key_pem().as_bytes(), 0o600).unwrap();
        crate::util::write_atomic(&dir.join(CA_CERT), ca.cert_pem.as_bytes(), 0o600).unwrap();
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("next"))
            .collect()
    }

    /// Every stop point of the file steps, recovered with the commit made (`committed` = new) or
    /// not (= old): the loaded root is always the committed one, with its key, and no staging
    /// directory is left.
    #[test]
    fn recovery_leaves_the_committed_root_after_a_stop_at_any_file_step() {
        for commit in [false, true] {
            for stop in [Step::KeyStaged, Step::Staged, Step::KeyPromoted, Step::Promoted] {
                let d = tempfile::tempdir().unwrap();
                let old = ca(&["home.arpa"]);
                write(d.path(), &old);
                let new = ca(&["lan.example"]);
                let rt = Runtime::default();
                rt.fail_at(Some(stop));
                let staged = stage(d.path(), &new, &rt).unwrap();
                if matches!(stop, Step::KeyStaged | Step::Staged) {
                    assert!(!staged);
                    if commit {
                        // A commit needs the whole staged root: no such state.
                        continue;
                    }
                } else {
                    assert!(staged);
                    if !commit {
                        continue; // promotion only follows a commit
                    }
                    let s = staging_dir(d.path(), &new.fingerprint());
                    let done = promote(d.path(), &s, Some(&rt)).unwrap();
                    assert_eq!(done, stop != Step::KeyPromoted);
                }
                let committed = if commit {
                    new.fingerprint()
                } else {
                    old.fingerprint()
                };
                recover(d.path(), Some(&committed)).unwrap();
                let loaded = LanCa::load(d.path()).unwrap();
                assert_eq!(loaded.fingerprint(), committed, "{stop:?} commit={commit}");
                assert!(leftovers(d.path()).is_empty(), "{stop:?} commit={commit}");
            }
        }
    }

    /// R1 (module docs, step 2 and Recovery): two roots staged at once never mix. Each has a
    /// directory of its own; recovery installs only the committed root's files, whichever was
    /// staged last, and discards the other root and any leftover.
    #[test]
    fn staged_roots_never_mix_and_only_the_committed_one_is_installed() {
        let d = tempfile::tempdir().unwrap();
        let old = ca(&["home.arpa"]);
        write(d.path(), &old);
        let (a, b) = (ca(&["a.example"]), ca(&["b.example"]));
        let rt = Runtime::default();
        assert!(stage(d.path(), &a, &rt).unwrap());
        assert!(stage(d.path(), &b, &rt).unwrap());
        let (sa, sb) = (
            staging_dir(d.path(), &a.fingerprint()),
            staging_dir(d.path(), &b.fingerprint()),
        );
        assert_ne!(sa, sb);
        assert_eq!(staged_fingerprint(&sa), Some(a.fingerprint()));
        assert_eq!(staged_fingerprint(&sb), Some(b.fingerprint()));
        // A leftover of an older layout, and a directory named for the committed root that holds
        // another root's certificate, are never installed.
        fs::create_dir(d.path().join("next")).unwrap();
        recover(d.path(), Some(&a.fingerprint())).unwrap();
        let loaded = LanCa::load(d.path()).unwrap();
        assert_eq!(loaded.fingerprint(), a.fingerprint());
        assert_eq!(loaded.zones(), ["a.example"]);
        assert!(leftovers(d.path()).is_empty());

        let d = tempfile::tempdir().unwrap();
        write(d.path(), &old);
        assert!(stage(d.path(), &b, &rt).unwrap());
        fs::rename(
            staging_dir(d.path(), &b.fingerprint()),
            staging_dir(d.path(), &a.fingerprint()),
        )
        .unwrap();
        recover(d.path(), Some(&a.fingerprint())).unwrap();
        assert_eq!(LanCa::load(d.path()).unwrap().fingerprint(), old.fingerprint());
        assert!(leftovers(d.path()).is_empty());
    }

    #[test]
    fn zone_sets_compare_without_order_or_case() {
        let v = |z: &[&str]| z.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(same_zones(&v(&["home.arpa", "lan"]), &v(&["LAN.", "home.arpa"])));
        assert!(!same_zones(&v(&["home.arpa"]), &v(&["home.arpa", "lan"])));
    }

    #[test]
    fn trust_holds_the_current_and_previous_roots() {
        let mut c = ca(&["home.arpa"]);
        let old = ca(&["lan"]);
        c.previous = vec![PreviousRoot {
            fingerprint: old.fingerprint(),
            cert_pem: old.cert_pem.clone(),
        }];
        let pem = c.trust_pem();
        assert_eq!(pem.matches("BEGIN CERTIFICATE").count(), 2);
        // A leaf from the old root isn't the current root's.
        let (leaf, _) = old
            .issue_with_new_key(&["dns.lan".into()], &[], crate::lanca::LEAF_VALIDITY)
            .unwrap();
        let der = crate::identity::pem_to_der(&leaf.cert_pem, "CERTIFICATE").unwrap();
        assert!(old.signed(&der));
        assert!(!c.signed(&der));
    }
}
