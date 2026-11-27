//! The edge release bundled with core (core.md §5, storage.md §3 `edge_releases`).
//!
//! - **One release ships core and edge at the same version.** Core offers edges only the edge
//!   release of its own version, found under the release directory (default
//!   `/usr/share/picket-core/edge`) as `<version>/picket-edge-<version>-<arch>.tar.gz` and its
//!   `.minisig`, for `aarch64` and `x86_64`. No upload, no download.
//! - **At start** core verifies each tarball's minisign signature against its `release_keys`
//!   (compiled in via `PICKET_RELEASE_PUB` / `PICKET_RELEASE_PUB_FILE`), taking the version and architecture only from the
//!   signature's verified trusted comment (`picket-edge <version> <arch>`), which must name core's
//!   own version and the file's architecture. A verified tarball is copied into the blob store
//!   (kind `release`, immutable) and registered in `edge_releases`; `GET
//!   /objects/releases/<version>/…` serves it from there.
//! - **On failure** core offers no release and raises `release_invalid`; it resolves when a
//!   release passes its check. A directory with no release at all (a development build) offers
//!   nothing and raises nothing.
//! - **Retention** ([`ReleaseRetention`]): storage.md §4 names none for `edge_releases`, yet every
//!   core upgrade adds one (README §2 Bounded), while configuration and data still in use are
//!   kept (README §2, data in use). An edge downloads the release its config offers (edge.md §14),
//!   and that need not be core's own: an edge whose bundle budget holds keeps its whole config
//!   across a core upgrade (bundles.md §2 Budget, `edges::publish`), so it still offers the
//!   previous release, `install_now` included. So core keeps the release of the version it
//!   registered at start and every release a config core may still serve an edge offers: each
//!   edge's current config (`edge_named`; a held one stays current) and each config pinned for an
//!   edge (served and not yet released by a `have`, storage.md §4 Pins). A pending `install_now`
//!   lives inside such a config's offer (it is rendered only while it names the offered release),
//!   and one naming a release no config offers is pending no more (api.md §4). The rows of any
//!   other release go [`OTHER_VERSION_KEEP`] after retention first found nothing offering it
//!   (`unoffered_at`, reset when one offers it again), never counted from `added_at`: a core
//!   rolled back to an older version re-registers rows that were added long ago. Release bytes go
//!   once nothing names them (`crate::blobs::unreferenced`). A core rollback brings its own
//!   release, registered at its start (core.md §5; pipelines.md §6–§7); an edge rolls back on its
//!   own disk (edge.md §14).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use arc_swap::ArcSwap;
use minisign_verify::{PublicKey, Signature};
use rusqlite::{OptionalExtension, params};

use crate::alerts::{RaiseSpec, Severity};
use crate::edges::render::ReleaseInput;
use crate::retention::RetentionHook;
use crate::scheduler::{BoxFuture, Step};
use crate::state::AppState;

/// The architectures core offers releases for (core.md §5).
pub const ARCHES: [&str; 2] = ["aarch64", "x86_64"];
/// The default release directory of the `.deb` (core.md §5).
pub const DEFAULT_DIR: &str = "/usr/share/picket-core/edge";
/// Largest tarball and signature core reads (README §2, Bounded).
pub const MAX_TARBALL: u64 = 256 << 20;
pub const MAX_SIGNATURE: u64 = 64 << 10;
/// A release nothing offers stays this long after retention first found it so (module docs; the
/// spec names no window: 72 h, as for bundle versions, storage.md §4).
pub const OTHER_VERSION_KEEP: std::time::Duration = std::time::Duration::from_secs(72 * 3600);
/// Release rows, and release blobs (their files go in the writer's turn), one retention step
/// deletes.
const RETENTION_ROWS: i64 = 64;
const RETENTION_BLOBS: i64 = 16;

/// One verified release file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseFile {
    pub version: String,
    pub arch: String,
    /// BLAKE3 of the tarball (its blob id).
    pub blake3: String,
    pub minisig: String,
    pub size: u64,
}

/// The release core offers, and where it came from.
pub struct Releases {
    dir: PathBuf,
    keys: Vec<String>,
    offer: ArcSwap<Option<ReleaseInput>>,
    files: ArcSwap<BTreeMap<String, ReleaseFile>>,
    /// The version the last registration ran for (`None` before it ends). Held while one runs,
    /// and by a retention step, so retention never removes a file a registration found in the
    /// store before its row names it.
    registered: tokio::sync::Mutex<Option<String>>,
}

impl Releases {
    /// Releases from `dir`, verified against `keys` (minisign public keys, base64 lines).
    pub fn new(dir: PathBuf, keys: Vec<String>) -> Self {
        Self {
            dir,
            keys,
            offer: ArcSwap::from_pointee(None),
            files: ArcSwap::from_pointee(BTreeMap::new()),
            registered: tokio::sync::Mutex::new(None),
        }
    }

    /// The release core offers now (`None`: nothing offered).
    pub fn offer(&self) -> Option<ReleaseInput> {
        self.offer.load().as_ref().clone()
    }

    /// The registered file for `version` and `arch`, if core offers it.
    pub fn file(&self, version: &str, arch: &str) -> Option<ReleaseFile> {
        let f = self.files.load().get(arch).cloned()?;
        (f.version == version).then_some(f)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Verifies and registers core's own release from the release directory; raises or
    /// resolves `release_invalid`. Returns the offer.
    pub async fn register(&self, state: &AppState) -> anyhow::Result<Option<ReleaseInput>> {
        self.register_version(state, crate::VERSION).await
    }

    /// [`Self::register`] for another version (tests).
    pub async fn register_version(
        &self,
        state: &AppState,
        version: &str,
    ) -> anyhow::Result<Option<ReleaseInput>> {
        let mut ran_for = self.registered.lock().await;
        *ran_for = None;
        let dir = self.dir.join(version);
        let keys = self.keys.clone();
        let version_s = version.to_string();
        let found = tokio::task::spawn_blocking(move || scan(&dir, &version_s, &keys)).await?;
        let mut files = BTreeMap::new();
        let mut failures = Vec::new();
        for (arch, r) in found {
            match r {
                Ok(Some(f)) => {
                    files.insert(arch, f);
                }
                Ok(None) => {}
                Err(e) => failures.push(format!("{arch}: {e}")),
            }
        }
        // Copy what verified into the blob store (off the writer), then register it.
        let data_dir = state.data_dir.clone();
        let rel_dir = self.dir.join(version);
        let to_store: Vec<ReleaseFile> = files.values().cloned().collect();
        let copied = tokio::task::spawn_blocking(move || {
            to_store
                .into_iter()
                .map(|f| {
                    let path = rel_dir.join(tarball_name(&f.version, &f.arch));
                    crate::blobs::copy_in(&data_dir, &path, &f.blake3, MAX_TARBALL)
                        .map(|_| f.clone())
                        .map_err(|e| format!("{}: cannot store: {e:#}", f.arch))
                })
                .collect::<Vec<_>>()
        })
        .await?;
        let (ok, bad): (Vec<_>, Vec<_>) = copied.into_iter().partition(Result::is_ok);
        failures.extend(bad.into_iter().filter_map(Result::err));
        let ok: Vec<ReleaseFile> = ok.into_iter().filter_map(Result::ok).collect();
        let stored = state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let mut out = Vec::new();
                for f in ok {
                    register_release(&tx, &f)?;
                    out.push(Ok::<_, String>(f));
                }
                tx.commit()?;
                Ok::<_, anyhow::Error>(out)
            })
            .await?;
        let mut registered = BTreeMap::new();
        for r in stored {
            match r {
                Ok(f) => {
                    registered.insert(f.arch.clone(), f);
                }
                Err(e) => failures.push(e),
            }
        }
        let offer = if failures.is_empty() && !registered.is_empty() {
            Some(ReleaseInput {
                version: version.to_string(),
                tarballs: registered
                    .values()
                    .map(|f| (f.arch.clone(), f.blake3.clone()))
                    .collect(),
            })
        } else {
            None
        };
        let key = "release_invalid";
        if failures.is_empty() {
            if !registered.is_empty() {
                let _ = state
                    .alerts
                    .resolve(key, Some(serde_json::json!({"version": version})))
                    .await;
                tracing::info!(version, arches = ?registered.keys().collect::<Vec<_>>(), "edge release registered");
            }
            self.files.store(std::sync::Arc::new(registered));
        } else {
            // core.md §5: on failure core offers no release.
            self.files.store(std::sync::Arc::new(BTreeMap::new()));
            tracing::warn!(version, failures = ?failures, "the bundled edge release fails its check; no release offered");
            let spec = RaiseSpec::new(
                "release_invalid",
                Severity::Critical,
                key,
                format!("The edge release {version} bundled with core fails its signature check"),
                serde_json::json!({"version": version, "failures": failures}),
            );
            let _ = state.alerts.raise(spec).await;
        }
        self.offer.store(std::sync::Arc::new(offer.clone()));
        *ran_for = Some(version.to_string());
        drop(ran_for);
        // Every edge's config names the release (core.md §5).
        state.edges.publisher.trigger(None);
        Ok(offer)
    }
}

/// The retention hook for edge releases (module docs).
pub struct ReleaseRetention;

impl RetentionHook for ReleaseRetention {
    fn name(&self) -> &str {
        "edge_releases"
    }

    fn step<'a>(&'a self, state: &'a AppState) -> BoxFuture<'a, anyhow::Result<Step>> {
        Box::pin(async move {
            // A registration running now goes first; this run leaves releases alone.
            let Ok(registered) = state.edges.releases.registered.try_lock() else {
                return Ok(Step::Done);
            };
            let Some(current) = registered.clone() else {
                return Ok(Step::Done);
            };
            let now = jiff::Timestamp::now();
            let keep = jiff::SignedDuration::try_from(OTHER_VERSION_KEEP)
                .unwrap_or(jiff::SignedDuration::from_hours(72));
            let (cutoff, now) = (crate::util::ts(&(now - keep)), crate::util::ts(&now));
            let data_dir = state.data_dir.clone();
            let more = state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    let offered = serde_json::to_string(&offered_versions(&tx, &current)?)?;
                    // Offered again (a config, a core rollback): its 72 h start afresh later.
                    tx.execute(
                        "UPDATE edge_releases SET unoffered_at = NULL
                         WHERE unoffered_at IS NOT NULL AND version IN (SELECT value FROM json_each(?1))",
                        [&offered],
                    )?;
                    // Nothing offers it, as found now: its 72 h run from here.
                    tx.execute(
                        "UPDATE edge_releases SET unoffered_at = ?2
                         WHERE unoffered_at IS NULL AND version NOT IN (SELECT value FROM json_each(?1))",
                        params![offered, now],
                    )?;
                    let rows = tx.execute(
                        "DELETE FROM edge_releases WHERE (version, arch) IN
                           (SELECT version, arch FROM edge_releases WHERE unoffered_at < ?1
                              AND version NOT IN (SELECT value FROM json_each(?2)) LIMIT ?3)",
                        params![cutoff, offered, RETENTION_ROWS],
                    )?;
                    let blobs = crate::blobs::unreferenced(
                        &tx,
                        &[crate::blobs::kind::RELEASE],
                        None,
                        RETENTION_BLOBS,
                    )?;
                    for b in &blobs {
                        tx.execute("DELETE FROM blobs WHERE blake3 = ?1", [b])?;
                    }
                    tx.commit()?;
                    // Still in the writer's turn, as `compiler::retention` removes bundle blobs.
                    for b in &blobs {
                        if let Ok(p) = crate::blobs::path(&data_dir, b) {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                    Ok::<_, anyhow::Error>(
                        crate::util::sat_i64(rows) >= RETENTION_ROWS
                            || crate::util::sat_i64(blobs.len()) >= RETENTION_BLOBS,
                    )
                })
                .await?;
            drop(registered);
            Ok(if more { Step::More } else { Step::Done })
        })
    }
}

/// The release versions an edge may still be served (module docs): `current` (the version core
/// registered at start) and each one offered by a config core may still serve an edge, its
/// current config (`edge_named`, written in the transaction that swaps in what the edge port
/// serves, `edges::publish`) or a pinned one (`edge_pins`). Read in the writer's turn, so no
/// publish lands in between.
fn offered_versions(c: &rusqlite::Connection, current: &str) -> rusqlite::Result<Vec<String>> {
    let mut st = c.prepare_cached(
        "SELECT DISTINCT json_extract(cf.body_json, '$.release.version') FROM edge_configs cf
         WHERE cf.config_id IN (SELECT id FROM edge_named WHERE kind = 'config'
                                UNION SELECT id FROM edge_pins WHERE kind = 'config')
           AND json_valid(cf.body_json)",
    )?;
    let mut out: Vec<String> = st
        .query_map([], |r| r.get::<_, Option<String>>(0))?
        .filter_map(Result::transpose)
        .collect::<rusqlite::Result<_>>()?;
    out.push(current.to_string());
    out.sort();
    out.dedup();
    Ok(out)
}

/// `picket-edge-<version>-<arch>.tar.gz` (edge.md §14 Offer).
pub fn tarball_name(version: &str, arch: &str) -> String {
    format!("picket-edge-{version}-{arch}.tar.gz")
}

/// Verifies each architecture's files in `dir`. `Ok(None)`: no tarball for that architecture.
fn scan(dir: &Path, version: &str, keys: &[String]) -> Vec<(String, Result<Option<ReleaseFile>, String>)> {
    ARCHES
        .iter()
        .map(|arch| (arch.to_string(), verify_file(dir, version, arch, keys)))
        .collect()
}

fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    if buf.len() as u64 > max {
        return Err(format!("larger than {max} bytes"));
    }
    Ok(buf)
}

/// Verifies one tarball against its signature and `keys`.
pub fn verify_file(
    dir: &Path,
    version: &str,
    arch: &str,
    keys: &[String],
) -> Result<Option<ReleaseFile>, String> {
    let tar = dir.join(tarball_name(version, arch));
    let sig_path = PathBuf::from(format!("{}.minisig", tar.display()));
    match std::fs::symlink_metadata(&tar) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if sig_path.exists() {
                return Err("a signature without its tarball".into());
            }
            return Ok(None);
        }
        Err(e) => return Err(e.to_string()),
        Ok(m) if !m.is_file() => return Err("not a regular file".into()),
        Ok(_) => {}
    }
    let sig_bytes = read_capped(&sig_path, MAX_SIGNATURE).map_err(|e| format!("signature: {e}"))?;
    let sig_text = String::from_utf8(sig_bytes).map_err(|_| "signature: not text".to_string())?;
    let mut file = std::fs::File::open(&tar).map_err(|e| e.to_string())?;
    let (blake3, size) = verify_signature(&sig_text, keys, &mut file, MAX_TARBALL)?;
    let sig = Signature::decode(&sig_text).map_err(|e| format!("signature: {e}"))?;
    match picket_api::update::parse_trusted_comment(sig.trusted_comment()) {
        Some((v, a)) if v == version && a == arch => {}
        _ => {
            return Err(format!(
                "the signed trusted comment names {:?}, not picket-edge {version} {arch}",
                crate::util::sanitize_for_message(sig.trusted_comment(), 128)
            ));
        }
    }
    Ok(Some(ReleaseFile {
        version: version.to_string(),
        arch: arch.to_string(),
        blake3,
        minisig: sig_text,
        size,
    }))
}

/// Verifies `data` (read to its end, at most `max` bytes) against the minisign signature text
/// with any of `keys`; returns the data's BLAKE3 and size. The trusted comment is authenticated
/// only once this succeeds.
pub fn verify_signature<R: Read + std::io::Seek>(
    sig_text: &str,
    keys: &[String],
    data: &mut R,
    max: u64,
) -> Result<(String, u64), String> {
    let sig = Signature::decode(sig_text).map_err(|e| format!("signature: {e}"))?;
    let keys: Vec<PublicKey> = keys
        .iter()
        .filter_map(|k| PublicKey::from_base64(k.trim()).ok())
        .collect();
    if keys.is_empty() {
        return Err("no usable release_keys".into());
    }
    let mut last = String::from("no release key matches the signature");
    for key in &keys {
        let mut v = match key.verify_stream(&sig) {
            Ok(v) => v,
            Err(e) => {
                last = format!("signature: {e}");
                continue;
            }
        };
        data.rewind().map_err(|e| e.to_string())?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = data.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > max {
                return Err(format!("larger than {max} bytes"));
            }
            v.update(&buf[..n]);
            hasher.update(&buf[..n]);
        }
        match v.finalize() {
            Ok(()) => return Ok((hasher.finalize().to_hex().to_string(), total)),
            Err(e) => last = format!("signature: {e}"),
        }
    }
    Err(last)
}

/// Registers a verified tarball (already in the blob store) in `blobs` and `edge_releases`.
fn register_release(tx: &rusqlite::Transaction<'_>, f: &ReleaseFile) -> anyhow::Result<()> {
    let existing: Option<String> = tx
        .query_row(
            "SELECT blob FROM edge_releases WHERE version = ?1 AND arch = ?2",
            params![f.version, f.arch],
            |r| r.get(0),
        )
        .optional()?;
    if existing.as_deref() != Some(f.blake3.as_str()) {
        crate::blobs::register(tx, &f.blake3, crate::blobs::kind::RELEASE, f.size)?;
        tx.execute(
            "INSERT INTO edge_releases(version, arch, blob, minisig, added_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(version, arch) DO UPDATE SET blob = excluded.blob, minisig = excluded.minisig,
                added_at = excluded.added_at",
            params![f.version, f.arch, f.blake3, f.minisig, crate::util::now_ts()],
        )?;
    }
    Ok(())
}

/// The registered release file for `version`/`arch`: (blob id, minisig, added_at).
pub fn lookup(
    c: &rusqlite::Connection,
    version: &str,
    arch: &str,
) -> rusqlite::Result<Option<(String, String, String)>> {
    c.query_row(
        "SELECT blob, minisig, added_at FROM edge_releases WHERE version = ?1 AND arch = ?2",
        params![version, arch],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
}
