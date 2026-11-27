//! Where bundle and verdict-set files live, and how they are fetched (edge.md §2, §13;
//! edge-unifi.md §1 "Bundles"; bundles.md §7; api.md §2 objects).
//!
//! - **Hot files** (heads, hot shard bases, IP shard bases, segments, hot and IP deltas):
//!   `<bundles>/<bundle>/heads/<head>.json` and `<bundles>/<bundle>/blobs/<blake3>`, where
//!   `<bundles>` is where bundles are kept at that moment ([`crate::storage::Storage::bundles_location`]):
//!   the SSD while it passes its checks, the eMMC copy in `data_dir` during an SSD failure (or its
//!   only place without `ssd_dir`), or memory only in the first 10 minutes after start.
//! - **Cold files** (cold shard manifests, cold filters, page files, cold deltas):
//!   `<cold root>/bundles/<bundle>/cold/<blake3>`, only where cold parts can live (the SSD;
//!   `data_dir` on Debian without `ssd_dir`), never in the eMMC copy or in memory.
//! - **Verdict sets:** `<cold root>/verdicts/<provider>/heads/<head>.json` and `…/blobs/<blake3>`.
//!
//! Every file is named by its BLAKE3 and verified before use, so a file can come from the SSD,
//! the eMMC copy or core (edge-unifi.md §1). A local file that fails verification is deleted and
//! fetched again. Writes are tmp → fsync → rename; the edge never keeps a file open on the SSD
//! between uses. A write that fails on the SSD asks for an SSD re-check (the bytes stay usable
//! in memory for the activation at hand); a move to the SSD ([`place`]) reports it instead.
//!
//! **RAM** (README §2, edge.md §17): every object is capped before it is read ([`Caps`]: no
//! file the edge loads can be larger than its bundle budget, nor a delta larger than its
//! overlays could hold); a blob downloaded where files are kept is streamed to disk (verified as
//! it arrives) and read back once, so it is never held twice; only in the memory-only window is a
//! download buffered in RAM.

use std::io::Read;
use std::path::{Path, PathBuf};

use picket_api::edge_api::keys;

use crate::core_client::{ClientError, ObjectReply};
use crate::edge::Edge;
use crate::fsutil::{self, WriteOpts};
use crate::logs::spool::Loc;
use crate::storage::BundlesLocation;

/// Largest head (`head.json`, verdict-set head) accepted (picket-bundle's own limit).
pub const MAX_HEAD: u64 = picket_bundle::head::MAX_HEAD_BYTES as u64;
/// Largest shard manifest.
pub const MAX_MANIFEST: u64 = 1 << 20;
/// Largest file read into memory (segments, `ips.bin`, shard files, deltas), whatever the budgets.
pub const MAX_BLOB: u64 = 1 << 30;
/// Largest page file (cold shard base, verdict-set base): never read into memory.
pub const MAX_PAGE_FILE: u64 = 16 << 30;

/// The largest object of each kind the edge reads into memory, from its budgets (edge.md §17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// A file loaded into RAM (shard files, `ips.bin`, segments, cold filters): no single file
    /// can be larger than the whole bundle budget.
    pub file: u64,
    /// A delta (compressed): its ops all land in an overlay, so a delta past a multiple of the
    /// overlay budget can't fit (8×: gzip'd ops are smaller than overlay entries; a policy
    /// bound), and never past `file`.
    pub delta: u64,
}

impl Caps {
    pub fn of(m: &picket_api::edge_config::MemoryConfig) -> Caps {
        let file = u64::from(m.bundle_budget_mib)
            .saturating_mul(1 << 20)
            .clamp(1 << 20, MAX_BLOB);
        let delta = u64::from(m.overlay_budget_mib)
            .saturating_mul(8 << 20)
            .clamp(1 << 20, file);
        Caps { file, delta }
    }
}

/// Why a step of an activation failed (`activation_failed`'s `stage` and `reason`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepError {
    pub stage: &'static str,
    pub reason: String,
    /// The object can't run as it stands (it doesn't fit the budget, or core sent something
    /// invalid): not retried until core sends another object.
    pub permanent: bool,
}

impl StepError {
    pub fn retry(stage: &'static str, reason: impl Into<String>) -> Self {
        Self {
            stage,
            reason: crate::diag::cap(reason.into()),
            permanent: false,
        }
    }
    pub fn permanent(stage: &'static str, reason: impl Into<String>) -> Self {
        Self {
            stage,
            reason: crate::diag::cap(reason.into()),
            permanent: true,
        }
    }
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage, self.reason)
    }
}

/// Which tree a file belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tree {
    /// A bundle's hot files.
    Hot,
    /// A bundle's cold files.
    Cold,
    /// A verdict set's files.
    Verdicts,
}

/// The directory hot files are written to now (`None`: memory only). While an eMMC copy exists
/// it stays the authority, so activations go there until the move to the SSD has completed
/// (edge-unifi.md §1 "When the SSD passes": the SSD's record is never newer than the copy).
pub fn hot_write_root(edge: &Edge) -> Option<PathBuf> {
    match edge.storage.bundles_location() {
        BundlesLocation::Ssd(p) => {
            let emmc = edge.layout.bundles_dir();
            if emmc != p && emmc.join("active.json").exists() {
                Some(emmc)
            } else {
                Some(p)
            }
        }
        BundlesLocation::DataDir(p) => Some(p),
        BundlesLocation::MemoryOnly => None,
    }
}

/// Every directory hot files may be read from: the eMMC copy (or Debian's `data_dir`), then the
/// SSD while it passes. A file is verified whatever its source.
pub fn hot_read_roots(edge: &Edge) -> Vec<PathBuf> {
    let mut v = vec![edge.layout.bundles_dir()];
    if let Some(s) = &edge.storage.ssd
        && edge.storage.ssd_passing()
    {
        v.push(s.bundles_dir());
    }
    v
}

/// The bundles tree cold files live in, if cold parts can be loaded now.
pub fn cold_root(edge: &Edge) -> Option<PathBuf> {
    edge.storage.cold_root().map(|r| r.join("bundles"))
}

/// The verdict-set tree, if verdict sets can be loaded now.
pub fn verdicts_root(edge: &Edge) -> Option<PathBuf> {
    edge.storage.cold_root().map(|r| r.join("verdicts"))
}

/// A file's path in `root` for `scope` (a bundle or provider id).
pub fn blob_path(root: &Path, tree: Tree, scope: &str, id: &str) -> PathBuf {
    match tree {
        Tree::Hot | Tree::Verdicts => root.join(scope).join("blobs").join(id),
        Tree::Cold => root.join(scope).join("cold").join(id),
    }
}

/// A head's path in `root`.
pub fn head_path(root: &Path, scope: &str, id: &str) -> PathBuf {
    root.join(scope).join("heads").join(format!("{id}.json"))
}

/// Which storage location a path is in, for disk-use accounting.
fn loc_of(edge: &Edge, p: &Path) -> Loc {
    match &edge.storage.ssd {
        Some(s) if p.starts_with(&s.root) => Loc::Ssd,
        _ => Loc::DataDir,
    }
}

/// Deletes a file, keeping the disk-use count.
pub fn remove(edge: &Edge, path: &Path) {
    if let Ok(m) = std::fs::symlink_metadata(path)
        && std::fs::remove_file(path).is_ok()
    {
        edge.storage.disk.add(
            loc_of(edge, path),
            fsutil::byte_delta(0, fsutil::allocated_bytes(&m)),
        );
    }
}

/// Writes `bytes` at `path` (tmp → fsync → rename, 0640), creating its directory.
pub fn write_file(edge: &Edge, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fsutil::create_dir_all_mode(dir, 0o750)?;
    }
    fsutil::atomic_write(path, bytes, WriteOpts::mode(0o640))?;
    if let Ok(m) = std::fs::metadata(path) {
        edge.storage.disk.add(
            loc_of(edge, path),
            fsutil::byte_delta(fsutil::allocated_bytes(&m), 0),
        );
    }
    Ok(())
}

fn client_error(stage: &'static str, key: &str, e: ClientError) -> StepError {
    match e {
        // Core sent something that fails verification or a limit: core is untrusted (README §2).
        ClientError::Invalid(m) => StepError::retry("verify", format!("{key}: {m}")),
        other => StepError::retry(stage, format!("{key}: {other}")),
    }
}

/// The bytes of an object `id` (its BLAKE3) of `tree`/`scope`: from a local copy that verifies,
/// else from core (`key` in the objects bucket), written where that tree is kept now. `None` for
/// `write_root` keeps a downloaded file in memory only.
#[expect(
    clippy::too_many_arguments,
    reason = "one fetch: where it reads and writes, what, and its size limit"
)]
pub async fn fetch_bytes(
    edge: &Edge,
    read_roots: &[PathBuf],
    write_root: Option<&Path>,
    tree: Tree,
    scope: &str,
    id: &str,
    key: &str,
    max: u64,
) -> Result<Vec<u8>, StepError> {
    let is_head = key.ends_with(".json") && key.contains("/heads/");
    let path_for = |root: &Path| {
        if is_head {
            head_path(root, scope, id)
        } else {
            blob_path(root, tree, scope, id)
        }
    };
    for root in read_roots {
        let p = path_for(root);
        let id2 = id.to_owned();
        let found = {
            let p = p.clone();
            tokio::task::spawn_blocking(move || std::fs::metadata(&p).is_ok())
                .await
                .unwrap_or(false)
        };
        if !found {
            continue;
        }
        if let Some(b) = read_local(edge, &p, &id2, max).await {
            // A copy found elsewhere is written where files are kept now (the SSD after an
            // SSD failure, say: edge-unifi.md §1).
            if let Some(w) = write_root
                && w != root.as_path()
            {
                let dst = path_for(w);
                if std::fs::metadata(&dst).is_err() && write_file(edge, &dst, &b).is_err() {
                    edge.storage.recheck();
                }
            }
            return Ok(b);
        }
    }
    let Some(core) = edge.core.load_full() else {
        return Err(StepError::retry(
            "fetch",
            format!("{key}: no local copy, and no core to fetch it from"),
        ));
    };
    // Where files are kept: streamed to disk as it arrives (verified), then read back once.
    if let Some(w) = write_root
        && !is_head
    {
        let p = path_for(w);
        match download_to(edge, &core, &p, id, key, max).await {
            Ok(()) => {
                let p2 = p.clone();
                match tokio::task::spawn_blocking(move || fsutil::read_nofollow_bounded(&p2, max)).await {
                    Ok(Ok(b)) => return Ok(b),
                    _ => {
                        tracing::warn!("reading back {}", p.display());
                        edge.storage.recheck();
                    }
                }
            }
            // The SSD may have just gone away: fetch into memory for this activation
            // (edge-unifi.md §1: retried where it would go after a failed check).
            Err(StepError { stage: "store", .. }) => edge.storage.recheck(),
            Err(e) => return Err(e),
        }
    }
    let bytes = match core.get_object(key, None, max).await {
        Ok(ObjectReply::Body { bytes, .. }) => bytes,
        Ok(ObjectReply::NotModified) => {
            return Err(StepError::retry("fetch", format!("{key}: unexpected 304")));
        }
        Err(e) => return Err(client_error("fetch", key, e)),
    };
    if picket_api::ids::object_id(&bytes) != id {
        return Err(StepError::retry("verify", format!("{key}: blake3 mismatch")));
    }
    let bytes = Vec::from(bytes);
    if let Some(w) = write_root {
        let p = path_for(w);
        if let Err(e) = write_file(edge, &p, &bytes) {
            // The SSD may have just gone away: the bytes still serve this activation
            // (edge-unifi.md §1: retried where it would go after a failed check).
            tracing::warn!("writing {}: {}", p.display(), crate::diag::cap(e));
            edge.storage.recheck();
        }
    }
    Ok(bytes)
}

/// Downloads object `id` from core straight to `path` (streamed, BLAKE3-checked as it arrives,
/// tmp → fsync → rename), keeping the disk-use count. A local write failure is stage `store`.
async fn download_to(
    edge: &Edge,
    core: &crate::core_client::CoreClient,
    path: &Path,
    id: &str,
    key: &str,
    max: u64,
) -> Result<(), StepError> {
    let dir = path
        .parent()
        .ok_or_else(|| StepError::retry("store", "a file with no directory"))?;
    if let Err(e) = fsutil::create_dir_all_mode(dir, 0o750) {
        return Err(StepError::retry("store", format!("{}: {e}", dir.display())));
    }
    match core.download_object(key, dir, id, max).await {
        Ok(final_path) => {
            if let Ok(m) = std::fs::metadata(&final_path) {
                edge.storage.disk.add(
                    loc_of(edge, &final_path),
                    fsutil::byte_delta(fsutil::allocated_bytes(&m), 0),
                );
            }
            Ok(())
        }
        Err(ClientError::Io(m)) => Err(StepError::retry("store", format!("{key}: {m}"))),
        Err(e) => Err(client_error("fetch", key, e)),
    }
}

/// Puts object `id` at `dest` for a move between locations (edge-unifi.md §1): kept when the file
/// there verifies, else copied from a local copy in `read_roots` that verifies, else downloaded
/// from core. Unlike [`fetch_bytes`], a failed write is an error: the move stops there.
pub async fn place(
    edge: &Edge,
    read_roots: &[PathBuf],
    dest: &Path,
    id: &str,
    key: &str,
    max: u64,
    is_head: bool,
) -> Result<(), StepError> {
    // Hashes and copies stream (64 KiB at a time): a move never holds a file in RAM.
    let verifies = |p: PathBuf, id: String| async move {
        tokio::task::spawn_blocking(move || {
            std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file() && m.len() <= max)
                && hash_file(&p).is_some_and(|h| h == id)
        })
        .await
        .unwrap_or(false)
    };
    if verifies(dest.to_path_buf(), id.to_owned()).await {
        return Ok(());
    }
    let rel = |root: &Path| -> Option<PathBuf> {
        // The same file in another root: the destination's path below its own root.
        let name = dest.file_name()?;
        let parent = dest.parent()?;
        let sub = parent.file_name()?; // blobs | heads | cold
        let scope = parent.parent()?.file_name()?;
        Some(root.join(scope).join(sub).join(name))
    };
    for root in read_roots {
        let Some(src) = rel(root).filter(|p| p != dest) else {
            continue;
        };
        if !verifies(src.clone(), id.to_owned()).await {
            continue;
        }
        let (s2, d2) = (src.clone(), dest.to_path_buf());
        let copied = tokio::task::spawn_blocking(move || copy_file(&s2, &d2))
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
        match copied {
            Ok(()) if verifies(dest.to_path_buf(), id.to_owned()).await => {
                if let Ok(m) = std::fs::metadata(dest) {
                    edge.storage.disk.add(
                        loc_of(edge, dest),
                        fsutil::byte_delta(fsutil::allocated_bytes(&m), 0),
                    );
                }
                return Ok(());
            }
            Ok(()) => {
                remove(edge, dest);
                return Err(StepError::retry(
                    "store",
                    format!("{}: the copy doesn't verify", dest.display()),
                ));
            }
            Err(e) => {
                return Err(StepError::retry("store", format!("{}: {e}", dest.display())));
            }
        }
    }
    let Some(core) = edge.core.load_full() else {
        return Err(StepError::retry(
            "fetch",
            format!("{key}: no local copy, and no core to fetch it from"),
        ));
    };
    if is_head {
        let bytes = match core.get_object(key, None, max).await {
            Ok(ObjectReply::Body { bytes, .. }) => bytes,
            Ok(ObjectReply::NotModified) => {
                return Err(StepError::retry("fetch", format!("{key}: unexpected 304")));
            }
            Err(e) => return Err(client_error("fetch", key, e)),
        };
        if picket_api::ids::object_id(&bytes) != id {
            return Err(StepError::retry("verify", format!("{key}: blake3 mismatch")));
        }
        return write_file(edge, dest, &bytes)
            .map_err(|e| StepError::retry("store", format!("{}: {e}", dest.display())));
    }
    download_to(edge, &core, dest, id, key, max).await
}

/// Copies `src` to `dest` (tmp → fsync → rename, 0640, then the directory synced), streaming.
fn copy_file(src: &Path, dest: &Path) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = dest
        .parent()
        .ok_or_else(|| std::io::Error::other("a file with no directory"))?;
    fsutil::create_dir_all_mode(dir, 0o750)?;
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other("a file with no name"))?;
    let tmp = dir.join(fsutil::tmp_name(name));
    let r = (|| {
        let mut from = std::fs::File::open(src)?;
        let mut to = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .custom_flags(fsutil::o_nofollow())
            .open(&tmp)?;
        std::io::copy(&mut from, &mut to)?;
        to.flush()?;
        to.sync_all()?;
        std::fs::rename(&tmp, dest)?;
        fsutil::fsync_dir(dir)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

async fn read_local(edge: &Edge, path: &Path, id: &str, max: u64) -> Option<Vec<u8>> {
    let p = path.to_path_buf();
    let id = id.to_owned();
    // `remove` needs the edge for disk accounting; do the read in a blocking thread and the
    // removal (rare) here.
    let r = tokio::task::spawn_blocking(move || match fsutil::read_nofollow_bounded(&p, max) {
        Ok(b) if picket_api::ids::object_id(&b) == id => Ok(Some(b)),
        Ok(_) => Err(()),
        Err(_) => Ok(None),
    })
    .await
    .unwrap_or(Ok(None));
    match r {
        Ok(b) => b,
        Err(()) => {
            tracing::warn!("{} fails its BLAKE3 check; fetching it again", path.display());
            remove(edge, path);
            None
        }
    }
}

/// Makes sure the page file `id` is at `path` and verified (streaming BLAKE3, never read into
/// memory): a local copy is hashed, else it is downloaded from core straight to disk.
/// `verified` remembers files already hashed by this process.
pub async fn ensure_page_file(
    edge: &Edge,
    path: &Path,
    id: &str,
    key: &str,
    size: Option<u64>,
    already_verified: bool,
) -> Result<(), StepError> {
    if already_verified && std::fs::metadata(path).is_ok() {
        return Ok(());
    }
    let p = path.to_path_buf();
    let id2 = id.to_owned();
    let ok = tokio::task::spawn_blocking(move || hash_file(&p).is_some_and(|h| h == id2))
        .await
        .unwrap_or(false);
    if ok {
        return Ok(());
    }
    remove(edge, path);
    let Some(core) = edge.core.load_full() else {
        return Err(StepError::retry(
            "fetch",
            format!("{key}: no local copy, and no core to fetch it from"),
        ));
    };
    let dir = path
        .parent()
        .ok_or_else(|| StepError::retry("fetch", "page file has no directory"))?;
    if let Err(e) = fsutil::create_dir_all_mode(dir, 0o750) {
        edge.storage.recheck();
        return Err(StepError::retry("fetch", format!("{}: {}", dir.display(), e)));
    }
    let max = size.unwrap_or(MAX_PAGE_FILE).min(MAX_PAGE_FILE);
    match core.download_object(key, dir, id, max).await {
        Ok(final_path) => {
            if let Ok(m) = std::fs::metadata(&final_path) {
                edge.storage.disk.add(
                    loc_of(edge, &final_path),
                    fsutil::byte_delta(fsutil::allocated_bytes(&m), 0),
                );
            }
            Ok(())
        }
        Err(ClientError::Io(m)) => {
            edge.storage.recheck();
            Err(StepError::retry("fetch", format!("{key}: {m}")))
        }
        Err(e) => Err(client_error("fetch", key, e)),
    }
}

/// The BLAKE3 of a file, streamed.
pub fn hash_file(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().to_hex().to_string())
}

/// The objects-bucket key of a blob.
pub fn blob_key(id: &str) -> String {
    keys::blob(id)
}
