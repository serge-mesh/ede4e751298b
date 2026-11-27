//! The content-addressed blob store `blobs/<b3[0:2]>/<blake3>` (storage.md §1–§3): immutable,
//! deduplicated by hash, registered in the `blobs` table with a kind and a refcount.
//!
//! Small blobs are written from memory ([`put`]); large files (edge releases) are streamed in
//! through `staging/` and hash-checked ([`copy_in`]). The edge API serves blobs with `Range`
//! (`edge_api::objects`). Bundle blobs are written by the compiler outside the writer
//! ([`write_file`]), then registered with the version that names them ([`register_named`]);
//! `lookups::verdict_sets` registers verdict-set heads, bases and deltas the same way. Edge
//! releases are copied in at start ([`copy_in`], `edges::releases`).
//!
//! **Collection** (storage.md §4: blobs go once nothing retained names them). A blob keeps the
//! kind it was first registered with, so one blob can be a feed's download, a manual file, a
//! bundle's or a verdict set's file and an edge release at once (the same bytes). Each collector
//! (`feeds::retention` for `download` and `manual_file`, `compiler::retention` for `bundle`,
//! `lookups::verdict_sets` for `verdict_set`, `edges::releases` for `release`) applies its own age
//! rule to the blobs of its kinds, and takes only those no row of any kind names
//! ([`REFERENCES`], [`unreferenced`]); a blob another kind still names waits for that row, then
//! goes with its own kind's collector.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, Transaction};

pub const BLOBS_DIR: &str = "blobs";

/// Blob kinds (api.md §2 serves only bundle and verdict-set kinds to edges).
pub mod kind {
    pub const MANUAL_FILE: &str = "manual_file";
    pub const DOWNLOAD: &str = "download";
    pub const BUNDLE: &str = "bundle";
    pub const VERDICT_SET: &str = "verdict_set";
    pub const RELEASE: &str = "release";
}

/// Every column that names a blob (storage.md §4), the larger indexed tables first. A table
/// that names blobs must be listed here, or a collector may delete a blob it still names.
pub const REFERENCES: &[(&str, &str)] = &[
    ("bundle_version_blobs", "blake3"),
    ("bundle_build_blobs", "blake3"),
    ("verdict_set_blobs", "blake3"),
    ("feed_runs", "blob"),
    ("manual_files", "blob"),
    ("feed_imports", "blob"),
    ("restore_applied", "blob"),
    // The file a feed's check stored, named in the same transaction, which its ingest job holds
    // in memory until its run names it (`feeds::check`): a download whose bytes an older blob
    // already had would otherwise go in between.
    ("feed_state", "seen_blake3"),
    ("edge_releases", "blob"),
];

/// An SQL condition, true when no row of [`REFERENCES`] names the blob `<alias>.blake3`.
pub fn unreferenced_sql(alias: &str) -> String {
    REFERENCES
        .iter()
        .map(|(t, c)| format!("NOT EXISTS (SELECT 1 FROM {t} r WHERE r.{c} = {alias}.blake3)"))
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// Up to `limit` blobs of `kinds` registered before `before` (any time with `None`) that nothing
/// names (module docs): what a collector of those kinds may delete, in its transaction, removing
/// their files after its commit while still in the writer's turn, so no registration can come
/// in between.
pub fn unreferenced(
    c: &rusqlite::Connection,
    kinds: &[&str],
    before: Option<&str>,
    limit: i64,
) -> rusqlite::Result<Vec<String>> {
    let kinds_json = serde_json::to_string(kinds).unwrap_or_else(|_| "[]".into());
    let mut st = c.prepare_cached(&format!(
        "SELECT b.blake3 FROM blobs b
         WHERE b.kind IN (SELECT value FROM json_each(?1)) AND (?2 IS NULL OR b.created_at < ?2)
           AND {}
         LIMIT ?3",
        unreferenced_sql("b")
    ))?;
    st.query_map(rusqlite::params![kinds_json, before, limit], |r| r.get(0))?
        .collect()
}

/// The path of a blob.
pub fn path(data_dir: &Path, b3: &str) -> Result<PathBuf> {
    if !picket_api::ids::is_object_id(b3) {
        bail!("bad blob id");
    }
    Ok(data_dir.join(BLOBS_DIR).join(&b3[..2]).join(b3))
}

/// Stores `bytes` (if new), registers it and adds one reference. Returns its BLAKE3.
pub fn put(tx: &Transaction<'_>, data_dir: &Path, kind: &str, bytes: &[u8]) -> Result<String> {
    let b3 = picket_api::ids::object_id(bytes);
    let p = path(data_dir, &b3)?;
    if !p.exists() {
        let dir = p.parent().context("blob dir")?;
        crate::util::ensure_dir(dir)?;
        // Written in staging/ (emptied at every start, README §2 Restarts), then renamed into
        // place, so a crash never leaves a partial file in the blob store.
        let staging = data_dir.join("staging");
        crate::util::ensure_dir(&staging)?;
        let tmp = staging.join(format!("blob-{}-{}.tmp", &b3[..16], crate::util::random_hex(8)));
        crate::util::write_private_new(&tmp, bytes)?;
        if let Err(e) = std::fs::rename(&tmp, &p) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("move a blob into {}", dir.display()));
        }
        crate::util::fsync_dir(dir)?;
    }
    tx.execute(
        "INSERT INTO blobs(blake3, kind, size, created_at, refcount) VALUES (?1, ?2, ?3, ?4, 1)
         ON CONFLICT(blake3) DO UPDATE SET refcount = refcount + 1",
        rusqlite::params![b3, kind, bytes.len(), crate::util::now_ts()],
    )?;
    Ok(b3)
}

/// Writes `bytes` into the store as a file (if it isn't there yet), through `staging/`, without
/// touching the database: the compiler writes a version's blobs before its commit and registers
/// them in that transaction ([`register_named`]). A file whose commit never happens is harmless
/// (nothing names it) and is overwritten by the same bytes next time. Returns its BLAKE3.
pub fn write_file(data_dir: &Path, bytes: &[u8]) -> Result<String> {
    let b3 = picket_api::ids::object_id(bytes);
    let p = path(data_dir, &b3)?;
    if p.exists() {
        return Ok(b3);
    }
    let dir = p.parent().context("blob dir")?;
    crate::util::ensure_dir(dir)?;
    let staging = data_dir.join("staging");
    crate::util::ensure_dir(&staging)?;
    let tmp = staging.join(format!("blob-{}-{}.tmp", &b3[..16], crate::util::random_hex(8)));
    crate::util::write_private_new(&tmp, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, &p) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("move a blob into {}", dir.display()));
    }
    crate::util::fsync_dir(dir)?;
    Ok(b3)
}

/// Registers a blob [`write_file`] wrote, as `kind`, and adds one reference (one per version that
/// names it).
pub fn register_named(tx: &Transaction<'_>, b3: &str, kind: &str, size: u64) -> Result<()> {
    register(tx, b3, kind, size)
}

/// Streams the file at `src` into the blob store as `expected` (its BLAKE3), through
/// `staging/` (emptied at every start), checking the hash and the size bound before the rename,
/// so the store never holds a partial or different file. Filesystem only: register it with
/// [`register`]. Returns the size.
pub fn copy_in(data_dir: &Path, src: &Path, expected: &str, max: u64) -> Result<u64> {
    use std::io::{Read, Write};
    let dst = path(data_dir, expected)?;
    if let Ok(m) = std::fs::metadata(&dst) {
        return Ok(m.len());
    }
    let dir = dst.parent().context("blob dir")?;
    crate::util::ensure_dir(dir)?;
    let staging = data_dir.join("staging");
    crate::util::ensure_dir(&staging)?;
    let tmp = staging.join(format!(
        "blob-{}-{}.tmp",
        &expected[..16],
        crate::util::random_hex(8)
    ));
    let result = (|| -> Result<u64> {
        let mut input = std::fs::File::open(src).with_context(|| format!("open {}", src.display()))?;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > max {
                bail!("{} is larger than {max} bytes", src.display());
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
        }
        out.sync_all()?;
        if hasher.finalize().to_hex().as_str() != expected {
            bail!("{} changed while it was copied", src.display());
        }
        std::fs::rename(&tmp, &dst).with_context(|| format!("move a blob into {}", dir.display()))?;
        crate::util::fsync_dir(dir)?;
        Ok(total)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Registers a blob already in the store (from [`copy_in`]) and adds one reference.
pub fn register(tx: &Transaction<'_>, b3: &str, kind: &str, size: u64) -> Result<()> {
    tx.execute(
        "INSERT INTO blobs(blake3, kind, size, created_at, refcount) VALUES (?1, ?2, ?3, ?4, 1)
         ON CONFLICT(blake3) DO UPDATE SET refcount = refcount + 1",
        rusqlite::params![b3, kind, size, crate::util::now_ts()],
    )?;
    Ok(())
}

/// A blob's kind, size and creation time, if it is registered.
pub fn info(c: &rusqlite::Connection, b3: &str) -> Result<Option<(String, u64, String)>> {
    Ok(c.query_row(
        "SELECT kind, size, created_at FROM blobs WHERE blake3 = ?1",
        [b3],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                crate::util::nonneg(r.get(1)?),
                r.get::<_, String>(2)?,
            ))
        },
    )
    .optional()?)
}

/// Reads a whole blob after checking its hash.
pub fn read(tx: &rusqlite::Connection, data_dir: &Path, b3: &str) -> Result<Option<Vec<u8>>> {
    let known: Option<String> = tx
        .query_row("SELECT blake3 FROM blobs WHERE blake3 = ?1", [b3], |r| r.get(0))
        .optional()?;
    if known.is_none() {
        return Ok(None);
    }
    let bytes = std::fs::read(path(data_dir, b3)?)?;
    if picket_api::ids::object_id(&bytes) != b3 {
        bail!("blob {b3} fails its hash check");
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_read_leave_no_temporary_file() {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let mut c = crate::db::open_connection(&opts, 1024).unwrap();
        let tx = c.transaction().unwrap();
        let b3 = put(&tx, d.path(), kind::MANUAL_FILE, b"||a.example^\n").unwrap();
        assert_eq!(
            put(&tx, d.path(), kind::MANUAL_FILE, b"||a.example^\n").unwrap(),
            b3
        );
        assert_eq!(read(&tx, d.path(), &b3).unwrap().unwrap(), b"||a.example^\n");
        let fan = d.path().join(BLOBS_DIR).join(&b3[..2]);
        assert_eq!(std::fs::read_dir(fan).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(d.path().join("staging")).unwrap().count(), 0);
    }
}
