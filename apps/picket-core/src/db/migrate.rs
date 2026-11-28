//! Schema migrations (storage.md §5, core.md §13).
//!
//! Each file records its version in `PRAGMA user_version`. At start, before serving, `run`
//! migrates `core.db` and `metrics.db` forward with the compiled-in steps of [`super::schema`],
//! one transaction per file. Before migrating it copies both with `VACUUM INTO` to
//! `pre-migration/` (replacing the previous copy); with too little free space it migrates
//! nothing and exits 78. If either migration fails it puts both copies back and exits 78, so the
//! previous release starts again. A file newer than this binary also exits 78.
//!
//! The copies are written, then `pre-migration/in-progress`, then the files are migrated; the
//! marker goes only once both files are at the latest version (or the copies were put back). A
//! start that finds it resumes the interrupted migration with the copies it already has, and
//! never replaces them with the half-migrated pair (README §2 Restarts; storage.md §5).
//!
//! This module implements the `user_version` scheme of the spec's default migration crate,
//! `rusqlite_migration`, which isn't a dependency: it can't be linked with the workspace's
//! rusqlite 0.43 (it requires 0.41).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rusqlite::Connection;

use super::{DbOptions, open_connection};
use crate::error::ExitError;

/// A file's migration steps: step `i` takes the schema from version `i` to `i + 1`.
#[derive(Clone, Copy, Debug)]
pub struct Migrations {
    pub name: &'static str,
    pub steps: &'static [&'static str],
}

impl Migrations {
    pub fn latest(&self) -> u32 {
        u32::try_from(self.steps.len()).unwrap_or(u32::MAX)
    }
}

pub const CORE: Migrations = Migrations {
    name: "core.db",
    steps: super::schema::CORE,
};
pub const METRICS: Migrations = Migrations {
    name: "metrics.db",
    steps: super::schema::METRICS,
};

/// Where a file stands against the binary's migrations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    UpToDate,
    Pending { from: u32, to: u32 },
    Newer { found: u32, known: u32 },
}

pub fn user_version(conn: &Connection) -> Result<u32> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    u32::try_from(v).map_err(|_| anyhow!("bad user_version {v}"))
}

pub fn status(conn: &Connection, m: &Migrations) -> Result<Status> {
    let v = user_version(conn)?;
    let latest = m.latest();
    Ok(if v == latest {
        Status::UpToDate
    } else if v < latest {
        Status::Pending { from: v, to: latest }
    } else {
        Status::Newer {
            found: v,
            known: latest,
        }
    })
}

/// Applies the pending steps in one transaction. Refuses a newer file.
pub fn apply(conn: &mut Connection, m: &Migrations) -> Result<()> {
    let from = match status(conn, m)? {
        Status::UpToDate => return Ok(()),
        Status::Pending { from, .. } => from,
        Status::Newer { found, known } => {
            return Err(anyhow!(
                "{} has schema version {found}, newer than this picket-core knows ({known})",
                m.name
            ));
        }
    };
    let tx = conn.transaction()?;
    for (i, step) in m.steps.iter().enumerate().skip(from as usize) {
        tx.execute_batch(step)
            .with_context(|| format!("{} migration step {}", m.name, i + 1))?;
    }
    tx.pragma_update(None, "user_version", m.latest())?;
    tx.commit()?;
    Ok(())
}

/// Creates a fresh file (for `init`) and applies every step.
pub fn create_fresh(opts: &DbOptions, m: &Migrations) -> Result<()> {
    let mut conn = open_connection(opts, opts.writer_cache_kib)?;
    apply(&mut conn, m)
}

const PRE_MIGRATION: &str = "pre-migration";
/// In `pre-migration/` while the copies there are the pair from before an unfinished migration.
pub const IN_PROGRESS: &str = "in-progress";

/// Extra free space asked for beyond the copies and the migration's growth.
const MIGRATION_MARGIN: u64 = 64 * 1024 * 1024;

/// Migrates `core.db` and `metrics.db` in `data_dir` before serving. Errors are exit-78 errors
/// with a message for the operator.
pub fn migrate_databases(data_dir: &Path) -> Result<(), ExitError> {
    let core = DbOptions::core(data_dir);
    let metrics = DbOptions::metrics(data_dir);
    if !core.path.exists() {
        return Err(ExitError::config(format!(
            "{} is missing in {}; restore it from a backup (the marker says an instance lives here)",
            core.path.display(),
            data_dir.display()
        )));
    }
    migrate_pair(data_dir, (&core, &CORE), (&metrics, &METRICS), free_space)
}

/// The free bytes available to core on the filesystem holding `path`.
pub fn free_space(path: &Path) -> Result<u64> {
    let st = rustix::fs::statvfs(path).with_context(|| format!("statvfs {}", path.display()))?;
    Ok(st.f_bavail.saturating_mul(st.f_frsize))
}

/// The migration procedure, with the migration lists and the free-space probe injectable for
/// tests.
pub fn migrate_pair(
    data_dir: &Path,
    a: (&DbOptions, &Migrations),
    b: (&DbOptions, &Migrations),
    free: impl Fn(&Path) -> Result<u64>,
) -> Result<(), ExitError> {
    migrate_pair_until(data_dir, a, b, free, false)
}

/// [`migrate_pair`]; with `stop_after_first`, it returns right after migrating the first file,
/// as a process killed there would (tests).
fn migrate_pair_until(
    data_dir: &Path,
    a: (&DbOptions, &Migrations),
    b: (&DbOptions, &Migrations),
    free: impl Fn(&Path) -> Result<u64>,
    stop_after_first: bool,
) -> Result<(), ExitError> {
    let fail = |msg: String| ExitError::config(msg);
    let mut statuses = Vec::new();
    for (opts, m) in [a, b] {
        let conn = open_connection(opts, 2048)
            .map_err(|e| fail(format!("cannot open {}: {e:#}", opts.path.display())))?;
        let st = status(&conn, m).map_err(|e| fail(format!("{}: {e:#}", m.name)))?;
        if let Status::Newer { found, known } = st {
            return Err(fail(format!(
                "{} has schema version {found}, newer than this picket-core ({}) knows ({known}); \
                 start the newer release, or restore a backup made by this one",
                opts.path.display(),
                crate::VERSION
            )));
        }
        statuses.push(st);
    }
    let pre = data_dir.join(PRE_MIGRATION);
    let marker = pre.join(IN_PROGRESS);
    let copies = [copy_path(&pre, a.0), copy_path(&pre, b.0)];
    let resuming = marker.exists();
    if statuses.iter().all(|s| *s == Status::UpToDate) {
        if resuming {
            // Both files got to the latest version before the marker could go.
            remove_marker(&marker).map_err(|e| fail(format!("{e:#}")))?;
        }
        return Ok(());
    }

    let size = file_size_with_wal(&a.0.path).saturating_add(file_size_with_wal(&b.0.path));
    if resuming {
        // An interrupted migration: the copies are the pair from before it, the only one the
        // previous release can start from. Keep them; finish the migration.
        if let Some(missing) = copies.iter().find(|c| !c.exists()) {
            return Err(fail(format!(
                "an interrupted migration left {} without its copy {}; restore {} and {} from a backup",
                pre.display(),
                missing.display(),
                a.0.path.display(),
                b.0.path.display()
            )));
        }
        let needed = size.saturating_add(MIGRATION_MARGIN);
        let available = free(data_dir).map_err(|e| fail(format!("{e:#}")))?;
        if available < needed {
            return Err(fail(format!(
                "not enough free space in {} to finish an interrupted migration: about {} MiB needed, {} MiB \
                 available; the pre-migration copies in {} are kept",
                data_dir.display(),
                needed / (1024 * 1024),
                available / (1024 * 1024),
                pre.display()
            )));
        }
        tracing::warn!(dir = %pre.display(), "resuming an interrupted migration; keeping its pre-migration copies");
    } else {
        // Free space: room for both copies, and as much again for the migration itself (a step
        // that rewrites a table grows the file and its WAL by up to its size), plus a margin.
        // The previous copies are replaced, so their space counts as free.
        let needed = size.saturating_mul(2).saturating_add(MIGRATION_MARGIN);
        let reclaimable: u64 = copies
            .iter()
            .filter_map(|c| fs::metadata(c).ok())
            .map(|m| m.len())
            .sum();
        let available = free(data_dir)
            .map_err(|e| fail(format!("{e:#}")))?
            .saturating_add(reclaimable);
        if available < needed {
            return Err(fail(format!(
                "not enough free space in {} to migrate: about {} MiB needed for the pre-migration copies \
                 and the migration, {} MiB available; nothing was changed",
                data_dir.display(),
                needed / (1024 * 1024),
                available / (1024 * 1024)
            )));
        }

        crate::util::ensure_dir(&pre).map_err(|e| fail(format!("{e:#}")))?;
        // The previous copies hold an older schema than the live files: they can't help any
        // more. Removing them first frees the space the check above counted.
        for c in &copies {
            let _ = fs::remove_file(c);
        }
        for (opts, copy) in [(a.0, &copies[0]), (b.0, &copies[1])] {
            vacuum_into(opts, copy).map_err(|e| {
                fail(format!(
                    "cannot copy {} before migrating: {e:#}; nothing was changed",
                    opts.path.display()
                ))
            })?;
        }
        // Durable before either file changes.
        crate::util::write_atomic(&marker, crate::util::now_ts().as_bytes(), 0o600).map_err(|e| {
            fail(format!(
                "cannot mark the migration as started: {e:#}; nothing was changed"
            ))
        })?;
        tracing::info!(dir = %pre.display(), "pre-migration copies written");
    }

    let mut failure = None;
    for (i, (opts, m)) in [a, b].into_iter().enumerate() {
        let r = (|| -> Result<()> {
            let mut conn = open_connection(opts, opts.writer_cache_kib)?;
            apply(&mut conn, m)?;
            conn.close().map_err(|(_, e)| anyhow::Error::from(e))?;
            Ok(())
        })();
        if let Err(e) = r {
            failure = Some(format!("{} migration failed: {e:#}", m.name));
            break;
        }
        if stop_after_first && i == 0 {
            return Ok(());
        }
    }
    if let Some(msg) = failure {
        let restored = restore(a.0, &copies[0])
            .and_then(|_| restore(b.0, &copies[1]))
            // The live pair is the copies again: nothing is left to resume.
            .and_then(|_| remove_marker(&marker));
        return Err(fail(match restored {
            Ok(()) => format!(
                "{msg}; both databases were restored from {}, so the previous release can start",
                pre.display()
            ),
            Err(e) => format!(
                "{msg}; restoring the copies from {} also failed: {e:#}",
                pre.display()
            ),
        }));
    }
    remove_marker(&marker).map_err(|e| fail(format!("{e:#}")))?;
    Ok(())
}

fn remove_marker(marker: &Path) -> Result<()> {
    match fs::remove_file(marker) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("remove {}", marker.display())),
    }
    if let Some(dir) = marker.parent() {
        crate::util::fsync_dir(dir)?;
    }
    Ok(())
}

fn copy_path(pre: &Path, opts: &DbOptions) -> PathBuf {
    pre.join(opts.path.file_name().unwrap_or_default())
}

fn file_size_with_wal(path: &Path) -> u64 {
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    [path.to_path_buf(), wal]
        .iter()
        .filter_map(|p| fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

/// `VACUUM INTO` a temporary name, then rename over the previous copy.
fn vacuum_into(opts: &DbOptions, dest: &Path) -> Result<()> {
    let tmp = PathBuf::from(format!("{}.tmp", dest.display()));
    let _ = fs::remove_file(&tmp);
    let conn = open_connection(opts, 2048)?;
    conn.execute("VACUUM INTO ?1", [tmp.to_string_lossy().as_ref()])?;
    drop(conn);
    fs::File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, dest)?;
    if let Some(dir) = dest.parent() {
        crate::util::fsync_dir(dir)?;
    }
    Ok(())
}

/// Puts a copy back: the live file's WAL and SHM go first, so no stale WAL is replayed onto the
/// restored file.
fn restore(opts: &DbOptions, copy: &Path) -> Result<()> {
    let live = &opts.path;
    for suffix in ["-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{suffix}", live.display()));
        match fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("remove {}", p.display())),
        }
    }
    let tmp = PathBuf::from(format!("{}.restore", live.display()));
    fs::copy(copy, &tmp).with_context(|| format!("copy {}", copy.display()))?;
    fs::File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, live)?;
    if let Some(dir) = live.parent() {
        crate::util::fsync_dir(dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(dir: &Path, name: &str) -> DbOptions {
        let mut o = DbOptions::core(dir);
        o.path = dir.join(name);
        o
    }

    const V1: &[&str] = &["CREATE TABLE a(x INTEGER);"];
    const V2: &[&str] = &["CREATE TABLE a(x INTEGER);", "ALTER TABLE a ADD COLUMN y TEXT;"];
    const V2_BAD: &[&str] = &["CREATE TABLE a(x INTEGER);", "THIS IS NOT SQL;"];

    fn m(steps: &'static [&'static str]) -> Migrations {
        Migrations { name: "t", steps }
    }

    fn plenty(_: &Path) -> Result<u64> {
        Ok(u64::MAX)
    }

    #[test]
    fn fresh_and_rerun() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (opts(d.path(), "a.db"), opts(d.path(), "b.db"));
        migrate_pair(d.path(), (&a, &m(V1)), (&b, &m(V1)), plenty).unwrap();
        // Re-running is a no-op and makes no copies.
        migrate_pair(d.path(), (&a, &m(V1)), (&b, &m(V1)), plenty).unwrap();
        let c = Connection::open(&a.path).unwrap();
        assert_eq!(user_version(&c).unwrap(), 1);
        // Upgrade to v2 makes copies at v1.
        migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2)), plenty).unwrap();
        let c = Connection::open(&a.path).unwrap();
        assert_eq!(user_version(&c).unwrap(), 2);
        let copy = Connection::open(d.path().join("pre-migration/a.db")).unwrap();
        assert_eq!(user_version(&copy).unwrap(), 1);
    }

    #[test]
    fn newer_database_refused() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (opts(d.path(), "a.db"), opts(d.path(), "b.db"));
        migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2)), plenty).unwrap();
        let e = migrate_pair(d.path(), (&a, &m(V1)), (&b, &m(V1)), plenty).unwrap_err();
        assert_eq!(e.code, 78);
        assert!(e.message.contains("newer"), "{}", e.message);
    }

    #[test]
    fn failed_migration_restores_both() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (opts(d.path(), "a.db"), opts(d.path(), "b.db"));
        migrate_pair(d.path(), (&a, &m(V1)), (&b, &m(V1)), plenty).unwrap();
        {
            let c = Connection::open(&a.path).unwrap();
            c.execute("INSERT INTO a VALUES (42)", []).unwrap();
        }
        // a migrates fine to v2, b fails: both must be back at v1 with a's row.
        let e = migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2_BAD)), plenty).unwrap_err();
        assert_eq!(e.code, 78);
        assert!(e.message.contains("restored"), "{}", e.message);
        let ca = Connection::open(&a.path).unwrap();
        assert_eq!(user_version(&ca).unwrap(), 1);
        let x: i64 = ca.query_row("SELECT x FROM a", [], |r| r.get(0)).unwrap();
        assert_eq!(x, 42);
        let has_y = ca.prepare("SELECT y FROM a").is_ok();
        assert!(!has_y, "a's v2 column must be gone after the restore");
        let cb = Connection::open(&b.path).unwrap();
        assert_eq!(user_version(&cb).unwrap(), 1);
    }

    #[test]
    fn an_interrupted_migration_keeps_the_original_pair() {
        // storage.md §5, README §2 Restarts: core dies after migrating the first file. The next
        // start must keep the copies from before the migration, so a later failure still puts
        // back the pair the previous release can start from.
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (opts(d.path(), "a.db"), opts(d.path(), "b.db"));
        migrate_pair(d.path(), (&a, &m(V1)), (&b, &m(V1)), plenty).unwrap();
        {
            let c = Connection::open(&a.path).unwrap();
            c.execute("INSERT INTO a VALUES (42)", []).unwrap();
        }
        migrate_pair_until(d.path(), (&a, &m(V2)), (&b, &m(V2)), plenty, true).unwrap();
        assert_eq!(user_version(&Connection::open(&a.path).unwrap()).unwrap(), 2);
        assert_eq!(user_version(&Connection::open(&b.path).unwrap()).unwrap(), 1);
        assert!(d.path().join("pre-migration").join(IN_PROGRESS).exists());
        // The next start fails on the second file: both go back to v1, a with its row.
        let e = migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2_BAD)), plenty).unwrap_err();
        assert_eq!(e.code, 78);
        assert!(e.message.contains("restored"), "{}", e.message);
        let ca = Connection::open(&a.path).unwrap();
        assert_eq!(user_version(&ca).unwrap(), 1, "the original core.db is back");
        assert!(ca.prepare("SELECT y FROM a").is_err());
        let x: i64 = ca.query_row("SELECT x FROM a", [], |r| r.get(0)).unwrap();
        assert_eq!(x, 42);
        assert_eq!(user_version(&Connection::open(&b.path).unwrap()).unwrap(), 1);
        assert!(!d.path().join("pre-migration").join(IN_PROGRESS).exists());
    }

    #[test]
    fn an_interrupted_migration_is_finished_at_the_next_start() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (opts(d.path(), "a.db"), opts(d.path(), "b.db"));
        migrate_pair(d.path(), (&a, &m(V1)), (&b, &m(V1)), plenty).unwrap();
        migrate_pair_until(d.path(), (&a, &m(V2)), (&b, &m(V2)), plenty, true).unwrap();
        migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2)), plenty).unwrap();
        assert_eq!(user_version(&Connection::open(&b.path).unwrap()).unwrap(), 2);
        assert!(!d.path().join("pre-migration").join(IN_PROGRESS).exists());
        // The copies are still the pair from before that migration.
        let copy = Connection::open(d.path().join("pre-migration/a.db")).unwrap();
        assert_eq!(user_version(&copy).unwrap(), 1);
        // Killed after the last migration but before the marker went: the next start clears it.
        crate::util::write_atomic(&d.path().join("pre-migration").join(IN_PROGRESS), b"x", 0o600).unwrap();
        migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2)), plenty).unwrap();
        assert!(!d.path().join("pre-migration").join(IN_PROGRESS).exists());
    }

    #[test]
    fn short_space_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (opts(d.path(), "a.db"), opts(d.path(), "b.db"));
        migrate_pair(d.path(), (&a, &m(V1)), (&b, &m(V1)), plenty).unwrap();
        let e = migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2)), |_| Ok(1024)).unwrap_err();
        assert_eq!(e.code, 78);
        assert!(e.message.contains("free space"));
        let c = Connection::open(&a.path).unwrap();
        assert_eq!(user_version(&c).unwrap(), 1);
        // The previous copy (made before the first migration, at version 0) is untouched.
        let copy = Connection::open(d.path().join("pre-migration/a.db")).unwrap();
        assert_eq!(user_version(&copy).unwrap(), 0);
    }

    const V3: &[&str] = &[
        "CREATE TABLE a(x INTEGER);",
        "ALTER TABLE a ADD COLUMN y TEXT;",
        "ALTER TABLE a ADD COLUMN z TEXT;",
    ];

    #[test]
    fn free_space_covers_copies_and_migration_growth() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (opts(d.path(), "a.db"), opts(d.path(), "b.db"));
        migrate_pair(d.path(), (&a, &m(V1)), (&b, &m(V1)), plenty).unwrap();
        {
            let c = Connection::open(&a.path).unwrap();
            c.execute("INSERT INTO a VALUES (?1)", [vec![7u8; 1 << 20]])
                .unwrap();
        }
        let size = file_size_with_wal(&a.path) + file_size_with_wal(&b.path);
        // Room for the copies alone isn't enough: a migration can grow the files by as much.
        let e = migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2)), |_| {
            Ok(size + MIGRATION_MARGIN + 4096)
        })
        .unwrap_err();
        assert!(e.message.contains("free space"), "{}", e.message);
        assert_eq!(user_version(&Connection::open(&a.path).unwrap()).unwrap(), 1);
        migrate_pair(d.path(), (&a, &m(V2)), (&b, &m(V2)), plenty).unwrap();
        // The previous copies are replaced, so their space counts as free.
        let size = file_size_with_wal(&a.path) + file_size_with_wal(&b.path);
        let copies: u64 = ["a.db", "b.db"]
            .iter()
            .map(|f| {
                fs::metadata(d.path().join("pre-migration").join(f))
                    .unwrap()
                    .len()
            })
            .sum();
        assert!(copies > 1 << 20);
        let free = 2 * size + MIGRATION_MARGIN - copies + 4096;
        migrate_pair(d.path(), (&a, &m(V3)), (&b, &m(V3)), move |_| Ok(free)).unwrap();
        let copy = Connection::open(d.path().join("pre-migration/a.db")).unwrap();
        assert_eq!(user_version(&copy).unwrap(), 2);
    }

    #[test]
    fn real_schemas_apply() {
        let d = tempfile::tempdir().unwrap();
        let core = DbOptions::core(d.path());
        let metrics = DbOptions::metrics(d.path());
        create_fresh(&core, &CORE).unwrap();
        create_fresh(&metrics, &METRICS).unwrap();
        let c = Connection::open(&core.path).unwrap();
        for t in crate::db::schema::CORE_TABLES {
            let n: i64 = c
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [t],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "table {t}");
        }
        let av: i64 = c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0)).unwrap();
        assert_eq!(av, 2);
        migrate_databases(d.path()).unwrap();
    }

    /// A `core.db` from before pauses were keyed by scope (version 4) keeps its stored pauses.
    #[test]
    fn stored_pauses_survive_the_scope_rename() {
        let d = tempfile::tempdir().unwrap();
        let core = DbOptions::core(d.path());
        create_fresh(&core, &m(&CORE.steps[..4])).unwrap();
        let mut c = Connection::open(&core.path).unwrap();
        c.execute(
            "INSERT INTO module_pauses (module, until) VALUES ('github', '2026-11-28T12:00:00Z')",
            [],
        )
        .unwrap();
        apply(&mut c, &CORE).unwrap();
        assert_eq!(user_version(&c).unwrap(), CORE.latest());
        let row: (String, String) = c
            .query_row("SELECT scope, until FROM rate_limit_pauses", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(row, ("github".into(), "2026-11-28T12:00:00Z".into()));
    }
}
