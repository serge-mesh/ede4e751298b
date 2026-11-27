//! SQLite access (storage.md, core.md §3).
//!
//! Each database file has **one writer connection owned by a writer thread** (closures are sent
//! over a bounded channel and their results come back on a oneshot) plus a **small read pool**.
//! WAL lets readers run while the writer commits. Large writes go in chunks
//! ([`Db::write_chunked`]) so other writers interleave (≈ 50k rows per chunk, core.md §3).
//!
//! ```ignore
//! let n: i64 = db.read(|c| Ok(c.query_row("SELECT count(*) FROM edges", [], |r| r.get(0))?)).await?;
//! db.write(|c| { c.execute("DELETE FROM edge_pending", [])?; Ok(()) }).await?;
//! ```

pub mod migrate;
pub mod schema;

use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rusqlite::Connection;
use tokio::sync::{Semaphore, mpsc, oneshot};

/// Rows per chunk for large writes (core.md §3).
pub const CHUNK_ROWS: usize = 50_000;
/// Writer queue bound; senders wait when it is full.
const WRITE_QUEUE: usize = 1024;

/// `PRAGMA synchronous` level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Synchronous {
    Full,
    Normal,
}

/// How a database file is opened.
#[derive(Clone, Debug)]
pub struct DbOptions {
    pub path: PathBuf,
    pub synchronous: Synchronous,
    /// Writer page cache in KiB (`cache_size = -N`).
    pub writer_cache_kib: i64,
    /// Each reader's page cache in KiB.
    pub reader_cache_kib: i64,
    pub readers: usize,
    pub busy_timeout: Duration,
}

impl DbOptions {
    /// `core.db`: WAL, `synchronous=FULL`, cache ≈ 32 MB, busy timeout 5 s (storage.md §2).
    pub fn core(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("core.db"),
            synchronous: Synchronous::Full,
            writer_cache_kib: 32 * 1024,
            reader_cache_kib: 8 * 1024,
            readers: 4,
            busy_timeout: Duration::from_secs(5),
        }
    }

    /// `metrics.db`: WAL, `synchronous=NORMAL` (storage.md §2).
    pub fn metrics(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("metrics.db"),
            synchronous: Synchronous::Normal,
            writer_cache_kib: 8 * 1024,
            reader_cache_kib: 4 * 1024,
            readers: 2,
            busy_timeout: Duration::from_secs(5),
        }
    }
}

/// Opens a connection with core's pragmas. A new file gets `auto_vacuum = INCREMENTAL` before
/// anything else (it only takes effect on an empty database; core.md §3 never runs a full
/// `VACUUM`), then WAL.
pub fn open_connection(opts: &DbOptions, cache_kib: i64) -> Result<Connection> {
    let conn = Connection::open(&opts.path).with_context(|| format!("open {}", opts.path.display()))?;
    conn.busy_timeout(opts.busy_timeout)?;
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    if pages == 0 {
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
    }
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(anyhow!("{} refused WAL mode ({mode})", opts.path.display()));
    }
    let sync = match opts.synchronous {
        Synchronous::Full => "FULL",
        Synchronous::Normal => "NORMAL",
    };
    conn.execute_batch(&format!(
        "PRAGMA synchronous = {sync}; PRAGMA cache_size = -{cache_kib}; PRAGMA foreign_keys = OFF;"
    ))?;
    Ok(conn)
}

type WriteJob = Box<dyn FnOnce(&mut Connection) + Send>;

struct Inner {
    path: PathBuf,
    opts: DbOptions,
    writer: mpsc::Sender<WriteJob>,
    readers: Mutex<Vec<Connection>>,
    reader_permits: Semaphore,
}

/// A database handle: cheap to clone, shared by every module.
#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}

impl Db {
    /// Opens the writer (on its own thread) and the read pool. The schema must already be
    /// migrated ([`migrate`]).
    pub fn open(opts: DbOptions) -> Result<Self> {
        let mut writer_conn = open_connection(&opts, opts.writer_cache_kib)?;
        let mut readers = Vec::with_capacity(opts.readers);
        for _ in 0..opts.readers.max(1) {
            readers.push(open_reader(&opts)?);
        }
        let (tx, mut rx) = mpsc::channel::<WriteJob>(WRITE_QUEUE);
        let name = format!(
            "db-writer-{}",
            opts.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        );
        std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                while let Some(job) = rx.blocking_recv() {
                    // A panicking closure costs its caller an error (its oneshot is dropped),
                    // never the writer: an open transaction rolls back when it is dropped.
                    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| job(&mut writer_conn)));
                }
            })
            .context("spawn db writer")?;
        let n = readers.len();
        Ok(Self {
            inner: Arc::new(Inner {
                path: opts.path.clone(),
                opts,
                writer: tx,
                readers: Mutex::new(readers),
                reader_permits: Semaphore::new(n),
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Writes queued for the writer and not yet started (tests use it to order their steps).
    pub fn pending_writes(&self) -> usize {
        self.inner.writer.max_capacity() - self.inner.writer.capacity()
    }

    /// Runs `f` on the writer connection and returns its result. Use a transaction inside `f`
    /// for multi-statement changes (`c.transaction()`).
    pub async fn write<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut Connection) -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: From<anyhow::Error> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let job: WriteJob = Box::new(move |c| {
            let _ = tx.send(f(c));
        });
        self.inner
            .writer
            .send(job)
            .await
            .map_err(|_| E::from(anyhow!("database writer stopped")))?;
        rx.await
            .map_err(|_| E::from(anyhow!("database write failed (panic)")))?
    }

    /// Runs `f` on a pooled read connection, on a blocking thread.
    pub async fn read<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&Connection) -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: From<anyhow::Error> + Send + 'static,
    {
        let _permit = self
            .inner
            .reader_permits
            .acquire()
            .await
            .map_err(|_| E::from(anyhow!("read pool closed")))?;
        let conn = self
            .inner
            .readers
            .lock()
            .map_err(|_| E::from(anyhow!("read pool poisoned")))?
            .pop();
        let conn = match conn {
            Some(c) => c,
            None => open_reader(&self.inner.opts).map_err(E::from)?,
        };
        let inner = self.inner.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let r = f(&conn);
            (conn, r)
        })
        .await;
        match joined {
            Ok((conn, r)) => {
                if let Ok(mut pool) = inner.readers.lock() {
                    pool.push(conn);
                }
                r
            }
            Err(e) => {
                // The connection went with the panicking task; replace it.
                if let Ok(c) = open_reader(&inner.opts)
                    && let Ok(mut pool) = inner.readers.lock()
                {
                    pool.push(c);
                }
                Err(E::from(anyhow!("database read failed: {e}")))
            }
        }
    }

    /// True when the writer answers within `timeout` (`/healthz`, core.md §12).
    pub async fn ping(&self, timeout: Duration) -> bool {
        let fut = self.write::<_, anyhow::Error, _>(|c| {
            c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?;
            Ok(())
        });
        matches!(tokio::time::timeout(timeout, fut).await, Ok(Ok(())))
    }

    /// Writes `items` in chunks of `chunk` rows, one transaction per chunk, so other writers
    /// run between chunks. `f` gets each chunk inside its transaction.
    pub async fn write_chunked<I, F>(&self, items: Vec<I>, chunk: usize, f: F) -> Result<()>
    where
        I: Send + 'static,
        F: Fn(&rusqlite::Transaction<'_>, &[I]) -> Result<()> + Send + Sync + 'static,
    {
        let f = Arc::new(f);
        let chunk = chunk.max(1);
        let mut items = items;
        while !items.is_empty() {
            let rest = if items.len() > chunk {
                items.split_off(chunk)
            } else {
                Vec::new()
            };
            let batch = std::mem::replace(&mut items, rest);
            let f = f.clone();
            self.write(move |c| {
                let tx = c.transaction()?;
                f(&tx, &batch)?;
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
            tokio::task::yield_now().await;
        }
        Ok(())
    }
}

fn open_reader(opts: &DbOptions) -> Result<Connection> {
    let c = open_connection(opts, opts.reader_cache_kib)?;
    c.execute_batch("PRAGMA query_only = 1;")?;
    Ok(c)
}

/// Converts any displayable error to anyhow (for `?` inside closures with `rusqlite` calls).
pub fn sql<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, Db) {
        let d = tempfile::tempdir().unwrap();
        let mut opts = DbOptions::core(d.path());
        opts.path = d.path().join("t.db");
        let db = Db::open(opts).unwrap();
        (d, db)
    }

    #[tokio::test]
    async fn write_then_read() {
        let (_d, db) = db();
        db.write(|c| {
            c.execute_batch("CREATE TABLE t(x INTEGER)")?;
            c.execute("INSERT INTO t VALUES (1)", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
        let n: i64 = db
            .read(|c| Ok::<_, anyhow::Error>(c.query_row("SELECT count(*) FROM t", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(n, 1);
        assert!(db.ping(Duration::from_secs(2)).await);
        // Readers can't write.
        let r: Result<(), anyhow::Error> = db
            .read(|c| {
                c.execute("INSERT INTO t VALUES (2)", [])?;
                Ok(())
            })
            .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn pragmas() {
        let (_d, db) = db();
        let (av, sync, mode): (i64, i64, String) = db
            .write(|c| {
                Ok::<_, anyhow::Error>((
                    c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?,
                    c.query_row("PRAGMA synchronous", [], |r| r.get(0))?,
                    c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(av, 2, "auto_vacuum = INCREMENTAL");
        assert_eq!(sync, 2, "synchronous = FULL");
        assert_eq!(mode, "wal");
    }

    #[tokio::test]
    async fn panicking_writer_closure_does_not_kill_writer() {
        let (_d, db) = db();
        let r: Result<(), anyhow::Error> = db.write(|_| panic!("boom")).await;
        assert!(r.is_err());
        assert!(db.ping(Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn chunked() {
        let (_d, db) = db();
        db.write(|c| {
            c.execute_batch("CREATE TABLE t(x INTEGER)")?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
        db.write_chunked((0..1000).collect::<Vec<i64>>(), 128, |tx, rows| {
            let mut st = tx.prepare_cached("INSERT INTO t VALUES (?1)")?;
            for r in rows {
                st.execute([r])?;
            }
            Ok(())
        })
        .await
        .unwrap();
        let n: i64 = db
            .read(|c| Ok::<_, anyhow::Error>(c.query_row("SELECT count(*) FROM t", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(n, 1000);
    }
}
