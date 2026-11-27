//! Manual feeds (feeds.md §1 "Manual feeds", api.md §7): no provider, no trigger, their file
//! stored on core. The save (`PUT feeds/{id}/file`, editor and upload alike), the append
//! (`POST feeds/{id}/file/lines`), the read, and the run a save starts ([`run`]).
//!
//! - **A save is the download.** The body is decoded as it arrives (gzip allowed) and the
//!   content streamed into `staging/`, BLAKE3-hashed; neither is held in RAM. Decoded content
//!   past the download size cap, or a body past twice that cap after decompression, is `413`,
//!   checked as it streams; nothing is stored.
//! - `base_version` must be the file's current `version` (null only while the feed has no
//!   file); any other is `409`. Saves to one feed run one at a time.
//! - A save identical to the feed's file makes no run. Otherwise the blob is stored and
//!   `manual_files` replaced in one transaction (whatever the run's outcome later), then the
//!   feed's run starts at once with `version` = the file's version and `updated_at` = the save
//!   time, continuing from step 3 of feeds.md §3; the run's result follows as a `feed_run` event
//!   (with `version` and `saved_at`). A write returns the file's `version` and `saved_at` (the
//!   string the run carries as `updated_at`), so the UI matches a save to its run.
//! - **Lost saves:** at start (and after a restore) core runs each manual feed whose file isn't
//!   its newest run's blob ([`run`]), so a save whose run was lost is still ingested.
//! - An append adds each line, with a `\n` first if the file doesn't end with one; the result,
//!   separators included, past the size cap is `413` before anything changes. Each item is one
//!   line with no line break in it, else `422`.
//! - **The request body is read first** (README §2 Bounded): streamed as it arrives, still
//!   compressed, into a spool file in `staging/`, with an idle deadline ([`BODY_IDLE`]) and a
//!   total one ([`BODY_TOTAL`]), under the body cap (`408` past a deadline, `413` past the cap),
//!   and only then is the feed's save lock taken. A client that stops sending holds no lock and
//!   no blocking thread. The blocking part (decompressing and parsing the spool, writing the
//!   new file) reads a local file, and stops when the request is dropped or core shuts down.
//! - **Bounded uploads** (README §2 Bounded): at most [`MAX_UPLOADS`] saves and appends run at
//!   once, and their spools together hold at most [`SPOOL_TOTAL_SPOOLS`] times one upload's
//!   spool cap; past either, `503` (nothing is stored; the client tries again later).

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::Serialize;

use super::body::{self, BodyError};
use super::ingest::{DownloadInput, Work};
use crate::config::Actor;
use crate::modules::download::StagedFile;
use crate::modules::download::ctx::stage_sync_in;
use crate::state::SharedState;

/// Why a write was refused.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    #[error("no feed {0:?}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    /// Refused with the problems found, each naming its field where one is at fault (`422`, as
    /// an entity save's validation).
    #[error("{}", .0.iter().map(|i| i.message.as_str()).collect::<Vec<_>>().join("; "))]
    Issues(Vec<crate::config::validate::Issue>),
    #[error("{0}")]
    Syntax(String),
    /// `base_version` isn't the file's current version.
    #[error("the file changed since it was read (version {current}); reload it and save again")]
    Conflict { current: String },
    #[error("the file would be larger than the download size cap ({0} bytes)")]
    TooLarge(u64),
    #[error("Content-Encoding {0:?} isn't supported (gzip or none)")]
    Encoding(String),
    /// The body didn't arrive in time.
    #[error("the request body didn't arrive in time ({0})")]
    Timeout(&'static str),
    /// Too many uploads at once, or their spools use the space they share: try again later.
    #[error("{0}; try again later")]
    Busy(&'static str),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// What a write returns: the file's version afterwards, and when it was saved.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SaveResult {
    pub version: String,
    /// When the file was saved, as `GET feeds/{id}/file` gives it: the run that reads this file
    /// carries it as `updated_at` (feeds.md §1), so a save is matched to its run. An unchanged
    /// write gives the current file's; null only when the feed still has no file.
    pub saved_at: Option<String>,
    /// False when the content equals the feed's file (no run).
    pub changed: bool,
}

/// A manual feed's file as `manual_files` records it.
#[derive(Clone, Debug)]
pub struct FileInfo {
    pub version: String,
    pub saved_at: Timestamp,
    pub size: u64,
    pub path: PathBuf,
    pub blake3: String,
}

/// The feed's current file, if it has one.
pub async fn file_info(state: &SharedState, feed: &str) -> anyhow::Result<Option<FileInfo>> {
    let f = feed.to_string();
    let row = state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(super::store::manual_file(c, &f)?))
        .await?;
    Ok(row.and_then(|(b, v, at)| {
        let path = crate::blobs::path(&state.data_dir, &b).ok()?;
        let size = std::fs::metadata(&path).map(|m| m.len()).ok()?;
        Some(FileInfo {
            version: v,
            saved_at: at,
            size,
            path,
            blake3: b,
        })
    }))
}

pub(crate) async fn check_manual(
    state: &SharedState,
    feed: &str,
) -> Result<crate::config::model::FeedDef, SaveError> {
    match state.feeds.def_or_reload(state, feed).await {
        None => Err(SaveError::NotFound(feed.to_string())),
        Some(d) if !d.is_manual() => Err(SaveError::Invalid(format!(
            "{feed:?} is a provider feed: its file comes from its provider"
        ))),
        Some(d) => Ok(d),
    }
}

/// The run of a manual feed's current file, when no run has read it yet (a save, a start, a
/// restore; feeds.md §1). The caller marked the feed busy; it is freed unless the run went to
/// the heavy lane.
pub async fn run(state: SharedState, feed: String) {
    match run_inner(&state, &feed).await {
        Ok(true) => {}
        Ok(false) => state.feeds.release(&state, &feed),
        Err(e) => {
            tracing::warn!(feed = %feed, error = %format!("{e:#}"), "a manual feed's run failed to start");
            state.feeds.release(&state, &feed);
            // A saved file is never left waiting for the next save or a restart.
            state
                .feeds
                .retry_manual(&feed, Timestamp::now() + jiff::SignedDuration::from_mins(1));
        }
    }
}

async fn run_inner(state: &SharedState, feed: &str) -> anyhow::Result<bool> {
    let Some(def) = state.feeds.def(feed) else {
        return Ok(false);
    };
    if !def.is_manual() || !def.enabled {
        return Ok(false);
    }
    let f = feed.to_string();
    let (file, newest, sgen) = state
        .db
        .read(move |c| {
            Ok::<_, anyhow::Error>((
                super::store::manual_file(c, &f)?,
                super::store::newest_with_blob(c, &f)?.and_then(|r| r.blob),
                super::store::source_gen(c, &f)?,
            ))
        })
        .await?;
    // A restored applied blob runs before the saved file (core.md §2), retried itself when the
    // heavy queue refused its run (README §2 Restarts).
    match crate::config::export::applied_next(state, feed).await? {
        crate::config::export::AppliedNext::None => {}
        crate::config::export::AppliedNext::Wait(at) => {
            state.feeds.retry_manual(feed, at);
            return Ok(false);
        }
        crate::config::export::AppliedNext::Run(blob, version, updated_at) => {
            // The saved file runs once this run ends.
            state.feeds.queue_save(feed);
            state.feeds.submit(
                state,
                feed,
                Work::Download(DownloadInput {
                    blob,
                    version,
                    updated_at: crate::util::parse_ts(&updated_at).unwrap_or_else(Timestamp::now),
                    downloaded_at: Timestamp::now(),
                    state: serde_json::json!({}),
                    source_gen: sgen,
                    trigger_cron: false,
                }),
            );
            return Ok(true);
        }
    }
    let Some((blob, version, saved_at)) = file else {
        return Ok(false);
    };
    if newest.as_deref() == Some(blob.as_str()) {
        // The newest run already read this file (a save identical to it makes no run).
        return Ok(false);
    }
    state.feeds.submit(
        state,
        feed,
        Work::Download(DownloadInput {
            blob,
            version,
            updated_at: saved_at,
            downloaded_at: Timestamp::now(),
            state: serde_json::json!({}),
            source_gen: sgen,
            trigger_cron: false,
        }),
    );
    Ok(true)
}

pub(crate) fn caps(state: &SharedState) -> (u64, u64) {
    let max = u64::from(state.settings().feeds.max_download_mib) * 1024 * 1024;
    (max, max.saturating_mul(2))
}

pub(crate) fn body_err(e: BodyError, max: u64) -> SaveError {
    match e {
        BodyError::TooLarge => SaveError::TooLarge(max),
        BodyError::Invalid(m) => SaveError::Invalid(m),
        BodyError::Syntax(m) => SaveError::Syntax(m),
        BodyError::Io(e) if e.kind() == std::io::ErrorKind::FileTooLarge => SaveError::TooLarge(max),
        BodyError::Io(e) => SaveError::Syntax(format!("cannot read the body: {e}")),
    }
}

/// Saves and appends that may run at once (each may spool up to twice the download cap).
pub const MAX_UPLOADS: usize = 4;
/// The spools of the uploads running at once hold at most this many times one upload's spool
/// cap together (2: two uploads of the largest size, or more smaller ones).
pub const SPOOL_TOTAL_SPOOLS: u64 = 2;

/// One upload's share of the spooled bytes all uploads share ([`SPOOL_TOTAL_SPOOLS`]): taken as
/// the body arrives, given back when the upload ends.
pub(crate) struct SpoolBudget {
    used: Arc<std::sync::atomic::AtomicU64>,
    limit: u64,
    mine: u64,
}

impl SpoolBudget {
    fn new(state: &SharedState, limit: u64) -> Self {
        Self {
            used: state.feeds.spooled(),
            limit,
            mine: 0,
        }
    }

    /// Takes `n` more bytes; false (nothing taken) when the total would pass the limit.
    fn take(&mut self, n: u64) -> bool {
        let limit = self.limit;
        let ok = self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |u| {
                u.checked_add(n).filter(|t| *t <= limit)
            })
            .is_ok();
        if ok {
            self.mine += n;
        }
        ok
    }
}

impl Drop for SpoolBudget {
    fn drop(&mut self) {
        self.used.fetch_sub(self.mine, Ordering::AcqRel);
    }
}

/// An upload's slot and its share of the spool space, held until the write ends.
pub(crate) struct Upload {
    _slot: tokio::sync::OwnedSemaphorePermit,
    pub(crate) budget: SpoolBudget,
}

/// Admits one upload ([`MAX_UPLOADS`]), or `503`.
pub(crate) fn admit(state: &SharedState, body_max: u64) -> Result<Upload, SaveError> {
    let slot = state
        .feeds
        .upload_slot()
        .ok_or(SaveError::Busy("too many manual feed uploads are in progress"))?;
    Ok(Upload {
        _slot: slot,
        budget: SpoolBudget::new(state, spool_cap(body_max).saturating_mul(SPOOL_TOTAL_SPOOLS)),
    })
}

/// One upload's spool cap: the body cap plus room for gzip's framing (the decoded body is capped
/// again as it is parsed).
fn spool_cap(body_max: u64) -> u64 {
    body_max.saturating_add(body_max / 64).saturating_add(64 * 1024)
}

/// The longest wait for the next part of a request body.
pub const BODY_IDLE: std::time::Duration = std::time::Duration::from_secs(30);
/// The longest a whole request body may take (twice the 256 MiB cap needs ≈ 0.9 MB/s).
pub const BODY_TOTAL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

pub(crate) fn gzip_of(encoding: Option<&str>) -> Result<bool, SaveError> {
    match encoding.map(|e| e.trim().to_ascii_lowercase()) {
        None => Ok(false),
        Some(e) if e.is_empty() || e == "identity" => Ok(false),
        Some(e) if e == "gzip" || e == "x-gzip" => Ok(true),
        Some(e) => Err(SaveError::Encoding(e)),
    }
}

/// Reads the request body, as sent (compressed or not), into a spool file in `staging/`, with
/// the idle and total deadlines, the spool cap ([`spool_cap`]) and the upload's share of the
/// spool space. Cancelled by shutdown.
pub(crate) async fn spool_body(
    state: &SharedState,
    feed: &str,
    body: axum::body::Body,
    body_max: u64,
    max: u64,
    budget: &mut SpoolBudget,
) -> Result<StagedFile, SaveError> {
    use futures_util::StreamExt;
    let cap = spool_cap(body_max);
    let staging = state.data_dir.join("staging");
    let mut w = crate::modules::download::ctx::Ctx::stage_in(&staging, feed, cap)
        .await
        .map_err(|e| SaveError::Other(anyhow::Error::new(e)))?;
    let mut stream = body.into_data_stream();
    let deadline = tokio::time::Instant::now() + BODY_TOTAL;
    loop {
        let wait = (tokio::time::Instant::now() + BODY_IDLE).min(deadline);
        let next = tokio::select! {
            _ = state.shutdown.cancelled() => return Err(SaveError::Other(anyhow::anyhow!("shutting down"))),
            n = tokio::time::timeout_at(wait, stream.next()) => n,
        };
        match next {
            Err(_) if tokio::time::Instant::now() >= deadline => return Err(SaveError::Timeout("total")),
            Err(_) => return Err(SaveError::Timeout("idle")),
            Ok(None) => break,
            Ok(Some(Err(e))) => return Err(SaveError::Syntax(format!("cannot read the body: {e}"))),
            Ok(Some(Ok(chunk))) => {
                if !budget.take(chunk.len() as u64) {
                    return Err(SaveError::Busy(
                        "the manual feed uploads in progress use the spool space",
                    ));
                }
                w.write(&chunk).await.map_err(|e| match e {
                    crate::modules::download::client::HttpError::TooLarge(_) => SaveError::TooLarge(max),
                    e => SaveError::Other(anyhow::Error::new(e)),
                })?
            }
        }
    }
    w.finish()
        .await
        .map_err(|e| SaveError::Other(anyhow::Error::new(e)))
}

/// Set when the request that started a blocking part is dropped (the client went away).
pub(crate) struct CancelOnDrop(pub(crate) Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// A reader that stops when its request is dropped or core shuts down.
struct Cancellable<R> {
    inner: R,
    dropped: Arc<AtomicBool>,
    shutdown: tokio_util::sync::CancellationToken,
}

impl<R: Read> Read for Cancellable<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.dropped.load(Ordering::Relaxed) || self.shutdown.is_cancelled() {
            return Err(std::io::Error::other("the request was cancelled"));
        }
        self.inner.read(buf)
    }
}

/// The spooled body as the parser reads it: decompressed when gzip, capped, cancellable.
pub(crate) fn spool_reader(
    path: &std::path::Path,
    gzip: bool,
    cap: u64,
    dropped: Arc<AtomicBool>,
    shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<Box<dyn Read + Send>> {
    let file = Cancellable {
        inner: std::fs::File::open(path)?,
        dropped,
        shutdown,
    };
    let inner: Box<dyn Read + Send> = if gzip {
        Box::new(flate2::read::MultiGzDecoder::new(std::io::BufReader::new(file)))
    } else {
        Box::new(file)
    };
    Ok(Box::new(body::Capped::new(inner, cap)))
}

/// `PUT feeds/{id}/file`.
pub async fn save(
    state: &SharedState,
    feed: &str,
    body: axum::body::Body,
    encoding: Option<&str>,
    actor: Actor,
) -> Result<SaveResult, SaveError> {
    check_manual(state, feed).await?;
    let (max, body_max) = caps(state);
    let gzip = gzip_of(encoding)?;
    let mut upload = admit(state, body_max)?;
    // The whole body first, outside the feed's lock (README §2 Bounded).
    let spool = spool_body(state, feed, body, body_max, max, &mut upload.budget).await?;
    let lock = state.feeds.save_lock(feed);
    let _g = lock.lock().await;
    let staging = state.data_dir.join("staging");
    let f = feed.to_string();
    let dropped = Arc::new(AtomicBool::new(false));
    let _cancel = CancelOnDrop(dropped.clone());
    let shutdown = state.shutdown.clone();
    let (parsed, file) = tokio::task::spawn_blocking(move || -> Result<_, SaveError> {
        let reader =
            spool_reader(spool.path(), gzip, body_max, dropped, shutdown).map_err(anyhow::Error::from)?;
        let mut w = stage_sync_in(&staging, &f, max).map_err(anyhow::Error::from)?;
        let parsed = body::parse_save(reader, &mut |b| w.write(b).map_err(BodyError::from))
            .map_err(|e| body_err(e, max))?;
        let file = w.finish().map_err(anyhow::Error::from)?;
        Ok((parsed, file))
    })
    .await
    .map_err(|e| anyhow::anyhow!("the save failed: {e}"))??;
    let current = file_info(state, feed).await?;
    match (&current, &parsed.base_version) {
        (None, None) => {}
        (Some(c), Some(b)) if &c.version == b => {}
        (Some(c), _) => {
            return Err(SaveError::Conflict {
                current: c.version.clone(),
            });
        }
        (None, Some(_)) => {
            return Err(SaveError::Conflict {
                current: String::new(),
            });
        }
    }
    store_and_check(state, feed, file, current, actor).await
}

/// `POST feeds/{id}/file/lines`.
pub async fn append(
    state: &SharedState,
    feed: &str,
    body: axum::body::Body,
    encoding: Option<&str>,
    actor: Actor,
) -> Result<SaveResult, SaveError> {
    let def = check_manual(state, feed).await?;
    if def.format == crate::config::model::FeedFormat::MispWarninglist {
        // api.md §7: appends take line formats only.
        return Err(SaveError::Invalid(
            "a misp-warninglist feed's file is JSON: lines can't be appended; save the file or import instead".into(),
        ));
    }
    let (max, body_max) = caps(state);
    let gzip = gzip_of(encoding)?;
    let mut upload = admit(state, body_max)?;
    // The whole body first, outside the feed's lock (README §2 Bounded).
    let spool = spool_body(state, feed, body, body_max, max, &mut upload.budget).await?;
    let lock = state.feeds.save_lock(feed);
    let _g = lock.lock().await;
    let current = file_info(state, feed).await?;
    let staging = state.data_dir.join("staging");
    let f = feed.to_string();
    let cur = current.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let _cancel = CancelOnDrop(dropped.clone());
    let shutdown = state.shutdown.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<Option<StagedFile>, SaveError> {
        // The lines first (validated whole before anything changes), then the new file.
        let reader =
            spool_reader(spool.path(), gzip, body_max, dropped, shutdown).map_err(anyhow::Error::from)?;
        let mut lines = stage_sync_in(&staging, &f, max).map_err(anyhow::Error::from)?;
        let n = body::parse_lines(reader, max.min(64 * 1024 * 1024) as usize, &mut |l| {
            lines.write(l).map_err(BodyError::from)?;
            lines.write(b"\n").map_err(BodyError::from)
        })
        .map_err(|e| body_err(e, max))?;
        if n == 0 {
            return Ok(None);
        }
        let lines = lines.finish().map_err(anyhow::Error::from)?;
        let mut out = stage_sync_in(&staging, &f, max).map_err(anyhow::Error::from)?;
        let copy = |path: &std::path::Path,
                    out: &mut crate::modules::download::ctx::SyncStageWriter|
         -> Result<Option<u8>, SaveError> {
            let mut r = std::fs::File::open(path).map_err(anyhow::Error::from)?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut last = None;
            loop {
                let k = r.read(&mut buf).map_err(anyhow::Error::from)?;
                if k == 0 {
                    break;
                }
                last = buf.get(k - 1).copied();
                out.write(&buf[..k])
                    .map_err(|e| body_err(BodyError::from(e), max))?;
            }
            Ok(last)
        };
        if let Some(c) = &cur {
            let last = copy(&c.path, &mut out)?;
            if last.is_some_and(|b| b != b'\n') {
                out.write(b"\n").map_err(|e| body_err(BodyError::from(e), max))?;
            }
        }
        copy(lines.path(), &mut out)?;
        Ok(Some(out.finish().map_err(anyhow::Error::from)?))
    })
    .await
    .map_err(|e| anyhow::anyhow!("the append failed: {e}"))??;
    match out {
        None => Ok(SaveResult {
            saved_at: current.as_ref().map(|c| crate::util::ts(&c.saved_at)),
            version: current.map(|c| c.version).unwrap_or_default(),
            changed: false,
        }),
        Some(file) => store_and_check(state, feed, file, current, actor).await,
    }
}

/// The `saved_at` for a new file of `feed`: now, but always after the stored one, so a feed's
/// save times strictly increase even when the wall clock steps back (the UI matches a save to
/// its run by this time, core.md §12; a run carries it as `updated_at`).
pub(crate) fn next_saved_at(tx: &rusqlite::Transaction<'_>, feed: &str) -> rusqlite::Result<String> {
    use rusqlite::OptionalExtension;
    let prev: Option<String> = tx
        .query_row(
            "SELECT saved_at FROM manual_files WHERE feed_id = ?1",
            [feed],
            |r| r.get(0),
        )
        .optional()?;
    Ok(crate::util::ts(&after(
        prev.as_deref().and_then(crate::util::parse_ts),
        Timestamp::now(),
    )))
}

/// `now`, or one microsecond after `prev` when the clock hasn't passed it.
fn after(prev: Option<Timestamp>, now: Timestamp) -> Timestamp {
    match prev {
        Some(p) if now <= p => picket_api::time::saturating_add(p, jiff::SignedDuration::from_micros(1)),
        _ => now,
    }
}

/// Stores a new file (unless identical), replaces `manual_files`, and starts its run.
pub(crate) async fn store_and_check(
    state: &SharedState,
    feed: &str,
    mut file: StagedFile,
    current: Option<FileInfo>,
    actor: Actor,
) -> Result<SaveResult, SaveError> {
    if let Some(c) = &current
        && c.blake3 == file.blake3()
    {
        // The same text: Unchanged, no run (providers.md §3).
        return Ok(SaveResult {
            version: c.version.clone(),
            saved_at: Some(crate::util::ts(&c.saved_at)),
            changed: false,
        });
    }
    let b3 = file.blake3().to_string();
    let blob = b3.clone();
    let size = file.size();
    let version = picket_api::ids::short_id(&b3).to_string();
    let data_dir = state.data_dir.clone();
    let (f, v) = (feed.to_string(), version.clone());
    // Stored and returned as one string, so the run's `updated_at` equals it.
    let saved_at = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if let Some(tmp) = file.take_temp_path() {
                let dst = crate::blobs::path(&data_dir, &b3)?;
                let dir = dst.parent().ok_or_else(|| anyhow::anyhow!("blob dir"))?.to_path_buf();
                crate::util::ensure_dir(&dir)?;
                if dst.exists() {
                    let _ = std::fs::remove_file(&tmp);
                } else {
                    std::fs::rename(&tmp, &dst)?;
                    crate::util::fsync_dir(&dir)?;
                }
            }
            crate::blobs::register(&tx, &b3, crate::blobs::kind::MANUAL_FILE, size)?;
            let at = next_saved_at(&tx, &f)?;
            tx.execute(
                "INSERT INTO manual_files(feed_id, blob, version, saved_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(feed_id) DO UPDATE SET blob = excluded.blob, version = excluded.version, saved_at = excluded.saved_at",
                rusqlite::params![f, b3, v, at],
            )?;
            crate::config::journal::record(
                &tx,
                actor.ip.as_deref(),
                &actor.source,
                crate::config::EntityKind::Feed,
                &f,
                &serde_json::json!({"op": "update", "file": "saved", "version": v, "size": size}),
            )?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(at)
        })
        .await?;
    let _ = blob;
    state.feeds.trigger_manual(state, feed);
    Ok(SaveResult {
        version,
        saved_at: Some(saved_at),
        changed: true,
    })
}

#[cfg(test)]
mod saved_at_tests {

    #[test]
    fn save_times_strictly_increase_when_the_clock_steps_back() {
        let t = "2026-11-24T12:00:00Z".parse::<jiff::Timestamp>().unwrap();
        // The clock moved on: now.
        assert_eq!(
            super::after(Some(t), t + jiff::SignedDuration::from_secs(1)),
            t + jiff::SignedDuration::from_secs(1)
        );
        // The same instant, or a clock stepped back: just after the stored time.
        assert_eq!(super::after(Some(t), t), t + jiff::SignedDuration::from_micros(1));
        assert_eq!(
            super::after(Some(t), t - jiff::SignedDuration::from_hours(1)),
            t + jiff::SignedDuration::from_micros(1)
        );
        assert_eq!(super::after(None, t), t);
    }
}
