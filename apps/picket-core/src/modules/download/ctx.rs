//! What a download module gets for one check of a feed provider (providers.md §2 `Ctx`): the
//! HTTP client, the staging directory with [`Ctx::stage_file`] (streamed, BLAKE3-hashed, bounded
//! by the decoded size cap), cancellation, the check's time, and [`Ctx::listing_incomplete`],
//! through which a module reports a listing walk it couldn't finish.
//!
//! A [`StagedFile`] is either a temporary file in `staging/` (deleted when dropped unless core
//! adopts it into the blob store) or a blob already in the store (a manual feed's saved file).

use std::path::{Path, PathBuf};

use jiff::Timestamp;
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::client::{Http, HttpError, Resp};

/// A blob in the store, with what `manual_files` records for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobFile {
    pub blake3: String,
    pub size: u64,
    pub path: PathBuf,
    /// `manual_files.version`.
    pub version: String,
    pub saved_at: Timestamp,
}

/// One check's context.
pub struct Ctx {
    pub http: Http,
    /// The feed provider being checked (logs, staged file names).
    pub provider_id: String,
    /// The check's time.
    pub now: Timestamp,
    /// The provider's previous successful check, if any (interval change times).
    pub last_ok: Option<Timestamp>,
    /// The download size cap in bytes, counted decoded (`feeds.max_download_mib`).
    pub max_download: u64,
    pub cancel: CancellationToken,
    staging: PathBuf,
    /// The check's light-lane slots, given back while it waits on another check.
    slot: Option<crate::scheduler::LightSlot>,
    /// Set by a module whose listing walk couldn't finish (providers.md §3).
    incomplete: std::sync::Mutex<Option<String>>,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("provider_id", &self.provider_id)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl Ctx {
    pub fn new(
        http: Http,
        provider_id: &str,
        staging: &Path,
        max_download: u64,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            http,
            provider_id: provider_id.to_string(),
            now: Timestamp::now(),
            last_ok: None,
            max_download,
            cancel,
            staging: staging.to_path_buf(),
            slot: None,
            incomplete: std::sync::Mutex::new(None),
        }
    }

    /// A module's listing walk couldn't finish (`why` says how far it got): the check gives no
    /// listing, and a provider whose `files` holds globs raises
    /// `feed_provider_listing_incomplete` until a listing succeeds again (providers.md §3).
    pub fn listing_incomplete(&self, why: impl Into<String>) {
        if let Ok(mut g) = self.incomplete.lock() {
            *g = Some(why.into());
        }
    }

    /// What [`Ctx::listing_incomplete`] reported in this check, if anything.
    pub fn take_listing_incomplete(&self) -> Option<String> {
        self.incomplete.lock().ok().and_then(|mut g| g.take())
    }

    /// The light-lane slots the check runs in (core.md §3).
    pub fn with_slot(mut self, slot: crate::scheduler::LightSlot) -> Self {
        self.slot = Some(slot);
        self
    }

    /// Waits for `fut` (another check's request in flight, such as `github`'s shared `ls-refs`)
    /// without holding the check's light-lane slots, then takes them again.
    pub async fn waiting<T>(&self, fut: impl std::future::Future<Output = T>) -> T {
        match &self.slot {
            Some(s) => s.released(fut).await,
            None => fut.await,
        }
    }

    pub fn with_now(mut self, now: Timestamp, last_ok: Option<Timestamp>) -> Self {
        self.now = now;
        self.last_ok = last_ok;
        self
    }

    /// A new staged file in `staging/`, written as the body streams (providers.md §2).
    pub async fn stage_file(&self) -> Result<StageWriter, HttpError> {
        StageWriter::create(&self.staging, &self.provider_id, self.max_download).await
    }

    /// Streams a response body into a new staged file; `text/html` and a body past the cap are
    /// failed checks (providers.md §2).
    pub async fn stage(&self, resp: Resp) -> Result<StagedFile, HttpError> {
        if resp.is_html() {
            return Err(HttpError::Refused(
                "the server answered with text/html (a captive portal or an error page)".into(),
            ));
        }
        let mut w = self.stage_file().await?;
        resp.stream_into(&mut w, &self.cancel).await?;
        w.finish().await
    }

    /// A new staged file in `dir`, outside a check (a manual feed's request body spooled before
    /// the save takes the feed's lock).
    pub async fn stage_in(dir: &Path, feed: &str, max: u64) -> Result<StageWriter, HttpError> {
        StageWriter::create(dir, feed, max).await
    }

    /// A new staged file written from blocking code (a module converting a download inside
    /// `spawn_blocking`), with the same hashing and cap as [`Ctx::stage_file`].
    pub fn stage_sync(&self) -> std::io::Result<SyncStageWriter> {
        SyncStageWriter::create(&self.staging, &self.provider_id, self.max_download)
    }
}

/// A file being streamed into `staging/`: BLAKE3 and SHA-256 as it goes, and the size cap.
pub struct StageWriter {
    path: PathBuf,
    file: Option<tokio::fs::File>,
    blake3: blake3::Hasher,
    sha256: sha2::Sha256,
    size: u64,
    max: u64,
}

impl StageWriter {
    async fn create(dir: &Path, feed: &str, max: u64) -> Result<Self, HttpError> {
        let path = dir.join(format!(
            "feed-{}-{}.part",
            safe_name(feed),
            crate::util::random_hex(8)
        ));
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|e| HttpError::Transport(format!("cannot create a staged file: {e}")))?;
        Ok(Self {
            path,
            file: Some(file),
            blake3: blake3::Hasher::new(),
            sha256: sha2::Sha256::new(),
            size: 0,
            max,
        })
    }

    /// Appends bytes; past the cap the write fails and the file is removed when dropped.
    pub async fn write(&mut self, chunk: &[u8]) -> Result<(), HttpError> {
        self.size = self.size.saturating_add(chunk.len() as u64);
        if self.size > self.max {
            return Err(HttpError::TooLarge(self.max));
        }
        self.blake3.update(chunk);
        self.sha256.update(chunk);
        let f = self
            .file
            .as_mut()
            .ok_or_else(|| HttpError::Transport("the staged file is closed".into()))?;
        f.write_all(chunk)
            .await
            .map_err(|e| HttpError::Transport(format!("cannot write the staged file: {e}")))
    }

    /// Bytes written so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Flushes and syncs the file and returns it (durable before core adopts it as a blob).
    pub async fn finish(mut self) -> Result<StagedFile, HttpError> {
        let mut f = self
            .file
            .take()
            .ok_or_else(|| HttpError::Transport("the staged file is closed".into()))?;
        f.flush()
            .await
            .map_err(|e| HttpError::Transport(format!("cannot write the staged file: {e}")))?;
        f.sync_all()
            .await
            .map_err(|e| HttpError::Transport(format!("cannot sync the staged file: {e}")))?;
        drop(f);
        let path = std::mem::take(&mut self.path);
        Ok(StagedFile {
            inner: Inner::Temp(TempFile { path }),
            blake3: self.blake3.finalize().to_hex().to_string(),
            sha256: hex::encode(std::mem::take(&mut self.sha256).finalize()),
            size: self.size,
        })
    }
}

impl Drop for StageWriter {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// [`StageWriter`] for blocking code.
pub struct SyncStageWriter {
    path: PathBuf,
    file: Option<std::io::BufWriter<std::fs::File>>,
    blake3: blake3::Hasher,
    sha256: sha2::Sha256,
    size: u64,
    max: u64,
}

impl SyncStageWriter {
    fn create(dir: &Path, feed: &str, max: u64) -> std::io::Result<Self> {
        let path = dir.join(format!(
            "feed-{}-{}.part",
            safe_name(feed),
            crate::util::random_hex(8)
        ));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: Some(std::io::BufWriter::new(file)),
            blake3: blake3::Hasher::new(),
            sha256: sha2::Sha256::new(),
            size: 0,
            max,
        })
    }

    /// Appends bytes; past the cap the write fails.
    pub fn write(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.size = self.size.saturating_add(chunk.len() as u64);
        if self.size > self.max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!("the file is larger than {} bytes", self.max),
            ));
        }
        self.blake3.update(chunk);
        self.sha256.update(chunk);
        match self.file.as_mut() {
            Some(f) => f.write_all(chunk),
            None => Err(std::io::Error::other("the staged file is closed")),
        }
    }

    /// Flushes, syncs and returns the file.
    pub fn finish(mut self) -> std::io::Result<StagedFile> {
        let f = self
            .file
            .take()
            .ok_or_else(|| std::io::Error::other("the staged file is closed"))?;
        let f = f.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        drop(f);
        let path = std::mem::take(&mut self.path);
        Ok(StagedFile {
            inner: Inner::Temp(TempFile { path }),
            blake3: self.blake3.finalize().to_hex().to_string(),
            sha256: hex::encode(std::mem::take(&mut self.sha256).finalize()),
            size: self.size,
        })
    }
}

impl Drop for SyncStageWriter {
    fn drop(&mut self) {
        self.file = None;
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// A staged file in `dir` written from blocking code, outside a check (manual saves, imports).
pub fn stage_sync_in(dir: &Path, feed: &str, max: u64) -> std::io::Result<SyncStageWriter> {
    SyncStageWriter::create(dir, feed, max)
}

/// A feed id as a file-name part: `[A-Za-z0-9_-]`, at most 64 characters.
fn safe_name(feed: &str) -> String {
    feed.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect()
}

/// A temporary file removed when dropped, unless taken.
#[derive(Debug)]
struct TempFile {
    path: PathBuf,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug)]
enum Inner {
    Temp(TempFile),
    Blob(PathBuf),
}

/// A downloaded (or saved) file: its hashes, its size and where it is.
#[derive(Debug)]
pub struct StagedFile {
    inner: Inner,
    blake3: String,
    sha256: String,
    size: u64,
}

impl Clone for StagedFile {
    /// Only a blob is cloned as itself; a temporary file can't have two owners, so its clone
    /// names the same path without owning it.
    fn clone(&self) -> Self {
        let inner = match &self.inner {
            Inner::Temp(t) => Inner::Blob(t.path.clone()),
            Inner::Blob(p) => Inner::Blob(p.clone()),
        };
        Self {
            inner,
            blake3: self.blake3.clone(),
            sha256: self.sha256.clone(),
            size: self.size,
        }
    }
}

impl StagedFile {
    /// A blob already in the store.
    pub fn from_blob(b: BlobFile) -> Self {
        Self {
            inner: Inner::Blob(b.path),
            blake3: b.blake3,
            sha256: String::new(),
            size: b.size,
        }
    }

    pub fn blake3(&self) -> &str {
        &self.blake3
    }

    /// The SHA-256 of a streamed file (empty for a stored blob).
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn path(&self) -> &Path {
        match &self.inner {
            Inner::Temp(t) => &t.path,
            Inner::Blob(p) => p,
        }
    }

    /// True while it is a temporary file in `staging/` (not yet a blob).
    pub fn is_staged(&self) -> bool {
        matches!(self.inner, Inner::Temp(_))
    }

    /// Takes the temporary file's path, so dropping no longer removes it (core moved it into
    /// the blob store). `None` for a stored blob.
    pub fn take_temp_path(&mut self) -> Option<PathBuf> {
        match &mut self.inner {
            Inner::Temp(t) => {
                let p = std::mem::take(&mut t.path);
                self.inner = Inner::Blob(p.clone());
                Some(p)
            }
            Inner::Blob(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn staged_file_hashes_caps_and_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        let mut w = StageWriter::create(d.path(), "f", 10).await.unwrap();
        w.write(b"hello").await.unwrap();
        let f = w.finish().await.unwrap();
        assert_eq!(f.blake3(), blake3::hash(b"hello").to_hex().as_str());
        assert_eq!(f.sha256(), hex::encode(sha2::Sha256::digest(b"hello")));
        assert_eq!(f.size(), 5);
        let p = f.path().to_path_buf();
        assert!(p.exists());
        drop(f);
        assert!(!p.exists(), "a dropped staged file is removed");

        let mut w = StageWriter::create(d.path(), "f", 4).await.unwrap();
        assert!(matches!(w.write(b"hello").await, Err(HttpError::TooLarge(4))));
        drop(w);
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            0,
            "nothing left behind"
        );

        let mut w = StageWriter::create(d.path(), "../x/y", 10).await.unwrap();
        w.write(b"a").await.unwrap();
        let mut f = w.finish().await.unwrap();
        assert!(f.path().starts_with(d.path()), "the feed id can't move the file");
        let p = f.take_temp_path().unwrap();
        drop(f);
        assert!(p.exists(), "a taken file stays");
    }
}
