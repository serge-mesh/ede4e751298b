//! The admin socket (edge.md §1, §2, §15): `<runtime-dir>/edge.sock`, 0660 group `picket` under
//! the service and 0600 otherwise, for the CLI. JSON lines: a request
//! `{"cmd": "<name>", "args": {…}}` gets `{"ok": true, "data": …}` or
//! `{"ok": false, "error": {"code", "message"}}`. Commands live in a registry other modules
//! extend ([`AdminRegistry::register`]); an unknown command answers `unknown_command`, which the
//! CLI shows as "not available".

use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::edge::Edge;
use crate::fsutil;
use crate::users;

/// Longest request line.
pub const MAX_REQUEST: usize = 64 << 10;
/// Longest reply line the client reads.
pub const MAX_REPLY: usize = 16 << 20;
/// Concurrent admin connections.
const MAX_CONNS: usize = 16;
const IDLE: Duration = Duration::from_secs(30);
const WRITE: Duration = Duration::from_secs(10);
/// How long one command may run before it is cut off.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(120);
/// Longest socket path the kernel takes (`sun_path` holds 108 bytes with its NUL).
const MAX_SUN_PATH: usize = 107;

/// An admin command's error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl AdminError {
    pub fn new(code: &str, message: impl std::fmt::Display) -> Self {
        Self {
            code: code.to_owned(),
            message: crate::diag::cap(message),
        }
    }
    pub fn bad_args(m: impl std::fmt::Display) -> Self {
        Self::new("bad_args", m)
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        Self::new("internal", e)
    }
}

/// A command handler.
pub type Handler = Arc<
    dyn Fn(Arc<Edge>, serde_json::Value) -> BoxFuture<'static, Result<serde_json::Value, AdminError>>
        + Send
        + Sync,
>;

/// The command registry.
pub struct AdminRegistry {
    cmds: ArcSwap<HashMap<String, Handler>>,
    timeout_ms: std::sync::atomic::AtomicU64,
}

impl Default for AdminRegistry {
    fn default() -> Self {
        Self {
            cmds: ArcSwap::default(),
            timeout_ms: std::sync::atomic::AtomicU64::new(picket_api::duration::as_millis_u64(
                HANDLER_TIMEOUT,
            )),
        }
    }
}

impl AdminRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Changes how long a command may run (tests).
    pub fn set_timeout(&self, d: Duration) {
        self.timeout_ms.store(
            picket_api::duration::as_millis_u64(d),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// How long a command may run before it is cut off (a command whose work may take longer
    /// answers before then and lets the work go on, as `update --install` does, edge.md §14).
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Registers (or replaces) a command.
    pub fn register<F, Fut>(&self, name: &str, f: F)
    where
        F: Fn(Arc<Edge>, serde_json::Value) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<serde_json::Value, AdminError>> + Send + 'static,
    {
        let h: Handler = Arc::new(move |e, a| Box::pin(f(e, a)));
        let name = name.to_owned();
        self.cmds.rcu(|m| {
            let mut m = HashMap::clone(m);
            m.insert(name.clone(), Arc::clone(&h));
            m
        });
    }

    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.cmds.load().keys().cloned().collect();
        v.sort();
        v
    }

    /// Runs a command.
    pub async fn call(
        &self,
        edge: Arc<Edge>,
        cmd: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, AdminError> {
        let Some(h) = self.cmds.load().get(cmd).cloned() else {
            return Err(AdminError::new(
                "unknown_command",
                format!("{cmd:?} isn't available in this edge"),
            ));
        };
        // In a task of its own: a handler that panics answers an error instead of taking the
        // connection with it, and one that hangs is cut off rather than holding a connection
        // slot forever.
        let task = tokio::spawn(h(edge, args));
        let abort = task.abort_handle();
        let timeout = self.timeout();
        match tokio::time::timeout(timeout, task).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.is_panic() => Err(AdminError::internal(format!(
                "{cmd} failed: {}",
                crate::supervisor::panic_message(e.into_panic())
            ))),
            Ok(Err(e)) => Err(AdminError::internal(format!("{cmd} failed: {e}"))),
            Err(_) => {
                abort.abort();
                Err(AdminError::internal(format!(
                    "{cmd} didn't finish within {} ms",
                    timeout.as_millis()
                )))
            }
        }
    }
}

#[derive(Deserialize)]
struct Request {
    cmd: String,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct Reply {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<AdminError>,
}

/// Creates a missing runtime directory 0700 (edge.md §2; the unit's `RuntimeDirectory=` makes it
/// under the service).
pub fn ensure_runtime_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fsutil::create_dir_all_mode(dir, 0o700)
            .with_context(|| format!("runtime directory {}", dir.display()))?;
    }
    Ok(())
}

/// The path to bind or dial for a socket: the path itself, or, when it is too long for
/// `sun_path` (a development edge under a deep directory), the same file relative to the
/// current directory.
pub fn sun_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.as_os_str().len() <= MAX_SUN_PATH {
        return Ok(path.to_path_buf());
    }
    if let Ok(cwd) = std::env::current_dir()
        && let Ok(rel) = path.strip_prefix(&cwd)
        && rel.as_os_str().len() <= MAX_SUN_PATH
    {
        return Ok(rel.to_path_buf());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "socket path {} is longer than {MAX_SUN_PATH} bytes; use a shorter --runtime-dir",
            path.display()
        ),
    ))
}

/// True when an edge answers on `socket`: another picket-edge runs with this runtime directory.
pub fn edge_answers(socket: &Path) -> bool {
    sun_path(socket).is_ok_and(|p| std::os::unix::net::UnixStream::connect(p).is_ok())
}

/// Binds the socket with its mode set before it appears under its name: bound to a temporary
/// name, chmod/chown'd there, then renamed over `edge.sock`. A stale socket is replaced, but
/// never one another edge still answers on; anything else at that path (a file, a symlink) is
/// refused.
pub fn bind(path: &Path, service: bool) -> Result<UnixListener> {
    let (dir, name) = fsutil::split(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if edge_answers(path) {
                bail!(
                    "another picket-edge is running with runtime directory {}",
                    dir.display()
                );
            }
        }
        Ok(_) => bail!(
            "{} exists and isn't a socket; refusing to replace it",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow!("{}: {e}", path.display())),
    }
    let tmp = dir.join(fsutil::tmp_name(name));
    let listener =
        UnixListener::bind(sun_path(&tmp)?).with_context(|| format!("binding {}", tmp.display()))?;
    let result = (|| -> Result<()> {
        let dirfd = rustix::fs::open(
            dir,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let tmp_name = tmp.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let mode = if service { 0o660 } else { 0o600 };
        rustix::fs::chmodat(
            &dirfd,
            tmp_name,
            rustix::fs::Mode::from_raw_mode(mode),
            rustix::fs::AtFlags::empty(),
        )?;
        if service && let Some(gid) = users::picket_gid() {
            rustix::fs::chownat(
                &dirfd,
                tmp_name,
                None,
                Some(rustix::fs::Gid::from_raw(gid)),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
        }
        rustix::fs::renameat(&dirfd, tmp_name, &dirfd, name)?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.context(format!("setting up {}", path.display())));
    }
    Ok(listener)
}

/// Serves the admin socket.
pub async fn serve(edge: Arc<Edge>, listener: UnixListener) -> Result<()> {
    let sem = Arc::new(Semaphore::new(MAX_CONNS));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
            drop(stream); // over the connection cap
            continue;
        };
        let edge = Arc::clone(&edge);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = connection(edge, stream).await {
                tracing::debug!("admin connection: {}", crate::diag::cap_chain(&e));
            }
        });
    }
}

async fn connection(edge: Arc<Edge>, stream: UnixStream) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    loop {
        let mut line = Vec::new();
        let n = tokio::time::timeout(IDLE, read_line_bounded(&mut reader, &mut line, MAX_REQUEST))
            .await
            .map_err(|_| anyhow!("idle"))??;
        if n == 0 {
            return Ok(());
        }
        let reply = match serde_json::from_slice::<Request>(&line) {
            Ok(req) => match edge.admin.call(Arc::clone(&edge), &req.cmd, req.args).await {
                Ok(data) => Reply {
                    ok: true,
                    data: Some(data),
                    error: None,
                },
                Err(e) => Reply {
                    ok: false,
                    data: None,
                    error: Some(e),
                },
            },
            Err(e) => Reply {
                ok: false,
                data: None,
                error: Some(AdminError::new("bad_request", e)),
            },
        };
        let mut out = serde_json::to_vec(&reply)?;
        out.push(b'\n');
        tokio::time::timeout(WRITE, w.write_all(&out))
            .await
            .map_err(|_| anyhow!("write timed out"))??;
    }
}

/// Reads one `\n`-terminated line of at most `max` bytes (without the newline). 0 at EOF.
async fn read_line_bounded<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    out: &mut Vec<u8>,
    max: usize,
) -> Result<usize> {
    loop {
        let buf = r.fill_buf().await?;
        if buf.is_empty() {
            return Ok(out.len());
        }
        if let Some(i) = buf.iter().position(|b| *b == b'\n') {
            if out.len() + i > max {
                bail!("line over {max} bytes");
            }
            out.extend_from_slice(&buf[..i]);
            r.consume(i + 1);
            return Ok(out.len().max(1));
        }
        let n = buf.len();
        if out.len() + n > max {
            bail!("line over {max} bytes");
        }
        out.extend_from_slice(buf);
        r.consume(n);
    }
}

/// Why a CLI call failed.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("the edge isn't running (no admin socket at {0}): {1}")]
    NotRunning(PathBuf, String),
    #[error("{0}")]
    Remote(AdminError),
    #[error("{0}")]
    Other(String),
}

/// Sends one command to the running edge.
pub async fn call(socket: &Path, cmd: &str, args: serde_json::Value) -> Result<serde_json::Value, CallError> {
    let addr = sun_path(socket).map_err(|e| CallError::NotRunning(socket.to_path_buf(), e.to_string()))?;
    let stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(addr))
        .await
        .map_err(|_| CallError::NotRunning(socket.to_path_buf(), "timed out".into()))?
        .map_err(|e| CallError::NotRunning(socket.to_path_buf(), e.to_string()))?;
    let (r, mut w) = stream.into_split();
    let mut req = serde_json::to_vec(&serde_json::json!({"cmd": cmd, "args": args}))
        .map_err(|e| CallError::Other(e.to_string()))?;
    req.push(b'\n');
    tokio::time::timeout(WRITE, w.write_all(&req))
        .await
        .map_err(|_| CallError::Other("write timed out".into()))?
        .map_err(|e| CallError::Other(e.to_string()))?;
    let mut reader = BufReader::new(r);
    let mut line = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(60),
        read_line_bounded(&mut reader, &mut line, MAX_REPLY),
    )
    .await
    .map_err(|_| CallError::Other("no reply in time".into()))?
    .map_err(|e| CallError::Other(e.to_string()))?;
    let reply: Reply = serde_json::from_slice(&line).map_err(|e| CallError::Other(crate::diag::cap(e)))?;
    if reply.ok {
        Ok(reply.data.unwrap_or(serde_json::Value::Null))
    } else {
        Err(CallError::Remote(
            reply
                .error
                .unwrap_or_else(|| AdminError::new("unknown", "no error detail")),
        ))
    }
}

/// The socket's mode and group, for tests and `status`.
pub fn socket_mode(path: &Path) -> Option<(u32, u32)> {
    std::fs::metadata(path).ok().map(|m| (m.mode() & 0o777, m.gid()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_sets_mode_and_refuses_non_sockets() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("edge.sock");
        let l = bind(&p, false).unwrap();
        assert_eq!(socket_mode(&p).unwrap().0, 0o600);
        // A live edge's socket is never taken over.
        let e = bind(&p, false).unwrap_err();
        assert!(format!("{e:#}").contains("another picket-edge"), "{e:#}");
        assert!(edge_answers(&p));
        drop(l);
        // A stale socket is replaced.
        assert!(!edge_answers(&p));
        let _l = bind(&p, false).unwrap();
        let f = d.path().join("other.sock");
        std::fs::write(&f, b"x").unwrap();
        assert!(bind(&f, false).is_err());
        let link = d.path().join("link.sock");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(bind(&link, false).is_err());
        assert_eq!(std::fs::read(&f).unwrap(), b"x");
    }

    #[test]
    fn long_socket_paths_fall_back_to_the_current_directory() {
        let cwd = std::env::current_dir().unwrap();
        let short = PathBuf::from("/run/picket/edge.sock");
        assert_eq!(sun_path(&short).unwrap(), short);
        let long_rel = PathBuf::from("dev").join("x".repeat(80)).join("run/edge.sock");
        let long = cwd.join(&long_rel);
        if cwd.as_os_str().len() + 1 + long_rel.as_os_str().len() > MAX_SUN_PATH {
            assert_eq!(sun_path(&long).unwrap(), long_rel);
        }
        let outside = PathBuf::from("/").join("y".repeat(120)).join("edge.sock");
        let e = sun_path(&outside).unwrap_err();
        assert!(e.to_string().contains("--runtime-dir"), "{e}");
    }

    #[tokio::test]
    async fn bounded_lines() {
        let data = b"short\nthis line is far too long\n".to_vec();
        let mut r = BufReader::new(&data[..]);
        let mut out = vec![];
        read_line_bounded(&mut r, &mut out, 10).await.unwrap();
        assert_eq!(out, b"short");
        let mut out = vec![];
        assert!(read_line_bounded(&mut r, &mut out, 10).await.is_err());
    }
}
