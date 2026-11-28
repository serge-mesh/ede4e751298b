//! The helper socket (edge-firewall.md §4 "Socket"): `/run/picket-helper/helper.sock`, 0660,
//! group `picket`; length-delimited JSON frames (`LengthDelimitedCodec` defaults: 4-byte
//! big-endian length; 1 MiB maximum both ways), each `{type, id?, data}`.
//!
//! - **Access:** `SO_PEERCRED` must show the edge's UID or root. Each has its own connection cap
//!   (root's slots are never taken by the edge), so idle or slow edge connections can't lock
//!   the CLI out; a frame that has started must arrive whole within a deadline. `disable` and
//!   `enable` are root's alone (the CLI, edge.md §15): `forbidden` for the edge.
//! - **Every connection on its own task**, one request at a time: the next frame is read only
//!   after the previous response is written, so a client can't queue work. Which connection is
//!   "fast" is never guessed: `ensure`/`delete` go to the fast worker whatever connection they
//!   come on, everything slow to the engine thread or a blocking task, so an `ensure` never
//!   waits behind a `dump` page, an `apply` or an `iptables-restore` holding out for the lock.
//! - **Bounded memory:** frames are decoded straight into typed requests (never into
//!   `serde_json::Value`, which can cost 30× a frame's size), frames over 64 KiB are decoded at
//!   most two at a time, and an `apply` is validated while it streams in, keeping only its
//!   normalised networks (never a string per CIDR). At most one decoded `apply` waits for the
//!   engine: a newer one replaces it (latest wins), so a slow engine can't pile them up. A connection holds at most one response
//!   (≤ 1 MiB) plus its coalesced events (a few KiB), and a client that doesn't read is
//!   dropped after a write timeout.
//! - **Events** go to connections that said `hello` with `events: true`.

use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use picket_api::helper::{
    DeleteRequest, DumpRequest, EnsureRequest, HelloRequest, HelloResponse, HelperError, MAX_FRAME,
    PROTO_VERSION, SetFull, SetStatus, StatusResponse, error_code, kind, sets,
};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::time::{Instant, sleep_until, timeout};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::apply::Apply;
use crate::backend::Backend;
use crate::dump::{self, DumpStore};
use crate::engine::Cmd;
use crate::fast::{FastHandle, Job, MAX_ENTRIES};
use crate::ipset::IpsetError;
use crate::rules::Desired;
use crate::shared::{Mailbox, Shared};

/// Frames larger than this take a decode permit.
const BIG_FRAME: usize = 64 * 1024;
const BIG_FRAME_PERMITS: usize = 2;
const FAST_TIMEOUT: Duration = Duration::from_secs(30);
/// Watchdog: probe the fast path every 10 s (edge-firewall.md §4 "Watchdog").
pub const WATCHDOG_TICK: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// The engine thread counts as stalled when it hasn't finished a pass for this long (a pass is
/// bounded by its exec timeouts, well under this).
pub const ENGINE_STALL: Duration = Duration::from_secs(300);
/// How often an unknown peer UID may trigger a fresh lookup of the edge user.
const RERESOLVE_EVERY: Duration = Duration::from_secs(10);

/// The codec both sides use.
pub fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME)
        .new_codec()
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// The edge's user (name or UID), re-resolved when an unknown UID connects.
    pub edge_user: Option<String>,
    pub edge_uid: Option<u32>,
    /// Root (the CLI).
    pub admin_uid: u32,
    /// A frame must arrive whole within this once its first byte has.
    pub frame_deadline: Duration,
    pub write_timeout: Duration,
    pub edge_conns: usize,
    pub admin_conns: usize,
    /// Longest wait for the engine thread (an `apply` may wait 5 s per lock, twice per family).
    pub engine_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            edge_user: None,
            edge_uid: None,
            admin_uid: 0,
            frame_deadline: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            edge_conns: 4,
            admin_conns: 2,
            engine_timeout: Duration::from_secs(120),
        }
    }
}

/// Binds the socket: a stale socket file is replaced (anything else at the path is refused).
/// It is bound under a temporary name, given mode 0660 and its group, then renamed into place,
/// so it never appears at its path with another mode (and the process-wide umask is left alone).
pub fn bind(path: &Path, gid: Option<u32>) -> io::Result<std::os::unix::net::UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let l = std::os::unix::net::UnixListener::bind(&tmp)?;
    let placed = (|| {
        if let Some(g) = gid
            && let Err(e) = rustix::fs::chown(&tmp, None, Some(rustix::fs::Gid::from_raw_unchecked(g)))
        {
            tracing::warn!(error = %e, gid = g, "cannot set the socket's group");
        }
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o660))?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = placed {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    l.set_nonblocking(true)?;
    Ok(l)
}

#[derive(Deserialize)]
struct Head {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    id: Option<u64>,
}

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(d: D) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de> + Default"))]
struct Body<T> {
    #[serde(default, deserialize_with = "nullable")]
    data: T,
}

fn body<T: for<'de> Deserialize<'de> + Default>(frame: &[u8]) -> Result<T, String> {
    serde_json::from_slice::<Body<T>>(frame)
        .map(|b| b.data)
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct Out<'a, T: Serialize> {
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    data: &'a T,
}

fn err_frame(id: Option<u64>, code: &str, message: &str) -> Vec<u8> {
    let e = HelperError {
        code: code.into(),
        message: message.chars().take(1024).collect(),
    };
    serde_json::to_vec(&Out {
        kind: kind::ERROR,
        id,
        data: &e,
    })
    .unwrap_or_default()
}

fn frame<T: Serialize>(kind: &str, id: Option<u64>, data: &T) -> Vec<u8> {
    match serde_json::to_vec(&Out { kind, id, data }) {
        Ok(v) if v.len() <= MAX_FRAME => v,
        Ok(_) => err_frame(id, error_code::INTERNAL, "response too large"),
        Err(e) => err_frame(id, error_code::INTERNAL, &e.to_string()),
    }
}

async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(d) => sleep_until(d).await,
        None => std::future::pending().await,
    }
}

async fn events(m: Option<&Mailbox>) {
    match m {
        Some(m) => m.notify.notified().await,
        None => std::future::pending().await,
    }
}

/// Releases a connection slot when the connection's task ends, however it ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Server<B: Backend> {
    b: Arc<B>,
    shared: Arc<Shared>,
    engine: SyncSender<Cmd>,
    fast: FastHandle,
    dumps: Arc<Mutex<DumpStore>>,
    cfg: ServerConfig,
    edge_uid: Mutex<(Option<u32>, Option<std::time::Instant>)>,
    edge_count: Arc<AtomicUsize>,
    admin_count: Arc<AtomicUsize>,
    big: Semaphore,
}

impl<B: Backend> Server<B> {
    pub fn new(
        b: Arc<B>,
        shared: Arc<Shared>,
        engine: SyncSender<Cmd>,
        fast: FastHandle,
        cfg: ServerConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            b,
            shared,
            engine,
            fast,
            dumps: Arc::new(Mutex::new(DumpStore::default())),
            edge_uid: Mutex::new((cfg.edge_uid, None)),
            cfg,
            edge_count: Arc::new(AtomicUsize::new(0)),
            admin_count: Arc::new(AtomicUsize::new(0)),
            big: Semaphore::new(BIG_FRAME_PERMITS),
        })
    }

    /// Accepts connections until `shutdown` turns true.
    pub async fn serve(self: Arc<Self>, listener: UnixListener, mut shutdown: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                r = listener.accept() => match r {
                    Ok((stream, _)) => self.clone().admit(stream, shutdown.clone()),
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
                _ = shutdown.changed() => return,
            }
        }
    }

    fn is_edge(&self, uid: u32) -> bool {
        let mut g = self.edge_uid.lock().unwrap_or_else(|p| p.into_inner());
        if g.0 == Some(uid) {
            return true;
        }
        let due = g.1.is_none_or(|t| t.elapsed() >= RERESOLVE_EVERY);
        if let (Some(user), true) = (&self.cfg.edge_user, due) {
            g.1 = Some(std::time::Instant::now());
            if let Some((u, _)) = crate::users::lookup_user(user) {
                if g.0 != Some(u) {
                    tracing::info!(uid = u, "edge user resolved");
                }
                g.0 = Some(u);
            }
        }
        g.0 == Some(uid)
    }

    fn admit(self: Arc<Self>, stream: UnixStream, shutdown: watch::Receiver<bool>) {
        let Ok(cred) = stream.peer_cred() else { return };
        let uid = cred.uid();
        let (count, cap) = if uid == self.cfg.admin_uid {
            (self.admin_count.clone(), self.cfg.admin_conns)
        } else if self.is_edge(uid) {
            (self.edge_count.clone(), self.cfg.edge_conns)
        } else {
            tracing::warn!(uid, "connection refused: neither the edge user nor root");
            return;
        };
        if count.fetch_add(1, Ordering::SeqCst) >= cap {
            count.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(
                uid,
                cap,
                "connection refused: too many connections from this user"
            );
            return;
        }
        let slot = Slot(count);
        tokio::spawn(async move {
            let _slot = slot;
            self.connection(stream, uid, shutdown).await;
        });
    }

    async fn connection(self: Arc<Self>, stream: UnixStream, uid: u32, mut shutdown: watch::Receiver<bool>) {
        let (mut rd, mut wr) = stream.into_split();
        let mut codec = codec();
        let mut buf = BytesMut::with_capacity(4096);
        let mut started: Option<Instant> = None;
        let mut mailbox: Option<Arc<Mailbox>> = None;
        let res: Result<(), String> = async {
            loop {
                match codec.decode(&mut buf) {
                    Ok(Some(f)) => {
                        started = None;
                        let out = self.handle(uid, &f, &mut mailbox).await;
                        drop(f);
                        self.write(&mut wr, out).await?;
                        if buf.capacity() > BIG_FRAME && buf.len() < 4096 {
                            buf = BytesMut::from(&buf[..]);
                        }
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => return Err(format!("bad frame: {e}")),
                }
                if !buf.is_empty() && started.is_none() {
                    started = Some(Instant::now());
                }
                let deadline = started.map(|s| s + self.cfg.frame_deadline);
                tokio::select! {
                    r = rd.read_buf(&mut buf) => match r {
                        Ok(0) => return Ok(()),
                        Ok(_) => {}
                        Err(e) => return Err(e.to_string()),
                    },
                    _ = until(deadline) => return Err("frame not completed in time".into()),
                    _ = events(mailbox.as_deref()), if buf.is_empty() => {
                        if let Some(m) = &mailbox {
                            self.write_events(&mut wr, m).await?;
                        }
                    }
                    _ = shutdown.changed() => return Ok(()),
                }
            }
        }
        .await;
        if let Err(e) = res {
            tracing::info!(uid, error = %e, "connection closed");
        }
        if let Some(m) = mailbox {
            self.shared.unsubscribe(&m);
        }
    }

    async fn write(&self, wr: &mut OwnedWriteHalf, payload: Vec<u8>) -> Result<(), String> {
        let mut out = BytesMut::with_capacity(payload.len() + 4);
        codec()
            .encode(Bytes::from(payload), &mut out)
            .map_err(|e| e.to_string())?;
        match timeout(self.cfg.write_timeout, wr.write_all(&out)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("peer not reading: write timed out".into()),
        }
    }

    async fn write_events(&self, wr: &mut OwnedWriteHalf, m: &Mailbox) -> Result<(), String> {
        let p = m.take();
        if let Some(r) = &p.repaired {
            self.write(wr, frame(kind::RULES_REPAIRED, None, r)).await?;
        }
        if let Some(c) = &p.conditions {
            self.write(wr, frame(kind::CONDITIONS, None, c)).await?;
        }
        for s in p.set_full {
            self.write(wr, frame(kind::SET_FULL, None, &SetFull { set: s }))
                .await?;
        }
        Ok(())
    }

    async fn engine_call<T>(
        &self,
        id: Option<u64>,
        make: impl FnOnce(oneshot::Sender<T>) -> Cmd,
    ) -> Result<T, Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        if self.engine.try_send(make(tx)).is_err() {
            return Err(err_frame(id, error_code::BUSY, "the helper is busy"));
        }
        match timeout(self.cfg.engine_timeout, rx).await {
            Ok(Ok(v)) => Ok(v),
            _ => Err(err_frame(id, error_code::INTERNAL, "the engine did not answer")),
        }
    }

    async fn fast_call(
        &self,
        id: Option<u64>,
        kind: &str,
        job: impl FnOnce(oneshot::Sender<picket_api::helper::EnsureResponse>) -> Job,
    ) -> Vec<u8> {
        let (tx, rx) = oneshot::channel();
        if let Err(e) = self.fast.submit(job(tx)) {
            return err_frame(id, error_code::BUSY, e);
        }
        match timeout(FAST_TIMEOUT, rx).await {
            Ok(Ok(r)) => frame(kind, id, &r),
            _ => err_frame(id, error_code::INTERNAL, "the fast path did not answer"),
        }
    }

    async fn handle(&self, uid: u32, f: &[u8], mailbox: &mut Option<Arc<Mailbox>>) -> Vec<u8> {
        let parsed = {
            // Large frames are decoded at most two at a time; the permit covers the decode only.
            let _permit = if f.len() > BIG_FRAME {
                self.big.acquire().await.ok()
            } else {
                None
            };
            parse_request(f)
        };
        let (id, req) = match parsed {
            Ok(x) => x,
            Err((id, e)) => return frame(kind::ERROR, id, &e),
        };
        match req {
            Request::Hello(req) => {
                if req.proto_version == PROTO_VERSION && req.events && mailbox.is_none() {
                    *mailbox = Some(self.shared.subscribe());
                }
                let s = self.shared.snapshot();
                frame(
                    kind::HELLO,
                    id,
                    &HelloResponse {
                        proto_version: PROTO_VERSION,
                        helper_version: picket_api::VERSION.into(),
                        sets: s.sets,
                        interfaces: s.interfaces,
                        rules_ok: s.rules_ok,
                        conditions: s.conditions,
                    },
                )
            }
            Request::Apply(d) => {
                let (tx, rx) = oneshot::channel();
                if self.shared.put_apply(d, tx) {
                    // A full queue means the engine is busy and looks for the apply after the
                    // command in hand, so a lost wake costs nothing.
                    let _ = self.engine.try_send(Cmd::ApplyPending);
                }
                match timeout(self.cfg.engine_timeout, rx).await {
                    Ok(Ok(r)) => frame(kind::APPLY, id, &r),
                    _ => err_frame(id, error_code::INTERNAL, "the engine did not answer"),
                }
            }
            // The emergency switch is the CLI's alone (edge.md §15): an edge can neither lift an
            // admin's `disable` nor set one.
            Request::Disable | Request::Enable if uid != self.cfg.admin_uid => err_frame(
                id,
                error_code::FORBIDDEN,
                "disable and enable are for root (picket-edge-helper disable | enable)",
            ),
            Request::Disable => match self.engine_call(id, Cmd::Disable).await {
                Ok(r) => frame(kind::DISABLE, id, &r),
                Err(f) => f,
            },
            Request::Enable => match self.engine_call(id, Cmd::Enable).await {
                Ok(r) => frame(kind::ENABLE, id, &r),
                Err(f) => f,
            },
            Request::Ensure(req) => {
                self.fast_call(id, kind::ENSURE, |tx| Job::Ensure(req.entries, tx))
                    .await
            }
            Request::Delete(req) => {
                self.fast_call(id, kind::DELETE, |tx| Job::Delete(req.entries, tx))
                    .await
            }
            Request::Dump(req) => {
                let (b, store) = (self.b.clone(), self.dumps.clone());
                match tokio::task::spawn_blocking(move || dump::page(&store, &*b, &req)).await {
                    Ok(Ok(r)) => frame(kind::DUMP, id, &r),
                    Ok(Err(e)) => frame(kind::ERROR, id, &e),
                    Err(_) => err_frame(id, error_code::INTERNAL, "dump failed"),
                }
            }
            Request::Status => {
                let s = self.shared.snapshot();
                let (rejects, mon_rejects) = self
                    .shared
                    .counters
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take_growth(uid);
                let b = self.b.clone();
                let fresh = tokio::task::spawn_blocking(move || {
                    sets::TIMED
                        .iter()
                        .map(|n| match b.ipset_header(n) {
                            Ok(Some(h)) => Some(SetStatus {
                                name: (*n).into(),
                                entries: h.elements.unwrap_or(0) as u64,
                                max: h.maxelem.unwrap_or(sets::MAXELEM) as u64,
                            }),
                            _ => None,
                        })
                        .collect::<Option<Vec<_>>>()
                })
                .await
                .ok()
                .flatten();
                frame(
                    kind::STATUS,
                    id,
                    &StatusResponse {
                        rules_ok: s.rules_ok,
                        sets: fresh.unwrap_or(s.sets),
                        last_repair: s.last_repair,
                        conditions: s.conditions,
                        rejects,
                        mon_rejects,
                        pending: s.pending,
                    },
                )
            }
        }
    }
}

/// A decoded request.
#[derive(Debug)]
pub enum Request {
    Hello(HelloRequest),
    Apply(Box<Desired>),
    Disable,
    Enable,
    Ensure(EnsureRequest),
    Delete(DeleteRequest),
    Dump(DumpRequest),
    Status,
}

fn invalid(id: Option<u64>, m: impl Into<String>) -> (Option<u64>, HelperError) {
    (
        id,
        HelperError {
            code: error_code::INVALID.into(),
            message: m.into(),
        },
    )
}

/// Decodes one frame straight into a typed request (never into `serde_json::Value`): its `id`
/// and request, or the `id` (if readable) and the error to answer with. Collections are checked
/// against their limits here.
pub fn parse_request(f: &[u8]) -> Result<(Option<u64>, Request), (Option<u64>, HelperError)> {
    let head: Head = serde_json::from_slice(f).map_err(|_| invalid(None, "malformed frame"))?;
    let id = head.id;
    macro_rules! parse {
        ($t:ty) => {
            body::<$t>(f).map_err(|e| invalid(id, e))?
        };
    }
    let req = match head.kind.as_str() {
        kind::HELLO => Request::Hello(parse!(HelloRequest)),
        kind::APPLY => Request::Apply(Box::new(parse!(Apply).desired().map_err(|e| invalid(id, e))?)),
        kind::DISABLE => Request::Disable,
        kind::ENABLE => Request::Enable,
        kind::ENSURE => {
            let r = parse!(EnsureRequest);
            if r.entries.len() > MAX_ENTRIES {
                return Err(invalid(id, "too many entries"));
            }
            Request::Ensure(r)
        }
        kind::DELETE => {
            let r = parse!(DeleteRequest);
            if r.entries.len() > MAX_ENTRIES {
                return Err(invalid(id, "too many entries"));
            }
            Request::Delete(r)
        }
        kind::DUMP => Request::Dump(parse!(DumpRequest)),
        kind::STATUS => Request::Status,
        other => {
            let name: String = other.chars().take(32).collect();
            return Err((
                id,
                HelperError {
                    code: error_code::UNKNOWN_TYPE.into(),
                    message: format!("unknown type {name:?}"),
                },
            ));
        }
    };
    Ok((id, req))
}

/// Did the fast worker answer a probe, with the kernel replying? A kernel error still proves the
/// path alive; a netlink timeout or no answer from the worker doesn't.
pub async fn probe(fast: &FastHandle, wait: Duration) -> bool {
    let (tx, rx) = oneshot::channel();
    if fast.submit(Job::Probe(tx)).is_err() {
        return false;
    }
    match timeout(wait, rx).await {
        Ok(Ok(Err(IpsetError::Timeout))) => false,
        Ok(Ok(_)) => true,
        _ => false,
    }
}

/// Feeds systemd's watchdog (edge-firewall.md §4 "Watchdog"). Since no connection is known to be
/// the fast one, a dedicated task proves the `ensure` path alive instead: every 10 s it sends a
/// probe through the same worker thread and netlink socket `ensure` uses, and pings only if it
/// comes back (and the engine thread isn't stalled). A hung netlink call stops the pings and
/// systemd restarts the helper after `WatchdogSec=30`.
pub async fn watchdog<B: Backend>(
    fast: FastHandle,
    shared: Arc<Shared>,
    b: Arc<B>,
    mut shutdown: watch::Receiver<bool>,
) {
    let enabled = sd_notify::watchdog_enabled().is_some();
    let mut tick = tokio::time::interval(WATCHDOG_TICK);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        // Probed (and logged) whether or not systemd watches.
        let feed = feed_watchdog(&fast, &shared, &*b, PROBE_TIMEOUT).await;
        if feed && enabled {
            let _ = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]);
        }
    }
}

/// Has the engine thread finished a pass within [`ENGINE_STALL`]?
pub fn engine_alive<B: Backend + ?Sized>(shared: &Shared, b: &B) -> bool {
    let beat = shared.engine_beat.load(Ordering::Relaxed);
    b.mono().as_secs().saturating_sub(beat) <= ENGINE_STALL.as_secs()
}

/// One watchdog tick's decision: feed systemd only if the fast path answers a probe within
/// `wait` and the engine thread isn't stalled; otherwise log why not.
pub async fn feed_watchdog<B: Backend + ?Sized>(
    fast: &FastHandle,
    shared: &Shared,
    b: &B,
    wait: Duration,
) -> bool {
    let alive = probe(fast, wait).await;
    let engine = engine_alive(shared, b);
    if !(alive && engine) {
        tracing::error!(fast_path = alive, engine, "watchdog not fed");
    }
    alive && engine
}

#[cfg(test)]
mod apply_tests {
    use super::*;
    use crate::engine::{self, Engine};
    use crate::fake::FakeBackend;
    use crate::fast;
    use crate::iptables::Platform;
    use std::sync::mpsc::sync_channel;

    const EDGE: u32 = 1001;

    fn apply(name: &str) -> Vec<u8> {
        format!(r#"{{"type":"apply","id":7,"data":{{"interfaces":[{{"name":"{name}","mode":"monitor"}}]}}}}"#)
            .into_bytes()
    }

    async fn call(s: &Server<FakeBackend>, f: &[u8]) -> serde_json::Value {
        serde_json::from_slice(&s.handle(EDGE, f, &mut None).await).unwrap()
    }

    #[tokio::test]
    async fn a_newer_apply_replaces_a_waiting_one_and_both_callers_get_the_answer() {
        let b = Arc::new(FakeBackend::new());
        let shared = Shared::new();
        // A one-slot queue, already full: the engine is busy and the applies' wakes are lost.
        let (tx, rx) = sync_channel(1);
        tx.try_send(Cmd::Trigger).unwrap();
        let fast = fast::spawn(b.clone(), shared.clone(), tx.clone()).unwrap();
        let s = Server::new(b.clone(), shared.clone(), tx, fast, ServerConfig::default());
        let first = tokio::spawn({
            let s = s.clone();
            async move { call(&s, &apply("br0")).await }
        });
        let second = tokio::spawn({
            let s = s.clone();
            async move { call(&s, &apply("br1")).await }
        });
        // Both are decoded and waiting before the engine starts; neither was refused.
        timeout(Duration::from_secs(2), async {
            while shared.apply_waiters() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the second apply did not replace the first");
        let engine = Engine::new(b.clone(), shared.clone(), Platform::Debian);
        std::thread::spawn(move || engine::run(engine, rx));
        for r in [first.await.unwrap(), second.await.unwrap()] {
            assert_eq!(r["type"], "apply", "{r}");
        }
        // Only the newer state was applied.
        let hello = call(
            &s,
            br#"{"type":"hello","id":8,"data":{"proto_version":1,"events":false}}"#,
        )
        .await;
        assert_eq!(
            hello["data"]["interfaces"],
            serde_json::json!([{"name": "br1", "mode": "monitor"}]),
            "{hello}"
        );
    }
}
