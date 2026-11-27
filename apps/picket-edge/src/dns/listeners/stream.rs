//! TCP and DoT listeners (edge.md §5; RFC 7766, RFC 7858): length-prefixed messages with
//! pipelining (queries are answered as they finish, out of order). `interfaces` matches the local
//! address's interface. DoT takes a profile id from the SNI prefix `<profile id>.<tls name>`; its
//! handshake is TLS 1.3 only, refusals reported ([`super::handshake`]).
//!
//! Bounds (README §2 "Bounded", edge.md §16):
//! - at most `max_connections` connections per listener, and a per-source share across every
//!   stream listener ([`super::share`]), both taken at `accept`, so a TLS handshake holds them
//!   too (at most [`HANDSHAKE_TIMEOUT`]);
//! - a connection is idle when every query it sent has its reply written (RFC 7766 §6.2.3); one
//!   idle with no progress (a complete query read or a reply written) for `idle_timeout_ms` is
//!   closed. The deadline is absolute: once it has passed it is checked before anything more is
//!   read, so bytes trickled into a partial frame never keep a connection open, even when they
//!   are ready at the same moment as the deadline;
//! - each reply write must finish within [`WRITE_TIMEOUT`]: a client that stops reading loses
//!   the connection (the writer is cancelled, never detached), and the reader stops with it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::AcqRel, Ordering::Acquire, Ordering::Relaxed};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::{Buf, BytesMut};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, mpsc, watch};

use picket_api::logs::Proto;

use super::SharedSpec;
use crate::dns::certs::CertSlot;
use crate::dns::pipeline::{self, Admitted, Inbound};
use crate::edge::Edge;

/// Queries in flight per connection; reading pauses beyond it (backpressure).
pub const MAX_PIPELINE: usize = 64;
/// TLS handshakes must finish within this (a LAN handshake takes milliseconds).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// One reply's write to the client must finish within this.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const LISTEN_BACKLOG: i32 = 1024;

pub enum Kind {
    Tcp,
    /// TLS 1.3 under this config ([`super::handshake`]), serving this slot's certificate.
    Dot(Arc<rustls::ServerConfig>, Arc<CertSlot>),
}

/// Binds a TCP listening socket (dual-stack for a wildcard IPv6 bind).
pub fn bind_tcp(addr: SocketAddr) -> Result<std::net::TcpListener> {
    let s =
        Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP)).context("TCP socket")?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        s.set_only_v6(false)?;
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into()).with_context(|| format!("TCP {addr}"))?;
    s.listen(LISTEN_BACKLOG)?;
    Ok(std::net::TcpListener::from(s))
}

/// Takes the next complete length-prefixed DNS message (RFC 1035 §4.2.2) off the front of
/// `buf`, or `None` while it holds only part of one (reserving room for the rest). Messages are
/// at most 65,535 bytes by construction (a 16-bit length).
pub fn take_frame(buf: &mut BytesMut) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if buf.len() < 2 + len {
        buf.reserve(2 + len - buf.len());
        return None;
    }
    buf.advance(2);
    Some(buf.split_to(len).to_vec())
}

/// [`take_frame`] into a buffer from `pool` (reused across the connection's queries).
fn take_frame_pooled(buf: &mut BytesMut, pool: &super::BufPool) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if buf.len() < 2 + len {
        buf.reserve(2 + len - buf.len());
        return None;
    }
    let mut v = pool.take();
    v.extend_from_slice(&buf[2..2 + len]);
    buf.advance(2 + len);
    Some(v)
}

/// Spare query and reply buffers kept per connection.
const CONN_POOL: usize = 8;

/// Counts open connections against `max_connections`.
pub struct ConnCount(pub Arc<AtomicUsize>);

impl ConnCount {
    pub fn try_take(c: &Arc<AtomicUsize>, max: usize) -> Option<ConnCount> {
        c.try_update(Relaxed, Relaxed, |n| (n < max).then_some(n + 1))
            .ok()
            .map(|_| ConnCount(Arc::clone(c)))
    }
}

impl Drop for ConnCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

/// What an accepted connection holds while it is open: a slot of its listener's
/// `max_connections` and one of its source's share.
pub struct ConnGuards {
    _slot: ConnCount,
    _share: super::share::ConnShare,
}

/// Admits an accepted connection: the listener's `max_connections`, its `interfaces`, then the
/// source's share. `None`: closed at once (counted as `rejected`).
pub fn admit_conn(
    edge: &Edge,
    spec: &SharedSpec,
    count: &Arc<AtomicUsize>,
    tcp: &TcpStream,
    peer: SocketAddr,
) -> Option<ConnGuards> {
    let sp = spec.load();
    let slot = ConnCount::try_take(count, sp.limits.max_connections as usize)?;
    let local = tcp.local_addr().ok()?;
    if !interface_ok(edge, &sp, local) {
        return None;
    }
    let key = super::share::source_key(edge, peer.ip());
    let Some(share) = edge.dns.listeners.shares.connect(key) else {
        edge.metrics.rejected.fetch_add(1, Relaxed);
        return None;
    };
    let _ = tcp.set_nodelay(true);
    Some(ConnGuards {
        _slot: slot,
        _share: share,
    })
}

/// True when a connection to `local` is accepted under the listener's `interfaces`.
pub fn interface_ok(edge: &Edge, spec: &crate::dns::runtime::ListenerSpec, local: SocketAddr) -> bool {
    if spec.interfaces.is_empty() {
        return true;
    }
    edge.dns
        .interfaces
        .interface_of(local.ip())
        .is_some_and(|n| spec.interfaces.iter().any(|x| x.as_str() == &*n))
}

pub fn spawn_accept(
    edge: Arc<Edge>,
    l: std::net::TcpListener,
    spec: SharedSpec,
    mut shutdown: watch::Receiver<bool>,
    kind: Kind,
    live: Arc<super::Live>,
) -> Result<tokio::task::JoinHandle<()>> {
    let l = TcpListener::from_std(l)?;
    let kind = Arc::new(kind);
    Ok(tokio::spawn(async move {
        let count = Arc::new(AtomicUsize::new(0));
        // The watchdog's liveness mark (edge.md §16): the first tick is at once. Not stamped
        // while the last accept failed for want of descriptors or memory (the connection waits
        // in the backlog and the next try repeats it), so lasting exhaustion fails the test.
        let mut tick = live.interval();
        let mut exhausted = false;
        loop {
            live.park_if_stalled().await;
            let (tcp, peer) = tokio::select! {
                _ = shutdown.changed() => return,
                _ = tick.tick() => {
                    if !exhausted {
                        live.stamp();
                    }
                    continue;
                }
                r = l.accept() => match r {
                    Ok(x) => {
                        exhausted = false;
                        x
                    }
                    Err(e) => {
                        exhausted = super::out_of_resources(&e);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                },
            };
            let Some(guards) = admit_conn(&edge, &spec, &count, &tcp, peer) else {
                continue;
            };
            let edge = Arc::clone(&edge);
            let kind = Arc::clone(&kind);
            let shutdown = shutdown.clone();
            let spec = Arc::clone(&spec);
            tokio::spawn(async move {
                let _guards = guards;
                serve_conn(edge, tcp, peer, spec, shutdown, &kind).await;
            });
        }
    }))
}

async fn serve_conn(
    edge: Arc<Edge>,
    tcp: TcpStream,
    peer: SocketAddr,
    spec: SharedSpec,
    shutdown: watch::Receiver<bool>,
    kind: &Kind,
) {
    match kind {
        Kind::Tcp => serve_stream(edge, tcp, peer, spec, None, Proto::Tcp, shutdown).await,
        Kind::Dot(cfg, slot) => {
            let id = Arc::clone(&spec.load().id);
            let transport = super::handshake::Transport::Dot;
            let Some(tls) =
                super::handshake::accept(&edge, cfg, tcp, peer, &id, transport, HANDSHAKE_TIMEOUT).await
            else {
                return;
            };
            let sni = tls.get_ref().1.server_name().map(str::to_ascii_lowercase);
            let names = tls_names(&spec.load(), slot);
            let named = sni.as_deref().and_then(|s| profile_prefix(s, &names));
            serve_stream(edge, tls, peer, spec, named, Proto::Dot, shutdown).await
        }
    }
}

/// The names a TLS listener answers to: its managed name, or the DNS names of its certificate.
pub fn tls_names(spec: &crate::dns::runtime::ListenerSpec, slot: &CertSlot) -> Vec<String> {
    match spec.tls.as_ref().and_then(|t| t.managed.clone()) {
        Some(n) => vec![n.trim_end_matches('.').to_ascii_lowercase()],
        None => slot
            .names()
            .into_iter()
            .filter(|n| !n.starts_with("*."))
            .collect(),
    }
}

/// The profile id an SNI names (edge.md §5): `<profile id>.<tls name>` with a single-label
/// prefix. The bare TLS name names none.
pub fn profile_prefix(sni: &str, names: &[String]) -> Option<String> {
    let sni = sni.trim_end_matches('.');
    names.iter().find_map(|n| {
        let rest = sni.strip_suffix(n.as_str())?;
        let label = rest.strip_suffix('.')?;
        (!label.is_empty() && !label.contains('.')).then(|| label.to_owned())
    })
}

/// A connection's idle clock (RFC 7766 §6.2.3): the last progress (a complete query read or a
/// reply written) and the queries still owed a reply.
struct Progress {
    base: Instant,
    ms: AtomicU64,
    /// Queries read whose reply isn't written yet (or that ended without one).
    owed: AtomicUsize,
    /// Wakes the reader when `owed` drops, so it can start the idle deadline.
    settled: Notify,
}

impl Progress {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            ms: AtomicU64::new(0),
            owed: AtomicUsize::new(0),
            settled: Notify::new(),
        }
    }
    fn touch(&self) {
        self.ms
            .store(picket_api::duration::as_millis_u64(self.base.elapsed()), Relaxed);
    }
    /// When the connection's idle time runs out, counted from its last progress.
    fn deadline(&self, idle: Duration) -> Instant {
        self.base + Duration::from_millis(self.ms.load(Relaxed)) + idle
    }
    /// True while no query is owed a reply.
    fn idle(&self) -> bool {
        self.owed.load(Acquire) == 0
    }
    fn owe(&self) {
        self.owed.fetch_add(1, AcqRel);
    }
    /// A query's work ended: its reply written (`wrote`, which is progress) or none to write.
    fn settle(&self, wrote: bool) {
        if wrote {
            self.touch();
        }
        self.owed.fetch_sub(1, AcqRel);
        self.settled.notify_one();
    }
}

/// A query owed a reply: settled (with no reply written) when dropped, unless its reply went to
/// the writer, which settles it once written. However the query's task ends, the connection can
/// still become idle.
struct Owed(Option<Arc<Progress>>);

impl Owed {
    fn new(p: &Arc<Progress>) -> Self {
        p.owe();
        Self(Some(Arc::clone(p)))
    }
    /// The reply is the writer's now.
    fn handed_over(mut self) {
        self.0 = None;
    }
}

impl Drop for Owed {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            p.settle(false);
        }
    }
}

/// Serves length-prefixed DNS messages on one connection with pipelining.
pub async fn serve_stream<S>(
    edge: Arc<Edge>,
    io: S,
    peer: SocketAddr,
    spec: SharedSpec,
    named: Option<String>,
    proto: Proto,
    mut shutdown: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(io);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_PIPELINE);
    let progress = Arc::new(Progress::new());
    let wrote = Arc::clone(&progress);
    let pool = Arc::new(super::BufPool::new(CONN_POOL));
    let spare = Arc::clone(&pool);
    let mut writer = tokio::spawn(async move {
        // One frame buffer for the connection's life: no allocation per reply once warm.
        let mut frame = Vec::with_capacity(514);
        while let Some(r) = rx.recv().await {
            let Ok(len) = u16::try_from(r.len()) else {
                spare.put(r);
                wrote.settle(false);
                continue;
            };
            frame.clear();
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&r);
            let w = tokio::time::timeout(WRITE_TIMEOUT, async {
                wr.write_all(&frame).await?;
                wr.flush().await
            })
            .await;
            spare.put(r);
            match w {
                Ok(Ok(())) => wrote.settle(true),
                // A write error, or a client that stopped reading: the connection ends.
                _ => return,
            }
        }
        let _ = tokio::time::timeout(WRITE_TIMEOUT, wr.shutdown()).await;
    });
    let mut writer_done = false;
    let inflight = Arc::new(Semaphore::new(MAX_PIPELINE));
    let named: Option<Arc<str>> = named.map(Into::into);
    let mut buf = BytesMut::with_capacity(1024);
    'conn: loop {
        // RFC 7766 §6.2.3: a connection is idle once every query has its reply written; one idle
        // for the listener's timeout since its last progress is closed. The deadline is absolute
        // and checked before the bytes of the last read are used, so a read that raced the
        // deadline (or a trickle of partial frames) never extends it (README §2 Bounded).
        let idle = Duration::from_millis(u64::from(spec.load().limits.idle_timeout_ms));
        if progress.idle() && Instant::now() >= progress.deadline(idle) {
            break;
        }
        // Every complete frame in the buffer.
        while let Some(msg) = take_frame_pooled(&mut buf, &pool) {
            progress.touch();
            let permit = tokio::select! {
                p = Arc::clone(&inflight).acquire_owned() => match p { Ok(p) => p, Err(_) => break 'conn },
                _ = shutdown.changed() => break 'conn,
                _ = &mut writer, if !writer_done => {
                    writer_done = true;
                    break 'conn;
                }
            };
            let owed = Owed::new(&progress);
            let edge = Arc::clone(&edge);
            let tx = tx.clone();
            let sp = spec.load_full();
            let named = named.clone();
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                let _permit = permit;
                let out = pipeline::serve_with(
                    &edge,
                    Inbound {
                        msg: &msg,
                        client: peer,
                        listener: &sp.id,
                        udp_payload: sp.limits.udp_payload,
                        proto,
                        named_profile: named.as_deref(),
                        extension: false,
                        internal: false,
                        admitted: Admitted::Here,
                    },
                    pool.take(),
                )
                .await;
                pool.put(msg);
                // The writer settles a reply it takes; anything else settles as `owed` drops.
                if let Some(r) = out.reply
                    && tx.send(r).await.is_ok()
                {
                    owed.handed_over();
                }
            });
        }
        let quiet = progress.idle();
        let deadline = progress.deadline(idle);
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = &mut writer, if !writer_done => {
                writer_done = true;
                break;
            }
            r = rd.read_buf(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            // Idle: wait for the deadline (checked at the top of the loop).
            _ = tokio::time::sleep_until(deadline.into()), if quiet => {}
            // Queries owed replies: the deadline starts once they are settled.
            _ = progress.settled.notified(), if !quiet => {}
        }
    }
    drop(tx);
    // Replies already queued get one write timeout to leave; then the writer is cancelled, never
    // left running on its own.
    if !writer_done && tokio::time::timeout(WRITE_TIMEOUT, &mut writer).await.is_err() {
        writer.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_profile_prefix() {
        let names = vec!["dns.home.arpa".to_owned()];
        assert_eq!(
            profile_prefix("strict.dns.home.arpa", &names).as_deref(),
            Some("strict")
        );
        assert_eq!(profile_prefix("dns.home.arpa", &names), None);
        assert_eq!(profile_prefix("a.b.dns.home.arpa", &names), None);
        assert_eq!(profile_prefix("xdns.home.arpa", &names), None);
        assert_eq!(
            profile_prefix("strict.dns.home.arpa.", &names).as_deref(),
            Some("strict")
        );
    }
}
