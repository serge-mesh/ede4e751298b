//! Listeners (edge.md §5, §16; edge-unifi.md §3): the sockets the active config names, filtered by
//! `allowed_binds`, rebound at each activation while keeping the sockets of listeners whose bind
//! address and protocol didn't change.
//!
//! - `dns`: UDP (one `SO_REUSEPORT` socket per worker, `IP_PKTINFO` / `IPV6_RECVPKTINFO` so
//!   `interfaces` is exact and replies leave from the address the query arrived at) plus TCP
//!   (RFC 7766 pipelining). `dot`: TCP + TLS, with the SNI profile prefix. `doh`: TCP + TLS,
//!   hyper with h2 and http/1.1. TLS is 1.3 only; a client offering no TLS 1.3 is refused and
//!   logged as a `tls_version_refused` event, at most once an hour per listener and client
//!   ([`handshake`]).
//! - A listener `allowed_binds` doesn't allow isn't opened and logs a `listener_rejected` event; a
//!   bind that fails holds `listener_failed` (key: the listener) and is retried. Ports in use are
//!   reported this way at start (edge-unifi.md §3).
//! - **Not an open resolver** (edge.md §16): a listener binds to a LAN address, or to a wildcard
//!   (`[::]`, `0.0.0.0`) restricted by `interfaces`. A wildcard bind without `interfaces` isn't
//!   opened and holds `listener_failed` with the reason until the config changes.
//! - Once listeners are bound, `ready_version` is set (the updater's readiness signal, edge.md §14)
//!   and the watchdog switches to the internal test query (edge.md §16). That query is a loopback
//!   datagram to the first `dns` listener's UDP socket ([`ListenerManager::self_test_target`]),
//!   which its receive loop recognises by its source ([`ListenerManager::is_self_test`]) and lets
//!   through whatever `interfaces` lists. Every receive and accept loop also stamps a liveness
//!   mark ([`Live`]) five times per `listener_stale`; a mark older than that (a stalled or ended
//!   loop) fails the test too. An accept loop whose last accept failed for want of descriptors
//!   or kernel memory ([`out_of_resources`]) doesn't stamp, so lasting exhaustion, the state a
//!   restart cures, fails the test.

pub mod client_hello;
pub mod doh;
pub mod handshake;
pub mod share;
pub mod stream;
pub mod udp;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::Serialize;
use tokio::sync::{Notify, watch};

use picket_api::edge_config::ListenerProto;
use picket_api::logs::event_kind;
use picket_api::session::condition_kind;

use super::certs::CertSlot;
use super::runtime::ListenerSpec;
use crate::edge::Edge;
use crate::logs::fields;

/// A listener's state for `status`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListenerState {
    Bound,
    /// `allowed_binds` doesn't allow it.
    Rejected,
    /// The bind failed (retried).
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListenerStatus {
    pub id: String,
    pub proto: ListenerProto,
    pub bind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<Vec<SocketAddr>>,
    pub state: ListenerState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    pub api: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<serde_json::Value>,
}

/// What a listener's tasks read per query or connection: swapped in place when the config
/// changes without changing the sockets.
pub type SharedSpec = Arc<ArcSwap<ListenerSpec>>;

/// A listener task's liveness mark (edge.md §16 watchdog): its receive or accept loop stamps it
/// on a timer it selects on beside its socket ([`Live::interval`], every [`Live::tick`]); a loop
/// that stalls or ends stops stamping, its mark goes stale and the watchdog's test fails.
pub struct Live {
    base: Instant,
    last_ms: AtomicU64,
    /// How often an idle loop stamps.
    pub tick: Duration,
    /// Set by [`ListenerManager::stall_tasks_for_test`]: the loop parks at its next turn.
    stall: AtomicBool,
}

impl Live {
    /// A fresh mark for a loop that is to stamp at least every `tick`.
    pub fn new(tick: Duration) -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            last_ms: AtomicU64::new(0),
            tick: tick.max(Duration::from_millis(10)),
            stall: AtomicBool::new(false),
        })
    }

    /// Called by each loop at the top of every turn: parks for good once a test asked for a
    /// stall, so the loop stops reading and stamping while its socket stays open, as a stuck
    /// loop does (edge.md §16; tests only).
    pub async fn park_if_stalled(&self) {
        if self.stall.load(Relaxed) {
            std::future::pending::<()>().await;
        }
    }

    pub fn stamp(&self) {
        self.last_ms
            .store(picket_api::duration::as_millis_u64(self.base.elapsed()), Relaxed);
    }

    /// Time since the last stamp.
    pub fn age(&self) -> Duration {
        let now = picket_api::duration::as_millis_u64(self.base.elapsed());
        Duration::from_millis(now.saturating_sub(self.last_ms.load(Relaxed)))
    }

    /// The idle stamp timer a loop selects on.
    pub fn interval(&self) -> tokio::time::Interval {
        let mut t = tokio::time::interval(self.tick);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t
    }
}

/// Whether `e` says the process or the host ran out of descriptors or kernel memory (EMFILE,
/// ENFILE, ENOBUFS, ENOMEM): the stuck state a restart cures (edge.md §16), unlike a peer's error
/// (a connection reset before it was accepted).
pub fn out_of_resources(e: &std::io::Error) -> bool {
    use rustix::io::Errno;
    Errno::from_io_error(e)
        .is_some_and(|n| [Errno::MFILE, Errno::NFILE, Errno::NOBUFS, Errno::NOMEM].contains(&n))
}

/// Spare buffers for queries and replies, reused across a socket's or a connection's queries so
/// the serving path allocates none once warm (build-and-test.md §4). Bounded: at most `max`
/// buffers of at most [`BufPool::KEEP`] bytes each are kept.
pub struct BufPool {
    free: Mutex<Vec<Vec<u8>>>,
    max: usize,
}

impl BufPool {
    /// The largest buffer kept (a UDP reply is at most 4,096 bytes, `bounds::UDP_PAYLOAD`).
    pub const KEEP: usize = 4096;

    pub fn new(max: usize) -> Self {
        Self {
            free: Mutex::new(Vec::with_capacity(max)),
            max,
        }
    }

    /// A spare buffer, or a new one of [`Self::KEEP`] bytes.
    pub fn take(&self) -> Vec<u8> {
        self.free
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(Self::KEEP))
    }

    /// Gives a buffer back (dropped when the pool is full or the buffer grew past the limit).
    pub fn put(&self, mut b: Vec<u8>) {
        if b.capacity() > Self::KEEP || b.capacity() == 0 {
            return;
        }
        b.clear();
        let mut g = self.free.lock().unwrap_or_else(|p| p.into_inner());
        if g.len() < self.max {
            g.push(b);
        }
    }
}

struct Bound {
    spec: SharedSpec,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// One per task.
    lives: Vec<Arc<Live>>,
    local: Vec<SocketAddr>,
}

impl Drop for Bound {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub struct ListenerManager {
    status: ArcSwap<Vec<ListenerStatus>>,
    bound: tokio::sync::Mutex<HashMap<Arc<str>, Bound>>,
    pub wake: Notify,
    rejected_logged: Mutex<HashSet<(String, String)>>,
    ready_marked: AtomicBool,
    /// Every listener the config wants (and `allowed_binds` allows) is bound.
    all_bound: AtomicBool,
    /// Per-source shares of the stream listeners' connections and DoH bodies.
    pub shares: Arc<share::SourceShares>,
    /// The rate limit of `tls_version_refused` events ([`handshake`]).
    pub tls_refusals: handshake::TlsRefusals,
    /// Every bound listener task's liveness mark, by listener (read by the watchdog's test).
    lives: ArcSwap<Vec<(Arc<str>, Arc<Live>)>>,
    /// The first `dns` listener's UDP address (the watchdog's test query goes there).
    primary_udp: ArcSwap<Option<SocketAddr>>,
    /// The source port and address of the test query in flight; port 0: none. The port is read
    /// for every datagram, the address only on a match.
    self_test_port: AtomicU16,
    self_test_src: Mutex<Option<SocketAddr>>,
    /// One test query at a time.
    pub self_test_lock: tokio::sync::Mutex<()>,
}

/// Holds a test query's source registered ([`ListenerManager::mark_self_test`]).
pub struct SelfTestMark<'a>(&'a ListenerManager);

impl Drop for SelfTestMark<'_> {
    fn drop(&mut self) {
        self.0.self_test_port.store(0, Relaxed);
        *self.0.self_test_src.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

impl ListenerManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            status: ArcSwap::from_pointee(vec![]),
            bound: tokio::sync::Mutex::new(HashMap::new()),
            wake: Notify::new(),
            rejected_logged: Mutex::new(HashSet::new()),
            ready_marked: AtomicBool::new(false),
            all_bound: AtomicBool::new(false),
            shares: share::SourceShares::new(),
            tls_refusals: handshake::TlsRefusals::default(),
            lives: ArcSwap::from_pointee(Vec::new()),
            primary_udp: ArcSwap::from_pointee(None),
            self_test_port: AtomicU16::new(0),
            self_test_src: Mutex::new(None),
            self_test_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// The first listener whose receive or accept loop hasn't stamped its mark within
    /// `max_age` (edge.md §16: a stalled or ended loop).
    pub fn stale_listener(&self, max_age: Duration) -> Option<Arc<str>> {
        self.lives
            .load()
            .iter()
            .find(|(_, l)| l.age() > max_age)
            .map(|(id, _)| Arc::clone(id))
    }

    /// Where the watchdog's test query goes: the first `dns` listener's UDP address, a wildcard
    /// bind reached over IPv4 loopback (an IPv6 wildcard socket is dual-stack).
    pub fn self_test_target(&self) -> Option<SocketAddr> {
        let a = (**self.primary_udp.load())?;
        let ip = a.ip().to_canonical();
        Some(if ip.is_unspecified() {
            SocketAddr::from((Ipv4Addr::LOCALHOST, a.port()))
        } else {
            SocketAddr::new(ip, a.port())
        })
    }

    /// Registers `src` as the test query's source until the mark drops.
    pub fn mark_self_test(&self, src: SocketAddr) -> SelfTestMark<'_> {
        *self.self_test_src.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(SocketAddr::new(src.ip().to_canonical(), src.port()));
        self.self_test_port.store(src.port(), Relaxed);
        SelfTestMark(self)
    }

    /// Whether a datagram from `from` is the watchdog's test query (edge.md §16).
    pub fn is_self_test(&self, from: SocketAddr) -> bool {
        let port = self.self_test_port.load(Relaxed);
        port != 0
            && from.port() == port
            && *self.self_test_src.lock().unwrap_or_else(|p| p.into_inner())
                == Some(SocketAddr::new(from.ip().to_canonical(), port))
    }

    pub fn status(&self) -> Arc<Vec<ListenerStatus>> {
        self.status.load_full()
    }

    /// The `listeners` firmware self-check (edge-unifi.md §1): every allowed listener is bound.
    pub fn all_bound(&self) -> bool {
        self.all_bound.load(Relaxed)
    }

    /// Ends a bound listener's tasks, leaving it recorded as bound: what a crashed receive or
    /// accept loop looks like to the watchdog (its sockets close; tests, edge.md §16). Returns
    /// how many.
    #[doc(hidden)]
    pub async fn end_tasks_for_test(&self, id: &str) -> usize {
        let bound = self.bound.lock().await;
        let Some(b) = bound.get(id) else { return 0 };
        for t in &b.tasks {
            t.abort();
        }
        b.tasks.len()
    }

    /// Stalls a bound listener's tasks: each parks at its next turn holding its socket open, so
    /// datagrams and connections queue unanswered and its mark stops, as a stuck loop does
    /// (tests, edge.md §16). Returns how many.
    #[doc(hidden)]
    pub async fn stall_tasks_for_test(&self, id: &str) -> usize {
        let bound = self.bound.lock().await;
        let Some(b) = bound.get(id) else { return 0 };
        for l in &b.lives {
            l.stall.store(true, Relaxed);
        }
        b.lives.len()
    }

    /// The local addresses a listener is bound to (tests use port 0).
    pub fn local_addrs(&self, id: &str) -> Vec<SocketAddr> {
        self.status
            .load()
            .iter()
            .find(|s| s.id == id)
            .and_then(|s| s.local.clone())
            .unwrap_or_default()
    }
}

fn allowed(binds: &[String], text: &str) -> bool {
    binds.iter().any(|b| b == "*" || b == text)
}

/// Why a wildcard listener without `interfaces` isn't opened.
pub const OPEN_WILDCARD: &str = "a wildcard bind needs interfaces (edge.md §16: not an open resolver)";

/// A wildcard bind no `interfaces` restricts: it would answer every network that reaches it
/// (edge.md §16).
pub fn open_wildcard(spec: &ListenerSpec) -> bool {
    spec.interfaces.is_empty() && spec.bind.is_some_and(|a| a.ip().to_canonical().is_unspecified())
}

fn tls_status(slot: Option<&Arc<CertSlot>>) -> Option<serde_json::Value> {
    let s = slot?;
    let i = s.info();
    let mut v = serde_json::to_value(&*i).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert("has_cert".into(), s.has_cert().into());
    }
    Some(v)
}

/// The workers' count (edge.md §1: `min(ncpu, 4)`), one UDP socket each.
pub fn workers() -> usize {
    tokio::runtime::Handle::try_current()
        .map(|h| h.metrics().num_workers())
        .unwrap_or(1)
        .clamp(1, 4)
}

fn bind(
    edge: &Arc<Edge>,
    spec: &Arc<ListenerSpec>,
    addr: SocketAddr,
    slot: Option<Arc<CertSlot>>,
) -> anyhow::Result<Bound> {
    let shared: SharedSpec = Arc::new(ArcSwap::new(Arc::clone(spec)));
    let (tx, rx) = watch::channel(false);
    let mut tasks = vec![];
    let mut lives = vec![];
    let tick = edge.dns.tuning.listener_stale / 5;
    let mut live = || {
        let l = Live::new(tick);
        lives.push(Arc::clone(&l));
        l
    };
    let mut local = vec![];
    match spec.proto {
        ListenerProto::Dns => {
            // TCP on the port UDP got. With port 0 (tests, development) a port free for UDP may
            // be busy for TCP: another is tried.
            let mut tries = 0;
            let (socks, at, tcp) = loop {
                let (socks, at) = udp::bind(addr, workers())?;
                match stream::bind_tcp(at) {
                    Ok(tcp) => break (socks, at, tcp),
                    Err(_) if addr.port() == 0 && tries < 32 => tries += 1,
                    Err(e) => return Err(e),
                }
            };
            local.push(at);
            for s in socks {
                tasks.push(udp::spawn(
                    Arc::clone(edge),
                    s,
                    Arc::clone(&shared),
                    rx.clone(),
                    live(),
                )?);
            }
            tasks.push(stream::spawn_accept(
                Arc::clone(edge),
                tcp,
                Arc::clone(&shared),
                rx.clone(),
                stream::Kind::Tcp,
                live(),
            )?);
        }
        ListenerProto::Dot => {
            let slot = slot.ok_or_else(|| anyhow::anyhow!("no tls settings"))?;
            let tcp = stream::bind_tcp(addr)?;
            local.push(tcp.local_addr()?);
            let cfg = slot.server_config(&[])?;
            tasks.push(stream::spawn_accept(
                Arc::clone(edge),
                tcp,
                Arc::clone(&shared),
                rx.clone(),
                stream::Kind::Dot(cfg, slot),
                live(),
            )?);
        }
        ListenerProto::Doh => {
            let slot = slot.ok_or_else(|| anyhow::anyhow!("no tls settings"))?;
            let tcp = stream::bind_tcp(addr)?;
            local.push(tcp.local_addr()?);
            let cfg = slot.server_config(&[b"h2", b"http/1.1"])?;
            tasks.push(doh::spawn(
                Arc::clone(edge),
                tcp,
                Arc::clone(&shared),
                rx.clone(),
                cfg,
                live(),
            )?);
        }
    }
    Ok(Bound {
        spec: shared,
        shutdown: tx,
        tasks,
        lives,
        local,
    })
}

/// One reconcile pass; returns true when something is still to retry.
pub async fn reconcile(edge: &Arc<Edge>) -> bool {
    let mgr = &edge.dns.listeners;
    let active = edge.active();
    let desired: Vec<Arc<ListenerSpec>> = active
        .dns
        .as_ref()
        .map(|rt| rt.listeners.clone())
        .unwrap_or_default();
    let lanca_root = active.config.as_ref().and_then(|c| c.lanca_root.clone());
    let slots = edge.dns.certs.sync(&desired, lanca_root.as_deref());
    let binds = &edge.local.allowed_binds;
    let mut bound = mgr.bound.lock().await;
    let mut status = vec![];
    let mut retry = false;
    let mut want_ids: HashSet<Arc<str>> = HashSet::new();

    // Close what is gone or rebinds elsewhere first, so a moved listener can take its port.
    let keep: HashSet<Arc<str>> = desired
        .iter()
        .filter(|s| s.bind.is_some() && allowed(binds, &s.bind_text) && !open_wildcard(s))
        .filter(|s| bound.get(&s.id).is_some_and(|b| b.spec.load().same_sockets(s)))
        .map(|s| Arc::clone(&s.id))
        .collect();
    bound.retain(|id, _| keep.contains(id));

    for spec in &desired {
        want_ids.insert(Arc::clone(&spec.id));
        let mut st = ListenerStatus {
            id: spec.id.to_string(),
            proto: spec.proto,
            bind: spec.bind_text.clone(),
            local: None,
            state: ListenerState::Bound,
            error: None,
            interfaces: spec.interfaces.clone(),
            api: spec.api,
            tls: tls_status(slots.get(&spec.id)),
        };
        if !allowed(binds, &spec.bind_text) {
            st.state = ListenerState::Rejected;
            let key = (spec.id.to_string(), spec.bind_text.clone());
            let first = mgr
                .rejected_logged
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(key);
            if first {
                tracing::warn!(
                    "listener {} ({}) isn't in allowed_binds: not opened",
                    spec.id,
                    spec.bind_text
                );
                edge.logs.event(
                    event_kind::LISTENER_REJECTED,
                    fields(&[
                        ("listener", spec.id.to_string().into()),
                        ("bind", spec.bind_text.clone().into()),
                    ]),
                );
            }
            edge.conditions
                .clear(condition_kind::LISTENER_FAILED, Some(&spec.id));
            status.push(st);
            continue;
        }
        let Some(addr) = spec.bind else {
            st.state = ListenerState::Failed;
            st.error = Some("bind isn't ip:port".into());
            edge.conditions.set(
                condition_kind::LISTENER_FAILED,
                Some(&spec.id),
                Some("bind isn't ip:port".into()),
            );
            status.push(st);
            continue;
        };
        if open_wildcard(spec) {
            st.state = ListenerState::Failed;
            st.error = Some(OPEN_WILDCARD.into());
            tracing::warn!("listener {} ({}): {OPEN_WILDCARD}", spec.id, spec.bind_text);
            edge.conditions.set(
                condition_kind::LISTENER_FAILED,
                Some(&spec.id),
                Some(OPEN_WILDCARD.into()),
            );
            status.push(st);
            continue;
        }
        if let Some(b) = bound.get(&spec.id) {
            b.spec.store(Arc::clone(spec));
            st.local = Some(b.local.clone());
            status.push(st);
            continue;
        }
        match bind(edge, spec, addr, slots.get(&spec.id).cloned()) {
            Ok(b) => {
                st.local = Some(b.local.clone());
                bound.insert(Arc::clone(&spec.id), b);
                edge.conditions
                    .clear(condition_kind::LISTENER_FAILED, Some(&spec.id));
            }
            Err(e) => {
                let msg = crate::diag::cap_chain(&e);
                tracing::warn!("listener {} ({}): {msg}", spec.id, spec.bind_text);
                st.state = ListenerState::Failed;
                st.error = Some(msg.clone());
                edge.conditions
                    .set(condition_kind::LISTENER_FAILED, Some(&spec.id), Some(msg.into()));
                retry = true;
            }
        }
        status.push(st);
    }
    // Conditions of listeners that are gone.
    for c in edge.conditions.snapshot() {
        if c.kind == condition_kind::LISTENER_FAILED
            && let Some(k) = &c.key
            && !want_ids.iter().any(|w| &**w == k.as_str())
        {
            edge.conditions.clear(condition_kind::LISTENER_FAILED, Some(k));
        }
    }
    let n_bound = bound.len();
    let lives: Vec<(Arc<str>, Arc<Live>)> = bound
        .iter()
        .flat_map(|(id, b)| b.lives.iter().map(|l| (Arc::clone(id), Arc::clone(l))))
        .collect();
    let primary = desired
        .iter()
        .filter(|s| s.proto == ListenerProto::Dns)
        .find_map(|s| bound.get(&s.id).and_then(|b| b.local.first().copied()));
    drop(bound);
    mgr.lives.store(Arc::new(lives));
    mgr.primary_udp.store(Arc::new(primary));
    let all = !status.is_empty()
        && status
            .iter()
            .all(|s| matches!(s.state, ListenerState::Bound | ListenerState::Rejected))
        && n_bound > 0;
    mgr.all_bound.store(all, Relaxed);
    mgr.status.store(Arc::new(status));
    if n_bound > 0 {
        // The watchdog follows the pipeline from the moment anything is bound, before
        // `ready_version` says so (anything seeing it ready sees the pipeline watched).
        if !edge.watchdog.in_pipeline_mode() {
            edge.watchdog.use_pipeline();
        }
        if !mgr.ready_marked.swap(true, Relaxed)
            && let Err(e) = edge
                .state
                .update_async(|s| s.ready_version = Some(picket_api::VERSION.to_owned()))
                .await
        {
            mgr.ready_marked.store(false, Relaxed);
            tracing::warn!("writing ready_version: {}", crate::diag::cap_chain(&e));
            retry = true;
        }
    } else if edge.watchdog.in_pipeline_mode() {
        edge.watchdog.use_tick();
    }
    retry
}

/// The listener task: reconciles at each activation, and retries failed binds.
pub async fn run(edge: Arc<Edge>) -> anyhow::Result<()> {
    let every = edge.dns.tuning.rebind_every;
    loop {
        let retry = reconcile(&edge).await;
        let wait = if retry { every } else { Duration::from_secs(3600) };
        tokio::select! {
            _ = edge.dns.listeners.wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}
