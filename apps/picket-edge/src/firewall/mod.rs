//! The firewall client (edge.md §9, edge-firewall.md §3–§5): the shadow map, and two connections to
//! picket-edge-helper over its Unix socket, each with at most one request in flight: **fast** for
//! `ensure` and `delete` only, **control** for `hello`, `apply`, `dump`, `status` and events.
//!
//! - **Ensure** ([`FwHook`], the data path's [`FirewallEnsure`]): per answer address,
//!   `fw_timeout = client_ttl + grace_s`. A key the shadow map holds until at least
//!   `desired − hysteresis` needs nothing; an absent or expired one is sent and its ack awaited
//!   (≤ `ack_wait_ms`, then `fw_ack_late`); one near expiry is refreshed fire-and-forget. Only ever
//!   extend: an `ensure` goes out only when the new expiry is later than the current one. An
//!   answer finding the key's `ensure` already out waits on that ack, and a longer expiry it wants
//!   follows as an extension once the ack lands.
//!   `per_client_ip` keys are expanded across every address the client's MAC holds in the
//!   answer's family; `global` keys are the answer IP alone. Each client may hold at most a
//!   quarter of a set, keys whose `ensure` is still out included; over its share, or with the
//!   set full, the profile's `on_full` applies.
//! - **Batching:** with nothing in flight an op goes out at once; ops arriving meanwhile are
//!   coalesced (≤ 64, same kind, in order) into the next message.
//! - **Order:** an op that carries the shadow map's state goes into the fast queue while the map's
//!   lock is held, so the helper applies the ops for a key in the order the map changed and an
//!   older expiry never lands after a newer one. One the full queue refuses is failed (its key
//!   left unconfirmed) only after the lock is released.
//! - **Every op completes in one place** (the fast task): an acked `ensure` from an answer goes
//!   into the shadow map there, so an answer dropped while it waits (a DoH stream reset) still
//!   leaves its key recorded and nothing stuck in flight. A key whose `ensure` failed (or whose
//!   set was recreated) is **unconfirmed**: answers treat it as absent, send `ensure` and wait,
//!   until one is acked. Nothing is taken into the shadow map before its ack.
//! - **Bulk re-sends** (a recreated set, the reconcile) go out with backpressure, a chunk at a
//!   time, so they never overflow the fast queue; each key is confirmed by its own ack. Each
//!   chunk is built from the map as it is when it goes out: an `ensure` takes the key's current
//!   expiry (and is skipped for a key revoked or lapsed since), a `delete` is skipped for a key
//!   live again or with an answer's `ensure` out.
//! - **Startup** (edge-firewall.md §5): `hello` on both connections (protocol version checked:
//!   no `ensure` goes out on a connection that hasn't passed it; a mismatch on the control
//!   connection makes the edge refuse to run, §4), then a paged `dump` of
//!   the four timed sets seeds the shadow map (each expiry capped at now + the largest
//!   `ttl.max + grace_s`), then, once the clock is synchronised, active IP allows from
//!   `allows.json` are re-sent where the kernel lacks them or holds them for less, then a
//!   reconcile. `apply` goes out once a config is active, and again after every reconnect.
//! - **Reconcile** every 10 minutes, and after every reconnect (ops may have failed, and a
//!   `rules_repaired` sent meanwhile is lost): missing or shorter kernel entries are ensured,
//!   unknown ones deleted (never adopted), longer ones ensured with the shadow map's expiry; keys
//!   changed after the dump began and differences within 5 s either way don't count (an entry the
//!   shadow map let lapse up to 5 s ago isn't unknown, nor one it holds for under 5 s more
//!   missing; pruning keeps a lapsed entry that long). Seeded entries count as unchanged, so the
//!   reconcile right after seeding trims entries over the cap. Any finding holds `fw_drift`.
//! - **Events:** `conditions` become the edge's conditions of the same names; `set_full` holds
//!   `fw_set_full`; `rules_repaired` re-sends every live key of each recreated set, each counting
//!   as absent until its own re-send is acked (and is logged as a `rules_repaired` event).
//! - **Address moves** (edge-firewall.md §1, edge.md §12): an address that moves to another MAC
//!   loses the old device's DNS grants and IP allows (the stored allow stops listing it) before
//!   the new owner's grants are backfilled, within its share and the set's room.
//! - **No helper:** a config with no firewall interfaces and no `unifi.redirect` runs without the
//!   helper: no connection, entries, seeding, reconcile or helper conditions. It replaces a config
//!   that used the helper only once the helper acks an `apply` with no interfaces.
//! - **Helper unreachable:** answers go out after `ack_wait_ms` (new IPs then hit the firewall,
//!   failing closed) and `helper_unreachable` holds while the helper can't be reached.

pub mod conn;
pub mod shadow;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use ipnet::IpNet;
use tokio::sync::{Notify, mpsc, oneshot, watch};

use picket_api::edge_config::{EdgeConfig, FwGranularity, FwMode, ListenerProto, OnFull};
use picket_api::helper::{
    ApplyRequest, ApplyResponse, Conditions as HelperConditions, DeleteRequest, DumpRequest, DumpResponse,
    EnsureRequest, EnsureResponse, Frame, HelloRequest, HelloResponse, InterfaceMode, MAX_DUMP_LIMIT,
    MAX_TIMEOUT_S, PROTO_VERSION, RedirectCheck, RulesRepaired, SetFull, StatusResponse, error_code, kind,
    sets,
};
use picket_api::logs::event_kind;
use picket_api::session::{FwStats, condition_kind};
use picket_api::time::Timestamp;

use crate::allows::AllowsStore;
use crate::clock::Clock;
use crate::conditions::{Conditions, Source};
use crate::dns::interfaces::Interfaces;
use crate::dns::{FirewallEnsure, FwOutcome, FwRequest};
use crate::edge::Edge;
use crate::hooks::{HelperProbe, HelperSeed, HelperSnapshot, SelfCheck};
use crate::logs::{LogProducer, fields};
use crate::neighbours::{Mac, NeighbourEvent, Neighbours};
use conn::{Conn, ConnError};
use shadow::{FwKey, SetId, Shadow, owner_of};

/// Most ops coalesced into one `ensure` or `delete` (edge-firewall.md §3 "Batching").
pub const BATCH: usize = 64;
/// Ops queued for the fast connection (README §2 Bounded).
pub const QUEUE: usize = 16_384;
/// A client's share of a set: a quarter of `maxelem` (edge-firewall.md §2 "Share per client").
pub const SHARE: u32 = sets::MAXELEM / 4;
/// `fw_set_full` at 80 % of a set; cleared below 75 %.
const FULL_AT: f64 = 0.8;
const FULL_CLEAR: f64 = 0.75;
/// Expiry differences the reconcile ignores.
const RECONCILE_SLACK: u64 = 5;
/// Bulk re-sends (a recreated set, the reconcile) go out this many ops at a time, each chunk
/// acked before the next, leaving the fast queue to answers.
const RESEND_CHUNK: usize = 1024;

/// The helper conditions the edge forwards (edge-firewall.md §4).
pub const HELPER_KINDS: [&str; 5] = [
    condition_kind::REDIRECT_MISSING,
    condition_kind::UNIFI_CONFLICT,
    condition_kind::FW_LAYOUT_UNKNOWN,
    condition_kind::FW_CATCH_ALL,
    condition_kind::HELPER_DISABLED,
];

/// Knobs tests shorten.
#[derive(Clone, Debug)]
pub struct FwTuning {
    pub socket: PathBuf,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// An `apply` may wait for the xtables lock (5 s per step, twice per family) and the
    /// helper's own engine timeout.
    pub apply_timeout: Duration,
    pub reconnect: (Duration, Duration),
    pub reconcile_every: Duration,
    /// How long the helper may be unreachable before `helper_unreachable`.
    pub unreachable_after: Duration,
    /// How long a config waits for the shadow map's seeding before going live anyway.
    pub seed_wait: Duration,
    /// An IP allow's wait for the helper's ack (edge.md §12: ≤ 2 s).
    pub allow_ack: Duration,
}

impl Default for FwTuning {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(picket_api::helper::DEFAULT_SOCKET),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(10),
            apply_timeout: Duration::from_secs(130),
            reconnect: (Duration::from_millis(500), Duration::from_secs(10)),
            reconcile_every: Duration::from_secs(600),
            unreachable_after: Duration::from_secs(5),
            seed_wait: Duration::from_secs(5),
            allow_ack: Duration::from_secs(2),
        }
    }
}

/// What the active config asks of the firewall.
#[derive(Clone, Debug, Default)]
pub struct View {
    pub needed: bool,
    pub apply: ApplyRequest,
    pub modes: HashMap<String, FwMode>,
    pub exempt: Vec<IpNet>,
    pub static_allow: Vec<IpNet>,
    /// The largest `ttl.max + grace_s` among the profiles: the cap on dumped expiries.
    pub cap_s: u64,
    /// The config is active (apply goes out).
    pub active: bool,
    pub redirect: bool,
    /// `firewall.ack_wait_ms`.
    pub ack_wait_ms: u32,
}

fn parse_nets(v: &[String]) -> Vec<IpNet> {
    v.iter()
        .take(4096)
        .filter_map(|s| crate::dns::profiles::parse_range(s))
        .collect()
}

impl View {
    pub fn of(cfg: &EdgeConfig) -> View {
        let redirect = cfg.unifi.redirect.as_ref().map(|r| {
            // The `dns` listener covering the redirect interfaces gives the port (edge-firewall.md §4).
            let port = cfg
                .listeners
                .iter()
                .filter(|l| l.proto == ListenerProto::Dns)
                .filter(|l| l.interfaces.is_empty() || r.interfaces.iter().all(|i| l.interfaces.contains(i)))
                .find_map(|l| l.bind.parse::<std::net::SocketAddr>().ok().map(|a| a.port()))
                .unwrap_or(53);
            RedirectCheck {
                interfaces: r.interfaces.clone(),
                port,
                ipv6: r.ipv6,
            }
        });
        let cap_s = cfg
            .profiles
            .values()
            .map(|p| u64::from(p.ttl.max.max(p.ttl.min)) + u64::from(p.firewall.grace_s))
            .max()
            .unwrap_or(300 + 120);
        View {
            needed: cfg.needs_helper(),
            redirect: redirect.is_some(),
            apply: ApplyRequest {
                interfaces: cfg
                    .firewall
                    .interfaces
                    .iter()
                    .map(|i| InterfaceMode {
                        name: i.name.clone(),
                        mode: i.mode,
                    })
                    .collect(),
                static_allow: cfg.firewall.static_allow.clone(),
                exempt: cfg.firewall.exempt_sources.clone(),
                redirect,
            },
            modes: cfg
                .firewall
                .interfaces
                .iter()
                .map(|i| (i.name.clone(), i.mode))
                .collect(),
            exempt: parse_nets(&cfg.firewall.exempt_sources),
            static_allow: parse_nets(&cfg.firewall.static_allow),
            cap_s,
            active: false,
            ack_wait_ms: cfg.firewall.ack_wait_ms,
        }
    }
}

/// The helper's last report.
#[derive(Clone, Debug, Default)]
pub struct HelperState {
    pub connected: bool,
    pub rules_ok: bool,
    pub conditions: HelperConditions,
    pub pid: Option<u32>,
    pub helper_version: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpKind {
    Ensure,
    Delete,
}

/// An op's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpResult {
    Ok,
    Failed(String),
    Unreachable,
}

struct Op {
    kind: OpKind,
    key: FwKey,
    timeout_s: u32,
    /// An answer's `ensure`: the entry the shadow map takes once it is acked, and its in-flight
    /// slot ends with it.
    record: Option<Record>,
    reply: Option<oneshot::Sender<OpResult>>,
}

/// What an answer's `ensure` records once acked.
#[derive(Clone, Copy, Debug)]
struct Record {
    dns_exp: u64,
    owner: u64,
    /// The expiry the `ensure` carries (seconds, monotonic).
    sent_exp: u64,
    /// The key counts against `owner`'s share and the set's room until settled
    /// ([`Shadow::reserve`]).
    reserved: bool,
}

/// An answer's `ensure` on its way: later answers for the key wait on the same ack.
struct Flight {
    tx: watch::Sender<Option<OpResult>>,
    /// The latest DNS expiry an answer waiting on it wants: the entry gets it once the ack lands
    /// (an extension follows when the `ensure` carried less; edge-firewall.md §3).
    want: u64,
}

/// Ops queued while the shadow map's lock is held, so their order in the fast queue follows the
/// map's changes (edge-firewall.md §3 "only ever extend": an older expiry never lands after a
/// newer one). An op the full queue refuses is failed by [`Outbox::finish`], after the lock is
/// released: completing an op takes that lock.
struct Outbox<'a> {
    c: &'a FwClient,
    failed: Vec<Op>,
}

impl<'a> Outbox<'a> {
    fn new(c: &'a FwClient) -> Self {
        Self {
            c,
            failed: Vec::new(),
        }
    }

    fn push(&mut self, op: Op) {
        if let Err(e) = self.c.fast_tx.try_send(op) {
            self.c.dropped_ops.fetch_add(1, Relaxed);
            self.failed.push(match e {
                mpsc::error::TrySendError::Full(o) | mpsc::error::TrySendError::Closed(o) => o,
            });
        }
    }

    fn ensure(&mut self, key: FwKey, secs: u64) {
        let t = timeout_s(secs);
        self.push(FwClient::op(OpKind::Ensure, key, t, None));
    }

    fn delete(&mut self, key: FwKey) {
        self.push(FwClient::op(OpKind::Delete, key, 1, None));
    }

    /// Fails what the queue refused (call with the shadow lock released).
    fn finish(self) {
        for op in self.failed {
            self.c.complete(op, &OpResult::Unreachable);
        }
    }
}

type CtlReply = oneshot::Sender<Result<serde_json::Value, ConnError>>;

struct CtlReq {
    kind: &'static str,
    data: serde_json::Value,
    timeout: Duration,
    reply: CtlReply,
}

/// The firewall client.
pub struct FwClient {
    pub tuning: FwTuning,
    base: Instant,
    shadow: Mutex<Shadow>,
    /// Keys an answer's `ensure` is out for: later answers wait on the same ack. Locked after
    /// the shadow map when both are held.
    inflight: Mutex<HashMap<FwKey, Flight>>,
    view: ArcSwap<View>,
    needed: AtomicBool,
    wake: Notify,
    fast_tx: mpsc::Sender<Op>,
    fast_rx: Mutex<Option<mpsc::Receiver<Op>>>,
    ctl_tx: mpsc::Sender<CtlReq>,
    ctl_rx: Mutex<Option<mpsc::Receiver<CtlReq>>>,
    pub state: ArcSwap<HelperState>,
    rejects: AtomicU64,
    mon_rejects: AtomicU64,
    seeded: AtomicBool,
    seed_done: Notify,
    reconcile_now: Notify,
    apply_now: Notify,
    /// When the helper became unreachable (while needed), ms since `base`; 0: reachable.
    down_since: AtomicU64,
    full_event: Mutex<HashMap<SetId, Instant>>,
    addr_owner: Mutex<HashMap<IpAddr, Mac>>,
    neighbours: Arc<Neighbours>,
    interfaces: Arc<Interfaces>,
    conditions: Arc<Conditions>,
    logs: LogProducer,
    clock: Arc<Clock>,
    allows: Arc<AllowsStore>,
    dropped_ops: AtomicU64,
    /// The helper speaks another protocol (edge-firewall.md §4): nothing goes to it.
    mismatch: AtomicBool,
}

impl FwClient {
    pub fn new(
        tuning: FwTuning,
        neighbours: Arc<Neighbours>,
        interfaces: Arc<Interfaces>,
        conditions: Arc<Conditions>,
        logs: LogProducer,
        clock: Arc<Clock>,
        allows: Arc<AllowsStore>,
    ) -> Arc<Self> {
        let (ftx, frx) = mpsc::channel(QUEUE);
        let (ctx, crx) = mpsc::channel(64);
        Arc::new(Self {
            tuning,
            base: Instant::now(),
            shadow: Mutex::new(Shadow::default()),
            inflight: Mutex::new(HashMap::new()),
            view: ArcSwap::from_pointee(View::default()),
            needed: AtomicBool::new(false),
            wake: Notify::new(),
            fast_tx: ftx,
            fast_rx: Mutex::new(Some(frx)),
            ctl_tx: ctx,
            ctl_rx: Mutex::new(Some(crx)),
            state: ArcSwap::from_pointee(HelperState::default()),
            rejects: AtomicU64::new(0),
            mon_rejects: AtomicU64::new(0),
            seeded: AtomicBool::new(false),
            seed_done: Notify::new(),
            reconcile_now: Notify::new(),
            apply_now: Notify::new(),
            down_since: AtomicU64::new(0),
            full_event: Mutex::new(HashMap::new()),
            addr_owner: Mutex::new(HashMap::new()),
            neighbours,
            interfaces,
            conditions,
            logs,
            clock,
            allows,
            dropped_ops: AtomicU64::new(0),
            mismatch: AtomicBool::new(false),
        })
    }

    /// Seconds since start on the monotonic clock, from 1 (a seeded entry's `changed` of 0 is
    /// before any reconcile).
    pub fn now_s(&self) -> u64 {
        self.base.elapsed().as_secs() + 1
    }

    fn ms(&self) -> u64 {
        picket_api::duration::as_millis_u64(self.base.elapsed())
    }

    fn shadow(&self) -> std::sync::MutexGuard<'_, Shadow> {
        self.shadow.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn inflight(&self) -> std::sync::MutexGuard<'_, HashMap<FwKey, Flight>> {
        self.inflight.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether the running config needs the helper.
    pub fn needed(&self) -> bool {
        self.needed.load(Relaxed)
    }

    pub fn view(&self) -> Arc<View> {
        self.view.load_full()
    }

    /// The shadow map's live expiry for `k`, if any (tests, the extension's PTR probe).
    pub fn live_exp(&self, k: &FwKey) -> Option<u64> {
        let now = self.now_s();
        self.shadow().live(k, now).map(|e| e.exp())
    }

    /// Live keys in the shadow map (tests, `status`).
    pub fn live_count(&self) -> usize {
        let now = self.now_s();
        self.shadow().map.values().filter(|e| e.exp() > now).count()
    }

    /// Live keys the kernel may lack (tests).
    pub fn unconfirmed_count(&self) -> usize {
        let now = self.now_s();
        self.shadow()
            .map
            .values()
            .filter(|e| e.exp() > now && e.unconfirmed)
            .count()
    }

    fn set_needed(&self, on: bool) {
        if self.needed.swap(on, Relaxed) != on {
            if !on {
                self.down_since.store(0, Relaxed);
                self.conditions.clear(condition_kind::HELPER_UNREACHABLE, None);
                self.conditions.sync_kinds(Source::Helper, &HELPER_KINDS, &[]);
                for s in SetId::ALL {
                    self.conditions.clear(condition_kind::FW_SET_FULL, Some(s.name()));
                }
                self.conditions.clear(condition_kind::FW_DRIFT, None);
            }
            self.wake.notify_waiters();
        }
    }

    // ------------------------------------------------------------------------------------------
    // Config and startup

    /// Before a config goes live (edge.md §3 step 2, §9).
    pub async fn prepare(&self, cfg: &EdgeConfig) -> Result<(), String> {
        if cfg.needs_helper() {
            // The running config's rules stay in force (and are what a reconnect re-applies)
            // until this one is active; with none running, this config's view serves seeding.
            if !self.view.load().active || !self.needed() {
                self.view.store(Arc::new(View::of(cfg)));
            }
            self.set_needed(true);
            self.wait_seeded().await;
            return Ok(());
        }
        if !self.needed() {
            self.view.store(Arc::new(View::of(cfg)));
            return Ok(());
        }
        // From a helper config to one without: the helper must ack an `apply` with no
        // interfaces first (edge.md §9), so no jump is left behind.
        let empty = ApplyRequest::default();
        match self
            .control(
                kind::APPLY,
                serde_json::to_value(&empty).unwrap_or_default(),
                self.tuning.apply_timeout,
            )
            .await
        {
            Ok(v) => {
                let r: ApplyResponse = serde_json::from_value(v).unwrap_or_default();
                if !r.ok {
                    return Err("the helper didn't take the apply with no interfaces".into());
                }
                self.view.store(Arc::new(View::of(cfg)));
                self.set_needed(false);
                Ok(())
            }
            Err(e) => Err(format!("removing the firewall rules first: {e}")),
        }
    }

    /// Once a config is active: its rules go to the helper (`apply`), now and after reconnects.
    pub fn config_active(&self, cfg: &EdgeConfig) {
        let mut v = View::of(cfg);
        v.active = true;
        let needed = v.needed;
        self.view.store(Arc::new(v));
        self.set_needed(needed);
        if needed {
            self.apply_now.notify_one();
        }
    }

    async fn wait_seeded(&self) {
        if self.seeded.load(Relaxed) {
            return;
        }
        let n = self.seed_done.notified();
        tokio::pin!(n);
        n.as_mut().enable();
        if self.seeded.load(Relaxed) {
            return;
        }
        let _ = tokio::time::timeout(self.tuning.seed_wait, n).await;
    }

    // ------------------------------------------------------------------------------------------
    // Control requests

    async fn control(
        &self,
        kind_: &'static str,
        data: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, ConnError> {
        if !self.needed() && kind_ != kind::APPLY {
            return Err(ConnError::Io("no helper in use".into()));
        }
        let (tx, rx) = oneshot::channel();
        self.ctl_tx
            .try_send(CtlReq {
                kind: kind_,
                data,
                timeout,
                reply: tx,
            })
            .map_err(|_| ConnError::Io("control queue full".into()))?;
        match tokio::time::timeout(timeout + self.tuning.connect_timeout, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(ConnError::Io("control connection dropped the request".into())),
            Err(_) => Err(ConnError::Io(format!("no response to {kind_} in time"))),
        }
    }

    // ------------------------------------------------------------------------------------------
    // Ops

    fn op(kind_: OpKind, key: FwKey, timeout_s: u32, reply: Option<oneshot::Sender<OpResult>>) -> Op {
        Op {
            kind: kind_,
            key,
            timeout_s: timeout_s.clamp(1, MAX_TIMEOUT_S),
            record: None,
            reply,
        }
    }

    /// An op's outcome, wherever it ends (acked, refused, the helper unreachable, the queue
    /// full): an acked `ensure` confirms its key (and records an answer's entry, extended to the
    /// longest expiry the answers waiting on it want), a failed one leaves the key unconfirmed;
    /// an answer's in-flight slot and share reservation end with its result. Never call it with
    /// the shadow map's lock held.
    fn complete(&self, op: Op, res: &OpResult) {
        if op.kind == OpKind::Ensure {
            let now = self.now_s();
            let mut sh = self.shadow();
            let flight = match op.record {
                Some(_) => self.inflight().remove(&op.key),
                None => None,
            };
            if let Some(r) = op.record
                && r.reserved
            {
                sh.release(r.owner, op.key.set);
            }
            let mut confirmed = *res == OpResult::Ok;
            if confirmed && let Some(r) = op.record {
                let want = flight.as_ref().map_or(r.dns_exp, |f| f.want.max(r.dns_exp));
                sh.upsert(op.key, want, None, r.owner, now);
                if want > r.sent_exp {
                    // A later answer wants the key longer than this `ensure` carried
                    // (edge-firewall.md §3): the extension follows it, queued under the lock so
                    // it stays in order. Without room the key is left unconfirmed: the next
                    // answer sends it again and waits.
                    let t = timeout_s(want.saturating_sub(now).max(1));
                    if self
                        .fast_tx
                        .try_send(Self::op(OpKind::Ensure, op.key, t, None))
                        .is_err()
                    {
                        self.dropped_ops.fetch_add(1, Relaxed);
                        confirmed = false;
                    }
                }
            }
            if confirmed {
                sh.confirm(&op.key);
            } else {
                sh.unconfirm(&op.key);
            }
            drop(sh);
            if let Some(f) = flight {
                f.tx.send_replace(Some(res.clone()));
            }
        }
        if let Some(r) = op.reply {
            let _ = r.send(res.clone());
        }
    }

    /// Waits until `deadline` for each reply (`None`: no ack in time).
    async fn wait_acks(
        rxs: Vec<oneshot::Receiver<OpResult>>,
        deadline: tokio::time::Instant,
    ) -> Vec<Option<OpResult>> {
        let mut out = Vec::with_capacity(rxs.len());
        for rx in rxs {
            match tokio::time::timeout_at(deadline, rx).await {
                Ok(Ok(r)) => out.push(Some(r)),
                Ok(Err(_)) => out.push(Some(OpResult::Unreachable)),
                Err(_) => out.push(None),
            }
        }
        out
    }

    /// Sends many ops with backpressure, [`RESEND_CHUNK`] at a time, each chunk's acks awaited
    /// before the next goes out (a recreated set, the reconcile): bounded in the queue, and each
    /// key confirmed by its own ack. Each chunk is built from the shadow map as it is when it
    /// goes out, under its lock (edge-firewall.md §3 "Set being refilled", "Reconcile"): an
    /// `ensure` carries the key's current expiry and is skipped when the key was revoked or
    /// lapsed since, so a later chunk never shortens what an answer extended or reopens what a
    /// revoke closed; a `delete` is skipped when the key is live again or an answer's `ensure`
    /// for it is out. Returns the ops sent that weren't acked.
    async fn send_bulk(&self, ops: Vec<(OpKind, FwKey)>) -> usize {
        let mut failed = 0usize;
        for chunk in ops.chunks(RESEND_CHUNK) {
            let Ok(permits) = self.fast_tx.reserve_many(chunk.len()).await else {
                return failed + chunk.len();
            };
            let mut rxs = Vec::with_capacity(chunk.len());
            {
                let now = self.now_s();
                let sh = self.shadow();
                let inf = self.inflight();
                for (&(kind_, key), permit) in chunk.iter().zip(permits) {
                    let t = match kind_ {
                        OpKind::Ensure => match sh.live(&key, now) {
                            Some(e) => timeout_s((e.exp() - now).max(1)),
                            None => continue,
                        },
                        OpKind::Delete => {
                            if sh.live(&key, now).is_some() || inf.contains_key(&key) {
                                continue;
                            }
                            1
                        }
                    };
                    let (tx, rx) = oneshot::channel();
                    permit.send(Self::op(kind_, key, t, Some(tx)));
                    rxs.push(rx);
                }
            }
            for rx in rxs {
                if !matches!(rx.await, Ok(OpResult::Ok)) {
                    failed += 1;
                }
            }
        }
        failed
    }

    /// The device's addresses in `ip`'s family for a `per_client_ip` key: every address its MAC
    /// holds, else the client address alone (a client behind another L3 hop).
    fn expand(&self, client: IpAddr, device: &crate::dns::profiles::DeviceKey, v4: bool) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = Vec::new();
        if let crate::dns::profiles::DeviceKey::Mac(m) = device {
            out.extend(
                self.neighbours
                    .addresses_of(m)
                    .into_iter()
                    .filter(|a| a.is_ipv4() == v4),
            );
        }
        let c = client.to_canonical();
        if c.is_ipv4() == v4 && !out.contains(&c) {
            out.push(c);
        }
        out
    }

    /// The ensure point (edge-firewall.md §3).
    pub async fn ensure(&self, req: &FwRequest<'_>) -> FwOutcome {
        let mut out = FwOutcome::default();
        if !self.needed() || !req.firewall.add_entries {
            return out;
        }
        let now = self.now_s();
        let grace = u64::from(req.firewall.grace_s);
        let owner = req.device.with_text(owner_of);
        let mac = match req.device {
            crate::dns::profiles::DeviceKey::Mac(m) => Some(*m),
            _ => None,
        };
        // Keys this answer sends: their in-flight slots' receivers.
        let mut mine: Vec<watch::Receiver<Option<OpResult>>> = Vec::new();
        // Keys another answer's `ensure` is out for.
        let mut waits: Vec<watch::Receiver<Option<OpResult>>> = Vec::new();
        let mut full = false;
        // Each op completes in the fast task whatever happens to this answer (edge-firewall.md
        // §3): its ack records the entry, so a dropped answer leaves nothing stuck in flight.
        let mut q = Outbox::new(self);
        {
            let mut sh = self.shadow();
            let mut inf = self.inflight();
            for a in req.addrs {
                let ip = a.ip.to_canonical();
                if ip.is_unspecified() || ip.is_multicast() {
                    continue;
                }
                let v4 = ip.is_ipv4();
                let fw_timeout = u64::from(a.client_ttl) + grace;
                let desired = now + fw_timeout;
                let hyst = grace.min(60u64.max(fw_timeout / 4));
                let keys: Vec<FwKey> = match req.firewall.granularity {
                    FwGranularity::PerClientIp => self
                        .expand(req.client, req.device, v4)
                        .into_iter()
                        .map(|src| FwKey {
                            set: SetId::pair(v4),
                            src: Some(src),
                            dst: ip,
                        })
                        .collect(),
                    FwGranularity::Global => vec![FwKey {
                        set: SetId::global(v4),
                        src: None,
                        dst: ip,
                    }],
                };
                // The grant follows only entries the device may hold (its share, the set's room).
                let mut granted = false;
                for k in keys {
                    let cur = sh.live(&k, now).copied();
                    match cur {
                        Some(e) if !e.unconfirmed => {
                            granted = true;
                            if e.dns_exp + hyst >= desired {
                                continue;
                            }
                            sh.upsert(k, desired, None, e.owner, now);
                            if desired > e.exp() {
                                // The refresh, fire-and-forget.
                                q.ensure(k, desired - now);
                            }
                        }
                        _ => {
                            if let Some(f) = inf.get_mut(&k) {
                                // Its ack confirms the key for this answer too; a longer expiry
                                // follows once it lands ([`Self::complete`]).
                                f.want = f.want.max(desired);
                                waits.push(f.tx.subscribe());
                                granted = true;
                                continue;
                            }
                            // A live (unconfirmed) key is counted already; a new one must fit,
                            // keys still waiting for their ack included.
                            let fresh = cur.is_none();
                            if fresh && !sh.room(owner, k.set, 1) {
                                full = true;
                                continue;
                            }
                            granted = true;
                            // Never shorten: an unconfirmed key keeps any longer expiry (an IP
                            // allow) in the timeout it is sent with.
                            let exp = desired.max(cur.map_or(0, |e| e.exp()));
                            let t = timeout_s(exp.saturating_sub(now));
                            let (tx, rx) = watch::channel(None);
                            inf.insert(k, Flight { tx, want: desired });
                            let rec_owner = cur.map_or(owner, |e| e.owner);
                            if fresh {
                                sh.reserve(rec_owner, k.set);
                            }
                            let mut op = Self::op(OpKind::Ensure, k, t, None);
                            op.record = Some(Record {
                                dns_exp: desired,
                                owner: rec_owner,
                                sent_exp: exp,
                                reserved: fresh,
                            });
                            q.push(op);
                            mine.push(rx);
                        }
                    }
                }
                if granted && let (Some(m), FwGranularity::PerClientIp) = (mac, req.firewall.granularity) {
                    sh.grant(m, SetId::pair(v4), ip, desired);
                }
            }
        }
        q.finish();
        if !mine.is_empty() || !waits.is_empty() {
            let wait = Duration::from_millis(u64::from(self.view.load().ack_wait()));
            let deadline = tokio::time::Instant::now() + wait;
            let n_mine = mine.len();
            for (i, mut rx) in mine.into_iter().chain(waits).enumerate() {
                match tokio::time::timeout_at(deadline, rx.wait_for(|v| v.is_some())).await {
                    Ok(Ok(v)) => match v.clone() {
                        Some(OpResult::Ok) => {
                            if i < n_mine {
                                out.added += 1;
                            }
                        }
                        Some(OpResult::Failed(reason)) => {
                            if reason == "set_full" {
                                full = true;
                            }
                        }
                        Some(OpResult::Unreachable) | None => out.late = true,
                    },
                    // No ack in time: reply anyway (`fw_ack_late`); the entry is recorded when
                    // the ack comes, never before.
                    Ok(Err(_)) | Err(_) => out.late = true,
                }
            }
        }
        if full && req.firewall.on_full == OnFull::Servfail {
            out.servfail = true;
        }
        out
    }

    // ------------------------------------------------------------------------------------------
    // Temporary IP allows (edge.md §12)

    /// Whether `ip` counts as blocked for `client` (edge.md §12 "IP allow"): its interface is in
    /// `enforce`, it isn't exempt, the IP isn't in `static_allow`, and the shadow map has neither a
    /// (client, IP) nor a global entry for it.
    pub fn ip_blocked(&self, client: IpAddr, ip: IpAddr) -> bool {
        let v = self.view.load();
        if !v.needed || v.modes.is_empty() {
            return false;
        }
        let client = client.to_canonical();
        let ip = ip.to_canonical();
        let enforce = match self.interfaces.interface_for_client(client) {
            Some(name) => v.modes.get(&*name) == Some(&FwMode::Enforce),
            // Unknown interface: Picket's view assumes the check applies when any protected
            // interface enforces (an allow for an IP that wasn't blocked only adds an entry).
            None => v.modes.values().any(|m| *m == FwMode::Enforce),
        };
        if !enforce
            || v.exempt.iter().any(|n| n.contains(&client))
            || v.static_allow.iter().any(|n| n.contains(&ip))
        {
            return false;
        }
        let now = self.now_s();
        let v4 = ip.is_ipv4();
        let sh = self.shadow();
        let pair = FwKey {
            set: SetId::pair(v4),
            src: Some(client),
            dst: ip,
        };
        let global = FwKey {
            set: SetId::global(v4),
            src: None,
            dst: ip,
        };
        sh.live(&pair, now).is_none() && sh.live(&global, now).is_none()
    }

    /// Grants an IP allow: a per-client pair in `picket4`/`picket6` for each of `addrs` in `ip`'s
    /// family, whatever the profiles' granularity, with `allow_exp = now + secs`, waiting for the
    /// helper's ack (≤ 2 s). All or nothing (api.md §6, edge.md §12): on failure every key it
    /// touched gets its previous allow expiry back, in the shadow map and in the kernel (an
    /// `ensure` with the expiry that results, or a `delete` once that has passed, queued after
    /// this request's own, so a late ack can't leave the kernel extended), and the error is
    /// returned. Returns the keys (for a later revoke or re-time).
    pub async fn grant_allow(
        &self,
        owner_text: &str,
        addrs: &[IpAddr],
        ip: IpAddr,
        secs: u64,
    ) -> Result<Vec<FwKey>, String> {
        if !self.needed() {
            return Err("the firewall isn't in use".into());
        }
        let ip = ip.to_canonical();
        let v4 = ip.is_ipv4();
        let keys: Vec<FwKey> = addrs
            .iter()
            .map(|a| a.to_canonical())
            .filter(|a| a.is_ipv4() == v4)
            .map(|a| FwKey {
                set: SetId::pair(v4),
                src: Some(a),
                dst: ip,
            })
            .collect();
        if keys.is_empty() {
            return Err("the device has no address in the IP's family".into());
        }
        // A grant can precede the maintenance subscriber's first poll. Remember its
        // known MAC so startup catch-up can recognise a later move, even if the first
        // Gained event was missed. Never overwrite ownership already learned by a watch.
        if let Some(mac) = crate::neighbours::parse_mac(owner_text) {
            let mut owners = self.addr_owner.lock().unwrap_or_else(|p| p.into_inner());
            for key in &keys {
                if let Some(ip) = key.src {
                    owners.entry(ip).or_insert(mac);
                }
            }
        }
        let now = self.now_s();
        let allow_exp = now + secs;
        let owner = owner_of(owner_text);
        // The shadow map takes the keys first (so a reconcile running meanwhile doesn't take the
        // new kernel entries for unknown ones), unconfirmed until acked, and gives them back if
        // the helper doesn't. New keys must fit the device's share and the set (edge-firewall.md
        // §2), as an answer's would.
        let mut out = Outbox::new(self);
        let mut rxs = Vec::with_capacity(keys.len());
        let prev: Vec<Option<shadow::Entry>> = {
            let mut sh = self.shadow();
            let neighbours = self.neighbours.snapshot();
            if keys.iter().any(|k| {
                k.src
                    .and_then(|ip| neighbours.by_ip.get(&ip))
                    .is_some_and(|mac| owner_of(&crate::neighbours::format_mac(mac)) != owner)
            }) {
                return Err("the device's address changed owner".into());
            }
            let new =
                u32::try_from(keys.iter().filter(|k| sh.live(k, now).is_none()).count()).unwrap_or(u32::MAX);
            if !sh.room(owner, keys[0].set, new) {
                return Err("the firewall set is full".into());
            }
            keys.iter()
                .map(|k| {
                    let old = sh.live(k, now).copied();
                    let cur = old.map(|e| e.dns_exp).unwrap_or(0);
                    let t = timeout_s(cur.max(allow_exp).saturating_sub(now));
                    sh.upsert(*k, 0, Some(allow_exp), owner, now);
                    sh.unconfirm(k);
                    let (tx, rx) = oneshot::channel();
                    out.push(Self::op(OpKind::Ensure, *k, t, Some(tx)));
                    rxs.push(rx);
                    old
                })
                .collect()
        };
        out.finish();
        let deadline = tokio::time::Instant::now() + self.tuning.allow_ack;
        let results = Self::wait_acks(rxs, deadline).await;
        let failed = results.iter().find_map(|r| match r {
            Some(OpResult::Ok) => None,
            Some(OpResult::Failed(x)) => Some(format!("the helper refused the entry ({x})")),
            Some(OpResult::Unreachable) => Some("the helper is unreachable".to_owned()),
            None => Some("no ack from the helper in time".to_owned()),
        });
        if let Some(reason) = failed {
            self.undo_allow(&keys, &prev, owner, allow_exp);
            return Err(reason);
        }
        Ok(keys)
    }

    /// Puts back the allow expiry `keys` had before a failed [`Self::grant_allow`] (`prev`: their
    /// live entries then), for every key it touched, acked or not: the shadow map takes the
    /// previous `allow_exp` (DNS grants keep theirs, one an answer added meanwhile included) and
    /// the kernel gets the expiry that results, sent after the grant's own `ensure`, so a
    /// success, a refusal and a late ack all end there. A key whose expiry has passed is deleted.
    /// The key stays unconfirmed until the restoring `ensure` is acked.
    fn undo_allow(&self, keys: &[FwKey], prev: &[Option<shadow::Entry>], owner: u64, attempted_exp: u64) {
        let mut out = Outbox::new(self);
        {
            let now = self.now_s();
            let mut sh = self.shadow();
            for (k, old) in keys.iter().zip(prev) {
                // Removed since (a revoke, an address move): its own `delete` went after ours.
                let Some(cur) = sh.get(k).copied() else {
                    continue;
                };
                // A revoke or a newer grant takes precedence over this failed request.
                if cur.allow_owner != Some(owner) || cur.allow_exp != attempted_exp {
                    continue;
                }
                let current_owner = k
                    .src
                    .and_then(|ip| {
                        self.neighbours.mac_of(&ip).or_else(|| {
                            self.addr_owner
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .get(&ip)
                                .copied()
                        })
                    })
                    .map(|mac| owner_of(&crate::neighbours::format_mac(&mac)));
                // A replacement can fail after maintenance has revoked the old device's
                // access. Its saved expiry is usable only by the address's current owner.
                let restore = old.filter(|e| current_owner.is_none_or(|o| e.allow_owner == Some(o)));
                let allow = restore.map_or(0, |e| e.allow_exp);
                let exp = cur.dns_exp.max(allow);
                if exp <= now {
                    sh.remove(k);
                    out.delete(*k);
                } else {
                    sh.set_exps(k, cur.dns_exp, allow, restore.and_then(|e| e.allow_owner), now);
                    sh.unconfirm(k);
                    out.ensure(*k, exp - now);
                }
            }
        }
        out.finish();
    }

    /// Sets the allow expiry of `keys` (a revoke: `None`; a re-time: the new expiry in seconds
    /// from now). A lowered `max(dns_exp, allow_exp)` is sent as an `ensure` with it, or a `delete`
    /// once it has passed (edge-firewall.md §3).
    pub fn set_allow(&self, keys: &[FwKey], secs: Option<u64>) {
        if !self.needed() {
            return;
        }
        let now = self.now_s();
        let new_allow = secs.map(|s| now + s).unwrap_or(0);
        let mut out = Outbox::new(self);
        {
            let mut sh = self.shadow();
            for k in keys {
                let Some(e) = sh.get(k).copied() else { continue };
                let old = e.exp();
                let new = e.dns_exp.max(new_allow);
                sh.set_exps(k, e.dns_exp, new_allow, e.allow_owner, now);
                if new == old {
                    continue;
                }
                if new <= now {
                    sh.remove(k);
                    out.delete(*k);
                } else {
                    out.ensure(*k, new - now);
                }
            }
        }
        out.finish();
    }

    /// Re-sends active IP allows from `allows.json` once the clock is synchronised: an ensure for
    /// each key the kernel lacks or holds for less (edge-firewall.md §3 "Seeding").
    pub fn replay_allows(&self) {
        let now_wall = Timestamp::now();
        let now = self.now_s();
        let allows = self.allows.list();
        let mut out = Outbox::new(self);
        {
            let mut sh = self.shadow();
            for a in allows {
                if a.kind != picket_api::logs::AllowKind::Ip || a.expires_at <= now_wall {
                    continue;
                }
                let left = u64::try_from((a.expires_at - now_wall).as_secs())
                    .unwrap_or(0)
                    .max(1);
                let allow_exp = now + left;
                let owner = owner_of(&a.device);
                for k in crate::bypass::allow_keys(&a) {
                    if k.src
                        .and_then(|ip| self.neighbours.mac_of(&ip))
                        .is_some_and(|mac| owner_of(&crate::neighbours::format_mac(&mac)) != owner)
                    {
                        continue;
                    }
                    let cur = sh.live(&k, now).map(|e| e.exp()).unwrap_or(0);
                    sh.upsert(k, 0, Some(allow_exp), owner, now);
                    if cur < allow_exp {
                        sh.unconfirm(&k);
                        out.ensure(k, allow_exp.saturating_sub(now));
                    }
                }
            }
        }
        out.finish();
    }

    // ------------------------------------------------------------------------------------------
    // Neighbour changes (edge-firewall.md §1)

    /// A new address for a known MAC gets the live entries backfilled, within the device's share
    /// and the set's room; an address that moved to another MAC first loses the entries expanded
    /// to it from the old device's grants and IP allows (allows are per device, edge.md §12), and
    /// the old device's stored IP allows stop listing it.
    pub fn neighbour_event(&self, ev: NeighbourEvent) {
        let NeighbourEvent::Gained { mac, ip } = ev else {
            return;
        };
        if !self.needed() {
            return;
        }
        let ip = ip.to_canonical();
        // A queued event may describe an intermediate owner that already moved again.
        let mac = self.neighbours.mac_of(&ip).unwrap_or(mac);
        let owner_text = crate::neighbours::format_mac(&mac);
        let owner = owner_of(&owner_text);
        let old = {
            let mut g = self.addr_owner.lock().unwrap_or_else(|p| p.into_inner());
            if g.len() > crate::neighbours::MAX_ADDRESSES && !g.contains_key(&ip) {
                g.clear();
            }
            g.insert(ip, mac)
        };
        let now = self.now_s();
        let v4 = ip.is_ipv4();
        let old = old.filter(|o| *o != mac);
        // An intermediate owner can have been missed too: only the current device may
        // retain a MAC-scoped allow on this address.
        let ip_text = ip.to_string();
        let moved_allows: Vec<crate::allows::StoredAllow> = self
            .allows
            .list()
            .into_iter()
            .filter(|a| {
                a.kind == picket_api::logs::AllowKind::Ip
                    && crate::neighbours::parse_mac(&a.device).is_some()
                    && a.device != owner_text
                    && a.addresses.contains(&ip_text)
            })
            .collect();
        let mut out = Outbox::new(self);
        {
            let mut sh = self.shadow();
            if let Some(old) = old {
                for (set, dst, _) in sh.grants_of(&old, now) {
                    if dst.is_ipv4() != v4 {
                        continue;
                    }
                    let k = FwKey {
                        set,
                        src: Some(ip),
                        dst,
                    };
                    if let Some(e) = sh.get(&k).copied() {
                        // A new owner's allow may already share the old DNS grant's key.
                        // Remove the DNS expiry while preserving that newer allow.
                        if e.allow_exp > now && e.allow_owner == Some(owner) {
                            sh.set_exps(&k, 0, e.allow_exp, e.allow_owner, now);
                            if e.exp() != e.allow_exp {
                                out.ensure(k, e.allow_exp - now);
                            }
                        } else {
                            sh.remove(&k);
                            out.delete(k);
                        }
                    }
                }
            }
            // A bypass re-check may already have removed this address from the
            // stored allow. The shadow still owns its kernel entries, so revoke from
            // that map rather than depending on which subscriber ran first.
            let moved_keys: Vec<FwKey> = sh
                .map
                .iter()
                .filter(|(k, e)| k.src == Some(ip) && e.allow_owner != Some(owner) && e.allow_exp > 0)
                .map(|(k, _)| *k)
                .collect();
            for k in moved_keys {
                let Some(e) = sh.get(&k).copied() else {
                    continue;
                };
                // As a revoke would (edge-firewall.md §3): a lowered expiry is sent, a
                // passed one deleted.
                if e.dns_exp <= now {
                    sh.remove(&k);
                    out.delete(k);
                } else {
                    sh.set_exps(&k, e.dns_exp, 0, None, now);
                    if e.exp() != e.dns_exp {
                        out.ensure(k, e.dns_exp - now);
                    }
                }
            }
            for (set, dst, exp) in sh.grants_of(&mac, now) {
                if dst.is_ipv4() != v4 {
                    continue;
                }
                let k = FwKey {
                    set,
                    src: Some(ip),
                    dst,
                };
                let cur = sh.live(&k, now).copied();
                if cur.is_some_and(|e| e.exp() >= exp) {
                    continue;
                }
                if cur.is_none() && !sh.room(owner, set, 1) {
                    continue; // over the device's share or the set's room: the next answer decides
                }
                sh.upsert(k, exp, None, owner, now);
                sh.unconfirm(&k);
                out.ensure(k, exp - now);
            }
        }
        out.finish();
        // The stored allows follow, in memory even when allows.json can't be written (retried
        // until it lands), so nothing later grants the old device's allow on this address again
        // (edge.md §12).
        if !moved_allows.is_empty() {
            let ip_text = ip.to_string();
            let changed: Vec<crate::allows::StoredAllow> = moved_allows
                .into_iter()
                .map(|mut a| {
                    a.addresses.retain(|x| *x != ip_text);
                    a
                })
                .collect();
            if let Err(e) = self.allows.change_held(changed) {
                tracing::warn!("allows.json: {}", crate::diag::cap_chain(&e));
            }
        }
    }

    /// Makes up for neighbour events the maintenance loop missed (its channel overflowed): each
    /// address the table gives another device than the one last seen for it goes through
    /// [`Self::neighbour_event`] as its lost `Gained` would have (edge-firewall.md §1), so an
    /// address that moved loses the old device's grant and IP-allow entries (edge.md §12: allows
    /// are per device) and a new one gets its device's backfill. Bounded by the table
    /// ([`crate::neighbours::MAX_ADDRESSES`]); only changed addresses do any work.
    pub fn neighbour_catch_up(&self, map: &crate::neighbours::NeighbourMap) {
        if !self.needed() {
            return;
        }
        let mut changed: HashMap<IpAddr, Mac> = {
            let g = self.addr_owner.lock().unwrap_or_else(|p| p.into_inner());
            map.by_ip
                .iter()
                .filter(|(ip, mac)| g.get(*ip) != Some(*mac))
                .map(|(ip, mac)| (*ip, *mac))
                .collect()
        };
        // A→B→A can leave the recorded owner unchanged while B's allow still needs
        // revoking. Scan the bounded shadow once, rather than replaying every address.
        for (key, entry) in &self.shadow().map {
            if entry.allow_exp > 0
                && let Some(ip) = key.src
                && let Some(mac) = map.by_ip.get(&ip)
                && entry.allow_owner != Some(owner_of(&crate::neighbours::format_mac(mac)))
            {
                changed.insert(ip, *mac);
            }
        }
        for (ip, mac) in changed {
            self.neighbour_event(NeighbourEvent::Gained { mac, ip });
        }
    }

    // ------------------------------------------------------------------------------------------
    // Helper reports

    fn apply_conditions(&self, c: &HelperConditions) {
        if !self.needed() {
            return;
        }
        let mut cur: Vec<(String, Option<String>, Option<serde_json::Value>)> = Vec::new();
        for f in c.redirect_missing.iter().take(8) {
            cur.push((
                condition_kind::REDIRECT_MISSING.into(),
                Some(crate::diag::truncate(f, 16)),
                None,
            ));
        }
        for f in c.unifi_conflict.iter().take(32) {
            cur.push((
                condition_kind::UNIFI_CONFLICT.into(),
                Some(crate::diag::truncate(f, 64)),
                None,
            ));
        }
        for i in c.fw_layout_unknown.iter().take(64) {
            cur.push((
                condition_kind::FW_LAYOUT_UNKNOWN.into(),
                Some(crate::diag::truncate(i, 32)),
                None,
            ));
        }
        for f in c.fw_catch_all.iter().take(64) {
            cur.push((
                condition_kind::FW_CATCH_ALL.into(),
                Some(crate::diag::truncate(&f.interface, 32)),
                Some(serde_json::Value::String(crate::diag::truncate(&f.found, 16))),
            ));
        }
        if c.helper_disabled {
            cur.push((condition_kind::HELPER_DISABLED.into(), None, None));
        }
        self.conditions.sync_kinds(Source::Helper, &HELPER_KINDS, &cur);
        let mut st = HelperState::clone(&self.state.load());
        st.conditions = c.clone();
        self.state.store(Arc::new(st));
    }

    fn note_fill(&self, sets_: &[picket_api::helper::SetStatus]) {
        let sh_fill: Vec<(SetId, u32)> = {
            let sh = self.shadow();
            SetId::ALL.iter().map(|s| (*s, sh.fill(*s))).collect()
        };
        let recent = self.full_event.lock().unwrap_or_else(|p| p.into_inner()).clone();
        for (s, shadow_fill) in sh_fill {
            let kernel = sets_.iter().find(|x| x.name == s.name());
            let max = kernel
                .map(|k| k.max)
                .filter(|m| *m > 0)
                .unwrap_or(u64::from(sets::MAXELEM)) as f64;
            let used = kernel.map(|k| k.entries).unwrap_or(0).max(u64::from(shadow_fill)) as f64;
            let event_recent = recent
                .get(&s)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(60));
            if used >= FULL_AT * max {
                self.conditions
                    .set(condition_kind::FW_SET_FULL, Some(s.name()), None);
            } else if used < FULL_CLEAR * max && !event_recent {
                self.conditions.clear(condition_kind::FW_SET_FULL, Some(s.name()));
            }
        }
    }

    fn handle_event(self: &Arc<Self>, f: Frame) {
        match f.kind.as_str() {
            kind::CONDITIONS => {
                if let Ok(c) = f.parse_data::<HelperConditions>() {
                    self.apply_conditions(&c);
                }
            }
            kind::SET_FULL => {
                if let Ok(s) = f.parse_data::<SetFull>()
                    && let Some(id) = SetId::from_name(&s.set)
                {
                    self.full_event
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(id, Instant::now());
                    self.conditions
                        .set(condition_kind::FW_SET_FULL, Some(id.name()), None);
                }
            }
            kind::RULES_REPAIRED => {
                let Ok(r) = f.parse_data::<RulesRepaired>() else {
                    return;
                };
                let recreated: Vec<SetId> = r
                    .recreated_sets
                    .iter()
                    .filter_map(|s| SetId::from_name(s))
                    .collect();
                let mut ff = fields(&[
                    (
                        "missing",
                        r.missing
                            .iter()
                            .take(64)
                            .map(|s| crate::diag::truncate(s, 64))
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                    ("gap_ms", r.gap_ms.into()),
                ]);
                ff.insert(
                    "recreated_sets".into(),
                    recreated.iter().map(|s| s.name()).collect::<Vec<_>>().into(),
                );
                self.logs.event(event_kind::RULES_REPAIRED, ff);
                if recreated.is_empty() {
                    return;
                }
                // Every live key of a recreated set counts as absent until its own re-send is
                // acked (edge-firewall.md §3 "Set being refilled"); each re-send takes the key's
                // expiry when its chunk goes out ([`Self::send_bulk`]).
                let ops: Vec<(OpKind, FwKey)> = {
                    let mut sh = self.shadow();
                    let now = self.now_s();
                    let mut v = Vec::new();
                    for s in &recreated {
                        for (k, _) in sh.live_keys(*s, now) {
                            sh.unconfirm(&k);
                            v.push((OpKind::Ensure, k));
                        }
                    }
                    v
                };
                let me = Arc::clone(self);
                tokio::spawn(async move {
                    let n = ops.len();
                    let failed = me.send_bulk(ops).await;
                    if failed > 0 {
                        // Those stay unconfirmed: answers send them again and wait.
                        tracing::warn!(
                            "re-sending a recreated firewall set: {failed} of {n} entries not acked"
                        );
                    }
                });
            }
            _ => {}
        }
    }

    fn note_reachable(&self, ok: bool) {
        if ok {
            self.down_since.store(0, Relaxed);
            self.conditions.clear(condition_kind::HELPER_UNREACHABLE, None);
        } else if self.needed() {
            let now = self.ms().max(1);
            let since = match self.down_since.compare_exchange(0, now, Relaxed, Relaxed) {
                Ok(_) => now,
                Err(s) => s,
            };
            if now.saturating_sub(since) >= picket_api::duration::as_millis_u64(self.tuning.unreachable_after)
            {
                self.conditions
                    .set(condition_kind::HELPER_UNREACHABLE, None, None);
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Seeding and the reconcile

    /// Dumps one timed set, page by page (restarting on `cursor_expired`, at most 3 times).
    async fn dump_set(self: &Arc<Self>, c: &mut Conn, set: SetId) -> Result<Vec<(FwKey, u32)>, ConnError> {
        let me = Arc::clone(self);
        let mut on_event = move |f: Frame| me.handle_event(f);
        'restart: for _ in 0..3 {
            let mut out: Vec<(FwKey, u32)> = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let req = DumpRequest {
                    set: set.name().to_owned(),
                    cursor: cursor.clone(),
                    limit: MAX_DUMP_LIMIT,
                };
                let r: Result<DumpResponse, ConnError> = c
                    .request(kind::DUMP, &req, self.tuning.request_timeout, &mut on_event)
                    .await;
                let r = match r {
                    Ok(r) => r,
                    Err(ConnError::Helper { code, .. }) if code == error_code::CURSOR_EXPIRED => {
                        continue 'restart;
                    }
                    Err(ConnError::Helper { code, .. }) if code == error_code::NO_SET => return Ok(vec![]),
                    Err(e) => return Err(e),
                };
                for e in r.entries.iter().take(MAX_DUMP_LIMIT as usize) {
                    let fam_ok = |a: &IpAddr| a.is_ipv4() == matches!(set, SetId::P4 | SetId::G4);
                    let ok = fam_ok(&e.dst)
                        && (set.is_pair() == e.src.is_some())
                        && e.src.as_ref().is_none_or(fam_ok);
                    if ok && out.len() < 4 * sets::MAXELEM as usize {
                        out.push((
                            FwKey {
                                set,
                                src: e.src.map(|s| s.to_canonical()),
                                dst: e.dst.to_canonical(),
                            },
                            e.timeout_s,
                        ));
                    }
                }
                match r.next_cursor {
                    Some(n) if n.len() <= 256 => cursor = Some(n),
                    _ => return Ok(out),
                }
            }
        }
        Err(ConnError::Io("dump cursor kept expiring".into()))
    }

    /// Seeds the shadow map from a dump (edge-firewall.md §3 "Seeding from dump").
    async fn seed(self: &Arc<Self>, c: &mut Conn) -> Result<(), ConnError> {
        let cap = self.view.load().cap_s.max(1);
        let mut all = Vec::new();
        for s in SetId::ALL {
            all.push((s, self.dump_set(c, s).await?));
        }
        let now = self.now_s();
        let mut sh = self.shadow();
        for (_, entries) in all {
            for (k, t) in entries {
                if t == 0 {
                    continue; // permanent: not Picket's; the reconcile deletes it
                }
                let exp = now + u64::from(t).min(cap);
                let owner_text = k.src.map(|s| s.to_string()).unwrap_or_default();
                let owner = match k.src.and_then(|s| self.neighbours.mac_of(&s)) {
                    Some(m) => {
                        sh.grant(m, k.set, k.dst, exp);
                        owner_of(&crate::neighbours::format_mac(&m))
                    }
                    None => owner_of(&owner_text),
                };
                sh.upsert(k, exp, None, owner, now);
                // Not changed by the edge: the reconcile right after seeding compares it, so
                // kernel entries over the cap are trimmed then (edge-firewall.md §3 Seeding).
                sh.mark_seeded(&k);
            }
        }
        Ok(())
    }

    /// One reconcile pass over the four timed sets (edge-firewall.md §3 "Reconcile").
    async fn reconcile(self: &Arc<Self>, c: &mut Conn) -> Result<(), ConnError> {
        let start = self.now_s();
        let mut kernel: Vec<(SetId, Vec<(FwKey, u32)>)> = Vec::new();
        for s in SetId::ALL {
            kernel.push((s, self.dump_set(c, s).await?));
        }
        let now = self.now_s();
        // Keys an answer is waiting on right now: the kernel may hold them before the shadow map
        // does (the ack is on its way), so they don't count.
        let inflight: std::collections::HashSet<FwKey> = self
            .inflight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect();
        let d = {
            let mut sh = self.shadow();
            let d = reconcile_diff(&sh, &kernel, now, start, &inflight);
            sh.prune(now.saturating_sub(RECONCILE_SLACK));
            d
        };
        // The ops carry no expiry: each takes the key's when its chunk goes out.
        let mut ops: Vec<(OpKind, FwKey)> = d.deletes.iter().map(|k| (OpKind::Delete, *k)).collect();
        ops.extend(d.ensures.iter().map(|(k, _)| (OpKind::Ensure, *k)));
        if !ops.is_empty() {
            // With backpressure, off the control connection (it keeps serving events).
            let me = Arc::clone(self);
            tokio::spawn(async move {
                me.send_bulk(ops).await;
            });
        }
        if d.missing + d.unknown + d.longer > 0 {
            self.conditions.set(
                condition_kind::FW_DRIFT,
                None,
                Some(serde_json::json!({"missing": d.missing, "unknown": d.unknown, "longer": d.longer})),
            );
        } else {
            self.conditions.clear(condition_kind::FW_DRIFT, None);
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------------------
    // Tasks

    async fn wait_needed(&self) {
        loop {
            let n = self.wake.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if self.needed() {
                return;
            }
            n.await;
        }
    }

    /// The control connection: hello, seeding, apply, events, status and the reconcile.
    pub async fn run_control(self: Arc<Self>) -> anyhow::Result<()> {
        let Some(mut rx) = self.ctl_rx.lock().unwrap_or_else(|p| p.into_inner()).take() else {
            std::future::pending::<()>().await;
            return Ok(());
        };
        let mut backoff = self.tuning.reconnect.0;
        loop {
            self.wait_needed().await;
            let mut c = match Conn::connect(&self.tuning.socket, self.tuning.connect_timeout).await {
                Ok(c) => c,
                Err(e) => {
                    self.note_reachable(false);
                    tracing::debug!("helper: {e}");
                    self.fail_queued(&mut rx);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(self.tuning.reconnect.1);
                    continue;
                }
            };
            match self.session(&mut c, &mut rx).await {
                Ok(()) => {}
                Err(e) if self.mismatch.load(Relaxed) => {
                    // edge-firewall.md §4: a version mismatch → the edge refuses to start (a
                    // broken install or an update half-way; the updater's readiness wait then
                    // rolls the update back). Exiting is how this critical task refuses.
                    self.fail_queued(&mut rx);
                    anyhow::bail!("{e}");
                }
                Err(e) => {
                    tracing::warn!("helper control connection: {e}");
                    let mut st = HelperState::clone(&self.state.load());
                    st.connected = false;
                    self.state.store(Arc::new(st));
                    self.note_reachable(false);
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(self.tuning.reconnect.1);
            if self.state.load().connected {
                backoff = self.tuning.reconnect.0;
            }
        }
    }

    fn fail_queued(&self, rx: &mut mpsc::Receiver<CtlReq>) {
        while let Ok(r) = rx.try_recv() {
            let _ = r
                .reply
                .send(Err(ConnError::Io("the helper is unreachable".into())));
        }
    }

    async fn session(
        self: &Arc<Self>,
        c: &mut Conn,
        rx: &mut mpsc::Receiver<CtlReq>,
    ) -> Result<(), ConnError> {
        let me = Arc::clone(self);
        let mut on_event = move |f: Frame| me.handle_event(f);
        let hello: HelloResponse = c
            .request(
                kind::HELLO,
                &HelloRequest {
                    proto_version: PROTO_VERSION,
                    events: true,
                },
                self.tuning.request_timeout,
                &mut on_event,
            )
            .await?;
        if hello.proto_version != PROTO_VERSION {
            // The edge, helper and updater ship together (edge.md §14): a mismatch means a broken
            // install or an update half-way. The edge refuses to run (edge-firewall.md §4) and
            // reports it: the journal, an event in the spool, and core's `edge_crash_loop` as
            // systemd restarts it.
            self.mismatch.store(true, Relaxed);
            let msg = format!(
                "picket-edge-helper {} speaks protocol {} (this edge: {PROTO_VERSION}); refusing to run",
                crate::diag::truncate(&hello.helper_version, 64),
                hello.proto_version
            );
            tracing::error!("{msg}");
            self.logs.event(
                "helper_protocol_mismatch",
                fields(&[
                    ("helper_proto", hello.proto_version.into()),
                    ("edge_proto", PROTO_VERSION.into()),
                    (
                        "helper_version",
                        crate::diag::truncate(&hello.helper_version, 64).into(),
                    ),
                ]),
            );
            return Err(ConnError::Invalid(msg));
        }
        self.state.store(Arc::new(HelperState {
            connected: true,
            rules_ok: hello.rules_ok,
            conditions: hello.conditions.clone(),
            pid: c.pid,
            helper_version: crate::diag::truncate(&hello.helper_version, 64),
        }));
        self.note_reachable(true);
        self.apply_conditions(&hello.conditions);
        self.note_fill(&hello.sets);
        if self.seeded.load(Relaxed) {
            // A reconnect: ops may have failed meanwhile, and a `rules_repaired` sent while
            // disconnected is lost; the reconcile finds and fixes both.
            self.reconcile_now.notify_one();
        } else {
            self.seed(c).await?;
            self.seeded.store(true, Relaxed);
            self.seed_done.notify_waiters();
            let me = Arc::clone(self);
            tokio::spawn(async move {
                while !me.clock.synced() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                me.replay_allows();
                me.reconcile_now.notify_one();
            });
            self.reconcile_now.notify_one();
        }
        let mut applied = false;
        let mut reconcile = tokio::time::interval(self.tuning.reconcile_every);
        reconcile.tick().await;
        loop {
            if !self.needed() {
                return Ok(());
            }
            let v = self.view.load_full();
            if v.active && !applied {
                let r: ApplyResponse = c
                    .request(kind::APPLY, &v.apply, self.tuning.apply_timeout, &mut on_event)
                    .await?;
                applied = true;
                let mut st = HelperState::clone(&self.state.load());
                st.rules_ok = r.rules_ok;
                self.state.store(Arc::new(st));
                self.apply_conditions(&r.conditions);
            }
            tokio::select! {
                req = rx.recv() => {
                    let Some(req) = req else { return Ok(()) };
                    let r: Result<serde_json::Value, ConnError> =
                        c.request(req.kind, &req.data, req.timeout, &mut on_event).await;
                    let io = matches!(r, Err(ConnError::Io(_)));
                    if let Ok(v) = &r && req.kind == kind::APPLY {
                        let a: ApplyResponse = serde_json::from_value(v.clone()).unwrap_or_default();
                        self.apply_conditions(&a.conditions);
                    }
                    let _ = req.reply.send(r.clone());
                    if io {
                        return r.map(|_| ());
                    }
                }
                f = c.read_frame() => {
                    let f = f?;
                    if f.id.is_none() {
                        self.handle_event(f);
                    }
                }
                _ = reconcile.tick() => { self.reconcile(c).await?; }
                _ = self.reconcile_now.notified() => { self.reconcile(c).await?; }
                _ = self.apply_now.notified() => { applied = false; }
                _ = self.wake.notified() => {}
            }
        }
    }

    /// The fast connection: coalesced `ensure` and `delete` batches, each op completed in
    /// [`Self::complete`]. It says `hello` first (without events) and is used only once the
    /// protocol version matches (edge-firewall.md §4).
    pub async fn run_fast(self: Arc<Self>) -> anyhow::Result<()> {
        let Some(mut rx) = self.fast_rx.lock().unwrap_or_else(|p| p.into_inner()).take() else {
            std::future::pending::<()>().await;
            return Ok(());
        };
        let mut held: VecDeque<Op> = VecDeque::new();
        let mut backoff = self.tuning.reconnect.0;
        // Ops failed since the last connection: the reconcile after a reconnect fixes them.
        let mut lost = false;
        loop {
            if !self.needed() {
                lost |= self.fail_ops(&mut held, &mut rx) > 0;
                tokio::select! {
                    _ = self.wait_needed() => {}
                    op = rx.recv() => {
                        if let Some(op) = op {
                            self.complete(op, &OpResult::Unreachable);
                        }
                        continue;
                    }
                }
            }
            let mut ignore = |_f: Frame| {};
            let conn = match Conn::connect(&self.tuning.socket, self.tuning.connect_timeout).await {
                Ok(mut c) => {
                    let hello: Result<HelloResponse, ConnError> = c
                        .request(
                            kind::HELLO,
                            &HelloRequest {
                                proto_version: PROTO_VERSION,
                                events: false,
                            },
                            self.tuning.request_timeout,
                            &mut ignore,
                        )
                        .await;
                    match hello {
                        Ok(h) if h.proto_version == PROTO_VERSION => Some(c),
                        Ok(_) => {
                            // Never an `ensure` to a helper speaking another protocol; the
                            // control connection reports it and stops the edge.
                            self.mismatch.store(true, Relaxed);
                            None
                        }
                        Err(_) => None,
                    }
                }
                Err(_) => None,
            };
            let Some(mut c) = conn else {
                self.note_reachable(false);
                lost |= self.fail_ops(&mut held, &mut rx) > 0;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(self.tuning.reconnect.1);
                continue;
            };
            backoff = self.tuning.reconnect.0;
            if std::mem::take(&mut lost) {
                self.reconcile_now.notify_one();
            }
            loop {
                if !self.needed() {
                    break;
                }
                let first = match held.pop_front() {
                    Some(o) => o,
                    None => tokio::select! {
                        o = rx.recv() => match o { Some(o) => o, None => return Ok(()) },
                        _ = self.wake.notified() => continue,
                    },
                };
                let k = first.kind;
                let mut batch = vec![first];
                while batch.len() < BATCH {
                    let next = match held.pop_front() {
                        Some(o) => Some(o),
                        None => rx.try_recv().ok(),
                    };
                    match next {
                        Some(o) if o.kind == k => batch.push(o),
                        Some(o) => {
                            held.push_front(o);
                            break;
                        }
                        None => break,
                    }
                }
                let entries: Vec<_> = batch.iter().map(|o| o.key.entry(o.timeout_s)).collect();
                let r: Result<EnsureResponse, ConnError> = match k {
                    OpKind::Ensure => {
                        c.request(
                            kind::ENSURE,
                            &EnsureRequest { entries },
                            self.tuning.request_timeout,
                            &mut ignore,
                        )
                        .await
                    }
                    OpKind::Delete => {
                        c.request(
                            kind::DELETE,
                            &DeleteRequest { entries },
                            self.tuning.request_timeout,
                            &mut ignore,
                        )
                        .await
                    }
                };
                match r {
                    Ok(resp) => {
                        for (i, op) in batch.into_iter().enumerate() {
                            let res = match resp.failed.iter().find(|f| f.index == i) {
                                Some(f) => OpResult::Failed(crate::diag::truncate(&f.reason, 64)),
                                None => OpResult::Ok,
                            };
                            self.complete(op, &res);
                        }
                    }
                    Err(ConnError::Helper { code, .. }) => {
                        for op in batch {
                            self.complete(op, &OpResult::Failed(code.clone()));
                        }
                    }
                    Err(e) => {
                        for op in batch {
                            self.complete(op, &OpResult::Unreachable);
                        }
                        lost = true;
                        tracing::debug!("helper fast connection: {e}");
                        self.note_reachable(false);
                        break;
                    }
                }
            }
        }
    }

    /// Fails every held and queued op (the helper isn't reachable or isn't needed); returns how
    /// many.
    fn fail_ops(&self, held: &mut VecDeque<Op>, rx: &mut mpsc::Receiver<Op>) -> usize {
        let mut n = 0usize;
        for op in held.drain(..) {
            self.complete(op, &OpResult::Unreachable);
            n += 1;
        }
        while let Ok(op) = rx.try_recv() {
            self.complete(op, &OpResult::Unreachable);
            n += 1;
        }
        n
    }

    /// Prunes the shadow map and keeps `helper_unreachable` current.
    pub async fn run_maintenance(self: Arc<Self>, neighbours: Arc<Neighbours>) -> anyhow::Result<()> {
        let mut events = neighbours.subscribe();
        // Startup (or a supervisor restart) can happen after a neighbour moved. Such
        // events precede this subscription and produce no Lagged notification.
        self.neighbour_catch_up(&neighbours.snapshot());
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut last_prune = Instant::now();
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                e = events.recv() => match e {
                    Ok(ev) => self.neighbour_event(ev),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("{n} neighbour events missed: reconciling with the neighbour table");
                        self.neighbour_catch_up(&neighbours.snapshot());
                    }
                    Err(_) => events = neighbours.subscribe(),
                }
            }
            if self.needed() && !self.state.load().connected {
                self.note_reachable(false);
            }
            if last_prune.elapsed() >= Duration::from_secs(30) {
                last_prune = Instant::now();
                self.prune();
            }
        }
    }

    /// Drops entries that lapsed more than the reconcile's 5 s tolerance ago (edge-firewall.md
    /// §3): the kernel's whole-second timeout outlives the shadow map's expiry a little, so a
    /// reconcile right after must still know the entry or it would delete it as unknown.
    fn prune(&self) {
        let now = self.now_s();
        self.shadow().prune(now.saturating_sub(RECONCILE_SLACK));
    }

    /// The heartbeat's helper fields: `status` (rejects growth, set fill, conditions).
    pub async fn snapshot(&self) -> HelperSnapshot {
        if !self.needed() {
            return HelperSnapshot::default();
        }
        let r = self
            .control(
                kind::STATUS,
                serde_json::json!({}),
                self.tuning.request_timeout.min(Duration::from_secs(2)),
            )
            .await;
        let st = self.state.load_full();
        let mut fw = None;
        if let Ok(v) = r
            && let Ok(s) = serde_json::from_value::<StatusResponse>(v)
        {
            let rj = self.rejects.fetch_add(s.rejects, Relaxed) + s.rejects;
            let mrj = self.mon_rejects.fetch_add(s.mon_rejects, Relaxed) + s.mon_rejects;
            self.apply_conditions(&s.conditions);
            self.note_fill(&s.sets);
            let mut st2 = HelperState::clone(&st);
            st2.rules_ok = s.rules_ok;
            self.state.store(Arc::new(st2));
            fw = Some(FwStats {
                entries: s.sets.iter().map(|x| x.entries).sum(),
                max: s.sets.iter().map(|x| x.max).sum(),
                rejects: rj,
                mon_rejects: mrj,
            });
        }
        let pid = st.pid;
        HelperSnapshot {
            pid,
            cpu_ms: pid.and_then(|p| crate::sysinfo::cpu_ms(Some(p))),
            rss: pid.and_then(|p| crate::sysinfo::rss(Some(p))),
            fw,
        }
    }
}

/// What a reconcile found, and the ops that put the kernel right.
#[derive(Debug, Default, PartialEq, Eq)]
struct Diff {
    missing: u64,
    unknown: u64,
    longer: u64,
    ensures: Vec<(FwKey, u32)>,
    deletes: Vec<FwKey>,
}

/// Compares a dump of the timed sets (`kernel`: remaining timeouts at `now`) with the shadow map
/// (edge-firewall.md §3 "Reconcile"). Keys changed at or after `start` (the first dump request)
/// and keys an answer waits on don't count, nor differences within [`RECONCILE_SLACK`] either
/// way: a kernel entry the shadow map let lapse at most that long ago isn't unknown (whole-second
/// timeouts and the add's latency make the kernel's outlive the shadow map's by up to a second,
/// and an entry can lapse during the dump), and one the shadow map holds for at most that much
/// longer isn't missing.
fn reconcile_diff(
    sh: &Shadow,
    kernel: &[(SetId, Vec<(FwKey, u32)>)],
    now: u64,
    start: u64,
    inflight: &std::collections::HashSet<FwKey>,
) -> Diff {
    let mut d = Diff::default();
    let recent = |e: &shadow::Entry| u64::from(e.changed) >= start;
    for (set, entries) in kernel {
        let held: HashMap<FwKey, u32> = entries.iter().copied().collect();
        for (k, t) in entries {
            if inflight.contains(k) {
                continue;
            }
            match sh.get(k) {
                Some(e) if recent(e) => {}
                Some(e) if e.exp() > now => {
                    let k_exp = now + u64::from(*t);
                    if *t != 0 && k_exp > e.exp() + RECONCILE_SLACK {
                        d.longer += 1;
                        d.ensures.push((*k, timeout_s((e.exp() - now).max(1))));
                    }
                }
                // Lapsed in the shadow map moments ago: the kernel's whole-second timeout
                // outlives it a little.
                Some(e)
                    if *t != 0
                        && e.exp() + RECONCILE_SLACK > now
                        && now + u64::from(*t) <= e.exp() + RECONCILE_SLACK => {}
                _ => {
                    d.unknown += 1;
                    d.deletes.push(*k);
                }
            }
        }
        for (k, exp) in sh.live_keys(*set, now) {
            if inflight.contains(&k) || sh.get(&k).is_some_and(recent) {
                continue;
            }
            let missing = match held.get(&k) {
                // About to lapse in the shadow map too: the kernel let it go a little earlier.
                None => exp > now + RECONCILE_SLACK,
                Some(t) => *t != 0 && now + u64::from(*t) + RECONCILE_SLACK < exp,
            };
            if missing {
                d.missing += 1;
                d.ensures.push((k, timeout_s((exp - now).max(1))));
            }
        }
    }
    d
}

impl View {
    /// `ack_wait_ms` (edge-firewall.md §3), bounded.
    fn ack_wait(&self) -> u32 {
        self.ack_wait_ms.clamp(1, 5000)
    }
}

/// The data path's firewall ensure point.
pub struct FwHook(pub Arc<FwClient>);

#[async_trait]
impl FirewallEnsure for FwHook {
    async fn ensure(&self, req: &FwRequest<'_>) -> FwOutcome {
        self.0.ensure(req).await
    }
    fn enabled(&self) -> bool {
        self.0.needed()
    }
}

/// The foundation's helper hooks.
pub struct FwHelperHooks(pub Arc<FwClient>);

#[async_trait]
impl HelperProbe for FwHelperHooks {
    async fn snapshot(&self) -> HelperSnapshot {
        self.0.snapshot().await
    }
}

#[async_trait]
impl HelperSeed for FwHelperHooks {
    async fn seed(&self, _edge: &Edge, config: &EdgeConfig) -> anyhow::Result<()> {
        let mut v = View::of(config);
        v.active = false;
        self.0.view.store(Arc::new(v));
        self.0.set_needed(true);
        self.0.wait_seeded().await;
        if !self.0.seeded.load(Relaxed) {
            anyhow::bail!("the helper didn't answer in time; seeding when it does");
        }
        Ok(())
    }
}

/// The `helper` firmware self-check (edge-unifi.md §1): the helper answers `hello` with
/// `rules_ok`.
pub struct HelperCheck(pub Arc<FwClient>);

#[async_trait]
impl SelfCheck for HelperCheck {
    fn name(&self) -> &'static str {
        "helper"
    }
    fn applies(&self, _edge: &Edge) -> bool {
        self.0.needed()
    }
    async fn passes(&self, _edge: &Edge) -> bool {
        let st = self.0.state.load();
        st.connected && st.rules_ok
    }
}

/// The `redirect` self-check (edge-unifi.md §1): the port-53 redirect is present.
pub struct RedirectSelfCheck(pub Arc<FwClient>);

#[async_trait]
impl SelfCheck for RedirectSelfCheck {
    fn name(&self) -> &'static str {
        "redirect"
    }
    fn applies(&self, _edge: &Edge) -> bool {
        self.0.needed() && self.0.view.load().redirect
    }
    async fn passes(&self, _edge: &Edge) -> bool {
        let st = self.0.state.load();
        st.connected && st.conditions.redirect_missing.is_empty()
    }
}

/// An ipset timeout of `secs`, capped at [`MAX_TIMEOUT_S`].
fn timeout_s(secs: u64) -> u32 {
    u32::try_from(secs).map_or(MAX_TIMEOUT_S, |s| s.min(MAX_TIMEOUT_S))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use picket_api::helper::{DumpRequest, HelloRequest};
    use tokio::net::UnixListener;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    use crate::dns::FwAddr;
    use crate::dns::profiles::DeviceKey;
    use picket_api::edge_config::ProfileFirewall;

    /// What the fake helper does and saw.
    #[derive(Default)]
    struct FakeState {
        delay: Duration,
        /// The protocol version it answers `hello` with (0: this edge's).
        proto: u32,
        /// `dump` pages per set name.
        dump: HashMap<String, Vec<picket_api::helper::SetEntry>>,
        ensured: Vec<picket_api::helper::SetEntry>,
        deleted: Vec<picket_api::helper::SetEntry>,
        /// Every ensure (true) and delete (false) entry, in the order the helper applied them.
        log: Vec<(bool, picket_api::helper::SetEntry)>,
        /// Entries from these sources fail (`set_full`).
        fail_src: Vec<IpAddr>,
        dumps: usize,
        /// Connections that said `hello` with events.
        events: Vec<mpsc::UnboundedSender<Frame>>,
    }

    /// A fake helper: answers `hello`, `dump` (the configured entries, paged), `apply` and
    /// `status`; `ensure` after `delay`, failing entries whose destination is 9.9.9.9 with
    /// `set_full`. Records what it got and can push events and be restarted.
    struct Fake {
        path: std::path::PathBuf,
        _dir: tempfile::TempDir,
        ensures: Arc<AtomicUsize>,
        entries: Arc<AtomicUsize>,
        st: Arc<Mutex<FakeState>>,
        tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    }

    impl Fake {
        fn st(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.st.lock().unwrap()
        }
        /// Sends an event on every connection that asked for them.
        fn event(&self, kind_: &str, data: serde_json::Value) {
            let f = Frame {
                kind: kind_.into(),
                id: None,
                data,
            };
            self.st().events.retain(|tx| tx.send(f.clone()).is_ok());
        }
        /// Stops serving: the socket goes away and every connection closes.
        fn stop(&self) {
            for t in self.tasks.lock().unwrap().drain(..) {
                t.abort();
            }
            self.st().events.clear();
            let _ = std::fs::remove_file(&self.path);
        }
        /// Serves again at the same path.
        fn restart(&self) {
            self.stop();
            serve_fake(&self.path, &self.st, &self.ensures, &self.entries, &self.tasks);
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            for t in self.tasks.lock().unwrap().drain(..) {
                t.abort();
            }
        }
    }

    fn serve_fake(
        path: &std::path::Path,
        st: &Arc<Mutex<FakeState>>,
        ensures: &Arc<AtomicUsize>,
        entries: &Arc<AtomicUsize>,
        tasks: &Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    ) {
        let l = UnixListener::bind(path).unwrap();
        let (st, e1, e2, t2) = (
            Arc::clone(st),
            Arc::clone(ensures),
            Arc::clone(entries),
            Arc::clone(tasks),
        );
        let accept = tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let (st, e1, e2) = (Arc::clone(&st), Arc::clone(&e1), Arc::clone(&e2));
                let conn = tokio::spawn(async move {
                    let mut io = Framed::new(s, LengthDelimitedCodec::new());
                    let (etx, mut erx) = mpsc::unbounded_channel::<Frame>();
                    loop {
                        let b = tokio::select! {
                            b = io.next() => match b { Some(Ok(b)) => b, _ => return },
                            ev = erx.recv() => {
                                let Some(ev) = ev else { continue };
                                if io.send(Bytes::from(serde_json::to_vec(&ev).unwrap())).await.is_err() {
                                    return;
                                }
                                continue;
                            }
                        };
                        let f: Frame = serde_json::from_slice(&b).unwrap();
                        let data = match f.kind.as_str() {
                            kind::HELLO => {
                                let r: HelloRequest = f.parse_data().unwrap();
                                let mut g = st.lock().unwrap();
                                if r.events {
                                    g.events.push(etx.clone());
                                }
                                let proto = if g.proto == 0 { PROTO_VERSION } else { g.proto };
                                serde_json::json!({"proto_version": proto, "rules_ok": true})
                            }
                            kind::DUMP => {
                                let r: DumpRequest = f.parse_data().unwrap();
                                let mut g = st.lock().unwrap();
                                g.dumps += 1;
                                let all = g.dump.get(&r.set).cloned().unwrap_or_default();
                                let from: usize = r.cursor.as_deref().map_or(0, |c| c.parse().unwrap());
                                let to = (from + r.limit as usize).min(all.len());
                                let next = (to < all.len()).then(|| to.to_string());
                                serde_json::json!({"entries": all[from..to], "next_cursor": next})
                            }
                            kind::APPLY => serde_json::json!({"ok": true, "rules_ok": true}),
                            kind::STATUS => serde_json::json!({"rules_ok": true, "rejects": 2}),
                            kind::ENSURE | kind::DELETE => {
                                let r: EnsureRequest = f.parse_data().unwrap();
                                let (delay, fail_src) = {
                                    let mut g = st.lock().unwrap();
                                    let is_e = f.kind == kind::ENSURE;
                                    g.log.extend(r.entries.iter().cloned().map(|e| (is_e, e)));
                                    if f.kind == kind::ENSURE {
                                        g.ensured.extend(r.entries.iter().cloned());
                                    } else {
                                        g.deleted.extend(r.entries.iter().cloned());
                                    }
                                    (g.delay, g.fail_src.clone())
                                };
                                if f.kind == kind::ENSURE {
                                    e1.fetch_add(1, Relaxed);
                                    e2.fetch_add(r.entries.len(), Relaxed);
                                }
                                tokio::time::sleep(delay).await;
                                let failed: Vec<serde_json::Value> = r
                                    .entries
                                    .iter()
                                    .enumerate()
                                    .filter(|(_, e)| {
                                        e.dst == "9.9.9.9".parse::<IpAddr>().unwrap()
                                            || e.src.is_some_and(|s| fail_src.contains(&s))
                                    })
                                    .map(|(i, _)| serde_json::json!({"index": i, "reason": "set_full"}))
                                    .collect();
                                serde_json::json!({"ok": failed.is_empty(), "failed": failed})
                            }
                            _ => serde_json::json!({}),
                        };
                        let out = Frame {
                            kind: f.kind.clone(),
                            id: f.id,
                            data,
                        };
                        if io
                            .send(Bytes::from(serde_json::to_vec(&out).unwrap()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
                t2.lock().unwrap().push(conn);
            }
        });
        tasks.lock().unwrap().push(accept);
    }

    fn fake(delay: Duration) -> Fake {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.sock");
        let f = Fake {
            path,
            _dir: dir,
            ensures: Arc::new(AtomicUsize::new(0)),
            entries: Arc::new(AtomicUsize::new(0)),
            st: Arc::new(Mutex::new(FakeState {
                delay,
                ..FakeState::default()
            })),
            tasks: Arc::new(Mutex::new(Vec::new())),
        };
        serve_fake(&f.path, &f.st, &f.ensures, &f.entries, &f.tasks);
        f
    }

    fn client(path: &std::path::Path) -> Arc<FwClient> {
        client_h(path).0
    }

    /// A client and its control task (to see it end).
    fn client_h(path: &std::path::Path) -> (Arc<FwClient>, tokio::task::JoinHandle<anyhow::Result<()>>) {
        client_t(path, |_| {})
    }

    /// A client with its tuning adjusted, and its control task.
    fn client_t(
        path: &std::path::Path,
        adjust: impl FnOnce(&mut FwTuning),
    ) -> (Arc<FwClient>, tokio::task::JoinHandle<anyhow::Result<()>>) {
        let (logs, _rx) = LogProducer::new("b".into(), Arc::default());
        let d = tempfile::tempdir().unwrap();
        let mut tuning = FwTuning {
            socket: path.to_path_buf(),
            reconnect: (Duration::from_millis(20), Duration::from_millis(100)),
            seed_wait: Duration::from_millis(500),
            ..FwTuning::default()
        };
        adjust(&mut tuning);
        let c = FwClient::new(
            tuning,
            Neighbours::new(),
            Interfaces::new(),
            Conditions::new(logs.clone()),
            logs.clone(),
            Clock::fixed(true),
            AllowsStore::load(&d.keep().join("allows.json"), logs),
        );
        let h = tokio::spawn(Arc::clone(&c).run_control());
        tokio::spawn(Arc::clone(&c).run_fast());
        (c, h)
    }

    fn cfg(ack_wait_ms: u32) -> EdgeConfig {
        serde_json::from_value(serde_json::json!({
            "firewall": {"interfaces": [{"name": "br0", "mode": "enforce"}], "ack_wait_ms": ack_wait_ms},
        }))
        .unwrap()
    }

    async fn ensure(c: &FwClient, fw: &ProfileFirewall, dst: &str, ttl: u32) -> FwOutcome {
        let dev = DeviceKey::Addr("192.168.1.10".parse().unwrap());
        let addrs = [FwAddr {
            ip: dst.parse().unwrap(),
            client_ttl: ttl,
        }];
        c.ensure(&FwRequest {
            client: "192.168.1.10".parse().unwrap(),
            device: &dev,
            profile: "p",
            firewall: fw,
            addrs: &addrs,
        })
        .await
    }

    #[tokio::test]
    async fn new_keys_wait_for_the_ack_and_live_ones_need_nothing() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        c.prepare(&cfg(1000)).await.unwrap();
        c.config_active(&cfg(1000));
        let fw = ProfileFirewall::default();
        let o = ensure(&c, &fw, "1.1.1.1", 300).await;
        assert_eq!((o.added, o.late, o.servfail), (1, false, false));
        let k = FwKey {
            set: SetId::P4,
            src: Some("192.168.1.10".parse().unwrap()),
            dst: "1.1.1.1".parse().unwrap(),
        };
        let exp = c.live_exp(&k).unwrap();
        assert!((419..=421).contains(&(exp - c.now_s())), "client_ttl + grace_s");
        // Covered until desired − hysteresis: nothing is sent.
        let before = f.ensures.load(Relaxed);
        let o = ensure(&c, &fw, "1.1.1.1", 250).await;
        assert_eq!(o.added, 0);
        assert_eq!(f.ensures.load(Relaxed), before, "no ensure for a covered key");
        // A full set (or a client over its share) with `on_full: servfail`.
        let mut sf = fw;
        sf.on_full = OnFull::Servfail;
        let o = ensure(&c, &sf, "9.9.9.9", 300).await;
        assert!(o.servfail);
        let o = ensure(&c, &fw, "9.9.9.9", 300).await;
        assert!(!o.servfail, "reply_anyway");
    }

    #[tokio::test]
    async fn a_late_ack_replies_anyway_and_ops_are_coalesced() {
        let f = fake(Duration::from_millis(300));
        let c = client(&f.path);
        c.prepare(&cfg(50)).await.unwrap();
        c.config_active(&cfg(50));
        let fw = ProfileFirewall::default();
        let started = Instant::now();
        let o = ensure(&c, &fw, "2.2.2.2", 300).await;
        assert!(o.late, "no ack within ack_wait_ms");
        assert!(started.elapsed() < Duration::from_millis(250));
        // Many answers at once: one message in flight, the rest coalesced (≤ 64 per message).
        let mut futs = Vec::new();
        for i in 0..200u32 {
            let c = Arc::clone(&c);
            futs.push(tokio::spawn(async move {
                let fw = ProfileFirewall::default();
                ensure(&c, &fw, &format!("10.1.{}.{}", i / 250, i % 250 + 1), 300).await
            }));
        }
        for f in futs {
            f.await.unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while f.entries.load(Relaxed) < 201 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(f.entries.load(Relaxed), 201);
        let msgs = f.ensures.load(Relaxed);
        assert!(
            msgs <= 1 + 200usize.div_ceil(BATCH) + 2,
            "coalesced into few messages: {msgs}"
        );
    }

    fn pkey(src: &str, dst: &str) -> FwKey {
        FwKey {
            set: SetId::P4,
            src: Some(src.parse().unwrap()),
            dst: dst.parse().unwrap(),
        }
    }

    async fn until(t: Duration, mut f: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + t;
        while Instant::now() < end {
            if f() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        f()
    }

    async fn ready(c: &FwClient) {
        c.prepare(&cfg(1000)).await.unwrap();
        c.config_active(&cfg(1000));
        assert!(
            until(Duration::from_secs(5), || c.seeded.load(Relaxed)).await,
            "seeded"
        );
    }

    #[tokio::test]
    async fn a_cancelled_answer_still_records_its_key_and_later_answers_send_again() {
        let f = fake(Duration::from_millis(200));
        let c = client(&f.path);
        ready(&c).await;
        let fw = ProfileFirewall::default();
        // A DoH stream reset drops the answer while its ensure is in flight.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), ensure(&c, &fw, "3.3.3.3", 300))
                .await
                .is_err()
        );
        let k = pkey("192.168.1.10", "3.3.3.3");
        // The helper's ack still lands in the shadow map.
        assert!(until(Duration::from_secs(3), || c.live_exp(&k).is_some()).await);
        // And nothing is left in flight for the key.
        assert!(c.inflight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_refill_resends_every_live_key_however_many() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let n = 40_000u32;
        {
            let now = c.now_s();
            let mut sh = c.shadow();
            for i in 0..n {
                let k = FwKey {
                    set: SetId::P4,
                    src: Some("192.168.1.10".parse().unwrap()),
                    dst: IpAddr::from(std::net::Ipv4Addr::from(0x0b00_0000 + i)),
                };
                sh.upsert(k, now + 600, None, 1, now);
            }
        }
        let before = f.st().ensured.len();
        f.event(
            kind::RULES_REPAIRED,
            serde_json::json!({"missing": ["set picket4"], "gap_ms": 5, "recreated_sets": ["picket4"]}),
        );
        // Every key counts as absent until its own re-send is acked.
        assert!(until(Duration::from_secs(5), || c.unconfirmed_count() > 0).await);
        assert!(
            until(Duration::from_secs(60), || f.st().ensured.len()
                >= before + n as usize)
            .await,
            "re-sent {} of {n}",
            f.st().ensured.len() - before
        );
        assert!(until(Duration::from_secs(10), || c.unconfirmed_count() == 0).await);
        assert_eq!(c.dropped_ops.load(Relaxed), 0, "nothing dropped at the queue");
    }

    #[test]
    fn reconcile_tolerates_five_seconds_either_way_and_compares_seeded_entries() {
        let mut sh = Shadow::default();
        let now = 1000;
        let (lapsed, ending, seeded, fresh, gone) = (
            pkey("192.168.1.10", "1.0.0.1"),
            pkey("192.168.1.10", "1.0.0.2"),
            pkey("192.168.1.10", "1.0.0.3"),
            pkey("192.168.1.10", "1.0.0.4"),
            pkey("192.168.1.10", "1.0.0.5"),
        );
        // Lapsed in the shadow map a second ago; the kernel still holds it a second or two.
        sh.upsert(lapsed, now - 1, None, 1, 900);
        // Two seconds left in the shadow map; the kernel let it go already.
        sh.upsert(ending, now + 2, None, 1, 900);
        // Seeded (never changed by the edge) and over the cap in the kernel: trimmed.
        sh.upsert(seeded, now + 420, None, 1, now);
        sh.mark_seeded(&seeded);
        // Changed after the dump began: doesn't count.
        sh.upsert(fresh, now + 300, None, 1, now);
        // Lapsed long ago in the shadow map, still in the kernel: unknown.
        sh.upsert(gone, now - 60, None, 1, 900);
        let kernel = vec![(
            SetId::P4,
            vec![(lapsed, 2), (seeded, 100_000), (fresh, 5), (gone, 200)],
        )];
        let d = reconcile_diff(&sh, &kernel, now, now, &Default::default());
        assert_eq!((d.missing, d.unknown, d.longer), (0, 1, 1), "{d:?}");
        assert_eq!(d.deletes, vec![gone]);
        assert_eq!(d.ensures, vec![(seeded, 420)]);
        // Missing and well short of its expiry: ensured.
        let kernel = vec![(
            SetId::P4,
            vec![(lapsed, 2), (seeded, 420), (fresh, 5), (gone, 200)],
        )];
        sh.upsert(ending, now + 60, None, 1, 900);
        let d = reconcile_diff(&sh, &kernel, now, now, &Default::default());
        assert_eq!((d.missing, d.unknown, d.longer), (1, 1, 0), "{d:?}");
        assert_eq!(d.ensures, vec![(ending, 60)]);
    }

    #[tokio::test]
    async fn the_reconcile_right_after_seeding_trims_entries_over_the_cap() {
        let f = fake(Duration::ZERO);
        // A kernel entry far longer than any profile allows (a revoked allow, a pre-NTP restore).
        f.st().dump.insert(
            sets::PICKET4.into(),
            vec![pkey("192.168.1.10", "5.5.5.5").entry(100_000)],
        );
        let c = client(&f.path);
        ready(&c).await;
        let cap = c.view().cap_s;
        assert!(
            until(Duration::from_secs(5), || f.st().ensured.iter().any(|e| e.dst
                == "5.5.5.5".parse::<IpAddr>().unwrap()
                && u64::from(e.timeout_s) <= cap + 1))
            .await,
            "trimmed to the cap ({cap} s): {:?}",
            f.st().ensured
        );
    }

    #[tokio::test]
    async fn own_entries_at_their_expiry_are_no_drift() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let dumps = f.st().dumps;
        assert!(until(Duration::from_secs(5), || f.st().dumps >= dumps + 4 || dumps >= 8).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (a, b) = (pkey("192.168.1.10", "6.6.6.6"), pkey("192.168.1.10", "7.7.7.7"));
        {
            let now = c.now_s();
            let mut sh = c.shadow();
            // `a` expires now; the kernel holds it a second or two longer (whole-second timeouts).
            sh.upsert(a, now + 1, None, 1, now);
            // `b` has two seconds left; the kernel has already let it go.
            sh.upsert(b, now + 4, None, 1, now);
            for k in [a, b] {
                sh.map.get_mut(&k).unwrap().changed = 0;
            }
        }
        f.st().dump.insert(sets::PICKET4.into(), vec![a.entry(2)]);
        tokio::time::sleep(Duration::from_millis(2100)).await;
        let dumps = f.st().dumps;
        c.reconcile_now.notify_one();
        assert!(until(Duration::from_secs(5), || f.st().dumps >= dumps + 4).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !c.conditions.is_set(condition_kind::FW_DRIFT, None),
            "{:?}",
            c.conditions.snapshot()
        );
        assert!(f.st().deleted.is_empty(), "{:?}", f.st().deleted);
    }

    #[tokio::test]
    async fn an_address_moving_to_another_device_drops_the_old_devices_ip_allow() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let (a, b) = ([0xaa, 0, 0, 0, 0, 1], [0xbb, 0, 0, 0, 0, 2]);
        let x: IpAddr = "192.168.1.50".parse().unwrap();
        c.neighbours.replace(&[(x, a)]);
        c.neighbour_event(NeighbourEvent::Gained { mac: a, ip: x });
        let a_text = crate::neighbours::format_mac(&a);
        let keys = c
            .grant_allow(&a_text, &[x], "100.100.100.100".parse().unwrap(), 600)
            .await
            .unwrap();
        let mut stored = crate::allows::tests::allow("a-1", picket_api::logs::AllowKind::Ip, 600);
        stored.device = a_text.clone();
        stored.client = x.to_string();
        stored.addresses = vec![x.to_string()];
        c.allows.upsert(stored).unwrap();
        assert!(c.live_exp(&keys[0]).is_some());
        // The address now belongs to device `b`.
        c.neighbours.replace(&[(x, b)]);
        c.neighbour_event(NeighbourEvent::Gained { mac: b, ip: x });
        assert!(c.live_exp(&keys[0]).is_none(), "b doesn't inherit a's allow");
        assert!(
            until(Duration::from_secs(3), || f
                .st()
                .deleted
                .iter()
                .any(|e| e.src == Some(x)))
            .await,
            "the kernel entry is deleted"
        );
        let a1 = c.allows.list().into_iter().find(|s| s.allow_id == "a-1").unwrap();
        assert!(!a1.addresses.contains(&x.to_string()), "{:?}", a1.addresses);
    }

    #[tokio::test]
    async fn a_move_revokes_kernel_entries_after_a_bypass_recheck_removed_the_address() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let (a, b) = ([0xaa, 0, 0, 0, 0, 1], [0xbb, 0, 0, 0, 0, 2]);
        let x: IpAddr = "192.168.1.50".parse().unwrap();
        c.neighbours.replace(&[(x, a)]);
        c.neighbour_event(NeighbourEvent::Gained { mac: a, ip: x });
        let a_text = crate::neighbours::format_mac(&a);
        let keys = c
            .grant_allow(&a_text, &[x], "100.100.100.100".parse().unwrap(), 600)
            .await
            .unwrap();
        let mut stored = crate::allows::tests::allow("a-1", picket_api::logs::AllowKind::Ip, 600);
        stored.device = a_text.clone();
        stored.client = x.to_string();
        stored.addresses = vec![x.to_string()];
        c.allows.upsert(stored).unwrap();
        assert!(c.live_exp(&keys[0]).is_some());
        // The bypass subscriber catches up first and forgets the moved address.
        // Firewall maintenance must still remove the kernel entry it owns.
        let mut rechecked = c.allows.list().into_iter().find(|s| s.allow_id == "a-1").unwrap();
        rechecked.addresses.clear();
        c.allows.change_held(vec![rechecked]).unwrap();
        // The address now belongs to device `b`.
        c.neighbours.replace(&[(x, b)]);
        c.neighbour_event(NeighbourEvent::Gained { mac: b, ip: x });
        assert!(c.live_exp(&keys[0]).is_none(), "b doesn't inherit a's allow");
        assert!(
            until(Duration::from_secs(3), || f
                .st()
                .deleted
                .iter()
                .any(|e| e.src == Some(x)))
            .await,
            "the kernel entry is deleted"
        );
        let a1 = c.allows.list().into_iter().find(|s| s.allow_id == "a-1").unwrap();
        assert!(!a1.addresses.contains(&x.to_string()), "{:?}", a1.addresses);
    }

    #[tokio::test]
    async fn a_move_revokes_allows_on_dns_keys_with_a_different_share_owner() {
        for share_text in ["192.168.1.50", "configured-client"] {
            for rechecked_first in [false, true] {
                let f = fake(Duration::ZERO);
                let c = client(&f.path);
                ready(&c).await;
                let (a, b) = ([0xaa, 0, 0, 0, 0, 1], [0xbb, 0, 0, 0, 0, 2]);
                let x: IpAddr = "192.168.1.50".parse().unwrap();
                let k = FwKey {
                    set: SetId::P4,
                    src: Some(x),
                    dst: "100.100.100.100".parse().unwrap(),
                };
                let share_owner = owner_of(share_text);
                let dns_exp = c.now_s() + 60;
                // DNS installed this key before the source MAC was known.
                c.shadow().upsert(k, dns_exp, None, share_owner, c.now_s());
                c.neighbours.replace(&[(x, a)]);
                let a_text = crate::neighbours::format_mac(&a);
                c.grant_allow(&a_text, &[x], k.dst, 600).await.unwrap();
                let mut stored =
                    crate::allows::tests::allow("mixed-owner", picket_api::logs::AllowKind::Ip, 600);
                stored.device = a_text;
                stored.addresses = vec![x.to_string()];
                c.allows.upsert(stored.clone()).unwrap();
                if rechecked_first {
                    stored.addresses.clear();
                    c.allows.change_held(vec![stored]).unwrap();
                }
                c.neighbours.replace(&[(x, b)]);
                c.neighbour_event(NeighbourEvent::Gained { mac: b, ip: x });
                {
                    let sh = c.shadow();
                    let e = sh.get(&k).unwrap();
                    assert_eq!((e.allow_exp, e.allow_owner), (0, None));
                    assert_eq!(e.dns_exp, dns_exp, "keep the original DNS lifetime");
                    assert_eq!(
                        e.owner, share_owner,
                        "share accounting stays with its original owner"
                    );
                    assert_eq!(sh.share_of(share_owner, k.set), 1);
                    assert_eq!(
                        sh.share_of(owner_of(&crate::neighbours::format_mac(&a)), k.set),
                        0
                    );
                }
                assert!(
                    until(Duration::from_secs(3), || ops_on(&f, &k)
                        .last()
                        .is_some_and(|(ensure, secs)| *ensure && *secs <= 60))
                    .await,
                    "the helper must lose the extended allow lifetime"
                );
            }
        }
    }

    #[tokio::test]
    async fn startup_catch_up_preserves_the_new_owners_shared_allow() {
        for old_dns_grant in [false, true] {
            let f = fake(Duration::ZERO);
            let c = client(&f.path);
            ready(&c).await;
            let (a, b, next) = (
                [0xaa, 0, 0, 0, 0, 1],
                [0xbb, 0, 0, 0, 0, 2],
                [0xcc, 0, 0, 0, 0, 3],
            );
            let x: IpAddr = "192.168.1.50".parse().unwrap();
            let k = FwKey {
                set: SetId::P4,
                src: Some(x),
                dst: "100.100.100.100".parse().unwrap(),
            };
            let a_text = crate::neighbours::format_mac(&a);
            let b_text = crate::neighbours::format_mac(&b);
            c.neighbours.replace(&[(x, a)]);
            if old_dns_grant {
                let now = c.now_s();
                let mut sh = c.shadow();
                sh.upsert(k, now + 900, None, owner_of(&a_text), now);
                sh.grant(a, k.set, k.dst, now + 900);
            }
            c.grant_allow(&a_text, &[x], k.dst, 600).await.unwrap();
            // Both grants precede maintenance's first subscription.
            c.neighbours.replace(&[(x, b)]);
            c.grant_allow(&b_text, &[x], k.dst, 1200).await.unwrap();
            c.neighbour_catch_up(&c.neighbours.snapshot());
            {
                let sh = c.shadow();
                let e = sh.get(&k).unwrap();
                assert_eq!(e.allow_owner, Some(owner_of(&b_text)));
                assert!(e.allow_exp >= c.now_s() + 1190, "B keeps its current allow");
                assert_eq!(e.dns_exp, 0, "A's DNS grant is gone");
                assert_eq!(sh.share_of(e.owner, k.set), 1);
            }
            assert!(!f.st().deleted.iter().any(|e| e.src == Some(x) && e.dst == k.dst));
            // The surviving allow is still revoked on the next move, without a stored record.
            c.neighbours.replace(&[(x, next)]);
            c.neighbour_event(NeighbourEvent::Gained { mac: next, ip: x });
            assert!(c.live_exp(&k).is_none());
            assert_eq!(c.shadow().fill(k.set), 0);
        }
    }

    #[tokio::test]
    async fn catch_up_revokes_an_intermediate_owners_allow() {
        let (a, b, next) = (
            [0xaa, 0, 0, 0, 0, 1],
            [0xbb, 0, 0, 0, 0, 2],
            [0xcc, 0, 0, 0, 0, 3],
        );
        for current in [a, next] {
            for old_dns_grant in [false, true] {
                let f = fake(Duration::ZERO);
                let c = client(&f.path);
                ready(&c).await;
                let x: IpAddr = "192.168.1.50".parse().unwrap();
                let k = FwKey {
                    set: SetId::P4,
                    src: Some(x),
                    dst: "100.100.100.100".parse().unwrap(),
                };
                let a_text = crate::neighbours::format_mac(&a);
                let b_text = crate::neighbours::format_mac(&b);
                c.neighbours.replace(&[(x, a)]);
                if old_dns_grant {
                    let now = c.now_s();
                    let mut sh = c.shadow();
                    sh.upsert(k, now + 60, None, owner_of(&a_text), now);
                    sh.grant(a, k.set, k.dst, now + 60);
                }
                c.grant_allow(&a_text, &[x], k.dst, 600).await.unwrap();
                c.neighbours.replace(&[(x, b)]);
                c.grant_allow(&b_text, &[x], k.dst, 1200).await.unwrap();
                let mut stored =
                    crate::allows::tests::allow("missed-owner", picket_api::logs::AllowKind::Ip, 1200);
                stored.device = b_text.clone();
                stored.target = k.dst.to_string();
                stored.addresses = vec![x.to_string()];
                c.allows.upsert(stored.clone()).unwrap();
                // Neither move has been processed: the recorded owner is still A.
                c.neighbours.replace(&[(x, current)]);
                c.neighbour_catch_up(&c.neighbours.snapshot());
                assert!(
                    c.shadow()
                        .get(&k)
                        .is_none_or(|e| e.allow_exp == 0 && e.allow_owner.is_none())
                );
                assert!(
                    c.allows
                        .list()
                        .iter()
                        .find(|a| a.allow_id == "missed-owner")
                        .unwrap()
                        .addresses
                        .is_empty()
                );
                // Neither a delayed B event nor replay of stale on-disk data can restore it.
                c.neighbour_event(NeighbourEvent::Gained { mac: b, ip: x });
                c.allows.upsert(stored).unwrap();
                c.replay_allows();
                assert!(
                    c.shadow()
                        .get(&k)
                        .is_none_or(|e| e.allow_exp == 0 && e.allow_owner.is_none())
                );
                assert!(c.grant_allow(&b_text, &[x], k.dst, 1200).await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn failed_grants_never_restore_access_revoked_by_a_move() {
        let (a, b) = ([0xaa, 0, 0, 0, 0, 1], [0xbb, 0, 0, 0, 0, 2]);
        for replacement in [a, b] {
            for old_dns_grant in [false, true] {
                let f = fake(Duration::ZERO);
                let c = client(&f.path);
                ready(&c).await;
                let x: IpAddr = "192.168.1.50".parse().unwrap();
                let other: IpAddr = "192.168.1.51".parse().unwrap();
                let k = FwKey {
                    set: SetId::P4,
                    src: Some(x),
                    dst: "100.100.100.100".parse().unwrap(),
                };
                let a_text = crate::neighbours::format_mac(&a);
                let replacement_text = crate::neighbours::format_mac(&replacement);
                let dns_exp = c.now_s() + 60;
                c.shadow()
                    .upsert(k, dns_exp, None, owner_of("address-before-discovery"), c.now_s());
                if old_dns_grant {
                    c.shadow().grant(a, k.set, k.dst, dns_exp);
                }
                c.neighbours.replace(&[(x, a)]);
                c.grant_allow(&a_text, &[x], k.dst, 600).await.unwrap();
                c.neighbours.replace(&[(x, replacement)]);
                f.st().fail_src = vec![other];
                f.st().delay = Duration::from_millis(150);
                let (result, ()) = tokio::join!(
                    c.grant_allow(&replacement_text, &[x, other], k.dst, 1200),
                    async {
                        assert!(
                            until(Duration::from_secs(3), || c
                                .shadow()
                                .get(&k)
                                .is_some_and(|e| e.allow_exp > c.now_s() + 1100))
                            .await
                        );
                        // The grant is waiting for acks when maintenance revokes A's access.
                        c.neighbours.replace(&[(x, b)]);
                        c.neighbour_event(NeighbourEvent::Gained { mac: b, ip: x });
                    }
                );
                assert!(result.is_err());
                assert!(
                    c.shadow()
                        .get(&k)
                        .is_none_or(|e| e.allow_exp == 0 && e.allow_owner.is_none() && e.exp() <= dns_exp)
                );
                assert!(
                    until(Duration::from_secs(3), || ops_on(&f, &k)
                        .last()
                        .is_some_and(|(ensure, secs)| !ensure || *secs <= 60))
                    .await,
                    "the helper must not regain A's saved 600-second allow"
                );
            }
        }
    }

    #[tokio::test]
    async fn maintenance_catches_a_move_before_it_subscribes() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let (a, b) = ([0xaa, 0, 0, 0, 0, 1], [0xbb, 0, 0, 0, 0, 2]);
        let x: IpAddr = "192.168.1.50".parse().unwrap();
        c.neighbours.replace(&[(x, a)]);
        // The first Gained event, as well as the later move, predates maintenance.
        let a_text = crate::neighbours::format_mac(&a);
        let keys = c
            .grant_allow(&a_text, &[x], "100.100.100.100".parse().unwrap(), 600)
            .await
            .unwrap();
        let mut stored = crate::allows::tests::allow("early-grant", picket_api::logs::AllowKind::Ip, 600);
        stored.device = a_text;
        stored.client = x.to_string();
        stored.addresses = vec![x.to_string()];
        c.allows.upsert(stored).unwrap();
        assert!(c.live_exp(&keys[0]).is_some());
        // No maintenance receiver exists yet, so this move cannot report channel lag.
        c.neighbours.replace(&[(x, b)]);
        let task = tokio::spawn(Arc::clone(&c).run_maintenance(Arc::clone(&c.neighbours)));
        assert!(
            until(Duration::from_secs(3), || c.live_exp(&keys[0]).is_none()
                && f.st().deleted.iter().any(|e| e.src == Some(x)))
            .await,
            "startup catch-up revokes the old owner's kernel entry"
        );
        task.abort();
    }

    #[tokio::test]
    async fn grants_only_follow_entries_within_the_share() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let m: Mac = [0xaa, 0, 0, 0, 0, 3];
        let (x, y): (IpAddr, IpAddr) = ("192.168.1.60".parse().unwrap(), "192.168.1.61".parse().unwrap());
        c.neighbours.replace(&[(x, m)]);
        c.neighbour_event(NeighbourEvent::Gained { mac: m, ip: x });
        let owner = owner_of(&crate::neighbours::format_mac(&m));
        {
            // The device holds its whole share of picket4 already.
            let now = c.now_s();
            let mut sh = c.shadow();
            for i in 0..SHARE {
                let k = FwKey {
                    set: SetId::P4,
                    src: Some(x),
                    dst: IpAddr::from(std::net::Ipv4Addr::from(0x0c00_0000 + i)),
                };
                sh.upsert(k, now + 600, None, owner, now);
            }
        }
        let dev = DeviceKey::Mac(m);
        let fw = ProfileFirewall::default();
        let addrs = [FwAddr {
            ip: "8.8.4.4".parse().unwrap(),
            client_ttl: 300,
        }];
        c.ensure(&FwRequest {
            client: x,
            device: &dev,
            profile: "p",
            firewall: &fw,
            addrs: &addrs,
        })
        .await;
        let now = c.now_s();
        assert!(
            !c.shadow()
                .grants_of(&m, now)
                .iter()
                .any(|(_, d, _)| *d == "8.8.4.4".parse::<IpAddr>().unwrap()),
            "no grant for an entry over the share"
        );
        // A new address backfills nothing past the share.
        c.neighbours.replace(&[(x, m), (y, m)]);
        c.neighbour_event(NeighbourEvent::Gained { mac: m, ip: y });
        assert!(c.shadow().share_of(owner, SetId::P4) <= SHARE);
    }

    #[tokio::test]
    async fn a_helper_speaking_another_protocol_gets_no_ensure_and_stops_the_edge() {
        let f = fake(Duration::ZERO);
        f.st().proto = PROTO_VERSION + 1;
        let (c, ctl) = client_h(&f.path);
        let _ = c.prepare(&cfg(50)).await;
        c.config_active(&cfg(50));
        let fw = ProfileFirewall::default();
        let _ = ensure(&c, &fw, "4.4.4.4", 300).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            f.ensures.load(Relaxed),
            0,
            "no ensure on an unverified connection"
        );
        // edge-firewall.md §4: a mismatch makes the edge refuse to start (a critical task ends).
        let r = tokio::time::timeout(Duration::from_secs(5), ctl).await;
        assert!(matches!(r, Ok(Ok(Err(_)))), "{r:?}");
    }

    #[tokio::test]
    async fn an_answer_that_times_out_isnt_taken_for_granted_and_a_reconnect_reconciles() {
        let f = fake(Duration::from_millis(300));
        let c = client(&f.path);
        c.prepare(&cfg(50)).await.unwrap();
        c.config_active(&cfg(50));
        assert!(until(Duration::from_secs(5), || c.seeded.load(Relaxed)).await);
        let fw = ProfileFirewall::default();
        let o = ensure(&c, &fw, "2.2.2.2", 300).await;
        assert!(o.late);
        let k = pkey("192.168.1.10", "2.2.2.2");
        assert!(c.live_exp(&k).is_none(), "not in the shadow map before the ack");
        assert!(
            until(Duration::from_secs(3), || c.live_exp(&k).is_some()).await,
            "the ack lands"
        );
        // The helper restarts: the edge reconnects and reconciles at once.
        tokio::time::sleep(Duration::from_millis(300)).await;
        f.st().delay = Duration::ZERO;
        let dumps = f.st().dumps;
        f.restart();
        assert!(
            until(Duration::from_secs(5), || f.st().dumps >= dumps + 4).await,
            "a reconcile after the reconnect"
        );
    }

    fn ip4(n: u32) -> IpAddr {
        IpAddr::from(std::net::Ipv4Addr::from(n))
    }

    /// The helper's ops on `k`, in order: (ensure?, timeout).
    fn ops_on(f: &Fake, k: &FwKey) -> Vec<(bool, u32)> {
        f.st()
            .log
            .iter()
            .filter(|(_, e)| e.src == k.src && e.dst == k.dst && e.set == k.set.name())
            .map(|(e, x)| (*e, x.timeout_s))
            .collect()
    }

    /// Fills the fast queue while the helper sits on a slow request.
    async fn saturate(c: &FwClient, f: &Fake) {
        f.st().delay = Duration::from_secs(3);
        let filler = |i: u32| FwKey {
            set: SetId::P4,
            src: Some("10.255.0.1".parse().unwrap()),
            dst: ip4(0x0d00_0000 + i),
        };
        // The fast task takes the first batch and waits on the helper.
        let _ = c
            .fast_tx
            .try_send(FwClient::op(OpKind::Delete, filler(0), 1, None));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut i = 1;
        while c
            .fast_tx
            .try_send(FwClient::op(OpKind::Delete, filler(i), 1, None))
            .is_ok()
        {
            i += 1;
        }
        assert!(c.fast_tx.capacity() == 0, "the queue is full");
    }

    /// Runs `f` on another thread; true when it returned within `t` (a deadlock never does).
    fn returns_within(t: Duration, f: impl FnOnce() + Send + 'static) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        rx.recv_timeout(t).is_ok()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_full_queue_never_deadlocks_a_shortened_allow() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let k = pkey("192.168.1.10", "100.64.0.1");
        {
            let now = c.now_s();
            c.shadow().upsert(k, now + 10, Some(now + 600), 1, now);
        }
        saturate(&c, &f).await;
        let c2 = Arc::clone(&c);
        assert!(
            returns_within(Duration::from_secs(2), move || c2.set_allow(&[k], Some(60))),
            "set_allow returns with the queue full"
        );
        assert!(returns_within(Duration::from_secs(2), {
            let c = Arc::clone(&c);
            move || {
                c.live_exp(&k);
            }
        }));
        assert!(
            c.shadow().get(&k).unwrap().unconfirmed,
            "its ensure didn't go out"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_full_queue_never_deadlocks_the_allow_replay() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let mut a = crate::allows::tests::allow("a-9", picket_api::logs::AllowKind::Ip, 600);
        a.target = "100.64.0.2".into();
        a.addresses = vec!["192.168.1.10".into()];
        c.allows.upsert(a).unwrap();
        saturate(&c, &f).await;
        let c2 = Arc::clone(&c);
        assert!(
            returns_within(Duration::from_secs(2), move || c2.replay_allows()),
            "replay_allows returns with the queue full"
        );
        let k = pkey("192.168.1.10", "100.64.0.2");
        assert!(c.shadow().get(&k).unwrap().unconfirmed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_full_queue_never_deadlocks_a_neighbour_backfill() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let m: Mac = [0xaa, 0, 0, 0, 0, 9];
        let (x, y): (IpAddr, IpAddr) = ("192.168.1.70".parse().unwrap(), "192.168.1.71".parse().unwrap());
        c.neighbours.replace(&[(x, m)]);
        c.neighbour_event(NeighbourEvent::Gained { mac: m, ip: x });
        {
            let now = c.now_s();
            c.shadow()
                .grant(m, SetId::P4, "100.64.0.3".parse().unwrap(), now + 300);
        }
        saturate(&c, &f).await;
        c.neighbours.replace(&[(x, m), (y, m)]);
        let c2 = Arc::clone(&c);
        assert!(
            returns_within(Duration::from_secs(2), move || c2
                .neighbour_event(NeighbourEvent::Gained { mac: m, ip: y })),
            "the backfill returns with the queue full"
        );
        let k = FwKey {
            set: SetId::P4,
            src: Some(y),
            dst: "100.64.0.3".parse().unwrap(),
        };
        assert!(c.shadow().get(&k).unwrap().unconfirmed);
    }

    /// A recreated set's re-send goes out a chunk at a time; an answer extending a key of a later
    /// chunk meanwhile isn't shortened again by it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refill_chunk_never_shortens_what_an_answer_extended() {
        let f = fake(Duration::from_millis(10));
        let c = client(&f.path);
        ready(&c).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = c.now_s();
        {
            let mut sh = c.shadow();
            for i in 0..3000u32 {
                let k = FwKey {
                    set: SetId::P4,
                    src: Some("192.168.1.10".parse().unwrap()),
                    dst: ip4(0x0b00_0000 + i),
                };
                sh.upsert(k, now + 600, None, 1, now);
            }
        }
        // The refill's order: the last key goes out in the last chunk.
        let last = c.shadow().live_keys(SetId::P4, now).last().unwrap().0;
        f.event(
            kind::RULES_REPAIRED,
            serde_json::json!({"missing": ["set picket4"], "gap_ms": 5, "recreated_sets": ["picket4"]}),
        );
        assert!(until(Duration::from_secs(5), || c.unconfirmed_count() > 0).await);
        let fw = ProfileFirewall::default();
        ensure(&c, &fw, &last.dst.to_string(), 3000).await;
        assert!(
            until(Duration::from_secs(5), || c
                .live_exp(&last)
                .is_some_and(|e| e > now + 1000))
            .await
        );
        assert!(until(Duration::from_secs(60), || c.unconfirmed_count() == 0).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let left = c.live_exp(&last).unwrap() - c.now_s();
        let ops = ops_on(&f, &last);
        let (is_e, t) = *ops.last().unwrap();
        assert!(
            is_e && u64::from(t) + 10 >= left,
            "kernel last set to {t} s while the shadow map holds {left} s: {ops:?}"
        );
    }

    /// The reconcile's deletes go out a chunk at a time; a key an answer took up meanwhile isn't
    /// deleted afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reconcile_chunk_never_deletes_a_key_an_answer_took_up() {
        let f = fake(Duration::from_millis(10));
        let c = client(&f.path);
        ready(&c).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let n = 3000u32;
        let keys: Vec<FwKey> = (0..n)
            .map(|i| FwKey {
                set: SetId::P4,
                src: Some("192.168.1.10".parse().unwrap()),
                dst: ip4(0x0c00_0000 + i),
            })
            .collect();
        f.st()
            .dump
            .insert(sets::PICKET4.into(), keys.iter().map(|k| k.entry(300)).collect());
        let last = *keys.last().unwrap();
        c.reconcile_now.notify_one();
        assert!(until(Duration::from_secs(10), || !f.st().deleted.is_empty()).await);
        let fw = ProfileFirewall::default();
        ensure(&c, &fw, &last.dst.to_string(), 300).await;
        assert!(until(Duration::from_secs(5), || c.live_exp(&last).is_some()).await);
        assert!(until(Duration::from_secs(60), || f.st().deleted.len() >= n as usize - 1).await);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let ops = ops_on(&f, &last);
        assert!(
            ops.last().unwrap().0,
            "the kernel's last op on the key was a delete, yet the shadow map holds it: {ops:?}"
        );
    }

    /// A key revoked while its set's re-send is under way isn't reopened by a later chunk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refill_chunk_never_reopens_a_revoked_key() {
        let f = fake(Duration::from_millis(10));
        let c = client(&f.path);
        ready(&c).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = c.now_s();
        {
            let mut sh = c.shadow();
            for i in 0..3000u32 {
                let k = FwKey {
                    set: SetId::P4,
                    src: Some("192.168.1.10".parse().unwrap()),
                    dst: ip4(0x0e00_0000 + i),
                };
                // IP allows: no DNS grant keeps them.
                sh.upsert(k, 0, Some(now + 600), 1, now);
            }
        }
        let last = c.shadow().live_keys(SetId::P4, now).last().unwrap().0;
        f.event(
            kind::RULES_REPAIRED,
            serde_json::json!({"missing": ["set picket4"], "gap_ms": 5, "recreated_sets": ["picket4"]}),
        );
        assert!(until(Duration::from_secs(5), || c.unconfirmed_count() > 0).await);
        c.set_allow(&[last], None);
        assert!(c.live_exp(&last).is_none());
        assert!(until(Duration::from_secs(60), || c.unconfirmed_count() == 0).await);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let ops = ops_on(&f, &last);
        assert!(
            !ops.last().unwrap().0,
            "a revoked key was ensured again after its delete: {ops:?}"
        );
    }

    /// A device with two addresses; extending its allow succeeds for one and fails for the
    /// other: both kernel entries end at the previous expiry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_failed_allow_extension_puts_the_kernel_back_for_every_address() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let (x1, x2): (IpAddr, IpAddr) = ("192.168.1.80".parse().unwrap(), "192.168.1.81".parse().unwrap());
        let ip: IpAddr = "100.64.1.1".parse().unwrap();
        let keys = c.grant_allow("dev", &[x1, x2], ip, 600).await.unwrap();
        f.st().fail_src = vec![x2];
        let r = c.grant_allow("replacement-device", &[x1, x2], ip, 1200).await;
        assert!(r.is_err());
        tokio::time::sleep(Duration::from_millis(300)).await;
        for k in &keys {
            let left = c.live_exp(k).unwrap() - c.now_s();
            assert!((590..=601).contains(&left), "shadow map back at 600 s: {left}");
            assert_eq!(
                c.shadow().get(k).unwrap().allow_owner,
                Some(owner_of("dev")),
                "restore the previous granting device too"
            );
            if k.src == Some(x1) {
                let (is_e, t) = *ops_on(&f, k).last().unwrap();
                assert!(
                    is_e && (590..=601).contains(&t),
                    "kernel back at 600 s: {:?}",
                    ops_on(&f, k)
                );
            }
        }
        assert!(
            until(Duration::from_secs(3), || keys.iter().all(|k| !c
                .shadow()
                .get(k)
                .unwrap()
                .unconfirmed
                || k.src == Some(x2)))
            .await
        );
    }

    /// An extension whose ack comes too late returns an error and the kernel ends at the
    /// previous expiry, not the late one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_late_ack_for_a_failed_allow_extension_is_undone() {
        let f = fake(Duration::ZERO);
        let (c, _) = client_t(&f.path, |t| t.allow_ack = Duration::from_millis(200));
        ready(&c).await;
        let x: IpAddr = "192.168.1.82".parse().unwrap();
        let ip: IpAddr = "100.64.1.2".parse().unwrap();
        let keys = c.grant_allow("dev", &[x], ip, 600).await.unwrap();
        f.st().delay = Duration::from_millis(600);
        assert_eq!(
            c.grant_allow("dev", &[x], ip, 1200).await.unwrap_err(),
            "no ack from the helper in time"
        );
        assert!(until(Duration::from_secs(5), || ops_on(&f, &keys[0]).len() >= 3).await);
        tokio::time::sleep(Duration::from_millis(800)).await;
        let ops = ops_on(&f, &keys[0]);
        let (is_e, t) = *ops.last().unwrap();
        assert!(is_e && (590..=601).contains(&t), "kernel back at 600 s: {ops:?}");
    }

    /// Two answers for one new key at once: the second, with the longer lifetime, waits on the
    /// first's ack and its expiry follows.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_coalesced_answer_keeps_its_longer_lifetime() {
        let f = fake(Duration::from_millis(200));
        let c = client(&f.path);
        ready(&c).await;
        let fw = ProfileFirewall::default();
        let k = pkey("192.168.1.10", "100.64.2.1");
        let (a, b) = tokio::join!(ensure(&c, &fw, "100.64.2.1", 1), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            ensure(&c, &fw, "100.64.2.1", 300).await
        });
        assert_eq!((a.added, a.late, b.late), (1, false, false));
        assert!(until(Duration::from_secs(3), || ops_on(&f, &k).len() >= 2).await);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let left = c.live_exp(&k).unwrap() - c.now_s();
        assert!((410..=421).contains(&left), "shadow map at 300 + 120 s: {left}");
        let ops = ops_on(&f, &k);
        let (is_e, t) = *ops.last().unwrap();
        assert!(is_e && (410..=421).contains(&t), "kernel at 300 + 120 s: {ops:?}");
        assert!(!c.shadow().get(&k).unwrap().unconfirmed);
    }

    /// Keys still waiting for their ack count against the client's share: one answer with ten
    /// new destinations, one place left, adds one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn keys_waiting_for_their_ack_count_against_the_share() {
        let f = fake(Duration::from_millis(100));
        let c = client(&f.path);
        ready(&c).await;
        let client_ip: IpAddr = "192.168.1.10".parse().unwrap();
        let dev = DeviceKey::Addr(client_ip);
        let owner = dev.with_text(owner_of);
        {
            let now = c.now_s();
            let mut sh = c.shadow();
            for i in 0..SHARE - 1 {
                let k = FwKey {
                    set: SetId::P4,
                    src: Some(client_ip),
                    dst: ip4(0x0f00_0000 + i),
                };
                sh.upsert(k, now + 600, None, owner, now);
            }
        }
        let addrs: Vec<FwAddr> = (0..10u32)
            .map(|i| FwAddr {
                ip: ip4(0x6440_0300 + i),
                client_ttl: 300,
            })
            .collect();
        let fw = ProfileFirewall::default();
        let before = f.entries.load(Relaxed);
        let o = c
            .ensure(&FwRequest {
                client: client_ip,
                device: &dev,
                profile: "p",
                firewall: &fw,
                addrs: &addrs,
            })
            .await;
        assert_eq!(o.added, 1, "{o:?}");
        assert_eq!(f.entries.load(Relaxed) - before, 1, "one ensure went out");
        let sh = c.shadow();
        assert_eq!(sh.share_of(owner, SetId::P4), SHARE);
        assert_eq!(sh.pending_of(owner, SetId::P4), 0, "the reservation is settled");
    }

    /// A shadow entry that lapsed a moment ago survives the maintenance prune, so a reconcile
    /// right after doesn't take the kernel's entry (whole-second rounding) for an unknown one.
    #[tokio::test]
    async fn pruning_keeps_entries_the_kernel_may_still_hold() {
        let f = fake(Duration::ZERO);
        let c = client(&f.path);
        ready(&c).await;
        let dumps = f.st().dumps;
        assert!(until(Duration::from_secs(5), || f.st().dumps >= dumps + 4 || dumps >= 8).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let k = pkey("192.168.1.10", "100.64.4.1");
        {
            let now = c.now_s();
            let mut sh = c.shadow();
            sh.upsert(k, now + 1, None, 1, now);
            sh.map.get_mut(&k).unwrap().changed = 0;
        }
        f.st().dump.insert(sets::PICKET4.into(), vec![k.entry(2)]);
        tokio::time::sleep(Duration::from_millis(2100)).await;
        c.prune();
        let dumps = f.st().dumps;
        c.reconcile_now.notify_one();
        assert!(until(Duration::from_secs(5), || f.st().dumps >= dumps + 4).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(f.st().deleted.is_empty(), "{:?}", f.st().deleted);
        assert!(!c.conditions.is_set(condition_kind::FW_DRIFT, None));
    }
}
