//! The upstream pool (edge.md §6, §7): one actor per upstream (its transport, RTT statistics,
//! in-flight count and circuit breaker), groups with their strategy, and resolution: selection,
//! hedging, retries on another upstream, validation and scrubbing with picket-wire, and the
//! `upstream_down` condition.
//!
//! - **Selection:** `fastest` is power-of-two-choices on EWMA RTT and in-flight count; `failover`
//!   takes the first healthy upstream in order.
//! - **Hedge:** if no answer arrives by the upstream's p90 RTT (bounded to 50–250 ms), the query
//!   also goes to a different upstream and the first valid answer wins.
//! - **Failure:** a timeout, a transport error, an invalid answer or (owner decision S6) an answer
//!   with TC set over a stream (TCP, DoT, DoH, or a UDP upstream's TCP retry) fails that
//!   upstream; the query moves to another. An answer
//!   carrying EDE 3 is a failure only for a caller that must not get stale data (a client that set
//!   DO, edge.md §7 step 3), and doesn't count against health.
//! - **Health** is passive (README §2 "Health": only timeouts, transport errors and malformed
//!   answers count) plus a breaker per upstream. An answer refused for its size alone
//!   ([`Invalid::is_size_limit`]: too many records in a section, an RRset over
//!   `limits.max_rrset_records`) or for an SVCB/HTTPS record's RFC 9460-forbidden parameters
//!   ([`Invalid::BadSvcb`], one domain's data; [`Invalid::leaves_upstream_unjudged`]) fails the
//!   attempt (counted as invalid, the query moving on) without judging the upstream: the breaker is
//!   left as it was (no failure, so one large domain can't take a single-upstream group down; no
//!   success, so a refused reply never erases earlier failures or closes a half-open breaker), and
//!   a probe slot the attempt held goes back. A
//!   group whose upstreams are all unhealthy for 30 s holds `upstream_down` (key: the group). An
//!   upstream is healthy while its breaker is closed:
//!   a half-open one takes a query as its probe but counts as unhealthy until that probe
//!   succeeds, so a dead group no query reaches still holds `upstream_down` (a reading of
//!   edge.md §6, flagged for the owner).
//! - Configuration updates keep the actors (and their connections) of unchanged upstreams. A
//!   group whose upstreams or their settings changed gets a new generation, which the cache and
//!   coalescing keys carry (edge.md §8), so its old servers' answers are never reused.

pub mod doh;
pub mod stream;
pub mod tls;
pub mod transport;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use futures_util::stream::{FuturesUnordered, StreamExt};

use picket_api::edge_config::{EdgeConfig, GroupStrategy, Upstream as UpstreamCfg, UpstreamProtocol};
use picket_api::session::condition_kind;
use picket_wire::{AnswerLimits, Invalid, ScrubbedAnswer, SentQuery, WireName};

use crate::conditions::Conditions;
use crate::metrics::{Metrics, UpstreamCounters};
use transport::{Endpoint, Transport, TxError};

/// Most upstreams and groups read from a config (README §2 Bounded).
pub const MAX_UPSTREAMS: usize = 64;
pub const MAX_GROUP_SIZE: usize = 16;
/// One attempt's longest wait.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(2_000);
/// The longest one resolution takes, retries and hedges included.
pub const RESOLVE_BUDGET: Duration = Duration::from_millis(3_500);
/// Hedge bounds (edge.md §6).
pub const HEDGE_MIN: Duration = Duration::from_millis(50);
pub const HEDGE_MAX: Duration = Duration::from_millis(250);
/// A group unhealthy this long holds `upstream_down` (edge.md §6).
pub const DOWN_AFTER: Duration = Duration::from_secs(30);
/// Consecutive failures that open an upstream's breaker.
pub const BREAKER_FAILURES: u32 = 3;
const BREAKER_OPEN_MIN: Duration = Duration::from_secs(5);
const BREAKER_OPEN_MAX: Duration = Duration::from_secs(60);
const RTT_SAMPLES: usize = 128;

/// The last upstream failure, as the EDE `cause=` token names it (edge.md §4 EDE).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cause {
    Timeout,
    Invalid,
    /// An upstream's stale answer, withheld from a client that set DO.
    Stale,
    Connect,
    /// Every upstream unhealthy.
    Down,
}

impl Cause {
    pub fn as_str(self) -> &'static str {
        match self {
            Cause::Timeout => "timeout",
            Cause::Invalid => "invalid",
            Cause::Stale => "stale",
            Cause::Connect => "connect",
            Cause::Down => "down",
        }
    }
}

/// RTT statistics: an EWMA and recent-sample percentiles.
struct RttStats {
    ewma_us: AtomicU64,
    p90_us: AtomicU64,
    p99_us: AtomicU64,
    samples: Mutex<(VecDeque<u32>, u32)>,
}

impl RttStats {
    fn new() -> Self {
        Self {
            ewma_us: AtomicU64::new(0),
            p90_us: AtomicU64::new(0),
            p99_us: AtomicU64::new(0),
            samples: Mutex::new((VecDeque::with_capacity(RTT_SAMPLES), 0)),
        }
    }

    fn record(&self, rtt: Duration) {
        let us32 = u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX);
        let us = u64::from(us32);
        let old = self.ewma_us.load(Relaxed);
        let new = if old == 0 { us } else { (old * 7 + us) / 8 };
        self.ewma_us.store(new.max(1), Relaxed);
        let mut g = self.samples.lock().unwrap_or_else(|p| p.into_inner());
        if g.0.len() == RTT_SAMPLES {
            g.0.pop_front();
        }
        g.0.push_back(us32);
        g.1 = g.1.wrapping_add(1);
        if g.1 % 16 == 1 || g.0.len() < 16 {
            let mut v: Vec<u32> = g.0.iter().copied().collect();
            v.sort_unstable();
            let pct = |p: usize| v[(v.len() * p / 100).min(v.len() - 1)];
            self.p90_us.store(u64::from(pct(90)), Relaxed);
            self.p99_us.store(u64::from(pct(99)), Relaxed);
        }
    }

    fn p90(&self) -> Option<Duration> {
        match self.p90_us.load(Relaxed) {
            0 => None,
            us => Some(Duration::from_micros(us)),
        }
    }

    fn p99(&self) -> Option<Duration> {
        match self.p99_us.load(Relaxed) {
            0 => None,
            us => Some(Duration::from_micros(us)),
        }
    }
}

#[derive(Debug)]
struct BreakerState {
    failures: u32,
    open_until: Option<Instant>,
    open_for: Duration,
    probing: bool,
}

/// The circuit breaker of one upstream.
struct Breaker(Mutex<BreakerState>);

impl Breaker {
    fn new() -> Self {
        Breaker(Mutex::new(BreakerState {
            failures: 0,
            open_until: None,
            open_for: BREAKER_OPEN_MIN,
            probing: false,
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BreakerState> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Healthy (edge.md §6 Health: `upstream_down`, `status`): closed. An open breaker whose time
    /// is up stays unhealthy until its probe succeeds: health is passive (README §2), so only a
    /// query's answer shows the upstream works again, and the open time (5–60 s) never resets the
    /// group's 30 s `upstream_down` timer.
    fn healthy(&self) -> bool {
        self.lock().open_until.is_none()
    }

    /// May take a query now: closed, or open with its time up and its probe slot free
    /// (half-open, one probe).
    fn selectable(&self, now: Instant) -> bool {
        let g = self.lock();
        match g.open_until {
            None => true,
            Some(t) => now >= t && !g.probing,
        }
    }

    /// Admits a query: `Some(false)` while closed, `Some(true)` taking the half-open probe slot,
    /// `None` while open (or another probe runs).
    fn admit(&self, now: Instant) -> Option<bool> {
        let mut g = self.lock();
        match g.open_until {
            None => Some(false),
            Some(t) if now >= t && !g.probing => {
                g.probing = true;
                Some(true)
            }
            Some(_) => None,
        }
    }

    fn success(&self) {
        let mut g = self.lock();
        g.failures = 0;
        g.open_until = None;
        g.open_for = BREAKER_OPEN_MIN;
        g.probing = false;
    }

    fn failure(&self, now: Instant) {
        let mut g = self.lock();
        g.failures = g.failures.saturating_add(1);
        if g.probing || g.open_until.is_some() {
            g.open_for = if g.probing {
                (g.open_for * 2).min(BREAKER_OPEN_MAX)
            } else {
                g.open_for
            };
            g.open_until = Some(now + g.open_for);
            g.probing = false;
        } else if g.failures >= BREAKER_FAILURES {
            g.open_until = Some(now + g.open_for);
        }
    }

    /// Releases a probe slot that ended without a verdict (a cancelled attempt).
    fn release_probe(&self) {
        self.lock().probing = false;
    }
}

/// Gives a half-open breaker's probe slot back when its attempt is dropped before it judged the
/// upstream (a hedge that lost, a resolution past its budget).
struct ProbeGuard {
    u: Arc<Upstream>,
    active: bool,
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        if self.active {
            self.u.breaker.release_probe();
        }
    }
}

/// One upstream's actor.
pub struct Upstream {
    pub id: Arc<str>,
    pub cfg: UpstreamCfg,
    transport: Arc<Transport>,
    rtt: RttStats,
    breaker: Breaker,
    inflight: AtomicU32,
    pub counters: Arc<UpstreamCounters>,
}

impl Upstream {
    fn new(id: &str, cfg: &UpstreamCfg, metrics: &Metrics) -> anyhow::Result<Arc<Self>> {
        let ep = Endpoint {
            protocol: cfg.protocol,
            ip: cfg.ip,
            port: cfg.port,
            tls_host: cfg.tls_host.clone(),
            trust_store: cfg.trust_store.clone(),
            path: cfg.path.clone(),
        };
        Ok(Arc::new(Self {
            id: id.into(),
            cfg: cfg.clone(),
            transport: Transport::new(&ep)?,
            rtt: RttStats::new(),
            breaker: Breaker::new(),
            inflight: AtomicU32::new(0),
            counters: metrics.upstream.get(id),
        }))
    }

    /// Its breaker is closed ([`Breaker::healthy`]).
    pub fn healthy(&self) -> bool {
        self.breaker.healthy()
    }

    pub fn encrypted(&self) -> bool {
        self.cfg.protocol.is_encrypted()
    }

    fn score(&self) -> u64 {
        let rtt = match self.rtt.ewma_us.load(Relaxed) {
            0 => 1_000,
            v => v,
        };
        rtt.saturating_mul(u64::from(self.inflight.load(Relaxed)) + 1)
    }

    fn hedge_after(&self) -> Duration {
        self.rtt
            .p90()
            .unwrap_or(HEDGE_MAX / 2)
            .clamp(HEDGE_MIN, HEDGE_MAX)
    }
}

/// `udp`/`tcp` upstreams only to private or loopback IPs (edge.md §6).
pub fn plain_allowed(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback() || picket_wire::reverse::is_private(ip)
}

/// One group.
pub struct Group {
    pub id: Arc<str>,
    pub upstreams: Vec<Arc<Upstream>>,
    pub strategy: GroupStrategy,
    pub optimistic: bool,
    /// All encrypted (DoT/DoH): queries set DO=1 (edge.md §6).
    pub encrypted: bool,
    /// Changes whenever the group's upstreams, or any of their settings, change: part of the
    /// cache and coalescing keys.
    pub generation: u64,
}

/// What a resolution asks for.
#[derive(Clone, Debug)]
pub struct ResolveRequest {
    pub group: Arc<str>,
    pub qname: WireName,
    pub qtype: u16,
    pub qclass: u16,
    /// The upstream DO (edge.md §6).
    pub do_up: bool,
    pub cd: bool,
    /// Don't use this upstream (a DO client retrying after its stale answer).
    pub exclude: Option<Arc<str>>,
    /// An answer carrying EDE 3 fails its upstream (for a client that set DO).
    pub reject_stale: bool,
}

/// A checked and scrubbed upstream answer.
pub struct Resolved {
    pub answer: ScrubbedAnswer,
    pub upstream: Arc<str>,
    pub rtt: Duration,
}

/// Why no upstream answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub cause: Cause,
}

enum Attempt {
    Ok(Box<Resolved>),
    Fail(Arc<Upstream>, Cause),
    /// Failed the query without judging the upstream: its breaker is untouched, and a probe slot
    /// the attempt held is given back.
    Unjudged(Arc<Upstream>, Cause),
}

/// Group → its upstreams' settings (sorted by id) and its generation.
type GroupGens = HashMap<String, (Vec<(String, UpstreamCfg)>, u64)>;

/// The pool.
pub struct UpstreamPool {
    upstreams: ArcSwap<HashMap<String, Arc<Upstream>>>,
    groups: ArcSwap<HashMap<String, Arc<Group>>>,
    metrics: Arc<Metrics>,
    conditions: Arc<Conditions>,
    /// Group → when it became all-unhealthy.
    down_since: Mutex<HashMap<String, Instant>>,
    /// Group → its upstreams' settings (sorted by id) and its generation.
    gens: Mutex<GroupGens>,
    next_gen: AtomicU64,
    /// Attempt timeout (tests shorten it).
    pub attempt_timeout: Duration,
    pub budget: Duration,
    /// How long a group stays all-unhealthy before `upstream_down` (30 s; tests shorten it).
    pub down_after: Duration,
    /// `limits.max_rrset_records` from the config (0: no per-RRset limit).
    max_rrset: AtomicU32,
}

impl UpstreamPool {
    pub fn new(metrics: Arc<Metrics>, conditions: Arc<Conditions>) -> Arc<Self> {
        Arc::new(Self {
            upstreams: ArcSwap::from_pointee(HashMap::new()),
            groups: ArcSwap::from_pointee(HashMap::new()),
            metrics,
            conditions,
            down_since: Mutex::new(HashMap::new()),
            gens: Mutex::new(HashMap::new()),
            next_gen: AtomicU64::new(1),
            attempt_timeout: ATTEMPT_TIMEOUT,
            budget: RESOLVE_BUDGET,
            down_after: DOWN_AFTER,
            max_rrset: AtomicU32::new(picket_api::edge_config::Limits::default().max_rrset_records),
        })
    }

    /// The answer limits for upstream answers: the configured per-RRset limit.
    fn answer_limits(&self) -> AnswerLimits {
        let max = self.max_rrset.load(Relaxed);
        AnswerLimits {
            // Past u16 is past the section bound anyway.
            max_rrset: (max != 0).then(|| u16::try_from(max).unwrap_or(u16::MAX)),
            ..AnswerLimits::default()
        }
    }

    /// Applies a config: unchanged upstreams keep their actor. Returns warnings for items it
    /// refused (a plain upstream to a public IP, a group mixing plain and encrypted upstreams or
    /// naming an unknown one).
    pub fn configure(&self, cfg: &EdgeConfig) -> Vec<String> {
        let mut warnings = vec![];
        self.max_rrset.store(cfg.limits.max_rrset_records, Relaxed);
        let old = self.upstreams.load_full();
        let mut next: HashMap<String, Arc<Upstream>> = HashMap::new();
        for (id, u) in cfg.upstreams.iter().take(MAX_UPSTREAMS) {
            if !u.protocol.is_encrypted() && !plain_allowed(u.ip) {
                warnings.push(format!(
                    "upstream {id}: {:?} only to private or loopback IPs",
                    u.protocol
                ));
                continue;
            }
            if u.port == 0 {
                warnings.push(format!("upstream {id}: port 0"));
                continue;
            }
            if let Some(o) = old.get(id).filter(|o| o.cfg == *u) {
                next.insert(id.clone(), Arc::clone(o));
                continue;
            }
            match Upstream::new(id, u, &self.metrics) {
                Ok(up) => {
                    next.insert(id.clone(), up);
                }
                Err(e) => warnings.push(format!("upstream {id}: {}", crate::diag::cap_chain(&e))),
            }
        }
        let mut groups = HashMap::new();
        let mut gens = self.gens.lock().unwrap_or_else(|p| p.into_inner());
        let mut next_gens = HashMap::new();
        for (gid, g) in &cfg.upstream_groups {
            let mut ups = vec![];
            let mut bad = false;
            for uid in g.upstreams.iter().take(MAX_GROUP_SIZE) {
                match next.get(uid) {
                    Some(u) => {
                        if !ups.iter().any(|x: &Arc<Upstream>| x.id == u.id) {
                            ups.push(Arc::clone(u));
                        }
                    }
                    None => {
                        warnings.push(format!("group {gid}: upstream {uid} isn't usable"));
                    }
                }
            }
            let enc = ups.iter().filter(|u| u.encrypted()).count();
            if enc != 0 && enc != ups.len() {
                // core refuses such a group on save (core.md §2); so does the edge.
                warnings.push(format!(
                    "group {gid} mixes plain and encrypted upstreams: refused"
                ));
                bad = true;
            }
            if bad {
                continue;
            }
            let mut members: Vec<(String, UpstreamCfg)> =
                ups.iter().map(|u| (u.id.to_string(), u.cfg.clone())).collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            let generation = match gens.remove(gid) {
                Some((m, generation)) if m == members => generation,
                _ => self.next_gen.fetch_add(1, Relaxed),
            };
            groups.insert(
                gid.clone(),
                Arc::new(Group {
                    id: gid.as_str().into(),
                    encrypted: !ups.is_empty() && enc == ups.len(),
                    upstreams: ups,
                    strategy: g.strategy,
                    optimistic: g.optimistic,
                    generation,
                }),
            );
            next_gens.insert(gid.clone(), (members, generation));
        }
        *gens = next_gens;
        drop(gens);
        self.upstreams.store(Arc::new(next));
        self.groups.store(Arc::new(groups));
        // Groups that are gone hold no condition.
        let gone: Vec<String> = {
            let mut d = self.down_since.lock().unwrap_or_else(|p| p.into_inner());
            let groups = self.groups.load();
            let gone: Vec<String> = d.keys().filter(|g| !groups.contains_key(*g)).cloned().collect();
            d.retain(|g, _| groups.contains_key(g));
            gone
        };
        for g in gone {
            self.conditions.clear(condition_kind::UPSTREAM_DOWN, Some(&g));
        }
        warnings
    }

    pub fn group(&self, id: &str) -> Option<Arc<Group>> {
        self.groups.load().get(id).cloned()
    }

    pub fn group_ids(&self) -> Vec<String> {
        self.groups.load().keys().cloned().collect()
    }

    /// True when every upstream of the group is unhealthy (or it has none).
    pub fn group_down(&self, id: &str) -> bool {
        match self.group(id) {
            Some(g) => g.upstreams.iter().all(|u| !u.healthy()),
            None => true,
        }
    }

    /// One health pass for `upstream_down`: call about every second.
    pub fn check_health(&self) {
        let groups = self.groups.load_full();
        let now = Instant::now();
        let mut set = vec![];
        let mut clear = vec![];
        {
            let mut d = self.down_since.lock().unwrap_or_else(|p| p.into_inner());
            for (id, g) in groups.iter() {
                let down = g.upstreams.iter().all(|u| !u.healthy());
                if down {
                    let since = *d.entry(id.clone()).or_insert(now);
                    if now.duration_since(since) >= self.down_after {
                        set.push(id.clone());
                    }
                } else if d.remove(id).is_some() {
                    clear.push(id.clone());
                }
            }
        }
        for id in set {
            self.conditions
                .set(condition_kind::UPSTREAM_DOWN, Some(&id), None);
        }
        for id in clear {
            self.conditions.clear(condition_kind::UPSTREAM_DOWN, Some(&id));
        }
    }

    fn pick(
        &self,
        g: &Group,
        tried: &HashSet<Arc<str>>,
        exclude: Option<&Arc<str>>,
    ) -> Option<(Arc<Upstream>, bool)> {
        let now = Instant::now();
        let candidates: smallvec::SmallVec<[&Arc<Upstream>; 8]> = g
            .upstreams
            .iter()
            .filter(|u| !tried.contains(&u.id) && exclude != Some(&u.id) && u.breaker.selectable(now))
            .collect();
        let chosen = match g.strategy {
            GroupStrategy::Failover => candidates.first().copied(),
            GroupStrategy::Fastest => match candidates.len() {
                0 => None,
                1 => candidates.first().copied(),
                n => {
                    let a = rand::random_range(0..n);
                    let mut b = rand::random_range(0..n - 1);
                    if b >= a {
                        b += 1;
                    }
                    let (ua, ub) = (candidates[a], candidates[b]);
                    Some(if ua.score() <= ub.score() { ua } else { ub })
                }
            },
        }?;
        chosen.breaker.admit(now).map(|probe| (Arc::clone(chosen), probe))
    }

    async fn attempt(&self, (u, probe): (Arc<Upstream>, bool), req: &ResolveRequest, hedge: bool) -> Attempt {
        let mut guard = ProbeGuard {
            u: Arc::clone(&u),
            active: probe,
        };
        let r = self.attempt_inner(u, req, hedge).await;
        // An attempt that judged the upstream reset the breaker's probe (success or failure); an
        // unjudged one leaves the guard to give the slot back.
        guard.active = guard.active && matches!(r, Attempt::Unjudged(..));
        r
    }

    async fn attempt_inner(&self, u: Arc<Upstream>, req: &ResolveRequest, hedge: bool) -> Attempt {
        u.counters.queries.fetch_add(1, Relaxed);
        if hedge {
            u.counters.hedges.fetch_add(1, Relaxed);
        }
        u.inflight.fetch_add(1, Relaxed);
        struct Dec(Arc<Upstream>);
        impl Drop for Dec {
            fn drop(&mut self) {
                self.0.inflight.fetch_sub(1, Relaxed);
            }
        }
        let _dec = Dec(Arc::clone(&u));
        let pad = u.transport.encrypted();
        let mut buf = [0u8; 512];
        let params = picket_wire::upstream::QueryParams {
            id: 0,
            cd: req.cd,
            do_bit: req.do_up,
            pad,
        };
        let n = match picket_wire::upstream::write_query(
            &mut buf,
            req.qname.as_name(),
            req.qtype,
            req.qclass,
            &params,
        ) {
            Ok(n) => n,
            Err(_) => return Attempt::Unjudged(u, Cause::Invalid),
        };
        let start = Instant::now();
        let raw = u
            .transport
            .query_leg(&buf[..n], self.attempt_timeout, u.rtt.p99())
            .await;
        let rtt = start.elapsed();
        let (raw, stream_leg) = match raw {
            Ok(r) => r,
            Err(e) => {
                u.counters.errors.fetch_add(1, Relaxed);
                u.breaker.failure(Instant::now());
                let cause = match e {
                    TxError::Timeout => Cause::Timeout,
                    TxError::Mismatch | TxError::TooLarge => {
                        u.counters
                            .invalid
                            .get(if e == TxError::Mismatch {
                                Invalid::QuestionMismatch.reason()
                            } else {
                                Invalid::TooLarge.reason()
                            })
                            .fetch_add(1, Relaxed);
                        Cause::Invalid
                    }
                    TxError::Connect(_) | TxError::Transport(_) => Cause::Connect,
                };
                return Attempt::Fail(u, cause);
            }
        };
        if stream_leg && picket_wire::answer::is_truncated_response(&raw, 0) {
            // Owner decision S6: TC over a stream fails the upstream, a UDP upstream's TCP retry
            // included; the query moves to another upstream.
            u.counters.invalid.get("tc_stream").fetch_add(1, Relaxed);
            u.breaker.failure(Instant::now());
            return Attempt::Fail(u, Cause::Invalid);
        }
        let sent = SentQuery {
            id: 0,
            qname: req.qname.as_name(),
            qtype: req.qtype,
            qclass: req.qclass,
        };
        match picket_wire::check_answer(&raw, &sent, &self.answer_limits()) {
            Ok(a) => {
                for (reason, n) in a.removed.labelled() {
                    if n > 0 {
                        u.counters.scrubbed.get(reason).fetch_add(u64::from(n), Relaxed);
                    }
                }
                u.rtt.record(rtt);
                u.counters
                    .rtt_ms
                    .record_ms_from_us(picket_api::duration::as_micros_u64(rtt));
                u.breaker.success();
                if req.reject_stale && a.facts.stale {
                    return Attempt::Fail(u, Cause::Stale);
                }
                Attempt::Ok(Box::new(Resolved {
                    answer: a,
                    upstream: Arc::clone(&u.id),
                    rtt,
                }))
            }
            Err(inv) => {
                u.counters.invalid.get(inv.reason()).fetch_add(1, Relaxed);
                if inv.leaves_upstream_unjudged() {
                    // Refused by a size limit (issue #16) or for one domain's SVCB/HTTPS
                    // parameters, not shown broken: no health signal.
                    return Attempt::Unjudged(u, Cause::Invalid);
                }
                u.breaker.failure(Instant::now());
                Attempt::Fail(u, Cause::Invalid)
            }
        }
    }

    /// Resolves through the group: selection, hedging, retries on another upstream (edge.md §6,
    /// §7). Never waits past [`Self::budget`].
    pub async fn resolve(&self, req: &ResolveRequest) -> Result<Resolved, Failure> {
        let Some(g) = self.group(&req.group) else {
            return Err(Failure { cause: Cause::Down });
        };
        let deadline = tokio::time::Instant::now() + self.budget;
        let mut tried: HashSet<Arc<str>> = HashSet::new();
        let mut last: Option<Cause> = None;
        let mut inflight = FuturesUnordered::new();
        let mut hedged = false;
        let first = self.pick(&g, &tried, req.exclude.as_ref());
        let Some(first) = first else {
            return Err(Failure { cause: Cause::Down });
        };
        tried.insert(Arc::clone(&first.0.id));
        let hedge_at = tokio::time::Instant::now() + first.0.hedge_after();
        inflight.push(Box::pin(self.attempt(first, req, false)));
        loop {
            let can_hedge = !hedged && inflight.len() == 1;
            tokio::select! {
                r = inflight.next() => {
                    match r {
                        // The other attempts are dropped (cancelled) here; their guards give
                        // back any probe slot they held.
                        Some(Attempt::Ok(res)) => return Ok(*res),
                        Some(Attempt::Fail(_u, cause) | Attempt::Unjudged(_u, cause)) => {
                            last = Some(cause);
                            if inflight.is_empty() {
                                match self.pick(&g, &tried, req.exclude.as_ref()) {
                                    Some(next) => {
                                        tried.insert(Arc::clone(&next.0.id));
                                        inflight.push(Box::pin(self.attempt(next, req, false)));
                                    }
                                    None => return Err(Failure { cause: last.unwrap_or(Cause::Down) }),
                                }
                            }
                        }
                        None => return Err(Failure { cause: last.unwrap_or(Cause::Down) }),
                    }
                }
                _ = tokio::time::sleep_until(hedge_at), if can_hedge => {
                    hedged = true;
                    if let Some(next) = self.pick(&g, &tried, req.exclude.as_ref()) {
                        tried.insert(Arc::clone(&next.0.id));
                        inflight.push(Box::pin(self.attempt(next, req, true)));
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Failure { cause: last.unwrap_or(Cause::Timeout) });
                }
            }
        }
    }

    /// The upstream ids and their health, for `status`.
    pub fn status(&self) -> serde_json::Value {
        let ups = self.upstreams.load();
        let mut v: Vec<serde_json::Value> = ups
            .values()
            .map(|u| {
                serde_json::json!({
                    "id": &*u.id,
                    "protocol": u.cfg.protocol,
                    "ip": u.cfg.ip,
                    "port": u.cfg.port,
                    "healthy": u.healthy(),
                    "inflight": u.inflight.load(Relaxed),
                    "rtt_ewma_us": u.rtt.ewma_us.load(Relaxed),
                })
            })
            .collect();
        v.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        serde_json::Value::Array(v)
    }
}

/// The upstream DO for a query (edge.md §6): 1 to an encrypted group; the client's DO for a plain
/// group and for a forward zone's queries.
pub fn upstream_do(group_encrypted: bool, via_zone: bool, client_do: bool) -> bool {
    if via_zone || !group_encrypted {
        client_do
    } else {
        true
    }
}

/// The protocol's default port, for display.
pub fn default_port(p: UpstreamProtocol) -> u16 {
    match p {
        UpstreamProtocol::Dot => 853,
        UpstreamProtocol::Doh => 443,
        UpstreamProtocol::Udp | UpstreamProtocol::Tcp => 53,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaker_opens_after_failures_and_probes_once() {
        let b = Breaker::new();
        let t0 = Instant::now();
        assert!(b.healthy() && b.selectable(t0));
        for _ in 0..BREAKER_FAILURES {
            b.failure(t0);
        }
        assert!(!b.selectable(t0));
        let later = t0 + BREAKER_OPEN_MIN + Duration::from_millis(1);
        assert!(b.selectable(later), "half-open");
        assert!(!b.healthy(), "unhealthy until a probe succeeds");
        assert_eq!(b.admit(later), Some(true));
        assert_eq!(b.admit(later), None, "one probe at a time");
        b.release_probe();
        assert_eq!(
            b.admit(later),
            Some(true),
            "a cancelled probe gives its slot back"
        );
        b.failure(later);
        assert!(!b.selectable(later + BREAKER_OPEN_MIN), "the open time doubled");
        b.success();
        assert!(b.healthy() && b.selectable(later));
    }

    #[test]
    fn do_rules() {
        assert!(upstream_do(true, false, false), "encrypted groups always DO=1");
        assert!(
            !upstream_do(false, false, false),
            "plain groups keep the client's DO"
        );
        assert!(upstream_do(false, false, true));
        assert!(
            !upstream_do(true, true, false),
            "forward zones keep the client's DO"
        );
    }

    #[test]
    fn plain_upstreams_only_to_private_or_loopback() {
        assert!(plain_allowed("127.0.0.1".parse().unwrap()));
        assert!(plain_allowed("192.168.1.1".parse().unwrap()));
        assert!(plain_allowed("fd00::1".parse().unwrap()));
        assert!(!plain_allowed("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn rtt_percentiles() {
        let s = RttStats::new();
        for i in 1..=100u64 {
            s.record(Duration::from_millis(i));
        }
        let p90 = s.p90().unwrap();
        assert!(
            p90 >= Duration::from_millis(85) && p90 <= Duration::from_millis(95),
            "{p90:?}"
        );
        assert!(s.p99().unwrap() >= p90);
    }

    /// A fake UDP upstream on loopback answering every query with `answers` A records at the
    /// question name and a header that claims `claimed` answers (more than are there to fake a
    /// header over the section bound).
    async fn fake_upstream(answers: u16, claimed: u16) -> u16 {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let q = &buf[..n];
                // The question ends at its name's root label plus type and class.
                let name_end = 12 + q[12..].iter().position(|b| *b == 0).unwrap() + 1;
                let mut a = Vec::new();
                a.extend_from_slice(&q[..2]);
                a.extend_from_slice(&[0x81, 0x80, 0, 1]);
                a.extend_from_slice(&claimed.to_be_bytes());
                a.extend_from_slice(&[0, 0, 0, 0]);
                a.extend_from_slice(&q[12..name_end + 4]);
                for i in 0..answers {
                    let [hi, lo] = i.to_be_bytes();
                    a.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, hi, lo]);
                }
                let _ = sock.send_to(&a, from).await;
            }
        });
        port
    }

    fn pool_for(port: u16, max_rrset_records: u32) -> (Arc<UpstreamPool>, Arc<Upstream>) {
        let (logs, _rx) = crate::logs::LogProducer::new("b".into(), Arc::default());
        let pool = UpstreamPool::new(Metrics::new(), Conditions::new(logs));
        let cfg: EdgeConfig = serde_json::from_value(serde_json::json!({
            "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
            "listeners": [],
            "upstreams": {"u": {"protocol": "udp", "ip": "127.0.0.1", "port": port}},
            "upstream_groups": {"g": {"upstreams": ["u"], "strategy": "failover"}},
            "limits": {"max_rrset_records": max_rrset_records},
        }))
        .unwrap();
        assert!(pool.configure(&cfg).is_empty());
        let u = Arc::clone(&pool.upstreams.load()["u"]);
        (pool, u)
    }

    fn request() -> ResolveRequest {
        ResolveRequest {
            group: "g".into(),
            qname: WireName::from_text("big.example").unwrap(),
            qtype: 1,
            qclass: 1,
            do_up: false,
            cd: false,
            exclude: None,
            reject_stale: false,
        }
    }

    /// Issue #16: an answer refused for its size alone fails the query (SERVFAIL, `cause=invalid`)
    /// and is counted by reason, but leaves the breaker as it was: it never opens it, never
    /// erases earlier failures and never closes a half-open one; a probe slot goes back.
    #[tokio::test]
    async fn size_refusals_fail_the_query_but_not_the_upstream() {
        assert_eq!(
            picket_api::edge_config::Limits::default().max_rrset_records,
            u32::from(picket_wire::answer::DEFAULT_MAX_RRSET),
            "the config default is picket-wire's"
        );
        // Over the section bound, from the header alone.
        let (pool, u) = pool_for(fake_upstream(0, 1025).await, 256);
        for _ in 0..BREAKER_FAILURES * 2 {
            let e = pool.resolve(&request()).await.err().unwrap();
            assert_eq!(e.cause, Cause::Invalid);
        }
        assert!(u.healthy(), "the breaker stays closed");
        assert_eq!(
            u.counters.invalid.get("too_many_records").load(Relaxed),
            u64::from(BREAKER_FAILURES * 2)
        );

        // Over the configured RRset limit; the same answer passes a higher one, and 0 is no limit.
        let port = fake_upstream(3, 3).await;
        let (pool, u) = pool_for(port, 2);
        for _ in 0..BREAKER_FAILURES * 2 {
            let e = pool.resolve(&request()).await.err().unwrap();
            assert_eq!(e.cause, Cause::Invalid);
        }
        assert!(u.healthy(), "the breaker stays closed");
        assert_eq!(
            u.counters.invalid.get("rrset_too_large").load(Relaxed),
            u64::from(BREAKER_FAILURES * 2)
        );
        for limit in [3, 0] {
            let (pool, _) = pool_for(port, limit);
            let ok = pool.resolve(&request()).await.ok().unwrap();
            assert_eq!(ok.answer.facts.addrs.len(), 3, "limit {limit}");
        }

        // Earlier failures stand: two, a size refusal, one more opens the breaker.
        let (pool, u) = pool_for(port, 2);
        for _ in 0..BREAKER_FAILURES - 1 {
            u.breaker.failure(Instant::now());
        }
        assert_eq!(
            pool.resolve(&request()).await.err().unwrap().cause,
            Cause::Invalid
        );
        assert!(u.healthy());
        u.breaker.failure(Instant::now());
        assert!(!u.healthy(), "the refusal didn't reset the count");

        // A half-open breaker whose probe is refused stays half-open, its slot free again.
        let (pool, u) = pool_for(port, 2);
        let past = Instant::now()
            .checked_sub(BREAKER_OPEN_MAX + Duration::from_secs(1))
            .unwrap();
        for _ in 0..BREAKER_FAILURES {
            u.breaker.failure(past);
        }
        assert_eq!(
            pool.resolve(&request()).await.err().unwrap().cause,
            Cause::Invalid
        );
        assert!(!u.healthy(), "a refused probe doesn't close the breaker");
        assert!(u.breaker.selectable(Instant::now()), "the probe slot went back");
    }

    /// A fake UDP upstream on loopback answering by the question's first label: `bad`, an HTTPS
    /// ServiceMode record with an empty `ipv4hint` (RFC 9460 §7.3 forbids it: `bad_svcb`);
    /// `broken`, a record whose RDLENGTH runs past the message (`undecodable`); anything else,
    /// one A record.
    async fn fake_svcb_upstream() -> u16 {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let q = &buf[..n];
                let name_end = 12 + q[12..].iter().position(|b| *b == 0).unwrap() + 1;
                let first = &q[13..13 + usize::from(q[12])];
                let mut a = Vec::new();
                a.extend_from_slice(&q[..2]);
                a.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                a.extend_from_slice(&q[12..name_end + 4]);
                match first {
                    // priority 1, target ".", key 4 (ipv4hint) with no addresses
                    b"bad" => a.extend_from_slice(&[
                        0xC0, 0x0C, 0, 65, 0, 1, 0, 0, 0, 60, 0, 7, 0, 1, 0, 0, 4, 0, 0,
                    ]),
                    b"broken" => {
                        a.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 9, 10, 0, 0, 1])
                    }
                    _ => a.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]),
                }
                let _ = sock.send_to(&a, from).await;
            }
        });
        port
    }

    /// Issue #94: an answer refused for one domain's SVCB/HTTPS parameters (`bad_svcb`) is
    /// counted and the query moves to the next upstream, but the breaker is left alone, so
    /// repeated refusals for that domain never take the upstream away from unrelated names. A
    /// genuinely undecodable answer still counts against its health.
    #[tokio::test]
    async fn semantic_svcb_refusals_fall_back_without_judging_the_upstream() {
        let (bad, good) = (fake_svcb_upstream().await, fake_upstream(1, 1).await);
        let (logs, _rx) = crate::logs::LogProducer::new("b".into(), Arc::default());
        let pool = UpstreamPool::new(Metrics::new(), Conditions::new(logs));
        let cfg: EdgeConfig = serde_json::from_value(serde_json::json!({
            "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
            "listeners": [],
            "upstreams": {
                "u": {"protocol": "udp", "ip": "127.0.0.1", "port": bad},
                "v": {"protocol": "udp", "ip": "127.0.0.1", "port": good},
            },
            "upstream_groups": {"g": {"upstreams": ["u", "v"], "strategy": "failover"}},
        }))
        .unwrap();
        assert!(pool.configure(&cfg).is_empty());
        let u = Arc::clone(&pool.upstreams.load()["u"]);
        let ask = |name: &str, qtype: u16| ResolveRequest {
            qname: WireName::from_text(name).unwrap(),
            qtype,
            ..request()
        };
        for _ in 0..BREAKER_FAILURES * 2 {
            let ok = pool.resolve(&ask("bad.example", 65)).await.ok().unwrap();
            assert_eq!(&*ok.upstream, "v", "the query fell back");
        }
        assert!(u.healthy(), "the breaker stays closed");
        assert_eq!(
            u.counters.invalid.get("bad_svcb").load(Relaxed),
            u64::from(BREAKER_FAILURES * 2)
        );
        let ok = pool.resolve(&ask("ok.example", 1)).await.ok().unwrap();
        assert_eq!(&*ok.upstream, "u", "an unrelated name still goes to it");
        assert_eq!(ok.answer.facts.addrs.len(), 1);

        // An undecodable answer is a health signal: enough of them open the breaker.
        for _ in 0..BREAKER_FAILURES {
            let ok = pool.resolve(&ask("broken.example", 1)).await.ok().unwrap();
            assert_eq!(&*ok.upstream, "v");
        }
        assert_eq!(
            u.counters.invalid.get("undecodable").load(Relaxed),
            u64::from(BREAKER_FAILURES)
        );
        assert!(!u.healthy(), "undecodable answers count against it");
    }

    /// edge.md §6 Health: an open breaker whose time is up takes one probe but stays unhealthy
    /// until that probe succeeds, so a dead group no query reaches still raises `upstream_down`
    /// after `down_after` (the open time, 5–60 s, never resets the 30 s timer).
    #[test]
    fn a_quiet_dead_group_raises_upstream_down_until_a_probe_succeeds() {
        use picket_api::session::condition_kind::UPSTREAM_DOWN;
        let (logs, _rx) = crate::logs::LogProducer::new("b".into(), Arc::default());
        let conditions = Conditions::new(logs);
        let mut pool = UpstreamPool::new(Metrics::new(), Arc::clone(&conditions));
        Arc::get_mut(&mut pool).unwrap().down_after = Duration::ZERO;
        let cfg: EdgeConfig = serde_json::from_value(serde_json::json!({
            "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
            "listeners": [],
            "upstreams": {"u": {"protocol": "udp", "ip": "127.0.0.1", "port": 5399}},
            "upstream_groups": {"g": {"upstreams": ["u"], "strategy": "failover"}},
        }))
        .unwrap();
        assert!(pool.configure(&cfg).is_empty());
        let u = Arc::clone(&pool.upstreams.load()["u"]);
        // The breaker opened long enough ago that its open time is up; no query came since.
        let past = Instant::now()
            .checked_sub(BREAKER_OPEN_MAX + Duration::from_secs(1))
            .unwrap();
        for _ in 0..BREAKER_FAILURES {
            u.breaker.failure(past);
        }
        pool.check_health();
        pool.check_health();
        assert!(!u.healthy(), "half-open isn't healthy");
        assert!(
            conditions.is_set(UPSTREAM_DOWN, Some("g")),
            "quiet and dead: down"
        );
        // A query may still probe it; a failed probe keeps it down, a passing one clears it.
        let (picked, probe) = pool
            .pick(&pool.group("g").unwrap(), &HashSet::new(), None)
            .expect("a half-open upstream takes a probe");
        assert!(probe && picked.id == u.id);
        u.breaker.failure(Instant::now());
        pool.check_health();
        assert!(conditions.is_set(UPSTREAM_DOWN, Some("g")));
        u.breaker.success();
        pool.check_health();
        assert!(u.healthy());
        assert!(
            !conditions.is_set(UPSTREAM_DOWN, Some("g")),
            "cleared by the probe"
        );
    }
}
