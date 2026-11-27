//! The validator (core.md §8 "Resolver path"): hickory's own `DnssecDnsHandle` over a small
//! adapter ([`Adapter`]).
//!
//! - **The adapter** answers the original question of a logged answer from the logged wire, and
//!   sends every other query (DNSKEY, DS and NS lookups, and fallback queries) through a
//!   [`ChainResolver`] (in production the DoH client to an edge listener, `super::resolver`).
//!   Chain answers are cached per their TTLs ([`ChainCache`], shared by all validations); each
//!   network request takes a token from the `dnssec.max_per_minute` limiter first ([`Limiter`]),
//!   so work beyond it waits instead of being skipped. The resolver sets DO=1 and CD=1 on every
//!   query, overriding hickory's CD=0, so the upstream returns signatures and data even when it
//!   judges them bogus (RFC 6840 §5.9).
//! - **Validation as of a time:** hickory reads "now" from its runtime's `Time::current_time()`,
//!   once per response it verifies, right after the adapter hands it that response. The adapter's
//!   runtime ([`AsOfRuntime`]) answers from a task-local the adapter sets as it answers: the
//!   logged answer's own records are checked as of its record's `received_at` (core.md §8), and
//!   every chain record (DNSKEY and DS answers, and a fallback answer) as of when it is used, so a
//!   zone that re-signed its chain since the answer was received still validates. Each
//!   validation gets its own `DnssecDnsHandle` (hickory's validation cache keys ignore the time).
//! - **Crypto reused by answer id:** a verdict depends on the receive time only through the
//!   logged answer's RRSIG inceptions and expirations. [`CryptoMemo`] keeps, per answer id, the
//!   verdicts found with the time cell they hold for (between the nearest boundaries), and the
//!   wall-clock cell of the chain's signatures; another `received_at` in the same cell reuses the
//!   verdict without crypto or requests while the chain's cell holds and the verdict is younger
//!   than the chain cache's longest TTL.
//! - **Rate waits:** waiting for a `dnssec.max_per_minute` token doesn't count against
//!   [`VALIDATION_TIMEOUT`] (core.md §8 "work beyond it waits"): the timeout bounds the
//!   validation's own work and requests, so a low rate never turns into timeouts and retries.
//! - **Verdicts** are read from the parsed `Message` of the returned `DnsResponse` (each record's
//!   `proof`), or from hickory's NSEC error. hickory's proof error for a failed RRset is only
//!   logged by hickory (`debug!`), so the validation captures those events ([`ProofCapture`])
//!   and names the first in the verdict; the RFC 8914 code is derived from it and the answer's
//!   signatures ([`ede_for`]).
//! - Trust anchors: hickory's built-in root KSKs (tests inject their own); its work limits
//!   (KeyTrap, NSEC3 iterations) stay at their defaults.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::stream::{self, BoxStream};
use hickory_net::dnssec::DnssecDnsHandle;
use hickory_net::proto::dnssec::rdata::{DNSSECRData, RRSIG};
use hickory_net::proto::dnssec::{Proof, TrustAnchors};
use hickory_net::proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Edns, Message, Query, ResponseCode,
};
use hickory_net::proto::rr::rdata::opt::EdnsCode;
use hickory_net::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_net::runtime::{
    RuntimeProvider, Time, TokioHandle, TokioRuntimeProvider, iocompat::AsyncIoTokioAsStd,
};
use hickory_net::xfer::FirstAnswer;
use hickory_net::{DnsError, DnsHandle, NetError};
use serde::{Deserialize, Serialize};

/// The most a validation may take (requests included, `dnssec.max_per_minute` waits not) before
/// it counts as a failed request.
pub const VALIDATION_TIMEOUT: Duration = Duration::from_secs(120);
/// Chain answers the cache keeps (README §2 Bounded).
pub const CHAIN_CACHE_ENTRIES: usize = 8192;
/// The longest a chain answer is cached, whatever its TTL.
pub const CHAIN_CACHE_MAX_TTL: u32 = 3600;
/// Chain answers (DNSKEY and DS) one verdict keeps as evidence.
pub const MAX_CHAIN_EVIDENCE: usize = 16;
/// Answer ids the crypto memo keeps.
pub const MEMO_ANSWERS: usize = 4096;
/// Requests one validation may make (hickory bounds its depth; this bounds the breadth).
pub const MAX_REQUESTS_PER_VALIDATION: u32 = 64;

// ---------------------------------------------------------------------------------------------
// Outcomes

/// A validation outcome (core.md §8, §10 `dnssec_results{outcome}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Insecure => "insecure",
            Self::Bogus => "bogus",
            Self::Indeterminate => "indeterminate",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "secure" => Self::Secure,
            "insecure" => Self::Insecure,
            "bogus" => Self::Bogus,
            "indeterminate" => Self::Indeterminate,
            _ => return None,
        })
    }

    fn of(p: Proof) -> Self {
        match p {
            Proof::Secure => Self::Secure,
            Proof::Insecure => Self::Insecure,
            Proof::Bogus => Self::Bogus,
            _ => Self::Indeterminate,
        }
    }

    /// The worse of two outcomes: Bogus, then Indeterminate, then Insecure, then Secure.
    fn worse(self, other: Self) -> Self {
        let rank = |o: Self| match o {
            Self::Secure => 0,
            Self::Insecure => 1,
            Self::Indeterminate => 2,
            Self::Bogus => 3,
        };
        if rank(other) > rank(self) { other } else { self }
    }
}

/// One chain answer the validator fetched (a DNSKEY or DS lookup), kept as `dnssec_bogus`
/// evidence (core.md §8, storage.md §3 `alert_evidence_answers` source `validator`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAnswer {
    pub qname: String,
    pub qtype: String,
    #[serde(with = "b64")]
    pub wire: Vec<u8>,
}

mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// What one validation found.
#[derive(Clone, Debug, Default)]
pub struct Verdict {
    pub outcome: Option<Outcome>,
    /// The RFC 8914 code 1.1.1.1 would return for a Bogus outcome.
    pub ede: Option<u16>,
    /// hickory's proof error (or the NSEC proof it failed), for a Bogus or Indeterminate outcome.
    pub proof: Option<String>,
    /// The zone where validation broke, when it can be told.
    pub zone: Option<String>,
    /// The DNSKEY and DS answers the validation fetched.
    pub chain: Vec<ChainAnswer>,
    /// A request failed while the edge was reachable (timeout, SERVFAIL, REFUSED, HTTP 403…).
    pub failed: Option<String>,
    /// No edge DoH listener was reachable for a request the validation needed.
    pub unreachable: bool,
    /// The fallback answer carried EDE 3 (stale): Indeterminate, retried (core.md §8).
    pub stale: bool,
    /// Network requests made (cache misses).
    pub requests: u32,
    /// The rcode of the fallback query's answer.
    pub rcode: Option<String>,
    /// The time cell the verdict holds for: `[lo, hi)` in Unix seconds of the logged answer's
    /// receive time (its own RRSIGs' boundaries).
    pub cell: (u64, u64),
    /// The wall-clock cell the chain's signatures held for when they were checked: `[lo, hi)`.
    pub chain_cell: (u64, u64),
    /// Reused from the crypto memo.
    pub reused: bool,
}

impl Verdict {
    /// True when the item should be tried again (a failed request, an Indeterminate outcome or a
    /// stale fallback answer, core.md §8).
    pub fn retry(&self) -> bool {
        self.failed.is_some() || self.stale || self.outcome.is_none_or(|o| o == Outcome::Indeterminate)
    }
}

// ---------------------------------------------------------------------------------------------
// Chain resolution

/// Why a chain query got no answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// No edge DoH listener could be reached (connect or TLS failed, none configured, none on a
    /// connected edge): the item waits without using an attempt.
    #[error("no edge DoH listener reachable: {0}")]
    Unreachable(String),
    /// The edge was reached but the request failed (timeout, HTTP error, bad answer).
    #[error("{0}")]
    Failed(String),
}

/// Sends one query with DO=1 and CD=1 and returns the raw answer (core.md §8).
#[async_trait]
pub trait ChainResolver: Send + Sync {
    async fn query(&self, qname: &Name, qtype: RecordType) -> Result<Vec<u8>, ResolveError>;
}

/// The query core sends for a chain lookup or fallback: RD=1, CD=1, EDNS with DO=1 (core.md §8).
pub fn chain_query(qname: &Name, qtype: RecordType) -> Result<Vec<u8>, String> {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.metadata.checking_disabled = true;
    m.add_query(Query::query(qname.clone(), qtype));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(4096);
    m.edns = Some(edns);
    m.to_vec().map_err(|e| format!("cannot write the query: {e}"))
}

/// The `dnssec.max_per_minute` limiter: a token bucket of that size refilled over a minute (on
/// tokio's monotonic clock).
pub struct Limiter {
    inner: Mutex<(f64, tokio::time::Instant, u32)>,
}

impl Limiter {
    pub fn new(per_minute: u32) -> Self {
        Self {
            inner: Mutex::new((
                f64::from(per_minute.max(1)),
                tokio::time::Instant::now(),
                per_minute.max(1),
            )),
        }
    }

    /// Changes the rate (settings change); keeps the tokens up to the new size.
    pub fn set_rate(&self, per_minute: u32) {
        if let Ok(mut g) = self.inner.lock() {
            let per_minute = per_minute.max(1);
            g.2 = per_minute;
            g.0 = g.0.min(f64::from(per_minute));
        }
    }

    /// Takes a token now, or says how long until one is free.
    fn try_take(&self) -> Result<(), Duration> {
        let Ok(mut g) = self.inner.lock() else {
            return Ok(());
        };
        let rate = f64::from(g.2) / 60.0;
        let now = tokio::time::Instant::now();
        let elapsed = now.saturating_duration_since(g.1).as_secs_f64();
        g.0 = (g.0 + elapsed * rate).min(f64::from(g.2));
        g.1 = now;
        if g.0 >= 1.0 {
            g.0 -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(((1.0 - g.0) / rate).max(0.01)))
        }
    }

    /// Waits for a token (work beyond the rate waits instead of being skipped).
    pub async fn acquire(&self) {
        loop {
            match self.try_take() {
                Ok(()) => return,
                Err(d) => tokio::time::sleep(d.min(Duration::from_secs(5))).await,
            }
        }
    }
}

type ChainKey = (String, u16);
type ChainMap = HashMap<ChainKey, (Vec<u8>, Instant)>;

/// Chain answers cached per their TTLs, shared by every validation (core.md §8). Entries carry
/// the restore generation they were fetched in: a validation that began before a config restore
/// adds nothing after it ([`ChainCache::reset_to`]; core.md §2).
#[derive(Default)]
pub struct ChainCache {
    inner: Mutex<ChainInner>,
}

#[derive(Default)]
struct ChainInner {
    map: ChainMap,
    order: VecDeque<ChainKey>,
    generation: u64,
}

impl ChainCache {
    fn get(&self, key: &(String, u16)) -> Option<Vec<u8>> {
        let g = self.inner.lock().ok()?;
        let (wire, until) = g.map.get(key)?;
        (Instant::now() < *until).then(|| wire.clone())
    }

    /// Caches an answer fetched by a validation of restore generation `generation` (none when
    /// the cache has moved on to another).
    fn put(&self, generation: u64, key: (String, u16), wire: Vec<u8>, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let Ok(mut g) = self.inner.lock() else { return };
        if g.generation != generation {
            return;
        }
        let until = Instant::now() + Duration::from_secs(u64::from(ttl.min(CHAIN_CACHE_MAX_TTL)));
        if g.map.insert(key.clone(), (wire, until)).is_none() {
            g.order.push_back(key);
        }
        while g.map.len() > CHAIN_CACHE_ENTRIES {
            let Some(old) = g.order.pop_front() else { break };
            g.map.remove(&old);
        }
    }

    /// Drops every entry (tests).
    pub fn clear(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.map.clear();
            g.order.clear();
        }
    }

    /// Drops every entry and takes only answers of restore generation `generation` from now on
    /// (a restore, on the writer right after its commit).
    pub fn reset_to(&self, generation: u64) {
        if let Ok(mut g) = self.inner.lock() {
            g.map.clear();
            g.order.clear();
            g.generation = generation;
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// How long a chain answer may be cached: the smallest TTL of its records (an SOA's for a
/// negative answer), capped.
fn cache_ttl(m: &Message) -> u32 {
    let mut ttl: Option<u32> = None;
    for r in m.answers.iter().chain(m.authorities.iter()) {
        let t = match &r.data {
            RData::SOA(soa) => r.ttl.min(soa.minimum),
            _ => r.ttl,
        };
        ttl = Some(ttl.map_or(t, |x| x.min(t)));
    }
    ttl.unwrap_or(0).min(CHAIN_CACHE_MAX_TTL)
}

// ---------------------------------------------------------------------------------------------
// The runtime: hickory's clock as of the validated time

tokio::task_local! {
    /// The times the current validation compares signatures against.
    static AS_OF: Arc<AsOf>;
    /// hickory's proof errors logged during the current validation.
    static CAPTURED: Arc<Mutex<Vec<String>>>;
}

/// The times one validation compares signatures against (core.md §8): the logged answer's own
/// records as of its record's `received_at`, every other record as of when it is used.
struct AsOf {
    /// The logged answer's receive time (Unix seconds); now for a fallback query.
    logged: u64,
    /// The time for the response hickory verifies next. `DnssecDnsHandle::send` hands each
    /// response the adapter returns straight to `verify_response`, which reads
    /// `current_time()` before anything else can run in the task, so the adapter sets this as it
    /// answers.
    next: AtomicU64,
}

/// The wall clock in Unix seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sets the time hickory checks the next response against.
fn verify_next_as_of(t: u64) {
    let _ = AS_OF.try_with(|a| a.next.store(t, Ordering::Relaxed));
}

/// The logged answer's receive time in the current validation.
fn logged_time() -> u64 {
    AS_OF.try_with(|a| a.logged).unwrap_or_else(|_| unix_now())
}

/// hickory's `Time` whose `current_time()` is the time the response being verified is checked
/// against ([`AsOf`]; core.md §8: "hickory's validity check takes the time to compare against").
#[derive(Clone, Copy, Debug, Default)]
pub struct AsOfTime;

#[async_trait]
impl Time for AsOfTime {
    async fn delay_for(duration: Duration) {
        tokio::time::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, io::Error> {
        tokio::time::timeout(duration, future)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out"))
    }

    fn current_time() -> u64 {
        AS_OF
            .try_with(|a| a.next.load(Ordering::Relaxed))
            .unwrap_or_else(|_| unix_now())
    }
}

/// tokio's runtime with [`AsOfTime`] as its timer; the adapter never opens sockets through it.
#[derive(Clone, Default)]
pub struct AsOfRuntime(TokioRuntimeProvider);

impl RuntimeProvider for AsOfRuntime {
    type Handle = TokioHandle;
    type Timer = AsOfTime;
    type Udp = tokio::net::UdpSocket;
    type Tcp = AsyncIoTokioAsStd<tokio::net::TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        self.0.connect_tcp(server_addr, bind_addr, timeout)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        self.0.bind_udp(local_addr, server_addr)
    }
}

// ---------------------------------------------------------------------------------------------
// hickory's proof errors

/// Captures hickory's per-RRset proof errors (`failed to verify: … : <kind>`, logged at debug
/// level by `DnssecDnsHandle`) for the validation running in the current task, and forwards
/// every other event to the process's own subscriber.
struct ProofCapture {
    forward: Option<tracing::Dispatch>,
}

const HICKORY_DNSSEC: &str = "hickory_net::dnssec";

impl tracing::Subscriber for ProofCapture {
    fn register_callsite(&self, meta: &'static tracing::Metadata<'static>) -> tracing::subscriber::Interest {
        if meta.target().starts_with(HICKORY_DNSSEC) && meta.is_event() {
            tracing::subscriber::Interest::sometimes()
        } else {
            match &self.forward {
                Some(f) => f.register_callsite(meta),
                None => tracing::subscriber::Interest::never(),
            }
        }
    }

    fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
        (meta.target().starts_with(HICKORY_DNSSEC) && meta.is_event())
            || self
                .forward
                .as_ref()
                .is_some_and(|f| meta.is_event() && f.enabled(meta))
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::DEBUG)
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let meta = event.metadata();
        if meta.target().starts_with(HICKORY_DNSSEC) {
            let mut v = MessageVisitor(String::new());
            event.record(&mut v);
            if let Some(kind) = v.0.strip_prefix("failed to verify: ") {
                let _ = CAPTURED.try_with(|c| {
                    if let Ok(mut g) = c.lock()
                        && g.len() < 16
                    {
                        g.push(kind.chars().take(512).collect());
                    }
                });
            }
            if *meta.level() > tracing::Level::INFO {
                return;
            }
        }
        if let Some(f) = &self.forward
            && f.enabled(meta)
        {
            f.event(event);
        }
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

/// The capture dispatcher: one per process, forwarding to the subscriber that was the default
/// when it was first needed.
fn capture_dispatch() -> tracing::Dispatch {
    static D: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    D.get_or_init(|| {
        let forward = tracing::dispatcher::get_default(|d| {
            (!d.is::<tracing::subscriber::NoSubscriber>()).then(|| d.clone())
        });
        tracing::Dispatch::new(ProofCapture { forward })
    })
    .clone()
}

// ---------------------------------------------------------------------------------------------
// The adapter

/// What the adapter saw during one validation.
#[derive(Default)]
struct Trace {
    chain: Vec<ChainAnswer>,
    failed: Option<String>,
    unreachable: bool,
    stale: bool,
    requests: u32,
    rcode: Option<String>,
    /// The logged answer's RRSIG validity boundaries (inception, expiration + 1): the receive
    /// times its verdict holds for.
    bounds: Vec<u64>,
    /// The chain's RRSIG validity boundaries, checked against the wall clock.
    chain_bounds: Vec<u64>,
    /// RRSIGs seen, with the time each was checked against.
    rrsigs: Vec<SigSeen>,

    /// The DNSKEYs fetched, per zone: (key tag, Zone Key bit set).
    dnskeys: HashMap<Name, Vec<(u16, bool)>>,
    /// The response for the validated question, as received (before hickory's changes).
    original: Option<Message>,
}

/// The time a validation spent waiting for `dnssec.max_per_minute` tokens (core.md §8: work
/// beyond the rate waits, and the wait isn't the validation's own time). hickory checks a
/// record set's signatures concurrently, so several requests of one validation may wait at once:
/// the time during which at least one waits counts once, and a wait whose request was dropped
/// (another signature verified first) stops counting when it is dropped. On tokio's clock, as the
/// limiter's.
#[derive(Default)]
pub struct RateWaits {
    inner: Mutex<RateInner>,
}

#[derive(Default)]
struct RateInner {
    /// Requests waiting now.
    waiting: u32,
    /// Since when at least one waits.
    since: Option<tokio::time::Instant>,
    /// Waits that ended.
    total: Duration,
}

/// One request's wait; dropping it ends the wait.
pub struct RateWait<'a>(&'a RateWaits);

impl RateWaits {
    /// A request starts waiting for a token.
    pub fn begin(&self) -> RateWait<'_> {
        if let Ok(mut g) = self.inner.lock() {
            if g.waiting == 0 {
                g.since = Some(tokio::time::Instant::now());
            }
            g.waiting += 1;
        }
        RateWait(self)
    }

    /// The time some request waited so far, the waits in progress included.
    pub fn total(&self) -> Duration {
        self.inner
            .lock()
            .map(|g| g.total + g.since.map(|t| t.elapsed()).unwrap_or_default())
            .unwrap_or_default()
    }
}

impl Drop for RateWait<'_> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.0.inner.lock() {
            g.waiting = g.waiting.saturating_sub(1);
            if g.waiting == 0
                && let Some(t) = g.since.take()
            {
                g.total += t.elapsed();
            }
        }
    }
}

/// One RRSIG the validation saw.
#[derive(Clone, Debug)]
struct SigSeen {
    owner: Name,
    signer: Name,
    covered: RecordType,
    key_tag: u16,
    window: SigWindow,
}

/// An RRSIG's validity window and the time it was checked against (Unix seconds).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigWindow {
    pub inception: u64,
    pub expiration: u64,
    pub at: u64,
}

/// The shared parts of every validation: the resolver, the chain cache and the limiter, and the
/// restore generation the validations run in (what they cache is of that generation).
#[derive(Clone)]
pub struct Shared {
    pub resolver: Arc<dyn ChainResolver>,
    pub cache: Arc<ChainCache>,
    pub limiter: Arc<Limiter>,
    pub anchors: Arc<TrustAnchors>,
    pub generation: u64,
}

/// The `DnsHandle` hickory's validator runs over (core.md §8).
#[derive(Clone)]
pub struct Adapter {
    shared: Shared,
    /// The logged answer: (its question, its wire).
    logged: Option<Arc<(Query, Vec<u8>)>>,
    /// The fallback question (not cached: each admission does its own query).
    fallback: Option<Query>,
    trace: Arc<Mutex<Trace>>,
    waits: Arc<RateWaits>,
}

fn same_question(a: &Query, b: &Query) -> bool {
    a.query_type() == b.query_type()
        && a.query_class() == b.query_class()
        && a.name().to_lowercase() == b.name().to_lowercase()
}

/// An rcode's mnemonic (`NOERROR`, `NXDOMAIN`, …), as log records write it.
fn rcode_text(r: ResponseCode) -> String {
    let n = u16::from(r);
    picket_wire::types::rcode_mnemonic(n)
        .map(str::to_string)
        .unwrap_or_else(|| format!("RCODE{n}"))
}

fn rtype_text(t: RecordType) -> String {
    t.to_string()
}

impl Adapter {
    /// Notes what a response carries. `logged`: the logged answer itself, checked as of `at`
    /// (its receive time); else a record checked as of `at` = now.
    fn note_message(&self, m: &Message, question: &Query, logged: bool, at: u64) {
        let Ok(mut t) = self.trace.lock() else { return };
        for r in m.answers.iter().chain(m.authorities.iter()) {
            match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                    let i = sig.input();
                    let inc = u64::from(i.sig_inception.get());
                    let exp = u64::from(i.sig_expiration.get());
                    let bounds = if logged {
                        &mut t.bounds
                    } else {
                        &mut t.chain_bounds
                    };
                    if bounds.len() < 4096 {
                        bounds.push(inc);
                        bounds.push(exp.saturating_add(1));
                    }
                    if t.rrsigs.len() < 512 {
                        t.rrsigs.push(SigSeen {
                            owner: r.name.to_lowercase(),
                            signer: i.signer_name.to_lowercase(),
                            covered: i.type_covered,
                            key_tag: i.key_tag,
                            window: SigWindow {
                                inception: inc,
                                expiration: exp,
                                at,
                            },
                        });
                    }
                }
                RData::DNSSEC(DNSSECRData::DNSKEY(k)) if question.query_type() == RecordType::DNSKEY => {
                    if let Ok(tag) = k.calculate_key_tag() {
                        let e = t.dnskeys.entry(r.name.to_lowercase()).or_default();
                        if e.len() < 32 {
                            e.push((tag, k.zone_key()));
                        }
                    }
                }
                _ => {}
            }
        }
        if question.query_type() == RecordType::DNSKEY {
            t.dnskeys.entry(question.name().to_lowercase()).or_default();
        }
    }

    fn record_chain(&self, q: &Query, wire: &[u8]) {
        if !matches!(q.query_type(), RecordType::DNSKEY | RecordType::DS) {
            return;
        }
        if let Ok(mut t) = self.trace.lock()
            && t.chain.len() < MAX_CHAIN_EVIDENCE
            && !t
                .chain
                .iter()
                .any(|c| c.qname == q.name().to_string() && c.qtype == rtype_text(q.query_type()))
        {
            t.chain.push(ChainAnswer {
                qname: q.name().to_lowercase().to_string(),
                qtype: rtype_text(q.query_type()),
                wire: wire.to_vec(),
            });
        }
    }

    fn fail(&self, why: String) -> NetError {
        if let Ok(mut t) = self.trace.lock()
            && t.failed.is_none()
        {
            t.failed = Some(why.clone());
        }
        NetError::from(why)
    }

    /// Turns an answer into what hickory's own stack would hand the validator. `original`: the
    /// answer to the validated question (the logged wire, or the fallback query's answer);
    /// `logged`: the logged wire, checked as of its receive time, where everything else is
    /// checked as of now (core.md §8).
    fn respond(
        &self,
        q: &Query,
        wire: Vec<u8>,
        original: bool,
        logged: bool,
    ) -> Result<DnsResponse, NetError> {
        let resp =
            DnsResponse::from_buffer(wire).map_err(|e| self.fail(format!("a malformed answer: {e}")))?;
        let at = if logged { logged_time() } else { unix_now() };
        self.note_message(&resp, q, logged, at);
        if original && let Ok(mut t) = self.trace.lock() {
            t.original = Some(resp.clone().into_message());
            t.rcode = Some(rcode_text(resp.metadata.response_code));
        }
        // hickory verifies this response next, as of `at` ([`AsOf`]).
        verify_next_as_of(at);
        DnsError::from_response(resp).map_err(NetError::from)
    }

    async fn answer(&self, q: Option<Query>) -> Result<DnsResponse, NetError> {
        let Some(q) = q else {
            return Err(NetError::from("no query in request"));
        };
        if let Some(l) = &self.logged
            && same_question(&l.0, &q)
        {
            return self.respond(&q, l.1.clone(), true, true);
        }
        let is_fallback = self.fallback.as_ref().is_some_and(|f| same_question(f, &q));
        let key = (q.name().to_lowercase().to_string(), u16::from(q.query_type()));
        if !is_fallback && let Some(wire) = self.shared.cache.get(&key) {
            self.record_chain(&q, &wire);
            return self.respond(&q, wire, false, false);
        }
        {
            let Ok(mut t) = self.trace.lock() else {
                return Err(NetError::from("trace poisoned"));
            };
            if t.unreachable {
                return Err(NetError::from("no edge DoH listener reachable"));
            }
            if t.requests >= MAX_REQUESTS_PER_VALIDATION {
                drop(t);
                return Err(self.fail("too many requests for one validation".into()));
            }
            t.requests += 1;
        }
        // Work beyond the rate waits (core.md §8); the wait isn't the validation's own time.
        {
            let _wait = self.waits.begin();
            self.shared.limiter.acquire().await;
        }
        let wire = match self.shared.resolver.query(q.name(), q.query_type()).await {
            Ok(w) => w,
            Err(ResolveError::Unreachable(why)) => {
                if let Ok(mut t) = self.trace.lock() {
                    t.unreachable = true;
                }
                return Err(NetError::from(why));
            }
            Err(ResolveError::Failed(why)) => return Err(self.fail(why)),
        };
        let msg = Message::from_vec(&wire).map_err(|e| self.fail(format!("a malformed answer: {e}")))?;
        let rcode = msg.metadata.response_code;
        if is_fallback {
            let stale = msg.edns.as_ref().is_some_and(|e| {
                e.options()
                    .get_all(EdnsCode::from(15u16))
                    .iter()
                    .any(|o| matches!(o, hickory_net::proto::rr::rdata::opt::EdnsOption::Unknown(15, d) if d.get(..2) == Some(&[0, 3])))
            });
            if stale && let Ok(mut t) = self.trace.lock() {
                t.stale = true;
            }
        }
        match rcode {
            ResponseCode::NoError | ResponseCode::NXDomain => {}
            other => {
                if is_fallback && let Ok(mut t) = self.trace.lock() {
                    t.rcode = Some(rcode_text(other));
                }
                return Err(self.fail(format!("{} {}: {other}", q.name(), q.query_type())));
            }
        }
        if !is_fallback {
            self.shared
                .cache
                .put(self.shared.generation, key, wire.clone(), cache_ttl(&msg));
            self.record_chain(&q, &wire);
        }
        self.respond(&q, wire, is_fallback, false)
    }
}

impl DnsHandle for Adapter {
    type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
    type Runtime = AsOfRuntime;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let q = request.queries.first().cloned();
        let this = self.clone();
        Box::pin(stream::once(async move { this.answer(q).await }))
    }
}

// ---------------------------------------------------------------------------------------------
// Reading the verdict

/// The outcome of hickory's result for `query`.
fn outcome_of(result: &Result<DnsResponse, NetError>) -> (Option<Outcome>, Option<String>) {
    match result {
        Ok(m) => {
            let answers: Vec<&Record> = m
                .answers
                .iter()
                .filter(|r| r.record_type() != RecordType::RRSIG)
                .collect();
            let records: Vec<&Record> = if answers.is_empty() {
                m.authorities
                    .iter()
                    .filter(|r| r.record_type() != RecordType::RRSIG)
                    .collect()
            } else {
                answers
            };
            // hickory returned the message without records to judge: the name is provably
            // insecure (its DS lookups said so).
            let mut o = if records.is_empty() {
                Outcome::Insecure
            } else {
                Outcome::Secure
            };
            for r in records {
                o = o.worse(Outcome::of(r.proof));
            }
            (Some(o), None)
        }
        Err(NetError::Dns(DnsError::Nsec { proof, .. })) => {
            (Some(Outcome::of(*proof)), Some(format!("NSEC proof: {proof}")))
        }
        Err(e) => (None, Some(e.to_string())),
    }
}

/// The zone named in a hickory proof error (`no dnskey was found: example.`, …).
fn zone_in_kind(kind: &str) -> Option<String> {
    for p in [
        "no dnskey was found: ",
        "ds record exists, but no dnskey: ",
        "dnskey has no ds: ",
        "ds record should exist: ",
        "dnskey revoked: ",
        "dnskey insecure: ",
        "not a zone signing key: ",
        "dnskey and rrset failed to verify: ",
    ] {
        if let Some(rest) = kind.find(p).map(|i| &kind[i + p.len()..]) {
            let name = rest.split([',', ' ']).next().unwrap_or("").trim();
            if !name.is_empty() {
                return Some(name.trim_end_matches('.').to_ascii_lowercase());
            }
        }
    }
    None
}

/// The RFC 8914 code 1.1.1.1 would return for a Bogus outcome (core.md §8), from hickory's proof
/// error and the signatures of what failed, each with the time it was checked against. hickory's
/// error kinds that RFC 8914 tells apart:
///
/// | hickory's proof error | code |
/// |---|---|
/// | `rrsigs are not present` | 10 RRSIGs Missing |
/// | `no dnskey was found`, `ds record exists, but no dnskey`, `dnskey has no ds` (no DNSKEY matches the parent's DS) | 9 DNSKEY Missing |
/// | `not a zone signing key` (the key lacks the Zone Key bit) | 11 No Zone Key Bit Set |
/// | `ds record should exist` without NSEC/NSEC3 in the answer | 12 NSEC Missing |
/// | an NSEC proof that fails with no NSEC/NSEC3 in the answer | 12 NSEC Missing |
/// | a signature that didn't verify, or any other error, when a signature of what failed was expired / not yet valid at its time | 7 Signature Expired / 8 Signature Not Yet Valid |
/// | everything else (revoked or insecure keys, algorithm mismatch, bad crypto, a bad denial) | 6 DNSSEC Bogus |
///
/// Codes 1 and 2 (unsupported DNSKEY algorithm, unsupported DS digest) never apply: hickory
/// proves those answers Insecure, not Bogus.
pub fn ede_for(kind: Option<&str>, nsec_error: bool, had_nsec: bool, sigs: &[SigWindow]) -> u16 {
    const DNSSEC_BOGUS: u16 = 6;
    const SIG_EXPIRED: u16 = 7;
    const SIG_NOT_YET_VALID: u16 = 8;
    const DNSKEY_MISSING: u16 = 9;
    const RRSIGS_MISSING: u16 = 10;
    const NO_ZONE_KEY_BIT: u16 = 11;
    const NSEC_MISSING: u16 = 12;
    let timing = || {
        if sigs.iter().any(|s| s.expiration < s.at) {
            Some(SIG_EXPIRED)
        } else if sigs.iter().any(|s| s.inception > s.at) {
            Some(SIG_NOT_YET_VALID)
        } else {
            None
        }
    };
    match kind {
        Some(k) if k.contains("rrsigs are not present") => RRSIGS_MISSING,
        Some(k)
            if k.contains("no dnskey was found")
                || k.contains("ds record exists, but no dnskey")
                || k.contains("dnskey has no ds") =>
        {
            DNSKEY_MISSING
        }
        Some(k) if k.contains("not a zone signing key") => NO_ZONE_KEY_BIT,
        Some(k) if k.contains("ds record should exist") => {
            if had_nsec {
                DNSSEC_BOGUS
            } else {
                NSEC_MISSING
            }
        }
        Some(_) => timing().unwrap_or(DNSSEC_BOGUS),
        None if nsec_error && !had_nsec => NSEC_MISSING,
        None => timing().unwrap_or(DNSSEC_BOGUS),
    }
}

/// The RRset a proof error names as unverified (`rrsigs were not able to be verified: NAME, type:
/// TYPE`), if any.
fn unverified_rrset(kind: &str) -> Option<(Name, RecordType)> {
    const P: &str = "rrsigs were not able to be verified: ";
    let rest = &kind[kind.find(P)? + P.len()..];
    let (name, rest) = rest.split_once(", type: ")?;
    let ty = rest.split([' ', ':', ',']).next()?;
    Some((Name::from_ascii(name).ok()?.to_lowercase(), ty.parse().ok()?))
}

/// The time cell `[lo, hi)` around `t` that the boundaries leave.
fn cell(bounds: &[u64], t: u64) -> (u64, u64) {
    let lo = bounds.iter().copied().filter(|b| *b <= t).max().unwrap_or(0);
    let hi = bounds
        .iter()
        .copied()
        .filter(|b| *b > t)
        .min()
        .unwrap_or(u64::MAX);
    (lo, hi)
}

/// Verdicts per answer id with the time cells they hold for (crypto reused by answer id) and
/// when they were found.
type MemoMap = HashMap<String, Vec<((u64, u64), Instant, Verdict)>>;

/// The longest a memoized verdict is reused: the chain it was found with is checked as of when
/// it was used, and a chain answer is cached no longer than this either.
pub const MEMO_MAX_AGE: Duration = Duration::from_secs(CHAIN_CACHE_MAX_TTL as u64);

/// Verdicts reused by answer id. Like the chain cache, it takes verdicts only from validations
/// of its restore generation ([`CryptoMemo::reset_to`]; core.md §2).
#[derive(Default)]
pub struct CryptoMemo {
    inner: Mutex<(MemoMap, VecDeque<String>, u64)>,
}

impl CryptoMemo {
    /// A verdict for receive time `t` found earlier: `t` in its cell, the chain's signatures
    /// still in theirs now, and found within [`MEMO_MAX_AGE`].
    pub fn get(&self, answer_id: &str, t: u64) -> Option<Verdict> {
        let now = unix_now();
        let g = self.inner.lock().ok()?;
        g.0.get(answer_id)?
            .iter()
            .find(|((lo, hi), found, v)| {
                *lo <= t
                    && t < *hi
                    && v.chain_cell.0 <= now
                    && now < v.chain_cell.1
                    && found.elapsed() < MEMO_MAX_AGE
            })
            .map(|(_, _, v)| Verdict {
                reused: true,
                requests: 0,
                ..v.clone()
            })
    }

    /// Keeps a verdict a validation of restore generation `generation` found.
    pub fn put(&self, generation: u64, answer_id: &str, v: &Verdict) {
        if v.retry() || v.unreachable {
            return;
        }
        let Ok(mut g) = self.inner.lock() else { return };
        if g.2 != generation {
            return;
        }
        let list = g.0.entry(answer_id.to_string()).or_default();
        let new = list.is_empty();
        list.retain(|(_, found, _)| found.elapsed() < MEMO_MAX_AGE);
        if list.len() < 8 {
            // Bounded (README §2): the chain answers stay with the first verdict's evidence.
            let kept = Verdict {
                chain: Vec::new(),
                ..v.clone()
            };
            list.push((v.cell, Instant::now(), kept));
        }
        if new {
            g.1.push_back(answer_id.to_string());
        }
        while g.0.len() > MEMO_ANSWERS {
            let Some(old) = g.1.pop_front() else { break };
            g.0.remove(&old);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.0.clear();
            g.1.clear();
        }
    }

    /// Forgets every verdict and takes only those of restore generation `generation` from now
    /// on (a restore).
    pub fn reset_to(&self, generation: u64) {
        if let Ok(mut g) = self.inner.lock() {
            g.0.clear();
            g.1.clear();
            g.2 = generation;
        }
    }
}

/// What to validate.
pub enum Subject<'a> {
    /// A logged answer: its question and wire, its own records checked as of `as_of` (its
    /// `received_at`), the chain as of now.
    Logged { query: Query, wire: &'a [u8] },
    /// Core's own query (fallback), validated as of now.
    Fallback { query: Query },
}

/// Parses a log-text name (`\DDD` escapes, api.md §5) into a fully qualified, lowercase name.
pub fn parse_name(text: &str) -> Option<Name> {
    if text.is_empty() || text.len() > 1100 {
        return None;
    }
    let text = text.strip_suffix('.').unwrap_or(text);
    let mut labels: Vec<Vec<u8>> = vec![Vec::new()];
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                let digits = b.get(i + 1..i + 4)?;
                if !digits.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                let v: u16 = std::str::from_utf8(digits).ok()?.parse().ok()?;
                labels.last_mut()?.push(u8::try_from(v).ok()?);
                i += 4;
            }
            b'.' => {
                labels.push(Vec::new());
                i += 1;
            }
            c => {
                labels.last_mut()?.push(c);
                i += 1;
            }
        }
    }
    if labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return None;
    }
    let mut n = Name::from_labels(labels.iter().map(|l| l.as_slice())).ok()?;
    n.set_fqdn(true);
    Some(n.to_lowercase())
}

/// Parses a log-text qtype (`A`, `AAAA`, `TYPE65`).
pub fn parse_qtype(text: &str) -> Option<RecordType> {
    if let Some(n) = text.strip_prefix("TYPE") {
        return n.parse::<u16>().ok().map(RecordType::from);
    }
    text.parse::<RecordType>().ok()
}

/// Validates one subject (core.md §8).
pub async fn validate(shared: &Shared, subject: Subject<'_>, as_of: u64) -> Verdict {
    let (query, logged, fallback) = match subject {
        Subject::Logged { query, wire } => (query.clone(), Some(Arc::new((query, wire.to_vec()))), None),
        Subject::Fallback { query } => (query.clone(), None, Some(query)),
    };
    let trace = Arc::new(Mutex::new(Trace::default()));
    let waits = Arc::new(RateWaits::default());
    let adapter = Adapter {
        shared: shared.clone(),
        logged,
        fallback,
        trace: trace.clone(),
        waits: waits.clone(),
    };
    let handle =
        DnssecDnsHandle::with_trust_anchor(adapter, shared.anchors.clone()).validation_cache_size(64);
    let captured: Arc<Mutex<Vec<String>>> = Arc::default();
    let opts = DnsRequestOptions::default();
    let fut = handle.lookup(query.clone(), opts).first_answer();
    let fut = tracing::instrument::WithSubscriber::with_subscriber(fut, capture_dispatch());
    let times = Arc::new(AsOf {
        logged: as_of,
        next: AtomicU64::new(as_of),
    });
    let fut = CAPTURED.scope(captured.clone(), AS_OF.scope(times, fut));
    // The timeout bounds the validation's own work and requests: time spent waiting for rate
    // tokens moves the deadline (core.md §8: work beyond the rate waits).
    let mut fut = std::pin::pin!(fut);
    let mut deadline = tokio::time::Instant::now() + VALIDATION_TIMEOUT;
    let mut credited = Duration::ZERO;
    let result = loop {
        match tokio::time::timeout_at(deadline, fut.as_mut()).await {
            Ok(r) => break r,
            Err(_) => {
                let waited = waits.total();
                let extra = waited.saturating_sub(credited);
                if extra.is_zero() {
                    break Err(NetError::from("the validation timed out"));
                }
                credited = waited;
                deadline += extra;
            }
        }
    };
    let (outcome, err_text) = outcome_of(&result);
    let mut t = std::mem::take(&mut *trace.lock().unwrap_or_else(|p| p.into_inner()));
    let kinds = captured.lock().map(|g| g.clone()).unwrap_or_default();
    let mut v = Verdict {
        chain: std::mem::take(&mut t.chain),
        failed: t.failed.clone(),
        unreachable: t.unreachable,
        stale: t.stale,
        requests: t.requests,
        rcode: t.rcode.clone(),
        cell: cell(&t.bounds, as_of),
        chain_cell: cell(&t.chain_bounds, unix_now()),
        ..Verdict::default()
    };
    if v.unreachable {
        return v;
    }
    if outcome.is_none() && v.failed.is_none() {
        v.failed = err_text.clone();
    }
    v.outcome = outcome;
    if matches!(outcome, Some(Outcome::Bogus) | Some(Outcome::Indeterminate)) {
        let kind = kinds
            .iter()
            .find(|k| !k.contains("ds record does not exist"))
            .cloned();
        v.proof = kind.clone().or(err_text.clone());
        let nsec_error = matches!(result, Err(NetError::Dns(DnsError::Nsec { .. })));
        let original = t.original.as_ref();
        let had_nsec = original.is_some_and(|m| {
            m.authorities
                .iter()
                .any(|r| matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3))
        });
        // The signatures of what failed: those of the RRset hickory's error names, else those
        // covering the Bogus records of the result, else every signature the validation saw.
        let bogus: Vec<(Name, RecordType)> = match &result {
            Ok(m) => m
                .answers
                .iter()
                .chain(m.authorities.iter())
                .filter(|r| r.proof == Proof::Bogus && r.record_type() != RecordType::RRSIG)
                .map(|r| (r.name.to_lowercase(), r.record_type()))
                .collect(),
            _ => vec![],
        };
        let named = kind.as_deref().and_then(unverified_rrset);
        let mut covering: Vec<&SigSeen> = match &named {
            Some((n, ty)) => t
                .rrsigs
                .iter()
                .filter(|s| s.covered == *ty && s.owner == *n)
                .collect(),
            None => vec![],
        };
        if covering.is_empty() {
            covering = t
                .rrsigs
                .iter()
                .filter(|s| bogus.iter().any(|(_, bt)| *bt == s.covered))
                .collect();
        }
        let windows: Vec<SigWindow> = if covering.is_empty() {
            t.rrsigs.iter().map(|s| s.window).collect()
        } else {
            covering.iter().map(|s| s.window).collect()
        };
        if outcome == Some(Outcome::Bogus) {
            v.ede = Some(ede_for(kind.as_deref(), nsec_error, had_nsec, &windows));
        }
        // The broken zone: named by a chain error, else the signer of what failed, else the
        // zone of the negative answer's SOA (core.md §8: keyed on the name when it can't be told).
        v.zone = kind
            .as_deref()
            .and_then(zone_in_kind)
            .or_else(|| {
                covering
                    .first()
                    .map(|s| s.signer.to_string().trim_end_matches('.').to_string())
            })
            .or_else(|| {
                original.and_then(|m| {
                    m.authorities
                        .iter()
                        .find(|r| r.record_type() == RecordType::SOA)
                        .map(|r| {
                            r.name
                                .to_lowercase()
                                .to_string()
                                .trim_end_matches('.')
                                .to_string()
                        })
                })
            })
            .filter(|z| !z.is_empty());
        // hickory reports a zone whose DNSKEYs all lack the Zone Key bit as having no DNSKEY
        // (their signatures can't verify, so none counts): with keys fetched for that zone and
        // none a zone key, it is No Zone Key Bit Set (11) (RFC 8914 §4.12).
        if v.ede == Some(9)
            && let Some(z) = v.zone.as_deref()
            && let Some(keys) = t
                .dnskeys
                .iter()
                .find(|(n, _)| n.to_string().trim_end_matches('.').eq_ignore_ascii_case(z))
                .map(|(_, k)| k)
            && !keys.is_empty()
            && keys.iter().all(|(_, zone)| !zone)
        {
            v.ede = Some(11);
        }
        // hickory drops the per-key reason a signature failed (it reports the RRset as
        // unverified), so the keys fetched tell the codes apart: no key with the tag the failed
        // signature names is DNSKEY Missing (9); only keys without the Zone Key bit, No Zone Key
        // Bit Set (11) (RFC 8914 §4.10, §4.12).
        if v.ede == Some(6)
            && let Some(sig) = covering.first().copied().or_else(|| t.rrsigs.first())
            && let Some(keys) = t.dnskeys.get(&sig.signer)
        {
            let same_tag: Vec<bool> = keys
                .iter()
                .filter(|(tag, _)| *tag == sig.key_tag)
                .map(|(_, zone)| *zone)
                .collect();
            if same_tag.is_empty() {
                v.ede = Some(9);
                v.zone
                    .get_or_insert_with(|| sig.signer.to_string().trim_end_matches('.').to_string());
            } else if same_tag.iter().all(|zone| !zone) {
                v.ede = Some(11);
                v.zone
                    .get_or_insert_with(|| sig.signer.to_string().trim_end_matches('.').to_string());
            }
        }
    }
    v
}

/// The question of a subject.
pub fn question(qname: &Name, qtype: RecordType) -> Query {
    let mut q = Query::query(qname.clone(), qtype);
    q.set_query_class(DNSClass::IN);
    q
}

/// RRSIG times as seen, for tests.
pub fn rrsig_window(sig: &RRSIG) -> (u64, u64) {
    let i = sig.input();
    (
        u64::from(i.sig_inception.get()),
        u64::from(i.sig_expiration.get()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worse_outcomes_win() {
        assert_eq!(Outcome::Secure.worse(Outcome::Insecure), Outcome::Insecure);
        assert_eq!(Outcome::Bogus.worse(Outcome::Secure), Outcome::Bogus);
        assert_eq!(
            Outcome::Insecure.worse(Outcome::Indeterminate),
            Outcome::Indeterminate
        );
    }

    fn w(inception: u64, expiration: u64, at: u64) -> SigWindow {
        SigWindow {
            inception,
            expiration,
            at,
        }
    }

    #[test]
    fn ede_codes() {
        let unverified = Some("rrsigs were not able to be verified: a., type: A");
        assert_eq!(
            ede_for(
                Some("rrsigs are not present for: a. record_type: A"),
                false,
                false,
                &[]
            ),
            10
        );
        assert_eq!(ede_for(Some("no dnskey was found: a."), false, false, &[]), 9);
        assert_eq!(ede_for(Some("dnskey has no ds: a."), false, false, &[]), 9);
        assert_eq!(
            ede_for(
                Some("not a zone signing key: test. key_tag: 10"),
                false,
                false,
                &[]
            ),
            11,
            "RFC 8914 §4.12 No Zone Key Bit Set"
        );
        assert_eq!(ede_for(Some("ds record should exist: a."), false, false, &[]), 12);
        assert_eq!(ede_for(Some("ds record should exist: a."), false, true, &[]), 6);
        assert_eq!(ede_for(unverified, false, false, &[w(1, 5, 10)]), 7);
        assert_eq!(ede_for(unverified, false, false, &[w(20, 30, 10)]), 8);
        assert_eq!(ede_for(unverified, false, false, &[w(1, 30, 10)]), 6);
        // Each signature against its own time: a chain signature valid now, the answer's
        // expired when it was received.
        assert_eq!(
            ede_for(unverified, false, false, &[w(1, 30, 40), w(35, 90, 40)]),
            7
        );
        assert_eq!(ede_for(unverified, false, false, &[w(35, 90, 40)]), 6);
        assert_eq!(
            ede_for(Some("dnskey revoked: a., key_tag: 1"), false, false, &[]),
            6
        );
        assert_eq!(ede_for(None, true, false, &[]), 12);
        assert_eq!(ede_for(None, true, true, &[]), 6);
    }

    #[test]
    fn unverified_rrsets_named() {
        assert_eq!(
            unverified_rrset("www.x. record_type: A: rrsigs were not able to be verified: www.x., type: A"),
            Some((Name::from_ascii("www.x.").unwrap(), RecordType::A))
        );
        assert_eq!(
            unverified_rrset("rrsigs were not able to be verified: x., type: DNSKEY"),
            Some((Name::from_ascii("x.").unwrap(), RecordType::DNSKEY))
        );
        assert_eq!(unverified_rrset("no dnskey was found: a."), None);
    }

    #[test]
    fn zones_from_kinds() {
        assert_eq!(
            zone_in_kind("no dnskey was found: Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            zone_in_kind("dnskey and rrset failed to verify: x.example. key_tag: 4").as_deref(),
            Some("x.example")
        );
        assert_eq!(zone_in_kind("rrsigs are not present for: a."), None);
    }

    #[test]
    fn cells_between_boundaries() {
        assert_eq!(cell(&[10, 20, 31], 15), (10, 20));
        assert_eq!(cell(&[10, 20], 5), (0, 10));
        assert_eq!(cell(&[10, 20], 25), (20, u64::MAX));
        assert_eq!(cell(&[], 25), (0, u64::MAX));
    }

    #[test]
    fn names_and_types_from_log_text() {
        assert_eq!(parse_name("Example.com").unwrap().to_string(), "example.com.");
        assert_eq!(parse_name("a\\032b.example").unwrap().num_labels(), 2);
        assert_eq!(parse_name("www.example.com.").unwrap().num_labels(), 3);
        assert!(parse_name("a..b").is_none());
        assert!(parse_name("a\\9").is_none());
        assert!(parse_name("").is_none());
        assert_eq!(parse_qtype("AAAA"), Some(RecordType::AAAA));
        assert_eq!(parse_qtype("TYPE65"), Some(RecordType::HTTPS));
        assert_eq!(parse_qtype("nope"), None);
    }

    #[tokio::test]
    async fn the_limiter_paces() {
        let l = Limiter::new(2);
        assert!(l.try_take().is_ok());
        assert!(l.try_take().is_ok());
        assert!(l.try_take().is_err(), "a third request in the minute waits");
    }

    /// core.md §8 (review round 2, R12): two requests of one validation waiting at once (hickory
    /// checks a record set's signatures concurrently) credit the time either waits, once; a wait
    /// whose request is dropped stops counting.
    #[tokio::test(start_paused = true)]
    async fn concurrent_rate_waits_are_credited_once() {
        let w = RateWaits::default();
        let a = w.begin();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let b = w.begin();
        tokio::time::sleep(Duration::from_secs(4)).await;
        drop(a);
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(b);
        assert_eq!(
            w.total(),
            Duration::from_secs(10),
            "from the first wait's start to the last's end"
        );
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(w.total(), Duration::from_secs(10), "nothing waits");
        // A wait dropped mid-way (its request lost a select) ends there.
        {
            let _c = w.begin();
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(w.total(), Duration::from_secs(12));
    }
}
