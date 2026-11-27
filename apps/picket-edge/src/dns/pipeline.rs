//! The query pipeline (edge.md §4, rules.md §5–§6):
//!
//! ```text
//! check (picket-wire on hickory) → device limits → profile (§5) → special names → forward zone?
//!   → [1] temporary allow → [2] allow bundles → [3] block bundles (BLOCK/REWRITE → reply)
//!   → cache / upstream (validate + scrub on miss) ∥ [4] sync lookups in scope
//!   → [5] response checks → join lookups (deadline → fail_mode) → TTL clamp → firewall ensure
//!   → send → log (never blocks)
//! ```
//!
//! - Owner decisions: QCLASS `*` (255) and the meta qtypes are answered NOTIMP (S7); an
//!   upstream answer with TC over a stream transport fails that upstream (S6, in the pool).
//! - Only recursion-desired queries are answered (edge.md §16): others get REFUSED, uncounted
//!   as a decision (`rejected`).
//! - Latency is `max(upstream, lookups)`: the two run concurrently. When [4] and [5] both block,
//!   the lower step (the lookup) decides.
//! - Every query runs inside `catch_unwind` ([`serve`]): a panic answers SERVFAIL, counts in
//!   `panics` and logs a `panic` event (edge.md §16).
//! - Hot path (build-and-test.md §4): a cache hit or a block reply allocates nothing after
//!   decoding. The reply goes into the buffer the listener lends ([`serve_with`]), and the `q`
//!   record's text fields are built only when the profile's `log` keeps the record.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures_util::FutureExt as _;

use picket_api::edge_config::{BlockResponseType, FailMode, LogLevel, PrivateReverse, ResponseChecks};
use picket_api::logs::{
    Decision, LookupItem, MatchKind, Proto, QueryRecord, Reason as LogReason, Stage, Timings, UpstreamInfo,
};
use picket_rules::rewrite::{RewriteAnswer, RewriteValue};
use picket_wire::reply::{self, MappingAnswer, NegativeKind, RecordData, RecordSpec};
use picket_wire::types::{class, rcode, rtype};
use picket_wire::{EdeOption, NameRef, QName, Query, ReplyTo, ServeParams, StaleServe, Transport, WireName};

use super::cache::{Entry, KeyRef, Lookup};
use super::filter::{self, BundleHit, LadderOut, Target, TempAllowHit, Verdict, Who};
use super::profiles::{Choice, Device, DeviceKey};
use super::runtime::{DnsRuntime, ProfileRt};
use super::upstream::{Cause, upstream_do};
use super::{BlockNote, FwAddr, FwRequest};
use crate::edge::{ActiveState, Edge};
use crate::logs::AnswerSlot;

/// TTL of the answers the edge makes for names it serves itself (managed listener names, local
/// zones), before the profile's clamp.
pub const LOCAL_TTL: u32 = 300;
/// TTL of the RFC 8482 answer to `ANY`, before the profile's clamp.
pub const ANY_TTL: u32 = 3600;

/// One received query.
#[derive(Clone, Copy, Debug)]
pub struct Inbound<'a> {
    pub msg: &'a [u8],
    pub client: SocketAddr,
    pub listener: &'a str,
    pub udp_payload: u16,
    pub proto: Proto,
    /// The profile named in the DoH path or DoT name.
    pub named_profile: Option<&'a str>,
    /// A DoH query with `X-Picket-Client: extension`.
    pub extension: bool,
    /// The watchdog's internal test query (edge.md §16): past the limiter and the profile
    /// choice, answered only from names the edge serves itself; never refused by the limits, and
    /// no log or metrics.
    pub internal: bool,
    /// Where the device's limits (edge.md §16) were applied.
    pub admitted: Admitted,
}

/// Where a query's per-device limits are applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Admitted {
    /// Here, by the pipeline.
    #[default]
    Here,
    /// By the listener, which holds the in-flight slot (DoH admits before reading a body, and
    /// answers a device over its limits itself, edge.md §16).
    Held,
}

/// Applies the device's limits for a query from `client` before the listener reads it (DoH,
/// edge.md §16): `Ok(Some(slot))` admitted, `Ok(None)` when no config is active (the pipeline
/// refuses it anyway), `Err(_)` over the limits.
pub fn admit_early(
    edge: &Edge,
    client: SocketAddr,
) -> Result<Option<super::limits::Slot>, super::limits::Over> {
    let active = edge.active();
    let Some(rt) = active.dns.as_ref() else {
        return Ok(None);
    };
    let src = client.ip().to_canonical();
    let device = rt.device(src, edge.neighbours.mac_of(&src));
    let key = rt.clients.key(&device);
    edge.dns
        .limiter
        .admit(
            key,
            rt.limits.client_qps,
            rt.limits.client_inflight,
            Instant::now(),
        )
        .map(Some)
}

/// What goes back.
#[derive(Clone, Debug, Default)]
pub struct Outbound {
    /// `None`: no reply (QR set, an unreadable header, a refused named profile over DoH).
    pub reply: Option<Vec<u8>>,
    /// A profile named in the DoH path refused the client: HTTP 403 (edge.md §5).
    pub named_refused: bool,
    /// The smallest TTL in the reply, for DoH's `Cache-Control` (edge.md §5).
    pub min_ttl: Option<u32>,
}

fn transport_of(p: Proto) -> Transport {
    Transport::of_proto(p)
}

fn is_meta_qtype(t: u16) -> bool {
    // RFC 6895 §3.1: OPT and 128–255 are QTYPE-only or meta types; ANY (255) has its own rule.
    t == rtype::OPT || ((128..=254).contains(&t))
}

fn reply_rcode(r: &[u8]) -> u16 {
    r.get(3).map_or(0, |b| u16::from(b & 0x0F))
}

/// The buffer the listener lends for the reply (build-and-test.md §4: serving after decoding
/// allocates nothing once the listener reuses its buffers). A reply is written into it; a second
/// reply for the same query (a firewall SERVFAIL replacing an answer) gets a fresh buffer.
struct ReplyBuf(std::sync::Mutex<Vec<u8>>);

impl ReplyBuf {
    fn new(buf: Vec<u8>) -> Self {
        Self(std::sync::Mutex::new(buf))
    }

    /// Takes the buffer (an empty one, no allocation, once taken).
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Writes with the buffer sized by `est`, retrying with the largest size if it was too small.
    fn write(
        &self,
        to: &ReplyTo<'_>,
        est: usize,
        mut f: impl FnMut(&mut [u8]) -> Result<reply::Reply, picket_wire::WriteError>,
    ) -> Option<(Vec<u8>, reply::Reply)> {
        let mut buf = self.take();
        buf.clear();
        buf.resize(to.limit.min(est.max(512)).max(512), 0);
        match f(&mut buf) {
            Ok(r) => {
                buf.truncate(r.len);
                Some((buf, r))
            }
            Err(_) => {
                buf.clear();
                buf.resize(to.limit.max(512), 0);
                let r = f(&mut buf).ok()?;
                buf.truncate(r.len);
                Some((buf, r))
            }
        }
    }
}

/// The `q` record under construction (edge.md §11). Its text fields cost allocations, so they are
/// filled only when the profile's `log` keeps the record ([`QLog::keeps`]): with `log: off`, or
/// `blocked` and an allowed answer, the serving path allocates nothing for it
/// (build-and-test.md §4). The fields every record carries are filled at the end, from what the
/// query loaded once ([`QLog::fill`]).
struct QLog<'a> {
    rec: QueryRecord,
    slot: AnswerSlot,
    level: LogLevel,
    inb: &'a Inbound<'a>,
    q: &'a Query,
    active: &'a ActiveState,
    /// The device, for the record's `device`.
    device: Option<(&'a DnsRuntime, &'a Device)>,
    profile: Option<Arc<str>>,
    /// The reply's rcode, if a reply was made.
    rcode: Option<u16>,
    /// The step that let the query through, kept as it was found: its `reason` is built when the
    /// record is filled, so a record kept only by what came later (an unchecked cold lookup in
    /// the response checks) still carries it.
    pass: Option<PassReason>,
}

/// What let a query through, for the record's `reason` (api.md §5). One per query, on the
/// stack: boxing the hit would allocate on the serving path (build-and-test.md §4).
enum PassReason {
    /// A forward zone (step 0).
    Forward(Arc<str>),
    /// Step 1.
    TempAllow(TempAllowHit),
    /// Step 2.
    Allow(BundleHit),
    /// Step 3: a block bundle's exception let the name through (api.md §5 `reason` with the
    /// exception's bundle, key and kind; core.md §6 attributes it).
    Exception(BundleHit),
}

impl PassReason {
    fn reason(&self) -> LogReason {
        match self {
            PassReason::Forward(zone) => LogReason {
                step: 0,
                kind: MatchKind::Forward,
                key: Some(zone.to_string()),
                ..Default::default()
            },
            PassReason::TempAllow(h) => filter::temp_allow_reason(h),
            PassReason::Allow(h) => filter::log_reason(h, 2, Stage::Query, None, None),
            PassReason::Exception(h) => filter::log_reason(h, 3, Stage::Query, None, None),
        }
    }
}

impl<'a> QLog<'a> {
    fn new(inb: &'a Inbound<'a>, q: &'a Query, active: &'a ActiveState) -> Self {
        let rec = QueryRecord {
            h: crate::logs::placeholder_header(),
            listener: String::new(),
            proto: inb.proto,
            client: String::new(),
            device: None,
            profile: None,
            qname: String::new(),
            qtype: String::new(),
            dnssec_ok: q.do_bit(),
            rcode: String::new(),
            decision: Decision::Allow,
            reason: None,
            answers: vec![],
            targets: vec![],
            truncated: false,
            cname: vec![],
            lookups: vec![],
            upstream: None,
            fw: None,
            us: Timings::default(),
            versions: Default::default(),
            answer_id: None,
            received_at: None,
            age_s: None,
            response: None,
            tc: false,
            cold_unchecked: vec![],
            edns: None,
        };
        Self {
            rec,
            slot: AnswerSlot::None,
            level: LogLevel::Full,
            inb,
            q,
            active,
            device: None,
            profile: None,
            rcode: None,
            pass: None,
        }
    }

    /// True when the profile's `log` keeps the record as it stands (its decision set first).
    fn keeps(&self) -> bool {
        crate::logs::query_admitted(self.level, &self.rec)
    }

    /// Fills the fields every kept record carries. The record names the versions of the active
    /// state the query loaded (edge.md §11 Versions).
    fn fill(&mut self) {
        let r = &mut self.rec;
        r.listener = self.inb.listener.to_owned();
        r.client = picket_wire::log::ip_text(self.inb.client.ip());
        r.qname = self.q.qname().as_name().log_text();
        r.qtype = picket_wire::types::TypeText(self.q.qtype).to_string();
        r.edns = self.q.edns_log();
        r.versions = self.active.versions.as_deref().cloned().unwrap_or_default();
        if let Some(rc) = self.rcode {
            r.rcode = picket_wire::types::RcodeText(rc).to_string();
        }
        if let Some((rt, d)) = self.device {
            r.device = rt.clients.log_name(d);
        }
        r.profile = self.profile.as_deref().map(str::to_owned);
        // A later step that decided (a block in the response checks) set its own reason.
        if r.reason.is_none()
            && let Some(p) = &self.pass
        {
            r.reason = Some(p.reason());
        }
    }

    fn preview(&mut self, facts: &picket_wire::AnswerFacts, ip: Option<IpAddr>, target: Option<&WireName>) {
        let p = picket_wire::log::Preview::of(facts, ip, target);
        self.rec.answers = p
            .answers
            .iter()
            .map(|ip| picket_wire::log::ip_text(*ip))
            .collect();
        self.rec.targets = p.targets.iter().map(|t| t.log_text()).collect();
        self.rec.cname = facts.chain.iter().map(|c| c.log_text()).collect();
        if p.cut {
            self.rec.truncated = true;
        }
    }

    fn answer(&mut self, e: &Entry, age: u32) {
        self.slot = e.slot();
        self.rec.answer_id = e.answer.as_ref().map(|a| a.id.clone());
        self.rec.received_at = picket_api::time::Timestamp::try_from(e.value.received_at()).ok();
        self.rec.age_s = Some(age);
    }

    fn response(&mut self, reply: &[u8]) {
        self.rec.response = Some(base64::engine::general_purpose::STANDARD.encode(reply));
    }
}

/// Serves one query inside `catch_unwind` (edge.md §16).
pub async fn serve(edge: &Edge, inb: Inbound<'_>) -> Outbound {
    serve_with(edge, inb, Vec::new()).await
}

/// [`serve`], writing the reply into `buf` (the listener's, reused across its queries): the
/// reply comes back in [`Outbound::reply`] in that allocation.
pub async fn serve_with(edge: &Edge, inb: Inbound<'_>, buf: Vec<u8>) -> Outbound {
    match AssertUnwindSafe(handle(edge, inb, buf)).catch_unwind().await {
        Ok(o) => o,
        Err(p) => {
            let msg = crate::supervisor::panic_message(p);
            tracing::error!("query task panicked: {msg}");
            edge.metrics.panics.fetch_add(1, Relaxed);
            edge.logs.event(
                picket_api::logs::event_kind::PANIC,
                crate::logs::fields(&[("task", "query".into()), ("message", msg.into())]),
            );
            servfail_reply(inb.msg, inb.proto, inb.udp_payload)
        }
    }
}

fn servfail_reply(msg: &[u8], proto: Proto, payload: u16) -> Outbound {
    let Ok(q) = picket_wire::check_query(msg) else {
        return Outbound::default();
    };
    let to = q.reply_to(transport_of(proto), payload);
    let rb = ReplyBuf::new(Vec::new());
    let reply = rb
        .write(&to, 512, |b| reply::write_rcode(b, &to, rcode::SERVFAIL, &[]))
        .map(|(v, _)| v);
    Outbound {
        reply,
        named_refused: false,
        min_ttl: None,
    }
}

/// Handles one query, writing its reply into `buf`.
async fn handle(edge: &Edge, inb: Inbound<'_>, buf: Vec<u8>) -> Outbound {
    let start = Instant::now();
    let tstart = tokio::time::Instant::now();
    let m = &edge.metrics;
    let transport = transport_of(inb.proto);
    let rb = ReplyBuf::new(buf);
    let q = match picket_wire::check_query(inb.msg) {
        Ok(q) => q,
        Err(e) => {
            if !inb.internal {
                m.rejected.fetch_add(1, Relaxed);
            }
            let mut buf = rb.take();
            buf.clear();
            buf.resize(1024, 0);
            let reply =
                match picket_wire::write_query_error(&mut buf, inb.msg, &e, transport, inb.udp_payload) {
                    Ok(Some(n)) => {
                        buf.truncate(n);
                        Some(buf)
                    }
                    _ => None,
                };
            return Outbound {
                reply,
                ..Default::default()
            };
        }
    };
    let to = q.reply_to(transport, inb.udp_payload);
    let rcode_only = |rc: u16, ede: &[EdeOption<'_>]| -> Outbound {
        Outbound {
            reply: rb
                .write(&to, 512, |b| reply::write_rcode(b, &to, rc, ede))
                .map(|(v, _)| v),
            ..Default::default()
        }
    };
    // Owner decision S7 and the meta qtypes: NOTIMP, never forwarded.
    if q.qclass == class::ANY || is_meta_qtype(q.qtype) {
        if !inb.internal {
            m.rejected.fetch_add(1, Relaxed);
        }
        return rcode_only(rcode::NOTIMP, &[]);
    }
    // edge.md §16: only recursion-desired queries are answered.
    if !q.rd {
        if !inb.internal {
            m.rejected.fetch_add(1, Relaxed);
        }
        return rcode_only(rcode::REFUSED, &[]);
    }
    let active = edge.active();
    let Some(rt) = active.dns.clone() else {
        if !inb.internal {
            m.rejected.fetch_add(1, Relaxed);
        }
        return rcode_only(rcode::REFUSED, &[]);
    };
    let dns = &edge.dns;
    let src = inb.client.ip().to_canonical();
    let device = rt.device(src, edge.neighbours.mac_of(&src));
    let dkey = rt.clients.key(&device);
    let _slot = match inb.admitted {
        Admitted::Here => match dns.limiter.admit(
            dkey.clone(),
            rt.limits.client_qps,
            rt.limits.client_inflight,
            Instant::now(),
        ) {
            Ok(s) => Some(s),
            // The test query only shows the limiter answered (edge.md §16).
            Err(_) if inb.internal => None,
            Err(_) => {
                m.rejected.fetch_add(1, Relaxed);
                return rcode_only(rcode::REFUSED, &[]);
            }
        },
        Admitted::Held => None,
    };
    let choice = rt.choose(inb.named_profile, &device);
    if inb.internal {
        // edge.md §16: past the listener, the limiter and the profile choice, the test query is
        // for a name the edge answers itself, whatever profile its own address gets.
        return internal_answer(&rt, &q, &to, &rb);
    }
    let mut log = QLog::new(&inb, &q, &active);
    log.device = Some((&rt, &device));

    let pid = match choice {
        Choice::Profile(p) => p,
        refused => {
            let named = refused == Choice::NamedRefused;
            let ede = if named {
                EdeOption::profile_not_permitted()
            } else {
                EdeOption::not_permitted()
            };
            let out = if named && inb.proto == Proto::Doh {
                Outbound {
                    reply: None,
                    named_refused: true,
                    min_ttl: None,
                }
            } else {
                rcode_only(rcode::REFUSED, &[ede])
            };
            log.rec.decision = Decision::Refused;
            log.rcode = Some(rcode::REFUSED);
            finish(edge, log, start);
            return out;
        }
    };
    let Some(profile) = rt.profile(&pid).cloned() else {
        return rcode_only(rcode::REFUSED, &[EdeOption::not_permitted()]);
    };
    log.profile = Some(Arc::clone(&profile.id));
    log.level = profile.cfg.log;

    // The extension's recent-blocks probe (edge.md §12).
    if inb.extension
        && let Some(r) = dns
            .hooks
            .recent_blocks
            .load()
            .extension_probe(&dkey, src, &q, inb.msg)
    {
        return Outbound {
            reply: Some(r),
            ..Default::default()
        };
    }

    let ctx = Ctx {
        edge,
        rt: &rt,
        active: &active,
        profile: &profile,
        q: &q,
        to,
        device: &device,
        dkey: &dkey,
        tstart,
        buf: &rb,
    };
    let out = ctx.run(&mut log).await;
    finish(edge, log, start);
    out
}

/// The watchdog's internal query: a managed listener name, or a `home.arpa` name, answered by
/// the edge itself.
fn internal_answer(rt: &DnsRuntime, q: &Query, to: &ReplyTo<'_>, rb: &ReplyBuf) -> Outbound {
    let qn = q.qname().as_name();
    if let Some(mn) = rt.managed_answer(qn) {
        let reply = rb
            .write(to, 512, |b| reply::write_local_answer(b, to, &mn.ips, LOCAL_TTL))
            .map(|(v, _)| v);
        return Outbound {
            reply,
            ..Default::default()
        };
    }
    let reply = rb
        .write(to, 512, |b| {
            reply::write_negative(b, to, NegativeKind::Nxdomain, LOCAL_TTL, &[])
        })
        .map(|(v, _)| v);
    Outbound {
        reply,
        ..Default::default()
    }
}

fn finish(edge: &Edge, mut log: QLog<'_>, start: Instant) {
    let total = picket_api::duration::as_micros_u64(start.elapsed());
    log.rec.us.total = total;
    edge.metrics.count_decision(log.rec.decision);
    edge.metrics.latency_us.record_us(total);
    if log.keeps() {
        log.fill();
        edge.logs.emit_query(log.rec, log.slot);
    }
}

/// What the cache or the upstreams gave.
enum Got {
    Answer {
        entry: Arc<Entry>,
        age: u32,
        /// `Some(cause)`: served stale (EDE 3).
        stale: Option<&'static str>,
        cached: bool,
        ms: u32,
        group: Arc<str>,
    },
    Fail {
        cause: Cause,
        group: Arc<str>,
    },
}

/// A lookup's outcome with its provider and fail mode.
struct LookupRes {
    provider: Arc<str>,
    fail_mode: FailMode,
    outcome: picket_lookup::SyncOutcome,
}

struct Ctx<'a> {
    edge: &'a Edge,
    rt: &'a DnsRuntime,
    active: &'a ActiveState,
    profile: &'a Arc<ProfileRt>,
    q: &'a Query,
    to: ReplyTo<'a>,
    device: &'a Device,
    dkey: &'a DeviceKey,
    tstart: tokio::time::Instant,
    /// The listener's reply buffer.
    buf: &'a ReplyBuf,
}

impl<'a> Ctx<'a> {
    fn ttl(&self, t: u32) -> u32 {
        self.profile.cfg.ttl.clamp(t)
    }

    fn who_names(&self) -> (smallvec::SmallVec<[&str; 2]>, smallvec::SmallVec<[&str; 8]>) {
        match self.rt.clients.naming_client(self.device) {
            Some(c) => (
                smallvec::smallvec![&*c.name],
                c.tags.iter().map(|t| &**t).collect(),
            ),
            None => (smallvec::SmallVec::new(), smallvec::SmallVec::new()),
        }
    }

    fn local(&self, log: &mut QLog<'_>, out: Option<(Vec<u8>, reply::Reply)>, ttl: Option<u32>) -> Outbound {
        log.rec.decision = Decision::Allow;
        log.rec.reason = Some(LogReason {
            step: 0,
            kind: MatchKind::Local,
            ..Default::default()
        });
        self.finish_reply(log, out, ttl, true)
    }

    fn finish_reply(
        &self,
        log: &mut QLog<'_>,
        out: Option<(Vec<u8>, reply::Reply)>,
        ttl: Option<u32>,
        made: bool,
    ) -> Outbound {
        match out {
            Some((v, r)) => {
                log.rcode = Some(reply_rcode(&v));
                log.rec.tc = r.tc;
                if made && !r.tc && log.keeps() {
                    log.response(&v);
                }
                Outbound {
                    reply: Some(v),
                    named_refused: false,
                    min_ttl: ttl,
                }
            }
            None => Outbound::default(),
        }
    }

    async fn run(&self, log: &mut QLog<'_>) -> Outbound {
        let q = self.q;
        let qn = q.qname().as_name();
        let to = &self.to;
        let profile = self.profile;

        // Special names (edge.md §4).
        if let Some(mn) = self.rt.managed_answer(qn) {
            let ttl = self.ttl(LOCAL_TTL);
            let out = self.buf.write(to, 512 + 32 * mn.ips.len(), |b| {
                reply::write_local_answer(b, to, &mn.ips, ttl)
            });
            return self.local(log, out, Some(ttl));
        }
        if is_local_zone(qn) && !profile.zones.covers(qn) {
            let ttl = self.ttl(LOCAL_TTL);
            let out = self.buf.write(to, 512, |b| {
                reply::write_negative(b, to, NegativeKind::Nxdomain, ttl, &[])
            });
            return self.local(log, out, Some(ttl));
        }
        if profile.cfg.private_reverse == PrivateReverse::Nxdomain
            && picket_wire::reverse::is_private_reverse(qn)
            && !profile.zones.covers(qn)
        {
            let ttl = self.ttl(LOCAL_TTL);
            let out = self.buf.write(to, 512, |b| {
                reply::write_negative(b, to, NegativeKind::Nxdomain, ttl, &[])
            });
            return self.local(log, out, Some(ttl));
        }

        // Forward zones: straight to the zone's group, no bundles, lookups or response checks.
        if let Some(z) = profile.zones.longest_match(qn) {
            log.pass = Some(PassReason::Forward(Arc::clone(&z.id)));
            let mut got = self.get_answer(&z.group, true).await;
            if let Got::Fail { .. } = got
                && z.fallback == picket_api::edge_config::ZoneFallback::Default
            {
                got = self.get_answer(&profile.group, false).await;
            }
            return self.answer_out(log, got).await;
        }

        // Ladder steps 1–3.
        let (names, tags) = self.who_names();
        let who = Who {
            ip: self.device.ip,
            names: &names,
            tags: &tags,
        };
        let allows = self.edge.dns.temp_allows(self.edge);
        let fstart = Instant::now();
        let lad = filter::ladder(
            &self.active.bundles,
            profile,
            &who,
            self.dkey,
            &*allows,
            Target::Name(q.qname()),
            q.qtype,
        )
        .await;
        log.rec.us.filter = picket_api::duration::as_micros_u64(fstart.elapsed());
        self.note_cold(log, &lad);
        let (allowed, temp_allowed, exception) = match lad.verdict {
            Verdict::Block(h) => return self.bundle_block(log, &h, 3, Stage::Query, None, None),
            Verdict::Rewrite(h, ans) => return self.rewrite(log, &h, ans).await,
            Verdict::HostMapping(h, ips) => return self.host_mapping(log, &h, &ips).await,
            // edge.md §11: the reason is built only if the record is kept (QLog::fill).
            Verdict::TempAllow(h) => {
                log.pass = Some(PassReason::TempAllow(h));
                (true, true, false)
            }
            Verdict::Allow(h) => {
                log.pass = Some(PassReason::Allow(h));
                (true, false, false)
            }
            Verdict::Pass { exception, by } => {
                if let Some(h) = by {
                    log.pass = Some(PassReason::Exception(h));
                }
                (false, false, exception)
            }
        };

        // ANY (edge.md §4): no upstream query; a live Block in a lookup tier can still block.
        if q.qtype == rtype::ANY {
            if !allowed {
                let looks = self.run_lookups(&who, false).await;
                if let Some(o) = self.lookup_block(log, &looks) {
                    return o;
                }
                self.log_lookups(log, &looks);
            }
            let ttl = self.ttl(ANY_TTL);
            let out = self.buf.write(to, 512, |b| reply::write_any_minimal(b, to, ttl));
            return self.finish_reply(log, out, Some(ttl), true);
        }

        // Cache / upstream ∥ sync lookups.
        let lookups_on = !allowed && !profile.sync.is_empty();
        let (got, looks) = tokio::join!(self.get_answer(&profile.group, false), async {
            if lookups_on {
                self.run_lookups(&who, true).await
            } else {
                vec![]
            }
        });
        // [4] wins over [5] (rules.md §5: the lower step decides).
        if let Some(o) = self.lookup_block(log, &looks) {
            return o;
        }
        self.log_lookups(log, &looks);
        // [5] response checks.
        let check = match profile.cfg.response_checks {
            ResponseChecks::All => !temp_allowed,
            ResponseChecks::SkipAfterAllow => !allowed && !exception,
        };
        if check
            && let Got::Answer { entry, age, .. } = &got
            && let Some(o) = self.response_checks(log, &who, entry, *age).await
        {
            return o;
        }
        self.answer_out(log, got).await
    }

    fn note_cold(&self, log: &mut QLog<'_>, lad: &LadderOut) {
        for b in &lad.cold_unchecked {
            let s = b.to_string();
            if !log.rec.cold_unchecked.contains(&s) {
                log.rec.cold_unchecked.push(s);
            }
            self.edge.metrics.cold.get(b).unchecked.fetch_add(1, Relaxed);
        }
        // Page files that failed their checksum are deleted and fetched again, logged as
        // `page_file_refetched` (bundles.md §4 "Reading").
        for f in &lad.refetch {
            self.edge.bundles.request_refetch(f);
        }
    }

    /// The cache key for this question in `group`.
    fn key<'k>(&'k self, group: &'k str, name: NameRef<'k>, via_zone: bool) -> KeyRef<'k> {
        let (enc, generation) = self
            .edge
            .dns
            .pool
            .group(group)
            .map_or((false, 0), |g| (g.encrypted, g.generation));
        KeyRef::new(
            name,
            self.q.qtype,
            self.q.qclass,
            upstream_do(enc, via_zone, self.q.do_bit()),
            self.q.cd,
            group,
            generation,
        )
    }

    async fn get_answer(&self, group: &Arc<str>, via_zone: bool) -> Got {
        self.fetch_name(group, self.q.qname().as_name(), via_zone).await
    }

    /// Cache, then upstream (edge.md §8), with stale serving and the DO rules (§7 step 3).
    async fn fetch_name(&self, group: &Arc<str>, name: NameRef<'_>, via_zone: bool) -> Got {
        let dns = &self.edge.dns;
        let m = &self.edge.metrics;
        let client_do = self.q.do_bit();
        let key = self.key(group, name, via_zone);
        let optimistic = dns.pool.group(group).is_some_and(|g| g.optimistic);
        let settings = dns.resolver.cache.settings();
        let mut stale_candidate = None;
        match dns.resolver.cache.get(&key, Instant::now()) {
            Lookup::Fresh { entry, age } => {
                let elapsed = Instant::now().saturating_duration_since(entry.value.received_mono());
                if entry.note_hit(elapsed, settings.prefetch_min_hits)
                    && let Some(slot) = entry.try_refresh()
                {
                    dns.resolver.refresh(key.to_owned(), slot);
                }
                m.cache_hits.fetch_add(1, Relaxed);
                return Got::Answer {
                    entry,
                    age,
                    stale: None,
                    cached: true,
                    ms: 0,
                    group: Arc::clone(group),
                };
            }
            Lookup::Expired { entry, age } => {
                if optimistic && !entry.value.is_negative() && !client_do {
                    // One refresh in flight at a time; a failed one doesn't stop the next.
                    if let Some(slot) = entry.try_refresh() {
                        dns.resolver.refresh(key.to_owned(), slot);
                    }
                    m.cache_hits.fetch_add(1, Relaxed);
                    m.stale_served.fetch_add(1, Relaxed);
                    return Got::Answer {
                        entry,
                        age,
                        stale: Some("optimistic"),
                        cached: true,
                        ms: 0,
                        group: Arc::clone(group),
                    };
                }
                stale_candidate = Some((entry, age));
            }
            Lookup::Miss => {}
        }
        m.cache_misses.fetch_add(1, Relaxed);
        match dns.resolver.fetch(&key).await {
            Ok(f) => {
                if client_do && f.entry.value.facts().stale {
                    // A DO client never gets an upstream's stale answer: another upstream, else
                    // SERVFAIL (edge.md §7 step 3), each waiter on its own.
                    return match dns
                        .resolver
                        .fetch_fresh_only(&key, Arc::clone(&f.entry.upstream))
                        .await
                    {
                        Ok(f2) => Got::Answer {
                            entry: Arc::clone(&f2.entry),
                            age: 0,
                            stale: None,
                            cached: false,
                            ms: f2.rtt_ms,
                            group: Arc::clone(group),
                        },
                        Err(e) => Got::Fail {
                            cause: if e.cause == Cause::Down {
                                Cause::Stale
                            } else {
                                e.cause
                            },
                            group: Arc::clone(group),
                        },
                    };
                }
                // An upstream's stale answer (EDE 3) reaches a client without DO as a stale
                // answer (edge.md §4 EDE table, §7 step 3): EDE 3 `cause=stale` and `stale_ttl`,
                // as core rebuilds a reply logged with `upstream.stale` (core.md §6).
                let stale = f.entry.value.facts().stale.then(|| {
                    m.stale_served.fetch_add(1, Relaxed);
                    Cause::Stale.as_str()
                });
                Got::Answer {
                    entry: Arc::clone(&f.entry),
                    age: 0,
                    stale,
                    cached: false,
                    ms: f.rtt_ms,
                    group: Arc::clone(group),
                }
            }
            Err(fail) => match stale_candidate {
                // RFC 8767: stale data when every upstream fails, never to a DO client.
                Some((entry, age)) if !client_do => {
                    m.stale_served.fetch_add(1, Relaxed);
                    Got::Answer {
                        entry,
                        age,
                        stale: Some(fail.cause.as_str()),
                        cached: true,
                        ms: 0,
                        group: Arc::clone(group),
                    }
                }
                _ => Got::Fail {
                    cause: fail.cause,
                    group: Arc::clone(group),
                },
            },
        }
    }

    /// The reply for what the cache or upstreams gave (allowed path, forward zones included):
    /// its addresses go through the firewall ensure point first (edge.md §4, §9).
    async fn answer_out(&self, log: &mut QLog<'_>, got: Got) -> Outbound {
        let to = &self.to;
        match got {
            Got::Fail { cause, group } => {
                log.rec.decision = Decision::Servfail;
                if log.keeps() {
                    log.rec.upstream = Some(UpstreamInfo {
                        group: group.to_string(),
                        upstream: None,
                        ms: 0,
                        cached: false,
                        stale: false,
                        cause: None,
                    });
                }
                let c = cause.as_str();
                let out = self.buf.write(to, 640, |b| {
                    reply::write_rcode(b, to, rcode::SERVFAIL, &[EdeOption::no_upstream(c)])
                });
                self.finish_reply(log, out, None, false)
            }
            Got::Answer {
                entry,
                age,
                stale,
                cached,
                ms,
                group,
            } => {
                let clamp = self.profile.cfg.ttl;
                let stale_ttl = self.edge.dns.resolver.cache.settings().stale_ttl_s;
                let params = ServeParams {
                    age_s: age,
                    clamp,
                    stale: stale.map(|cause| StaleServe {
                        ttl: stale_ttl,
                        cause,
                    }),
                };
                let facts = entry.value.facts();
                let est = 12 + to.question.len() + entry.value.blob(to.do_bit()).len() + 11 + 160 + 468;
                let out = self
                    .buf
                    .write(to, est, |b| picket_wire::serve_hit(b, to, &entry.value, &params));
                let min_ttl = match stale {
                    Some(_) => Some(stale_ttl),
                    None => facts.min_ttl.map(|t| clamp.clamp(t.saturating_sub(age))),
                };
                log.rec.decision = Decision::Allow;
                if log.keeps() {
                    log.answer(&entry, age);
                    log.preview(facts, None, None);
                    log.rec.upstream = Some(UpstreamInfo {
                        group: group.to_string(),
                        upstream: Some(entry.upstream.to_string()),
                        ms,
                        cached,
                        stale: stale.is_some(),
                        cause: stale.map(str::to_owned),
                    });
                }
                if self.wants_firewall() {
                    let addrs = served_addrs(
                        out.as_ref().map(|(v, _)| v.as_slice()),
                        facts.addrs.iter().map(|a| a.ip),
                        min_ttl.unwrap_or(0),
                    );
                    if self.firewall(log, &addrs).await {
                        return self.fw_servfail(log);
                    }
                }
                self.finish_reply(log, out, min_ttl, false)
            }
        }
    }

    /// True when answers' addresses go to the firewall: the profile adds entries and a firewall
    /// client is installed. Callers check it before working out the addresses.
    fn wants_firewall(&self) -> bool {
        self.profile.cfg.firewall.add_entries && self.edge.dns.hooks.firewall.load().enabled()
    }

    /// The firewall ensure point (edge.md §9, edge-firewall.md §3): each address with the
    /// `client_ttl` its own record carries in the reply ([`served_addrs`]). True when the
    /// profile's `on_full: servfail` asks for SERVFAIL.
    async fn firewall(&self, log: &mut QLog<'_>, addrs: &[FwAddr]) -> bool {
        if addrs.is_empty() || !self.profile.cfg.firewall.add_entries {
            return false;
        }
        let fw = self.edge.dns.hooks.firewall.load();
        if !fw.enabled() {
            return false;
        }
        let req = FwRequest {
            client: self.device.ip,
            device: self.dkey,
            profile: &self.profile.id,
            firewall: &self.profile.cfg.firewall,
            addrs,
        };
        let out = fw.ensure(&req).await;
        if out.late {
            self.edge.metrics.fw_ack_late.fetch_add(1, Relaxed);
        }
        if out.added > 0 {
            log.rec.fw = Some(picket_api::logs::FwInfo { added: out.added });
        }
        out.servfail
    }

    /// The SERVFAIL a full firewall set asks for (`on_full: servfail`).
    fn fw_servfail(&self, log: &mut QLog<'_>) -> Outbound {
        let to = &self.to;
        let out = self
            .buf
            .write(to, 512, |b| reply::write_rcode(b, to, rcode::SERVFAIL, &[]));
        log.rec.decision = Decision::Servfail;
        self.finish_reply(log, out, None, false)
    }

    /// A block by a bundle rule (edge.md §4 "Blocked answers").
    fn bundle_block(
        &self,
        log: &mut QLog<'_>,
        h: &BundleHit,
        step: u8,
        stage: Stage,
        value: Option<String>,
        checked: Option<(&Entry, u32, Option<IpAddr>, Option<&WireName>)>,
    ) -> Outbound {
        let qwire = self.q.qname().wire();
        let bid = filter::bundle_block_id(h, qwire, value.as_deref().unwrap_or("").as_bytes());
        let ede = EdeOption::blocked_by_bundle(&h.bundle, h.short_head(), bid.as_str());
        self.edge.dns.hooks.recent_blocks.load().record_block(
            self.dkey,
            &BlockNote {
                block_id: bid.as_str(),
                name: self.q.qname().as_name(),
                stage,
                target: value.as_deref(),
                source: super::BlockSource::Bundle {
                    bundle: &h.bundle,
                    head: &h.reason.head,
                },
                response: &self.profile.cfg.block_response,
                profile: &self.profile.id,
            },
        );
        if h.reason.cold {
            self.edge.metrics.cold.get(&h.bundle).blocks.fetch_add(1, Relaxed);
        }
        log.rec.decision = Decision::Block;
        if log.keeps() {
            log.rec.reason = Some(filter::log_reason(h, step, stage, Some(&bid), value));
            if let Some((e, age, ip, t)) = checked {
                log.answer(e, age);
                log.preview(e.value.facts(), ip, t);
            }
        }
        self.block_reply(log, ede)
    }

    fn block_reply(&self, log: &mut QLog<'_>, ede: EdeOption<'_>) -> Outbound {
        let to = &self.to;
        let br = &self.profile.cfg.block_response;
        let out = self.buf.write(to, 768, |b| reply::write_block(b, to, br, ede));
        log.rec.decision = Decision::Block;
        if reply::block_has_records(br, self.q.qtype) && log.rec.answers.is_empty() && log.keeps() {
            let ip = match (br.kind, self.q.qtype) {
                (BlockResponseType::CustomIp, rtype::A) => br.ipv4.map(IpAddr::V4),
                (BlockResponseType::CustomIp, _) => br.ipv6.map(IpAddr::V6),
                (_, rtype::A) => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                _ => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            };
            log.rec.answers = ip.map(picket_wire::log::ip_text).into_iter().collect();
        }
        let ttl = match br.kind {
            BlockResponseType::Refused => None,
            _ => Some(br.ttl),
        };
        self.finish_reply(log, out, ttl, false)
    }

    /// A `$dnsrewrite` answer (edge.md §4 "Rewrites"; rules.md §4): its own values, never
    /// `block_response`; no EDE; not response-checked. Its records carry `block_response.ttl`
    /// clamped to the profile's `ttl`: the `client_ttl` the firewall gets too (edge-firewall.md
    /// §3, "rewritten in place in the answer").
    async fn rewrite(&self, log: &mut QLog<'_>, h: &BundleHit, ans: RewriteAnswer) -> Outbound {
        let to = &self.to;
        let ttl = self.ttl(self.profile.cfg.block_response.ttl);
        log.rec.decision = Decision::Rewrite;
        if log.keeps() {
            log.rec.reason = Some(filter::log_reason(h, 3, Stage::Query, None, None));
        }
        match ans {
            RewriteAnswer::Rcode(rc) => {
                let out = self.buf.write(to, 512, |b| reply::write_rcode(b, to, rc, &[]));
                self.finish_reply(log, out, None, false)
            }
            RewriteAnswer::Records(values) => {
                let owned = build_records(&values, self.q.qtype);
                let specs: Vec<RecordSpec<'_>> = owned.iter().filter_map(|r| r.spec(ttl)).collect();
                let est = 512 + owned.iter().map(OwnedRecord::size).sum::<usize>();
                let out = self.buf.write(to, est, |b| {
                    reply::write_records(b, to, rcode::NOERROR, &specs, &[], &[])
                });
                let ips: Vec<IpAddr> = owned.iter().flat_map(OwnedRecord::addrs).collect();
                if log.keeps() {
                    log.rec.answers = ips
                        .iter()
                        .take(picket_api::logs::MAX_PREVIEW)
                        .map(|ip| picket_wire::log::ip_text(*ip))
                        .collect();
                }
                let made = !specs.is_empty();
                if self.wants_firewall() {
                    let addrs =
                        served_addrs(out.as_ref().map(|(v, _)| v.as_slice()), ips.iter().copied(), ttl);
                    if self.firewall(log, &addrs).await {
                        return self.fw_servfail(log);
                    }
                }
                self.finish_reply(log, out, Some(ttl), made)
            }
            RewriteAnswer::Cname(target) => {
                let Ok(tname) = WireName::from_text(&target) else {
                    let out = self
                        .buf
                        .write(to, 512, |b| reply::write_rcode(b, to, rcode::SERVFAIL, &[]));
                    log.rec.decision = Decision::Servfail;
                    return self.finish_reply(log, out, None, false);
                };
                let group = Arc::clone(&self.profile.group);
                match self.fetch_name(&group, tname.as_name(), false).await {
                    Got::Fail { cause, group } => {
                        log.rec.decision = Decision::Servfail;
                        if log.keeps() {
                            log.rec.upstream = Some(UpstreamInfo {
                                group: group.to_string(),
                                ..Default::default()
                            });
                        }
                        let c = cause.as_str();
                        let out = self.buf.write(to, 640, |b| {
                            reply::write_rcode(b, to, rcode::SERVFAIL, &[EdeOption::no_upstream(c)])
                        });
                        self.finish_reply(log, out, None, false)
                    }
                    Got::Answer {
                        entry,
                        age,
                        stale,
                        cached,
                        ms,
                        group,
                    } => {
                        let stale_ttl = self.edge.dns.resolver.cache.settings().stale_ttl_s;
                        let clamp = self.profile.cfg.ttl;
                        let params = ServeParams {
                            age_s: age,
                            clamp,
                            stale: stale.map(|cause| StaleServe {
                                ttl: stale_ttl,
                                cause,
                            }),
                        };
                        // A stale target answer: its records at `stale_ttl` and EDE 3 with the
                        // cause (edge.md §4 EDE table), as a hit on it would be served.
                        let est = 12 + to.question.len() + entry.value.wire().len() + 300 + 468;
                        let out = self.buf.write(to, est, |b| {
                            picket_wire::cache::write_cname_rewrite(
                                b,
                                to,
                                ttl,
                                tname.as_name(),
                                &entry.value,
                                &params,
                            )
                        });
                        if log.keeps() {
                            log.answer(&entry, age);
                            log.preview(entry.value.facts(), None, None);
                            let mut chain = vec![tname.log_text()];
                            chain.append(&mut log.rec.cname);
                            log.rec.cname = chain;
                            log.rec.upstream = Some(UpstreamInfo {
                                group: group.to_string(),
                                upstream: Some(entry.upstream.to_string()),
                                ms,
                                cached,
                                stale: stale.is_some(),
                                cause: stale.map(str::to_owned),
                            });
                        }
                        // The target's records: remaining TTLs clamped, or `stale_ttl`.
                        let facts = entry.value.facts();
                        let target_ttl = match stale {
                            Some(_) => Some(stale_ttl),
                            None => facts.min_ttl.map(|t| clamp.clamp(t.saturating_sub(age))),
                        };
                        // The target's addresses go to the firewall like any rewrite's (edge.md
                        // §9), each with the TTL the client got for it.
                        if self.wants_firewall() {
                            let addrs = served_addrs(
                                out.as_ref().map(|(v, _)| v.as_slice()),
                                facts.addrs.iter().map(|a| a.ip),
                                target_ttl.unwrap_or(0),
                            );
                            if self.firewall(log, &addrs).await {
                                return self.fw_servfail(log);
                            }
                        }
                        let min = Some(target_ttl.map_or(ttl, |t| t.min(ttl)));
                        self.finish_reply(log, out, min, true)
                    }
                }
            }
        }
    }

    /// A host-IP mapping (edge.md §4 "Host-IP mappings").
    async fn host_mapping(&self, log: &mut QLog<'_>, h: &BundleHit, ips: &[IpAddr]) -> Outbound {
        let to = &self.to;
        let br = &self.profile.cfg.block_response;
        if br.kind != BlockResponseType::NullIp {
            return self.bundle_block(log, h, 3, Stage::Query, None, None);
        }
        let v4: Vec<Ipv4Addr> = ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(a) => Some(*a),
                _ => None,
            })
            .collect();
        let v6: Vec<Ipv6Addr> = ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(a) => Some(*a),
                _ => None,
            })
            .collect();
        let qwire = self.q.qname().wire();
        let bid = filter::bundle_block_id(h, qwire, b"");
        let ede = EdeOption::blocked_by_bundle(&h.bundle, h.short_head(), bid.as_str());
        // A mapping that answers with addresses is a rewrite and carries the clamped TTL the
        // firewall gets (edge-firewall.md §3); the other answers are blocks, at
        // `block_response.ttl`.
        let rewrites = match self.q.qtype {
            rtype::A => !v4.is_empty(),
            rtype::AAAA => !v6.is_empty(),
            _ => false,
        };
        let ttl = if rewrites { self.ttl(br.ttl) } else { br.ttl };
        let mut kind = MappingAnswer::Block;
        let out = self.buf.write(to, 512 + 20 * ips.len(), |b| {
            reply::write_host_mapping(b, to, &v4, &v6, ttl, ede).map(|(r, k)| {
                kind = k;
                r
            })
        });
        match kind {
            MappingAnswer::Rewrite => {
                log.rec.decision = Decision::Rewrite;
                let shown: Vec<IpAddr> = match self.q.qtype {
                    rtype::A => v4.iter().map(|a| IpAddr::V4(*a)).collect(),
                    _ => v6.iter().map(|a| IpAddr::V6(*a)).collect(),
                };
                if log.keeps() {
                    log.rec.reason = Some(filter::log_reason(h, 3, Stage::Query, None, None));
                    log.rec.answers = shown
                        .iter()
                        .take(picket_api::logs::MAX_PREVIEW)
                        .map(|ip| picket_wire::log::ip_text(*ip))
                        .collect();
                }
                // Mapped addresses go to the firewall like a rewrite's (edge.md §4).
                if self.wants_firewall() {
                    let addrs = served_addrs(
                        out.as_ref().map(|(v, _)| v.as_slice()),
                        shown.iter().copied(),
                        ttl,
                    );
                    if self.firewall(log, &addrs).await {
                        return self.fw_servfail(log);
                    }
                }
                self.finish_reply(log, out, Some(ttl), true)
            }
            MappingAnswer::Block => {
                self.edge.dns.hooks.recent_blocks.load().record_block(
                    self.dkey,
                    &BlockNote {
                        block_id: bid.as_str(),
                        name: self.q.qname().as_name(),
                        stage: Stage::Query,
                        target: None,
                        source: super::BlockSource::Bundle {
                            bundle: &h.bundle,
                            head: &h.reason.head,
                        },
                        response: br,
                        profile: &self.profile.id,
                    },
                );
                log.rec.decision = Decision::Block;
                if log.keeps() {
                    log.rec.reason = Some(filter::log_reason(h, 3, Stage::Query, Some(&bid), None));
                }
                self.finish_reply(log, out, Some(ttl), false)
            }
        }
    }

    /// Runs the profile's sync lookups in scope (edge.md §10). `call`: false for a cache-only
    /// pass (ANY).
    async fn run_lookups(&self, who: &Who<'_>, call: bool) -> Vec<LookupRes> {
        let q = self.q;
        let name_text = q.qname().as_name().log_text();
        let qtype_text = picket_wire::types::TypeText(q.qtype).to_string();
        let mut futs = vec![];
        for att in &self.profile.sync {
            let Some(client) = self.edge.dns.lookups.get(&att.provider) else {
                continue;
            };
            let settings = client.settings();
            let bundles = &self.active.bundles;
            let excluded = settings
                .scope
                .exclude_bundles
                .iter()
                .chain(att.exclude.iter())
                .any(|b| filter::in_bundle(bundles, b, q.qname(), who, q.qtype));
            if excluded {
                continue;
            }
            let included = [&settings.scope.include_bundles, &att.include]
                .iter()
                .all(|list| {
                    list.is_empty()
                        || list
                            .iter()
                            .any(|b| filter::in_bundle(bundles, b, q.qname(), who, q.qtype))
                });
            if !included {
                continue;
            }
            let calls = call
                && q.qtype != rtype::ANY
                && settings
                    .scope
                    .qtypes
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(&qtype_text));
            let deadline = client.sync_deadline(self.tstart, self.profile.cfg.sync_lookup_budget_ms);
            let provider = Arc::clone(&att.provider);
            let fail_mode = settings.fail_mode;
            let tag: Arc<str> = Arc::clone(&self.profile.id);
            let name = name_text.clone();
            futs.push(async move {
                let outcome = client
                    .lookup_sync(picket_lookup::SyncRequest {
                        name: &name,
                        deadline,
                        call: calls,
                        tag: Some(tag),
                    })
                    .await;
                LookupRes {
                    provider,
                    fail_mode,
                    outcome,
                }
            });
        }
        futures_util::future::join_all(futs).await
    }

    fn log_lookups(&self, log: &mut QLog<'_>, looks: &[LookupRes]) {
        log.rec.lookups = looks
            .iter()
            .filter_map(|l| l.outcome.log_item(&l.provider))
            .collect::<Vec<LookupItem>>();
    }

    /// A block by a sync lookup, if one blocks (the first blocking provider names it).
    fn lookup_block(&self, log: &mut QLog<'_>, looks: &[LookupRes]) -> Option<Outbound> {
        let first = looks.iter().find(|l| l.outcome.blocks(l.fail_mode))?;
        self.log_lookups(log, looks);
        let verdict = match first.outcome.log_verdict() {
            Some(v) => lookup_verdict_text(v),
            None => "block",
        };
        let bid = filter::lookup_block_id(&first.provider, self.q.qname().wire());
        let ede = EdeOption::blocked_by_lookup(&first.provider, verdict, bid.as_str());
        self.edge.dns.hooks.recent_blocks.load().record_block(
            self.dkey,
            &BlockNote {
                block_id: bid.as_str(),
                name: self.q.qname().as_name(),
                stage: Stage::Query,
                target: None,
                source: super::BlockSource::Lookup {
                    provider: &first.provider,
                    verdict,
                },
                response: &self.profile.cfg.block_response,
                profile: &self.profile.id,
            },
        );
        log.rec.decision = Decision::Block;
        if log.keeps() {
            log.rec.reason = Some(LogReason {
                step: 4,
                kind: MatchKind::Lookup,
                stage: Stage::Query,
                block_id: Some(bid.as_str().to_owned()),
                provider: Some(first.provider.to_string()),
                ..Default::default()
            });
        }
        Some(self.block_reply(log, ede))
    }

    /// Response checks (rules.md §5 step 5, §6): CNAME targets, A/AAAA, HTTPS/SVCB hints and
    /// targets re-run steps 1–3. A BLOCK (or a host-IP mapping, an ordinary block there) replaces
    /// the whole response; a REWRITE there is ignored.
    async fn response_checks(
        &self,
        log: &mut QLog<'_>,
        who: &Who<'_>,
        entry: &Arc<Entry>,
        age: u32,
    ) -> Option<Outbound> {
        let facts = entry.value.facts();
        let allows = self.edge.dns.temp_allows(self.edge);
        let bundles = &self.active.bundles;
        let profile = self.profile;
        for name in &facts.chain {
            let Ok(qn) = QName::from_labels(name.as_name().labels()) else {
                continue;
            };
            let lad = filter::ladder(
                bundles,
                profile,
                who,
                self.dkey,
                &*allows,
                Target::Name(&qn),
                rtype::CNAME,
            )
            .await;
            self.note_cold(log, &lad);
            if let Verdict::Block(h) | Verdict::HostMapping(h, _) = lad.verdict {
                return Some(self.bundle_block(
                    log,
                    &h,
                    5,
                    Stage::Cname,
                    Some(name.log_text()),
                    Some((entry, age, None, None)),
                ));
            }
        }
        for a in &facts.addrs {
            let ip = a.match_ip();
            let (stage, rt) = match a.source {
                picket_wire::AddrSource::A => (Stage::AnswerIp, rtype::A),
                picket_wire::AddrSource::Aaaa => (Stage::AnswerIp, rtype::AAAA),
                _ => (Stage::Svcb, self.q.qtype),
            };
            let lad = filter::ladder(bundles, profile, who, self.dkey, &*allows, Target::Addr(ip), rt).await;
            self.note_cold(log, &lad);
            if let Verdict::Block(h) | Verdict::HostMapping(h, _) = lad.verdict {
                return Some(self.bundle_block(
                    log,
                    &h,
                    5,
                    stage,
                    Some(picket_wire::log::ip_text(a.ip)),
                    Some((entry, age, Some(a.ip), None)),
                ));
            }
        }
        for t in &facts.targets {
            let Ok(qn) = QName::from_labels(t.as_name().labels()) else {
                continue;
            };
            let lad = filter::ladder(
                bundles,
                profile,
                who,
                self.dkey,
                &*allows,
                Target::Name(&qn),
                self.q.qtype,
            )
            .await;
            self.note_cold(log, &lad);
            if let Verdict::Block(h) | Verdict::HostMapping(h, _) = lad.verdict {
                return Some(self.bundle_block(
                    log,
                    &h,
                    5,
                    Stage::Svcb,
                    Some(t.log_text()),
                    Some((entry, age, None, Some(t))),
                ));
            }
        }
        None
    }
}

/// The firewall's view of a reply (edge-firewall.md §3): each of `want` (the answer's addresses)
/// with the TTL of the record carrying it in `reply`, the reply the client got (aged, clamped or
/// `stale_ttl` as served), the longest where several do. A reply with TC set gave the client no
/// records (it retries over TCP, and that answer goes to the firewall), and no reply gave it
/// nothing: neither has addresses. The reply is the edge's own, so every record reads; an
/// address the walk doesn't find (it can't happen) falls back to `fallback_ttl`.
fn served_addrs(
    reply: Option<&[u8]>,
    want: impl Iterator<Item = IpAddr>,
    fallback_ttl: u32,
) -> smallvec::SmallVec<[FwAddr; 8]> {
    use hickory_proto::op::Query as HQuery;
    use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamValue};
    use hickory_proto::rr::{RData, Record};
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

    let mut out: smallvec::SmallVec<[FwAddr; 8]> = smallvec::SmallVec::new();
    let Some(reply) = reply else { return out };
    let Some(&[_, _, flags, _, qd0, qd1, an0, an1]) = reply.get(..8) else {
        return out;
    };
    if flags & 0x02 != 0 {
        return out;
    }
    // Every address record of the answer section with its TTL, the longest per address.
    let mut seen: smallvec::SmallVec<[FwAddr; 8]> = smallvec::SmallVec::new();
    let mut note = |ip: IpAddr, ttl: u32| match seen.iter_mut().find(|a| a.ip == ip) {
        Some(a) => a.client_ttl = a.client_ttl.max(ttl),
        None => seen.push(FwAddr { ip, client_ttl: ttl }),
    };
    let hints = |s: &SVCB, ttl: u32, note: &mut dyn FnMut(IpAddr, u32)| {
        for (_, v) in &s.svc_params {
            match v {
                SvcParamValue::Ipv4Hint(h) => h.0.iter().for_each(|a| note(IpAddr::V4(a.0), ttl)),
                SvcParamValue::Ipv6Hint(h) => h.0.iter().for_each(|a| note(IpAddr::V6(a.0), ttl)),
                _ => {}
            }
        }
    };
    let mut dec = BinDecoder::new(reply);
    let walked = dec.read_slice(12).is_ok()
        && (0..u16::from_be_bytes([qd0, qd1])).all(|_| HQuery::read(&mut dec).is_ok())
        && (0..u16::from_be_bytes([an0, an1])).all(|_| match Record::read(&mut dec) {
            Ok(r) => {
                match &r.data {
                    RData::A(a) => note(IpAddr::V4(a.0), r.ttl),
                    RData::AAAA(a) => note(IpAddr::V6(a.0), r.ttl),
                    RData::HTTPS(h) => hints(&h.0, r.ttl, &mut note),
                    RData::SVCB(sv) => hints(sv, r.ttl, &mut note),
                    _ => {}
                }
                true
            }
            Err(_) => false,
        });
    if !walked {
        tracing::debug!("firewall: the reply's records didn't read; fallback TTL used");
    }
    for ip in want {
        if out.iter().any(|a| a.ip == ip) {
            continue;
        }
        let client_ttl = seen
            .iter()
            .find(|a| a.ip == ip)
            .map_or(fallback_ttl, |a| a.client_ttl);
        out.push(FwAddr { ip, client_ttl });
    }
    out
}

/// `home.arpa` and `local` names (edge.md §4).
pub fn is_local_zone(n: NameRef<'_>) -> bool {
    const HOME_ARPA: &[u8] = b"\x04home\x04arpa\x00";
    const LOCAL: &[u8] = b"\x05local\x00";
    let w = n.wire();
    let at_or_below = |zone: &[u8]| {
        w.len() >= zone.len() && {
            let mut cur = n;
            loop {
                if cur.wire() == zone {
                    break true;
                }
                match cur.parent() {
                    Some(p) if p.wire().len() >= zone.len() => cur = p,
                    _ => break false,
                }
            }
        }
    };
    at_or_below(HOME_ARPA) || at_or_below(LOCAL)
}

fn lookup_verdict_text(v: picket_api::logs::LookupVerdict) -> &'static str {
    use picket_api::logs::LookupVerdict::*;
    match v {
        Block => "block",
        Clean => "clean",
        Unknown => "unknown",
        Timeout => "timeout",
        Error => "error",
        Rejected => "rejected",
    }
}

/// A rewrite value as record data the reply writer takes.
enum OwnedRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(WireName),
    Mx(u16, WireName),
    Srv(u16, u16, u16, WireName),
    Txt(Vec<u8>),
    Raw(u16, Vec<u8>),
}

impl OwnedRecord {
    fn spec(&self, ttl: u32) -> Option<RecordSpec<'_>> {
        let data = match self {
            OwnedRecord::A(a) => RecordData::A(*a),
            OwnedRecord::Aaaa(a) => RecordData::Aaaa(*a),
            OwnedRecord::Ptr(n) => RecordData::Ptr(n.as_name()),
            OwnedRecord::Mx(p, n) => RecordData::Mx {
                preference: *p,
                exchange: n.as_name(),
            },
            OwnedRecord::Srv(p, w, port, n) => RecordData::Srv {
                priority: *p,
                weight: *w,
                port: *port,
                target: n.as_name(),
            },
            OwnedRecord::Txt(t) => RecordData::TxtSplit(t),
            OwnedRecord::Raw(t, d) => RecordData::Raw { rtype: *t, rdata: d },
        };
        Some(RecordSpec {
            owner: None,
            ttl,
            data,
        })
    }

    fn size(&self) -> usize {
        16 + match self {
            OwnedRecord::A(_) => 4,
            OwnedRecord::Aaaa(_) => 16,
            OwnedRecord::Ptr(n) | OwnedRecord::Mx(_, n) | OwnedRecord::Srv(_, _, _, n) => n.wire().len() + 6,
            OwnedRecord::Txt(t) => t.len() + t.len() / 255 + 1,
            OwnedRecord::Raw(_, d) => d.len(),
        }
    }

    /// Addresses the answer carries (for the firewall and the preview).
    fn addrs(&self) -> Vec<IpAddr> {
        match self {
            OwnedRecord::A(a) => vec![IpAddr::V4(*a)],
            OwnedRecord::Aaaa(a) => vec![IpAddr::V6(*a)],
            OwnedRecord::Raw(t, d) if *t == rtype::HTTPS || *t == rtype::SVCB => {
                picket_wire::svcb::rdata_facts(*t, d)
                    .map(|f| f.hints.iter().map(|h| h.ip).collect())
                    .unwrap_or_default()
            }
            _ => vec![],
        }
    }
}

/// The records of a `$dnsrewrite` answer for `qtype` (AdGuard Home answers only the values of
/// the question's type; none → NOERROR with no records).
fn build_records(values: &[(u16, RewriteValue)], qtype: u16) -> Vec<OwnedRecord> {
    let mut out = vec![];
    for (t, v) in values {
        if *t != qtype {
            continue;
        }
        let r = match v {
            RewriteValue::Ip(IpAddr::V4(a)) if *t == rtype::A => Some(OwnedRecord::A(*a)),
            RewriteValue::Ip(IpAddr::V6(a)) if *t == rtype::AAAA => Some(OwnedRecord::Aaaa(*a)),
            RewriteValue::Ip(IpAddr::V4(a)) if *t == rtype::AAAA => {
                Some(OwnedRecord::Aaaa(a.to_ipv6_mapped()))
            }
            RewriteValue::Ip(_) => None,
            RewriteValue::Text(s) => Some(OwnedRecord::Txt(s.as_bytes().to_vec())),
            RewriteValue::Ptr(n) => WireName::from_text(n).ok().map(OwnedRecord::Ptr),
            RewriteValue::Mx { preference, exchange } => WireName::from_text(exchange)
                .ok()
                .map(|n| OwnedRecord::Mx(*preference, n)),
            RewriteValue::Srv {
                priority,
                weight,
                port,
                target,
            } => WireName::from_text(target)
                .ok()
                .map(|n| OwnedRecord::Srv(*priority, *weight, *port, n)),
            RewriteValue::Svcb {
                priority,
                target,
                params,
            } => svcb_rdata(*priority, target, params).map(|d| OwnedRecord::Raw(*t, d)),
        };
        if let Some(r) = r {
            out.push(r);
        }
    }
    out
}

/// Encodes an HTTPS/SVCB rewrite value (RFC 9460) with hickory: priority, target and the
/// parameters AdGuard Home writes (`alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ech`,
/// `ipv6hint`, `mandatory`). A value with a parameter it can't encode is left out.
pub fn svcb_rdata(priority: u16, target: &str, params: &[(String, String)]) -> Option<Vec<u8>> {
    use hickory_proto::rr::rdata::svcb::{
        Alpn, EchConfigList, IpHint, Mandatory, SVCB, SvcParamKey, SvcParamValue,
    };
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
    let target = if target == "." || target.is_empty() {
        hickory_proto::rr::Name::root()
    } else {
        hickory_proto::rr::Name::from_ascii(target).ok()?
    };
    let mut out_params = vec![];
    for (k, v) in params.iter().take(32) {
        let (key, value) = match k.as_str() {
            "alpn" => (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(v.split(',').map(str::to_owned).collect())),
            ),
            "no-default-alpn" => (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn),
            "port" => (SvcParamKey::Port, SvcParamValue::Port(v.parse().ok()?)),
            "ipv4hint" => {
                let ips: Option<Vec<A>> = v
                    .split(',')
                    .map(|s| s.trim().parse::<Ipv4Addr>().ok().map(A))
                    .collect();
                (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(ips?)))
            }
            "ipv6hint" => {
                let ips: Option<Vec<AAAA>> = v
                    .split(',')
                    .map(|s| s.trim().parse::<Ipv6Addr>().ok().map(AAAA))
                    .collect();
                (SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(ips?)))
            }
            "ech" => {
                let bytes = base64::engine::general_purpose::STANDARD.decode(v).ok()?;
                (
                    SvcParamKey::EchConfigList,
                    SvcParamValue::EchConfigList(EchConfigList(bytes)),
                )
            }
            "mandatory" => {
                let keys: Option<Vec<SvcParamKey>> = v
                    .split(',')
                    .map(|s| match s {
                        "alpn" => Some(SvcParamKey::Alpn),
                        "no-default-alpn" => Some(SvcParamKey::NoDefaultAlpn),
                        "port" => Some(SvcParamKey::Port),
                        "ipv4hint" => Some(SvcParamKey::Ipv4Hint),
                        "ech" => Some(SvcParamKey::EchConfigList),
                        "ipv6hint" => Some(SvcParamKey::Ipv6Hint),
                        _ => None,
                    })
                    .collect();
                (SvcParamKey::Mandatory, SvcParamValue::Mandatory(Mandatory(keys?)))
            }
            _ => return None,
        };
        out_params.push((key, value));
    }
    let svcb = SVCB::new(priority, target, out_params);
    let mut buf = Vec::with_capacity(64);
    {
        let mut enc = BinEncoder::new(&mut buf);
        svcb.emit(&mut enc).ok()?;
    }
    picket_wire::svcb::rdata_facts(rtype::HTTPS, &buf)?;
    Some(buf)
}

/// The watchdog's internal test query (edge.md §16): once listeners are bound, `WATCHDOG=1` is
/// sent only after a query for a name the edge answers itself passed through the pipeline.
pub async fn watchdog_loop(edge: Arc<Edge>) -> anyhow::Result<()> {
    let every = edge.dns.tuning.watchdog_every;
    let mut t = tokio::time::interval(every);
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        t.tick().await;
        if !edge.watchdog.in_pipeline_mode() {
            continue;
        }
        if self_test(&edge).await {
            edge.watchdog.pipeline_passed();
        }
    }
}

/// The longest one test query may take.
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs one internal test query (edge.md §16); true when it was answered, at most
/// [`SELF_TEST_TIMEOUT`] later. It passes only while every listener's receive and accept loops
/// stamp their liveness marks, and goes through the first `dns` listener's UDP socket as a
/// loopback datagram (then the limiter, the profile choice and the internal answer), so a
/// stalled loop, socket or pipeline stops the watchdog. Without a `dns` listener (DoT or DoH
/// only), or when its address can't be used from here, the query enters the pipeline in
/// process. A reading of edge.md §16, flagged for the owner.
pub async fn self_test(edge: &Edge) -> bool {
    let mgr = &edge.dns.listeners;
    if let Some(id) = mgr.stale_listener(edge.dns.tuning.listener_stale) {
        tracing::debug!("watchdog test: listener {id}'s loop has stopped");
        return false;
    }
    let name = edge
        .active()
        .dns
        .as_ref()
        .and_then(|rt| rt.managed.first().map(|m| m.name.clone()))
        .or_else(|| WireName::from_text("picket-watchdog.home.arpa").ok());
    let Some(name) = name else { return false };
    let id = picket_wire::upstream::random_query_id();
    let mut buf = [0u8; 512];
    let Ok(n) = picket_wire::upstream::write_query(
        &mut buf,
        name.as_name(),
        rtype::A,
        class::IN,
        &picket_wire::upstream::QueryParams {
            id,
            cd: false,
            do_bit: false,
            pad: false,
        },
    ) else {
        return false;
    };
    let run = async {
        let udp = match mgr.self_test_target() {
            Some(to) => udp_self_test(edge, to, &buf[..n], id).await,
            None => None,
        };
        match udp {
            Some(passed) => passed,
            None => in_process_self_test(edge, &buf[..n]).await,
        }
    };
    tokio::time::timeout(SELF_TEST_TIMEOUT, run)
        .await
        .unwrap_or(false)
}

/// The test query as a loopback datagram to the listener at `to`, from a fresh socket (a new
/// source port each time, so `SO_REUSEPORT` spreads the tests over the listener's sockets).
/// `None` when the listener's address can't be used from here ([`address_unusable`]: a scoped
/// link-local address, say): the caller tests in process instead, as a failure would restart the
/// edge for good. Any other bind or connect error fails the test: running out of descriptors is
/// the stuck state a restart cures (edge.md §16).
async fn udp_self_test(edge: &Edge, to: SocketAddr, query: &[u8], id: u16) -> Option<bool> {
    let mgr = &edge.dns.listeners;
    let _one = mgr.self_test_lock.lock().await;
    let sock = match tokio::net::UdpSocket::bind(SocketAddr::new(to.ip(), 0)).await {
        Ok(s) => s,
        Err(e) if address_unusable(&e) => {
            tracing::debug!("watchdog test: binding next to {to}: {e}; testing in process");
            return None;
        }
        Err(e) => {
            tracing::warn!("watchdog test: binding next to {to}: {e}");
            return Some(false);
        }
    };
    // Connected: replies from anywhere but the listener are dropped by the kernel.
    match sock.connect(to).await {
        Ok(()) => {}
        Err(e) if address_unusable(&e) => {
            tracing::debug!("watchdog test: connecting to {to}: {e}; testing in process");
            return None;
        }
        Err(e) => {
            tracing::warn!("watchdog test: connecting to {to}: {e}");
            return Some(false);
        }
    }
    let src = sock.local_addr().ok()?;
    let _mark = mgr.mark_self_test(src);
    if sock.send(query).await.is_err() {
        return Some(false);
    }
    let mut reply = [0u8; 1232];
    loop {
        let Ok(n) = sock.recv(&mut reply).await else {
            return Some(false);
        };
        let r = &reply[..n];
        if n >= 12 && u16::from_be_bytes([r[0], r[1]]) == id {
            return Some(reply_rcode(r) != rcode::SERVFAIL);
        }
    }
}

/// Whether a bind or connect error says the listener's address can't be used from here
/// (EADDRNOTAVAIL, EINVAL, EAFNOSUPPORT, ENETUNREACH, EHOSTUNREACH: a scoped link-local address,
/// a family the host lacks), the only errors after which the test goes in process.
fn address_unusable(e: &std::io::Error) -> bool {
    use rustix::io::Errno;
    Errno::from_io_error(e).is_some_and(|n| {
        [
            Errno::ADDRNOTAVAIL,
            Errno::INVAL,
            Errno::AFNOSUPPORT,
            Errno::NETUNREACH,
            Errno::HOSTUNREACH,
        ]
        .contains(&n)
    })
}

/// The test query handed to the pipeline in process (no `dns` listener to send it to).
async fn in_process_self_test(edge: &Edge, query: &[u8]) -> bool {
    let out = serve(
        edge,
        Inbound {
            msg: query,
            client: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            listener: "internal",
            udp_payload: picket_wire::EDGE_UDP_PAYLOAD,
            proto: Proto::Udp,
            named_profile: None,
            extension: false,
            internal: true,
            admitted: Admitted::Here,
        },
    )
    .await;
    out.reply.is_some_and(|r| reply_rcode(&r) != rcode::SERVFAIL)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// edge.md §16: only an address the test can't use from here sends it in process; running
    /// out of descriptors or memory fails it (a restart cures that).
    #[test]
    fn only_address_errors_send_the_watchdog_test_in_process() {
        use rustix::io::Errno;
        let e = |n: Errno| std::io::Error::from_raw_os_error(n.raw_os_error());
        assert!(address_unusable(&e(Errno::ADDRNOTAVAIL)));
        assert!(address_unusable(&e(Errno::INVAL)));
        assert!(address_unusable(&e(Errno::AFNOSUPPORT)));
        for n in [
            Errno::MFILE,
            Errno::NFILE,
            Errno::NOBUFS,
            Errno::NOMEM,
            Errno::ACCESS,
        ] {
            assert!(!address_unusable(&e(n)), "{n:?}");
        }
        assert!(crate::dns::listeners::out_of_resources(&e(Errno::MFILE)));
        assert!(!crate::dns::listeners::out_of_resources(&e(Errno::CONNABORTED)));
    }

    #[test]
    fn local_zones() {
        let n = |s: &str| WireName::from_text(s).unwrap();
        assert!(is_local_zone(n("home.arpa").as_name()));
        assert!(is_local_zone(n("nas.home.arpa").as_name()));
        assert!(is_local_zone(n("printer.local").as_name()));
        assert!(!is_local_zone(n("arpa").as_name()));
        assert!(!is_local_zone(n("myhome.arpa").as_name()));
        assert!(!is_local_zone(n("local.example").as_name()));
    }

    #[test]
    fn meta_types_and_svcb_rewrites() {
        assert!(is_meta_qtype(rtype::AXFR));
        assert!(is_meta_qtype(rtype::OPT));
        assert!(!is_meta_qtype(rtype::ANY));
        assert!(!is_meta_qtype(rtype::HTTPS));
        let d = svcb_rdata(
            1,
            ".",
            &[
                ("alpn".into(), "h2,h3".into()),
                ("ipv4hint".into(), "192.0.2.1".into()),
            ],
        )
        .unwrap();
        let f = picket_wire::svcb::rdata_facts(rtype::HTTPS, &d).unwrap();
        assert_eq!(f.hints.len(), 1);
        assert!(svcb_rdata(1, ".", &[("bogus".into(), "1".into())]).is_none());
    }
}
