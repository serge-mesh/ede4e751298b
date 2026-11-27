//! The cross-check of unsigned answers (core.md §8 "Cross-check of unsigned answers").
//!
//! With `crosscheck.enabled` on (off by default: the resolver sees every name checked), core asks
//! a second resolver about answers that look like an upstream blocking a name:
//!
//! - **Negative check** (`crosscheck.negative`): a DNSSEC candidate whose upstream answered
//!   NXDOMAIN or SERVFAIL (any type), or NODATA to an A query, and whose outcome is Insecure
//!   ([`admit_negative_in`], from the DNSSEC results). The resolver disagrees only when it returns
//!   data: a usable RRset of the requested type at the question name or at the end of its CNAME
//!   chain ([`has_data`]).
//! - **Sinkhole check** (`crosscheck.sinkhole`): an allowed A or AAAA answer for a public name (a
//!   registrable domain, outside the `lookup-exclude` bundle) holding a sinkhole address,
//!   flagged locally after ingest ([`sinkhole_candidate`]). The resolver disagrees when it returns
//!   addresses, none of them sinkhole addresses.
//! - **Skipped:** names in the record's profile's forward zones, and records the profile blocked
//!   or rewrote. Each (qname, qtype) is checked once per `crosscheck.dedupe_window`
//!   (`crosscheck_seen`), whichever check flags it; a queued item gathers the edges, clients and
//!   upstream groups of later flagged records.
//! - **Resolver** (`crosscheck.resolver`): one server by IP over DoT or DoH, queried directly from
//!   core with the `dns` lookup module's client path (core's `DnsServerClient`, picket-wire's
//!   query writer and lookup-answer check), never through `resolver`, an edge or an upstream
//!   group. Its operator independence is checked on save (`config::validate`).
//! - **No answer, never a disagreement:** a filtering answer (EDE 15, 16 or 17), SERVFAIL or
//!   REFUSED, an invalid answer, and a timeout or transport error after 3 attempts (backoff 30 s →
//!   30 min).
//! - **Queue:** `crosscheck_queue`, light lane, `crosscheck.max_per_minute` resolver queries;
//!   items older than the retention window or over the cap are dropped and counted (by age only
//!   once the wall clock is synchronised, README §2 Clocks), and an item admitted before then
//!   is checked only once stamped ([`restamp_in`]). A turn takes about a minute of queries
//!   ([`turn_items`]) and stores each result as its check ends. Work that began before a config
//!   restore stores nothing after it (core.md §2), and a result needs its queue item.
//! - **Disagreement → `upstream_disagrees`**, one per registrable domain and upstream group,
//!   naming the check, the name and qtype, the upstream's rcode and addresses, the resolver's
//!   rcode, addresses and EDE, and the edges and clients; its evidence keeps the resolver's answer
//!   (source `crosscheck`, charged to the shared evidence budget) next to the copied records and
//!   their upstream answers.
//!
//! Metrics: `crosscheck{check, result}` (`agree`, `disagree`, `no_answer`, `dropped`).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_net::proto::op::Message;
use hickory_net::proto::rr::{RData, RecordType};
use picket_api::edge_config::UpstreamProtocol;
use picket_lookup::{DnsClientError, DnsServer, DnsServerClient};
use picket_wire::answer::SentQuery;
use picket_wire::name::QName;
use picket_wire::types::class;
use picket_wire::upstream::{QueryParams, random_query_id, write_query};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::candidate::{ConfigParts, sinkhole_ip};
use super::queue::{Context as DnssecContext, Item as DnssecItem, RecRef};
use super::validator::Limiter;
use crate::alerts::{Changes, RaiseSpec, Severity};
use crate::config::model::Model;
use crate::logs::record::Rec;
use crate::settings::{CrosscheckResolver, EncryptedProtocol};
use crate::state::SharedState;

/// The queue's cap (README §2 Bounded).
pub const QUEUE_CAP: i64 = 20_000;
/// Attempts of a query that timed out or failed in transport (core.md §8).
pub const MAX_ATTEMPTS: i64 = 3;
/// One query's timeout.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// The most items one turn takes.
const TURN_ITEMS: usize = 32;
/// A turn starts no new check after this long; the items left wait for the next turn.
const TURN_BUDGET: Duration = Duration::from_secs(60);
const BACKOFF_MIN: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);

/// The items one turn takes at `crosscheck.max_per_minute` (core.md §8: work beyond the rate
/// waits): about a minute of resolver queries (one per item), at least one and at most
/// [`TURN_ITEMS`]. With [`TURN_BUDGET`] and each result stored as its check ends, a turn stays
/// short at any rate: a restart or a restore loses only the check in flight, and the queue's
/// state follows each check.
pub fn turn_items(max_per_minute: u32) -> usize {
    usize::try_from(max_per_minute)
        .unwrap_or(usize::MAX)
        .clamp(1, TURN_ITEMS)
}

/// The backoff before attempt `attempts + 1`: 30 s doubling to 30 min, ±20 %.
pub fn backoff(attempts: i64) -> Duration {
    let exp = u32::try_from(attempts.saturating_sub(1).clamp(0, 16)).unwrap_or(16);
    BACKOFF_MIN
        .saturating_mul(2u32.saturating_pow(exp))
        .min(BACKOFF_MAX)
        .mul_f64(rand::random_range(0.8..=1.2))
}

/// Which check flagged a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Check {
    Negative,
    Sinkhole,
}

impl Check {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Negative => "negative",
            Self::Sinkhole => "sinkhole",
        }
    }
}

/// `crosscheck{check, result}`.
pub fn count(check: &str, result: &str) -> (String, crate::metrics::Labels, i64, f64) {
    (
        "crosscheck".into(),
        crate::metrics::labels("", &[("check", check), ("result", result)]),
        jiff::Timestamp::now().as_millisecond(),
        1.0,
    )
}

/// The cross-check's runtime state.
pub struct Runtime {
    pub limiter: Arc<Limiter>,
    client: Mutex<Option<Arc<dyn DnsServerClient>>>,
    wake: tokio::sync::Notify,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            limiter: Arc::new(Limiter::new(60)),
            client: Mutex::new(None),
            wake: tokio::sync::Notify::new(),
        }
    }
}

impl Runtime {
    /// Builds the resolver client (core's `DnsServerClient`) unless a test set one.
    pub fn init(&self, opts: &crate::modules::download::client::HttpOptions) {
        if let Ok(mut g) = self.client.lock()
            && g.is_none()
        {
            *g = Some(Arc::new(crate::lookups::clients::CoreDns::new(opts)));
        }
    }

    /// Replaces the resolver client (tests).
    pub fn set_client(&self, c: Arc<dyn DnsServerClient>) {
        if let Ok(mut g) = self.client.lock() {
            *g = Some(c);
        }
    }

    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Waits for [`Runtime::wake`].
    pub async fn notified(&self) {
        self.wake.notified().await
    }

    pub fn reset(&self) {}

    fn client(&self) -> Option<Arc<dyn DnsServerClient>> {
        self.client.lock().ok()?.clone()
    }
}

/// What a queued item gathers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    /// The upstream's rcode and addresses (from the first flagged record).
    #[serde(default)]
    pub rcode: String,
    #[serde(default)]
    pub addrs: Vec<String>,
    #[serde(default)]
    pub edges: Vec<String>,
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub records: Vec<RecRef>,
}

fn push(v: &mut Vec<String>, s: &str) {
    if !s.is_empty() && v.len() < super::queue::MAX_NAMED && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

impl Context {
    fn join(&mut self, r: &RecRef) {
        if self
            .records
            .iter()
            .any(|x| x.edge == r.edge && x.boot == r.boot && x.seq == r.seq)
        {
            return;
        }
        push(&mut self.edges, &r.edge);
        push(&mut self.clients, &r.client);
        if let Some(g) = &r.group {
            push(&mut self.groups, g);
        }
        if self.records.len() < super::queue::MAX_RECORDS {
            self.records.push(r.clone());
        }
    }

    fn parse(s: Option<&str>) -> Self {
        s.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default()
    }
}

/// Queue sizes per admitting edge.
#[derive(Default)]
pub struct Sizes {
    total: i64,
    per_edge: BTreeMap<String, i64>,
}

impl Sizes {
    pub fn load(tx: &Transaction<'_>) -> rusqlite::Result<Self> {
        let mut s = Sizes::default();
        let mut st = tx.prepare("SELECT edge_id, count(*) FROM crosscheck_queue GROUP BY edge_id")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (e, n) = r?;
            s.total += n;
            s.per_edge.insert(e, n);
        }
        Ok(s)
    }

    fn admits(&mut self, edge: &str) -> bool {
        let edges = i64::try_from(self.per_edge.len() + usize::from(!self.per_edge.contains_key(edge)))
            .unwrap_or(1)
            .max(1);
        let share = (QUEUE_CAP / edges).max(QUEUE_CAP / 4);
        let mine = self.per_edge.get(edge).copied().unwrap_or(0);
        if self.total >= QUEUE_CAP || mine >= share {
            return false;
        }
        self.total += 1;
        *self.per_edge.entry(edge.to_string()).or_default() += 1;
        true
    }
}

/// What admitting a flagged record did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admitted {
    Queued,
    Joined,
    /// Checked within `crosscheck.dedupe_window` already.
    Seen,
    Dropped,
}

/// One flagged record.
pub struct Flag<'a> {
    pub check: Check,
    pub qname: &'a str,
    pub qtype: &'a str,
    pub rcode: &'a str,
    pub addrs: Vec<IpAddr>,
    pub rec: RecRef,
}

/// Admits one flagged record (module docs: dedupe window, joining, caps). `seen_from` is now
/// less `crosscheck.dedupe_window`; `None` while the wall clock isn't synchronised (README §2
/// Clocks): then the window can't be told, and a new item is stored unstamped, its times and its
/// `crosscheck_seen` row set when the clock is synchronised ([`restamp_in`]).
pub fn admit_in(
    tx: &Transaction<'_>,
    f: &Flag<'_>,
    now: &str,
    seen_from: Option<&str>,
    sizes: &mut Sizes,
) -> rusqlite::Result<Admitted> {
    let queued: Option<Option<String>> = tx
        .query_row(
            "SELECT context_json FROM crosscheck_queue WHERE qname = ?1 AND qtype = ?2",
            params![f.qname, f.qtype],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(ctx) = queued {
        let mut c = Context::parse(ctx.as_deref());
        c.join(&f.rec);
        tx.execute(
            "UPDATE crosscheck_queue SET context_json = ?3 WHERE qname = ?1 AND qtype = ?2",
            params![f.qname, f.qtype, serde_json::to_string(&c).unwrap_or_default()],
        )?;
        return Ok(Admitted::Joined);
    }
    if let Some(seen_from) = seen_from {
        let seen: Option<String> = tx
            .query_row(
                "SELECT at FROM crosscheck_seen WHERE qname = ?1 AND qtype = ?2",
                params![f.qname, f.qtype],
                |r| r.get(0),
            )
            .optional()?;
        if seen.is_some_and(|at| at.as_str() >= seen_from) {
            return Ok(Admitted::Seen);
        }
    }
    if !sizes.admits(&f.rec.edge) {
        return Ok(Admitted::Dropped);
    }
    let mut c = Context {
        rcode: f.rcode.to_string(),
        addrs: f.addrs.iter().take(8).map(|a| a.to_string()).collect(),
        ..Context::default()
    };
    c.join(&f.rec);
    tx.execute(
        "INSERT INTO crosscheck_queue(qname, qtype, \"check\", first_seen, attempts, next_at, context_json, edge_id, stamped)
         VALUES (?1, ?2, ?3, ?4, 0, ?4, ?5, ?6, ?7)",
        params![
            f.qname,
            f.qtype,
            f.check.as_str(),
            now,
            serde_json::to_string(&c).unwrap_or_default(),
            f.rec.edge,
            seen_from.is_some()
        ],
    )?;
    if seen_from.is_some() {
        tx.execute(
            "INSERT INTO crosscheck_seen(qname, qtype, at) VALUES (?1, ?2, ?3)
             ON CONFLICT(qname, qtype) DO UPDATE SET at = excluded.at",
            params![f.qname, f.qtype, now],
        )?;
    }
    Ok(Admitted::Queued)
}

/// Stamps the items admitted while the wall clock wasn't synchronised with `now`, and records
/// them as checked now for the dedupe window (README §2 Clocks). Returns how many.
pub fn restamp_in(tx: &Transaction<'_>, now: &str) -> rusqlite::Result<usize> {
    tx.execute(
        "INSERT INTO crosscheck_seen(qname, qtype, at) SELECT qname, qtype, ?1 FROM crosscheck_queue WHERE stamped = 0
         ON CONFLICT(qname, qtype) DO UPDATE SET at = excluded.at",
        [now],
    )?;
    tx.execute(
        "UPDATE crosscheck_queue SET first_seen = ?1, next_at = ?1, stamped = 1 WHERE stamped = 0",
        [now],
    )
}

/// Admits the negative check for a DNSSEC item found Insecure: each of its records not in its
/// profile's forward zones (the DNSSEC candidates already leave those out).
pub fn admit_negative_in(
    tx: &Transaction<'_>,
    it: &DnssecItem,
    ctx: &DnssecContext,
    now: &str,
    seen_from: &str,
    sizes: &mut Sizes,
) -> rusqlite::Result<Admitted> {
    let Some(first) = ctx.records.first() else {
        return Ok(Admitted::Seen);
    };
    let flag = Flag {
        check: Check::Negative,
        qname: &it.qname,
        qtype: &it.qtype,
        rcode: &ctx.rcode,
        addrs: vec![],
        rec: first.clone(),
    };
    // Only after a validation, which waits for a synchronised clock.
    let r = admit_in(tx, &flag, now, Some(seen_from), sizes)?;
    if matches!(r, Admitted::Queued | Admitted::Joined) {
        for rec in ctx.records.iter().skip(1) {
            let f = Flag {
                rec: rec.clone(),
                addrs: vec![],
                ..flag_ref(&flag)
            };
            admit_in(tx, &f, now, Some(seen_from), sizes)?;
        }
    }
    Ok(r)
}

fn flag_ref<'a>(f: &Flag<'a>) -> Flag<'a> {
    Flag {
        check: f.check,
        qname: f.qname,
        qtype: f.qtype,
        rcode: f.rcode,
        addrs: f.addrs.clone(),
        rec: f.rec.clone(),
    }
}

/// The sinkhole check's local flag on one record (module docs): its answer's addresses when it
/// is flagged.
pub fn sinkhole_candidate(
    c: &rusqlite::Connection,
    model: &Model,
    parts: &ConfigParts,
    r: &Rec,
    block_page: &[IpAddr],
) -> rusqlite::Result<Option<Vec<IpAddr>>> {
    let Some(addrs) = super::candidate::sinkhole_flag(r, block_page) else {
        return Ok(None);
    };
    if parts.in_forward_zone(r.profile.as_deref(), &r.qname) {
        return Ok(None);
    }
    if crate::psl::registrable_domain(&r.qname).is_none() {
        return Ok(None);
    }
    if crate::lookups::scope::in_bundle(c, model, "lookup-exclude", &r.qname)? {
        return Ok(None);
    }
    Ok(Some(addrs))
}

/// The resolver as a `DnsServer`.
fn server(r: &CrosscheckResolver) -> DnsServer {
    DnsServer {
        transport: match r.protocol {
            EncryptedProtocol::Dot => UpstreamProtocol::Dot,
            EncryptedProtocol::Doh => UpstreamProtocol::Doh,
        },
        ip: r.ip,
        port: r.port,
        tls_host: Some(r.tls_host.clone()),
        trust_store: None,
        path: r
            .path
            .clone()
            .or_else(|| (r.protocol == EncryptedProtocol::Doh).then(|| "/dns-query".into())),
    }
}

/// What the resolver said.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ResolverAnswer {
    pub rcode: String,
    pub addrs: Vec<String>,
    pub ede: Vec<u16>,
    /// It returned data for the question (a usable RRset of the type, at the name or the end of
    /// its CNAME chain).
    pub data: bool,
    #[serde(skip)]
    pub wire: Vec<u8>,
}

/// The result of asking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asked {
    Answer(ResolverAnswer),
    /// SERVFAIL, REFUSED, a filtering answer or an invalid one: no answer, never retried.
    NoAnswer(String, Option<ResolverAnswer>),
    /// A timeout or transport error: retried.
    Retry(String),
}

/// True when `m` holds an RRset of `qtype` at `qname` or at the end of its CNAME chain.
pub fn has_data(m: &Message, qname: &hickory_net::proto::rr::Name, qtype: RecordType) -> bool {
    let mut name = qname.to_lowercase();
    for _ in 0..16 {
        if m.answers
            .iter()
            .any(|r| r.name.to_lowercase() == name && r.record_type() == qtype)
        {
            return true;
        }
        match m.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(t) if r.name.to_lowercase() == name => Some(t.0.to_lowercase()),
            _ => None,
        }) {
            Some(next) => name = next,
            None => return false,
        }
    }
    false
}

/// Asks the resolver about one name (module docs: the `dns` lookup module's client path).
pub async fn ask(client: &dyn DnsServerClient, r: &CrosscheckResolver, qname: &str, qtype: &str) -> Asked {
    let (Ok(qn), Some(qt)) = (QName::from_text(qname), super::validator::parse_qtype(qtype)) else {
        return Asked::NoAnswer("the name or type can't be queried".into(), None);
    };
    let s = server(r);
    let id = random_query_id();
    let params = QueryParams {
        id,
        cd: false,
        do_bit: false,
        pad: true,
    };
    let mut buf = [0u8; 600];
    let Ok(n) = write_query(&mut buf, qn.as_name(), u16::from(qt), class::IN, &params) else {
        return Asked::NoAnswer("cannot write the query".into(), None);
    };
    let wire = match client.query(&s, &buf[..n], QUERY_TIMEOUT).await {
        Ok(w) => w,
        Err(DnsClientError::TooLarge) => {
            return Asked::NoAnswer("an answer over the size limit".into(), None);
        }
        Err(e) => return Asked::Retry(e.to_string()),
    };
    let sent = SentQuery {
        id,
        qname: qn.as_name(),
        qtype: u16::from(qt),
        qclass: class::IN,
    };
    let facts = match picket_wire::facts::lookup_answer_facts(&wire, &sent) {
        Ok(f) => f,
        Err(e) => return Asked::NoAnswer(format!("an invalid answer: {e:?}"), None),
    };
    let rcode_text = picket_wire::types::rcode_mnemonic(facts.rcode)
        .map(str::to_string)
        .unwrap_or_else(|| format!("RCODE{}", facts.rcode));
    let mut ans = ResolverAnswer {
        rcode: rcode_text,
        addrs: facts.addrs.iter().take(16).map(|a| a.to_string()).collect(),
        ede: facts.ede.iter().map(|e| e.code).collect(),
        data: false,
        wire: wire.clone(),
    };
    if ans.ede.iter().any(|c| matches!(c, 15..=17)) {
        return Asked::NoAnswer("a filtering answer".into(), Some(ans));
    }
    if facts.rcode != 0 && facts.rcode != 3 {
        let why = ans.rcode.clone();
        return Asked::NoAnswer(why, Some(ans));
    }
    ans.data = match qt {
        RecordType::A | RecordType::AAAA => !facts.addrs.is_empty(),
        _ => Message::from_vec(&wire)
            .ok()
            .zip(super::validator::parse_name(qname))
            .is_some_and(|(m, n)| has_data(&m, &n, qt)),
    };
    Asked::Answer(ans)
}

/// The verdict on one check: `agree`, `disagree` or `no_answer`.
pub fn judge(check: Check, asked: &Asked, block_page: &[IpAddr]) -> &'static str {
    match asked {
        Asked::Answer(a) => match check {
            Check::Negative => {
                if a.data {
                    "disagree"
                } else {
                    "agree"
                }
            }
            Check::Sinkhole => {
                let ips: Vec<IpAddr> = a.addrs.iter().filter_map(|s| s.parse().ok()).collect();
                if !ips.is_empty() && ips.iter().all(|ip| !sinkhole_ip(*ip, block_page)) {
                    "disagree"
                } else {
                    "agree"
                }
            }
        },
        Asked::NoAnswer(..) | Asked::Retry(_) => "no_answer",
    }
}

/// One queued item (its context is read again when it is applied: records may have joined).
struct Item {
    qname: String,
    qtype: String,
    check: Check,
    attempts: i64,
}

/// One turn of the cross-check queue.
pub async fn turn(state: &SharedState) -> anyhow::Result<usize> {
    let settings = state.settings();
    let cc = settings.crosscheck.clone();
    let rt = &state.dnssec.crosscheck;
    rt.limiter.set_rate(cc.max_per_minute);
    let generation = state.restore.generation();
    let synced = state.clock.synced();
    // Items admitted before the clock was synchronised are stamped first (README §2 Clocks), so
    // they are due in this turn.
    super::restamp(state).await?;
    let now = crate::util::now();
    let window = settings.retention.query_logs.as_duration();
    let cutoff = crate::util::ts(&crate::util::window_start(now, window));
    // Items older than the retention window are dropped and counted (once the wall clock is
    // synchronised: a drop can't be undone, README §2 Clocks), as is everything queued while the
    // cross-check is off (nothing is sent then).
    let clock = state.clock.clone();
    let coalesced = state.events.coalesced().clone();
    let dropped: Vec<String> = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let rows: Vec<(String, String, String)> = {
                let sql = if !(cc.enabled && cc.resolver.is_some()) {
                    "SELECT qname, qtype, \"check\" FROM crosscheck_queue WHERE ?1 IS NOT NULL LIMIT 1000"
                } else if synced {
                    "SELECT qname, qtype, \"check\" FROM crosscheck_queue WHERE first_seen < ?1 AND stamped = 1 LIMIT 1000"
                } else {
                    "SELECT qname, qtype, \"check\" FROM crosscheck_queue WHERE ?1 IS NULL LIMIT 1000"
                };
                let mut st = tx.prepare(sql)?;
                st.query_map([&cutoff], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for (n, t, _) in &rows {
                tx.execute(
                    "DELETE FROM crosscheck_queue WHERE qname = ?1 AND qtype = ?2",
                    params![n, t],
                )?;
            }
            // The counts commit with the drop (README §2 Restarts).
            let counts: Vec<_> = rows.iter().map(|(_, _, c)| count(c, "dropped")).collect();
            crate::metrics::outbox::queue_in(&tx, &counts, &clock)?;
            tx.commit()?;
            // On the writer, right after the commit (`web::events` module docs).
            coalesced.dnssec_queued(&crate::web::events::DnssecQueuedEvent {
                dropped: rows.len() as u64,
                ..Default::default()
            });
            Ok::<_, anyhow::Error>(rows.into_iter().map(|(_, _, c)| c).collect())
        })
        .await?;
    if !dropped.is_empty() {
        flush_counts(state).await;
    }
    let cc = settings.crosscheck.clone();
    let (true, Some(resolver), Some(client)) = (cc.enabled, cc.resolver.clone(), rt.client()) else {
        return Ok(0);
    };
    let now_s = crate::util::ts(&now);
    let limit = turn_items(cc.max_per_minute);
    // Only stamped items (README §2 Clocks): one admitted before the wall clock was synchronised
    // waits until [`restamp_in`] gives it its times and its `crosscheck_seen` row, so its check
    // keeps the dedupe window (core.md §8) instead of running, and being forgotten, before.
    let items: Vec<Item> = state
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT qname, qtype, \"check\", attempts FROM crosscheck_queue
                 WHERE stamped = 1 AND next_at <= ?1 ORDER BY next_at LIMIT ?2",
            )?;
            let rows = st.query_map(params![now_s, limit], |r| {
                Ok(Item {
                    qname: r.get(0)?,
                    qtype: r.get(1)?,
                    check: if r.get::<_, String>(2)? == "negative" {
                        Check::Negative
                    } else {
                        Check::Sinkhole
                    },
                    attempts: r.get(3)?,
                })
            })?;
            Ok::<_, anyhow::Error>(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await?;
    // One check at a time (core.md §8 Queue: `crosscheck.max_per_minute` limits the queries, and
    // work beyond it waits): its token is taken outside the light lane, so a wait holds no slot
    // and `job_ms` measures the query and its store, not the wait (core.md §3); then the query
    // and the store of its result, as one light-lane job. No check starts after the turn's
    // budget or once a restore committed; the items left wait for the next turn.
    let started = tokio::time::Instant::now();
    let mut done = 0;
    for it in items {
        if started.elapsed() >= TURN_BUDGET || !state.restore.is_current(generation) {
            break;
        }
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            _ = rt.limiter.acquire() => {}
        }
        let (st, client, resolver) = (state.clone(), client.clone(), resolver.clone());
        let job = state.scheduler.light.spawn(Some("crosscheck"), async move {
            let asked = ask(client.as_ref(), &resolver, &it.qname, &it.qtype).await;
            apply(&st, vec![(it, asked)], generation).await
        });
        let Some(h) = job else {
            break;
        };
        h.await.map_err(|e| anyhow::anyhow!("crosscheck job: {e}"))??;
        done += 1;
    }
    Ok(done)
}

/// Runs turns until nothing is due (tests).
pub async fn drain(state: &SharedState) -> anyhow::Result<usize> {
    let mut total = 0;
    for _ in 0..50 {
        let n = turn(state).await?;
        total += n;
        if n == 0 {
            break;
        }
    }
    Ok(total)
}

/// Applies checks' answers (one check's, as it ends); nothing when a restore committed since the
/// turn began (core.md §2).
async fn apply(state: &SharedState, results: Vec<(Item, Asked)>, generation: u64) -> anyhow::Result<()> {
    let settings = state.settings();
    let block_page = settings.crosscheck.block_page_ips.clone();
    let resolver = settings.crosscheck.resolver.clone();
    let total = u64::from(settings.alerts.evidence_total_mib) * 1024 * 1024;
    let now = crate::util::now();
    let alerts = state.alerts.clone();
    let st = state.clone();
    let (new, ch) = state
        .db
        .write(move |c| {
            if !st.restore.is_current(generation) {
                return Ok((Vec::new(), Changes::default()));
            }
            let tx = c.transaction()?;
            let mut ch = Changes::default();
            let mut counts = Vec::new();
            let mut new: Vec<(i64, String)> = Vec::new();
            // Checks retried or ended (the `dnssec_queued` UI event, api.md §7: the queue view
            // changes without a DNSSEC result).
            let mut changed = crate::web::events::DnssecQueuedEvent::default();
            for (it, asked) in &results {
                if let Asked::Retry(_) = asked
                    && it.attempts + 1 < MAX_ATTEMPTS
                {
                    let next = crate::util::ts(&(now + jiff::SignedDuration::try_from(backoff(it.attempts + 1)).unwrap_or_default()));
                    tx.execute(
                        "UPDATE crosscheck_queue SET attempts = ?3, next_at = ?4 WHERE qname = ?1 AND qtype = ?2",
                        params![it.qname, it.qtype, it.attempts + 1, next],
                    )?;
                    changed.crosscheck_retried += 1;
                    continue;
                }
                // Records that joined while it was asked. An item no longer queued stores
                // nothing.
                let Some(ctx) = tx
                    .query_row(
                        "SELECT context_json FROM crosscheck_queue WHERE qname = ?1 AND qtype = ?2",
                        params![it.qname, it.qtype],
                        |r| r.get::<_, Option<String>>(0),
                    )
                    .optional()?
                    .map(|c| Context::parse(c.as_deref()))
                else {
                    continue;
                };
                tx.execute(
                    "DELETE FROM crosscheck_queue WHERE qname = ?1 AND qtype = ?2",
                    params![it.qname, it.qtype],
                )?;
                changed.crosscheck_ended += 1;
                let result = judge(it.check, asked, &block_page);
                counts.push(count(it.check.as_str(), result));
                if result == "disagree"
                    && let Asked::Answer(a) = asked
                {
                    let groups: Vec<String> = if ctx.groups.is_empty() {
                        vec![String::new()]
                    } else {
                        ctx.groups.clone()
                    };
                    let domain = crate::psl::grouping_key(&it.qname);
                    for g in groups {
                        let key = format!("upstream_disagrees:{domain}:{g}");
                        let recs: Vec<&RecRef> = ctx
                            .records
                            .iter()
                            .filter(|r| r.group.as_deref().unwrap_or("") == g)
                            .collect();
                        let details = json!({
                            "check": it.check.as_str(),
                            "name": it.qname,
                            "qtype": it.qtype,
                            "domain": domain,
                            "upstream_group": g,
                            "upstream": {"rcode": ctx.rcode, "addresses": ctx.addrs},
                            "resolver": {
                                "rcode": a.rcode, "addresses": a.addrs, "ede": a.ede,
                                "server": resolver.as_ref().map(|r| json!({"ip": r.ip, "port": r.port, "tls_host": r.tls_host, "operator": r.operator})),
                            },
                            "edges": ctx.edges,
                            "clients": recs.iter().map(|r| r.client.clone()).collect::<Vec<_>>(),
                        });
                        let title = format!(
                            "Upstream group {} answered {} {} {} where the cross-check resolver returned {}",
                            crate::util::sanitize_for_message(&g, 64),
                            crate::util::sanitize_for_message(&it.qname, 128),
                            it.qtype,
                            if it.check == Check::Negative { ctx.rcode.as_str() } else { "a sinkhole address" },
                            if a.addrs.is_empty() { "data".to_string() } else { a.addrs.join(", ") }
                        );
                        // Keyed on (domain, group): the edge is where it was seen (none once
                        // several edges' records raised it), no per-edge share.
                        let spec = RaiseSpec::new("upstream_disagrees", Severity::Warning, key.clone(), title, details)
                            .seen_on_edges(&ctx.edges);
                        let rule = crate::logs::evidence::EvidenceRule {
                            domain: domain.clone(),
                            ..Default::default()
                        };
                        if let Some(id) =
                            crate::logs::evidence::raise_security_with_rule_in(&alerts, &tx, &spec, &rule, &mut ch)?
                        {
                            new.push((id, domain.clone()));
                        }
                        // The resolver's answer, beside the copied records and their answers,
                        // charged to the shared evidence budget (core.md §9).
                        let id: Option<i64> = tx
                            .query_row("SELECT id FROM alerts WHERE dedupe_key = ?1", [&key], |r| r.get(0))
                            .optional()?;
                        if let Some(id) = id {
                            let aid = format!("crosscheck:{}", &blake3::hash(&a.wire).to_hex()[..16]);
                            st.analysis
                                .capture
                                .add_answer_in(&tx, id, &aid, "crosscheck", &a.wire, total)?;
                        }
                    }
                }
            }
            // The counts commit with the results (README §2 Restarts).
            crate::metrics::outbox::queue_in(&tx, &counts, &st.clock)?;
            tx.commit()?;
            alerts.committed(&ch);
            // On the writer, right after the commit (`web::events` module docs).
            st.events.coalesced().dnssec_queued(&changed);
            Ok::<_, anyhow::Error>((new, ch))
        })
        .await?;
    state.alerts.announce(ch);
    flush_counts(state).await;
    for (id, domain) in new {
        let st = state.clone();
        tokio::spawn(async move {
            let rule = crate::logs::evidence::EvidenceRule {
                domain,
                ..Default::default()
            };
            if let Err(e) = crate::logs::evidence::start_since(&st, generation, id, rule).await {
                tracing::warn!(error = %format!("{e:#}"), alert = id, "upstream_disagrees evidence capture failed to start");
            }
        });
    }
    Ok(())
}

/// One queued cross-check of an unsigned answer (core.md §8 Cross-check; the DNSSEC page's
/// cross-check queue, `GET dnssec/queue`'s `crosscheck_items`, earliest due first). Each (qname,
/// qtype) is queued once, whichever check flagged it first; later flagged records join it.
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct CrosscheckQueueItem {
    /// The name the resolver is asked about.
    pub qname: String,
    pub qtype: String,
    /// The check that queued it: `negative` (an Insecure NXDOMAIN, SERVFAIL or A NODATA, after
    /// its DNSSEC result) or `sinkhole` (an allowed answer holding a sinkhole address, flagged at
    /// ingest).
    pub kind: String,
    /// Failed resolver queries so far (timeouts and transport errors); at the third the item ends
    /// as no answer.
    pub attempts: i64,
    /// When it is due: at once when queued, later after a failed query (backoff 30 s to 30 min).
    /// An item queued while core's wall clock wasn't synchronised waits, and its times are set
    /// once the clock is (README §2 Clocks).
    pub next_at: String,
    /// When it was queued (or stamped, for an item queued before the clock was synchronised).
    pub queued_at: String,
}

pub async fn queue_view(
    state: &SharedState,
    limit: usize,
) -> anyhow::Result<(Vec<CrosscheckQueueItem>, i64)> {
    state
        .db
        .read(move |c| {
            let total: i64 = c.query_row("SELECT count(*) FROM crosscheck_queue", [], |r| r.get(0))?;
            let mut st = c.prepare(
                "SELECT qname, qtype, \"check\", attempts, next_at, first_seen FROM crosscheck_queue ORDER BY next_at LIMIT ?1",
            )?;
            let rows = st.query_map([limit], |r| {
                Ok(CrosscheckQueueItem {
                    qname: r.get(0)?,
                    qtype: r.get(1)?,
                    kind: r.get(2)?,
                    attempts: r.get(3)?,
                    next_at: r.get(4)?,
                    queued_at: r.get(5)?,
                })
            })?;
            Ok::<_, anyhow::Error>((rows.collect::<rusqlite::Result<_>>()?, total))
        })
        .await
}

/// Moves queued metric increments to metrics.db (what fails here waits for the next flush).
async fn flush_counts(state: &SharedState) {
    if let Err(e) = crate::metrics::outbox::flush(state).await {
        tracing::warn!(error = %format!("{e:#}"), "cross-check counts wait in the metric outbox");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judging() {
        let a = |addrs: &[&str], data: bool| {
            Asked::Answer(ResolverAnswer {
                rcode: "NOERROR".into(),
                addrs: addrs.iter().map(|s| s.to_string()).collect(),
                data,
                ..Default::default()
            })
        };
        assert_eq!(
            judge(Check::Negative, &a(&["93.184.216.34"], true), &[]),
            "disagree"
        );
        assert_eq!(
            judge(Check::Negative, &a(&[], false), &[]),
            "agree",
            "a CNAME plus NODATA from both agrees"
        );
        assert_eq!(
            judge(Check::Sinkhole, &a(&["93.184.216.34"], true), &[]),
            "disagree"
        );
        assert_eq!(judge(Check::Sinkhole, &a(&["0.0.0.0"], true), &[]), "agree");
        assert_eq!(judge(Check::Sinkhole, &a(&[], false), &[]), "agree");
        assert_eq!(
            judge(Check::Negative, &Asked::NoAnswer("SERVFAIL".into(), None), &[]),
            "no_answer"
        );
    }

    /// core.md §8 Queue (final check, round 3): a turn takes about a minute of queries.
    #[test]
    fn turns_follow_the_rate() {
        assert_eq!(turn_items(1), 1);
        assert_eq!(turn_items(10), 10);
        assert_eq!(turn_items(60), TURN_ITEMS);
        assert_eq!(turn_items(100_000), TURN_ITEMS);
    }

    #[test]
    fn backoff_range() {
        assert!((24..=36).contains(&backoff(1).as_secs()));
        assert!((1440..=2160).contains(&backoff(20).as_secs()));
    }
}
