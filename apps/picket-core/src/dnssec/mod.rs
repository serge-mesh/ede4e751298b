//! Async DNSSEC validation of logged answers through an edge, and the cross-check of unsigned
//! answers (core.md §8).
//!
//! - **Candidates** ([`candidate`]): after ingest, the log analysis hands each batch of records
//!   to [`admit`] (light lane, never delaying ingest or the ack). Each `q` record with decision
//!   `allow` or `servfail` counts once in `dnssec_answers{edge}` and once in
//!   `dnssec_coverage{edge, class, outcome}`: at once under `edge`, `forward_zone`,
//!   `plain_upstream` or `off`, or when its check ends under the check's result. Admission is
//!   once per record: its key stays in `dnssec_admitted` until the analysis marks it analysed
//!   ([`Admission`], [`admitted`]), so a batch that runs again counts and joins nothing twice.
//! - **Queue** ([`queue`]): `dnssec_queue` in `core.db`, worked by [`start`]'s loop in the light
//!   lane. `dnssec.max_per_minute` limits the validator's network requests ([`validator::Limiter`]),
//!   not its local checks. While no edge DoH listener is reachable, items that need a request
//!   wait without using an attempt. A request that fails while the edge is reachable (timeout,
//!   SERVFAIL, REFUSED, HTTP 403, Indeterminate) is retried with backoff (30 s → 30 min, at most
//!   10 attempts), then the outcome is Indeterminate; a SERVFAIL candidate's query isn't retried.
//!   Items older than the retention window, or over the queue's cap, are dropped and counted.
//!   Validation and dropping by age wait until the wall clock is synchronised (README §2 Clocks:
//!   signatures are checked against it).
//! - **Validation** ([`validator`]): hickory's `DnssecDnsHandle` over an adapter that answers the
//!   logged question from the logged wire and sends every other query over DoH to an edge
//!   listener ([`resolver`]) with DO=1 and CD=1.
//! - **Outcomes:** `dnssec_results{outcome}`, `dnssec_fallback`; Bogus raises `dnssec_bogus`,
//!   one per zone where validation broke, with the RFC 8914 code, hickory's proof error, the
//!   validator's upstream group, the names, edges and clients (each with its own group) and, as
//!   evidence (charged to the shared evidence budget), the validator's DNSKEY and DS answers and
//!   the copied records. A record that takes a known Bogus result joins that alert's names,
//!   edges, clients and groups. While candidates wait and none is validated (Secure, Insecure or
//!   Bogus) for an hour, `dnssec_unavailable`.
//! - **Restores:** work that began before a config restore stores nothing after it
//!   ([`crate::config::export::RestoreGate`]), and a result needs its queue item to still exist.
//! - **Cross-check** ([`crosscheck`]): the negative check of Insecure answers and the sinkhole
//!   check, through a second resolver, raising `upstream_disagrees`.
//! - **UI** ([`api`]): `GET dnssec/queue`, `GET dnssec/results`. Results stored send the
//!   coalesced `dnssec` event, and every other change to either queue (queued, joined, retried,
//!   waiting, a cross-check ended, dropped, stamped) `dnssec_queued` (api.md §7,
//!   `web::events::DnssecQueuedEvent`), so the queue view needn't poll while its socket is open.

pub mod api;
pub mod candidate;
pub mod crosscheck;
pub mod queue;
pub mod resolver;
pub mod validator;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use hickory_net::proto::dnssec::TrustAnchors;
use jiff::Timestamp;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use self::candidate::{Class, PartsCache};
use self::queue::{Admit, Admitted, Context, Item, Kind, RecRef};
use self::validator::{ChainCache, ChainResolver, CryptoMemo, Limiter, Outcome, Shared, Subject, Verdict};
use crate::alerts::{Changes, RaiseSpec, Severity};
use crate::logs::record::Rec;
use crate::state::{AppState, SharedState};
// Changes to the queues, for the coalesced `dnssec_queued` UI event (api.md §7).
use crate::web::events::DnssecQueuedEvent as QueueChanges;

/// The most items one turn takes.
const TURN_ITEMS: usize = 64;
/// Validations run at once.
const CONCURRENCY: usize = 4;
/// Network requests one validation makes, about (a chain not cached yet: DNSKEY and DS per zone
/// level): turns are sized to the rate with it ([`turn_items`]).
const REQUESTS_PER_ITEM: usize = 4;
/// A turn starts no new validation after this long; those running finish, and their results
/// are stored as they end.
const TURN_BUDGET: Duration = Duration::from_secs(60);
/// The loop's idle tick.
const TICK: Duration = Duration::from_secs(5);
/// How long an item waits while no edge DoH listener is reachable.
const WAIT_UNREACHABLE: Duration = Duration::from_secs(30);
/// Retries of a failed request (core.md §8).
pub const MAX_ATTEMPTS: i64 = 10;
const BACKOFF_MIN: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
/// Names one `dnssec_bogus` alert lists.
const MAX_ALERT_NAMES: usize = 100;

/// The items one turn takes at `dnssec.max_per_minute` (core.md §8: work beyond the rate waits):
/// about a minute of requests, between [`CONCURRENCY`] and [`TURN_ITEMS`]. With [`TURN_BUDGET`]
/// and results stored as each validation ends, a turn stays short at any rate, so a restart or a
/// restore loses only the validations in flight, `dnssec_unavailable` sees each result as it is
/// stored, and the turn's job time isn't hours of token waits.
pub fn turn_items(max_per_minute: u32) -> usize {
    (usize::try_from(max_per_minute).unwrap_or(usize::MAX) / REQUESTS_PER_ITEM).clamp(CONCURRENCY, TURN_ITEMS)
}

/// The backoff before attempt `attempts + 1`: 30 s doubling to 30 min, ±20 % (core.md §8).
pub fn backoff(attempts: i64) -> Duration {
    let exp = u32::try_from(attempts.saturating_sub(1).clamp(0, 16)).unwrap_or(16);
    let base = BACKOFF_MIN
        .saturating_mul(2u32.saturating_pow(exp))
        .min(BACKOFF_MAX);
    base.mul_f64(rand::random_range(0.8..=1.2))
}

/// The DNSSEC runtime shared through [`AppState`].
pub struct Dnssec {
    pub cache: Arc<ChainCache>,
    pub limiter: Arc<Limiter>,
    pub memo: CryptoMemo,
    pub parts: PartsCache,
    pub crosscheck: crosscheck::Runtime,
    resolver: Mutex<Option<Arc<dyn ChainResolver>>>,
    anchors: Mutex<Option<Arc<TrustAnchors>>>,
    wake: tokio::sync::Notify,
    paused: AtomicBool,
    cap: std::sync::atomic::AtomicI64,
    /// Items may wait for their stamps ([`restamp`]): set at start and by an admission while
    /// the wall clock isn't synchronised.
    unstamped: AtomicBool,
}

impl Default for Dnssec {
    fn default() -> Self {
        Self {
            cache: Arc::new(ChainCache::default()),
            limiter: Arc::new(Limiter::new(120)),
            memo: CryptoMemo::default(),
            parts: PartsCache::default(),
            crosscheck: crosscheck::Runtime::default(),
            resolver: Mutex::new(None),
            anchors: Mutex::new(None),
            wake: tokio::sync::Notify::new(),
            paused: AtomicBool::new(false),
            cap: std::sync::atomic::AtomicI64::new(queue::QUEUE_CAP),
            unstamped: AtomicBool::new(true),
        }
    }
}

impl Dnssec {
    /// Replaces the chain resolver (tests: a local zone set).
    pub fn set_resolver(&self, r: Arc<dyn ChainResolver>) {
        if let Ok(mut g) = self.resolver.lock() {
            *g = Some(r);
        }
    }

    /// Replaces hickory's built-in root KSKs (tests: their own signed root).
    pub fn set_trust_anchors(&self, a: TrustAnchors) {
        if let Ok(mut g) = self.anchors.lock() {
            *g = Some(Arc::new(a));
        }
        self.memo.clear();
        self.cache.clear();
    }

    /// Stops (or resumes) the background loop's work (tests drive [`drain`] themselves).
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
        if !paused {
            self.wake.notify_one();
        }
    }

    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Lowers the queue's cap (tests).
    pub fn set_queue_cap(&self, cap: i64) {
        self.cap.store(cap.max(1), Ordering::Relaxed);
    }

    /// Forgets every cached chain answer and verdict, and takes only those of restore
    /// generation `generation` from now on (a restore, on the writer right after its commit:
    /// a validation that began before it caches nothing after it, core.md §2).
    pub fn reset_to(&self, generation: u64) {
        self.cache.reset_to(generation);
        self.memo.reset_to(generation);
        self.parts.clear();
        self.crosscheck.reset();
    }

    fn shared(&self, generation: u64) -> Option<Shared> {
        let resolver = self.resolver.lock().ok()?.clone()?;
        let anchors = self
            .anchors
            .lock()
            .ok()
            .and_then(|a| a.clone())
            .unwrap_or_else(|| Arc::new(TrustAnchors::default()));
        Some(Shared {
            resolver,
            cache: self.cache.clone(),
            limiter: self.limiter.clone(),
            anchors,
            generation,
        })
    }
}

/// Starts the DNSSEC and cross-check loops.
pub fn start(state: &SharedState, opts: &crate::modules::download::client::HttpOptions) {
    {
        let mut g = state.dnssec.resolver.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            *g = Some(Arc::new(resolver::EdgeDoh::new(Arc::downgrade(state), opts)));
        }
    }
    state.dnssec.crosscheck.init(opts);
    // Validation. A turn may wait on `dnssec.max_per_minute` tokens for long (work beyond the
    // rate waits, core.md §8), so the cross-check and the monitor run in their own loops.
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = st.shutdown.cancelled() => return,
                _ = st.dnssec.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
            if st.dnssec.paused.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(e) = turn(&st).await {
                tracing::warn!(error = %format!("{e:#}"), "DNSSEC validation failed");
            }
        }
    });
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = st.shutdown.cancelled() => return,
                _ = st.dnssec.crosscheck.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
            if st.dnssec.paused.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(e) = crosscheck::turn(&st).await {
                tracing::warn!(error = %format!("{e:#}"), "the cross-check failed");
            }
        }
    });
    // Queue gauges every 30 s; `dnssec_unavailable` every minute.
    let st = state.clone();
    tokio::spawn(async move {
        let mut last_unavailable: Option<tokio::time::Instant> = None;
        loop {
            sample(&st).await;
            if !st.dnssec.paused.load(Ordering::Relaxed)
                && last_unavailable.is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
            {
                last_unavailable = Some(tokio::time::Instant::now());
                if let Err(e) = unavailable_check(&st).await {
                    tracing::warn!(error = %format!("{e:#}"), "dnssec_unavailable check failed");
                }
            }
            tokio::select! {
                _ = st.shutdown.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    });
}

/// `queue_depth{queue=dnssec|crosscheck}` (core.md §10).
async fn sample(state: &SharedState) {
    let depths = state
        .db
        .read(|c| {
            let d: i64 = c.query_row("SELECT count(*) FROM dnssec_queue", [], |r| r.get(0))?;
            let x: i64 = c.query_row("SELECT count(*) FROM crosscheck_queue", [], |r| r.get(0))?;
            Ok::<_, anyhow::Error>((d, x))
        })
        .await;
    if let Ok((d, x)) = depths {
        state
            .metrics
            .gauges(
                &state.metrics_db,
                vec![
                    (
                        "queue_depth".into(),
                        crate::metrics::labels("", &[("queue", "dnssec")]),
                        d as f64,
                    ),
                    (
                        "queue_depth".into(),
                        crate::metrics::labels("", &[("queue", "crosscheck")]),
                        x as f64,
                    ),
                ],
            )
            .await;
    }
}

/// One metric increment: (name, labels, event time in ms, n).
type Count = (String, crate::metrics::Labels, i64, f64);

fn coverage(edge: &str, class: &str, outcome: &str, ts_ms: i64, n: f64) -> Count {
    (
        "dnssec_coverage".into(),
        crate::metrics::labels(edge, &[("class", class), ("outcome", outcome)]),
        ts_ms,
        n,
    )
}

/// The coverage counts of an item's records under `class` (`outcome` for class `fallback`).
fn coverage_of(ctx: &Context, class: &str, outcome: &str) -> Vec<Count> {
    let mut out = Vec::new();
    for (edge, bins) in &ctx.cov {
        for (bin, n) in bins {
            out.push(coverage(edge, class, outcome, *bin, *n as f64));
        }
    }
    out
}

/// The record's device, else its client address.
fn client_of(r: &Rec) -> String {
    r.device.clone().unwrap_or_else(|| r.client_ip.clone())
}

/// The records one [`admit`] took. Their keys stay in `dnssec_admitted` until the analysis has
/// marked them analysed in their partition ([`admitted`]): a batch cut off between its
/// admission and that marker runs again, and then counts, queues and joins nothing twice
/// (core.md §8: each record counts once).
#[derive(Debug, Default)]
#[must_use = "pass it to dnssec::admitted once the records are marked analysed"]
pub struct Admission {
    keys: Vec<(String, String, i64)>,
}

/// Forgets the admission keys of records now marked analysed (see [`Admission`]). A failure
/// only leaves keys that the age sweep deletes later.
pub async fn admitted(state: &SharedState, a: Admission) {
    if a.keys.is_empty() {
        return;
    }
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            {
                let mut st = tx.prepare_cached(
                    "DELETE FROM dnssec_admitted WHERE edge_id = ?1 AND boot = ?2 AND seq = ?3",
                )?;
                for (e, b, s) in &a.keys {
                    st.execute(params![e, b, s])?;
                }
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await;
    if let Err(e) = r {
        tracing::warn!(error = %format!("{e:#}"), "cannot forget DNSSEC admission keys; the age sweep does");
    }
}

/// Admits the DNSSEC and cross-check candidates among `recs`, records the analysis just
/// passed over (core.md §8), and counts `dnssec_answers` and the coverage classes known now.
/// `generation`: the restore generation when the records were read; after a restore nothing is
/// admitted (they are pre-restore records, core.md §2).
pub async fn admit(state: &SharedState, recs: &[Rec], generation: u64) -> anyhow::Result<Admission> {
    let relevant: Vec<Rec> = recs
        .iter()
        .filter(|r| r.decision == "allow" || r.decision == "servfail")
        .cloned()
        .collect();
    if relevant.is_empty() || !state.restore.is_current(generation) {
        return Ok(Admission::default());
    }
    let settings = state.settings();
    let enabled = settings.dnssec.enabled;
    let model = state.analysis.model(state).await?;
    let st = state.clone();
    let cap = state.dnssec.cap.load(Ordering::Relaxed);
    let recs2 = relevant.clone();
    // Classify on a read connection (published config parts; the cross-check's scope check).
    let classes: Vec<(Class, Option<Vec<std::net::IpAddr>>)> = {
        let model = model.clone();
        let cc = settings.crosscheck.clone();
        state
            .db
            .read(move |c| {
                let current = Arc::new(candidate::ConfigParts::from_model(&model));
                let mut out = Vec::with_capacity(recs2.len());
                for r in &recs2 {
                    let short = candidate::config_short(r);
                    let parts = st
                        .dnssec
                        .parts
                        .get(c, &r.edge, &short)?
                        .unwrap_or_else(|| current.clone());
                    let class = candidate::classify(r, &parts, enabled);
                    let sink = if cc.enabled && cc.sinkhole && cc.resolver.is_some() {
                        crosscheck::sinkhole_candidate(c, &model, &parts, r, &cc.block_page_ips)?
                    } else {
                        None
                    };
                    out.push((class, sink));
                }
                Ok::<_, anyhow::Error>(out)
            })
            .await?
    };
    let now = crate::util::now();
    let now_s = crate::util::ts(&now);
    // The dedupe windows and the items' stamps need the wall clock (README §2 Clocks): while it
    // isn't synchronised, no result is reused by its time and new items wait for their stamps.
    let synced = state.clock.synced();
    let window = settings.dnssec.dedupe_window.as_duration();
    let dedupe_from = synced.then(|| crate::util::ts(&crate::util::window_start(now, window)));
    let cc_window = settings.crosscheck.dedupe_window.as_duration();
    let cc_from = synced.then(|| crate::util::ts(&crate::util::window_start(now, cc_window)));
    let rows: Vec<(Rec, Class, Option<Vec<std::net::IpAddr>>)> = relevant
        .into_iter()
        .zip(classes)
        .map(|(r, (c, s))| (r, c, s))
        .collect();
    let alerts = state.alerts.clone();
    let gate = state.restore.clone();
    let group = validator_group(&model);
    let clock = state.clock.clone();
    let coalesced = state.events.coalesced().clone();
    let (woke, keys, ch, new_alerts) = state
        .db
        .write(move |c| {
            if !gate.is_current(generation) {
                return Ok((false, Vec::new(), Changes::default(), Vec::new()));
            }
            let tx = c.transaction()?;
            let mut sizes = queue::Sizes::load(&tx, cap)?;
            let mut cc_sizes = crosscheck::Sizes::load(&tx)?;
            let mut counts: Vec<Count> = Vec::new();
            let mut queued = false;
            // Items newly queued for validation and for the cross-check, and records joining a
            // queued validation (the `dnssec_queued` UI event, api.md §7).
            let mut newly = QueueChanges::default();
            let mut keys: Vec<(String, String, i64)> = Vec::with_capacity(rows.len());
            let mut ch = Changes::default();
            let mut new_alerts: Vec<(i64, String)> = Vec::new();
            for (r, class, sink) in &rows {
                // Once per record (see [`Admission`]); a key found from an earlier run is
                // released with this batch too.
                keys.push((r.edge.clone(), r.boot.clone(), r.seq));
                let new = tx
                    .prepare_cached(
                        "INSERT OR IGNORE INTO dnssec_admitted(edge_id, boot, seq, ts) VALUES (?1, ?2, ?3, ?4)",
                    )?
                    .execute(params![r.edge, r.boot, r.seq, r.ts])?;
                if new == 0 {
                    continue;
                }
                let ts_ms = r.time().map(|t| t.as_millisecond()).unwrap_or(0);
                counts.push((
                    "dnssec_answers".into(),
                    crate::metrics::labels(&r.edge, &[]),
                    ts_ms,
                    1.0,
                ));
                let up = candidate::upstream_of(r);
                let rec = RecRef {
                    edge: r.edge.clone(),
                    boot: r.boot.clone(),
                    seq: r.seq,
                    ts: r.ts.clone(),
                    client: client_of(r),
                    group: up.as_ref().and_then(|u| u.group.clone()),
                    profile: r.profile.clone(),
                };
                let kind = match class {
                    Class::NotAnswer => continue,
                    Class::Unchecked(cls) => {
                        counts.push(coverage(&r.edge, cls, "", ts_ms, 1.0));
                        None
                    }
                    Class::Answer => Some(Kind::Answer),
                    Class::Fallback => Some(Kind::Fallback),
                    Class::Servfail => Some(Kind::Servfail),
                };
                if let Some(kind) = kind {
                    let a = Admit {
                        kind,
                        answer_id: if kind == Kind::Answer {
                            r.answer_id.as_deref()
                        } else {
                            None
                        },
                        received_at: if kind == Kind::Answer {
                            r.received_at.as_deref()
                        } else {
                            None
                        },
                        wire: if kind == Kind::Answer {
                            r.answer_wire.as_deref()
                        } else {
                            None
                        },
                        qname: &r.qname,
                        qtype: &r.qtype,
                        rcode: &r.rcode,
                        nodata: candidate::nodata(r),
                        rec: rec.clone(),
                        ts_ms,
                    };
                    match queue::admit_in(&tx, &a, &now_s, dedupe_from.as_deref(), &mut sizes)? {
                        Admitted::Queued => {
                            queued = true;
                            newly.validation += 1;
                        }
                        Admitted::Joined => newly.joined += 1,
                        Admitted::Known(o, fallback, id) => {
                            if fallback {
                                counts.push(coverage(&r.edge, "fallback", o.as_str(), ts_ms, 1.0));
                            } else {
                                counts.push(coverage(&r.edge, o.as_str(), "", ts_ms, 1.0));
                            }
                            if o == Outcome::Bogus
                                && let Some(n) = join_bogus_in(
                                    &alerts,
                                    &tx,
                                    id,
                                    &r.qname,
                                    &r.qtype,
                                    kind,
                                    &rec,
                                    group.as_deref(),
                                    &mut ch,
                                )?
                            {
                                new_alerts.push(n);
                            }
                        }
                        Admitted::Dropped => {
                            counts.push(coverage(&r.edge, "dropped", "", ts_ms, 1.0));
                            counts.push((
                                "dnssec_dropped".into(),
                                crate::metrics::labels("", &[("reason", "full")]),
                                now.as_millisecond(),
                                1.0,
                            ));
                        }
                    }
                }
                if let Some(addrs) = sink {
                    let res = crosscheck::admit_in(
                        &tx,
                        &crosscheck::Flag {
                            check: crosscheck::Check::Sinkhole,
                            qname: &r.qname,
                            qtype: &r.qtype,
                            rcode: &r.rcode,
                            addrs: addrs.clone(),
                            rec: rec.clone(),
                        },
                        &now_s,
                        cc_from.as_deref(),
                        &mut cc_sizes,
                    )?;
                    if res == crosscheck::Admitted::Queued {
                        queued = true;
                        newly.crosscheck += 1;
                    }
                    if res == crosscheck::Admitted::Dropped {
                        counts.push(crosscheck::count("sinkhole", "dropped"));
                    }
                }
            }
            // The counts commit with the admission markers (README §2 Restarts: a stop or a
            // failed metrics write loses none, and a batch admitted again adds none); the
            // analysis moves them to metrics.db after its own commit.
            crate::metrics::outbox::queue_in(&tx, &counts, &clock)?;
            tx.commit()?;
            alerts.committed(&ch);
            // On the writer, right after the commit (`web::events` module docs).
            coalesced.dnssec_queued(&newly);
            Ok::<_, anyhow::Error>((queued, keys, ch, new_alerts))
        })
        .await?;
    if !synced {
        // Set after the commit: a re-stamp that ran meanwhile didn't see these items.
        state.dnssec.unstamped.store(true, Ordering::SeqCst);
    }
    state.alerts.announce(ch);
    start_evidence(state, generation, new_alerts);
    if woke {
        state.dnssec.wake();
        state.dnssec.crosscheck.wake();
    }
    Ok(Admission { keys })
}

/// Starts (or resumes) the evidence capture of `dnssec_bogus` alerts just raised: their rules
/// went in with the raise.
fn start_evidence(state: &SharedState, generation: u64, alerts: Vec<(i64, String)>) {
    for (id, zone) in alerts {
        let st = state.clone();
        tokio::spawn(async move {
            let rule = crate::logs::evidence::EvidenceRule {
                domain: zone,
                ..Default::default()
            };
            if let Err(e) = crate::logs::evidence::start_since(&st, generation, id, rule).await {
                tracing::warn!(error = %format!("{e:#}"), alert = id, "dnssec_bogus evidence capture failed to start");
            }
        });
    }
}

/// Moves queued metric increments to metrics.db (README §2 Restarts: they were queued with the
/// effects that produced them; what fails here waits for the next flush).
async fn flush_counts(state: &SharedState) {
    if let Err(e) = crate::metrics::outbox::flush(state).await {
        tracing::warn!(error = %format!("{e:#}"), "DNSSEC counts wait in the metric outbox");
    }
}

/// Stamps the items admitted while the wall clock wasn't synchronised (README §2 Clocks), once it
/// is: before their age, their due time or `dnssec_unavailable` is decided by those stamps.
async fn restamp(state: &SharedState) -> anyhow::Result<()> {
    if !state.clock.synced() || !state.dnssec.unstamped.swap(false, Ordering::SeqCst) {
        return Ok(());
    }
    let coalesced = state.events.coalesced().clone();
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let now = crate::util::now_ts();
            let n = queue::restamp_in(&tx, &now)? + crosscheck::restamp_in(&tx, &now)?;
            tx.commit()?;
            // On the writer, right after the commit (`web::events` module docs).
            coalesced.dnssec_queued(&QueueChanges {
                stamped: u64::try_from(n).unwrap_or(u64::MAX),
                ..QueueChanges::default()
            });
            Ok::<_, anyhow::Error>(n)
        })
        .await;
    match r {
        Ok(n) => {
            if n > 0 {
                tracing::info!(
                    items = n,
                    "DNSSEC and cross-check items admitted before the clock was synchronised are stamped now"
                );
            }
            Ok(())
        }
        Err(e) => {
            state.dnssec.unstamped.store(true, Ordering::SeqCst);
            Err(e)
        }
    }
}

/// One turn: drops items past the retention window, then validates the due items. Both wait
/// until the wall clock is synchronised (README §2 Clocks): signatures are checked against it,
/// and a drop by age can't be undone.
pub async fn turn(state: &SharedState) -> anyhow::Result<usize> {
    let settings = state.settings();
    state.dnssec.limiter.set_rate(settings.dnssec.max_per_minute);
    if !state.clock.synced() {
        return Ok(0);
    }
    let generation = state.restore.generation();
    restamp(state).await?;
    drop_old(state).await?;
    if !settings.dnssec.enabled {
        return Ok(0);
    }
    let Some(shared) = state.dnssec.shared(generation) else {
        return Ok(0);
    };
    let now_s = crate::util::now_ts();
    let limit = turn_items(settings.dnssec.max_per_minute);
    let items = state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(queue::due(c, &now_s, limit)?))
        .await?;
    if items.is_empty() {
        return Ok(0);
    }
    let st = state.clone();
    let job = state.scheduler.light.spawn(Some("dnssec"), async move {
        // Results are stored as validations end, a few at a time (core.md §8); no validation
        // starts after the turn's budget, and the items left wait for the next turn.
        let started = tokio::time::Instant::now();
        let mut ended = futures_util::stream::iter(items)
            .take_while(move |_| std::future::ready(started.elapsed() < TURN_BUDGET))
            .map(|it| {
                let shared = shared.clone();
                let st = st.clone();
                async move {
                    let v = check(&st, &shared, &it).await;
                    (it, v)
                }
            })
            .buffer_unordered(CONCURRENCY)
            .ready_chunks(CONCURRENCY);
        let mut n = 0;
        while let Some(results) = ended.next().await {
            n += results.len();
            apply(&st, results, generation).await?;
        }
        Ok::<_, anyhow::Error>(n)
    });
    match job {
        Some(h) => h.await.map_err(|e| anyhow::anyhow!("dnssec job: {e}"))?,
        None => Ok(0),
    }
}

/// Runs turns until no item is due (tests).
pub async fn drain(state: &SharedState) -> anyhow::Result<usize> {
    let mut total = 0;
    for _ in 0..100 {
        let n = turn(state).await?;
        total += n;
        if n == 0 {
            break;
        }
    }
    Ok(total)
}

fn epoch(ts: Option<&str>) -> u64 {
    ts.and_then(crate::util::parse_ts)
        .map(|t| u64::try_from(t.as_second()).unwrap_or(0))
        .unwrap_or_else(|| u64::try_from(Timestamp::now().as_second()).unwrap_or(0))
}

/// Validates one item.
async fn check(state: &AppState, shared: &Shared, it: &Item) -> Verdict {
    let (Some(qname), Some(qtype)) = (
        validator::parse_name(&it.qname),
        validator::parse_qtype(&it.qtype),
    ) else {
        return Verdict {
            outcome: Some(Outcome::Indeterminate),
            proof: Some("the name or type can't be queried".into()),
            ..Verdict::default()
        };
    };
    let query = validator::question(&qname, qtype);
    match (it.kind, &it.wire, &it.answer_id) {
        (Kind::Answer, Some(wire), Some(id)) => {
            let t = epoch(it.received_at.as_deref());
            if let Some(v) = state.dnssec.memo.get(id, t) {
                return v;
            }
            let v = validator::validate(shared, Subject::Logged { query, wire }, t).await;
            state.dnssec.memo.put(shared.generation, id, &v);
            v
        }
        _ => {
            let t = u64::try_from(Timestamp::now().as_second()).unwrap_or(0);
            validator::validate(shared, Subject::Fallback { query }, t).await
        }
    }
}

/// The validator's upstream group: the `dnssec-validator` profile's (core.md §8).
fn validator_group(model: &crate::config::Model) -> Option<String> {
    model
        .profiles
        .get(crate::config::system::DNSSEC_PROFILE)
        .map(|p| p.edge.upstream.clone())
        .filter(|g| !g.is_empty())
}

/// Applies a turn's verdicts; nothing when a restore committed since the turn began (core.md
/// §2).
async fn apply(state: &SharedState, results: Vec<(Item, Verdict)>, generation: u64) -> anyhow::Result<()> {
    let model = state.analysis.model(state).await?;
    let group = validator_group(&model);
    let now = crate::util::now();
    let now_s = crate::util::ts(&now);
    let now_ms = now.as_millisecond();
    let settings = state.settings();
    let cc = settings.crosscheck.clone();
    let cc_from = crate::util::ts(&crate::util::window_start(now, cc.dedupe_window.as_duration()));
    let total_bytes = u64::from(settings.alerts.evidence_total_mib) * 1024 * 1024;
    let alerts = state.alerts.clone();
    let st = state.clone();
    let (new_alerts, ch) = state
        .db
        .write(move |c| {
            if !st.restore.is_current(generation) {
                return Ok((Vec::new(), Changes::default()));
            }
            let tx = c.transaction()?;
            let mut ch = Changes::default();
            let mut counts: Vec<Count> = Vec::new();
            // Results stored, by outcome (the `dnssec` UI event, api.md §7).
            let mut stored: BTreeMap<String, u64> = BTreeMap::new();
            let mut new_alerts: Vec<(i64, String)> = Vec::new();
            let mut cc_sizes = crosscheck::Sizes::load(&tx)?;
            // Items rescheduled, and negative cross-checks newly queued (the `dnssec_queued` UI
            // event, api.md §7: the queue view changes without a result).
            let mut changed = QueueChanges::default();
            for (it, v) in &results {
                let fallback = it.kind != Kind::Answer;
                if fallback && !v.unreachable {
                    counts.push((
                        "dnssec_fallback".into(),
                        crate::metrics::Labels::new(),
                        now_ms,
                        1.0,
                    ));
                }
                if v.unreachable {
                    let next = crate::util::ts(
                        &(now + jiff::SignedDuration::try_from(WAIT_UNREACHABLE).unwrap_or_default()),
                    );
                    // Its `next_at` moves on, which `GET dnssec/queue` shows and orders by: a
                    // change of the queue view (counted only when the item is still queued).
                    if queue::reschedule_in(&tx, it.id, it.attempts, &next)? {
                        changed.waiting += 1;
                    }
                    continue;
                }
                let attempts = it.attempts + i64::from(v.retry());
                if v.retry() && it.kind != Kind::Servfail && attempts < MAX_ATTEMPTS {
                    let next = crate::util::ts(
                        &(now + jiff::SignedDuration::try_from(backoff(attempts)).unwrap_or_default()),
                    );
                    if queue::reschedule_in(&tx, it.id, attempts, &next)? {
                        changed.retried += 1;
                    }
                    continue;
                }
                let outcome = if v.stale || v.failed.is_some() {
                    Outcome::Indeterminate
                } else {
                    v.outcome.unwrap_or(Outcome::Indeterminate)
                };
                let detail = json!({
                    "kind": it.kind.as_str(),
                    "ede": v.ede,
                    "proof": v.proof.as_deref().or(v.failed.as_deref()),
                    "zone": v.zone,
                    "group": group,
                    "rcode": v.rcode,
                    "attempts": attempts,
                    "requests": v.requests,
                    "reused": v.reused,
                    "edges": it.ctx.edges,
                    "clients": it.ctx.clients,
                    "groups": it.ctx.groups,
                });
                let Some(ctx) = queue::finish_in(&tx, it, outcome, &detail, &now_s)? else {
                    continue;
                };
                *stored.entry(outcome.as_str().to_string()).or_insert(0) += 1;
                counts.push((
                    "dnssec_results".into(),
                    crate::metrics::labels("", &[("outcome", outcome.as_str())]),
                    now_ms,
                    1.0,
                ));
                if fallback {
                    counts.extend(coverage_of(&ctx, "fallback", outcome.as_str()));
                } else {
                    counts.extend(coverage_of(&ctx, outcome.as_str(), ""));
                }
                if outcome == Outcome::Bogus {
                    if let Some(id) = raise_bogus_in(&alerts, &tx, it, v, &ctx, group.as_deref(), &mut ch)? {
                        new_alerts.push(id);
                    }
                    if let Some(key) = bogus_key(it, v) {
                        add_chain_evidence_in(&st.analysis.capture, &tx, &key, v, total_bytes)?;
                    }
                }
                // The negative cross-check takes Insecure answers that look like an upstream
                // blocking the name (core.md §8).
                if outcome == Outcome::Insecure
                    && cc.enabled
                    && cc.negative
                    && cc.resolver.is_some()
                    && candidate::negative_candidate(&ctx.rcode, &it.qtype, ctx.nodata)
                {
                    let res = crosscheck::admit_negative_in(&tx, it, &ctx, &now_s, &cc_from, &mut cc_sizes)?;
                    if res == crosscheck::Admitted::Dropped {
                        counts.push(crosscheck::count("negative", "dropped"));
                    }
                    if res == crosscheck::Admitted::Queued {
                        changed.crosscheck += 1;
                    }
                }
            }
            // The counts commit with the results (README §2 Restarts).
            crate::metrics::outbox::queue_in(&tx, &counts, &st.clock)?;
            tx.commit()?;
            alerts.committed(&ch);
            // On the writer, right after the commit (`web::events` module docs).
            st.events.coalesced().dnssec(&stored);
            st.events.coalesced().dnssec_queued(&changed);
            Ok::<_, anyhow::Error>((new_alerts, ch))
        })
        .await?;
    state.alerts.announce(ch);
    flush_counts(state).await;
    start_evidence(state, generation, new_alerts);
    state.dnssec.crosscheck.wake();
    Ok(())
}

/// The zone a Bogus verdict keys on: the broken zone, else the name (core.md §8).
fn bogus_zone(it: &Item, v: &Verdict) -> String {
    v.zone
        .clone()
        .unwrap_or_else(|| it.qname.trim_end_matches('.').to_ascii_lowercase())
}

fn bogus_key(it: &Item, v: &Verdict) -> Option<String> {
    let z = bogus_zone(it, v);
    (!z.is_empty()).then(|| format!("dnssec_bogus:{z}"))
}

/// The text of an RFC 8914 code.
pub fn ede_text(code: u16) -> &'static str {
    match code {
        1 => "Unsupported DNSKEY Algorithm",
        2 => "Unsupported DS Digest Type",
        6 => "DNSSEC Bogus",
        7 => "Signature Expired",
        8 => "Signature Not Yet Valid",
        9 => "DNSKEY Missing",
        10 => "RRSIGs Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        _ => "Other",
    }
}

/// Adds what `ctx` gathered to the alert's entry for (`qname`, `qtype`), or a new entry while
/// the alert lists fewer than [`MAX_ALERT_NAMES`]: its edges, clients and groups, and who
/// resolved it (each edge and client with its own group). Returns true when anything changed.
fn merge_name(names: &mut Vec<Value>, qname: &str, qtype: &str, kind: Kind, ctx: &Context) -> bool {
    let uses: Vec<Value> = ctx
        .records
        .iter()
        .map(|r| json!({"edge": r.edge, "client": r.client, "group": r.group}))
        .collect();
    let at = names.iter().position(|n| {
        n.get("name").and_then(Value::as_str) == Some(qname)
            && n.get("qtype").and_then(Value::as_str) == Some(qtype)
    });
    let Some(i) = at else {
        if names.len() >= MAX_ALERT_NAMES {
            return false;
        }
        names.push(json!({
            "name": qname,
            "qtype": qtype,
            "kind": kind.as_str(),
            "edges": ctx.edges,
            "clients": ctx.clients,
            "groups": ctx.groups,
            "resolved_by": uses,
        }));
        return true;
    };
    let Some(o) = names.get_mut(i).and_then(Value::as_object_mut) else {
        return false;
    };
    let mut changed = false;
    for (field, add) in [
        ("edges", &ctx.edges),
        ("clients", &ctx.clients),
        ("groups", &ctx.groups),
    ] {
        let mut list: Vec<Value> = o
            .get(field)
            .and_then(|x| x.as_array().cloned())
            .unwrap_or_default();
        for a in add {
            let a = Value::String(a.clone());
            if list.len() < queue::MAX_NAMED && !list.contains(&a) {
                list.push(a);
                changed = true;
            }
        }
        o.insert(field.into(), Value::Array(list));
    }
    let mut list = o
        .get("resolved_by")
        .and_then(|x| x.as_array().cloned())
        .unwrap_or_default();
    for u in uses {
        if list.len() < 50 && !list.contains(&u) {
            list.push(u);
            changed = true;
        }
    }
    o.insert("resolved_by".into(), Value::Array(list));
    changed
}

/// Every edge the alert's names list, sorted.
fn name_edges(names: &[Value]) -> Vec<String> {
    let mut e: Vec<String> = names
        .iter()
        .flat_map(|n| {
            n.get("edges")
                .and_then(|x| x.as_array().cloned())
                .unwrap_or_default()
        })
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect();
    e.sort();
    e.dedup();
    e
}

/// A record that takes a known Bogus result (core.md §8: "a record that shares another's check
/// takes that check's result") joins that result's `dnssec_bogus` alert: its edge, client and
/// upstream group go under the name, as when a record joins a queued item, so the alert names
/// every client that resolved the name. An open alert isn't raised again (the verdict isn't new);
/// a resolved one is (core.md §9 Dedupe: the same key reopens a resolved alert), and a deleted
/// one is raised anew, from the result's verdict. Returns the alert's id and zone when its
/// evidence capture should start.
#[expect(
    clippy::too_many_arguments,
    reason = "one Bogus result joined to its alert in the caller's transaction"
)]
fn join_bogus_in(
    alerts: &crate::alerts::Alerts,
    tx: &rusqlite::Transaction<'_>,
    result_id: i64,
    qname: &str,
    qtype: &str,
    kind: Kind,
    rec: &RecRef,
    group: Option<&str>,
    ch: &mut Changes,
) -> anyhow::Result<Option<(i64, String)>> {
    let Some(detail) = queue::result_detail_in(tx, result_id)? else {
        return Ok(None);
    };
    let zone = detail
        .get("zone")
        .and_then(Value::as_str)
        .filter(|z| !z.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| qname.trim_end_matches('.').to_ascii_lowercase());
    if zone.is_empty() {
        return Ok(None);
    }
    let key = format!("dnssec_bogus:{zone}");
    let old: Option<(String, String)> = tx
        .query_row(
            "SELECT details_json, state FROM alerts WHERE dedupe_key = ?1",
            [&key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let mut ctx = Context::default();
    ctx.join(rec, 0);
    match old {
        Some((details, state)) if state == "open" => {
            let Ok(mut details) = serde_json::from_str::<Value>(&details) else {
                return Ok(None);
            };
            let Some(mut names) = details.get("names").and_then(|n| n.as_array().cloned()) else {
                return Ok(None); // a truncated alert keeps what it has
            };
            if !merge_name(&mut names, qname, qtype, kind, &ctx) {
                return Ok(None);
            }
            let edges = name_edges(&names);
            if let Some(o) = details.as_object_mut() {
                o.insert("names".into(), Value::Array(names));
                o.insert("edges".into(), json!(edges));
            }
            alerts.update_details_in(tx, &key, &details, &edges, ch)?;
            Ok(None)
        }
        _ => {
            let ede = detail
                .get("ede")
                .and_then(Value::as_u64)
                .and_then(|e| u16::try_from(e).ok());
            let proof = detail.get("proof").and_then(Value::as_str).map(str::to_string);
            let group = detail.get("group").and_then(Value::as_str).or(group);
            let b = Bogus {
                zone,
                ede,
                proof,
                kind,
                qname,
                qtype,
            };
            raise_bogus_with(alerts, tx, &b, &ctx, group, ch)
        }
    }
}

/// What a `dnssec_bogus` raise names about the verdict.
struct Bogus<'a> {
    zone: String,
    ede: Option<u16>,
    proof: Option<String>,
    kind: Kind,
    qname: &'a str,
    qtype: &'a str,
}

/// Raises `dnssec_bogus` for one Bogus verdict (one alert per broken zone; core.md §8, §9).
/// Returns the alert's id and zone when its evidence capture should start.
fn raise_bogus_in(
    alerts: &crate::alerts::Alerts,
    tx: &rusqlite::Transaction<'_>,
    it: &Item,
    v: &Verdict,
    ctx: &Context,
    group: Option<&str>,
    ch: &mut Changes,
) -> anyhow::Result<Option<(i64, String)>> {
    if bogus_key(it, v).is_none() {
        return Ok(None);
    }
    let b = Bogus {
        zone: bogus_zone(it, v),
        ede: v.ede,
        proof: v.proof.clone(),
        kind: it.kind,
        qname: &it.qname,
        qtype: &it.qtype,
    };
    raise_bogus_with(alerts, tx, &b, ctx, group, ch)
}

/// [`raise_bogus_in`] from the verdict's parts (a validation's, or a stored result's).
fn raise_bogus_with(
    alerts: &crate::alerts::Alerts,
    tx: &rusqlite::Transaction<'_>,
    b: &Bogus<'_>,
    ctx: &Context,
    group: Option<&str>,
    ch: &mut Changes,
) -> anyhow::Result<Option<(i64, String)>> {
    let zone = b.zone.clone();
    let key = format!("dnssec_bogus:{zone}");
    // The names the alert lists, with their edges and clients, each with its own group.
    let old: Option<String> = tx
        .query_row(
            "SELECT details_json FROM alerts WHERE dedupe_key = ?1",
            [&key],
            |r| r.get(0),
        )
        .optional()?;
    let mut names: Vec<Value> = old
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|d| d.get("names").and_then(|n| n.as_array().cloned()))
        .unwrap_or_default();
    merge_name(&mut names, b.qname, b.qtype, b.kind, ctx);
    let edges = name_edges(&names);
    let details = json!({
        "zone": zone,
        "ede": b.ede,
        "ede_text": b.ede.map(ede_text),
        "proof": b.proof,
        "validator_group": group,
        "check": if b.kind == Kind::Answer { "logged answer, with the chain from the validator group's view" } else { "the validator group's view (core's own query)" },
        "names": names,
        "edges": edges,
    });
    let title = format!(
        "DNSSEC validation failed for {}{}",
        crate::util::sanitize_for_message(&zone, 128),
        b.ede
            .map(|c| format!(" (EDE {c} {})", ede_text(c)))
            .unwrap_or_default()
    );
    // The alert's `edge` (core.md §9 record) while one edge's records raised it, none once
    // several did; keyed on the zone, so it takes no per-edge share.
    let spec = RaiseSpec::new("dnssec_bogus", Severity::Critical, key, title, details).seen_on_edges(&edges);
    // The evidence rule (records under the zone) goes in with the raise (core.md §9).
    let rule = crate::logs::evidence::EvidenceRule {
        domain: zone.clone(),
        ..Default::default()
    };
    Ok(
        crate::logs::evidence::raise_security_with_rule_in(alerts, tx, &spec, &rule, ch)?
            .map(|id| (id, zone)),
    )
}

/// Keeps the validator's DNSKEY and DS answers as the alert's evidence (source `validator`),
/// each charged to the shared evidence budget (core.md §9 `alerts.evidence_total_mib`).
fn add_chain_evidence_in(
    cap: &crate::logs::evidence::Capture,
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    v: &Verdict,
    total: u64,
) -> rusqlite::Result<()> {
    let Some(id): Option<i64> = tx
        .query_row("SELECT id FROM alerts WHERE dedupe_key = ?1", [key], |r| r.get(0))
        .optional()?
    else {
        return Ok(());
    };
    for a in &v.chain {
        let aid = format!(
            "{}:{}:{}",
            a.qtype.to_ascii_lowercase(),
            a.qname.trim_end_matches('.'),
            &blake3::hash(&a.wire).to_hex()[..16]
        );
        if !cap.add_answer_in(tx, id, &aid, "validator", &a.wire, total)? {
            break;
        }
    }
    Ok(())
}

/// Drops items older than the retention window (core.md §8), counting their records `dropped`
/// (the counts commit with the drop, README §2 Restarts).
async fn drop_old(state: &SharedState) -> anyhow::Result<()> {
    let window = state.settings().retention.query_logs.as_duration();
    let now = crate::util::now();
    let cutoff = crate::util::ts(&crate::util::window_start(now, window));
    let clock = state.clock.clone();
    let coalesced = state.events.coalesced().clone();
    let dropped = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let items = queue::take_old_in(&tx, &cutoff, 1000)?;
            // Admission keys a stop left behind: past the window their partition is gone, so
            // the record can't be analysed again.
            tx.execute("DELETE FROM dnssec_admitted WHERE ts < ?1", [&cutoff])?;
            let mut counts: Vec<Count> = Vec::new();
            for it in &items {
                counts.extend(coverage_of(&it.ctx, "dropped", ""));
                counts.push((
                    "dnssec_dropped".into(),
                    crate::metrics::labels("", &[("reason", "too_old")]),
                    now.as_millisecond(),
                    1.0,
                ));
            }
            crate::metrics::outbox::queue_in(&tx, &counts, &clock)?;
            tx.commit()?;
            // On the writer, right after the commit (`web::events` module docs).
            coalesced.dnssec_queued(&QueueChanges {
                dropped: u64::try_from(items.len()).unwrap_or(u64::MAX),
                ..QueueChanges::default()
            });
            Ok::<_, anyhow::Error>(items.len())
        })
        .await?;
    if dropped == 0 {
        return Ok(());
    }
    tracing::info!(
        items = dropped,
        "DNSSEC queue items past the retention window dropped"
    );
    flush_counts(state).await;
    Ok(())
}

/// `dnssec_unavailable` (core.md §8, §9): candidates wait and none is validated. The condition
/// holds since the later of the oldest waiting item's admission and the last validation: a
/// Secure, Insecure or Bogus result (an Indeterminate one, such as a SERVFAIL candidate whose
/// query the edge refused, validated nothing). It survives restarts and clears when the queue is
/// empty; it waits for a synchronised clock (README §2 Clocks).
pub async fn unavailable_check(state: &SharedState) -> anyhow::Result<()> {
    if !state.clock.synced() {
        return Ok(());
    }
    // Items admitted before the clock was synchronised are stamped first: their stamps then
    // were the unsynchronised clock's.
    restamp(state).await?;
    let enabled = state.settings().dnssec.enabled;
    let since = state
        .db
        .read(|c| {
            let oldest: Option<String> = c.query_row(
                "SELECT min(first_seen) FROM dnssec_queue WHERE stamped = 1",
                [],
                |r| r.get(0),
            )?;
            let last: Option<String> = c.query_row(
                "SELECT max(at) FROM dnssec_results WHERE outcome IN ('secure', 'insecure', 'bogus')",
                [],
                |r| r.get(0),
            )?;
            Ok::<_, anyhow::Error>((oldest, last))
        })
        .await?;
    let now = crate::util::now();
    let held: Option<Timestamp> = match since {
        (Some(oldest), last) if enabled => {
            let o = crate::util::parse_ts(&oldest);
            let l = last.as_deref().and_then(crate::util::parse_ts);
            match (o, l) {
                (Some(o), Some(l)) => Some(o.max(l)),
                (Some(o), None) => Some(o),
                _ => None,
            }
        }
        _ => None,
    };
    let waiting = state
        .db
        .read(|c| {
            let n: i64 = c.query_row("SELECT count(*) FROM dnssec_queue", [], |r| r.get(0))?;
            Ok::<_, anyhow::Error>(n)
        })
        .await?;
    let spec = RaiseSpec::new(
        "dnssec_unavailable",
        Severity::Warning,
        "dnssec_unavailable",
        "DNSSEC validation is stalled: candidates wait and none is validated",
        json!({
            "waiting": waiting,
            "hint": "Validation fetches chains through an edge DoH listener under the dnssec-validator profile. Check that an edge with a DoH listener is connected and that dnssec.source_ips is the address the edge sees core's traffic come from.",
        }),
    );
    let threshold = state.settings().alerts.threshold("dnssec_unavailable");
    state.alerts.condition(spec, held, threshold, now).await?;
    Ok(())
}

/// Counts for the UI and tests.
pub async fn queue_depth(state: &AppState) -> anyhow::Result<i64> {
    state
        .db
        .read(|c| Ok::<_, anyhow::Error>(c.query_row("SELECT count(*) FROM dnssec_queue", [], |r| r.get(0))?))
        .await
}

/// Results by outcome (tests).
pub async fn results_by_outcome(state: &AppState) -> anyhow::Result<BTreeMap<String, i64>> {
    state
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT outcome, count(*) FROM dnssec_results GROUP BY outcome")?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
            Ok::<_, anyhow::Error>(rows.collect::<rusqlite::Result<_>>()?)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_thirty_minutes() {
        for (a, lo, hi) in [(1, 24, 36), (2, 48, 72), (10, 1440, 2160), (40, 1440, 2160)] {
            let b = backoff(a).as_secs();
            assert!((lo..=hi).contains(&b), "attempt {a}: {b}");
        }
    }

    #[test]
    fn ede_texts() {
        assert_eq!(ede_text(7), "Signature Expired");
        assert_eq!(ede_text(9), "DNSKEY Missing");
    }
}
