//! What the edges' logs give async lookups (core.md §7), applied by log ingest in one `core.db`
//! transaction before the batch is acked ([`apply`]; README §2 Restarts), so nothing an acked
//! batch carried is lost:
//!
//! - **Verdicts:** every `lookups[]` item with `obtained_at` (a provider's answer, a cache hit
//!   included) and every `lookup` record (a late answer) goes into `lookup_verdicts` under the
//!   store's rules ([`super::store`]: the generation is checked against the provider's row in this
//!   transaction), and each Block into `lookup_blocks`. `obtained_at` is clamped to core's clock.
//! - **Source (a), retries:** a `lookups[]` item with `retry: true` queues a retry while the
//!   provider's `retries` is on; its first attempt waits `async_timeout_ms` + 5 s after ingest.
//! - **Source (b), async attachments:** a query allowed at ladder step 3 or later (not forwarded,
//!   not let through by a temporary allow or an allow bundle) in a profile whose attachment for a
//!   provider is `async`, of a type in the provider's `scope.qtypes`, queues a lookup. Whether the
//!   name is within the attachment's and the provider's scope bundles, and whether the profile
//!   still attaches the provider, is checked before every call ([`super::queue::process`]), so
//!   an out-of-scope name never reaches the provider. Async attachments never block.
//! - **Source (c), re-checks:** the same answered queries, for every provider the profile attaches
//!   (`sync` or `async`) with `recheck` on, add re-check deadlines ([`super::queue::admit`]).
//!   `alert_lookup_providers` never adds a provider to a re-check.
//! - **Answers against Blocks:** a real answer (allowed, or rewritten with records) in a profile
//!   that alerts on providers is checked against their Blocks already checked in the window
//!   ([`super::answered`]); a match raises `category_answered`. A batch's answers are grouped by
//!   name: one check per (provider, name), raised once for the answers it found that the alert
//!   hasn't counted yet (the count goes up by that many; a Block's scan may have counted one
//!   already, [`super::answered::count_new`]), so many answers for one name never crowd out
//!   another's.
//!   At most [`MAX_ANSWER_NAMES`] names are checked per batch; the answers of names past it are
//!   dropped and counted (`lookup_dropped{reason=answer_checks}`). A new alert's evidence rule,
//!   with its backfill, is stored in the same transaction as the alert
//!   ([`crate::logs::evidence::raise_security_with_rule_in`]; core.md §9 Evidence), so a stop
//!   right after the commit still copies its evidence.
//!
//! **Once per record:** re-check deadlines and answer checks are applied once for each `q` record.
//! Which records' effects are applied is kept in `lookup_ingested` (seq ranges per edge and boot),
//! written in the same transaction as the effects. A batch whose lookup step failed after its
//! records reached their partitions is resent by the edge as duplicates; their effects are
//! applied then, exactly once (README §2 Restarts), and a resend of an applied batch adds nothing.
//! Delivery is at-least-once (edge.md §11), so a boot's row is kept as long as its records can be
//! resent: until it is older than the log retention window (retention; older records are dropped
//! at decode). A batch's own boots are never evicted; only an edge with more than
//! [`MAX_LEDGER_BOOTS`] boots in the window loses its oldest rows early.
//! Everything else is idempotent (later `obtained_at` wins, Blocks are unique, the queue dedups).
//!
//! **Clocks** (README §2): with the wall clock not yet synchronised, no verdict or Block is
//! discarded for its age ([`super::store::RecordClock`]); an edge's `obtained_at` is clamped to
//! core's clock at receipt like every received timestamp (`lookup` records at decode, `lookups[]`
//! items here, in the ingest request before the ack). A first lookup queued then is due from its
//! record's time rather than core's clock (a boot clock days ahead would otherwise hold it for
//! days after the correction); the queue calls nothing before the clock is synchronised.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use jiff::Timestamp;
use picket_api::edge_config::LookupMode;
use picket_api::logs::{Decision, LookupItem, LookupRecord, LookupVerdict, MatchKind, QueryRecord};
use picket_bundle::verdict::VerdictKind;
use serde_json::Value;

use super::queue::{AdmitKind, Admitted, NeedKind};
use super::store::{self, ProviderView};
use crate::alerts::Changes;
use crate::config::Model;
use crate::state::AppState;

/// Distinct names whose answers one batch checks against Blocks (README §2 Bounded; module docs).
/// Policy choice: the spec gives no number; a batch holds at most a few thousand records.
pub const MAX_ANSWER_NAMES: usize = 1000;
/// Seq ranges kept per (edge, boot) in `lookup_ingested`; past it the lowest two merge (a record
/// in the gap between them then counts as applied). Policy choice.
pub const MAX_RANGES: usize = 256;
/// Boots one edge keeps in `lookup_ingested` (README §2 Bounded: boot ids come from the edge).
/// A batch holds at most 1,000 records (api.md §5), so its own boots always fit and are never
/// evicted; past the cap the rows written longest ago go first. A healthy edge has a few boots in
/// the log retention window, so rows leave by age (retention) unless an edge crash-loops through
/// thousands. Policy choice: the spec gives no number.
pub const MAX_LEDGER_BOOTS: i64 = 4096;

/// What lookups need of one `q` record.
#[derive(Clone, Debug)]
pub struct QueryInfo {
    pub ts: Timestamp,
    pub boot: String,
    pub seq: u64,
    pub profile: Option<String>,
    pub qname: String,
    pub qtype: String,
    pub decision: Decision,
    pub rcode: String,
    pub step: Option<u8>,
    pub kind: Option<MatchKind>,
    pub client: String,
    pub device: Option<String>,
    /// The reply carried records (preview answers, targets, a CNAME chain, or a `response`).
    pub has_records: bool,
    pub lookups: Vec<LookupItem>,
    /// Stored now (not a duplicate of an earlier batch's record in its partition). Informational:
    /// whether the record's once-only effects are applied is `lookup_ingested`'s to say (module
    /// docs), since a duplicate may be the resend of a batch whose lookup step failed.
    pub stored: bool,
}

impl QueryInfo {
    pub fn of(q: &QueryRecord, has_response: bool) -> Self {
        Self {
            ts: q.h.ts,
            boot: q.h.boot.clone(),
            seq: q.h.seq,
            profile: q.profile.clone(),
            qname: q.qname.clone(),
            qtype: q.qtype.clone(),
            decision: q.decision,
            rcode: q.rcode.clone(),
            step: q.reason.as_ref().map(|r| r.step),
            kind: q.reason.as_ref().map(|r| r.kind),
            client: q.client.clone(),
            device: q.device.clone(),
            has_records: has_response
                || !q.answers.is_empty()
                || !q.targets.is_empty()
                || !q.cname.is_empty(),
            lookups: q.lookups.clone(),
            stored: false,
        }
    }

    /// Allowed at ladder step 3 or later: not forwarded or a local name (step 0), not a temporary
    /// allow (1) or an allow bundle (2). No reason means the default allow (step 6).
    pub fn allowed_late(&self) -> bool {
        self.decision == Decision::Allow
            && !matches!(
                self.kind,
                Some(MatchKind::Forward | MatchKind::Local | MatchKind::TempAllow)
            )
            && self.step.is_none_or(|s| s >= 3)
    }

    /// A real answer (core.md §7): allowed, or rewritten with records, with NOERROR.
    pub fn real_answer(&self) -> bool {
        self.rcode.eq_ignore_ascii_case("NOERROR")
            && match self.decision {
                Decision::Allow => true,
                Decision::Rewrite => self.has_records,
                _ => false,
            }
    }
}

fn verdict_of(v: LookupVerdict) -> Option<VerdictKind> {
    match v {
        LookupVerdict::Block => Some(VerdictKind::Block),
        LookupVerdict::Clean => Some(VerdictKind::Clean),
        LookupVerdict::Unknown => Some(VerdictKind::Unknown),
        LookupVerdict::Timeout | LookupVerdict::Error | LookupVerdict::Rejected => None,
    }
}

/// One verdict from the log.
struct LoggedVerdict {
    provider: String,
    name: String,
    verdict: VerdictKind,
    score: Option<f32>,
    reason: Option<String>,
    detail: Option<Value>,
    obtained_at: Timestamp,
    generation: String,
}

/// One queue admission, prepared outside the transaction.
struct Admission {
    provider: String,
    name: String,
    kind: AdmitKind,
    profile: Option<String>,
    asker: Option<String>,
    /// The record (its index in the batch) for an effect applied once per record (re-checks);
    /// none for an idempotent one.
    once: Option<usize>,
}

/// One real answer to check against Blocks, applied once per record.
struct AnswerCheck {
    /// The record's index in the batch.
    idx: usize,
    name: String,
    /// The record's boot, seq and time: how an alert counts it once ([`super::answered`]).
    boot: String,
    seq: i64,
    ts: String,
    /// The providers whose Blocks alert for the answer's profile.
    alerting: Vec<String>,
}

/// Which `q` records' once-only effects are applied ([`apply`]; `lookup_ingested`): sorted,
/// disjoint, inclusive seq ranges per boot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub ranges: BTreeMap<String, Vec<(u64, u64)>>,
}

impl Ledger {
    /// True when (boot, seq)'s effects are applied.
    pub fn contains(&self, boot: &str, seq: u64) -> bool {
        self.ranges.get(boot).is_some_and(|r| {
            let i = r.partition_point(|(_, hi)| *hi < seq);
            r.get(i).is_some_and(|(lo, _)| *lo <= seq)
        })
    }

    /// Adds seqs of `boot`, merging adjacent ranges; past [`MAX_RANGES`] the lowest merge.
    pub fn add(&mut self, boot: &str, seqs: impl IntoIterator<Item = u64>) {
        let r = self.ranges.entry(boot.to_string()).or_default();
        r.extend(seqs.into_iter().map(|s| (s, s)));
        r.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(r.len());
        for (lo, hi) in r.drain(..) {
            match out.last_mut() {
                Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
                _ => out.push((lo, hi)),
            }
        }
        while out.len() > MAX_RANGES {
            let second = out.remove(1);
            out[0].1 = out[0].1.max(second.1);
        }
        *r = out;
    }
}

/// Reads the ledger rows of `edge`'s `boots`.
fn read_ledger(c: &rusqlite::Connection, edge: &str, boots: &BTreeSet<&str>) -> rusqlite::Result<Ledger> {
    let mut l = Ledger::default();
    let mut st =
        c.prepare_cached("SELECT ranges_json FROM lookup_ingested WHERE edge_id = ?1 AND boot = ?2")?;
    for b in boots {
        let row: Option<String> =
            rusqlite::OptionalExtension::optional(st.query_row(rusqlite::params![edge, b], |r| r.get(0)))?;
        if let Some(j) = row {
            let v: Vec<(u64, u64)> = serde_json::from_str(&j).unwrap_or_default();
            l.ranges.insert((*b).to_string(), v);
        }
    }
    Ok(l)
}

/// Writes the ledger rows of the boots in `l` (the batch's boots) back. When that adds a row, the
/// edge keeps at most [`MAX_LEDGER_BOOTS`]: the batch's own boots, then the others written most
/// recently.
fn write_ledger(tx: &rusqlite::Transaction<'_>, edge: &str, l: &Ledger, now: &str) -> rusqlite::Result<()> {
    let mut added = false;
    for (boot, ranges) in &l.ranges {
        let json = serde_json::to_string(ranges).unwrap_or_else(|_| "[]".into());
        let n = tx.execute(
            "UPDATE lookup_ingested SET ranges_json = ?3, updated_at = ?4 WHERE edge_id = ?1 AND boot = ?2",
            rusqlite::params![edge, boot, json, now],
        )?;
        if n == 0 {
            tx.execute(
                "INSERT INTO lookup_ingested(edge_id, boot, ranges_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![edge, boot, json, now],
            )?;
            added = true;
        }
    }
    if added {
        let mine: Vec<&str> = l.ranges.keys().map(String::as_str).collect();
        let others = MAX_LEDGER_BOOTS
            .saturating_sub(i64::try_from(mine.len()).unwrap_or(i64::MAX))
            .max(0);
        tx.execute(
            "DELETE FROM lookup_ingested WHERE edge_id = ?1 AND boot NOT IN (SELECT value FROM json_each(?3))
               AND boot NOT IN (SELECT boot FROM lookup_ingested WHERE edge_id = ?1
                 AND boot NOT IN (SELECT value FROM json_each(?3)) ORDER BY updated_at DESC, boot LIMIT ?2)",
            rusqlite::params![
                edge,
                others,
                serde_json::to_string(&mine).unwrap_or_else(|_| "[]".into())
            ],
        )?;
    }
    Ok(())
}

/// What [`apply`] did, for metrics and tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub verdicts: usize,
    pub blocks: usize,
    pub queued: usize,
    pub settled: usize,
    pub dropped: usize,
    pub alerts: usize,
}

/// Collects the verdicts, admissions and answer checks of one batch. `synced`: core's wall clock
/// is synchronised (module docs, Clocks).
fn prepare(
    model: &Model,
    queries: &[QueryInfo],
    records: &[LookupRecord],
    now: Timestamp,
    synced: bool,
    edge: &str,
) -> (Vec<LoggedVerdict>, Vec<Admission>) {
    let mut verdicts = Vec::new();
    let mut admissions = Vec::new();
    let clamp = |t: Timestamp| picket_api::time::clamp_to_now(t, now);
    for (idx, q) in queries.iter().enumerate() {
        let asker = Some(format!("{edge}/{}", q.client));
        // When a first lookup is due from: its ingest, or, before the clock is synchronised, its
        // record's time (already clamped to core's clock).
        let base = if synced { now } else { q.ts.min(now) };
        for l in &q.lookups {
            if let (Some(at), Some(v)) = (l.obtained_at, verdict_of(l.verdict))
                && model.lookup_providers.contains_key(&l.provider)
            {
                verdicts.push(LoggedVerdict {
                    provider: l.provider.clone(),
                    name: q.qname.clone(),
                    verdict: v,
                    score: l.score,
                    reason: l.reason.clone(),
                    detail: l.detail.clone(),
                    obtained_at: clamp(at),
                    generation: l.generation.clone(),
                });
            }
            if l.retry
                && let Some(p) = model.lookup_providers.get(&l.provider)
                && p.settings.retries
            {
                let wait = std::time::Duration::from_millis(u64::from(p.settings.async_timeout_ms))
                    + super::queue::RETRY_GRACE;
                admissions.push(Admission {
                    provider: l.provider.clone(),
                    name: q.qname.clone(),
                    kind: AdmitKind::Need {
                        kind: NeedKind::Retry,
                        due_at: base
                            + jiff::SignedDuration::try_from(wait)
                                .unwrap_or(jiff::SignedDuration::from_secs(15)),
                    },
                    profile: q.profile.clone(),
                    asker: asker.clone(),
                    once: None,
                });
            }
        }
        if !q.allowed_late() {
            continue;
        }
        let Some(prof) = q.profile.as_ref().and_then(|p| model.profiles.get(p)) else {
            continue;
        };
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for att in &prof.edge.lookup_providers {
            if !seen.insert(att.provider.as_str()) {
                continue;
            }
            let Some(p) = model.lookup_providers.get(&att.provider) else {
                continue;
            };
            if !super::scope::calls_for(p, &q.qtype) {
                continue;
            }
            if att.mode == LookupMode::Async {
                admissions.push(Admission {
                    provider: att.provider.clone(),
                    name: q.qname.clone(),
                    kind: AdmitKind::Need {
                        kind: NeedKind::Async,
                        due_at: base,
                    },
                    profile: q.profile.clone(),
                    asker: asker.clone(),
                    once: None,
                });
            }
            // Re-check deadlines are added once per record (module docs: the ledger decides).
            let deadlines = super::queue::recheck_deadlines(p, q.ts);
            if !deadlines.is_empty() {
                admissions.push(Admission {
                    provider: att.provider.clone(),
                    name: q.qname.clone(),
                    kind: AdmitKind::Recheck {
                        answered_at: q.ts,
                        deadlines,
                    },
                    profile: q.profile.clone(),
                    asker: asker.clone(),
                    once: Some(idx),
                });
            }
        }
    }
    for r in records {
        if let (Some(at), Some(v)) = (r.obtained_at, verdict_of(r.verdict))
            && model.lookup_providers.contains_key(&r.provider)
        {
            verdicts.push(LoggedVerdict {
                provider: r.provider.clone(),
                name: r.qname.clone(),
                verdict: v,
                score: r.score,
                reason: r.reason.clone(),
                detail: r.detail.clone(),
                obtained_at: clamp(at),
                generation: r.generation.clone(),
            });
        }
    }
    (verdicts, admissions)
}

/// Applies one batch's lookup work (module docs). `queries` are the batch's decoded `q` records
/// (duplicates included); `records` its `lookup` records.
pub async fn apply(
    state: &AppState,
    edge: &str,
    queries: Vec<QueryInfo>,
    records: Vec<LookupRecord>,
) -> anyhow::Result<Applied> {
    let model = state.lookups.model();
    if model.lookup_providers.is_empty() {
        return Ok(Applied::default());
    }
    let now = crate::util::now();
    let synced = state.clock.synced();
    let (verdicts, admissions) = prepare(&model, &queries, &records, now, synced, edge);
    // Answers to check against Blocks: real answers in profiles alerting on providers (applied
    // once per record: the ledger decides in the transaction).
    let mut answers: Vec<AnswerCheck> = Vec::new();
    for (idx, q) in queries.iter().enumerate().filter(|(_, q)| q.real_answer()) {
        let Some(prof) = q.profile.as_ref().and_then(|p| model.profiles.get(p)) else {
            continue;
        };
        let alerting = super::alert_lookup_providers(&model, prof);
        if !alerting.is_empty() {
            answers.push(AnswerCheck {
                idx,
                name: q.qname.clone(),
                boot: q.boot.clone(),
                seq: i64::try_from(q.seq).unwrap_or(i64::MAX),
                ts: crate::util::ts(&q.ts),
                alerting,
            });
        }
    }
    if verdicts.is_empty() && admissions.is_empty() && answers.is_empty() {
        return Ok(Applied::default());
    }
    // Every q record of the batch, for the ledger, and whether it is the first of its (boot, seq)
    // in the batch (a batch may repeat a record).
    let mut seqs: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut seen: HashSet<(&str, u64)> = HashSet::new();
    let keys: Vec<(String, u64, bool)> = queries
        .iter()
        .map(|q| {
            seqs.entry(q.boot.clone()).or_default().push(q.seq);
            (q.boot.clone(), q.seq, seen.insert((q.boot.as_str(), q.seq)))
        })
        .collect();
    let settings = state.settings();
    let clock = store::RecordClock::now(synced, settings.retention.lookup_blocks.as_duration());
    let log_window = settings.retention.query_logs.as_duration();
    let since = crate::util::ts(&crate::util::window_start(now, log_window));
    let full = state.lookups.queue.full();
    let all_full = full.contains("*");
    let me = state.alerts.clone();
    let holds = state.lookups.scan_holds.clone();
    let edge_s = edge.to_string();
    let m2 = model.clone();
    let (applied, ch, admitted, blocks_changed, new_rules, dropped) = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let mut out = Applied::default();
            let mut admitted: Vec<(String, Admitted)> = Vec::new();
            let mut blocks_changed: BTreeSet<String> = BTreeSet::new();
            // Which records' once-only effects to apply now: the first of their (boot, seq) in the
            // batch, not applied by an earlier attempt (module docs).
            let boots: BTreeSet<&str> = seqs.keys().map(String::as_str).collect();
            let mut ledger = read_ledger(&tx, &edge_s, &boots)?;
            let once: Vec<bool> = keys
                .iter()
                .map(|(boot, seq, first)| *first && !ledger.contains(boot, *seq))
                .collect();
            let fresh = |idx: usize| once.get(idx).copied().unwrap_or(false);
            // The generation each provider has in this transaction (providers.md §4).
            let mut gens: BTreeMap<String, Option<String>> = BTreeMap::new();
            for v in &verdicts {
                let Some(p) = m2.lookup_providers.get(&v.provider) else {
                    continue;
                };
                let pv = ProviderView {
                    id: &v.provider,
                    generation: &p.cache_generation,
                    cache: &p.settings.cache,
                };
                let r = store::record(
                    &tx,
                    &pv,
                    &store::Incoming {
                        name: &v.name,
                        verdict: v.verdict,
                        score: v.score,
                        reason: v.reason.as_deref(),
                        detail: v.detail.as_ref(),
                        obtained_at: v.obtained_at,
                        generation: &v.generation,
                        source: store::Source::Edge(&edge_s),
                    },
                    &clock,
                )?;
                if r.changed {
                    out.verdicts += 1;
                }
                if r.new_block {
                    out.blocks += 1;
                }
                if r.changed && v.verdict == VerdictKind::Block {
                    blocks_changed.insert(v.provider.clone());
                }
            }
            for a in &admissions {
                if a.once.is_some_and(|i| !fresh(i)) {
                    continue;
                }
                let Some(p) = m2.lookup_providers.get(&a.provider) else {
                    continue;
                };
                let generation = match gens.get(&a.provider) {
                    Some(g) => g.clone(),
                    None => {
                        let g = store::current_generation(&tx, &a.provider)?;
                        gens.insert(a.provider.clone(), g.clone());
                        g
                    }
                };
                let Some(generation) = generation else { continue };
                let pv = ProviderView {
                    id: &a.provider,
                    generation: &generation,
                    cache: &p.settings.cache,
                };
                let r = super::queue::admit(
                    &tx,
                    &pv,
                    &a.name,
                    &a.kind,
                    a.profile.as_deref(),
                    a.asker.as_deref(),
                    all_full || full.contains(&a.provider),
                    now,
                )?;
                match r {
                    Admitted::Queued | Admitted::Merged => out.queued += 1,
                    Admitted::Settled => out.settled += 1,
                    Admitted::Full => out.dropped += 1,
                    Admitted::Unchanged => {}
                }
                admitted.push((a.provider.clone(), r));
            }
            // Answers grouped by name: the answers per (name, provider).
            let mut by_name: BTreeMap<&str, BTreeMap<&str, Vec<&AnswerCheck>>> = BTreeMap::new();
            let mut dropped: BTreeMap<String, u64> = BTreeMap::new();
            for a in &answers {
                if !fresh(a.idx) {
                    continue;
                }
                if !by_name.contains_key(a.name.as_str()) && by_name.len() >= MAX_ANSWER_NAMES {
                    for p in &a.alerting {
                        *dropped.entry(p.clone()).or_insert(0) += 1;
                    }
                    continue;
                }
                let counts = by_name.entry(a.name.as_str()).or_default();
                for p in &a.alerting {
                    counts.entry(p.as_str()).or_default().push(a);
                }
            }
            let mut ch = Changes::default();
            // Alerts that got their evidence rule (and backfill) in this transaction.
            let mut new_rules = 0usize;
            for (name, counts) in &by_name {
                let alerting: Vec<String> = counts.keys().map(|p| (*p).to_string()).collect();
                for b in super::answered::blocks_for_answer(&tx, name, &alerting, &since)? {
                    // Only answers the alert hasn't counted raise it (super::answered).
                    let found: Vec<super::answered::CountedAnswer<'_>> = counts
                        .get(b.provider.as_str())
                        .into_iter()
                        .flatten()
                        .map(|a| super::answered::CountedAnswer {
                            edge: &edge_s,
                            boot: &a.boot,
                            seq: a.seq,
                            ts: a.ts.clone(),
                        })
                        .collect();
                    let n = super::answered::count_new(&tx, &b.provider, &b.name, &found, &holds)?;
                    if n == 0 {
                        continue;
                    }
                    // The alert's `edge` (core.md §9 record): the edge whose answers raised it.
                    let spec = super::answered::spec(&m2, &b, n).seen_on_edge(&edge_s);
                    let rule = super::answered::evidence_rule(&m2, &b.provider, &b.name);
                    if crate::logs::evidence::raise_security_with_rule_in(&me, &tx, &spec, &rule, &mut ch)?
                        .is_some()
                    {
                        new_rules += 1;
                    }
                    out.alerts += 1;
                }
            }
            for (boot, s) in &seqs {
                ledger.add(boot, s.iter().copied());
            }
            write_ledger(&tx, &edge_s, &ledger, &crate::util::ts(&now))?;
            tx.commit()?;
            me.committed(&ch);
            Ok::<_, anyhow::Error>((out, ch, admitted, blocks_changed, new_rules, dropped))
        })
        .await?;
    state.alerts.announce(ch);
    if new_rules > 0 {
        // The backfills read the log window: the backfill worker runs them off the ack's path.
        crate::logs::evidence::wake_backfills(state);
    }
    let mut metrics = Vec::new();
    let mut woke = false;
    for (p, a) in admitted {
        super::queue::note_admitted(state, &p, a);
        match a {
            Admitted::Full => metrics.push((
                "lookup_dropped".to_string(),
                crate::metrics::labels("", &[("provider", &p), ("reason", "full")]),
                now.as_millisecond(),
                1.0,
            )),
            Admitted::Queued | Admitted::Merged => woke = true,
            _ => {}
        }
    }
    for (p, n) in dropped {
        metrics.push((
            "lookup_dropped".to_string(),
            crate::metrics::labels("", &[("provider", &p), ("reason", "answer_checks")]),
            now.as_millisecond(),
            n as f64,
        ));
    }
    state.metrics.count(&state.metrics_db, metrics).await;
    if woke {
        state.lookups.queue.wake.notify_one();
    }
    if applied.blocks > 0 {
        state.lookups.blocks_wake.notify_one();
    }
    for p in blocks_changed {
        state.lookups.sets.block_recorded(&p);
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_api::logs::Reason;

    fn q(decision: Decision, step: Option<u8>, kind: Option<MatchKind>) -> QueryInfo {
        QueryInfo {
            ts: crate::util::now(),
            boot: "b".into(),
            seq: 1,
            profile: Some("kids".into()),
            qname: "x.example".into(),
            qtype: "A".into(),
            decision,
            rcode: "NOERROR".into(),
            step,
            kind,
            client: "10.0.0.2".into(),
            device: None,
            has_records: false,
            lookups: vec![],
            stored: true,
        }
    }

    /// core.md §7 source (b): allowed at step 3 or later only.
    #[test]
    fn allowed_late_excludes_forward_temp_allow_and_allow_bundles() {
        assert!(q(Decision::Allow, None, None).allowed_late());
        assert!(q(Decision::Allow, Some(6), Some(MatchKind::Exact)).allowed_late());
        assert!(q(Decision::Allow, Some(3), Some(MatchKind::Exact)).allowed_late());
        assert!(!q(Decision::Allow, Some(0), Some(MatchKind::Forward)).allowed_late());
        assert!(!q(Decision::Allow, Some(1), Some(MatchKind::TempAllow)).allowed_late());
        assert!(!q(Decision::Allow, Some(2), Some(MatchKind::Exact)).allowed_late());
        assert!(!q(Decision::Block, Some(3), Some(MatchKind::Exact)).allowed_late());
        let _ = Reason::default();
    }

    /// core.md §7: a rewrite counts as a real answer only with records (a `$dnsrewrite` that
    /// returns only an rcode counts as a block).
    #[test]
    fn real_answers() {
        assert!(q(Decision::Allow, None, None).real_answer());
        let mut r = q(Decision::Rewrite, Some(3), Some(MatchKind::Rich));
        assert!(!r.real_answer());
        r.has_records = true;
        assert!(r.real_answer());
        r.rcode = "NXDOMAIN".into();
        assert!(!r.real_answer());
        assert!(!q(Decision::Block, Some(3), None).real_answer());
    }

    /// L5 (README §2 Restarts): the ledger of applied records merges adjacent seqs, answers
    /// membership by range, keeps boots apart and stays bounded (the lowest ranges merge).
    #[test]
    fn the_ledger_holds_applied_records_as_bounded_ranges() {
        let mut l = Ledger::default();
        l.add("b1", [3, 1, 2, 7, 8]);
        assert_eq!(l.ranges["b1"], vec![(1, 3), (7, 8)]);
        assert!(l.contains("b1", 2) && l.contains("b1", 8));
        assert!(!l.contains("b1", 5) && !l.contains("b1", 9) && !l.contains("b2", 2));
        l.add("b1", [4, 5, 6]);
        assert_eq!(l.ranges["b1"], vec![(1, 8)], "a filled gap merges");
        let mut big = Ledger::default();
        big.add("b1", (0..(MAX_RANGES as u64 + 10)).map(|i| i * 10));
        let r = &big.ranges["b1"];
        assert_eq!(r.len(), MAX_RANGES);
        assert_eq!(r[0], (0, 100), "the lowest ranges merged");
        assert!(big.contains("b1", 50), "a closed gap counts as applied");
        assert!(!big.contains("b1", 2005));
        assert!(big.contains("b1", 2000));
    }

    /// U4 (README §2 Restarts and Bounded; edge.md §11): past [`MAX_LEDGER_BOOTS`] an edge keeps
    /// the batch's own boots, then the others written most recently, even when older rows look
    /// newer (the clock went back since); another edge's rows aren't touched.
    #[test]
    fn the_ledger_never_evicts_the_batch_s_own_boots() {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let mut c = crate::db::open_connection(&opts, 1024).unwrap();
        let tx = c.transaction().unwrap();
        for i in 0..MAX_LEDGER_BOOTS {
            tx.execute(
                "INSERT INTO lookup_ingested(edge_id, boot, ranges_json, updated_at) VALUES ('e1', ?1, '[[1,1]]', ?2)",
                rusqlite::params![
                    format!("old{i:05}"),
                    format!("2099-01-01T{:02}:{:02}:{:02}.000000Z", i / 3600, (i / 60) % 60, i % 60)
                ],
            )
            .unwrap();
        }
        tx.execute(
            "INSERT INTO lookup_ingested(edge_id, boot, ranges_json, updated_at)
             VALUES ('e2', 'x', '[[1,1]]', '2000-01-01T00:00:00.000000Z')",
            [],
        )
        .unwrap();
        let mut l = Ledger::default();
        for b in ["new1", "new2", "new3"] {
            l.add(b, [1, 2]);
        }
        write_ledger(&tx, "e1", &l, "2026-11-24T00:00:00.000000Z").unwrap();
        let count = |sql: &str| -> i64 { tx.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(
            count("SELECT count(*) FROM lookup_ingested WHERE edge_id = 'e1'"),
            MAX_LEDGER_BOOTS
        );
        assert_eq!(
            count("SELECT count(*) FROM lookup_ingested WHERE boot IN ('new1', 'new2', 'new3')"),
            3,
            "the batch's boots stay"
        );
        assert_eq!(
            count("SELECT count(*) FROM lookup_ingested WHERE boot IN ('old00000', 'old00001', 'old00002')"),
            0,
            "the others written longest ago went"
        );
        assert_eq!(
            count("SELECT count(*) FROM lookup_ingested WHERE edge_id = 'e2'"),
            1
        );
        // A batch holds at most 1,000 records, so at most 1,000 boots: always within the cap.
        assert!(picket_api::logs::MAX_BATCH_RECORDS as i64 <= MAX_LEDGER_BOOTS);
        tx.commit().unwrap();
    }
}
