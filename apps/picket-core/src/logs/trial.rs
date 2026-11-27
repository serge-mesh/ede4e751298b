//! Trial bundles (core.md §6 "Trial bundles", §2, §12): each logged query its profile allowed,
//! or rewrote with records, at ladder step 3 or later (not forwarded, not let through by a
//! temporary allow or an allow bundle, per the record's `reason`) is checked once against the
//! profile's `trial_bundles` as they stand when core first checks it (edge configs don't carry
//! them), so a record still waiting for its first check when a bundle joins is checked against
//! it, and isn't checked again when the list changes (`trial_check`).
//!
//! - **Values:** the query name, and the CNAME targets, addresses and HTTPS/SVCB targets of the
//!   complete logged answer (the answer `answer_id` names, else `response`, else the preview).
//! - **Matching:** each trial bundle on its own, at its current head, as a block bundle is matched
//!   (its exceptions and `$badfilter` cancel its own blocks; rich rules as in attribution). Core
//!   replays the head's feed runs ([`super::replay`]), which decides as the head's compiled keys,
//!   IP runs and segments do (bundles.md §2 "Determinism": a build equals the reference
//!   semantics).
//! - **Would-block:** a BLOCK, or a REWRITE on the query name (a `$dnsrewrite` answer or a
//!   host-IP mapping, which also rewrites the answer, api.md §5; response checks ignore
//!   rewrites): one `would_blocks` row per record and trial bundle, with the head and the key and
//!   stage of the first hit (`query`, else `cname`, `answer_ip` or `svcb`), counted in
//!   `trial_would_block{edge, profile, bundle}` at the record's event time (the edge label lets a
//!   trial view chart one edge; `edge=all` sums them).
//! - **No head yet:** a trial bundle with no built head when core first checks a record leaves
//!   the record waiting for that bundle (`trial_pending` in core.db, one row per record and
//!   bundle, at most [`MAX_PENDING`], counted once per batch): [`retry_pending`] checks it once
//!   the bundle has a head (found through the rows' `bundle` index from the bundles that have
//!   one, so waiting rows cost nothing while no head comes), until its hour leaves the window;
//!   `trial_check` is set once every bundle of the record is checked. A failing hour or record
//!   holds up only itself: the hour backs off, the record is given up (counted) after its
//!   attempts.
//! - **Checked once, across restarts** (README §2 Restarts): a would-block is stored in the
//!   partition before the `core.db` transaction that counts it (and moves the progress or the
//!   waiting rows) commits. A pass that repeats a record (a stop between the two) takes the
//!   would-blocks already stored for it as its results for those bundles and counts them then,
//!   rather than checking those bundles again at a head that may have changed; only bundles with
//!   no stored result are checked.
//! - **Attribution:** every rule of the bundle's feeds that matched the name or the answer, with
//!   role `would_block`, or `overridden` when an exception or `$badfilter` cancels it; no
//!   self-check and no alert. Would-blocks raise no `category_blocked` or other alert.

use std::collections::BTreeMap;

use picket_api::logs::{MatchKind, Stage};
use picket_rules::matcher::{MatchHow, Outcome, Role};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

use super::attribution::{Env, Match, Status, matches_of, stage_str, value_qtype};
use super::record::Rec;
use super::replay::{self, BundleAt, CandKey, ClientCtx, Value};
use crate::state::SharedState;

/// Waiting (record, bundle) rows, at most (README §2 Bounded). A policy choice: one hour of a
/// busy network's allowed queries for one bundle; past it a record is checked without the
/// bundles that have no head yet, and counted (`analysis_skipped{work="trial_pending"}`).
pub const MAX_PENDING: i64 = 100_000;
/// Waiting records one [`retry_pending`] round reads.
const RETRY_ROWS: i64 = 512;

/// One would-block (a `would_blocks` row).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct WouldBlock {
    pub bundle: String,
    pub head: String,
    pub key: String,
    pub stage: String,
    pub matches: Vec<Match>,
    pub status: Status,
    /// Read back from the partition (an earlier pass stored it): kept as stored, not written
    /// again.
    #[serde(skip)]
    pub stored: bool,
}

/// The would-blocks stored for record (`edge`, `boot`, `seq`) in partition `p` (none when the
/// partition has no `would_blocks`).
pub fn stored_would_blocks(
    p: &super::Partition,
    edge: &str,
    boot: &str,
    seq: i64,
) -> rusqlite::Result<Vec<WouldBlock>> {
    if !p.has_table("would_blocks") {
        return Ok(Vec::new());
    }
    let mut st = p.conn.prepare_cached(
        "SELECT bundle_id, head_id, coalesce(key, ''), coalesce(stage, ''), matches_json, status
         FROM would_blocks WHERE edge_id = ?1 AND boot = ?2 AND seq = ?3",
    )?;
    let rows = st.query_map(params![edge, boot, seq], |r| {
        let matches: Option<String> = r.get(4)?;
        let status: Option<String> = r.get(5)?;
        Ok(WouldBlock {
            bundle: r.get(0)?,
            head: r.get(1)?,
            key: r.get(2)?,
            stage: r.get(3)?,
            matches: matches
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default(),
            status: if status.as_deref() == Some("complete") {
                Status::Complete
            } else {
                Status::Incomplete
            },
            stored: true,
        })
    })?;
    rows.collect()
}

/// What checking one record found.
#[derive(Clone, Debug, Default)]
pub struct TrialOutcome {
    /// The record was eligible and checked (`trial_check` is set once nothing is pending).
    pub checked: bool,
    pub would_blocks: Vec<WouldBlock>,
    /// Trial bundles with no built head yet: the record waits for them.
    pub pending: Vec<String>,
}

impl TrialOutcome {
    /// The outcome of a record whose check finished before a stop cut its batch off
    /// (`trial_check` set): its stored would-blocks.
    pub fn stored(would_blocks: Vec<WouldBlock>) -> TrialOutcome {
        TrialOutcome {
            checked: true,
            would_blocks,
            pending: Vec::new(),
        }
    }
}

/// True when the record is checked against trial bundles (see the module docs).
pub fn eligible(r: &Rec) -> bool {
    if !r.answered() {
        return false;
    }
    match &r.reason {
        None => true,
        Some(reason) => {
            reason.step >= 3
                && !matches!(
                    reason.kind,
                    MatchKind::TempAllow | MatchKind::Forward | MatchKind::Local
                )
        }
    }
}

/// The bundle's current head (`bundle_builds.head_id`).
pub fn current_head(c: &rusqlite::Connection, bundle: &str) -> rusqlite::Result<Option<String>> {
    c.query_row(
        "SELECT head_id FROM bundle_builds WHERE bundle_id = ?1 AND head_id IS NOT NULL",
        [bundle],
        |r| r.get::<_, String>(0),
    )
    .optional()
}

/// The key a decisive rule shows: a keyed rule's name, a pattern's source, an IP rule's text.
fn shown_key(row: &crate::compiler::source::Row) -> String {
    match row.rule.key_kind() {
        picket_rules::Kind::Name | picket_rules::Kind::HostMapping => {
            let mut l: Vec<&str> = row.rule.key.split('.').collect();
            l.reverse();
            l.join(".")
        }
        _ => row.rule.key.clone(),
    }
}

/// Checks one record against its profile's trial bundles (current model); `stored` are the
/// would-blocks an earlier pass stored for it (see the module docs), taken as they are.
pub fn check(env: &Env<'_>, r: &Rec, stored: &[WouldBlock]) -> anyhow::Result<TrialOutcome> {
    let mut out = TrialOutcome::default();
    if !eligible(r) {
        return Ok(out);
    }
    let mut bundles: Vec<String> = r
        .profile
        .as_deref()
        .and_then(|p| env.model.profiles.get(p))
        .map(|profile| profile.trial_bundles.iter().take(64).cloned().collect())
        .unwrap_or_default();
    // A stored result stands even when its bundle left the list since (checked once).
    for wb in stored {
        if !bundles.contains(&wb.bundle) {
            bundles.push(wb.bundle.clone());
        }
    }
    if bundles.is_empty() {
        out.checked = true;
        return Ok(out);
    }
    check_bundles(env, r, &bundles, stored)
}

/// Checks one record against `bundles` (each on its own, at its current head); a bundle with no
/// head yet goes into `pending`; a bundle with a would-block in `stored` keeps it, unchecked.
pub fn check_bundles(
    env: &Env<'_>,
    r: &Rec,
    bundles: &[String],
    stored: &[WouldBlock],
) -> anyhow::Result<TrialOutcome> {
    let mut out = TrialOutcome {
        checked: true,
        ..Default::default()
    };
    if bundles.is_empty() {
        return Ok(out);
    }
    let qtype = r.qtype_num();
    let mut values: Vec<(Stage, Value)> = Vec::new();
    if let Some(q) = r.qname_value() {
        values.push((Stage::Query, q));
    }
    let av = r.answer_values();
    for (s, v) in av.staged() {
        if !values.iter().any(|(_, x)| x == v) {
            values.push((s, v.clone()));
        }
    }
    // The record's client context, from its published config when core still has it.
    let cfg = replay::parse_versions(&r.versions_json)
        .and_then(|v| env.caches.config(env.c, &r.edge, &v.config).ok().flatten());
    let client = ClientCtx::of(cfg.as_deref(), &r.client_ip, r.device.as_deref());
    for bundle in bundles {
        if let Some(wb) = stored.iter().find(|wb| wb.bundle == *bundle) {
            out.would_blocks.push(wb.clone());
            continue;
        }
        let Some(head) = current_head(env.c, bundle)? else {
            out.pending.push(bundle.clone());
            continue;
        };
        let at = BundleAt::resolve(
            env.caches,
            env.c,
            env.model,
            bundle,
            &picket_api::logs::BundleVersion::Plain(head.clone()),
        )?;
        if at.unavailable().is_some() {
            continue;
        }
        let mut first: Option<(usize, String, Stage)> = None;
        let mut matches = Vec::new();
        let mut partial = false;
        for (vi, (stage, v)) in values.iter().enumerate() {
            let key = CandKey {
                versions: format!("trial:{head}"),
                value: v.text(),
                qtype,
                profile: r.profile.clone().unwrap_or_default(),
                bundle: bundle.clone(),
            };
            let cands = replay::candidates(env.c, env.caches, &at, key, v)?;
            partial |= cands.partial;
            let res = client.eval(&cands, v, value_qtype(*stage, v, qtype));
            // A host-IP mapping on the query name rewrites the answer (api.md §5 `rewrite`); on a
            // response value the edge's response check blocks on it, as on a hosts block line
            // (rules.md §3, §5), while a `$dnsrewrite` there is ignored.
            let hit = match &res.outcome {
                Outcome::Block | Outcome::HostMapping(_) => true,
                Outcome::Rewrite(_) => *stage == Stage::Query,
                _ => false,
            };
            if hit && first.as_ref().is_none_or(|(i, _, _)| vi < *i) {
                let k = res
                    .decisive()
                    .next()
                    .and_then(|m| cands.rows.get(m.rule))
                    .map(shown_key)
                    .or_else(|| {
                        res.matches
                            .iter()
                            .find(|m| {
                                !matches!(m.role, Role::Overridden(_)) && !matches!(m.how, MatchHow::Pattern)
                            })
                            .and_then(|m| cands.rows.get(m.rule))
                            .map(shown_key)
                    })
                    .unwrap_or_else(|| v.text());
                first = Some((vi, k, *stage));
            }
            matches_of(
                env,
                bundle,
                &cands.rows,
                &res,
                *stage,
                v,
                |role| match role {
                    Role::Overridden(_) => ("overridden".into(), None),
                    _ => ("would_block".into(), None),
                },
                &mut matches,
            );
        }
        if let Some((_, key, stage)) = first {
            matches.dedup_by(|a, b| a.entry == b.entry && a.value == b.value);
            out.would_blocks.push(WouldBlock {
                bundle: bundle.clone(),
                head: head.clone(),
                key,
                stage: stage_str(stage).to_string(),
                matches,
                status: if r.incomplete() || partial {
                    Status::Incomplete
                } else {
                    Status::Complete
                },
                stored: false,
            });
        }
    }
    Ok(out)
}

/// The waiting rows the analysis transaction `tx` may still add ([`MAX_PENDING`] less those
/// there): counted once per batch, then kept by [`pend_in`].
pub fn pending_room(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<i64> {
    let n: i64 = tx.query_row("SELECT count(*) FROM trial_pending", [], |r| r.get(0))?;
    Ok(MAX_PENDING.saturating_sub(n))
}

/// Records that record `rowid` of partition `hour_key` waits for `bundles`' first heads, in the
/// analysis transaction `tx`, within `room` ([`pending_room`]); a record past it is counted (in the
/// metric outbox, aged by `clock`) and checked without them. True when it waits.
pub fn pend_in(
    tx: &rusqlite::Transaction<'_>,
    hour_key: &str,
    rowid: i64,
    bundles: &[String],
    room: &mut i64,
    clock: &crate::clock::Clock,
) -> rusqlite::Result<bool> {
    let need = i64::try_from(bundles.len()).unwrap_or(i64::MAX);
    if need > *room {
        crate::metrics::outbox::queue_in(tx, &[super::analysis::skipped_item("trial_pending", 1)], clock)?;
        return Ok(false);
    }
    for b in bundles {
        *room -= tx
            .prepare_cached("INSERT OR IGNORE INTO trial_pending(hour, rowid_, bundle) VALUES (?1, ?2, ?3)")?
            .execute(params![hour_key, rowid, b])?
            .try_into()
            .unwrap_or(i64::MAX);
    }
    Ok(true)
}

/// The waiting records [`retry_pending`] takes in one round: those waiting for a bundle that has
/// a head now, read from the bundles with a head through `trial_pending`'s `bundle` index (a
/// round where no waiting bundle has a head reads no waiting row), leaving out the hours that back
/// off after failing as a whole (`?2`, a JSON array of hour keys), so they never take a round's
/// rows from the other hours (README §2: a bad item never stalls the receiver).
pub const READY_SQL: &str = "SELECT DISTINCT p.hour, p.rowid_ FROM bundle_builds b CROSS JOIN trial_pending p
     ON p.bundle = b.bundle_id WHERE b.head_id IS NOT NULL AND p.hour NOT IN (SELECT value FROM json_each(?2))
     LIMIT ?1";

/// Checks the records waiting for trial bundles that have a head now (see the module docs),
/// hour by hour: the partition's results first (idempotent; a would-block an earlier, interrupted
/// retry stored is taken as it is), then, in one core.db transaction, each checked bundle's
/// waiting row goes with its would-block's metric (counted only when this transaction deletes the
/// row, so a repeat never counts it twice). Rows of a record or partition that is gone are
/// dropped.
///
/// Failures stay local (README §2: a bad item never stalls the receiver; core.md §6: a waiting
/// record is checked before its hour leaves the window): an hour whose work fails as a whole (its
/// partition can't be opened or written, its transaction fails) backs off while the other hours
/// go on, and is left out of the rounds while it waits ([`READY_SQL`]); a record whose own load or
/// check fails waits for the next round, and after [`super::analysis::MAX_ATTEMPTS`] its waiting
/// rows go, counted (`analysis_skipped{work="trial_pending"}`). Returns the records checked, or
/// the first hour's failure once every hour of the round was tried.
pub async fn retry_pending(state: &SharedState) -> anyhow::Result<usize> {
    if state.restore.logs_pending() {
        return Ok(0);
    }
    let generation = state.restore.generation();
    let an = state.analysis.clone();
    let waiting: Vec<String> = an
        .trial_backoff
        .waiting()
        .iter()
        .map(super::partition::hour_key)
        .collect();
    let waiting = serde_json::to_string(&waiting)?;
    // (hour, rowid) → the bundles it waits for.
    let rows: BTreeMap<(String, i64), Vec<String>> = state
        .db
        .read(move |c| {
            let mut st = c.prepare_cached(READY_SQL)?;
            let ready = st
                .query_map(params![RETRY_ROWS, waiting], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut each =
                c.prepare_cached("SELECT bundle FROM trial_pending WHERE hour = ?1 AND rowid_ = ?2")?;
            let mut out = BTreeMap::new();
            for (h, id) in ready {
                let b = each
                    .query_map(params![h, id], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                out.insert((h, id), b);
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let mut by_hour: BTreeMap<String, Vec<(i64, Vec<String>)>> = BTreeMap::new();
    for ((h, rowid), b) in rows {
        by_hour.entry(h).or_default().push((rowid, b));
    }
    let model = an.model(state).await?;
    let mut done = 0;
    let mut failure: Option<anyhow::Error> = None;
    for (hk, list) in by_hour {
        let Some(hour) = super::partition::parse_hour_key(&hk) else {
            continue;
        };
        match retry_hour(state, generation, &model, hour, hk, list).await {
            Ok(n) => {
                an.trial_backoff.ok(hour);
                done += n;
            }
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), hour = %hour,
                    "trial checks awaiting a head failed in a partition; it backs off");
                an.trial_backoff.failed(hour);
                failure.get_or_insert(e);
            }
        }
    }
    match failure {
        Some(e) => Err(e.context("trial checks awaiting a head failed in a partition")),
        None => Ok(done),
    }
}

/// What became of one waiting record in a round of [`retry_pending`].
enum Fate {
    /// Checked against the bundles that have a head (the others still in `pending`).
    Checked(Box<(Rec, TrialOutcome)>),
    /// The record (or its partition) is gone: its waiting rows go.
    Gone,
    /// Its load or check failed: it waits for the next round.
    Retry,
    /// Its load or check kept failing: its waiting rows go, counted.
    GivenUp,
}

/// One hour's waiting records (`list`: rowid and the bundles it waits for) in a round of
/// [`retry_pending`]; returns the records checked. An error is the hour's as a whole.
async fn retry_hour(
    state: &SharedState,
    generation: u64,
    model: &std::sync::Arc<crate::config::model::Model>,
    hour: jiff::Timestamp,
    hk: String,
    list: Vec<(i64, Vec<String>)>,
) -> anyhow::Result<usize> {
    let store = state.logs.writer().store().clone();
    let wanted: Vec<(i64, Vec<String>)> = list.clone();
    // Each waiting record with the would-blocks stored for its waiting bundles; a record whose
    // load fails holds up only itself. None: the partition is gone.
    type Loaded = BTreeMap<i64, Result<(Rec, Vec<WouldBlock>), String>>;
    let loaded: Option<Loaded> = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Loaded>> {
        let Some(p) = store.open(&hour, false)? else {
            return Ok(None);
        };
        let mut out = BTreeMap::new();
        for (id, bundles) in wanted {
            let one = (|| -> anyhow::Result<Option<(Rec, Vec<WouldBlock>)>> {
                let Some(r) = super::record::load(&p, "WHERE e.rowid = ?1", &[&id])?
                    .into_iter()
                    .next()
                else {
                    return Ok(None);
                };
                let stored: Vec<WouldBlock> = stored_would_blocks(&p, &r.edge, &r.boot, r.seq)?
                    .into_iter()
                    .filter(|wb| bundles.contains(&wb.bundle))
                    .collect();
                Ok(Some((r, stored)))
            })();
            match one {
                Ok(Some(x)) => {
                    out.insert(id, Ok(x));
                }
                Ok(None) => {}
                Err(e) => {
                    out.insert(id, Err(format!("{e:#}")));
                }
            }
        }
        Ok(Some(out))
    })
    .await??;
    let mut loaded = loaded.unwrap_or_default();
    // Check each waiting record against its bundles, each on its own; those still without a
    // head wait on.
    type Work = (i64, Option<Result<(Rec, Vec<WouldBlock>), String>>, Vec<String>);
    let work: Vec<Work> = list
        .into_iter()
        .map(|(id, b)| (id, loaded.remove(&id), b))
        .collect();
    let an = state.analysis.clone();
    let model2 = model.clone();
    let checked: Vec<(i64, Vec<String>, Fate)> = state
        .db
        .read(move |c| {
            let env = Env {
                c,
                caches: &an.caches,
                model: &model2,
            };
            let mut out = Vec::with_capacity(work.len());
            for (id, x, bundles) in work {
                let res: Result<(Rec, TrialOutcome), String> = match x {
                    None => {
                        out.push((id, bundles, Fate::Gone));
                        continue;
                    }
                    Some(Err(e)) => Err(e),
                    Some(Ok((r, stored))) => {
                        let one = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            if an.poisoned_in("trial", &r.qname) {
                                anyhow::bail!("a poisoned record (test)");
                            }
                            check_bundles(&env, &r, &bundles, &stored)
                        }));
                        match one {
                            Ok(Ok(o)) => Ok((r, o)),
                            Ok(Err(e)) => Err(format!("{e:#}")),
                            Err(_) => Err("the trial check panicked".to_string()),
                        }
                    }
                };
                let fate = match res {
                    Ok(x) => Fate::Checked(Box::new(x)),
                    Err(e) => {
                        if an.failed_item_attempt(hour, &format!("t:{id}")) {
                            tracing::warn!(error = %e, hour = %hour, rowid = id,
                                "record awaiting a trial head given up: its check keeps failing");
                            Fate::GivenUp
                        } else {
                            tracing::warn!(error = %e, hour = %hour, rowid = id,
                                "trial check of a record awaiting a head failed; retried later");
                            Fate::Retry
                        }
                    }
                };
                out.push((id, bundles, fate));
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await?;
    let now = crate::util::now_ts();
    let results: Vec<(Rec, TrialOutcome)> = checked
        .iter()
        .filter_map(|(_, _, f)| match f {
            Fate::Checked(x) => Some((x.0.clone(), x.1.clone())),
            _ => None,
        })
        .collect();
    if !results.is_empty() {
        state
            .logs
            .writer()
            .with_partition(hour, move |p| {
                let tx = p.conn.unchecked_transaction()?;
                let has_wb = p.has_table("would_blocks");
                let has_tc = p.has_column("events", "trial_check");
                for (r, o) in &results {
                    if has_wb {
                        for wb in o.would_blocks.iter().filter(|wb| !wb.stored) {
                            let j = serde_json::to_string(&wb.matches)?;
                            tx.prepare_cached(
                                "INSERT OR REPLACE INTO would_blocks(edge_id, boot, seq, bundle_id, head_id, key, stage, matches_json, status)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                            )?
                            .execute(params![r.edge, r.boot, r.seq, wb.bundle, wb.head, wb.key, wb.stage, j, wb.status.as_str()])?;
                        }
                    }
                    if has_tc && o.pending.is_empty() {
                        tx.execute(
                            "UPDATE events SET trial_check = coalesce(trial_check, ?4) WHERE edge_id = ?1 AND boot = ?2 AND seq = ?3",
                            params![r.edge, r.boot, r.seq, now],
                        )?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
    }
    let gate = state.restore.clone();
    let clock = state.clock.clone();
    state
        .db
        .write(move |c| {
            if !gate.is_current(generation) {
                return Ok(0);
            }
            let tx = c.transaction()?;
            let mut items = Vec::new();
            let mut n = 0;
            let mut given_up = 0usize;
            let mut del = tx.prepare_cached(
                "DELETE FROM trial_pending WHERE hour = ?1 AND rowid_ = ?2 AND bundle = ?3",
            )?;
            for (id, bundles, fate) in &checked {
                match fate {
                    Fate::Retry => {}
                    Fate::Gone => {
                        for b in bundles {
                            del.execute(params![hk, id, b])?;
                        }
                    }
                    Fate::GivenUp => {
                        // Counted once: a repeat finds the rows gone.
                        let mut gone = 0;
                        for b in bundles {
                            gone += del.execute(params![hk, id, b])?;
                        }
                        if gone > 0 {
                            given_up += 1;
                        }
                    }
                    Fate::Checked(x) => {
                        let (r, o) = &**x;
                        let ms = r.time().map(|t| t.as_millisecond()).unwrap_or(0);
                        for b in bundles.iter().filter(|b| !o.pending.contains(b)) {
                            // The row as read: a repeat that finds it gone counts nothing.
                            if del.execute(params![hk, id, b])? == 0 {
                                continue;
                            }
                            if o.would_blocks.iter().any(|wb| wb.bundle == *b) {
                                // Per edge (core.md §10: per-edge charts), summed for all edges.
                                items.push((
                                    "trial_would_block".to_string(),
                                    crate::metrics::labels(
                                        &r.edge,
                                        &[("profile", r.profile.as_deref().unwrap_or("")), ("bundle", b)],
                                    ),
                                    ms,
                                    1.0,
                                ));
                            }
                        }
                        n += 1;
                    }
                }
            }
            drop(del);
            if given_up > 0 {
                items.push(super::analysis::skipped_item("trial_pending", given_up));
            }
            crate::metrics::outbox::queue_in(&tx, &items, &clock)?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(n)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_api::logs::Reason;

    #[test]
    fn eligibility_follows_the_ladder_step() {
        let mut r = Rec {
            decision: "allow".into(),
            ..Default::default()
        };
        assert!(eligible(&r), "a default allow (no reason) is checked");
        r.reason = Some(Reason {
            step: 2,
            bundle: Some("allow-common".into()),
            ..Default::default()
        });
        assert!(!eligible(&r), "an allow bundle let it through");
        r.reason = Some(Reason {
            step: 1,
            kind: MatchKind::TempAllow,
            ..Default::default()
        });
        assert!(!eligible(&r));
        r.reason = Some(Reason {
            step: 0,
            kind: MatchKind::Forward,
            ..Default::default()
        });
        assert!(!eligible(&r), "forwarded");
        r.reason = Some(Reason {
            step: 4,
            kind: MatchKind::Lookup,
            ..Default::default()
        });
        assert!(eligible(&r), "a clean lookup at step 4");
        r.decision = "block".into();
        assert!(!eligible(&r));
    }
}
