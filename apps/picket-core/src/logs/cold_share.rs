//! `bundle_cold_share` (core.md §9: operational, warning): blocks answered from a bundle's cold
//! part pass 1 % of its blocks over 24 h; the details give the share per feed (bundles.md §6).
//!
//! - **What edges report:** every logged block's `reason.cold` (api.md §5) says whether its
//!   deciding key came from the bundle's cold part. Heartbeats count cold blocks per bundle too
//!   (`metrics.cold{bundle}.blocks`, api.md §3) but not the bundle's blocks, so both counts come
//!   from the records: the same logged blocks on both sides. A profile with `log: off` logs no
//!   blocks and counts on neither side, as on the dashboard's panels (core.md §12).
//! - **Per feed:** a cold block counts for each feed attribution found decisive in the bundle
//!   (core.md §6), once per record; its share is those blocks over all the bundle's blocks. Cold
//!   blocks with no decisive feed yet (attribution not run, or `unavailable`) are given as
//!   `unattributed_cold_blocks`.
//! - **When:** [`ColdShareJob`] runs hourly in the heavy lane at P3, one partition a step
//!   (core.md §3), over the records whose `ts` lies in the last 24 h. A partition without
//!   `events.reason_json` (log schema 1) can't tell cold blocks and is left out. The window is
//!   wall-clock time, so a run waits for a synchronised clock (README §2 Clocks).
//! - **Raise and resolve:** for each bundle with a cold part (`BundleDef::cold_capable`), a share
//!   past [`SHARE_LIMIT`] is the alert's condition, keyed `bundle_cold_share:<bundle>`. It raises
//!   once it has held for the kind's threshold (core.md §9 Thresholds: `alerts.thresholds`,
//!   none by default, so at the first check past the limit), through the condition path the
//!   other operational kinds use ([`crate::alerts::Alerts::condition_in`]); while the alert is
//!   open, each run replaces its details (no new raise). It resolves once the share has stayed at
//!   or below the limit (no blocks counting as 0 %) for the same threshold, as
//!   `upstream_invalid_spike` resolves "after 5 min below its threshold" (§9; the spec gives
//!   `bundle_cold_share` no rule of its own), so a share hovering at the limit with a threshold
//!   set doesn't raise and resolve every hour. Since when each has held is kept in
//!   `cold_share_state` (README §2 Restarts), measured by the job's synchronised wall clock.
//!   A bundle deleted or left without a cold part resolves at once.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use jiff::Timestamp;
use rusqlite::params;
use serde_json::json;

use crate::alerts::{Changes, RaiseSpec, Severity};
use crate::scheduler::{BoxFuture, HeavyJob, Priority, Step};
use crate::state::SharedState;

/// The share of a bundle's blocks its cold part may answer (core.md §9: 1 %).
pub const SHARE_LIMIT: f64 = 0.01;
/// The window the share covers (core.md §9: 24 h).
pub const WINDOW: jiff::SignedDuration = jiff::SignedDuration::from_hours(24);
/// How often the share is checked.
pub const EVERY: Duration = Duration::from_secs(3600);
/// Most feeds one bundle's details list (README §2 Bounded; a bundle has far fewer).
const MAX_FEEDS: i64 = 1_000;

/// "Is this a cold block": `reason.cold` true, read only from valid JSON.
const COLD: &str = "(CASE WHEN json_valid(e.reason_json) THEN json_extract(e.reason_json, '$.cold') END) = 1";
/// The decisive matches of the bundle in a record's attribution.
const DECISIVE: &str =
    "json_each(CASE WHEN json_valid(a.matches_json) THEN a.matches_json END, '$.matches') m";

/// One bundle's logged blocks in the window.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Tally {
    pub blocks: i64,
    pub cold: i64,
    /// Cold blocks by deciding feed.
    pub feeds: BTreeMap<String, i64>,
    /// Cold blocks with a decisive feed.
    pub attributed: i64,
}

/// Adds one partition's blocks of `bundles` with `from <= ts <= to` to `out`.
pub fn tally_partition(
    p: &super::Partition,
    bundles: &[String],
    from: &str,
    to: &str,
    out: &mut BTreeMap<String, Tally>,
) -> rusqlite::Result<()> {
    if !p.has_column("events", "reason_json") || !p.has_column("events", "bundle") {
        return Ok(());
    }
    let attribution = p.has_table("attribution");
    let window = "e.bundle = ?1 AND e.decision = 'block' AND e.ts >= ?2 AND e.ts <= ?3";
    for b in bundles {
        let (blocks, cold): (i64, i64) = p.conn.query_row(
            &format!("SELECT count(*), coalesce(sum({COLD}), 0) FROM events e WHERE {window}"),
            params![b, from, to],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if blocks == 0 {
            continue;
        }
        let t = out.entry(b.clone()).or_default();
        t.blocks += blocks;
        t.cold += cold;
        if cold == 0 || !attribution {
            continue;
        }
        let decisive = "a.edge_id = e.edge_id AND a.boot = e.boot AND a.seq = e.seq
             AND json_extract(m.value, '$.role') = 'decisive' AND json_extract(m.value, '$.bundle') = ?1";
        let mut st = p.conn.prepare(&format!(
            "SELECT f, count(*) FROM (
               SELECT DISTINCT e.edge_id, e.boot, e.seq, json_extract(m.value, '$.feed') AS f
               FROM events e, attribution a, {DECISIVE}
               WHERE {window} AND {COLD} AND {decisive})
             WHERE f IS NOT NULL GROUP BY f LIMIT ?4"
        ))?;
        let rows = st.query_map(params![b, from, to, MAX_FEEDS], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (f, n) = row?;
            *t.feeds.entry(f).or_default() += n;
        }
        t.attributed += p.conn.query_row(
            &format!(
                "SELECT count(*) FROM events e WHERE {window} AND {COLD}
                   AND EXISTS (SELECT 1 FROM attribution a, {DECISIVE} WHERE {decisive})"
            ),
            params![b, from, to],
            |r| r.get::<_, i64>(0),
        )?;
    }
    Ok(())
}

/// The details of a bundle's alert: the counts, the share, and each deciding feed's share.
pub fn details(bundle: &str, t: &Tally) -> serde_json::Value {
    let share = |n: i64| {
        if t.blocks > 0 {
            n as f64 / t.blocks as f64
        } else {
            0.0
        }
    };
    let mut feeds: Vec<(&String, &i64)> = t.feeds.iter().collect();
    feeds.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    json!({
        "bundle": bundle,
        "window_h": WINDOW.as_hours(),
        "blocks": t.blocks,
        "cold_blocks": t.cold,
        "share": share(t.cold),
        "limit": SHARE_LIMIT,
        "feeds": feeds.iter().map(|(f, n)| json!({"feed": f, "cold_blocks": n, "share": share(**n)})).collect::<Vec<_>>(),
        "unattributed_cold_blocks": (t.cold - t.attributed).max(0),
    })
}

/// One check of every bundle's cold share, a partition a step (module docs).
pub struct ColdShareJob {
    state: SharedState,
    /// Set by the first step: the bundles with a cold part, the window and its partitions left.
    plan: Option<Plan>,
    tally: BTreeMap<String, Tally>,
}

struct Plan {
    bundles: Vec<String>,
    from: String,
    to: String,
    /// When the check began (`to`).
    now: Timestamp,
    hours: VecDeque<Timestamp>,
}

impl ColdShareJob {
    pub fn new(state: SharedState) -> Self {
        Self {
            state,
            plan: None,
            tally: BTreeMap::new(),
        }
    }

    async fn start(&mut self) -> anyhow::Result<bool> {
        if !self.state.clock.synced() {
            tracing::debug!("the cold-share check waits for a synchronised clock (README §2 Clocks)");
            return Ok(false);
        }
        let model = self.state.config.model().await?;
        let bundles: Vec<String> = model
            .bundles
            .iter()
            .filter(|(_, d)| d.cold_capable())
            .map(|(id, _)| id.clone())
            .collect();
        let now = Timestamp::now();
        let from_at = now - WINDOW;
        let first = super::partition::hour_start(&from_at);
        let store = self.state.logs.writer().store().clone();
        let hours: VecDeque<Timestamp> = if bundles.is_empty() {
            VecDeque::new()
        } else {
            tokio::task::spawn_blocking(move || store.list())
                .await??
                .into_iter()
                .map(|(h, _)| h)
                .filter(|h| *h >= first && *h <= now)
                .collect()
        };
        self.plan = Some(Plan {
            bundles,
            from: crate::util::ts(&from_at),
            to: crate::util::ts(&now),
            now,
            hours,
        });
        Ok(true)
    }

    /// Raises, updates or resolves each bundle's alert from the tally, with since when its
    /// condition (or its clearing) has held, in one transaction (module docs).
    async fn finish(&mut self) -> anyhow::Result<()> {
        let Some(plan) = self.plan.take() else {
            return Ok(());
        };
        let tally = std::mem::take(&mut self.tally);
        let alerts = self.state.alerts.clone();
        let threshold = self.state.settings().alerts.threshold("bundle_cold_share");
        let ch = self
            .state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let mut ch = Changes::default();
                let now = plan.now;
                let open: BTreeSet<String> = {
                    let mut st = tx.prepare(
                        "SELECT bundle_id FROM alerts WHERE kind = 'bundle_cold_share' AND state = 'open'
                           AND bundle_id IS NOT NULL",
                    )?;
                    st.query_map([], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?
                };
                let held: BTreeMap<String, (Option<String>, Option<String>)> = {
                    let mut st = tx.prepare("SELECT bundle_id, above_since, below_since FROM cold_share_state")?;
                    st.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?
                        .collect::<rusqlite::Result<_>>()?
                };
                // A stored time, never after now (README §2 Clocks), else now.
                let since_of = |t: &Option<String>| {
                    t.as_deref()
                        .and_then(crate::util::parse_ts)
                        .map_or(now, |t| picket_api::time::clamp_to_now(t, now))
                };
                let empty = Tally::default();
                for b in &plan.bundles {
                    let t = tally.get(b).unwrap_or(&empty);
                    let key = format!("bundle_cold_share:{b}");
                    let share = if t.blocks > 0 { t.cold as f64 / t.blocks as f64 } else { 0.0 };
                    let d = details(b, t);
                    let (above_since, below_since) = held.get(b).cloned().unwrap_or_default();
                    let state = if share > SHARE_LIMIT {
                        let since = since_of(&above_since);
                        if open.contains(b) {
                            alerts.update_details_in(&tx, &key, &d, &[], &mut ch)?;
                        } else {
                            let spec = RaiseSpec::new(
                                "bundle_cold_share",
                                Severity::Warning,
                                key,
                                format!(
                                    "Bundle {b}: {:.1} % of its blocks in the last 24 h came from its cold part",
                                    share * 100.0
                                ),
                                d,
                            )
                            .bundle(b.clone());
                            alerts.condition_in(&tx, &spec, Some(since), threshold, now, &mut ch)?;
                        }
                        (Some(since), None)
                    } else if open.contains(b) {
                        let since = since_of(&below_since);
                        if std::time::Duration::try_from(now - since).unwrap_or_default() >= threshold {
                            alerts.resolve_in(&tx, &key, Some(&d), &mut ch)?;
                            (None, None)
                        } else {
                            alerts.update_details_in(&tx, &key, &d, &[], &mut ch)?;
                            (None, Some(since))
                        }
                    } else {
                        (None, None)
                    };
                    match state {
                        (None, None) => {
                            tx.execute("DELETE FROM cold_share_state WHERE bundle_id = ?1", [b])?;
                        }
                        (above, below) => {
                            let ts = |t: Option<Timestamp>| t.map(|t| crate::util::ts(&t));
                            tx.execute(
                                "INSERT INTO cold_share_state(bundle_id, above_since, below_since) VALUES (?1, ?2, ?3)
                                 ON CONFLICT(bundle_id) DO UPDATE SET above_since = excluded.above_since,
                                    below_since = excluded.below_since",
                                params![b, ts(above), ts(below)],
                            )?;
                        }
                    }
                }
                // A bundle deleted, or left without a cold part.
                for b in open.iter().filter(|b| !plan.bundles.contains(b)) {
                    alerts.resolve_in(
                        &tx,
                        &format!("bundle_cold_share:{b}"),
                        Some(&json!({"bundle": b, "cold_part": false})),
                        &mut ch,
                    )?;
                }
                let bundles = serde_json::to_string(&plan.bundles)?;
                tx.execute(
                    "DELETE FROM cold_share_state WHERE bundle_id NOT IN (SELECT value FROM json_each(?1))",
                    [bundles],
                )?;
                tx.commit()?;
                alerts.committed(&ch);
                Ok::<_, anyhow::Error>(ch)
            })
            .await?;
        self.state.alerts.announce(ch);
        Ok(())
    }
}

impl HeavyJob for ColdShareJob {
    fn kind(&self) -> &str {
        "cold_share"
    }

    fn target(&self) -> &str {
        "core"
    }

    fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
        Box::pin(async move {
            if self.plan.is_none() {
                return Ok(if self.start().await? {
                    Step::More
                } else {
                    Step::Done
                });
            }
            let next = self.plan.as_mut().and_then(|p| p.hours.pop_front());
            let Some(hour) = next else {
                self.finish().await?;
                return Ok(Step::Done);
            };
            let plan = self
                .plan
                .as_ref()
                .map(|p| (p.bundles.clone(), p.from.clone(), p.to.clone()));
            let Some((bundles, from, to)) = plan else {
                return Ok(Step::Done);
            };
            let store = self.state.logs.writer().store().clone();
            let part = tokio::task::spawn_blocking(move || -> anyhow::Result<BTreeMap<String, Tally>> {
                let mut out = BTreeMap::new();
                // A partition retention deleted meanwhile is skipped.
                if let Some(p) = store.open(&hour, false)? {
                    tally_partition(&p, &bundles, &from, &to, &mut out)?;
                }
                Ok(out)
            })
            .await??;
            for (b, t) in part {
                let e = self.tally.entry(b).or_default();
                e.blocks += t.blocks;
                e.cold += t.cold;
                e.attributed += t.attributed;
                for (f, n) in t.feeds {
                    *e.feeds.entry(f).or_default() += n;
                }
            }
            Ok(Step::More)
        })
    }
}

/// Schedules the hourly check (first ten minutes after start).
pub fn schedule(state: SharedState) -> tokio::task::JoinHandle<()> {
    let st = state.clone();
    state.scheduler.every(
        Duration::from_secs(600),
        EVERY,
        state.shutdown.clone(),
        move |heavy| {
            heavy.submit(Priority::P3, Box::new(ColdShareJob::new(st.clone())));
        },
    )
}
