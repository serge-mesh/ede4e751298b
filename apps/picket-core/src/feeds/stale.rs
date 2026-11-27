//! `feed_stale` (feed-scheduling.md §8): a feed that has gone quiet for longer than its own
//! history explains, whatever its provider's trigger.
//!
//! - **Reference:** at each change, the model as it stands right after it (the driving candidate,
//!   or the warm-started model: [`super::schedule::learner::Frozen`]), the change's time, `n`
//!   (the feed's mean changes per day over the 60 days before it) and the number of changes in
//!   those 60 days, warm-start changes included, frozen in `feed_state.stale_ref_json`. Checks
//!   never retrain it or recompute it from history that has since expired.
//! - **Judging:** after each successful check without a change, `E` = the changes the frozen
//!   model expects between the last change and this check; it fires at once when
//!   `E > max(3, ln(D × n))`, `D` = `alerts.feed_stale_days`, with at least 5 changes in the
//!   frozen count.
//! - **Resolving:** at the feed's next change; when the feed or its provider is disabled or
//!   deleted (the runtime's reload); and when the feed starts a new epoch, which drops its
//!   reference (reason: retargeted, [`resolve_retargeted`]). Failed checks neither raise nor
//!   resolve it.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::schedule::{self, learner::Frozen};
use crate::alerts::{Alerts, Changes as AlertChanges, RaiseSpec, Severity};
use crate::state::SharedState;

/// The fewest changes in the frozen count before `feed_stale` can fire.
pub const MIN_CHANGES: usize = 5;
/// The shortest span `n` is averaged over (policy choice): a warm start or a new feed whose
/// changes fall within hours doesn't make `n`, and so the threshold, arbitrarily large.
pub const MIN_SPAN_DAYS: f64 = 1.0;
/// The longest: the 60 days of feed-scheduling.md §8.
pub const MAX_SPAN_DAYS: f64 = 60.0;
/// The floor of the threshold.
pub const MIN_THRESHOLD: f64 = 3.0;
const DAY: f64 = 86_400.0;

/// The staleness reference frozen at a feed's last change.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reference {
    pub model: Frozen,
    /// The change's time (Unix seconds).
    pub t_change: f64,
    /// Mean changes per day over the 60 days before it, or over the part of them the feed was
    /// observed (its epoch's first check or warm-start span) when shorter.
    pub n: f64,
    /// Changes in those 60 days.
    pub count: usize,
    /// The learned pattern in words, as it was.
    pub pattern: String,
}

impl Reference {
    /// A reference from a model, the change time, the changes in the 60 days before it and the
    /// days of those 60 the feed was observed. `n` is averaged over that span (at least
    /// [`MIN_SPAN_DAYS`]), so a feed warm-started from a day of commits isn't taken for one that
    /// changes once in 60 days (feed-scheduling.md §8: about one false alert per D days).
    pub fn new(model: Frozen, t_change: f64, count: usize, span_days: f64, pattern: String) -> Self {
        let span = if span_days.is_finite() {
            span_days.clamp(MIN_SPAN_DAYS, MAX_SPAN_DAYS)
        } else {
            MAX_SPAN_DAYS
        };
        Self {
            model,
            t_change,
            n: count as f64 / span,
            count,
            pattern,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// `E` at `t`: the changes the frozen model expects since the last change.
    pub fn expected_at(&self, t: f64) -> f64 {
        if t <= self.t_change {
            return 0.0;
        }
        self.model.expected_since(self.t_change, t)
    }

    /// The threshold for `D` days per false alert: `max(3, ln(D × n))`.
    pub fn threshold(&self, days: u32) -> f64 {
        let x = f64::from(days) * self.n;
        if x > 0.0 {
            x.ln().max(MIN_THRESHOLD)
        } else {
            MIN_THRESHOLD
        }
    }

    /// True when a check at `t` finds the feed stale.
    pub fn stale_at(&self, t: f64, days: u32) -> bool {
        self.count >= MIN_CHANGES && self.expected_at(t) > self.threshold(days)
    }
}

/// What a successful check tells the staleness judge.
#[derive(Clone, Debug)]
pub struct Input {
    pub feed: String,
    pub name: String,
    pub provider: Option<String>,
    pub now: jiff::Timestamp,
    /// The model right after this check's change, its time and pattern; `None` for a check
    /// without a change.
    pub change: Option<(Frozen, f64, String)>,
    /// The learned pattern in words now.
    pub pattern: Option<String>,
    /// `alerts.feed_stale_days`.
    pub days: u32,
}

/// Judges a feed after a successful check, in the check's transaction: a change freezes a new
/// reference and resolves `feed_stale`; a check without one may raise it.
pub fn after_check(
    tx: &rusqlite::Transaction<'_>,
    alerts: &Alerts,
    i: &Input,
    ch: &mut AlertChanges,
) -> rusqlite::Result<()> {
    let key = format!("feed_stale:{}", i.feed);
    if let Some((model, t_change, pattern)) = &i.change {
        let (count, span_days) = changes_before(tx, &i.feed, *t_change)?;
        let r = Reference::new(model.clone(), *t_change, count, span_days, pattern.clone());
        super::store::set_stale_ref(tx, &i.feed, Some(&r.to_json()))?;
        alerts.resolve_in(tx, &key, Some(&json!({"by": "the feed changed"})), ch)?;
        return Ok(());
    }
    let Some(r) = reference(tx, &i.feed)? else {
        return Ok(());
    };
    let t = schedule::to_secs(i.now);
    if !r.stale_at(t, i.days) || Alerts::is_open_in(tx, &key)? {
        return Ok(());
    }
    let last = schedule::from_unix(r.t_change);
    let spec = RaiseSpec::new(
        "feed_stale",
        Severity::Warning,
        key,
        format!("Feed {}: quieter than its history explains", i.name),
        json!({
            "last_change": crate::util::ts(&last),
            "pattern": r.pattern,
            "pattern_now": i.pattern,
            "usual_gap_s": if r.n > 0.0 { (DAY / r.n).round() } else { 0.0 },
            "expected_changes": (r.expected_at(t) * 100.0).round() / 100.0,
            "threshold": (r.threshold(i.days) * 100.0).round() / 100.0,
            "changes_in_60d": r.count,
        }),
    )
    .feed(i.feed.clone());
    let spec = match &i.provider {
        Some(p) => spec.feed_provider(p.clone()),
        None => spec,
    };
    alerts.raise_in(tx, &spec, ch)?;
    Ok(())
}

/// The feed's frozen reference, if it has one.
pub fn reference(c: &rusqlite::Connection, feed: &str) -> rusqlite::Result<Option<Reference>> {
    let j: Option<Option<String>> = c
        .query_row(
            "SELECT stale_ref_json FROM feed_state WHERE feed_id = ?1",
            [feed],
            |r| r.get(0),
        )
        .optional()?;
    Ok(j.flatten().and_then(|s| serde_json::from_str(&s).ok()))
}

/// Changes of the feed's current epoch in the 60 days up to `t` (Unix seconds), warm-start
/// changes included, and how many of those days the epoch observed: from its warm start's span
/// or its first successful check, whichever is earlier.
fn changes_before(c: &rusqlite::Connection, feed: &str, t: f64) -> rusqlite::Result<(usize, f64)> {
    let hi = crate::util::ts(&schedule::from_unix(t + 1.0));
    let lo = crate::util::ts(&schedule::from_unix(t - 60.0 * DAY));
    let (epoch, warm_span): (Option<String>, Option<String>) = c
        .query_row(
            "SELECT epoch_at, warm_span_at FROM feed_state WHERE feed_id = ?1",
            [feed],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or_default();
    let n: i64 = c.query_row(
        "SELECT count(*) FROM feed_changes WHERE feed_id = ?1
           AND coalesce(t_change, t_seen) > ?2 AND coalesce(t_change, t_seen) <= ?3
           AND (?4 IS NULL OR t_seen >= ?4)",
        params![feed, lo, hi, epoch],
        |r| r.get(0),
    )?;
    let first_check: Option<String> = c.query_row(
        "SELECT min(t) FROM feed_checks WHERE feed_id = ?1 AND ok = 1 AND (?2 IS NULL OR t >= ?2)",
        params![feed, epoch],
        |r| r.get(0),
    )?;
    let from = [first_check, warm_span]
        .into_iter()
        .flatten()
        .filter_map(|s| crate::util::parse_ts(&s))
        .map(schedule::to_secs)
        .fold(f64::INFINITY, f64::min);
    let span_days = if from.is_finite() {
        (t - from) / DAY
    } else {
        MAX_SPAN_DAYS
    };
    Ok((crate::util::nonneg_usize(n), span_days))
}

/// Resolves every open `feed_stale` whose feed no longer has a reference: it started a new epoch
/// (feed-scheduling.md §8: reason retargeted).
pub async fn resolve_retargeted(state: &SharedState) {
    let alerts = state.alerts.clone();
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let keys: Vec<String> = {
                let mut st = tx.prepare(
                    "SELECT a.dedupe_key FROM alerts a LEFT JOIN feed_state s ON s.feed_id = a.feed_id
                     WHERE a.kind = 'feed_stale' AND a.state = 'open' AND s.feed_id IS NOT NULL AND s.stale_ref_json IS NULL",
                )?;
                st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
            };
            let mut ch = AlertChanges::default();
            for k in keys {
                alerts.resolve_in(&tx, &k, Some(&json!({"by": "retargeted"})), &mut ch)?;
            }
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await;
    if let Ok(ch) = r {
        state.alerts.announce(ch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::schedule::learner::{Learner, Obs};

    const H: f64 = 3_600.0;

    /// A daily feed learned over 30 days, then frozen at its last change.
    fn daily(days: usize) -> (Learner, f64) {
        let start = 1_800_000_000.0 - (1_800_000_000.0 % DAY);
        let mut l = Learner::new();
        let mut t = start;
        let mut last = start;
        while t < start + days as f64 * DAY {
            t += 15.0 * 60.0;
            let ex = if t - last >= DAY {
                last = t - 1.0;
                vec![t - 1.0]
            } else {
                vec![]
            };
            l.observe(
                &Obs {
                    t,
                    exact: ex,
                    interval: false,
                },
                false,
            );
        }
        l.refit(t);
        (l, last)
    }

    /// feed-scheduling.md §8: a daily feed that stops is flagged within a few days, never on its
    /// normal rhythm, and the threshold follows `ln(D × n)`.
    #[test]
    fn a_stopped_daily_feed_is_flagged_and_a_normal_one_isnt() {
        let (l, last) = daily(30);
        let r = Reference::new(l.frozen(), last, 30, 60.0, l.describe(last));
        assert!((r.n - 0.5).abs() < 1e-9);
        assert_eq!(r.threshold(30), MIN_THRESHOLD, "ln(15) < 3");
        // Its normal gap: not stale.
        assert!(!r.stale_at(last + DAY - H, 30));
        assert!(!r.stale_at(last + DAY + H, 30), "an hour late is no alert");
        // A week without a change: stale.
        assert!(
            r.stale_at(last + 7.0 * DAY, 30),
            "E = {}",
            r.expected_at(last + 7.0 * DAY)
        );
        // Fewer than 5 changes: never.
        let few = Reference {
            count: 4,
            ..r.clone()
        };
        assert!(!few.stale_at(last + 30.0 * DAY, 30));
        // A busy feed's threshold grows: ln(30 × 24) ≈ 6.6.
        let busy = Reference { n: 24.0, ..r };
        assert!((busy.threshold(30) - (720f64).ln()).abs() < 1e-9);
    }

    /// feed-scheduling.md §8 with a warm start: `n` is averaged over the span the feed was
    /// observed, so 20 changes read from one day of history give ≈ 20 a day (threshold
    /// ln(30 × 20)), not 20 in 60 days (threshold 3); a span of hours counts as a day, and one
    /// longer than 60 days as 60.
    #[test]
    fn n_follows_the_observed_span() {
        let (l, last) = daily(10);
        let warm = Reference::new(l.frozen(), last, 20, 1.0, "x".into());
        assert!((warm.n - 20.0).abs() < 1e-9);
        assert!((warm.threshold(30) - 600f64.ln()).abs() < 1e-9);
        let hours = Reference::new(l.frozen(), last, 20, 2.0 / 24.0, "x".into());
        assert!((hours.n - 20.0).abs() < 1e-9, "at least a day");
        let long = Reference::new(l.frozen(), last, 30, 400.0, "x".into());
        assert!((long.n - 0.5).abs() < 1e-9, "at most 60 days");
        let odd = Reference::new(l.frozen(), last, 30, f64::NAN, "x".into());
        assert!((odd.n - 0.5).abs() < 1e-9);
    }

    #[test]
    fn references_round_trip() {
        let (l, last) = daily(10);
        let r = Reference::new(l.frozen(), last, 10, 60.0, "daily".into());
        let back: Reference = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!((back.t_change, back.count), (r.t_change, r.count));
        let t = last + 2.0 * DAY;
        assert!((back.expected_at(t) - r.expected_at(t)).abs() < 1e-9 * r.expected_at(t).max(1.0));
        assert_eq!(back.expected_at(last - 5.0), 0.0);
    }
}
