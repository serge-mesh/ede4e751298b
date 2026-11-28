//! Feed time series (feeds.md §6, core.md §10): checks and failures, records added, deleted and
//! total per rule type, parse errors and held runs, counted at their event time in
//! `metrics.db` (the export keeps totals since core started).

use super::types::{RunStatus, TypeCounts};
use crate::metrics::Labels;
use crate::state::AppState;

/// The feed series' names (registered in `metrics::CORE_SERIES`).
pub const CHECKS: &str = "feed_checks";
pub const ADDED: &str = "feed_records_added";
pub const DELETED: &str = "feed_records_deleted";
/// The records in a feed's applied run per rule type: a gauge, exported as `picket_feed_records`
/// (`metrics::CORE_SERIES`).
pub const TOTAL: &str = "feed_records";
pub const PARSE_ERRORS: &str = "feed_parse_errors";
pub const HELD: &str = "feed_held_runs";

fn labels(feed: &str, extra: &[(&str, &str)]) -> Labels {
    let mut l = Labels::new();
    l.insert("feed".into(), feed.into());
    for (k, v) in extra {
        l.insert((*k).into(), (*v).into());
    }
    l
}

/// A check happened.
pub async fn check(state: &AppState, feed: &str, ok: bool) {
    let now = jiff::Timestamp::now().as_millisecond();
    state
        .metrics
        .count(
            &state.metrics_db,
            vec![(
                CHECKS.into(),
                labels(feed, &[("result", if ok { "ok" } else { "failed" })]),
                now,
                1.0,
            )],
        )
        .await;
}

/// A run was stored.
#[expect(clippy::too_many_arguments, reason = "one run's counts, recorded together")]
pub async fn run_stored(
    state: &AppState,
    feed: &str,
    status: RunStatus,
    added: &TypeCounts,
    removed: &TypeCounts,
    totals: &TypeCounts,
    parse_errors: u64,
    download: bool,
) {
    let now = jiff::Timestamp::now().as_millisecond();
    let mut items = Vec::new();
    if matches!(status, RunStatus::Applied | RunStatus::Expired) {
        for t in picket_rules::RuleType::ALL {
            items.push((
                ADDED.to_string(),
                labels(feed, &[("type", t.as_str())]),
                now,
                added.get(t) as f64,
            ));
            items.push((
                DELETED.to_string(),
                labels(feed, &[("type", t.as_str())]),
                now,
                removed.get(t) as f64,
            ));
        }
    }
    if status == RunStatus::Held {
        items.push((HELD.to_string(), labels(feed, &[]), now, 1.0));
    }
    if download && parse_errors > 0 {
        items.push((
            PARSE_ERRORS.to_string(),
            labels(feed, &[]),
            now,
            parse_errors as f64,
        ));
    }
    state.metrics.count(&state.metrics_db, items).await;
    if matches!(status, RunStatus::Applied | RunStatus::Expired) {
        let gauges = picket_rules::RuleType::ALL
            .iter()
            .map(|t| {
                (
                    TOTAL.to_string(),
                    labels(feed, &[("type", t.as_str())]),
                    totals.get(*t) as f64,
                )
            })
            .collect();
        state.metrics.gauges(&state.metrics_db, gauges).await;
    }
}
