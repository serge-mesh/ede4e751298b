//! Choosing the next check (feed-scheduling.md §5): each feed's ask (the learned `dynamic`
//! schedule, [`learner`], spaced from the feed's own last check: [`ask_after_check`]; or its
//! error backoff), the provider's trigger (`cron` with jitter, the `sqs` backstop), the hard
//! `min_interval` floor, and on `cron` triggers a list's `! Expires:` as the minimum interval
//! between full downloads of its file (feeds.md §5).

// The model and its backtests live in their own crate, which CI builds optimised.
pub use picket_schedule::{backtest, learner};

use jiff::{SignedDuration, Timestamp};
use picket_api::time::saturating_add;

use crate::config::model::Trigger;
use learner::{Learner, Obs};

/// The error backoff: 1, 2, 4 … min, up to 1 h (feed-scheduling.md §5).
pub fn backoff(failures: u32) -> jiff::SignedDuration {
    let exp = failures.saturating_sub(1).min(6);
    jiff::SignedDuration::from_mins((1i64 << exp).min(60))
}

/// What the next-check choice needs.
pub struct Inputs<'a> {
    pub now: Timestamp,
    pub schedule: &'a Trigger,
    /// The last check of any outcome.
    pub last_check: Option<Timestamp>,
    /// Consecutive failed checks.
    pub failures: u32,
    /// The latest download's `! Expires:` and when it was downloaded (cron feeds only).
    pub expires_s: Option<u64>,
    pub last_download: Option<Timestamp>,
    /// The feed's learner (`dynamic`).
    pub learner: Option<&'a Learner>,
    /// `√(cost of a no-change check ÷ cost of a 304)`, capped at 10.
    pub cost_factor: f64,
}

fn secs(t: Timestamp) -> f64 {
    t.as_second() as f64 + f64::from(t.subsec_microsecond()) / 1e6
}

fn from_secs(s: f64) -> Timestamp {
    let whole = s.floor();
    let nanos = i32::try_from(crate::util::f64_to_u32((s - whole) * 1e9)).unwrap_or(0);
    Timestamp::new(crate::util::f64_to_i64(whole), nanos).unwrap_or_else(|_| Timestamp::now())
}

/// The next cron occurrence strictly after `after` (UTC; [`picket_lookup::cron`]).
pub fn cron_next(expr: &str, after: Timestamp) -> Option<Timestamp> {
    picket_lookup::cron::next_after(&picket_lookup::cron::parse(expr).ok()?, after)
}

/// The longest `! Expires:` honoured (a bad header can't park a feed for good).
pub const MAX_EXPIRES_S: u64 = 30 * 86_400;

/// The earliest next full download a list's `! Expires:` allows on a cron schedule: the last
/// full download plus the header's interval (feeds.md §5).
pub fn expires_floor(last_download: Option<Timestamp>, expires_s: Option<u64>) -> Option<Timestamp> {
    let d = SignedDuration::from_secs(crate::util::sat_i64(expires_s?.min(MAX_EXPIRES_S)));
    Some(saturating_add(last_download?, d))
}

/// When a feed is next due by itself: its ask under a `dynamic` trigger, the trigger's next time
/// under `cron` or `sqs` (the `sqs` backstop), the error backoff after a failed check. Sums
/// with stored times and configured intervals saturate at the end of the timestamp range.
pub fn next_check(i: &Inputs<'_>) -> Timestamp {
    let min = SignedDuration::from_secs(crate::util::sat_i64(i.schedule.min_interval().as_secs()));
    let floor = i.last_check.map(|t| saturating_add(t, min)).unwrap_or(i.now);
    if i.failures > 0 {
        // After a failed check the backoff decides until one succeeds (cron feeds too).
        let base = i.last_check.unwrap_or(i.now);
        return saturating_add(base, backoff(i.failures)).max(floor);
    }
    match i.schedule {
        Trigger::Sqs { backstop, .. } => {
            let last = i.last_check.unwrap_or(i.now);
            let backstop =
                SignedDuration::from_secs(crate::util::sat_i64(backstop.as_secs().min(30 * 86_400)));
            saturating_add(last, backstop).max(floor)
        }
        Trigger::Cron { cron, jitter, .. } => {
            let after = floor.max(i.now) - jiff::SignedDuration::from_secs(1);
            let mut next = cron_next(cron, after).unwrap_or(i.now + SignedDuration::from_hours(1));
            let j = jitter.as_secs();
            if j > 0 {
                let jitter =
                    SignedDuration::from_secs(crate::util::sat_i64(rand::random_range(0..=j.min(86_400))));
                next = saturating_add(next, jitter);
            }
            if let Some(f) = expires_floor(i.last_download, i.expires_s) {
                next = next.max(f);
            }
            next.max(floor)
        }
        Trigger::Dynamic { .. } => {
            let last = i.last_check.unwrap_or(i.now);
            let l = match i.learner {
                Some(l) => l,
                None => {
                    let safety = SignedDuration::from_secs(crate::util::f64_to_i64(learner::SAFETY) / 6);
                    return saturating_add(last, safety).max(floor);
                }
            };
            let k_eff = l.k * i.cost_factor.clamp(1.0, 10.0);
            from_secs(l.next_check(secs(last), min.as_secs() as f64, k_eff)).max(floor)
        }
    }
}

/// The trigger's own next time (feed-scheduling.md §5): the next cron time (with its jitter) or
/// the `sqs` backstop, after the provider's previous check; none for `dynamic`.
pub fn trigger_next(trigger: &Trigger, now: Timestamp, last_check: Option<Timestamp>) -> Option<Timestamp> {
    match trigger {
        Trigger::Dynamic { .. } => None,
        t => Some(next_check(&Inputs {
            now,
            schedule: t,
            last_check,
            failures: 0,
            expires_s: None,
            last_download: None,
            learner: None,
            cost_factor: 1.0,
        })),
    }
}

/// A feed's ask (feed-scheduling.md §5): by its model under a `dynamic` trigger, by its error
/// backoff after a failed check under any trigger, else none (the trigger decides).
pub fn feed_ask(i: &Inputs<'_>) -> Option<Timestamp> {
    if i.failures > 0 || matches!(i.schedule, Trigger::Dynamic { .. }) {
        Some(next_check(i))
    } else {
        None
    }
}

/// A feed's ask after a successful check at `now` (feed-scheduling.md §5 "Spacing"): `fresh`
/// (its [`feed_ask`] from this check), unless the check came before the feed's `pending` ask and
/// found none of its changes (a sibling's check, or a manual one). Then it keeps the earlier of
/// the two, so its gap counts from its own last check and a sibling's check never delays it
/// ([`learner::respace`]). After a failing streak (`failing`), the schedule resumes from this
/// check.
pub fn ask_after_check(
    fresh: Option<Timestamp>,
    now: Timestamp,
    pending: Option<Timestamp>,
    failing: bool,
    changed: bool,
) -> Option<Timestamp> {
    let fresh = fresh?;
    Some(if failing {
        fresh
    } else {
        learner::respace(pending, fresh, now, changed)
    })
}

/// How often a `dynamic` provider whose `files` holds globs is checked at least, to keep listing
/// files (feed-scheduling.md §5).
pub const LIST_EVERY: jiff::SignedDuration = jiff::SignedDuration::from_hours(1);

/// What a provider's due time depends on.
pub struct ProviderDue<'a> {
    pub now: Timestamp,
    pub trigger: &'a Trigger,
    /// The provider's previous check (`None`: its first check is due at once).
    pub last_check: Option<Timestamp>,
    /// Its enabled feeds' asks.
    pub asks: Vec<Timestamp>,
    /// The trigger's own next time: the next cron time, or the `sqs` backstop.
    pub trigger_next: Option<Timestamp>,
    /// `files` holds globs (a `dynamic` provider keeps listing at least hourly).
    pub globs: bool,
    /// Due at once (a nudge, "Check now", an edit), within `min_interval`.
    pub now_wanted: bool,
}

/// When a provider is due (feed-scheduling.md §5): a `dynamic` provider at its feeds' earliest
/// ask (and, with globs or without asks, at least hourly); a `cron` or `sqs` provider at its
/// trigger's next time or a feed's error backoff, whichever is first. Never sooner than
/// `min_interval` after its previous check.
pub fn provider_due(d: &ProviderDue<'_>) -> Timestamp {
    let min = jiff::SignedDuration::from_secs(crate::util::sat_i64(d.trigger.min_interval().as_secs()));
    let Some(last) = d.last_check else {
        return d.now;
    };
    let floor = saturating_add(last, min);
    if d.now_wanted {
        return floor.max(d.now);
    }
    let earliest_ask = d.asks.iter().copied().min();
    let base = match d.trigger {
        Trigger::Dynamic { .. } => {
            let list = (d.globs || earliest_ask.is_none()).then_some(saturating_add(last, LIST_EVERY));
            [earliest_ask, list].into_iter().flatten().min()
        }
        Trigger::Cron { .. } | Trigger::Sqs { .. } => {
            [earliest_ask, d.trigger_next].into_iter().flatten().min()
        }
    };
    base.unwrap_or(saturating_add(last, LIST_EVERY)).max(floor)
}

/// `√(cost of a no-change check ÷ cost of a 304)`, capped at 10 (feed-scheduling.md §5): the
/// mean bytes of recent successful no-change checks against a 304's ~600 bytes.
pub fn cost_factor(mean_unchanged_bytes: Option<f64>) -> f64 {
    let b = mean_unchanged_bytes.unwrap_or(600.0).max(600.0);
    (b / 600.0).sqrt().clamp(1.0, 10.0)
}

/// Unix seconds.
pub fn to_secs(t: Timestamp) -> f64 {
    secs(t)
}

pub fn from_unix(s: f64) -> Timestamp {
    from_secs(s)
}

/// The learner's view of the stored history: successful checks with their changes, oldest
/// first (feed-scheduling.md §4 "Rebuild": the current epoch's last 60 days of `feed_checks` /
/// `feed_changes`; `since` is the later of 60 days ago and the epoch's start).
pub fn load_observations(
    c: &rusqlite::Connection,
    feed: &str,
    since: Timestamp,
) -> rusqlite::Result<Vec<Obs>> {
    let since_s = crate::util::ts(&since);
    let mut st = c.prepare_cached(
        "SELECT id, t FROM feed_checks WHERE feed_id = ?1 AND ok = 1 AND t >= ?2 ORDER BY t, id LIMIT 200000",
    )?;
    let checks: Vec<(i64, String)> = st
        .query_map(rusqlite::params![feed, since_s], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut ch = c.prepare_cached(
        "SELECT check_id, t_change, exact FROM feed_changes WHERE feed_id = ?1 AND t_seen >= ?2 AND check_id IS NOT NULL",
    )?;
    let mut by_check: std::collections::HashMap<i64, (Vec<f64>, bool)> = std::collections::HashMap::new();
    let rows = ch.query_map(rusqlite::params![feed, since_s], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<i64>>(2)?,
        ))
    })?;
    for row in rows {
        let (id, t, exact) = row?;
        let e = by_check.entry(id).or_default();
        match (exact, t.as_deref().and_then(crate::util::parse_ts)) {
            (Some(1), Some(t)) => e.0.push(secs(t)),
            _ => e.1 = true,
        }
    }
    Ok(checks
        .into_iter()
        .filter_map(|(id, t)| {
            let t = crate::util::parse_ts(&t)?;
            let (exact, interval) = by_check.remove(&id).unwrap_or_default();
            Some(Obs {
                t: secs(t),
                exact,
                interval,
            })
        })
        .collect())
}

/// The observations a rebuild, a `k` replay or a backtest replays for a feed (feed-scheduling.md
/// §4 "Rebuild": the current epoch's last 60 days): the successful checks since
/// [`crate::feeds::store::history_since`], led by the epoch's warm start where its span began
/// before that (its first `bootstrap` check, at most 60 days back), so the warm-start changes
/// keep their exposure after every rebuild (§6), until the 60-day window passes the warm start.
pub fn epoch_observations(
    c: &rusqlite::Connection,
    feed: &str,
    now: Timestamp,
) -> rusqlite::Result<Vec<Obs>> {
    let since = crate::feeds::store::history_since(c, feed, now)?;
    let mut obs = load_observations(c, feed, since)?;
    let st = crate::feeds::store::load_state(c, feed)?;
    if let (Some(span), Some(warmed)) = (st.warm_span_at, st.warm_started_at)
        && span < since
        && warmed >= since
    {
        let start = span.max(now - jiff::SignedDuration::from_hours(24 * 60));
        if obs.first().is_none_or(|o| o.t > secs(start)) {
            obs.insert(
                0,
                Obs {
                    t: secs(start),
                    exact: vec![],
                    interval: false,
                },
            );
        }
    }
    Ok(obs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_api::DurationStr;

    fn utc(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    /// Golden (F13: the scheduling model's seconds; plan §5 step 1, unchanged after the move to
    /// jiff).
    #[test]
    fn golden_model_seconds() {
        use picket_api::time::golden::{ROWS, ts_from_nanos};
        for r in ROWS {
            assert_eq!(secs(ts_from_nanos(r.nanos)), r.f64_secs, "{}", r.name);
            let back = picket_api::time::format_micros(&from_secs(r.f64_secs));
            assert_eq!(back, r.f64_back, "{}", r.name);
        }
    }

    /// Golden (croner 4's schedules, jiff plan choice D1): a `cron` trigger's next time for
    /// pattern shapes croner 5 refuses unless they are rewritten, and an ordinary one. After
    /// 2026-11-13T10:22:01.123456Z, a Friday.
    #[test]
    fn golden_cron_next() {
        let after = picket_api::time::golden::ts_from_nanos(1_794_565_321_123_456_000);
        for (expr, want) in [
            ("5 4 * * sun", Some("2026-11-15T04:05:00.000000Z")),
            ("@weekly", Some("2026-11-15T00:00:00.000000Z")),
            // A month name in day-of-week was its number: Mondays.
            ("0 0 * * jan", Some("2026-11-16T00:00:00.000000Z")),
            // A weekday name in the month field: January.
            ("0 0 * mon *", Some("2027-01-01T00:00:00.000000Z")),
            ("0 0 * JAN-SUN *", Some("2027-01-01T00:00:00.000000Z")),
            ("mon * * * *", Some("2026-11-13T11:01:00.000000Z")),
            // A bare `L` in day-of-week was dropped.
            ("0 0 * * 1,L", Some("2026-11-16T00:00:00.000000Z")),
            ("0 0 1 * L", Some("2026-12-01T00:00:00.000000Z")),
            ("0 0 L * L", Some("2026-11-30T00:00:00.000000Z")),
            // Never ran.
            ("0 0 * * L", None),
        ] {
            let got = cron_next(expr, after)
                .as_ref()
                .map(picket_api::time::format_micros);
            assert_eq!(got.as_deref(), want, "{expr}");
        }
    }

    #[test]
    fn backoff_doubles_up_to_an_hour() {
        let m: Vec<i64> = (1..=9).map(|f| backoff(f).as_mins()).collect();
        assert_eq!(m, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[test]
    fn cron_with_min_interval_backoff_and_expires() {
        let now = utc("2026-11-21T10:00:30Z");
        let s = Trigger::Cron {
            cron: "17 */6 * * *".into(),
            jitter: DurationStr::secs(0),
            min_interval: DurationStr::minutes(2),
        };
        let base = Inputs {
            now,
            schedule: &s,
            last_check: Some(utc("2026-11-21T06:17:00Z")),
            failures: 0,
            expires_s: None,
            last_download: None,
            learner: None,
            cost_factor: 1.0,
        };
        assert_eq!(next_check(&base), utc("2026-11-21T12:17:00Z"));
        // A failed check: the backoff, cron or not, never under min_interval.
        let failed = Inputs {
            failures: 1,
            last_check: Some(now),
            ..base
        };
        assert_eq!(next_check(&failed), now + jiff::SignedDuration::from_mins(2));
        let failed3 = Inputs {
            failures: 3,
            last_check: Some(now),
            schedule: &s,
            ..failed
        };
        assert_eq!(next_check(&failed3), now + jiff::SignedDuration::from_mins(4));
        // `! Expires: 1 day` after a download at 06:17: not before tomorrow's 06:17.
        let exp = Inputs {
            now,
            schedule: &s,
            last_check: Some(utc("2026-11-21T06:17:00Z")),
            failures: 0,
            expires_s: Some(86_400),
            last_download: Some(utc("2026-11-21T06:17:00Z")),
            learner: None,
            cost_factor: 1.0,
        };
        assert_eq!(next_check(&exp), utc("2026-11-22T06:17:00Z"));
        // Jitter stays within its bound.
        let sj = Trigger::Cron {
            cron: "0 * * * *".into(),
            jitter: DurationStr::minutes(5),
            min_interval: DurationStr::minutes(2),
        };
        for _ in 0..20 {
            let n = next_check(&Inputs {
                schedule: &sj,
                last_check: None,
                failures: 0,
                expires_s: None,
                last_download: None,
                learner: None,
                cost_factor: 1.0,
                now,
            });
            assert!(
                n >= utc("2026-11-21T11:00:00Z") && n <= utc("2026-11-21T11:05:00Z"),
                "{n}"
            );
        }
    }

    #[test]
    fn dynamic_respects_min_interval_without_data() {
        let now = utc("2026-11-21T10:00:00Z");
        let s = Trigger::Dynamic {
            min_interval: DurationStr::minutes(30),
        };
        let i = Inputs {
            now,
            schedule: &s,
            last_check: Some(now),
            failures: 0,
            expires_s: None,
            last_download: None,
            learner: None,
            cost_factor: 1.0,
        };
        assert!(next_check(&i) >= now + jiff::SignedDuration::from_mins(30));
        let l = Learner::new();
        let i = Inputs {
            learner: Some(&l),
            ..i
        };
        let n = next_check(&i);
        assert!(
            n >= now + jiff::SignedDuration::from_mins(30) && n <= now + jiff::SignedDuration::from_hours(1)
        );
    }

    #[test]
    fn provider_due_times() {
        let now = utc("2026-11-21T10:00:00Z");
        let dynamic = Trigger::Dynamic {
            min_interval: DurationStr::minutes(2),
        };
        let base = ProviderDue {
            now,
            trigger: &dynamic,
            last_check: Some(now - jiff::SignedDuration::from_mins(1)),
            asks: vec![
                now + jiff::SignedDuration::from_mins(30),
                now + jiff::SignedDuration::from_mins(10),
            ],
            trigger_next: None,
            globs: false,
            now_wanted: false,
        };
        assert_eq!(
            provider_due(&base),
            now + jiff::SignedDuration::from_mins(10),
            "the earliest ask"
        );
        let first = ProviderDue {
            last_check: None,
            ..base
        };
        assert_eq!(provider_due(&first), now, "a first check is due at once");
        let wanted = ProviderDue {
            now_wanted: true,
            asks: vec![],
            last_check: Some(now - jiff::SignedDuration::from_mins(1)),
            ..first
        };
        assert_eq!(
            provider_due(&wanted),
            now + jiff::SignedDuration::from_mins(1),
            "min_interval holds"
        );
        let globs = ProviderDue {
            now_wanted: false,
            asks: vec![now + jiff::SignedDuration::from_hours(5)],
            globs: true,
            ..wanted
        };
        assert_eq!(
            provider_due(&globs),
            now - jiff::SignedDuration::from_mins(1) + LIST_EVERY,
            "hourly listing"
        );
        let sqs = Trigger::Sqs {
            queue_url: String::new(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            backstop: DurationStr::hours(1),
            min_interval: DurationStr::minutes(2),
        };
        let s = ProviderDue {
            trigger: &sqs,
            asks: vec![now + jiff::SignedDuration::from_mins(4)],
            trigger_next: Some(now + jiff::SignedDuration::from_mins(59)),
            globs: false,
            ..globs
        };
        assert_eq!(
            provider_due(&s),
            now + jiff::SignedDuration::from_mins(4),
            "a feed's backoff comes first"
        );
        // The sqs backstop as a feed's next check.
        let i = Inputs {
            now,
            schedule: &sqs,
            last_check: Some(now),
            failures: 0,
            expires_s: None,
            last_download: None,
            learner: None,
            cost_factor: 1.0,
        };
        assert_eq!(next_check(&i), now + jiff::SignedDuration::from_hours(1));
        assert!(feed_ask(&i).is_none(), "no ask but a backoff under sqs");
        assert!(feed_ask(&Inputs { failures: 2, ..i }).is_some());
    }

    /// feed-scheduling.md §5 "Spacing": a check before a feed's ask that finds none of its
    /// changes keeps the ask (or an earlier fresh one); the feed's own check, one that finds a
    /// change, or the end of a failing streak spaces the next ask from this check; triggers
    /// without asks stay without.
    #[test]
    fn a_siblings_check_never_delays_a_feeds_ask() {
        let now = utc("2026-11-21T10:00:00Z");
        let m = |n: i64| Some(now + jiff::SignedDuration::from_mins(n));
        // (fresh ask, pending ask, failing, found a change) → ask
        for (fresh, pending, failing, changed, want, why) in [
            (m(9), m(4), false, false, m(4), "a sibling's check"),
            (m(3), m(4), false, false, m(3), "an earlier fresh ask"),
            (m(9), m(4), false, true, m(9), "it found a change"),
            (m(9), m(0), false, false, m(9), "its own check"),
            (m(9), m(-1), false, false, m(9), "a late own check"),
            (m(9), None, false, false, m(9), "no ask yet"),
            (m(9), m(4), true, false, m(9), "after a failing streak"),
            (None, m(4), false, false, None, "cron and sqs"),
        ] {
            assert_eq!(
                ask_after_check(fresh, now, pending, failing, changed),
                want,
                "{why}"
            );
        }
    }

    #[test]
    fn cost_factor_caps() {
        assert_eq!(cost_factor(None), 1.0);
        assert_eq!(cost_factor(Some(2_400.0)), 2.0);
        assert_eq!(cost_factor(Some(1e12)), 10.0);
    }
}
