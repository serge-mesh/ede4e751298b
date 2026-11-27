//! Self-tests on core (providers.md §4 "Self-tests"; core.md §7, §9).
//!
//! A module can name a self-test for a provider: a name, the verdict it must get and a `cron`
//! schedule (UTC). Only core runs them, in the light lane: on the schedule, when the provider is
//! saved (or first seen), and from **Test now**. A test skips the verdict cache and its result is
//! never cached or logged as a query ([`picket_lookup::LookupClient::run_self_test`]). A wrong
//! verdict is tested again 5 min later: a right one then raises nothing; a second wrong verdict
//! raises `lookup_self_test_failed` with the answer's detail (the alert offers **Flush cached
//! verdicts**); the next passing test resolves it. An error, a timeout or a rejection isn't a
//! failed test. A failed test changes nothing else.
//!
//! The last result is kept in `lookup_providers.last_self_test_json` (time, name, expectation,
//! result, verdict, detail, state); its state survives restarts, so a retest due 5 min after a
//! wrong verdict still runs after one.
//!
//! **Clocks** (README §2): the schedule is wall-clock time, so the scheduler runs nothing before
//! the clock is synchronised, and then works out every scheduled time again (one computed on a
//! boot clock days ahead would hold the tests for days). **Test now** runs whenever asked.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use jiff::Timestamp;
use picket_lookup::{Expect, SelfTestAction, SelfTestResult, SelfTestState, StoredVerdict};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;

use crate::state::{AppState, SharedState};

/// A self-test's last result, as `last_self_test_json` and the API hold it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SelfTestView {
    pub at: String,
    /// The name tested.
    pub name: String,
    /// `block` or `clean`.
    pub expect: String,
    /// `pass`, `wrong` or `inconclusive` (an error, timeout, rejection, pause or open breaker).
    pub result: String,
    /// The verdict got (`block`, `clean`, `unknown`), when there was one.
    pub verdict: Option<String>,
    pub reason: Option<String>,
    /// The module's detail of the answer.
    pub detail: Option<Value>,
    /// Why an inconclusive test had no verdict.
    pub why: Option<String>,
    /// `ok`, `suspect` (one wrong verdict, retest due) or `failing` (alert raised).
    #[schemars(with = "String")]
    pub state: SelfTestState,
    /// When the next test is due.
    pub next_at: Option<String>,
    /// `schedule`, `save` or `manual`.
    pub trigger: String,
}

/// The scheduler's state.
#[derive(Default)]
pub struct SelfTests {
    pub wake: Notify,
    next: std::sync::Mutex<HashMap<String, (Timestamp, &'static str)>>,
    running: std::sync::Mutex<HashSet<String>>,
}

impl SelfTests {
    /// The provider was saved: its test runs now.
    pub fn due_now(&self, provider: &str) {
        if let Ok(mut n) = self.next.lock() {
            n.insert(provider.to_string(), (crate::util::now(), "save"));
        }
        self.wake.notify_one();
    }

    /// At start: a suspect test's retest is due 5 min after it (it survives restarts); otherwise
    /// the next run is the schedule's next time (a start isn't a save).
    pub fn schedule_initial(&self, state: &AppState, provider: &str) {
        let model = state.lookups.model();
        let last: Option<SelfTestView> = model
            .lookup_providers
            .get(provider)
            .and_then(|p| p.last_self_test.clone())
            .and_then(|v| serde_json::from_value(v).ok());
        let retest =
            jiff::SignedDuration::try_from(picket_lookup::selftest::RETEST_AFTER).unwrap_or_default();
        let when = match &last {
            Some(l) if l.state == SelfTestState::Suspect => Some(suspect_retest_at(
                crate::util::parse_ts(&l.at),
                crate::util::now(),
                retest,
            )),
            _ => next_scheduled(state, provider, crate::util::now()),
        };
        if let (Some(when), Ok(mut n)) = (when, self.next.lock()) {
            n.insert(provider.to_string(), (when, "schedule"));
        }
    }

    fn set_next(&self, provider: &str, at: Timestamp, trigger: &'static str) {
        if let Ok(mut n) = self.next.lock() {
            n.insert(provider.to_string(), (at, trigger));
        }
    }

    fn next_of(&self, provider: &str) -> Option<(Timestamp, &'static str)> {
        self.next.lock().ok().and_then(|n| n.get(provider).copied())
    }
}

/// When a suspect test stored at `at` is retested after a start: `retest` after it, never later
/// than `retest` from `now` (a test stamped by a clock that was ahead), and now when its time
/// can't be read. The stored time is anything the RFC 3339 reader accepts, so the sum saturates:
/// one at the end of the timestamp range can't panic core's start.
fn suspect_retest_at(at: Option<Timestamp>, now: Timestamp, retest: jiff::SignedDuration) -> Timestamp {
    // `now + retest`: the wall clock plus RETEST_AFTER (5 min).
    at.map_or(now, |t| picket_api::time::saturating_add(t, retest))
        .min(now + retest)
}

fn verdict_text(v: &StoredVerdict) -> (&'static str, Option<String>) {
    match v {
        StoredVerdict::Block { reason, .. } => ("block", Some(reason.to_string())),
        StoredVerdict::Clean => ("clean", None),
        StoredVerdict::Unknown => ("unknown", None),
    }
}

/// The next scheduled run after `after`, from the module's test for the provider.
fn next_scheduled(state: &AppState, provider: &str, after: Timestamp) -> Option<Timestamp> {
    let model = state.lookups.model();
    let p = model.lookup_providers.get(provider)?;
    let module = state.lookups.modules().get(&p.module)?;
    let cfg = picket_lookup::secrets::with_placeholders(&p.config).ok()?;
    let test = module.self_test(&cfg)?;
    let cron = picket_lookup::selftest::parse_cron(&test.cron).ok()?;
    picket_lookup::cron::next_after(&cron, after)
}

/// The scheduler: runs due tests in the light lane (module docs).
pub async fn run(state: SharedState) {
    let mut was_unsynced = false;
    loop {
        let synced = state.clock.synced();
        if synced && was_unsynced {
            // The times were worked out on an unsynchronised clock: again, now. A save's test is
            // due at once.
            let model = state.lookups.model();
            for id in model.lookup_providers.keys() {
                match state.lookups.selftests.next_of(id) {
                    Some((_, "save")) => state.lookups.selftests.set_next(id, crate::util::now(), "save"),
                    _ => state.lookups.selftests.schedule_initial(&state, id),
                }
            }
        }
        was_unsynced = !synced;
        let now = crate::util::now();
        let model = state.lookups.model();
        for id in model.lookup_providers.keys().filter(|_| synced) {
            let next = state.lookups.selftests.next_of(id);
            let (due, trigger) = match next {
                Some((t, trig)) => (t <= now, trig),
                None => {
                    if let Some(t) = next_scheduled(&state, id, now) {
                        state.lookups.selftests.set_next(id, t, "schedule");
                    }
                    continue;
                }
            };
            if !due {
                continue;
            }
            let running = state
                .lookups
                .selftests
                .running
                .lock()
                .map(|mut r| !r.insert(id.clone()))
                .unwrap_or(true);
            if running {
                continue;
            }
            let st = state.clone();
            let pid = id.clone();
            let spawned = state.scheduler.light.spawn(Some(&super::lane_key(id)), async move {
                if let Err(e) = run_one(&st, &pid, trigger).await {
                    tracing::warn!(provider = %pid, error = %format!("{e:#}"), "a lookup self-test failed to run");
                }
                if let Ok(mut r) = st.lookups.selftests.running.lock() {
                    r.remove(&pid);
                }
            });
            if spawned.is_none()
                && let Ok(mut r) = state.lookups.selftests.running.lock()
            {
                r.remove(id);
            }
        }
        tokio::select! {
            _ = state.shutdown.cancelled() => return,
            _ = state.lookups.selftests.wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    }
}

/// Runs a provider's self-test once and records it; `None` when its module names no test for
/// its config.
pub async fn run_one(
    state: &AppState,
    provider: &str,
    trigger: &str,
) -> anyhow::Result<Option<SelfTestView>> {
    let Some(client) = state.lookups.client(provider) else {
        return Ok(None);
    };
    let Some(run) = client.run_self_test().await else {
        // No test for this config: nothing scheduled.
        if let Ok(mut n) = state.lookups.selftests.next.lock() {
            n.remove(provider);
        }
        return Ok(None);
    };
    let model = state.lookups.model();
    let prior: SelfTestState = {
        let pid = provider.to_string();
        state
            .db
            .read(move |c| {
                let s: Option<Option<String>> = rusqlite::OptionalExtension::optional(c.query_row(
                    "SELECT last_self_test_json FROM lookup_providers WHERE id = ?1",
                    [&pid],
                    |r| r.get(0),
                ))?;
                Ok::<_, anyhow::Error>(
                    s.flatten()
                        .and_then(|s| serde_json::from_str::<SelfTestView>(&s).ok())
                        .map(|v| v.state)
                        .unwrap_or_default(),
                )
            })
            .await?
    };
    let (next_state, action) = picket_lookup::selftest::next_state(prior, &run.result);
    let now = crate::util::now();
    let next_at = match action {
        SelfTestAction::RetestIn(d) => {
            Some(now + jiff::SignedDuration::try_from(d).unwrap_or(jiff::SignedDuration::from_mins(5)))
        }
        _ => next_scheduled(state, provider, now),
    };
    match next_at {
        Some(t) => state.lookups.selftests.set_next(provider, t, "schedule"),
        None => {
            if let Ok(mut n) = state.lookups.selftests.next.lock() {
                n.remove(provider);
            }
        }
    }
    let expect = match run.test.expect {
        Expect::Block => "block",
        Expect::Clean => "clean",
    };
    let (result, verdict, reason, detail, why) = match &run.result {
        SelfTestResult::Pass { verdict, detail } => {
            let (v, r) = verdict_text(verdict);
            ("pass", Some(v.to_string()), r, detail.as_deref().cloned(), None)
        }
        SelfTestResult::Wrong { verdict, detail } => {
            let (v, r) = verdict_text(verdict);
            ("wrong", Some(v.to_string()), r, detail.as_deref().cloned(), None)
        }
        SelfTestResult::Inconclusive { why } => (
            "inconclusive",
            None,
            None,
            None,
            Some(crate::util::sanitize_for_message(why, 300)),
        ),
    };
    let view = SelfTestView {
        at: crate::util::ts(&now),
        name: run.test.name.clone(),
        expect: expect.into(),
        result: result.into(),
        verdict,
        reason,
        detail,
        why,
        state: next_state,
        next_at: next_at.map(|t| crate::util::ts(&t)),
        trigger: trigger.to_string(),
    };
    let pname = model
        .lookup_providers
        .get(provider)
        .map(|p| p.name.clone())
        .unwrap_or_default();
    let key = format!("lookup_self_test_failed:{provider}");
    let raise = (action == SelfTestAction::RaiseAlert).then(|| {
        crate::alerts::RaiseSpec::new(
            "lookup_self_test_failed",
            crate::alerts::Severity::Warning,
            key.clone(),
            format!("Lookup provider {provider} failed its self-test twice"),
            serde_json::json!({
                "provider": provider,
                "provider_name": pname,
                "name": view.name,
                "expect": view.expect,
                "verdict": view.verdict,
                "reason": view.reason,
                "detail": view.detail,
                "flush": {"action": format!("lookup-providers/{provider}/flush"),
                          "label": "Flush cached verdicts"},
            }),
        )
    });
    let resolve = action == SelfTestAction::ResolveAlert;
    let json = serde_json::to_string(&view)?;
    let me = state.alerts.clone();
    let pid = provider.to_string();
    let detail = serde_json::json!({"provider": provider, "name": view.name, "verdict": view.verdict});
    let ch = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE lookup_providers SET last_self_test_json = ?2 WHERE id = ?1",
                rusqlite::params![pid, json],
            )?;
            let mut ch = crate::alerts::Changes::default();
            if let Some(spec) = &raise {
                me.raise_in(&tx, spec, &mut ch)?;
            }
            if resolve {
                me.resolve_in(&tx, &key, Some(&detail), &mut ch)?;
            }
            tx.commit()?;
            me.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    Ok(Some(view))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored suspect test at the end of the timestamp range is retested `RETEST_AFTER` from
    /// now instead of overflowing; an earlier one `RETEST_AFTER` after it; an unreadable one now.
    #[test]
    fn suspect_retest_times() {
        let retest = jiff::SignedDuration::try_from(picket_lookup::selftest::RETEST_AFTER).unwrap();
        let now: Timestamp = "2026-11-26T10:00:00Z".parse().unwrap();
        let end = crate::util::parse_ts("9999-12-30T22:00:00.000000Z");
        assert_eq!(
            end.map(|t| crate::util::ts(&t)).as_deref(),
            Some("9999-12-30T22:00:00.000000Z")
        );
        assert_eq!(suspect_retest_at(end, now, retest), now + retest);
        assert_eq!(suspect_retest_at(Some(Timestamp::MAX), now, retest), now + retest);
        let earlier = now - jiff::SignedDuration::from_mins(2);
        assert_eq!(suspect_retest_at(Some(earlier), now, retest), earlier + retest);
        assert_eq!(suspect_retest_at(None, now, retest), now);
    }
}
