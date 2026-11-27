//! Self-tests (providers.md §4 "Self-tests"): core runs a provider's self-test on its `cron`
//! schedule (UTC), when the provider is saved and from **Test now**. This module has the pure
//! decision logic and the schedule helpers; core keeps the state, schedules the runs and raises
//! and resolves `lookup_self_test_failed` (core.md §9). One run: [`crate::LookupClient::run_self_test`].
//!
//! A wrong verdict is tested again 5 min later: a right one then raises nothing, and a second
//! wrong verdict raises the alert with the answer's detail; the next passing test resolves it.
//! An error, a timeout or a rejection isn't a failed test.

use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{AsyncOutcome, AsyncResult, StoredVerdict};
use crate::module::{Expect, SelfTest};

/// How soon a wrong verdict is tested again.
pub const RETEST_AFTER: Duration = Duration::from_secs(300);
/// The longest `cron` expression accepted.
pub const MAX_CRON: usize = 128;

/// One self-test run.
#[derive(Clone, Debug, PartialEq)]
pub struct SelfTestRun {
    pub test: SelfTest,
    pub result: SelfTestResult,
}

/// What a run found.
#[derive(Clone, Debug, PartialEq)]
pub enum SelfTestResult {
    /// The expected verdict.
    Pass {
        verdict: StoredVerdict,
        detail: Option<Arc<Value>>,
    },
    /// Another verdict (Unknown included): the provider answers but doesn't filter as it
    /// should.
    Wrong {
        verdict: StoredVerdict,
        detail: Option<Arc<Value>>,
    },
    /// No verdict: an error, a timeout, a rejection, a pause, an open breaker, exhausted
    /// limits. Not a failed test.
    Inconclusive { why: String },
}

impl SelfTestResult {
    /// Judges a run's outcome against what the test expects.
    pub fn judge(expect: Expect, outcome: &AsyncOutcome) -> Self {
        let inconclusive = |why: &str| Self::Inconclusive { why: why.to_owned() };
        let (verdict, detail) = match &outcome.result {
            AsyncResult::Answer { verdict, detail, .. } => (verdict.clone(), detail.clone()),
            AsyncResult::Cached { verdict, .. } => (verdict.clone(), None),
            AsyncResult::NameCheck => (StoredVerdict::Unknown, None),
            AsyncResult::Error { message, .. } => return inconclusive(message),
            AsyncResult::Rejected { .. } => return inconclusive("rejected by the provider"),
            AsyncResult::Paused { .. } => return inconclusive("paused after a rejection"),
            AsyncResult::BreakerOpen { .. } => return inconclusive("circuit breaker open"),
            AsyncResult::LimitsExhausted => return inconclusive("limits exhausted"),
            AsyncResult::Cancelled => return inconclusive("cancelled"),
            AsyncResult::GenerationMoved { .. } => return inconclusive("the cache generation moved on"),
            AsyncResult::ClockUnsynced => return inconclusive("the clock isn't synchronised"),
        };
        let right = matches!(
            (expect, &verdict),
            (Expect::Block, StoredVerdict::Block { .. }) | (Expect::Clean, StoredVerdict::Clean)
        );
        if right {
            Self::Pass { verdict, detail }
        } else {
            Self::Wrong { verdict, detail }
        }
    }
}

/// A provider's self-test state, kept by core between runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfTestState {
    /// Passing, or not yet run.
    #[default]
    Ok,
    /// One wrong verdict; a retest is due 5 min later.
    Suspect,
    /// Two wrong verdicts in a row: `lookup_self_test_failed` is raised.
    Failing,
}

/// What core does after a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTestAction {
    Nothing,
    /// Run the test again after this long ([`RETEST_AFTER`]).
    RetestIn(Duration),
    /// Raise `lookup_self_test_failed` with the answer's detail.
    RaiseAlert,
    /// Resolve `lookup_self_test_failed`.
    ResolveAlert,
}

/// The next state and the action for a run's result.
pub fn next_state(state: SelfTestState, result: &SelfTestResult) -> (SelfTestState, SelfTestAction) {
    use SelfTestAction as A;
    use SelfTestState as S;
    match (state, result) {
        (S::Ok, SelfTestResult::Pass { .. }) => (S::Ok, A::Nothing),
        (S::Ok, SelfTestResult::Wrong { .. }) => (S::Suspect, A::RetestIn(RETEST_AFTER)),
        (S::Ok, SelfTestResult::Inconclusive { .. }) => (S::Ok, A::Nothing),
        (S::Suspect, SelfTestResult::Pass { .. }) => (S::Ok, A::Nothing),
        (S::Suspect, SelfTestResult::Wrong { .. }) => (S::Failing, A::RaiseAlert),
        // The retest settled nothing: try again after the same delay.
        (S::Suspect, SelfTestResult::Inconclusive { .. }) => (S::Suspect, A::RetestIn(RETEST_AFTER)),
        (S::Failing, SelfTestResult::Pass { .. }) => (S::Ok, A::ResolveAlert),
        (S::Failing, SelfTestResult::Wrong { .. } | SelfTestResult::Inconclusive { .. }) => {
            (S::Failing, A::Nothing)
        }
    }
}

/// Parses a self-test schedule ([`crate::cron::parse`], UTC); what the config form refuses.
pub fn parse_cron(expr: &str) -> Result<crate::cron::Cron, String> {
    if expr.len() > MAX_CRON {
        return Err(format!("cron expression over {MAX_CRON} bytes"));
    }
    crate::cron::parse(expr).map_err(|e| format!("invalid cron expression: {}", cron_error(&e)))
}

/// croner's message, unless it quotes part of the expression: croner upper-cases the expression
/// and quotes a field of it (`IllegalCharacters`) or numbers parsed from it (`ComponentError`), a
/// transformed fragment of a secret resolved into the field that the redactor wouldn't know
/// (README §2 "Secrets"; review round 2, CR7). The other variants carry fixed text.
fn cron_error(e: &crate::cron::CronError) -> String {
    use crate::cron::CronError;
    match e {
        CronError::IllegalCharacters(_) => "a field holds a character cron doesn't allow".into(),
        CronError::ComponentError(_) => "a field is out of range or malformed".into(),
        other => other.to_string(),
    }
}

/// The next `n` run times after `after`, for the form (providers.md §5 `dns` "Self-test").
pub fn next_runs(expr: &str, after: Timestamp, n: usize) -> Result<Vec<Timestamp>, String> {
    let cron = parse_cron(expr)?;
    let mut out = Vec::with_capacity(n.min(64));
    let mut t = after;
    for _ in 0..n.min(64) {
        let Some(next) = crate::cron::next_after(&cron, t) else {
            break;
        };
        out.push(next);
        t = next;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ErrorKind, Source};

    fn outcome(result: AsyncResult) -> AsyncOutcome {
        AsyncOutcome {
            result,
            generation: "0000000000000001".into(),
            elapsed: Duration::ZERO,
        }
    }

    fn answer(v: StoredVerdict) -> AsyncOutcome {
        outcome(AsyncResult::Answer {
            verdict: v,
            obtained_at: Timestamp::now(),
            detail: None,
            source: Source::Call,
            storable: false,
        })
    }

    fn block() -> StoredVerdict {
        StoredVerdict::Block {
            score: None,
            reason: "blocked".into(),
        }
    }

    /// build-and-test.md §5 "Lookup self-tests": a wrong verdict.
    #[test]
    fn wrong_verdict_retests_then_alerts_then_resolves() {
        let wrong = SelfTestResult::judge(Expect::Block, &answer(StoredVerdict::Clean));
        assert!(matches!(wrong, SelfTestResult::Wrong { .. }));
        let right = SelfTestResult::judge(Expect::Block, &answer(block()));
        assert!(matches!(right, SelfTestResult::Pass { .. }));
        let unknown = SelfTestResult::judge(Expect::Block, &answer(StoredVerdict::Unknown));
        assert!(matches!(unknown, SelfTestResult::Wrong { .. }));

        // Wrong, then right 5 min later: nothing raised.
        let (s, a) = next_state(SelfTestState::Ok, &wrong);
        assert_eq!(
            (s, a),
            (SelfTestState::Suspect, SelfTestAction::RetestIn(RETEST_AFTER))
        );
        assert_eq!(
            next_state(s, &right),
            (SelfTestState::Ok, SelfTestAction::Nothing)
        );
        // Wrong twice: the alert; the next pass resolves it.
        let (s, a) = next_state(s, &wrong);
        assert_eq!((s, a), (SelfTestState::Failing, SelfTestAction::RaiseAlert));
        assert_eq!(
            next_state(s, &wrong),
            (SelfTestState::Failing, SelfTestAction::Nothing)
        );
        assert_eq!(
            next_state(s, &right),
            (SelfTestState::Ok, SelfTestAction::ResolveAlert)
        );
    }

    #[test]
    fn errors_are_not_failed_tests() {
        for r in [
            AsyncResult::Error {
                kind: ErrorKind::Failed,
                message: "timed out".into(),
                timed_out: true,
            },
            AsyncResult::Rejected { retry_after: None },
            AsyncResult::LimitsExhausted,
        ] {
            let res = SelfTestResult::judge(Expect::Block, &outcome(r));
            assert!(matches!(res, SelfTestResult::Inconclusive { .. }));
            assert_eq!(
                next_state(SelfTestState::Ok, &res),
                (SelfTestState::Ok, SelfTestAction::Nothing)
            );
            assert_eq!(
                next_state(SelfTestState::Failing, &res),
                (SelfTestState::Failing, SelfTestAction::Nothing)
            );
        }
    }

    #[test]
    fn cron_schedule() {
        assert!(parse_cron("0 * * * *").is_ok());
        assert!(parse_cron("not a cron").is_err());
        assert!(parse_cron(&"* ".repeat(100)).is_err());
        let after = "2026-11-21T10:15:00Z".parse::<Timestamp>().unwrap();
        let runs = next_runs("0 * * * *", after, 3).unwrap();
        assert_eq!(runs.len(), 3);
        assert_eq!(picket_api::time::format_secs(&runs[0]), "2026-11-21T11:00:00Z");
        assert_eq!(picket_api::time::format_secs(&runs[2]), "2026-11-21T13:00:00Z");
    }

    /// Golden (jiff plan choice D1): each pattern's next 20 run times as croner 4 found them
    /// (`fixtures/cron/croner4-next-runs.txt`): its schedule shapes, names in and out of their
    /// fields, nicknames, `L`, `W` and `#`, the seconds and year fields, and what it refused.
    #[test]
    fn golden_croner4_schedules() {
        let text = include_str!("../../../fixtures/cron/croner4-next-runs.txt");
        let after = picket_api::time::golden::ts_from_nanos(1_794_565_321_123_456_000);
        let mut n = 0;
        for block in text.split("\n= ").skip(1) {
            let mut lines = block.lines();
            let expr = lines.next().unwrap();
            let want: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
            let got = next_runs(expr, after, 20)
                .map(|v| v.iter().map(picket_api::time::format_micros).collect::<Vec<_>>());
            match want.as_slice() {
                ["rejected"] => assert!(got.is_err(), "{expr}: {got:?}"),
                // croner 4 parsed it but never found a time; croner 5 refuses it (jiff plan choice D1).
                ["never"] => assert!(got.is_err(), "{expr}: {got:?}"),
                times => assert_eq!(got.unwrap_or_else(|e| panic!("{expr}: {e}")), times, "{expr}"),
            }
            n += 1;
        }
        assert_eq!(n, 57);
    }
}
