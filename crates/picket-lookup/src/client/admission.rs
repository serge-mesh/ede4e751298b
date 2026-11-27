//! Whether a provider call may start (providers.md §4): the rejection pause, the circuit
//! breaker, `max_inflight` and the token bucket, kept together so one decision sees them all.

use std::time::Duration;

use picket_api::edge_config::{BreakerSettings, LookupLimits, LookupSettings};
use tokio::time::Instant;

/// The longest pause (providers.md §4 "Rejections": `retry_after` at most 1 h; doubling up to
/// 1 h).
pub const MAX_PAUSE: Duration = Duration::from_secs(3600);
/// The first pause after a rejection without `retry_after`.
pub const FIRST_PAUSE: Duration = Duration::from_secs(60);
/// ±20 % jitter on every pause.
pub const PAUSE_JITTER: f64 = 0.2;
/// A hard cap on `max_inflight` ("Bounded").
pub const MAX_INFLIGHT_CAP: u32 = 4096;
/// How soon to look again while the breaker's half-open trials or a pause's probe are out.
const RECHECK: Duration = Duration::from_secs(1);

/// What an admitted call holds: whether it is a half-open trial, the breaker round it was
/// admitted in, and whether it is the probe a pause lets through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ticket {
    pub trial: bool,
    /// The breaker round the call was admitted in (a half-open round, and the closed period
    /// that follows it); only that round's state counts it.
    pub round: u64,
    pub probe: bool,
}

/// Why a call may not start now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Paused after a rejection, until about then.
    Paused { until: Instant },
    /// The breaker is open (or its half-open trials are out), until about then.
    BreakerOpen { until: Instant },
    /// `max_inflight` reached, or the token bucket is empty (`retry_in` is when the next token
    /// comes).
    Limits { retry_in: Option<Duration> },
}

/// How an admitted call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Finish {
    /// The provider answered with a verdict.
    Answer,
    /// `LookupError::Failed`, or the call ran out of `async_timeout_ms`: counts against health.
    Failed,
    /// `LookupError::Other`, a panic or a cancelled call: not counted against health.
    Other,
    Rejected(Option<Duration>),
}

#[derive(Debug)]
pub(crate) struct Admission {
    inflight: u32,
    bucket: TokenBucket,
    breaker: Breaker,
    pause: Pause,
}

impl Admission {
    pub fn new(settings: &LookupSettings, now: Instant) -> Self {
        Self {
            inflight: 0,
            bucket: TokenBucket::new(&settings.limits, now),
            breaker: Breaker::default(),
            pause: Pause::default(),
        }
    }

    /// Admits one call or says why not. The pause comes first, then the breaker, then the
    /// limits; nothing is taken unless the call is admitted.
    pub fn try_admit(&mut self, now: Instant, s: &LookupSettings) -> Result<Ticket, Refusal> {
        let probe = match self.pause.check(now) {
            PauseCheck::Clear => false,
            PauseCheck::Probe => true,
            PauseCheck::Paused(until) => return Err(Refusal::Paused { until }),
        };
        let trial = self
            .breaker
            .check(now, &s.breaker)
            .map_err(|until| Refusal::BreakerOpen { until })?;
        if self.inflight >= max_inflight(&s.limits) {
            return Err(Refusal::Limits { retry_in: None });
        }
        self.bucket
            .try_take(now, &s.limits)
            .map_err(|wait| Refusal::Limits { retry_in: Some(wait) })?;
        if probe {
            self.pause.probe_in_flight = true;
        }
        if trial {
            self.breaker.take_trial();
        }
        self.inflight = self.inflight.saturating_add(1);
        Ok(Ticket {
            trial,
            round: self.breaker.round,
            probe,
        })
    }

    /// Records how an admitted call ended.
    pub fn finish(&mut self, t: Ticket, f: Finish, now: Instant, s: &LookupSettings) {
        self.inflight = self.inflight.saturating_sub(1);
        self.breaker.finish(t, f, now, &s.breaker);
        self.pause.finish(t.probe, f, now);
    }

    /// `Some(until)` while paused, its probe included: sync lookups then apply the fail mode at
    /// once, even ones that would join a call in flight.
    pub fn paused_until(&self, now: Instant) -> Option<Instant> {
        match self.pause.check(now) {
            PauseCheck::Paused(u) => Some(u),
            PauseCheck::Clear | PauseCheck::Probe => None,
        }
    }

    /// The `breaker_open` gauge: the breaker is open now.
    pub fn breaker_open(&self, now: Instant) -> bool {
        matches!(self.breaker.state, BreakerState::Open { until } if now < until)
    }

    /// Calls in flight.
    pub fn inflight(&self) -> u32 {
        self.inflight
    }
}

/// `max_inflight`, at least 1 and at most [`MAX_INFLIGHT_CAP`].
fn max_inflight(l: &LookupLimits) -> u32 {
    l.max_inflight.clamp(1, MAX_INFLIGHT_CAP)
}

// ---------------------------------------------------------------------------------------------

/// The token bucket (`limits.rps`, `limits.burst`). Its tokens survive settings updates; a new
/// `burst` caps them at the next refill. `rps` 0 means no rate limit (`max_inflight` still
/// bounds the calls).
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(l: &LookupLimits, now: Instant) -> Self {
        Self {
            tokens: f64::from(l.burst.max(1)),
            last: now,
        }
    }

    fn try_take(&mut self, now: Instant, l: &LookupLimits) -> Result<(), Duration> {
        if l.rps == 0 {
            self.last = now;
            return Ok(());
        }
        let rate = f64::from(l.rps);
        let burst = f64::from(l.burst.max(1));
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(((1.0 - self.tokens) / rate).max(0.001)))
        }
    }
}

// ---------------------------------------------------------------------------------------------

/// The circuit breaker (`breaker.failures`, `open_s`, `half_open`). Only `Failed` counts
/// against it (providers.md §4): rejections and other errors neither count nor reset it.
/// `failures` 0 turns it off. Each half-open round has a number, carried by the tickets of the
/// calls admitted in it and in the closed period after it, so a call admitted in an earlier round
/// that ends in a later one doesn't move it, whatever the state (review round 2, CR8): a stale
/// trial's failure can't reopen a breaker a newer round closed, and a stale success can't reset
/// the failures the current closed period counts.
#[derive(Debug, Default)]
struct Breaker {
    state: BreakerState,
    /// The current (or last) half-open round; calls admitted while closed carry it too.
    round: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BreakerState {
    /// Consecutive failures so far.
    Closed {
        failures: u32,
    },
    Open {
        until: Instant,
    },
    /// Trials let through and still out, and trials that answered.
    HalfOpen {
        trials: u32,
        successes: u32,
    },
}

impl Default for BreakerState {
    fn default() -> Self {
        Self::Closed { failures: 0 }
    }
}

impl Breaker {
    /// `Ok(is_trial)`, or `Err(until)` while open. An open breaker whose time is up turns
    /// half-open here.
    fn check(&mut self, now: Instant, b: &BreakerSettings) -> Result<bool, Instant> {
        if let BreakerState::Open { until } = self.state {
            if now < until {
                return Err(until);
            }
            self.state = BreakerState::HalfOpen {
                trials: 0,
                successes: 0,
            };
            self.round = self.round.wrapping_add(1);
        }
        match self.state {
            BreakerState::Closed { .. } => Ok(false),
            BreakerState::HalfOpen { trials, .. } if trials < b.half_open.max(1) => Ok(true),
            BreakerState::HalfOpen { .. } | BreakerState::Open { .. } => Err(now + RECHECK),
        }
    }

    fn take_trial(&mut self) {
        if let BreakerState::HalfOpen { trials, .. } = &mut self.state {
            *trials = trials.saturating_add(1);
        }
    }

    /// Records how a call ended; only a call of the current round counts (see [`Breaker`]).
    fn finish(&mut self, t: Ticket, f: Finish, now: Instant, b: &BreakerSettings) {
        let open = |now: Instant| BreakerState::Open {
            until: now + Duration::from_secs(u64::from(b.open_s)),
        };
        let current = t.round == self.round;
        match &mut self.state {
            BreakerState::Closed { failures } if current => match f {
                Finish::Failed if b.failures > 0 => {
                    *failures = failures.saturating_add(1);
                    if *failures >= b.failures {
                        self.state = open(now);
                    }
                }
                Finish::Answer => *failures = 0,
                _ => {}
            },
            BreakerState::HalfOpen { trials, successes } if t.trial && current => {
                *trials = trials.saturating_sub(1);
                match f {
                    Finish::Failed => self.state = open(now),
                    Finish::Answer => {
                        *successes = successes.saturating_add(1);
                        if *successes >= b.half_open.max(1) {
                            self.state = BreakerState::Closed { failures: 0 };
                        }
                    }
                    Finish::Other | Finish::Rejected(_) => {}
                }
            }
            // Calls that started before the breaker opened, calls and trials of an earlier round
            // (their ticket names another round), and non-trial calls while half-open don't move
            // it or free a trial slot.
            BreakerState::Closed { .. } | BreakerState::HalfOpen { .. } | BreakerState::Open { .. } => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------

/// The pause after a rejection (providers.md §4 "Rejections"): until `retry_after` (at most
/// 1 h), or without one 60 s doubling up to 1 h, each with ±20 % jitter. Then one call goes
/// through: an answer ends the pause, another rejection starts the next one; any other end lets
/// the next call probe.
#[derive(Debug, Default)]
struct Pause {
    until: Option<Instant>,
    probe_in_flight: bool,
    /// Rejections in a row, for the doubling.
    consecutive: u32,
}

enum PauseCheck {
    Clear,
    Probe,
    Paused(Instant),
}

impl Pause {
    fn check(&self, now: Instant) -> PauseCheck {
        match self.until {
            None => PauseCheck::Clear,
            Some(until) if now < until => PauseCheck::Paused(until),
            Some(_) if self.probe_in_flight => PauseCheck::Paused(now + RECHECK),
            Some(_) => PauseCheck::Probe,
        }
    }

    fn finish(&mut self, probe: bool, f: Finish, now: Instant) {
        match f {
            Finish::Rejected(retry_after) => {
                if probe || self.until.is_none() {
                    self.consecutive = self.consecutive.saturating_add(1);
                }
                let base = pause_base(retry_after, self.consecutive);
                let until = now + jitter(base);
                self.until = Some(self.until.map_or(until, |u| u.max(until)));
                if probe {
                    self.probe_in_flight = false;
                }
            }
            Finish::Answer => {
                if probe {
                    self.until = None;
                    self.consecutive = 0;
                    self.probe_in_flight = false;
                } else if self.until.is_none() {
                    self.consecutive = 0;
                }
            }
            Finish::Failed | Finish::Other => {
                if probe {
                    self.probe_in_flight = false;
                }
            }
        }
    }
}

/// The pause before jitter: `retry_after` capped at 1 h, or 60 s · 2^(n−1) capped at 1 h for the
/// n-th rejection in a row.
pub(crate) fn pause_base(retry_after: Option<Duration>, consecutive: u32) -> Duration {
    match retry_after {
        Some(d) => d.min(MAX_PAUSE),
        None => {
            let doublings = consecutive.saturating_sub(1).min(16);
            FIRST_PAUSE
                .checked_mul(1u32 << doublings)
                .unwrap_or(MAX_PAUSE)
                .min(MAX_PAUSE)
        }
    }
}

/// `d` ± 20 %.
fn jitter(d: Duration) -> Duration {
    let f = 1.0 - PAUSE_JITTER + 2.0 * PAUSE_JITTER * rand::random::<f64>();
    d.mul_f64(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> LookupSettings {
        LookupSettings::default()
    }

    #[test]
    fn pause_doubling_and_cap() {
        assert_eq!(pause_base(None, 1), Duration::from_secs(60));
        assert_eq!(pause_base(None, 2), Duration::from_secs(120));
        assert_eq!(pause_base(None, 6), Duration::from_secs(1920));
        assert_eq!(pause_base(None, 7), MAX_PAUSE);
        assert_eq!(pause_base(None, 100), MAX_PAUSE);
        assert_eq!(
            pause_base(Some(Duration::from_secs(5)), 3),
            Duration::from_secs(5)
        );
        assert_eq!(pause_base(Some(Duration::from_secs(99_999)), 1), MAX_PAUSE);
        for _ in 0..100 {
            let j = jitter(Duration::from_secs(100));
            assert!(j >= Duration::from_secs(80) && j <= Duration::from_secs(120));
        }
    }

    #[test]
    fn breaker_counts_only_failed() {
        let s = settings();
        let t0 = Instant::now();
        let mut a = Admission::new(&s, t0);
        for _ in 0..10 {
            let t = a.try_admit(t0, &s).unwrap();
            a.finish(t, Finish::Other, t0, &s);
            let t = a.try_admit(t0, &s).unwrap();
            a.finish(t, Finish::Rejected(None), t0, &s);
            // The rejection paused the provider; clear the pause for this test.
            a.pause = Pause::default();
        }
        assert!(!a.breaker_open(t0));
        for _ in 0..5 {
            let t = a.try_admit(t0, &s).unwrap();
            a.finish(t, Finish::Failed, t0, &s);
        }
        assert!(a.breaker_open(t0));
        assert!(matches!(a.try_admit(t0, &s), Err(Refusal::BreakerOpen { .. })));
        // After open_s: half-open, two trials, then closed after two answers.
        let t1 = t0 + Duration::from_secs(30);
        let a1 = a.try_admit(t1, &s).unwrap();
        let a2 = a.try_admit(t1, &s).unwrap();
        assert!(a1.trial && a2.trial);
        assert!(matches!(a.try_admit(t1, &s), Err(Refusal::BreakerOpen { .. })));
        a.finish(a1, Finish::Answer, t1, &s);
        a.finish(a2, Finish::Answer, t1, &s);
        let t = a.try_admit(t1, &s).unwrap();
        assert!(!t.trial);
    }

    #[test]
    fn half_open_failure_reopens() {
        let s = settings();
        let t0 = Instant::now();
        let mut a = Admission::new(&s, t0);
        for _ in 0..5 {
            let t = a.try_admit(t0, &s).unwrap();
            a.finish(t, Finish::Failed, t0, &s);
        }
        let t1 = t0 + Duration::from_secs(31);
        let tr = a.try_admit(t1, &s).unwrap();
        a.finish(tr, Finish::Failed, t1, &s);
        assert!(a.breaker_open(t1));
        assert!(a.breaker_open(t1 + Duration::from_secs(29)));
        assert!(!a.breaker_open(t1 + Duration::from_secs(30)));
    }

    /// Opens the breaker, waits `open_s` and admits `half_open` trials.
    fn half_open_round(a: &mut Admission, s: &LookupSettings, now: Instant) -> Vec<Ticket> {
        while !a.breaker_open(now) {
            let t = a.try_admit(now, s).unwrap();
            a.finish(t, Finish::Failed, now, s);
        }
        let t1 = now + Duration::from_secs(u64::from(s.breaker.open_s));
        let trials: Vec<Ticket> = (0..s.breaker.half_open)
            .map(|_| a.try_admit(t1, s).unwrap())
            .collect();
        assert!(trials.iter().all(|t| t.trial));
        assert!(matches!(a.try_admit(t1, s), Err(Refusal::BreakerOpen { .. })));
        trials
    }

    /// A trial of an earlier half-open round that ends during a later one neither frees one of
    /// its trial slots nor counts toward closing it.
    #[test]
    fn stale_trial_answer_frees_no_slot_and_counts_nothing() {
        let s = settings();
        let t0 = Instant::now();
        let mut a = Admission::new(&s, t0);
        let round1 = half_open_round(&mut a, &s, t0);
        let t1 = t0 + Duration::from_secs(30);
        // The first trial fails: open again; the second is still out.
        a.finish(round1[0], Finish::Failed, t1, &s);
        let t2 = t1 + Duration::from_secs(30);
        let r2a = a.try_admit(t2, &s).unwrap();
        let r2b = a.try_admit(t2, &s).unwrap();
        assert!(r2a.trial && r2b.trial);
        a.finish(round1[1], Finish::Answer, t2, &s);
        assert!(
            matches!(a.try_admit(t2, &s), Err(Refusal::BreakerOpen { .. })),
            "no third concurrent trial"
        );
        a.finish(r2a, Finish::Answer, t2, &s);
        assert!(
            matches!(a.try_admit(t2, &s), Ok(Ticket { trial: true, .. })),
            "one answer of this round: still half-open, its slot free again"
        );
    }

    /// … and its failure doesn't reopen the breaker.
    #[test]
    fn stale_trial_failure_doesnt_reopen() {
        let s = settings();
        let t0 = Instant::now();
        let mut a = Admission::new(&s, t0);
        let round1 = half_open_round(&mut a, &s, t0);
        let t1 = t0 + Duration::from_secs(30);
        a.finish(round1[0], Finish::Failed, t1, &s);
        let t2 = t1 + Duration::from_secs(30);
        let r2a = a.try_admit(t2, &s).unwrap();
        let r2b = a.try_admit(t2, &s).unwrap();
        a.finish(round1[1], Finish::Failed, t2, &s);
        assert!(
            !a.breaker_open(t2),
            "an earlier round's failure doesn't reopen it"
        );
        a.finish(r2a, Finish::Answer, t2, &s);
        a.finish(r2b, Finish::Answer, t2, &s);
        assert!(
            matches!(a.try_admit(t2, &s), Ok(Ticket { trial: false, .. })),
            "closed"
        );
    }

    /// Settings where one failure opens the breaker and two trials close it.
    fn one_failure_two_trials() -> LookupSettings {
        let mut s = settings();
        s.breaker.failures = 1;
        s.breaker.half_open = 2;
        s
    }

    /// Review round 2, CR8: round 1 reopened with a trial still out; round 2 closed the breaker.
    /// The stale round-1 trial ending in failure must not reopen the healthy breaker.
    #[test]
    fn stale_trial_failure_after_a_newer_round_closed_doesnt_reopen() {
        let s = one_failure_two_trials();
        let t0 = Instant::now();
        let mut a = Admission::new(&s, t0);
        let round1 = half_open_round(&mut a, &s, t0);
        let t1 = t0 + Duration::from_secs(30);
        a.finish(round1[0], Finish::Failed, t1, &s);
        let t2 = t1 + Duration::from_secs(30);
        let round2 = [a.try_admit(t2, &s).unwrap(), a.try_admit(t2, &s).unwrap()];
        a.finish(round2[0], Finish::Answer, t2, &s);
        a.finish(round2[1], Finish::Answer, t2, &s);
        assert!(
            matches!(a.try_admit(t2, &s), Ok(Ticket { trial: false, .. })),
            "closed"
        );
        a.finish(round1[1], Finish::Failed, t2, &s);
        assert!(
            !a.breaker_open(t2),
            "a stale round-1 failure reopened a closed breaker"
        );
        // A call of the current closed period still counts.
        let t = a.try_admit(t2, &s).unwrap();
        a.finish(t, Finish::Failed, t2, &s);
        assert!(a.breaker_open(t2));
    }

    /// … and a stale success doesn't reset the consecutive failures the current closed period
    /// has counted; nor does a call admitted before the breaker last opened.
    #[test]
    fn stale_success_doesnt_reset_newer_failures() {
        let mut s = one_failure_two_trials();
        s.breaker.failures = 2;
        let t0 = Instant::now();
        let mut a = Admission::new(&s, t0);
        // A call admitted while first closed, still out when the breaker opens.
        let early = a.try_admit(t0, &s).unwrap();
        let round1 = half_open_round(&mut a, &s, t0);
        let t1 = t0 + Duration::from_secs(30);
        a.finish(round1[0], Finish::Failed, t1, &s);
        let t2 = t1 + Duration::from_secs(30);
        let round2 = [a.try_admit(t2, &s).unwrap(), a.try_admit(t2, &s).unwrap()];
        a.finish(round2[0], Finish::Answer, t2, &s);
        a.finish(round2[1], Finish::Answer, t2, &s);
        // One failure of the current period, then stale successes, then a second failure.
        let f1 = a.try_admit(t2, &s).unwrap();
        a.finish(f1, Finish::Failed, t2, &s);
        a.finish(round1[1], Finish::Answer, t2, &s);
        a.finish(early, Finish::Answer, t2, &s);
        let f2 = a.try_admit(t2, &s).unwrap();
        a.finish(f2, Finish::Failed, t2, &s);
        assert!(a.breaker_open(t2), "stale successes reset the current failures");
    }

    #[test]
    fn token_bucket_and_inflight() {
        let mut s = settings();
        s.limits = LookupLimits {
            max_inflight: 2,
            rps: 10,
            burst: 3,
        };
        let t0 = Instant::now();
        let mut a = Admission::new(&s, t0);
        let x = a.try_admit(t0, &s).unwrap();
        let _y = a.try_admit(t0, &s).unwrap();
        assert_eq!(a.try_admit(t0, &s), Err(Refusal::Limits { retry_in: None }));
        a.finish(x, Finish::Answer, t0, &s);
        let _z = a.try_admit(t0, &s).unwrap();
        a.inflight = 0;
        // Burst of 3 spent; the next token comes after 100 ms.
        match a.try_admit(t0, &s) {
            Err(Refusal::Limits { retry_in: Some(d) }) => {
                assert!(d <= Duration::from_millis(100) && d > Duration::from_millis(90))
            }
            other => panic!("{other:?}"),
        }
        assert!(a.try_admit(t0 + Duration::from_millis(100), &s).is_ok());
    }

    #[test]
    fn pause_probe_cycle() {
        let s = settings();
        let t0 = Instant::now();
        let mut a = Admission::new(&s, t0);
        let t = a.try_admit(t0, &s).unwrap();
        a.finish(t, Finish::Rejected(Some(Duration::from_secs(10))), t0, &s);
        let until = a.paused_until(t0).unwrap();
        assert!(until >= t0 + Duration::from_secs(8) && until <= t0 + Duration::from_secs(12));
        assert!(matches!(a.try_admit(t0, &s), Err(Refusal::Paused { .. })));
        // Time up: one probe goes through, others stay paused while it is out.
        let t1 = t0 + Duration::from_secs(13);
        let probe = a.try_admit(t1, &s).unwrap();
        assert!(probe.probe);
        assert!(matches!(a.try_admit(t1, &s), Err(Refusal::Paused { .. })));
        assert!(a.paused_until(t1).is_some());
        // Another rejection without retry_after: the second in a row, 120 s ± 20 %.
        a.finish(probe, Finish::Rejected(None), t1, &s);
        let until = a.paused_until(t1).unwrap();
        assert!(until >= t1 + Duration::from_secs(96) && until <= t1 + Duration::from_secs(144));
        let t2 = t1 + Duration::from_secs(145);
        let probe = a.try_admit(t2, &s).unwrap();
        assert!(probe.probe);
        // A failure isn't an answer: the next call probes again.
        a.finish(probe, Finish::Failed, t2, &s);
        let probe = a.try_admit(t2, &s).unwrap();
        assert!(probe.probe);
        a.finish(probe, Finish::Answer, t2, &s);
        assert!(a.paused_until(t2).is_none());
        let t = a.try_admit(t2, &s).unwrap();
        assert!(!t.probe);
        assert_eq!(a.pause.consecutive, 0);
    }
}
