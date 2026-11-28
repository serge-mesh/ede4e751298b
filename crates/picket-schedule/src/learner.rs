//! The learned `dynamic` scheduler (feed-scheduling.md §4–§5), per feed.
//!
//! `rate(t) = r[age_bin(t − last_change)] × s[phase_bin(t mod P)]`, expected changes per
//! second, for ten candidate models: one per period P in {1, 2, 3, 4, 6, 8, 12 h, 1 d, 1 w}
//! (phase bins of 1–5 min, 1 h for the week) and one with no period. In a periodic candidate
//! every age ≥ P/2 shares one bin, so phase alone says *when* in the cycle.
//!
//! - **Tables** per candidate: *exposure* (seconds observed, added to every (age, phase) cell an
//!   interval between two successful checks passes through) and *events* (+1 per change in its
//!   cell; an interval-only change goes at the rate-weighted mean time of its interval). Data is
//!   weighted by recency with a 14-day half-life (stored with a growing weight and divided out
//!   when fitting).
//! - **Fit:** `r` and `s` alternately for a few rounds (Poisson MLE: events ÷ exposure); `r`
//!   gets ½ pseudo-event per age bin pulled toward the feed's mean rate, `s` 2 pseudo-events in
//!   total spread over its bins, smoothed ±1 bin.
//! - **Choosing the model:** before each check is added, every candidate is scored by the
//!   log-likelihood of its outcome (no change: `−E`; exact changes: `Σ log rate(tᵢ) − E`; an
//!   interval-only change: `log(1 − e^(−E))`); scores fade with a 7-day half-life, and a
//!   challenger must lead by 3 points to take over.
//! - **Next check:** gap ≈ `k_eff / √rate`, scanning forward in 15 s steps with the running
//!   maximum rate, so a check lands at the start of a predicted window; bounded by the feed's
//!   `min_interval` and the safety interval (1 h; after 2 quiet days, a tenth of the quiet time,
//!   up to 6 h).
//!
//! Failed checks never reach the learner. Times are Unix seconds (`f64`).

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// Data half-life.
pub const DATA_HALF_LIFE: f64 = 14.0 * 86_400.0;
/// Score half-life.
pub const SCORE_HALF_LIFE: f64 = 7.0 * 86_400.0;
/// A challenger's lead before it takes over.
pub const SWITCH_LEAD: f64 = 3.0;
/// The scan step for the next check.
pub const SCAN_STEP: f64 = 15.0;
/// The safety interval, and the dormant one's cap.
pub const SAFETY: f64 = 3_600.0;
pub const DORMANT_AFTER: f64 = 2.0 * 86_400.0;
pub const DORMANT_MAX: f64 = 6.0 * 3_600.0;
/// The prior: one change per 6 h.
pub const PRIOR_RATE: f64 = 1.0 / 21_600.0;
/// The periods of the periodic candidates.
pub const PERIODS: [u64; 9] = [
    3_600, 7_200, 10_800, 14_400, 21_600, 28_800, 43_200, 86_400, 604_800,
];
/// How long the learner keeps change times (backtests, delays).
const HISTORY_SECS: f64 = 60.0 * 86_400.0;
/// The most change times kept (README §2 Bounded).
const MAX_CHANGES: usize = 20_000;
/// Refit at most this often while replaying.
const REFIT_EVERY: f64 = 3_600.0;
/// Rounds of the alternating fit.
const FIT_ROUNDS: usize = 4;

fn phase_width(period: u64) -> u64 {
    match period {
        3_600 => 60,
        7_200 => 120,
        10_800 => 180,
        14_400 => 240,
        604_800 => 3_600,
        _ => 300,
    }
}

/// Age bin edges: 0, then 1 min doubling up to past 60 days.
fn age_edges(cap: Option<f64>) -> Vec<f64> {
    let mut e = vec![0.0];
    let mut x = 60.0;
    while x < 60.0 * 86_400.0 * 2.0 {
        if let Some(c) = cap
            && x >= c
        {
            break;
        }
        e.push(x);
        x *= 2.0;
    }
    if let Some(c) = cap {
        e.push(c);
    }
    e
}

/// One candidate model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub period: Option<u64>,
    phase_w: u64,
    n_phase: usize,
    /// Lower edges of the age bins (the last bin is open-ended).
    edges: Vec<f64>,
    expo: Vec<f64>,
    events: Vec<f64>,
    r: Vec<f64>,
    s: Vec<f64>,
    pub score: f64,
    score_t: f64,
}

impl Candidate {
    fn new(period: Option<u64>) -> Self {
        let (phase_w, n_phase) = match period {
            Some(p) => {
                let w = phase_width(p);
                (w, usize::try_from(p / w).unwrap_or(usize::MAX))
            }
            None => (1, 1),
        };
        let edges = age_edges(period.map(|p| p as f64 / 2.0));
        let n_age = edges.len();
        Self {
            period,
            phase_w,
            n_phase,
            expo: vec![0.0; n_age * n_phase],
            events: vec![0.0; n_age * n_phase],
            r: vec![PRIOR_RATE; n_age],
            s: vec![1.0; n_phase],
            edges,
            score: 0.0,
            score_t: 0.0,
        }
    }

    fn n_age(&self) -> usize {
        self.edges.len()
    }

    fn age_bin(&self, age: f64) -> usize {
        let a = age.max(0.0);
        self.edges.iter().rposition(|e| *e <= a).unwrap_or(0)
    }

    fn phase_bin(&self, t: f64) -> usize {
        match self.period {
            Some(p) => {
                crate::f64_to_usize(t.rem_euclid(p as f64) / self.phase_w as f64).min(self.n_phase - 1)
            }
            None => 0,
        }
    }

    /// The end of the constant-rate segment starting at `t`.
    fn segment_end(&self, t: f64, b: f64, lc: Option<f64>) -> f64 {
        let mut end = b;
        if let Some(l) = lc {
            let ab = self.age_bin(t - l);
            if let Some(next) = self.edges.get(ab + 1) {
                end = end.min(l + next);
            }
        }
        if self.period.is_some() {
            let w = self.phase_w as f64;
            end = end.min(((t / w).floor() + 1.0) * w);
        }
        if end <= t { b.min(t + 1.0) } else { end }
    }

    fn age_of(&self, t: f64, lc: Option<f64>) -> f64 {
        match lc {
            Some(l) => t - l,
            None => f64::MAX / 4.0,
        }
    }

    pub fn rate(&self, t: f64, lc: Option<f64>) -> f64 {
        let a = self.age_bin(self.age_of(t, lc));
        let p = self.phase_bin(t);
        self.r.get(a).copied().unwrap_or(PRIOR_RATE) * self.s.get(p).copied().unwrap_or(1.0)
    }

    /// Expected changes over `(a, b]` with the last change at `lc` and no change inside.
    fn expected(&self, a: f64, b: f64, lc: Option<f64>) -> f64 {
        let mut t = a;
        let mut e = 0.0;
        while t < b {
            let end = self.segment_end(t, b, lc);
            e += (end - t) * self.rate((t + end) / 2.0, lc);
            t = end;
        }
        e
    }

    /// The rate-weighted mean time of `(a, b]`.
    fn placement(&self, a: f64, b: f64, lc: Option<f64>) -> f64 {
        let (mut num, mut den) = (0.0, 0.0);
        let mut t = a;
        while t < b {
            let end = self.segment_end(t, b, lc);
            let m = (t + end) / 2.0;
            let w = (end - t) * self.rate(m, lc);
            num += m * w;
            den += w;
            t = end;
        }
        if den > 0.0 && (num / den).is_finite() {
            (num / den).clamp(a, b)
        } else {
            (a + b) / 2.0
        }
    }

    fn add_exposure(&mut self, a: f64, b: f64, lc: Option<f64>, w: &dyn Fn(f64) -> f64) {
        let mut t = a;
        while t < b {
            let end = self.segment_end(t, b, lc);
            let m = (t + end) / 2.0;
            let ab = self.age_bin(self.age_of(m, lc));
            let pb = self.phase_bin(m);
            if let Some(x) = self.expo.get_mut(ab * self.n_phase + pb) {
                *x += (end - t) * w(m);
            }
            t = end;
        }
    }

    fn add_event(&mut self, c: f64, lc: Option<f64>, w: f64) {
        let ab = self.age_bin(self.age_of(c, lc));
        let pb = self.phase_bin(c);
        if let Some(x) = self.events.get_mut(ab * self.n_phase + pb) {
            *x += w;
        }
    }

    fn scale(&mut self, f: f64) {
        self.expo.iter_mut().for_each(|x| *x *= f);
        self.events.iter_mut().for_each(|x| *x *= f);
    }

    /// Fits `r` and `s` from the decayed tables (`decay` = 1 / current weight).
    fn fit(&mut self, decay: f64) {
        let na = self.n_age();
        let np = self.n_phase;
        if np == 0 || self.expo.len() != na * np || self.events.len() != na * np {
            return;
        }
        // The event counts per age and per phase bin don't change between rounds. (Index loops:
        // they keep unoptimised test builds fast.)
        let mut n_age = vec![0.0; na];
        let mut n_phase = vec![0.0; np];
        for a in 0..na {
            let row = &self.events[a * np..(a + 1) * np];
            for p in 0..np {
                n_age[a] += row[p];
                n_phase[p] += row[p];
            }
        }
        let total_n = n_age.iter().sum::<f64>() * decay;
        let total_e = self.expo.iter().sum::<f64>() * decay;
        let mean = (total_n + 0.5) / (total_e + 0.5 / PRIOR_RATE);
        let mut s = vec![1.0; np];
        let mut r = vec![mean; na];
        let mut e_phase = vec![0.0; np];
        let mut raw = vec![1.0; np];
        for _ in 0..FIT_ROUNDS {
            for a in 0..na {
                let row = &self.expo[a * np..(a + 1) * np];
                let mut e = 0.0;
                for p in 0..np {
                    e += row[p] * s[p];
                }
                r[a] = (n_age[a] * decay + 0.5) / (e * decay + 0.5 / mean);
            }
            if np > 1 {
                let prior = 2.0 / np as f64;
                e_phase.iter_mut().for_each(|x| *x = 0.0);
                for a in 0..na {
                    let row = &self.expo[a * np..(a + 1) * np];
                    for p in 0..np {
                        e_phase[p] += row[p] * r[a];
                    }
                }
                // `e` is in expected changes (exposure × r), so a prior of `prior` events over
                // `prior` expected changes pulls s toward 1.
                for p in 0..np {
                    raw[p] = (n_phase[p] * decay + prior) / (e_phase[p] * decay + prior);
                }
                for p in 0..np {
                    s[p] = (raw[(p + np - 1) % np] + raw[p] + raw[(p + 1) % np]) / 3.0;
                }
                let avg = s.iter().sum::<f64>() / np as f64;
                if avg > 0.0 && avg.is_finite() {
                    s.iter_mut().for_each(|x| *x /= avg);
                }
            }
        }
        if r.iter().chain(s.iter()).all(|x| x.is_finite() && *x >= 0.0) {
            self.r = r;
            self.s = s;
        }
    }

    fn fade(&mut self, t: f64) {
        if t > self.score_t {
            self.score *= 0.5f64.powf((t - self.score_t) / SCORE_HALF_LIFE);
            self.score_t = t;
        }
    }

    /// The phase bin with the highest `s`, and that `s`.
    fn peak(&self) -> (usize, f64) {
        self.s
            .iter()
            .enumerate()
            .fold((0, 0.0), |acc, (i, v)| if *v > acc.1 { (i, *v) } else { acc })
    }
}

/// A candidate's fitted model without its tables: what `feed_stale` freezes at each change
/// (feed-scheduling.md §8). Small (the age and phase rates), serialisable, and never trained.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Frozen {
    pub period: Option<u64>,
    phase_w: u64,
    n_phase: usize,
    edges: Vec<f64>,
    r: Vec<f64>,
    s: Vec<f64>,
}

impl Frozen {
    fn age_bin(&self, age: f64) -> usize {
        let a = age.max(0.0);
        self.edges.iter().rposition(|e| *e <= a).unwrap_or(0)
    }

    fn phase_bin(&self, t: f64) -> usize {
        match self.period {
            Some(p) if self.n_phase > 0 && self.phase_w > 0 => {
                crate::f64_to_usize(t.rem_euclid(p as f64) / self.phase_w as f64).min(self.n_phase - 1)
            }
            _ => 0,
        }
    }

    fn rate(&self, t: f64, lc: f64) -> f64 {
        let a = self.age_bin(t - lc);
        let p = self.phase_bin(t);
        self.r.get(a).copied().unwrap_or(PRIOR_RATE) * self.s.get(p).copied().unwrap_or(1.0)
    }

    fn segment_end(&self, t: f64, b: f64, lc: f64) -> f64 {
        let mut end = b;
        let ab = self.age_bin(t - lc);
        if let Some(next) = self.edges.get(ab + 1) {
            end = end.min(lc + next);
        }
        if self.period.is_some() && self.phase_w > 0 {
            let w = self.phase_w as f64;
            end = end.min(((t / w).floor() + 1.0) * w);
        }
        if end <= t { b.min(t + 1.0) } else { end }
    }

    /// The changes this model expects over `(lc, t]` with the last change at `lc` and none
    /// since: `E` of feed-scheduling.md §8. Bounded: at most 100,000 segments.
    pub fn expected_since(&self, lc: f64, t: f64) -> f64 {
        let mut x = lc;
        let mut e = 0.0;
        let mut steps = 0usize;
        while x < t && steps < 100_000 {
            let end = self.segment_end(x, t, lc);
            e += (end - x) * self.rate((x + end) / 2.0, lc);
            x = end;
            steps += 1;
        }
        if x < t {
            // Past the bound: the rest at the last rate.
            e += (t - x) * self.rate(t, lc);
        }
        e
    }
}

/// One successful check's outcome, for the learner.
#[derive(Clone, Debug, PartialEq)]
pub struct Obs {
    pub t: f64,
    /// Exact change times.
    pub exact: Vec<f64>,
    /// A change somewhere in the interval, time unknown.
    pub interval: bool,
}

/// The learner of one feed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Learner {
    cands: Vec<Candidate>,
    pub best: usize,
    pub last_change: Option<f64>,
    pub prev_ok: Option<f64>,
    t0: f64,
    fitted_at: f64,
    /// Aggressiveness (feed-scheduling.md §5).
    pub k: f64,
    /// When `k` was last chosen.
    pub k_chosen_at: Option<f64>,
    /// Change times (exact, or placed), newest last.
    pub changes: VecDeque<f64>,
    /// Checks the learner saw, newest last (times), for the counts the UI shows.
    pub checks: VecDeque<f64>,
}

impl Default for Learner {
    fn default() -> Self {
        Self::new()
    }
}

impl Learner {
    pub fn new() -> Self {
        let mut cands: Vec<Candidate> = PERIODS.iter().map(|p| Candidate::new(Some(*p))).collect();
        cands.push(Candidate::new(None));
        let best = cands.len() - 1;
        Self {
            cands,
            best,
            last_change: None,
            prev_ok: None,
            t0: 0.0,
            fitted_at: f64::MIN,
            k: 3.0,
            k_chosen_at: None,
            changes: VecDeque::new(),
            checks: VecDeque::new(),
        }
    }

    /// The candidates (for the UI and tests).
    pub fn candidates(&self) -> &[Candidate] {
        &self.cands
    }

    fn weight(&self, t: f64) -> f64 {
        2f64.powf((t - self.t0) / DATA_HALF_LIFE)
    }

    /// Keeps weights in range: rescales the tables when they grow too large.
    fn rebase(&mut self, t: f64) {
        if self.t0 == 0.0 {
            self.t0 = t;
            return;
        }
        if (t - self.t0) / DATA_HALF_LIFE > 200.0 {
            let f = 1.0 / self.weight(t);
            for c in &mut self.cands {
                c.scale(f);
            }
            self.t0 = t;
        }
    }

    /// Copies a sibling's tables at ⅕ weight (feed-scheduling.md §6, `http` warm start).
    pub fn warm_from(&mut self, sibling: &Learner) {
        // Re-express the sibling's weighted values in this learner's weight scale.
        let f = if self.t0 == 0.0 {
            0.2
        } else {
            0.2 * self.weight(sibling.t0)
        };
        for (c, s) in self.cands.iter_mut().zip(sibling.cands.iter()) {
            if c.expo.len() == s.expo.len() {
                for (a, b) in c.expo.iter_mut().zip(s.expo.iter()) {
                    *a += b * f;
                }
                for (a, b) in c.events.iter_mut().zip(s.events.iter()) {
                    *a += b * f;
                }
            }
        }
        if self.t0 == 0.0 {
            self.t0 = sibling.t0;
        }
        self.best = sibling.best;
        self.refit(sibling.fitted_at.max(self.fitted_at));
    }

    /// The driving candidate's fitted model, frozen (feed-scheduling.md §8).
    pub fn frozen(&self) -> Frozen {
        let c = &self.cands[self.best];
        Frozen {
            period: c.period,
            phase_w: c.phase_w,
            n_phase: c.n_phase,
            edges: c.edges.clone(),
            r: c.r.clone(),
            s: c.s.clone(),
        }
    }

    /// Fits every candidate as of `now`.
    pub fn refit(&mut self, now: f64) {
        let decay = 1.0 / self.weight(now);
        for c in &mut self.cands {
            c.fit(decay);
        }
        self.fitted_at = now;
    }

    /// The best candidate's rate at `t`, given no change since the last one.
    pub fn rate(&self, t: f64) -> f64 {
        self.cands[self.best].rate(t, self.last_change)
    }

    /// Adds one successful check (feed-scheduling.md §4). `refit`: refit afterwards (live
    /// checks); a replay refits hourly.
    pub fn observe(&mut self, obs: &Obs, refit: bool) {
        let t = obs.t;
        self.checks.push_back(t);
        while self.checks.len() > 50_000 || self.checks.front().is_some_and(|c| t - c > HISTORY_SECS) {
            self.checks.pop_front();
        }
        let Some(prev) = self.prev_ok else {
            self.rebase(t);
            self.prev_ok = Some(t);
            for c in obs.exact.iter().filter(|c| **c <= t) {
                self.last_change = Some(self.last_change.map_or(*c, |l| l.max(*c)));
            }
            return;
        };
        if t <= prev {
            return;
        }
        self.rebase(t);
        // An exact time outside (prev, t] is an interval (feed-scheduling.md §3).
        let mut exact: Vec<f64> = obs
            .exact
            .iter()
            .copied()
            .filter(|c| *c > prev && *c <= t)
            .collect();
        exact.sort_by(f64::total_cmp);
        exact.dedup();
        let interval = obs.interval || exact.len() < obs.exact.len();
        let interval = interval && exact.is_empty();
        let lc0 = self.last_change;
        // 1. Score every candidate on this outcome.
        for c in &mut self.cands {
            c.fade(t);
            let ll = if !exact.is_empty() {
                let mut ll = 0.0;
                let mut a = prev;
                let mut lc = lc0;
                for &ch in &exact {
                    ll -= c.expected(a, ch, lc);
                    ll += c.rate(ch, lc).max(1e-12).ln();
                    a = ch;
                    lc = Some(ch);
                }
                ll - c.expected(a, t, lc)
            } else if interval {
                let e = c.expected(prev, t, lc0);
                (1.0 - (-e).exp()).max(1e-12).ln()
            } else {
                -c.expected(prev, t, lc0)
            };
            c.score += ll.max(-50.0);
        }
        // 2. The best recent scorer drives scheduling; a challenger leads by 3 points.
        let (top, top_score) = self
            .cands
            .iter()
            .enumerate()
            .fold((self.best, f64::MIN), |acc, (i, c)| {
                if c.score > acc.1 { (i, c.score) } else { acc }
            });
        if top != self.best && top_score >= self.cands[self.best].score + SWITCH_LEAD {
            self.best = top;
        }
        // 3. Exposure and events.
        let changes: Vec<f64> = if interval {
            vec![self.cands[self.best].placement(prev, t, lc0)]
        } else {
            exact
        };
        let wf = {
            let t0 = self.t0;
            move |x: f64| 2f64.powf((x - t0) / DATA_HALF_LIFE)
        };
        for c in &mut self.cands {
            let mut a = prev;
            let mut lc = lc0;
            for &ch in &changes {
                c.add_exposure(a, ch, lc, &wf);
                c.add_event(ch, lc, wf(ch));
                a = ch;
                lc = Some(ch);
            }
            c.add_exposure(a, t, lc, &wf);
        }
        for &ch in &changes {
            self.changes.push_back(ch);
            self.last_change = Some(ch);
        }
        while self.changes.len() > MAX_CHANGES || self.changes.front().is_some_and(|c| t - c > HISTORY_SECS) {
            self.changes.pop_front();
        }
        self.prev_ok = Some(t);
        if refit || t - self.fitted_at >= REFIT_EVERY {
            self.refit(t);
        }
    }

    /// Replays observations (start-up, daily rebuild, backtests).
    pub fn replay(obs: &[Obs]) -> Self {
        let mut l = Self::new();
        for o in obs {
            l.observe(o, false);
        }
        if let Some(last) = obs.last() {
            l.refit(last.t);
        }
        l
    }

    /// The safety interval at `now`: 1 h, or after 2 quiet days a tenth of the quiet time, up
    /// to 6 h.
    pub fn safety(&self, now: f64) -> f64 {
        let quiet = match self.last_change {
            Some(l) => now - l,
            None => self.checks.front().map_or(0.0, |f| now - f),
        };
        if quiet >= DORMANT_AFTER {
            (quiet / 10.0).clamp(SAFETY, DORMANT_MAX)
        } else {
            SAFETY
        }
    }

    /// The next check after `last_check` (feed-scheduling.md §5). `k_eff` is `k` times the
    /// cost factor.
    pub fn next_check(&self, last_check: f64, min_interval: f64, k_eff: f64) -> f64 {
        let safety = self.safety(last_check).max(min_interval);
        let c = &self.cands[self.best];
        let mut t = last_check;
        let mut maxrate: f64 = 0.0;
        loop {
            t += SCAN_STEP;
            let gap = t - last_check;
            if gap >= safety {
                return last_check + safety;
            }
            maxrate = maxrate.max(c.rate(t, self.last_change));
            if maxrate > 0.0 && gap >= k_eff / maxrate.sqrt() {
                return t.max(last_check + min_interval);
            }
        }
    }

    /// The learned pattern in words (feed-scheduling.md §6 UI).
    pub fn describe(&self, now: f64) -> String {
        let per_day = {
            let recent = self
                .changes
                .iter()
                .filter(|c| now - **c <= 7.0 * 86_400.0)
                .count();
            recent as f64 / 7.0
        };
        let freq = if per_day >= 1.0 {
            format!("about {per_day:.0} changes a day")
        } else if per_day > 0.0 {
            format!("about {:.0} changes a week", per_day * 7.0)
        } else {
            "no change in the last week".to_string()
        };
        let c = &self.cands[self.best];
        match c.period {
            None => format!("no regular pattern; {freq}"),
            Some(_) => {
                // A daily pattern that repeats every hour reads as hourly: the shortest period
                // the phase profile repeats at.
                let p = self.shortest_repeat(c);
                let folded = self.cands.iter().find(|x| x.period == Some(p)).unwrap_or(c);
                let c = if folded.n_phase > 1 { folded } else { c };
                let (bin, peak) = c.peak();
                if peak < 1.5 {
                    return format!("no clear time in a {}-cycle; {freq}", period_words(p));
                }
                let off = bin as u64 * c.phase_w;
                let when = match p {
                    604_800 => {
                        let day = [
                            "Thursday",
                            "Friday",
                            "Saturday",
                            "Sunday",
                            "Monday",
                            "Tuesday",
                            "Wednesday",
                        ][((off / 86_400) % 7) as usize];
                        format!("weekly on {day} around {:02}:00 UTC", (off % 86_400) / 3_600)
                    }
                    86_400 => format!("daily at {:02}:{:02} UTC", off / 3_600, (off % 3_600) / 60),
                    3_600 => format!("every hour at :{:02}", off / 60),
                    _ => format!(
                        "every {} at {:02}:{:02} UTC (and every {} after)",
                        period_words(p),
                        off / 3_600,
                        (off % 3_600) / 60,
                        period_words(p)
                    ),
                };
                format!("{when}; {freq}")
            }
        }
    }
}

impl Learner {
    /// The shortest candidate period whose cycle `c`'s phase profile repeats (within 35 % of
    /// its peak), so equivalent longer periods aren't reported.
    fn shortest_repeat(&self, c: &Candidate) -> u64 {
        let Some(p) = c.period else { return 0 };
        let peak = c.s.iter().copied().fold(0.0, f64::max);
        if peak <= 0.0 {
            return p;
        }
        for q in PERIODS {
            if q >= p || p % q != 0 || q % c.phase_w != 0 {
                continue;
            }
            let shift = usize::try_from(q / c.phase_w).unwrap_or(usize::MAX);
            let n = c.n_phase;
            let repeats = (0..n).all(|i| (c.s[i] - c.s[(i + shift) % n]).abs() <= 0.35 * peak);
            if repeats {
                return q;
            }
        }
        p
    }
}

fn period_words(p: u64) -> String {
    match p {
        604_800 => "week".into(),
        86_400 => "day".into(),
        p => format!("{} h", p / 3_600),
    }
}

/// A simulated stretch of checks (feed-scheduling.md §5 `k` choice, the `backtest` endpoint).
#[derive(Clone, Debug, Default, PartialEq, Serialize, schemars::JsonSchema)]
pub struct SimResult {
    pub k: f64,
    pub changes: usize,
    /// Changes caught within 2 minutes.
    pub caught_2min: usize,
    pub checks: usize,
    pub checks_per_day: f64,
    pub share_2min: f64,
    pub median_delay_s: Option<f64>,
    pub p90_delay_s: Option<f64>,
    /// A provider replay's result per feed, in the order of its feeds, so an aggregate never
    /// hides one feed's losses (empty for a single-feed simulation, `simulate`).
    pub feeds: Vec<FeedSim>,
}

/// One feed's part of a provider replay (`SimResult::feeds`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, schemars::JsonSchema)]
pub struct FeedSim {
    pub changes: usize,
    /// Changes caught within 2 minutes.
    pub caught_2min: usize,
    /// `caught_2min ÷ changes` (1 without changes).
    pub share_2min: f64,
}

impl FeedSim {
    fn new(changes: usize, caught_2min: usize) -> Self {
        Self {
            changes,
            caught_2min,
            share_2min: if changes == 0 {
                1.0
            } else {
                caught_2min as f64 / changes as f64
            },
        }
    }
}

/// Replays `[start, end)` with simulated checks: `base` is the learner trained on what came
/// before `start`, `changes` the true change times (exact, or placed where the learner placed
/// them).
pub fn simulate(
    base: &Learner,
    changes: &[f64],
    start: f64,
    end: f64,
    k: f64,
    cost_factor: f64,
    min_interval: f64,
) -> SimResult {
    let mut l = base.clone();
    let mut last = start;
    if l.prev_ok.is_none() {
        l.prev_ok = Some(start);
    }
    let mut sorted: Vec<f64> = changes
        .iter()
        .copied()
        .filter(|c| *c >= start && *c < end)
        .collect();
    sorted.sort_by(f64::total_cmp);
    let mut delays = Vec::new();
    let mut checks = 0usize;
    let mut i = 0usize;
    let k_eff = k * cost_factor;
    loop {
        let next = l.next_check(last, min_interval, k_eff);
        if next >= end {
            break;
        }
        let mut seen = Vec::new();
        while i < sorted.len() && sorted[i] <= next {
            seen.push(sorted[i]);
            i += 1;
        }
        for c in &seen {
            delays.push(next - c);
        }
        l.observe(
            &Obs {
                t: next,
                exact: seen,
                interval: false,
            },
            false,
        );
        checks += 1;
        last = next;
    }
    let days = ((end - start) / 86_400.0).max(1.0 / 24.0);
    let caught = delays.iter().filter(|d| **d <= 120.0).count();
    delays.sort_by(f64::total_cmp);
    let pct = |q: f64| -> Option<f64> {
        if delays.is_empty() {
            None
        } else {
            let idx = crate::f64_to_usize(((delays.len() as f64 - 1.0) * q).round());
            delays.get(idx).copied()
        }
    };
    SimResult {
        k,
        changes: sorted.len(),
        caught_2min: caught,
        checks,
        checks_per_day: checks as f64 / days,
        share_2min: if sorted.is_empty() {
            1.0
        } else {
            caught as f64 / sorted.len() as f64
        },
        median_delay_s: pct(0.5),
        p90_delay_s: pct(0.9),
        feeds: vec![],
    }
}

/// A feed's ask after a successful check of its provider at `t` (feed-scheduling.md §5
/// "Spacing"): `fresh`, the ask spaced from `t`, unless the check came before the feed's
/// `pending` ask and found none of its changes (a sibling's check, or a manual one). That check
/// still trains the model, but it never moves the feed's ask later: the feed keeps the gap
/// counted from its own last check, so a sibling's check just before a predicted window doesn't
/// push this feed's check past the window's start.
pub fn respace<T: PartialOrd + Copy>(pending: Option<T>, fresh: T, t: T, changed: bool) -> T {
    match pending {
        Some(p) if p > t && !changed && p < fresh => p,
        _ => fresh,
    }
}

/// [`simulate`] for a feed provider (feed-scheduling.md §5): one check covers every feed, and the
/// provider is checked at its feeds' earliest ask, each feed's ask spaced from its own last check
/// ([`respace`]). `feeds` pairs each feed's learner (trained on what came before `start`) with its
/// true change times; delays count every feed's changes.
pub fn simulate_provider(
    feeds: &[(Learner, Vec<f64>)],
    start: f64,
    end: f64,
    k: f64,
    cost_factor: f64,
    min_interval: f64,
) -> SimResult {
    let mut ls: Vec<Learner> = feeds.iter().map(|(l, _)| l.clone()).collect();
    for l in &mut ls {
        if l.prev_ok.is_none() {
            l.prev_ok = Some(start);
        }
    }
    let sorted: Vec<Vec<f64>> = feeds
        .iter()
        .map(|(_, c)| {
            let mut v: Vec<f64> = c.iter().copied().filter(|x| *x >= start && *x < end).collect();
            v.sort_by(f64::total_cmp);
            v
        })
        .collect();
    let total: usize = sorted.iter().map(Vec::len).sum();
    let mut idx = vec![0usize; ls.len()];
    let mut caught_by_feed = vec![0usize; ls.len()];
    let mut delays = Vec::new();
    let mut checks = 0usize;
    let mut last = start;
    let k_eff = k * cost_factor;
    if ls.is_empty() {
        return SimResult {
            k,
            share_2min: 1.0,
            ..SimResult::default()
        };
    }
    // Each feed's pending ask, spaced from its own last check (§5 "Spacing": [`respace`]).
    let mut asks: Vec<f64> = ls
        .iter()
        .map(|l| l.next_check(start, min_interval, k_eff))
        .collect();
    loop {
        // Due at the earliest ask, never sooner than `min_interval` after the previous check.
        let next = asks
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min)
            .max(last + min_interval);
        if !next.is_finite() || next >= end {
            break;
        }
        for (j, l) in ls.iter_mut().enumerate() {
            let mut seen = Vec::new();
            while idx[j] < sorted[j].len() && sorted[j][idx[j]] <= next {
                seen.push(sorted[j][idx[j]]);
                idx[j] += 1;
            }
            for c in &seen {
                delays.push(next - c);
                if next - c <= 120.0 {
                    caught_by_feed[j] += 1;
                }
            }
            let changed = !seen.is_empty();
            l.observe(
                &Obs {
                    t: next,
                    exact: seen,
                    interval: false,
                },
                false,
            );
            asks[j] = respace(
                Some(asks[j]),
                l.next_check(next, min_interval, k_eff),
                next,
                changed,
            );
        }
        checks += 1;
        last = next;
    }
    let days = ((end - start) / 86_400.0).max(1.0 / 24.0);
    let caught = delays.iter().filter(|d| **d <= 120.0).count();
    delays.sort_by(f64::total_cmp);
    let pct = |q: f64| -> Option<f64> {
        if delays.is_empty() {
            None
        } else {
            delays
                .get(crate::f64_to_usize(((delays.len() as f64 - 1.0) * q).round()))
                .copied()
        }
    };
    SimResult {
        k,
        changes: total,
        caught_2min: caught,
        checks,
        checks_per_day: checks as f64 / days,
        share_2min: if total == 0 {
            1.0
        } else {
            caught as f64 / total as f64
        },
        median_delay_s: pct(0.5),
        p90_delay_s: pct(0.9),
        feeds: sorted
            .iter()
            .zip(&caught_by_feed)
            .map(|(c, n)| FeedSim::new(c.len(), *n))
            .collect(),
    }
}

/// The `k` values tried each week.
pub const K_CHOICES: [f64; 4] = [1.0, 2.0, 3.0, 5.0];
/// The per-provider **planning budget** (feed-scheduling.md §5): the checks a day a provider's
/// replayed schedule may predict when the weekly choice picks its `k`. It shapes which `k` is
/// chosen and nothing else: it is not a runtime quota (when no `k` fits, the least aggressive is
/// used anyway, [`BudgetFit::NoneFits`]), it guarantees no detection rate (the backtests measure
/// that, per feed, [`crate::backtest`]), and it isn't what keeps core from asking a server too
/// often (the error backoff, `min_interval` and server cooldowns do that, in core).
pub const BUDGET_PER_DAY: f64 = 400.0;
/// The days the weekly `k` replay covers (feed-scheduling.md §5): long enough that a feed
/// changing once a day brings ~28 changes, so one change more or less is noise, not a verdict.
pub const K_REPLAY_DAYS: f64 = 28.0;
/// What one caught change is worth in checks (feed-scheduling.md §5): a more aggressive `k` must
/// catch one more of a feed's changes within 2 min per this many extra checks of it.
pub const CHECKS_PER_CHANGE: usize = 300;

const DAY: f64 = 86_400.0;

/// Where a feed's weekly `k` replay starts (feed-scheduling.md §5): [`K_REPLAY_DAYS`] before
/// `now`, but not before `own_since`, when its own checks in its current epoch began (before it
/// the feed has only its warm start, and a replay from there scores a learner that knew nothing,
/// which favours the most aggressive `k`). `None` (the feed sits the choice out) while it has no
/// own check, or less than a day of them.
pub fn k_replay_start(now: f64, own_since: Option<f64>) -> Option<f64> {
    let start = (now - K_REPLAY_DAYS * DAY).max(own_since?);
    (now - start >= DAY).then_some(start)
}

/// When a feed's own checks in its current epoch began, for the `k` replay (§5): its first
/// successful check that wasn't its warm start, or the warm start's read if that came later (a
/// delayed warm start records the history it read as a change at the read, which the replay must
/// not score). `None` while it has no successful check.
pub fn own_since(first_check: Option<f64>, warm_started: Option<f64>) -> Option<f64> {
    let first = first_check?;
    Some(warm_started.map_or(first, |w| first.max(w)))
}

/// [`k_replay_start`] for each feed of a provider, from its `(first_check, warm_started)`
/// ([`own_since`]): each feed replays from its own checks, so a new feed doesn't shorten a mature
/// one's span and a feed without a successful check doesn't hold the others back.
pub fn k_replay_starts(now: f64, feeds: &[(Option<f64>, Option<f64>)]) -> Vec<Option<f64>> {
    feeds
        .iter()
        .map(|(first, warm)| k_replay_start(now, own_since(*first, *warm)))
        .collect()
}

/// Picks a feed's `k` from its replay alone (feed-scheduling.md §5): within the budget, the `k`
/// whose `CHECKS_PER_CHANGE × caught − checks` is largest (changes caught within 2 min net of
/// the checks they took; on a tie, the one with fewer checks); if none fits the budget, the
/// largest. `None` (no opinion) when the replay saw no change. Integer scores, so a tie is a tie.
pub fn choose_k(results: &[SimResult]) -> Option<f64> {
    if results.is_empty() || results.iter().all(|r| r.changes == 0) {
        return None;
    }
    let net = |r: &SimResult| CHECKS_PER_CHANGE as i128 * r.caught_2min as i128 - r.checks as i128;
    results
        .iter()
        .filter(|r| r.checks_per_day <= BUDGET_PER_DAY)
        .min_by(|a, b| net(b).cmp(&net(a)).then(a.checks.cmp(&b.checks)))
        .map(|r| r.k)
        .or_else(|| results.iter().map(|r| r.k).reduce(f64::max))
}

/// The provider's `k` (feed-scheduling.md §5): the most aggressive (smallest) of its feeds' own
/// choices, each from that feed's replay alone ([`choose_k`]), so no feed is checked less
/// eagerly than it would be alone, and feeds that change together don't count a change twice;
/// but if `pooled` (the replay of all those feeds together) puts that `k` over the budget, the
/// most aggressive `k` that keeps within it, else the largest. `None` (keep `k`) when no feed
/// has a choice. [`provider_k_choice`] says how the budget shaped it.
pub fn provider_k<'a>(
    per_feed: impl IntoIterator<Item = &'a [SimResult]>,
    pooled: &[SimResult],
) -> Option<f64> {
    provider_k_choice(per_feed, pooled).map(|c| c.k)
}

/// How the planning budget shaped a provider's `k` (`KChoice::budget`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetFit {
    /// The feeds' preferred `k` fits the budget: the provider takes it.
    Within,
    /// The preferred `k` predicts more checks a day than the budget: the provider takes the most
    /// aggressive `k` that fits, less eager than its feeds would be.
    Slowed,
    /// No `k` fits: the least aggressive is taken anyway (the budget is no runtime ceiling).
    NoneFits,
}

/// The weekly `k` choice of a provider with the planning budget's part in it (`provider_k`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KChoice {
    /// The `k` taken.
    pub k: f64,
    /// The most aggressive of the feeds' own choices: what the provider would take without the
    /// budget.
    pub preferred: f64,
    pub budget: BudgetFit,
    /// The pooled replay's predicted checks a day at `preferred` and at `k` (`None` when it
    /// didn't replay that `k`).
    pub preferred_checks_per_day: Option<f64>,
    pub checks_per_day: Option<f64>,
}

/// [`provider_k`] with how the budget shaped the choice.
pub fn provider_k_choice<'a>(
    per_feed: impl IntoIterator<Item = &'a [SimResult]>,
    pooled: &[SimResult],
) -> Option<KChoice> {
    let preferred = per_feed.into_iter().filter_map(choose_k).reduce(f64::min)?;
    let cpd = |k: f64| pooled.iter().find(|r| r.k == k).map(|r| r.checks_per_day);
    let fits = |k: f64| cpd(k).is_none_or(|c| c <= BUDGET_PER_DAY);
    let fitting = K_CHOICES
        .iter()
        .copied()
        .filter(|k| *k >= preferred)
        .find(|k| fits(*k));
    let (k, budget) = match fitting {
        Some(k) if k == preferred => (k, BudgetFit::Within),
        Some(k) => (k, BudgetFit::Slowed),
        None => (
            K_CHOICES.iter().copied().fold(preferred, f64::max),
            BudgetFit::NoneFits,
        ),
    };
    Some(KChoice {
        k,
        preferred,
        budget,
        preferred_checks_per_day: cpd(preferred),
        checks_per_day: cpd(k),
    })
}

/// One feed's estimated cost of a budget-driven compromise (`slowed`, `none_fits`): its share of
/// changes caught within 2 minutes on its standalone schedule (alone, at its own choice) against
/// the provider's (beside its siblings, at the `k` taken), both replayed over the same window.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedImpact {
    pub feed: String,
    /// The feed's own choice (`choose_k`); `None` when its replay saw no change.
    pub standalone_k: Option<f64>,
    /// Its changes in the window.
    pub changes: usize,
    pub standalone_share_2min: f64,
    pub grouped_share_2min: f64,
    /// `grouped − standalone`, in percentage points (negative: the compromise costs this feed).
    pub change_points: f64,
}

impl FeedImpact {
    /// The impact from the two shares (0–1).
    pub fn new(
        feed: String,
        standalone_k: Option<f64>,
        changes: usize,
        standalone_share_2min: f64,
        grouped_share_2min: f64,
    ) -> Self {
        Self {
            feed,
            standalone_k,
            changes,
            standalone_share_2min,
            grouped_share_2min,
            change_points: (grouped_share_2min - standalone_share_2min) * 100.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic histories; the acceptance backtests on recorded ones (feed-scheduling.md §6) are
    // in `schedule::backtest`.

    const H: f64 = 3_600.0;
    const DAY: f64 = 86_400.0;

    /// A feed that changes every hour at :05 (± a few seconds): the hourly candidate wins, the
    /// pattern reads "every hour at :05", and checks bunch up around :05.
    #[test]
    fn learns_an_hourly_pattern() {
        let start = 1_800_000_000.0 - (1_800_000_000.0 % H);
        let changes: Vec<f64> = (0..24 * 14)
            .map(|i| start + i as f64 * H + 300.0 + (i % 7) as f64)
            .collect();
        // Train with 5-minute polling for two weeks.
        let mut obs = Vec::new();
        let mut t = start;
        let mut j = 0;
        while t < start + 14.0 * DAY {
            t += 300.0;
            let mut ex = Vec::new();
            while j < changes.len() && changes[j] <= t {
                ex.push(changes[j]);
                j += 1;
            }
            obs.push(Obs {
                t,
                exact: ex,
                interval: false,
            });
        }
        let l = Learner::replay(&obs);
        assert!(
            l.candidates()[l.best]
                .period
                .is_some_and(|p| p % 3_600 == 0 && p <= 86_400),
            "{:?}",
            l.describe(t)
        );
        let words = l.describe(t);
        assert!(
            ["every hour at :04", "every hour at :05", "every hour at :06"]
                .iter()
                .any(|w| words.starts_with(w)),
            "{words}"
        );
        // A check lands just after :05 rather than every few minutes all hour.
        let next = l.next_check(t, 120.0, 3.0);
        assert!(next - t >= 120.0 && next - t <= SAFETY, "{}", next - t);
        // Simulated over the next 3 days: most changes caught within 2 min, far fewer than 1440
        // checks a day.
        let future: Vec<f64> = (0..72)
            .map(|i| start + 14.0 * DAY + i as f64 * H + 300.0)
            .collect();
        let r = simulate(
            &l,
            &future,
            start + 14.0 * DAY,
            start + 17.0 * DAY,
            3.0,
            1.0,
            120.0,
        );
        assert!(r.share_2min >= 0.9, "{r:?}");
        assert!(r.checks_per_day < 500.0, "{r:?}");
    }

    /// No changes at all: the safety interval grows once the feed is dormant.
    #[test]
    fn dormant_feeds_slow_down() {
        let mut l = Learner::new();
        let t0 = 1_800_000_000.0;
        l.observe(
            &Obs {
                t: t0,
                exact: vec![t0 - 10.0],
                interval: false,
            },
            true,
        );
        let mut t = t0;
        for _ in 0..100 {
            t += H;
            l.observe(
                &Obs {
                    t,
                    exact: vec![],
                    interval: false,
                },
                true,
            );
        }
        assert!(l.safety(t) > SAFETY, "{}", l.safety(t));
        assert!(l.safety(t) <= DORMANT_MAX);
        let early = l.next_check(t, 120.0, 3.0) - t;
        // Ten more quiet days: the learned rate falls and checks spread out, up to the cap.
        for _ in 0..240 {
            t += H;
            l.observe(
                &Obs {
                    t,
                    exact: vec![],
                    interval: false,
                },
                false,
            );
        }
        l.refit(t);
        let late = l.next_check(t, 120.0, 3.0) - t;
        assert!(late > early, "{early} → {late}");
        assert!(late <= DORMANT_MAX);
    }

    #[test]
    fn interval_changes_and_bounds() {
        let mut l = Learner::new();
        let t0 = 1_800_000_000.0;
        l.observe(
            &Obs {
                t: t0,
                exact: vec![],
                interval: false,
            },
            true,
        );
        l.observe(
            &Obs {
                t: t0 + 600.0,
                exact: vec![],
                interval: true,
            },
            true,
        );
        let placed = *l.changes.back().unwrap();
        assert!(placed > t0 && placed <= t0 + 600.0, "placed inside its interval");
        // An exact time outside the interval is an interval.
        l.observe(
            &Obs {
                t: t0 + 1200.0,
                exact: vec![t0 - 99.0],
                interval: false,
            },
            true,
        );
        let placed = *l.changes.back().unwrap();
        assert!(placed > t0 + 600.0 && placed <= t0 + 1200.0);
        // min_interval is a floor, the safety interval a ceiling.
        let n = l.next_check(t0 + 1200.0, 600.0, 0.001);
        assert!(n >= t0 + 1800.0);
        let n = l.next_check(t0 + 1200.0, 60.0, 1e9);
        assert!(n <= t0 + 1200.0 + DORMANT_MAX);
    }

    /// An `http` feed with no history starts from a sibling's tables at ⅕ weight
    /// (feed-scheduling.md §6).
    #[test]
    fn sibling_warm_start() {
        let start = 1_800_000_000.0 - (1_800_000_000.0 % DAY);
        let mut sib = Learner::new();
        let mut t = start;
        let mut lc = start;
        while t < start + 10.0 * DAY {
            t += 600.0;
            let ex = if t - lc >= DAY {
                lc = t - 1.0;
                vec![t - 1.0]
            } else {
                vec![]
            };
            sib.observe(
                &Obs {
                    t,
                    exact: ex,
                    interval: false,
                },
                false,
            );
        }
        sib.refit(t);
        let mut fresh = Learner::new();
        fresh.warm_from(&sib);
        let total = |l: &Learner| {
            l.candidates()
                .iter()
                .map(|c| c.events.iter().sum::<f64>())
                .sum::<f64>()
        };
        let ratio = total(&fresh) / total(&sib);
        assert!((ratio - 0.2).abs() < 1e-9, "{ratio}");
        assert_eq!(fresh.best, sib.best);
        // Its own data then builds up on top.
        fresh.observe(
            &Obs {
                t: t + 600.0,
                exact: vec![],
                interval: false,
            },
            true,
        );
        assert!(fresh.prev_ok.is_some());
    }

    /// A provider with two feeds catches at least what each does alone (feed-scheduling.md §6),
    /// at no more checks than the two would take separately.
    #[test]
    fn a_provider_of_two_feeds_catches_what_each_does_alone() {
        let start = 1_800_000_000.0 - (1_800_000_000.0 % DAY);
        let hourly: Vec<f64> = (0..24 * 21).map(|i| start + i as f64 * H + 300.0).collect();
        let daily: Vec<f64> = (0..21).map(|i| start + i as f64 * DAY + 7.0 * H).collect();
        let train = |changes: &[f64]| {
            let mut obs = Vec::new();
            let mut t = start;
            let mut j = 0;
            while t < start + 14.0 * DAY {
                t += 300.0;
                let mut ex = Vec::new();
                while j < changes.len() && changes[j] <= t {
                    ex.push(changes[j]);
                    j += 1;
                }
                obs.push(Obs {
                    t,
                    exact: ex,
                    interval: false,
                });
            }
            Learner::replay(&obs)
        };
        let (a, b) = (train(&hourly), train(&daily));
        let (s0, s1) = (start + 14.0 * DAY, start + 21.0 * DAY);
        let ra = simulate(&a, &hourly, s0, s1, 3.0, 1.0, 120.0);
        let rb = simulate(&b, &daily, s0, s1, 3.0, 1.0, 120.0);
        let both = simulate_provider(
            &[(a, hourly.clone()), (b, daily.clone())],
            s0,
            s1,
            3.0,
            1.0,
            120.0,
        );
        assert!(
            both.caught_2min >= ra.caught_2min + rb.caught_2min,
            "{both:?} {ra:?} {rb:?}"
        );
        assert!(both.checks <= ra.checks + rb.checks, "{both:?}");
    }

    /// The frozen model's `E` grows with the quiet time and matches the live candidate's.
    #[test]
    fn frozen_models_expect_changes() {
        let start = 1_800_000_000.0 - (1_800_000_000.0 % DAY);
        let mut l = Learner::new();
        let mut t = start;
        let mut lc = start;
        while t < start + 10.0 * DAY {
            t += 600.0;
            let ex = if t - lc >= 6.0 * H {
                lc = t - 1.0;
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
        let f = l.frozen();
        let e1 = f.expected_since(lc, lc + 6.0 * H);
        let e2 = f.expected_since(lc, lc + 3.0 * DAY);
        assert!(e1 > 0.0 && e2 > e1 * 3.0, "{e1} {e2}");
        let live = l.cands[l.best].expected(lc, lc + 3.0 * DAY, Some(lc));
        assert!((live - e2).abs() < 1e-6 * live.max(1.0), "{live} {e2}");
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.len() < 64 * 1024, "{}", j.len());
        let back = serde_json::from_str::<Frozen>(&j).unwrap();
        let e3 = back.expected_since(lc, lc + 3.0 * DAY);
        assert!((e3 - e2).abs() < 1e-9 * e2.max(1.0), "{e3} {e2}");
    }

    /// feed-scheduling.md §5 "`k`": a more aggressive `k` must catch one more change per 300
    /// extra provider checks; ties go to fewer checks; over budget, the largest.
    #[test]
    fn k_choice() {
        let r = |k: f64, caught: usize, checks: usize| SimResult {
            k,
            changes: 30,
            caught_2min: caught,
            checks,
            checks_per_day: checks as f64 / 28.0,
            ..SimResult::default()
        };
        // k=2 earns its 600 extra checks over k=3 (3 more changes > 2); k=1's 1,800 more over
        // k=2 bring 4 changes (< 6).
        assert_eq!(
            choose_k(&[
                r(1.0, 29, 4_000),
                r(2.0, 25, 2_200),
                r(3.0, 22, 1_600),
                r(5.0, 15, 1_000)
            ]),
            Some(2.0)
        );
        // A rare-change feed: one more change for 600 more checks isn't worth it.
        assert_eq!(
            choose_k(&[
                r(1.0, 25, 3_800),
                r(2.0, 24, 2_200),
                r(3.0, 22, 1_600),
                r(5.0, 21, 1_000)
            ]),
            Some(5.0)
        );
        // A tie goes to fewer checks, also where floating point would see a difference.
        assert_eq!(choose_k(&[r(2.0, 24, 1_800), r(3.0, 23, 1_500)]), Some(3.0));
        assert_eq!(choose_k(&[r(1.0, 21, 1_339), r(5.0, 20, 1_039)]), Some(5.0));
        // Only budget-fitting `k`s count; none fits: the largest.
        assert_eq!(choose_k(&[r(1.0, 30, 12_000), r(2.0, 20, 8_000)]), Some(2.0));
        assert_eq!(choose_k(&[r(1.0, 30, 30_000), r(5.0, 20, 12_000)]), Some(5.0));
        // No change in the span: keep `k`.
        assert_eq!(
            choose_k(&[r(3.0, 0, 100)].map(|x| SimResult { changes: 0, ..x })),
            None
        );
        assert_eq!(choose_k(&[]), None);
    }

    /// feed-scheduling.md §5 "`k`": the replay covers 28 days, never reaching before the
    /// feeds' own checks, and waits for a day of them.
    #[test]
    fn k_replay_span() {
        let now = 1_800_000_000.0;
        assert_eq!(
            k_replay_start(now, Some(now - 90.0 * DAY)),
            Some(now - 28.0 * DAY)
        );
        assert_eq!(k_replay_start(now, Some(now - 3.0 * DAY)), Some(now - 3.0 * DAY));
        assert_eq!(k_replay_start(now, Some(now - DAY)), Some(now - DAY));
        assert_eq!(k_replay_start(now, Some(now - 3_600.0)), None);
        assert_eq!(k_replay_start(now, None), None);
    }

    /// feed-scheduling.md §5 "`k`": the provider takes the most aggressive of its feeds' own
    /// choices; a feed whose replay saw no change has no say; identical feeds count as one.
    #[test]
    fn provider_k_is_the_most_aggressive_feed_choice() {
        let r = |k: f64, caught: usize, checks: usize| SimResult {
            k,
            changes: 30,
            caught_2min: caught,
            checks,
            checks_per_day: checks as f64 / 28.0,
            ..SimResult::default()
        };
        let busy = [r(1.0, 29, 4_000), r(2.0, 25, 2_200), r(3.0, 22, 1_600)];
        let rare = [r(1.0, 25, 3_800), r(3.0, 22, 1_600), r(5.0, 21, 1_000)];
        let quiet = [r(1.0, 0, 900), r(5.0, 0, 300)].map(|x| SimResult { changes: 0, ..x });
        assert_eq!(provider_k([&busy[..], &rare[..]], &[]), Some(2.0));
        assert_eq!(provider_k([&rare[..], &quiet[..]], &[]), Some(5.0));
        assert_eq!(
            provider_k([&busy[..], &busy[..]], &[]),
            provider_k([&busy[..]], &[])
        );
        assert_eq!(provider_k([&quiet[..]], &[]), None);
        assert_eq!(provider_k(std::iter::empty::<&[SimResult]>(), &[]), None);
        // The provider's own checks keep within the budget: k=2 would take 420 a day together.
        let pooled = |k: f64, per_day: f64| SimResult {
            k,
            checks_per_day: per_day,
            ..SimResult::default()
        };
        let together = [
            pooled(1.0, 700.0),
            pooled(2.0, 420.0),
            pooled(3.0, 330.0),
            pooled(5.0, 200.0),
        ];
        assert_eq!(provider_k([&busy[..], &rare[..]], &together), Some(3.0));
        let flooded = together.clone().map(|r| SimResult {
            checks_per_day: 900.0,
            ..r
        });
        assert_eq!(provider_k([&busy[..], &rare[..]], &flooded), Some(5.0));

        // How the budget shaped each choice (issue #65): the diagnostics tell a fit, a slowdown
        // and a fallback apart.
        let c = provider_k_choice([&busy[..], &rare[..]], &[]).unwrap();
        assert_eq!((c.k, c.preferred, c.budget), (2.0, 2.0, BudgetFit::Within));
        assert_eq!(c.checks_per_day, None, "no pooled replay");
        let c = provider_k_choice([&busy[..], &rare[..]], &together).unwrap();
        assert_eq!(
            c,
            KChoice {
                k: 3.0,
                preferred: 2.0,
                budget: BudgetFit::Slowed,
                preferred_checks_per_day: Some(420.0),
                checks_per_day: Some(330.0),
            }
        );
        let c = provider_k_choice([&busy[..], &rare[..]], &flooded).unwrap();
        assert_eq!((c.k, c.preferred, c.budget), (5.0, 2.0, BudgetFit::NoneFits));
        assert_eq!(c.checks_per_day, Some(900.0), "over the budget all the same");
        assert_eq!(provider_k_choice([&quiet[..]], &[]), None);
        let impact = FeedImpact::new("f".into(), Some(2.0), 40, 0.9, 0.85);
        assert!((impact.change_points + 5.0).abs() < 1e-9, "{impact:?}");
    }

    /// A provider replay reports each feed's own catches (issue #65), so an aggregate can't hide
    /// one feed's losses: the per-feed figures add up to the aggregate.
    #[test]
    fn provider_replays_report_each_feed() {
        let start = 1_800_000_000.0 - (1_800_000_000.0 % H);
        let hourly: Vec<f64> = (0..24 * 14).map(|i| start + i as f64 * H + 300.0).collect();
        let daily: Vec<f64> = (0..14).map(|i| start + i as f64 * DAY + 4.0 * H).collect();
        let mut warm_h = Learner::new();
        let mut warm_d = Learner::new();
        for d in 0..14 {
            let t = start - 14.0 * DAY + d as f64 * DAY;
            let hours: Vec<f64> = (0..24).map(|h| t + h as f64 * H + 300.0).collect();
            warm_h.observe(
                &Obs {
                    t: t + DAY - 1.0,
                    exact: hours,
                    interval: false,
                },
                true,
            );
            warm_d.observe(
                &Obs {
                    t: t + DAY - 1.0,
                    exact: vec![t + 4.0 * H],
                    interval: false,
                },
                true,
            );
        }
        let r = simulate_provider(
            &[(warm_h, hourly.clone()), (warm_d, daily.clone())],
            start,
            start + 14.0 * DAY,
            3.0,
            1.0,
            120.0,
        );
        assert_eq!(r.feeds.len(), 2);
        assert_eq!(r.feeds[0].changes, hourly.len());
        assert_eq!(r.feeds[1].changes, daily.len());
        assert_eq!(r.feeds.iter().map(|f| f.changes).sum::<usize>(), r.changes);
        assert_eq!(
            r.feeds.iter().map(|f| f.caught_2min).sum::<usize>(),
            r.caught_2min
        );
        for f in &r.feeds {
            assert!((f.share_2min - f.caught_2min as f64 / f.changes as f64).abs() < 1e-12);
        }
    }

    /// feed-scheduling.md §5 "`k`": each feed's replay starts at its own checks: a feed with
    /// none sits the choice out without stopping the others, a new feed doesn't shorten a mature
    /// one's 28 days, and a warm start read after the first check moves the start to it.
    #[test]
    fn each_feed_replays_from_its_own_checks() {
        let now = 1_800_000_000.0;
        let starts = k_replay_starts(
            now,
            &[
                (Some(now - 90.0 * DAY), None),
                (Some(now - 3_600.0), None),
                (None, None),
                (Some(now - 10.0 * DAY), Some(now - 9.0 * DAY)),
                (Some(now - 10.0 * DAY), Some(now - 70.0 * DAY)),
            ],
        );
        assert_eq!(
            starts,
            vec![
                Some(now - 28.0 * DAY),
                None,
                None,
                Some(now - 9.0 * DAY),
                Some(now - 10.0 * DAY)
            ]
        );
    }
}
