//! Backtests (feed-scheduling.md §5 "`k`", §6): replaying a feed provider's recorded history
//! with simulated checks. The weekly `k` choice ([`weekly_choice`]) and the `backtest` endpoint
//! both call [`replay`]; the tests below hold the acceptance harness on recorded histories (§6
//! "Tests"), including how much a feed may lose beside busy siblings under the planning budget,
//! measured per feed over several windows (issue #65).

use crate::learner::{
    BudgetFit, FeedImpact, K_CHOICES, KChoice, Learner, Obs, SimResult, choose_k, provider_k_choice,
    simulate_provider,
};

/// Replays `[start, end)` of a provider's feeds with simulated checks, once per `k` in `ks`: the
/// provider is checked at its feeds' earliest ask, each spaced from that feed's own last check
/// (feed-scheduling.md §5, [`simulate_provider`]). `obs` holds each feed's stored observations
/// (its current epoch, oldest first). Each feed's learner is trained on what came before
/// `start`; the changes it then recorded, exact or placed where it placed them (§5: the replay
/// places an interval-only change where the learner does), are the ones the simulated checks
/// must catch.
pub fn replay(
    obs: &[Vec<Obs>],
    start: f64,
    end: f64,
    ks: &[f64],
    cost_factor: f64,
    min_interval: f64,
) -> Vec<SimResult> {
    let pairs: Vec<(Learner, Vec<f64>)> = obs
        .iter()
        .map(|o| {
            let before: Vec<Obs> = o.iter().filter(|x| x.t < start).cloned().collect();
            let base = Learner::replay(&before);
            // The rest through the same update path, from where the base stands.
            let mut full = base.clone();
            for x in o.iter().filter(|x| x.t >= start) {
                full.observe(x, false);
            }
            let changes = full.changes.iter().copied().filter(|c| *c >= start).collect();
            (base, changes)
        })
        .collect();
    ks.iter()
        .map(|k| simulate_provider(&pairs, start, end, *k, cost_factor, min_interval))
        .collect()
}

/// One voting feed of a provider's weekly `k` choice (feed-scheduling.md §5).
#[derive(Clone, Debug)]
pub struct VotingFeed {
    pub name: String,
    /// Its stored observations (its current epoch, oldest first).
    pub obs: Vec<Obs>,
    /// Where its replay starts ([`crate::learner::k_replay_starts`]).
    pub start: f64,
    pub cost_factor: f64,
}

/// A provider's weekly `k` choice with the planning budget's part in it.
#[derive(Clone, Debug, PartialEq)]
pub struct WeeklyChoice {
    pub choice: KChoice,
    /// The pooled replay's start (the latest of the feeds' starts); it ends at `end`.
    pub window_start: f64,
    /// After a compromise ([`BudgetFit::Slowed`], [`BudgetFit::NoneFits`]): each feed's share
    /// caught within 2 min alone at its own choice against beside its siblings at the `k` taken,
    /// both over the pooled window. Empty when the budget changed nothing.
    pub impacts: Vec<FeedImpact>,
}

/// The weekly `k` choice (feed-scheduling.md §5): each feed replays from its own start alone
/// with each `k` in [`K_CHOICES`], the feeds together from the latest start for the budget
/// (`pooled_cost`: their cost factor together), and the provider takes [`provider_k_choice`].
/// After a compromise, each feed's standalone schedule is replayed over the pooled window too,
/// so its estimated cost compares like with like. `None` when no feed has a choice.
pub fn weekly_choice(
    feeds: &[VotingFeed],
    pooled_cost: f64,
    end: f64,
    min_interval: f64,
) -> Option<WeeklyChoice> {
    let per_feed: Vec<Vec<SimResult>> = feeds
        .iter()
        .map(|f| {
            replay(
                std::slice::from_ref(&f.obs),
                f.start,
                end,
                &K_CHOICES,
                f.cost_factor,
                min_interval,
            )
        })
        .collect();
    let window_start = feeds.iter().map(|f| f.start).fold(f64::MIN, f64::max);
    let pooled = if feeds.len() > 1 {
        let obs: Vec<Vec<Obs>> = feeds.iter().map(|f| f.obs.clone()).collect();
        replay(&obs, window_start, end, &K_CHOICES, pooled_cost, min_interval)
    } else {
        per_feed.first().cloned().unwrap_or_default()
    };
    let choice = provider_k_choice(per_feed.iter().map(Vec::as_slice), &pooled)?;
    let impacts = if choice.budget == BudgetFit::Within {
        vec![]
    } else {
        let at_k = pooled.iter().find(|r| r.k == choice.k);
        feeds
            .iter()
            .zip(&per_feed)
            .enumerate()
            .map(|(i, (f, alone))| {
                let grouped = at_k.and_then(|r| r.feeds.get(i)).cloned().unwrap_or_default();
                let own = choose_k(alone);
                let standalone = match own {
                    // Its own replay already covers the window.
                    Some(k) if f.start == window_start => alone.iter().find(|r| r.k == k).cloned(),
                    Some(k) => replay(
                        std::slice::from_ref(&f.obs),
                        window_start,
                        end,
                        &[k],
                        f.cost_factor,
                        min_interval,
                    )
                    .into_iter()
                    .next(),
                    // No change in its own replay, so none in the window either.
                    None => None,
                }
                .and_then(|r| r.feeds.into_iter().next())
                .unwrap_or_else(|| grouped.clone());
                FeedImpact::new(
                    f.name.clone(),
                    own,
                    grouped.changes,
                    standalone.share_2min,
                    grouped.share_2min,
                )
            })
            .collect()
    };
    Some(WeeklyChoice {
        choice,
        window_start,
        impacts,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::OnceLock;

    use super::*;
    use crate::learner::{K_CHOICES, K_REPLAY_DAYS, k_replay_starts, provider_k, respace};

    const DAY: f64 = 86_400.0;

    fn checks_every(changes: &[f64], from: f64, to: f64, step: f64) -> Vec<Obs> {
        let mut obs = Vec::new();
        let mut j = changes.partition_point(|c| *c <= from);
        let mut t = from;
        while t < to {
            t += step;
            let mut exact = Vec::new();
            while j < changes.len() && changes[j] <= t {
                exact.push(changes[j]);
                j += 1;
            }
            obs.push(Obs {
                t,
                exact,
                interval: false,
            });
        }
        obs
    }

    /// The replay trains each feed on what came before `start` and asks the simulated checks to
    /// catch the changes recorded from `start` on, the interval-only ones where the learner put
    /// them.
    #[test]
    fn replay_trains_on_the_past_and_scores_the_rest() {
        let t0 = 1_800_000_000.0 - (1_800_000_000.0 % 3_600.0);
        let hourly: Vec<f64> = (0..24 * 21).map(|i| t0 + i as f64 * 3_600.0 + 300.0).collect();
        let mut obs = checks_every(&hourly, t0, t0 + 21.0 * DAY, 300.0);
        let (start, end) = (t0 + 14.0 * DAY, t0 + 21.0 * DAY);
        let r = replay(&[obs.clone()], start, end, &K_CHOICES, 1.0, 120.0);
        assert_eq!(r.len(), K_CHOICES.len());
        assert!(r.iter().all(|x| x.changes == 24 * 7), "{r:?}");
        // The same as simulating from the learner trained on the checks before `start`.
        let before: Vec<Obs> = obs.iter().filter(|o| o.t < start).cloned().collect();
        let pairs = [(
            Learner::replay(&before),
            hourly.iter().copied().filter(|c| *c >= start).collect::<Vec<_>>(),
        )];
        let direct: Vec<SimResult> = K_CHOICES
            .iter()
            .map(|k| simulate_provider(&pairs, start, end, *k, 1.0, 120.0))
            .collect();
        assert_eq!(r, direct);
        // A smaller k checks more and catches at least as much.
        assert!(
            r[0].checks > r[3].checks && r[0].caught_2min >= r[3].caught_2min,
            "{r:?}"
        );
        // An interval-only change after `start` is counted where the learner placed it.
        let i = obs
            .iter()
            .position(|o| o.t > start + DAY && !o.exact.is_empty())
            .unwrap();
        obs[i].exact.clear();
        obs[i].interval = true;
        let r = replay(&[obs.clone()], start, end, &[3.0], 1.0, 120.0);
        assert_eq!(r[0].changes, 24 * 7);
        let mut full = Learner::replay(&obs[..i]);
        full.observe(&obs[i], false);
        let placed = *full.changes.back().unwrap();
        assert!(placed > obs[i - 1].t && placed <= obs[i].t, "{placed}");
    }

    // ---- The acceptance harness on recorded histories (feed-scheduling.md §6 "Tests") ----
    //
    // Each fixture holds when a public list's published file changed, read from its git history
    // (tests/fixtures/feed-histories/; each header names the source). The harness creates a
    // `dynamic` provider of `github` feeds at the start of the last 60 days (the history the
    // learner keeps; its warm start reads the 60 days before), checks it as core would with
    // weekly-chosen `k`, and measures the share of changes caught within 2 min and the checks a
    // day over those 60 days.

    /// A recorded history.
    struct Fixture {
        name: &'static str,
        /// Change times, Unix seconds, oldest first.
        changes: Vec<f64>,
        /// The span the fixture covers, `[from, to)`.
        from: f64,
        to: f64,
    }

    /// Parses a fixture: `#` header lines, among them `# Range: [<from>, <to>), …`, then one UTC
    /// RFC 3339 time per line.
    fn parse(name: &'static str, text: &str) -> Fixture {
        let ts = |s: &str| {
            picket_api::time::parse(s.trim())
                .unwrap_or_else(|e| panic!("{name}: {s:?}: {e}"))
                .as_second() as f64
        };
        let range = text
            .lines()
            .find_map(|l| l.strip_prefix("# Range: ["))
            .and_then(|l| l.split_once(')'))
            .and_then(|(r, _)| r.split_once(", "))
            .unwrap_or_else(|| panic!("{name}: no range in the header"));
        let changes: Vec<f64> = text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(ts)
            .collect();
        Fixture {
            name,
            changes,
            from: ts(range.0),
            to: ts(range.1),
        }
    }

    fn oisd_big() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            parse(
                "OISD big",
                include_str!("../tests/fixtures/feed-histories/oisd-big.txt"),
            )
        })
    }

    fn adguard_dns_filter() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            parse(
                "AdGuard DNS filter",
                include_str!("../tests/fixtures/feed-histories/adguard-dns-filter.txt"),
            )
        })
    }

    fn jpgpi250_doh() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            parse(
                "jpgpi250 DoH",
                include_str!("../tests/fixtures/feed-histories/jpgpi250-doh.txt"),
            )
        })
    }

    /// The days replayed: the history the learner keeps (feed-scheduling.md §4 "Rebuild").
    const REPLAYED_DAYS: f64 = 60.0;
    /// The `github` warm start's reach (feed-scheduling.md §6): back until 20 changes or 60 days.
    const WARM_CHANGES: usize = crate::HISTORY_CHANGES;
    const WARM_DAYS: f64 = crate::HISTORY_DAYS as f64;
    /// The default `min_interval`; a `github` check's no-change cost is one `ls-refs`, so the
    /// cost factor is 1.
    const MIN_INTERVAL: f64 = 120.0;
    const COST: f64 = 1.0;

    #[test]
    fn fixtures_cover_the_warm_start_and_the_replay() {
        for f in [oisd_big(), adguard_dns_filter(), jpgpi250_doh()] {
            assert!(
                f.to - f.from >= (WARM_DAYS + REPLAYED_DAYS) * DAY,
                "{}: the fixture must cover the warm start's 60 days and the 60 replayed",
                f.name
            );
            assert!(f.changes.windows(2).all(|w| w[0] < w[1]), "{}: unsorted", f.name);
            assert!(
                f.changes.iter().all(|c| *c >= f.from && *c < f.to),
                "{}: a change outside the range",
                f.name
            );
            let created = f.to - REPLAYED_DAYS * DAY;
            let read = f
                .changes
                .iter()
                .filter(|c| **c < created && **c >= created - WARM_DAYS * DAY);
            assert!(read.count() >= WARM_CHANGES, "{}", f.name);
        }
    }

    /// A feed's learner at a replay's start and the changes the replay must catch.
    type FeedReplay = (Learner, Vec<f64>);

    /// One feed of the simulated provider.
    struct Feed<'a> {
        changes: &'a [f64],
        learner: Learner,
        /// The stored history (`feed_checks` / `feed_changes`): its bootstrap and simulated checks.
        obs: Vec<Obs>,
        /// The first change no check has seen yet.
        next: usize,
        /// Its pending ask, spaced from its own last check (§5 "Spacing").
        ask: f64,
        /// Changes in the measured span, and those caught within 2 min.
        measured: usize,
        caught: usize,
    }

    /// What a run measured.
    #[derive(Debug)]
    struct Outcome {
        /// Per feed: (changes, caught within 2 min).
        feeds: Vec<(usize, usize)>,
        checks_per_day: f64,
        /// The `k` chosen each week.
        ks: Vec<f64>,
    }

    impl Outcome {
        fn share(&self, i: usize) -> f64 {
            let (n, c) = self.feeds[i];
            c as f64 / n.max(1) as f64
        }
    }

    /// Runs a `dynamic` provider of `github` feeds over recorded change times as core would:
    /// created at `created` (each feed warm-starts from the history before it, §6), then checked
    /// at its feeds' earliest ask until `end`, each feed's ask spaced from its own last check
    /// ([`respace`]), every check reporting each feed's commit times since the previous one as
    /// exact changes (providers.md §3). Once a day, a provider whose `k` is unset or a week old
    /// picks it again: each feed replays its last 28 days alone, from no earlier than its own
    /// checks, with each `k` in {1, 2, 3, 5}, and the provider takes the most aggressive feed
    /// choice ([`k_replay_starts`], [`provider_k`], §5). Measures changes and checks from
    /// `created` on.
    ///
    /// Shortcuts that keep it fast without moving the figures (measured against the full path:
    /// within one change and 1.5 checks a day per fixture): the learners refit hourly,
    /// as a replay does, instead of after every check; the daily rebuild is left out (over the
    /// 60 days nothing the learner holds is older than a rebuild keeps); and the weekly replay
    /// starts from the learners as they stood at its start instead of replaying the stored
    /// history up to then ([`replay`] does that: the same data through the same update path),
    /// with its simulations on threads.
    fn run(histories: &[&[f64]], created: f64, end: f64) -> Outcome {
        let mut k = Learner::new().k;
        let mut feeds: Vec<Feed<'_>> = histories
            .iter()
            .map(|changes| warm_start(changes, created, k * COST))
            .collect();
        let mut k_chosen_at: Option<f64> = None;
        let mut ks = Vec::new();
        // The learners at each daily tick of the replay's span.
        let mut snapshots: VecDeque<(f64, Vec<Learner>)> = VecDeque::new();
        snapshots.push_back((created, feeds.iter().map(|f| f.learner.clone()).collect()));
        let mut next_tick = created + DAY;
        let mut last = created;
        let mut checks = 0usize;
        loop {
            // Due at the feeds' earliest ask, never sooner than `min_interval` after the last check.
            let due = feeds
                .iter()
                .map(|f| f.ask)
                .fold(f64::INFINITY, f64::min)
                .max(last + MIN_INTERVAL);
            // The daily job (feeds/mod.rs): pick `k` when unset or a week old.
            while next_tick <= due.min(end) {
                let tick = next_tick;
                next_tick += DAY;
                snapshots.push_back((tick, feeds.iter().map(|f| f.learner.clone()).collect()));
                while snapshots
                    .front()
                    .is_some_and(|(t, _)| *t < tick - K_REPLAY_DAYS * DAY - 1.0)
                {
                    snapshots.pop_front();
                }
                if k_chosen_at.is_some_and(|t| tick - t < 7.0 * DAY) {
                    continue;
                }
                // Each feed replays alone from its own checks (here all begin at the provider's
                // creation) and the provider takes the most aggressive choice.
                let own = vec![(Some(created), None); feeds.len()];
                let replays: Vec<(usize, f64, (Learner, Vec<f64>))> = feeds
                    .iter()
                    .zip(k_replay_starts(tick, &own))
                    .enumerate()
                    .filter_map(|(i, (f, start))| {
                        let start = start?;
                        let base = snapshots
                            .iter()
                            .find(|(t, _)| (*t - start).abs() < 1.0)
                            .map(|(_, ls)| ls[i].clone())
                            .unwrap_or_else(|| {
                                let before: Vec<Obs> =
                                    f.obs.iter().filter(|o| o.t < start).cloned().collect();
                                Learner::replay(&before)
                            });
                        let recorded = f
                            .obs
                            .iter()
                            .flat_map(|o| o.exact.iter().copied())
                            .filter(|c| *c >= start && *c < tick)
                            .collect();
                        Some((i, start, (base, recorded)))
                    })
                    .collect();
                if replays.is_empty() {
                    continue;
                }
                // And the voting feeds together, for the provider's budget (from the latest of
                // their starts).
                let together: Vec<(Learner, Vec<f64>)> = replays.iter().map(|r| r.2.clone()).collect();
                let latest = replays.iter().map(|r| r.1).fold(f64::MIN, f64::max);
                let mut sets: Vec<(&[FeedReplay], f64)> = replays
                    .iter()
                    .map(|(_, start, pair)| (std::slice::from_ref(pair), *start))
                    .collect();
                if replays.len() > 1 {
                    sets.push((&together, latest));
                }
                let mut results: Vec<Vec<SimResult>> = std::thread::scope(|sc| {
                    let hs: Vec<Vec<_>> = sets
                        .iter()
                        .map(|&(set, start)| {
                            K_CHOICES
                                .iter()
                                .map(|k| {
                                    sc.spawn(move || {
                                        simulate_provider(set, start, tick, *k, COST, MIN_INTERVAL)
                                    })
                                })
                                .collect()
                        })
                        .collect();
                    hs.into_iter()
                        .map(|v| {
                            v.into_iter()
                                .map(|h| h.join().expect("a simulation panicked"))
                                .collect()
                        })
                        .collect()
                });
                let pooled = if replays.len() > 1 {
                    results.pop().unwrap_or_default()
                } else {
                    results[0].clone()
                };
                let per_feed = results;
                if let Some(c) = provider_k(per_feed.iter().map(Vec::as_slice), &pooled) {
                    k = c;
                }
                k_chosen_at = Some(tick);
                ks.push(k);
            }
            if due >= end {
                break;
            }
            for f in &mut feeds {
                let prev = f.next;
                while f.next < f.changes.len() && f.changes[f.next] <= due {
                    f.next += 1;
                }
                let seen = &f.changes[prev..f.next];
                f.measured += seen.len();
                f.caught += seen.iter().filter(|c| due - **c <= 120.0).count();
                let o = Obs {
                    t: due,
                    exact: seen.to_vec(),
                    interval: false,
                };
                f.learner.observe(&o, false);
                let fresh = f.learner.next_check(due, MIN_INTERVAL, k * COST);
                f.ask = respace(Some(f.ask), fresh, due, !o.exact.is_empty());
                f.obs.push(o);
            }
            checks += 1;
            last = due;
        }
        let feeds = feeds
            .iter()
            .map(|f| {
                // Changes after the last check count as missed.
                let missed = f.changes[f.next..].iter().filter(|c| **c < end).count();
                (f.measured + missed, f.caught)
            })
            .collect();
        Outcome {
            feeds,
            checks_per_day: checks as f64 / ((end - created) / DAY),
            ks,
        }
    }

    /// A `github` feed created at `created` (feed-scheduling.md §6): the warm start reads the
    /// newest 20 changes of the 60 days before it, between two `bootstrap` checks (the start of
    /// the span read, and now); then its first check finds no change (§3: no `seen_blake3`).
    fn warm_start(changes: &[f64], created: f64, k_eff: f64) -> Feed<'_> {
        let from = changes.partition_point(|c| *c < created - WARM_DAYS * DAY);
        let to = changes.partition_point(|c| *c < created);
        let read = &changes[from.max(to.saturating_sub(WARM_CHANGES))..to];
        let span_start = if read.len() >= WARM_CHANGES {
            read[0] - 1.0
        } else {
            created - WARM_DAYS * DAY
        };
        let obs = vec![
            Obs {
                t: span_start,
                exact: vec![],
                interval: false,
            },
            Obs {
                t: created - 0.001,
                exact: read.to_vec(),
                interval: false,
            },
            Obs {
                t: created,
                exact: vec![],
                interval: false,
            },
        ];
        let mut learner = Learner::new();
        for o in &obs {
            learner.observe(o, true);
        }
        Feed {
            changes,
            ask: learner.next_check(created, MIN_INTERVAL, k_eff),
            learner,
            obs,
            next: to,
            measured: 0,
            caught: 0,
        }
    }

    /// A fixture alone: a provider with that one feed over the last 60 days (each computed once,
    /// shared with the two-feed tests).
    fn alone(f: &'static Fixture) -> &'static Outcome {
        static OISD: OnceLock<Outcome> = OnceLock::new();
        static ADGUARD: OnceLock<Outcome> = OnceLock::new();
        static DOH: OnceLock<Outcome> = OnceLock::new();
        let slot = if std::ptr::eq(f, oisd_big()) {
            &OISD
        } else if std::ptr::eq(f, adguard_dns_filter()) {
            &ADGUARD
        } else {
            &DOH
        };
        slot.get_or_init(|| run(&[&f.changes], f.to - REPLAYED_DAYS * DAY, f.to))
    }

    /// Per fixture (feed-scheduling.md §6): the share of feed `i`'s changes caught within 2 min
    /// is at least the figure minus 5 points.
    fn assert_share(f: &Fixture, share: f64, o: &Outcome, i: usize) {
        let (n, caught) = o.feeds[i];
        eprintln!("{}: {caught} of {n} caught within 2 min; {o:?}", f.name);
        assert!(n >= 50, "{}: {n} changes in 60 days", f.name);
        assert!(
            o.share(i) >= share - 0.05,
            "{}: {caught} of {n} changes caught within 2 min ({:.1} %, figure {:.0} %); {o:?}",
            f.name,
            o.share(i) * 100.0,
            share * 100.0
        );
    }

    /// Per fixture: the checks a day at most 1.2 × the figure, with `k` chosen weekly.
    fn assert_checks(f: &Fixture, checks_per_day: f64, o: &Outcome) {
        // The first choice a day after creation, then weekly: 9 in 60 days.
        assert_eq!(o.ks.len(), 9, "{}: {o:?}", f.name);
        assert!(
            o.checks_per_day <= 1.2 * checks_per_day,
            "{}: {:.1} checks a day (figure {checks_per_day}); {o:?}",
            f.name,
            o.checks_per_day
        );
    }

    /// The figures (feed-scheduling.md §6): share caught within 2 min, checks a day. jpgpi250's
    /// (owner decision D11) is this harness's mean over five 60-day spans of its recorded
    /// history, ending 0, 7, 14, 21 and 28 days before its end: 80.0 %, 75.3 checks a day (this
    /// test's span: 50 of 59, 72.2 a day).
    const OISD_BIG: (f64, f64) = (0.97, 281.0);
    const ADGUARD_DNS_FILTER: (f64, f64) = (0.95, 275.0);
    const JPGPI250_DOH: (f64, f64) = (0.80, 75.0);

    #[test]
    fn oisd_big_meets_its_figure() {
        let (f, o) = (oisd_big(), alone(oisd_big()));
        assert_share(f, OISD_BIG.0, o, 0);
        assert_checks(f, OISD_BIG.1, o);
    }

    #[test]
    fn adguard_dns_filter_meets_its_figure() {
        let (f, o) = (adguard_dns_filter(), alone(adguard_dns_filter()));
        assert_share(f, ADGUARD_DNS_FILTER.0, o, 0);
        assert_checks(f, ADGUARD_DNS_FILTER.1, o);
    }

    #[test]
    fn jpgpi250_doh_meets_its_figure() {
        let (f, o) = (jpgpi250_doh(), alone(jpgpi250_doh()));
        assert_share(f, JPGPI250_DOH.0, o, 0);
        assert_checks(f, JPGPI250_DOH.1, o);
    }

    /// On these recorded fixtures, a provider with two of them catches at least what each does
    /// alone (feed-scheduling.md §6), each feed on its own, with fewer checks than the two would
    /// take apart, and each feed still meets its figure. Each feed's ask is spaced from its own
    /// last check (§5 "Spacing") and the provider's `k` is the most aggressive of the feeds' own
    /// choices (§5 "`k`"), so the sibling's checks only add to a feed's own. This holds on this
    /// span; where the provider's planning budget binds (the busiest lists together), other spans
    /// leave a feed short, within the tolerance the multi-window tests below measure and hold
    /// ([`GROUPED_TOLERANCE_POINTS`]).
    fn assert_pair(a: &'static Fixture, fa: (f64, f64), b: &'static Fixture, fb: (f64, f64)) {
        assert_eq!(a.to, b.to, "the fixtures end together");
        let both = run(&[&a.changes, &b.changes], a.to - REPLAYED_DAYS * DAY, a.to);
        let (ra, rb) = (alone(a), alone(b));
        for (i, (f, r)) in [(a, ra), (b, rb)].into_iter().enumerate() {
            assert!(
                both.feeds[i].1 >= r.feeds[0].1,
                "{}: {} caught beside the other feed, {} alone; {both:?} against {r:?}",
                f.name,
                both.feeds[i].1,
                r.feeds[0].1
            );
        }
        assert!(
            both.checks_per_day <= ra.checks_per_day + rb.checks_per_day,
            "{both:?} against {ra:?} and {rb:?}"
        );
        assert_share(a, fa.0, &both, 0);
        assert_share(b, fb.0, &both, 1);
    }

    #[test]
    fn oisd_big_and_adguard_dns_filter_each_catch_what_they_do_alone() {
        assert_pair(oisd_big(), OISD_BIG, adguard_dns_filter(), ADGUARD_DNS_FILTER);
    }

    #[test]
    fn oisd_big_and_jpgpi250_doh_each_catch_what_they_do_alone() {
        assert_pair(oisd_big(), OISD_BIG, jpgpi250_doh(), JPGPI250_DOH);
    }

    /// Two feeds with the same history (one commit changes both) behave as one: each catches
    /// what it catches alone, at the same checks (the `k` replay prices a change against its own
    /// feed's checks, feed-scheduling.md §5).
    #[test]
    fn identical_feeds_behave_as_one() {
        let f = jpgpi250_doh();
        let both = run(&[&f.changes, &f.changes], f.to - REPLAYED_DAYS * DAY, f.to);
        let one = alone(f);
        assert_eq!(both.feeds, vec![one.feeds[0]; 2], "{both:?} against {one:?}");
        assert!(
            (both.checks_per_day - one.checks_per_day).abs() < 1e-9,
            "{both:?} against {one:?}"
        );
    }

    // ---- Grouped against alone across windows (issue #65) ----
    //
    // The planning budget can make a provider less aggressive than one of its feeds would be
    // alone (`BudgetFit::Slowed`), so a feed beside busy siblings can catch less than alone. These
    // tests measure that on every combination of the recorded fixtures (the three pairs and all
    // three together, the busiest), over five 60-day windows ending 0, 7, 14, 21 and 28 days
    // before the fixtures' end, each feed against the same feed run alone over the same window.
    //
    // **The tolerance** (an acceptance requirement of the model, not a runtime guarantee): for
    // each feed, in each window, its share of changes caught within 2 min beside its siblings is
    // at most [`GROUPED_TOLERANCE_POINTS`] percentage points below its share alone. The
    // denominator is that feed's changes in that window; there is no aggregation over feeds or
    // windows, so a total can't hide one feed's repeated losses. Measured when adopted (Nov 2026
    // fixtures): the worst shortfall is 1.86 points (OISD big beside both others, the window
    // ending 28 days back: 1158 of 1235 against 1181 alone); pairs lose at most 1.05 points (OISD
    // big beside AdGuard, same window); in most windows grouped feeds catch more than alone. So a
    // "≤ 1 %" claim does not hold on these histories, and no fixed budget guarantees anything on
    // other workloads.
    //
    // **When it fails:** a change to the learner, the `k` choice or the budget that pushes a feed
    // past the tolerance doesn't ship as is: fix it, or re-measure (these tests print every
    // feed's figures), decide the new tolerance, and update this figure and the planning
    // budget's description ([`crate::learner::BUDGET_PER_DAY`]) together.

    /// The most a feed's 2-minute share may fall, in percentage points of its own changes in a
    /// window, beside its siblings against alone.
    const GROUPED_TOLERANCE_POINTS: f64 = 2.5;

    /// The most checks a day a provider of several fixtures may take, against the sum of its
    /// feeds' checks alone.
    const GROUPED_CHECKS_FACTOR: f64 = 1.05;

    /// How far before the fixtures' end each measured window ends, in days.
    const WINDOW_ENDS: [f64; 5] = [0.0, 7.0, 14.0, 21.0, 28.0];

    /// The windows' warm starts read inside the fixtures: each window's provider is created 60
    /// days before the window's end and warm-starts from the 20 changes before that.
    #[test]
    fn every_window_warm_starts_inside_the_fixtures() {
        for f in [oisd_big(), adguard_dns_filter(), jpgpi250_doh()] {
            for back in WINDOW_ENDS {
                let created = f.to - back * DAY - REPLAYED_DAYS * DAY;
                let before = f.changes.iter().filter(|c| **c < created).count();
                assert!(
                    before >= WARM_CHANGES,
                    "{}: {before} changes before the window ending {back} days back",
                    f.name
                );
            }
        }
    }

    /// Runs every combination of the fixtures, and each fixture alone, over the 60 days ending
    /// `back` days before the fixtures' end, and checks the tolerance and the checks.
    fn grouped_against_alone(back: f64) {
        let fx = [oisd_big(), adguard_dns_filter(), jpgpi250_doh()];
        let combos: [&[usize]; 4] = [&[0, 1], &[0, 2], &[1, 2], &[0, 1, 2]];
        let end = fx[0].to - back * DAY;
        let created = end - REPLAYED_DAYS * DAY;
        assert!(fx.iter().all(|f| f.to == fx[0].to), "the fixtures end together");
        let (alone, grouped): (Vec<Outcome>, Vec<Outcome>) = std::thread::scope(|sc| {
            let a: Vec<_> = fx
                .iter()
                .map(|f| sc.spawn(move || run(&[&f.changes], created, end)))
                .collect();
            let g: Vec<_> = combos
                .iter()
                .map(|c| {
                    let hist: Vec<&[f64]> = c.iter().map(|i| fx[*i].changes.as_slice()).collect();
                    sc.spawn(move || run(&hist, created, end))
                })
                .collect();
            let join = |h: std::thread::ScopedJoinHandle<'_, Outcome>| h.join().expect("a run panicked");
            (
                a.into_iter().map(join).collect(),
                g.into_iter().map(join).collect(),
            )
        });
        let mut failures = Vec::new();
        for (c, g) in combos.iter().zip(&grouped) {
            for (j, &i) in c.iter().enumerate() {
                let (n, caught) = g.feeds[j];
                let (n_alone, caught_alone) = alone[i].feeds[0];
                assert_eq!(n, n_alone, "{}: the same changes", fx[i].name);
                let points = (g.share(j) - alone[i].share(0)) * 100.0;
                eprintln!(
                    "window ending {back} d back, {:?}: {}: {caught} of {n} beside its siblings, {caught_alone} alone ({points:+.2} points); {:.1} checks a day",
                    c.iter().map(|i| fx[*i].name).collect::<Vec<_>>(),
                    fx[i].name,
                    g.checks_per_day
                );
                if points < -GROUPED_TOLERANCE_POINTS {
                    failures.push(format!(
                        "{} beside {c:?}: {points:+.2} points ({caught} of {n}, {caught_alone} alone)",
                        fx[i].name
                    ));
                }
            }
            // One provider takes about the checks its feeds would apart, or fewer: it takes its
            // most aggressive feed's `k`, so a calmer sibling can add a few (measured: at most
            // 3.3 % more, AdGuard DNS filter with jpgpi250 DoH, the window ending 14 days back).
            let apart: f64 = c.iter().map(|i| alone[*i].checks_per_day).sum();
            assert!(
                g.checks_per_day <= GROUPED_CHECKS_FACTOR * apart,
                "{c:?}, window ending {back} d back: {:.1} checks a day together, {apart:.1} apart",
                g.checks_per_day
            );
        }
        assert!(
            failures.is_empty(),
            "window ending {back} d back: past the {GROUPED_TOLERANCE_POINTS}-point tolerance: {failures:?}"
        );
    }

    #[test]
    fn grouped_feeds_keep_within_the_tolerance_window_0() {
        grouped_against_alone(WINDOW_ENDS[0]);
    }

    #[test]
    fn grouped_feeds_keep_within_the_tolerance_window_7() {
        grouped_against_alone(WINDOW_ENDS[1]);
    }

    #[test]
    fn grouped_feeds_keep_within_the_tolerance_window_14() {
        grouped_against_alone(WINDOW_ENDS[2]);
    }

    #[test]
    fn grouped_feeds_keep_within_the_tolerance_window_21() {
        grouped_against_alone(WINDOW_ENDS[3]);
    }

    #[test]
    fn grouped_feeds_keep_within_the_tolerance_window_28() {
        grouped_against_alone(WINDOW_ENDS[4]);
    }

    /// The weekly choice reports what the budget did (issue #65): the three fixtures together,
    /// checked every 2 minutes for the last 28 days, prefer `k` = 2, whose pooled replay predicts
    /// over the planning budget, so the provider is slowed to 3; each feed's estimated cost
    /// compares its standalone schedule with the grouped one over the same window. Two of them
    /// over the same days fit at their preferred `k`.
    #[test]
    fn the_weekly_choice_reports_a_budget_compromise() {
        let fx = [oisd_big(), adguard_dns_filter(), jpgpi250_doh()];
        let end = fx[0].to;
        let start = end - K_REPLAY_DAYS * DAY;
        let feeds: Vec<VotingFeed> = fx
            .iter()
            .map(|f| VotingFeed {
                name: f.name.into(),
                obs: checks_every(&f.changes, start - 14.0 * DAY, end, 120.0),
                start,
                cost_factor: COST,
            })
            .collect();
        let w = weekly_choice(&feeds, COST, end, MIN_INTERVAL).unwrap();
        eprintln!("{w:#?}");
        assert_eq!(w.window_start, start);
        assert_eq!(
            (w.choice.preferred, w.choice.k, w.choice.budget),
            (2.0, 3.0, BudgetFit::Slowed),
            "{w:?}"
        );
        let budget = crate::learner::BUDGET_PER_DAY;
        assert!(
            w.choice.preferred_checks_per_day.is_some_and(|c| c > budget),
            "{w:?}"
        );
        assert!(w.choice.checks_per_day.is_some_and(|c| c <= budget), "{w:?}");
        assert_eq!(w.impacts.len(), 3);
        for (imp, f) in w.impacts.iter().zip(fx) {
            assert_eq!(imp.feed, f.name);
            let n = f.changes.iter().filter(|c| **c >= start && **c < end).count();
            assert_eq!(imp.changes, n, "{}", f.name);
            assert!(imp.standalone_k.is_some(), "{}", f.name);
            assert!(
                (imp.change_points - (imp.grouped_share_2min - imp.standalone_share_2min) * 100.0).abs()
                    < 1e-9
            );
        }

        let pair = weekly_choice(&feeds[..2], COST, end, MIN_INTERVAL).unwrap();
        assert_eq!(pair.choice.budget, BudgetFit::Within, "{pair:?}");
        assert_eq!(pair.choice.k, pair.choice.preferred);
        assert!(pair.impacts.is_empty(), "no compromise, no estimate");
        // One feed alone: its own replay is the pooled one.
        let one = weekly_choice(&feeds[2..], COST, end, MIN_INTERVAL).unwrap();
        assert_eq!(one.window_start, start);
        assert!(one.choice.checks_per_day.is_some());
    }

    #[test]
    fn adguard_dns_filter_and_jpgpi250_doh_each_catch_what_they_do_alone() {
        assert_pair(
            adguard_dns_filter(),
            ADGUARD_DNS_FILTER,
            jpgpi250_doh(),
            JPGPI250_DOH,
        );
    }
}
