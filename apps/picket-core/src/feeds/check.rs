//! One check of a feed provider (feeds.md §3 steps 1–3, providers.md §2, feed-scheduling.md
//! §3–§6).
//!
//! 1. **Which feeds:** every enabled feed of the provider that isn't busy (a feed whose download
//!    is staged or waiting for ingest is left out, with no check recorded, until its run is
//!    stored; "Check now" waits the same way); under a `cron` trigger, a feed before its list's
//!    `! Expires:` floor is left out too (feeds.md §5). Each goes to the module as a
//!    [`FileCheck`] with its own `last`, so a file left out of a check, added later, or failed or
//!    missing last time still sees every change since its own last run.
//! 2. **The module's `check()`** runs in the light lane, keyed by module (its share), with the
//!    provider's state, the config's `${secret:name}` references resolved just before the call
//!    (errors redacted of every secret value used), and the `files` patterns as `select`. For
//!    feeds without a warm start in their epoch, the same job reads `history()` first
//!    (feed-scheduling.md §6), a few per check.
//! 3. **The provider:** the check is recorded (`feed_provider_checks`, with its cause); the
//!    module's provider state and listing are kept. A check that failed as a whole, or in every
//!    file, starts or continues the provider's failing streak (`feed_provider_down` after its
//!    threshold, 1 h); any file that succeeds ends it. A walk the module couldn't finish raises
//!    `feed_provider_listing_incomplete` for a provider whose `files` holds globs, until a
//!    listing succeeds. A listing adds feeds for newly selected files ([`super::select`]).
//! 4. **Each feed:** `Unchanged` → recorded, `confirmed_at` set on the run that read what the
//!    check observed (a held run only when it is that run, it has waited `confirm_after`, and
//!    this wasn't the `http` Range rung); `Changed` → the staged file becomes a blob (identical
//!    to the newest run's: unchanged, the file's state still kept) and the run goes to the heavy
//!    lane; an error (`Missing` included) → recorded, the feed's error backoff, and `feed_down`
//!    once every check of the feed has failed for its threshold while the provider's other
//!    checks work. After `RateLimited`, no check through the module starts until `until` (at
//!    most 1 h).
//! 5. **Void:** a check whose provider's `module` or `config` changed, or whose feed was deleted
//!    (and maybe created again), while it ran stores nothing it observed of that source (feeds.md
//!    §3; storage.md §4): each transaction checks the source generations it read
//!    (`store::provider_source_current`, `store::source_current`). A check whose provider's
//!    selection (`files`, `exclude`, or the source) changed while it ran stores no provider state
//!    or listing and adds no feeds (`store::provider_list_current`, checked in the provider's
//!    transaction and again in the one that adds feeds), so a listing for the old selection never
//!    overwrites the reset an edit made (providers.md §2 Listing).
//! 6. **Busy feeds** left out of the check (step 1) keep what made the provider due: the nudges
//!    recorded before the check stay, and each such feed makes its provider due at once when its
//!    run is stored ([`super::Feeds::owe`]).
//!
//! Every successful check of a feed trains the feed's model and asks for the next check
//! ([`schedule::feed_ask`]), spaced from the feed's own last check: one that came before its ask
//! and found none of its changes (a sibling's) never moves that ask later
//! ([`schedule::ask_after_check`]); the provider is due at its feeds' earliest ask or by its
//! trigger ([`schedule::provider_due`]), never sooner than `min_interval`. After each successful
//! check, `feed_stale` is judged against the reference frozen at the feed's last change
//! ([`super::stale`]). The model is trained on a copy, put in place only by the transaction that
//! stores the check, after it commits with the source still current, so a voided check trains
//! nothing.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use jiff::Timestamp;
use serde_json::{Value, json};

use super::ingest::{DownloadInput, Work};
use super::schedule::{self, learner::Obs};
use super::store::{self, CheckRecord, FeedState, RunRow};
use super::types::RunStatus;
use super::{Cause, metrics, stale};
use crate::alerts::{Changes as AlertChanges, RaiseSpec, Severity};
use crate::config::model::{FeedDef, FeedProviderDef, Trigger};
use crate::modules::download::{
    ChangeTime, CheckError, CheckOutcome, Ctx, FileCheck, LastRun, Listing, ProviderCheck, StagedFile,
};
use crate::state::SharedState;

/// The longest one file's share of a check may take: the body deadline (5 min,
/// `client::HttpOptions`) plus the small requests around it.
pub const FILE_DEADLINE: Duration = Duration::from_secs(8 * 60);
/// The longest a whole check may take, however many files it covers.
pub const MAX_CHECK_DEADLINE: Duration = Duration::from_secs(60 * 60);
/// The longest the warm-start history of one file may take (it pages the commits API).
const HISTORY_DEADLINE: Duration = Duration::from_secs(120);
/// Feeds whose warm start one check reads (each pages the commits API; GitHub's quota).
pub const WARM_PER_CHECK: usize = 5;
/// The longest error text a check record keeps.
const MAX_ERROR: usize = 500;

/// The deadline of a check covering `files` files.
pub fn check_deadline(files: usize) -> Duration {
    (FILE_DEADLINE + Duration::from_secs(60) * u32::try_from(files.saturating_sub(1)).unwrap_or(u32::MAX))
        .min(MAX_CHECK_DEADLINE)
}

/// The feeds a check holds busy; dropping it frees the ones whose run didn't go to the heavy
/// lane (that job's guard frees those).
struct Held {
    state: SharedState,
    feeds: BTreeSet<String>,
}

impl Held {
    /// A run of `feed` went to the heavy lane: its job frees it.
    fn keep(&mut self, feed: &str) {
        self.feeds.remove(feed);
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        for f in std::mem::take(&mut self.feeds) {
            self.state.feeds.release(&self.state, &f);
        }
    }
}

/// Runs one check of `provider` (the caller marked it checking) and frees it. A failed setup's
/// backoff is installed before the provider is freed, so the scheduler can't claim it in
/// between; a panic or a cancellation of this task frees it too ([`Release`]).
pub async fn run(state: SharedState, provider: String, cause: Cause) {
    let s = state.clone();
    let p = provider.clone();
    let mut release = Release::new(move || s.feeds.provider_done(&s, &p));
    match run_inner(&state, &provider, cause, &mut release).await {
        Ok(()) => state.feeds.setup_ok(&provider),
        Err(e) => {
            // Nothing could be recorded (the database): back off in memory, as the error backoff
            // would (feed-scheduling.md §5).
            let n = state.feeds.setup_failed(&provider);
            let due = Timestamp::now() + schedule::backoff(n);
            tracing::warn!(provider = %provider, failures = n, error = %format!("{e:#}"), "feed provider check failed to run");
            state.feeds.retry_at(&provider, due);
        }
    }
    release.now();
}

/// Frees a checking provider exactly once: when its check ends, or when the task running it
/// panics or is cancelled (#45: the provider would otherwise stay `checking` until a restart).
/// While the check's light-lane job runs, freeing waits for it: dropping its join handle doesn't
/// stop it, and the provider must not be checked twice at once.
pub(crate) struct Release {
    free: Option<Box<dyn FnOnce() + Send>>,
    /// The check's light-lane job while it runs.
    lane: Option<tokio::task::JoinHandle<()>>,
}

impl Release {
    pub(crate) fn new(free: impl FnOnce() + Send + 'static) -> Self {
        Self {
            free: Some(Box::new(free)),
            lane: None,
        }
    }

    /// The check's light-lane job is running: a cancellation frees the provider when it ends.
    pub(crate) fn lane(&mut self, job: tokio::task::JoinHandle<()>) {
        self.lane = Some(job);
    }

    /// The light-lane job ended.
    pub(crate) fn lane_done(&mut self) {
        self.lane = None;
    }

    /// The check ended: frees the provider now.
    pub(crate) fn now(mut self) {
        self.lane = None;
        if let Some(f) = self.free.take() {
            f();
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        let Some(free) = self.free.take() else { return };
        let lane = self.lane.take().filter(|j| !j.is_finished());
        match (lane, tokio::runtime::Handle::try_current()) {
            (Some(job), Ok(rt)) => {
                tracing::warn!(
                    "a feed provider check ended early; the provider is freed once its download ends"
                );
                rt.spawn(async move {
                    let _ = job.await;
                    free();
                });
            }
            // No runtime (core is stopping): nothing would run another check anyway.
            (Some(_), Err(_)) => {}
            (None, _) => {
                tracing::warn!("a feed provider check ended early; the provider is freed");
                free();
            }
        }
    }
}

/// What the stored history says about one feed before a check.
pub(crate) struct FeedBefore {
    pub st: FeedState,
    pub newest_download: Option<RunRow>,
    pub newest_blob: Option<String>,
    pub mean_unchanged_bytes: Option<f64>,
    pub source: Option<store::StoredSource>,
}

pub(crate) fn load_feed_before(c: &rusqlite::Connection, f: &str) -> Result<FeedBefore> {
    let st = store::load_state(c, f)?;
    let newest_download = store::newest_download(c, f)?;
    let newest_blob = store::newest_with_blob(c, f)?.and_then(|r| r.blob);
    let since = crate::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(24 * 7)));
    let mean_unchanged_bytes: Option<f64> = c.query_row(
        "SELECT avg(bytes) FROM feed_checks WHERE feed_id = ?1 AND ok = 1 AND changed = 0 AND t >= ?2 AND method <> 'bootstrap'",
        rusqlite::params![f, since],
        |r| r.get(0),
    )?;
    let source = store::stored_source(c, f)?;
    Ok(FeedBefore {
        st,
        newest_download,
        newest_blob,
        mean_unchanged_bytes,
        source,
    })
}

/// Checks change times against this check's interval (feed-scheduling.md §3): an exact time
/// older than the previous successful check, or later than this check, is an interval.
pub fn checked_times(times: &[ChangeTime], prev_ok: Option<Timestamp>, now: Timestamp) -> Vec<ChangeTime> {
    let mut out = Vec::new();
    let mut interval = false;
    for t in times {
        match *t {
            ChangeTime::Exact(x) if x <= now && prev_ok.is_none_or(|p| x > p) => {
                out.push(ChangeTime::Exact(x))
            }
            ChangeTime::Exact(x) if prev_ok.is_none() && x > now => interval = true,
            ChangeTime::Exact(_) | ChangeTime::Interval { .. } => interval = true,
        }
    }
    out.truncate(1000);
    if interval && out.is_empty() {
        out.push(interval_since(prev_ok, now));
    }
    out
}

fn interval_since(prev_ok: Option<Timestamp>, now: Timestamp) -> ChangeTime {
    match prev_ok {
        Some(lo) => ChangeTime::Interval { lo, hi: now },
        None => ChangeTime::Exact(now),
    }
}

pub(crate) fn obs_of(now: Timestamp, times: &[ChangeTime]) -> Obs {
    let mut exact = Vec::new();
    let mut interval = false;
    for t in times {
        match t {
            ChangeTime::Exact(x) => exact.push(schedule::to_secs(*x)),
            ChangeTime::Interval { .. } => interval = true,
        }
    }
    Obs {
        t: schedule::to_secs(now),
        exact,
        interval,
    }
}

/// The learner summary kept in `feed_state.learner_json` (rebuildable).
fn learner_summary(l: &super::Learner, now: Timestamp) -> Value {
    json!({
        "k": l.k,
        "k_chosen_at": l.k_chosen_at,
        "period": l.candidates().get(l.best).and_then(|c| c.period),
        "pattern": l.describe(schedule::to_secs(now)),
    })
}

/// The last full download and its `! Expires:`, for the cron floor (feeds.md §5).
#[derive(Clone, Copy)]
struct Download {
    at: Option<Timestamp>,
    expires_s: Option<u64>,
}

impl Download {
    fn previous(b: &FeedBefore) -> Self {
        Self {
            at: b.st.last_download_at,
            expires_s: b.st.expires_s,
        }
    }

    fn floor(&self) -> Option<Timestamp> {
        schedule::expires_floor(self.at, self.expires_s)
    }
}

/// Moves a staged download into the blob store (`blobs/<b3[0:2]>/<b3>`), durably, and
/// registers it. A stored blob (a manual save) is only registered.
pub(crate) fn adopt(
    c: &rusqlite::Transaction<'_>,
    data_dir: &std::path::Path,
    file: &mut StagedFile,
    kind: &str,
) -> Result<String> {
    let b3 = file.blake3().to_string();
    if let Some(tmp) = file.take_temp_path() {
        let dst = crate::blobs::path(data_dir, &b3)?;
        let dir = dst.parent().context("blob dir")?.to_path_buf();
        crate::util::ensure_dir(&dir)?;
        if dst.exists() {
            let _ = std::fs::remove_file(&tmp);
        } else {
            std::fs::rename(&tmp, &dst).with_context(|| format!("move a download into {}", dir.display()))?;
            crate::util::fsync_dir(&dir)?;
        }
    }
    crate::blobs::register(c, &b3, kind, file.size())?;
    Ok(b3)
}

/// What the light-lane job of a check returns.
enum LaneOut {
    /// The module is paused by a rate limit (set meanwhile): no request was made.
    Paused(Timestamp),
    Done {
        /// The warm starts read: feed id → its file's change times (or why not).
        history: Vec<(String, Result<Vec<ChangeTime>, CheckError>)>,
        outcome: Box<Result<ProviderCheck, CheckError>>,
        /// What the module reported through `Ctx::listing_incomplete`.
        incomplete: Option<String>,
    },
}

/// One feed's part of a check: what every per-feed step needs.
struct FeedCtx<'a> {
    state: &'a SharedState,
    pdef: &'a FeedProviderDef,
    def: &'a FeedDef,
    before: &'a FeedBefore,
    source_gen: Option<i64>,
    provider_check_id: Option<i64>,
    now: Timestamp,
    duration_ms: u64,
}

impl FeedCtx<'_> {
    fn feed(&self) -> &str {
        &self.def.id
    }

    /// What the staleness judge needs after a successful check (feed-scheduling.md §8).
    fn stale_input(&self, tr: &Trained) -> stale::Input {
        stale::Input {
            feed: self.def.id.clone(),
            name: self.def.name.clone(),
            provider: Some(self.pdef.id.clone()),
            now: self.now,
            change: tr.frozen.clone(),
            pattern: tr.pattern.clone(),
            days: self.state.settings().alerts.feed_stale_days,
        }
    }

    /// Trains the feed's learner with a successful check's outcome and returns its ask, the
    /// predicted rate, the learner summary and, when it recorded a change, the staleness
    /// reference to freeze (feed-scheduling.md §4, §5, §8).
    ///
    /// The training happens on a copy of the learner ([`Trained::learner`]): the transaction
    /// storing the check puts it in place ([`super::Feeds::install_learner`]) only once it commits
    /// with the feed's source still current (feed-scheduling.md §4: failed or voided checks never
    /// train the model).
    fn train(&self, failures: u32, train: Option<&Obs>, download: Download) -> Trained {
        let mut frozen = None;
        let mut l = self.state.feeds.learner(self.feed()).unwrap_or_default();
        if let Some(o) = train {
            l.observe(o, true);
            if !o.exact.is_empty() || o.interval {
                frozen = l.last_change.map(|t| (l.frozen(), t, l.describe(o.t)));
            }
        }
        let predicted = Some(l.rate(schedule::to_secs(self.now)));
        let summary = Some(learner_summary(&l, self.now));
        let fresh = schedule::feed_ask(&schedule::Inputs {
            now: self.now,
            schedule: &self.pdef.trigger,
            last_check: Some(self.now),
            failures,
            expires_s: download.expires_s,
            last_download: download.at,
            learner: Some(&l),
            cost_factor: schedule::cost_factor(self.before.mean_unchanged_bytes),
        });
        // Spaced from the feed's own last check (feed-scheduling.md §5 "Spacing").
        let ask = match train {
            Some(o) => schedule::ask_after_check(
                fresh,
                self.now,
                self.before.st.next_ask_at,
                self.before.st.failures > 0,
                !o.exact.is_empty() || o.interval,
            ),
            None => fresh,
        };
        Trained {
            ask,
            predicted,
            summary,
            frozen,
            pattern: Some(l.describe(schedule::to_secs(self.now))),
            learner: train.is_some().then_some(l),
        }
    }
}

/// What training the model gave.
struct Trained {
    ask: Option<Timestamp>,
    predicted: Option<f64>,
    summary: Option<Value>,
    /// `(model, change time, pattern)` to freeze when the check recorded a change.
    frozen: Option<(schedule::learner::Frozen, f64, String)>,
    pattern: Option<String>,
    /// The trained copy, to put in place once the check is stored (none when nothing trained).
    learner: Option<super::Learner>,
}

async fn run_inner(state: &SharedState, provider: &str, cause: Cause, release: &mut Release) -> Result<()> {
    let pdef = state
        .feeds
        .provider_def(provider)
        .ok_or_else(|| anyhow!("no feed provider {provider:?}"))?;
    if !pdef.enabled {
        return Ok(());
    }
    let module = state
        .feeds
        .registry()
        .get(&pdef.module)
        .ok_or_else(|| anyhow!("{:?} is not a download module", pdef.module))?;
    let now = Timestamp::now();
    let cron = matches!(pdef.trigger, Trigger::Cron { .. });
    // The feeds this check covers (step 1).
    let candidates: Vec<FeedDef> = state
        .feeds
        .provider_feeds(provider)
        .into_iter()
        .filter(|f| f.enabled)
        // "Check now" bypasses the trigger, a cron feed's `! Expires:` floor included.
        .filter(|f| {
            cause == Cause::CheckNow || !(cron && state.feeds.floor(&f.id).is_some_and(|fl| fl > now))
        })
        .collect();
    let ids: Vec<String> = candidates.iter().map(|f| f.id.clone()).collect();
    let taken: BTreeSet<String> = state.feeds.acquire_many(&ids).into_iter().collect();
    // Busy feeds (a run staged or waiting): left out, with no check recorded, until their run is
    // stored (feeds.md §3 step 1); they keep the provider owing them this check.
    let left_out: Vec<String> = ids.iter().filter(|id| !taken.contains(*id)).cloned().collect();
    let mut held = Held {
        state: state.clone(),
        feeds: taken.clone(),
    };
    let mut feeds: Vec<FeedDef> = candidates.into_iter().filter(|f| taken.contains(&f.id)).collect();
    tracing::debug!(provider = %provider, cause = cause.as_str(), feeds = feeds.len(), "feed provider check");
    // What the stored history says, with the source generations this check observes for.
    let (pstate, stored, befores) = {
        let (p, fids) = (
            provider.to_string(),
            feeds.iter().map(|f| f.id.clone()).collect::<Vec<_>>(),
        );
        state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let pstate = store::load_provider_state(&tx, &p)?;
                let stored = store::stored_provider(&tx, &p)?;
                let mut befores = HashMap::new();
                for f in &fids {
                    befores.insert(f.clone(), load_feed_before(&tx, f)?);
                }
                // A nudge after this time makes the provider due again (feed-scheduling.md §7).
                store::ensure_provider_state(&tx, &p)?;
                tx.execute(
                    "UPDATE feed_provider_state SET check_started_at = ?2 WHERE provider_id = ?1",
                    rusqlite::params![p, crate::util::ts(&now)],
                )?;
                tx.commit()?;
                Ok::<_, anyhow::Error>((pstate, stored, befores))
            })
            .await?
    };
    // The stored provider must be the one `pdef` names, read with its generation: an edit or a
    // deletion committed after the runtime loaded `pdef` voids the check; the reload that
    // follows runs what comes next.
    let (provider_gen, list_gen) = match &stored {
        Some(sp) if sp.is(&pdef) => (sp.source_gen, sp.list_gen),
        _ => {
            void(state, provider);
            return Ok(());
        }
    };
    // Each feed's stored source must be the one the runtime loaded.
    feeds.retain(|f| {
        befores
            .get(&f.id)
            .and_then(|b| b.source.as_ref())
            .is_some_and(|s| s.provider == f.provider && s.file == f.file)
    });
    let started = tokio::time::Instant::now();
    let prepared = prepare(state, &pdef, &pstate).await;
    let (ctx, cfg, redactor) = match prepared {
        Ok(p) => p,
        Err(e) => {
            // A failure before the module is called (the resolver's client, the secrets) is a
            // failed check like any other (feeds.md §6).
            let e = CheckError::Failed(e);
            let outcome: Result<ProviderCheck, CheckError> = Err(e);
            return finish(
                state,
                &pdef,
                &feeds,
                &befores,
                &mut held,
                Finish {
                    cause,
                    now,
                    provider_gen,
                    list_gen,
                    left_out,
                    duration_ms: picket_api::duration::as_millis_u64(started.elapsed()),
                    outcome,
                    incomplete: None,
                },
            )
            .await;
        }
    };
    let checks: Vec<FileCheck> = feeds
        .iter()
        .map(|f| FileCheck {
            file: f.file.clone().unwrap_or_default(),
            last: befores.get(&f.id).and_then(|b| b.st.last.clone()),
        })
        .collect();
    // Warm starts to read (feed-scheduling.md §6): feeds without one in their epoch.
    let warm: Vec<(String, String)> = feeds
        .iter()
        .filter(|f| befores.get(&f.id).is_some_and(|b| b.st.warm_started_at.is_none()))
        .take(WARM_PER_CHECK)
        .map(|f| (f.id.clone(), f.file.clone().unwrap_or_default()))
        .collect();
    let select = pdef.select();
    let state_in = pstate.state.clone();
    let m = module.clone();
    let key = format!("feed:{}", pdef.module);
    let (s2, module_id) = (state.clone(), pdef.module.clone());
    let deadline = check_deadline(checks.len());
    let job = move |slot: crate::scheduler::LightSlot| async move {
        // A rate limit that started while this check waited: no request (providers.md §2).
        if let Some(u) = s2.feeds.paused_until(&module_id) {
            return LaneOut::Paused(u);
        }
        let ctx = ctx.with_slot(slot);
        let mut history = Vec::new();
        for (feed, file) in &warm {
            let r = match tokio::time::timeout(HISTORY_DEADLINE, m.history(&ctx, &cfg, file)).await {
                Ok(Ok(t)) => Ok(t),
                Ok(Err(e)) => match e.downcast::<CheckError>() {
                    Ok(ce) => Err(ce),
                    Err(e) => Err(CheckError::Failed(e)),
                },
                Err(_) => Err(CheckError::Failed(anyhow!("reading the history timed out"))),
            };
            let limited = matches!(r, Err(CheckError::RateLimited { .. }));
            history.push((feed.clone(), r));
            if limited {
                break;
            }
        }
        if let Some((_, Err(CheckError::RateLimited { until }))) = history.last() {
            // The history hit the rate limit: the check would too. The module is paused like
            // after a rate-limited check.
            let until = *until;
            return LaneOut::Done {
                history,
                outcome: Box::new(Err(CheckError::RateLimited { until })),
                incomplete: None,
            };
        }
        let r =
            tokio::time::timeout(deadline, m.check(&ctx, &cfg, state_in.as_ref(), &checks, &select)).await;
        let incomplete = ctx.take_listing_incomplete();
        drop(ctx);
        LaneOut::Done {
            history,
            outcome: Box::new(match r {
                Ok(r) => r,
                Err(_) => Err(CheckError::Failed(anyhow!("the check timed out"))),
            }),
            incomplete,
        }
    };
    let keys = [key.as_str(), crate::modules::download::FEED_SHARE_KEY];
    // The job's output goes through a channel, so `release` can hold its handle: a cancelled
    // check frees the provider only once the job ends.
    let (out_tx, out_rx) = tokio::sync::oneshot::channel();
    let job = move |slot: crate::scheduler::LightSlot| async move {
        let _ = out_tx.send(job(slot).await);
    };
    let Some(h) = state.scheduler.light.spawn_slotted(&keys, job) else {
        // The light lane is full: try again in a minute, nothing recorded; the retry holds
        // through the check's end (#45).
        state
            .feeds
            .retry_at(provider, now + jiff::SignedDuration::from_mins(1));
        return Ok(());
    };
    release.lane(h);
    let joined = match release.lane.as_mut() {
        Some(h) => h.await,
        None => Ok(()),
    };
    release.lane_done();
    let h = async move {
        match joined {
            Ok(()) => out_rx
                .await
                .map_err(|_| "the check's job ended without an outcome".to_string()),
            Err(e) => Err(e.to_string()),
        }
    };
    let redact = |e: CheckError| match e {
        CheckError::Failed(err) => CheckError::Failed(anyhow!(redactor.redact(&format!("{err:#}")))),
        other => other,
    };
    let (history, outcome, incomplete) = match h.await {
        Ok(LaneOut::Paused(u)) => {
            state.feeds.set_due(provider, u);
            return Ok(());
        }
        Ok(LaneOut::Done {
            history,
            outcome,
            incomplete,
        }) => {
            let outcome = (*outcome).map_err(redact).map(|mut pc| {
                pc.files = std::mem::take(&mut pc.files)
                    .into_iter()
                    .map(|(f, r)| (f, r.map_err(redact)))
                    .collect();
                pc
            });
            (history, outcome, incomplete.map(|i| redactor.redact(&i)))
        }
        Err(e) => (
            vec![],
            Err(CheckError::Failed(anyhow!("the check panicked: {e}"))),
            None,
        ),
    };
    // Warm starts first, so the first check's outcome trains a warm model.
    for (feed, r) in history {
        let Some(def) = feeds.iter().find(|f| f.id == feed) else {
            continue;
        };
        let Some(b) = befores.get(&feed) else { continue };
        let sgen = b.source.as_ref().and_then(|s| s.source_gen);
        match r {
            Ok(times) => warm_start(state, &pdef, def, sgen, now, &times).await,
            Err(CheckError::RateLimited { .. }) => {}
            Err(e) => {
                tracing::info!(feed = %feed, error = %e, "no warm start: the history can't be read");
                warm_start(state, &pdef, def, sgen, now, &[]).await;
            }
        }
    }
    finish(
        state,
        &pdef,
        &feeds,
        &befores,
        &mut held,
        Finish {
            cause,
            now,
            provider_gen,
            list_gen,
            left_out,
            duration_ms: picket_api::duration::as_millis_u64(started.elapsed()),
            outcome,
            incomplete,
        },
    )
    .await
}

/// What [`finish`] stores.
struct Finish {
    cause: Cause,
    now: Timestamp,
    provider_gen: Option<i64>,
    /// The selection generation the check listed for.
    list_gen: Option<i64>,
    /// Busy feeds the check left out.
    left_out: Vec<String>,
    duration_ms: u64,
    outcome: Result<ProviderCheck, CheckError>,
    incomplete: Option<String>,
}

/// Stores a check's outcome: the provider's record, state, listing and alerts, then each feed's.
async fn finish(
    state: &SharedState,
    pdef: &FeedProviderDef,
    feeds: &[FeedDef],
    befores: &HashMap<String, FeedBefore>,
    held: &mut Held,
    fin: Finish,
) -> Result<()> {
    let Finish {
        cause,
        now,
        provider_gen,
        list_gen,
        left_out,
        duration_ms,
        outcome,
        incomplete,
    } = fin;
    let gens = Gens {
        provider_gen,
        list_gen,
        left_out,
    };
    // Per-file results, in the order of `feeds`.
    let (pstate_new, listing, results): (
        Option<Value>,
        Option<Listing>,
        Vec<Result<CheckOutcome, CheckError>>,
    ) = match outcome {
        Err(e) => {
            let msg = e.to_string();
            let rl = match &e {
                CheckError::RateLimited { until } => Some(*until),
                _ => None,
            };
            let results = feeds
                .iter()
                .map(|_| match rl {
                    Some(until) => Err(CheckError::RateLimited { until }),
                    None => Err(CheckError::Failed(anyhow!("{msg}"))),
                })
                .collect();
            let whole = WholeFailure {
                msg,
                rate_limited: rl,
            };
            return finish_feeds(
                state,
                pdef,
                feeds,
                befores,
                held,
                cause,
                now,
                gens,
                duration_ms,
                None,
                None,
                results,
                Some(whole),
                incomplete,
            )
            .await;
        }
        Ok(pc) => {
            let mut by_file: HashMap<String, Result<CheckOutcome, CheckError>> = HashMap::new();
            for (f, r) in pc.files {
                // A result for a file not asked about is ignored; a second for one, too.
                by_file.entry(f).or_insert(r);
            }
            let results = feeds
                .iter()
                .map(|f| {
                    by_file
                        .remove(f.file.as_deref().unwrap_or_default())
                        .unwrap_or_else(|| {
                            Err(CheckError::Failed(anyhow!(
                                "the module gave no result for this file"
                            )))
                        })
                })
                .collect();
            // No file name is blank: a listing's blank path is no file (it is neither stored
            // nor selected).
            let listing = pc.listing.map(|mut l| {
                l.files.retain(|f| !f.trim().is_empty());
                l
            });
            (Some(pc.state), listing, results)
        }
    };
    finish_feeds(
        state,
        pdef,
        feeds,
        befores,
        held,
        cause,
        now,
        gens,
        duration_ms,
        pstate_new,
        listing,
        results,
        None,
        incomplete,
    )
    .await
}

/// What a check read of its provider, for the transactions that store it.
struct Gens {
    provider_gen: Option<i64>,
    list_gen: Option<i64>,
    left_out: Vec<String>,
}

/// A check that failed as a whole.
struct WholeFailure {
    msg: String,
    rate_limited: Option<Timestamp>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the end of a provider check: the check's state and every result it stores"
)]
async fn finish_feeds(
    state: &SharedState,
    pdef: &FeedProviderDef,
    feeds: &[FeedDef],
    befores: &HashMap<String, FeedBefore>,
    held: &mut Held,
    cause: Cause,
    now: Timestamp,
    gens: Gens,
    duration_ms: u64,
    pstate_new: Option<Value>,
    listing: Option<Listing>,
    results: Vec<Result<CheckOutcome, CheckError>>,
    whole: Option<WholeFailure>,
    incomplete: Option<String>,
) -> Result<()> {
    let provider = pdef.id.clone();
    let now_done = Timestamp::now();
    let Gens {
        provider_gen,
        list_gen,
        left_out,
    } = gens;
    let keep_nudges = !left_out.is_empty();
    let all_failed = whole.is_some() || (!results.is_empty() && results.iter().all(Result::is_err));
    let error_text = match (&whole, all_failed) {
        (Some(w), _) => Some(crate::util::sanitize_for_message(&w.msg, MAX_ERROR)),
        (None, true) => results
            .iter()
            .find_map(|r| r.as_ref().err())
            .map(|e| crate::util::sanitize_for_message(&format!("every file failed: {e}"), MAX_ERROR)),
        _ => None,
    };
    // A rate limit anywhere pauses the module (providers.md §2).
    let pause = whole
        .as_ref()
        .and_then(|w| w.rate_limited)
        .or_else(|| {
            results.iter().find_map(|r| match r {
                Err(CheckError::RateLimited { until }) => Some(*until),
                _ => None,
            })
        })
        .map(|u| u.min(now + jiff::SignedDuration::from_hours(1)).max(now));
    if let Some(u) = pause {
        state.feeds.set_pause(&pdef.module, u);
    }
    // 1. The provider's record, state, listing and alerts.
    let threshold = state.settings().alerts.threshold("feed_provider_down");
    let has_globs = pdef.has_globs();
    let listing_json = listing.as_ref().map(serde_json::to_string).transpose()?;
    let pstate_json = pstate_new.as_ref().map(Value::to_string);
    let alerts = state.alerts.clone();
    let p = provider.clone();
    let pname = pdef.name.clone();
    let module_name = pdef.module.clone();
    let incomplete2 = incomplete.clone();
    let listed = listing.is_some();
    let stored = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if let Some(u) = pause {
                store::set_pause(&tx, &module_name, u)?;
            }
            if !store::provider_source_current(&tx, &p, provider_gen)? {
                tx.commit()?;
                return Ok::<_, anyhow::Error>(None);
            }
            // The selection changed while the check ran: its provider state and listing are for
            // the old one (an edit after a limited listing reset the state, so it lists again).
            let selection_ok = store::provider_list_current(&tx, &p, list_gen)?;
            let check_id = store::record_provider_check(
                &tx,
                &p,
                now,
                cause.as_str(),
                duration_ms,
                !all_failed,
                error_text.as_deref(),
            )?;
            if let Some(s) = pstate_json.as_ref().filter(|_| selection_ok) {
                tx.execute(
                    "UPDATE feed_provider_state SET state_json = ?2 WHERE provider_id = ?1",
                    rusqlite::params![p, s],
                )?;
            }
            if let Some(l) = listing_json.as_ref().filter(|_| selection_ok) {
                tx.execute(
                    "UPDATE feed_provider_state SET listing_json = ?2 WHERE provider_id = ?1",
                    rusqlite::params![p, l],
                )?;
            }
            // The failing streak (feed_provider_down, core.md §9).
            let since: Option<String> = tx.query_row(
                "SELECT failing_since FROM feed_provider_state WHERE provider_id = ?1",
                [&p],
                |r| r.get(0),
            )?;
            let since = if all_failed {
                let s = since.as_deref().and_then(crate::util::parse_ts).unwrap_or(now);
                tx.execute(
                    "UPDATE feed_provider_state SET failing_since = ?2 WHERE provider_id = ?1",
                    rusqlite::params![p, crate::util::ts(&s)],
                )?;
                Some(s)
            } else {
                tx.execute(
                    "UPDATE feed_provider_state SET failing_since = NULL WHERE provider_id = ?1",
                    [&p],
                )?;
                None
            };
            let mut ch = AlertChanges::default();
            let spec = RaiseSpec::new(
                "feed_provider_down",
                Severity::Warning,
                format!("feed_provider_down:{p}"),
                format!("Feed provider {pname}: every check has failed for an hour"),
                json!({"since": since.map(|s| crate::util::ts(&s)), "last_error": error_text}),
            )
            .feed_provider(p.clone());
            alerts.condition_in(&tx, &spec, since, threshold, now, &mut ch)?;
            let provider_down = crate::alerts::Alerts::is_open_in(&tx, &format!("feed_provider_down:{p}"))?;
            // A walk the module couldn't finish (providers.md §3).
            let key = format!("feed_provider_listing_incomplete:{p}");
            if listed && selection_ok {
                alerts.resolve_in(&tx, &key, Some(&json!({"by": "a listing finished"})), &mut ch)?;
            } else if let Some(why) = incomplete2.as_ref().filter(|_| has_globs && selection_ok) {
                let spec = RaiseSpec::new(
                    "feed_provider_listing_incomplete",
                    Severity::Warning,
                    key,
                    format!("Feed provider {pname} can't list the files its files can select"),
                    json!({"reason": why}),
                )
                .feed_provider(p.clone());
                if !crate::alerts::Alerts::is_open_in(&tx, &spec.dedupe_key)? {
                    alerts.raise_in(&tx, &spec, &mut ch)?;
                }
            }
            // The nudges recorded before this check started are served (feed-scheduling.md §7),
            // unless it left busy feeds out: they stay until a check covers those feeds too
            // (feeds.md §3 step 1), durable across a restart.
            if !keep_nudges {
                tx.execute(
                    "UPDATE feed_provider_state SET nudged_at = NULL
                     WHERE provider_id = ?1 AND nudged_at IS NOT NULL AND check_started_at IS NOT NULL AND nudged_at <= check_started_at",
                    [&p],
                )?;
            }
            let (nudge_pending, nudged_during): (bool, bool) = tx.query_row(
                "SELECT nudged_at IS NOT NULL, nudged_at IS NOT NULL AND (check_started_at IS NULL OR nudged_at > check_started_at)
                 FROM feed_provider_state WHERE provider_id = ?1",
                [&p],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok(Some((check_id, provider_down || all_failed, nudge_pending, nudged_during, selection_ok, ch)))
        })
        .await?;
    let Some((check_id, suppress_down, nudge_pending, nudged_during, selection_ok, ch)) = stored else {
        void(state, &provider);
        return Ok(());
    };
    state.alerts.announce(ch);
    // 2. Each feed.
    for (def, r) in feeds.iter().zip(results) {
        let Some(before) = befores.get(&def.id) else {
            continue;
        };
        let source_gen = before.source.as_ref().and_then(|s| s.source_gen);
        let fc = FeedCtx {
            state,
            pdef,
            def,
            before,
            source_gen,
            provider_check_id: Some(check_id),
            now: now_done,
            duration_ms,
        };
        let submitted = match r {
            Err(e) => {
                on_failure(&fc, e, suppress_down).await?;
                false
            }
            Ok(CheckOutcome::Unchanged {
                state: new_state,
                observed,
                bytes,
                method,
            }) => {
                let times = checked_times(&observed, before.st.last_ok_at, now_done);
                let new_last = match (&before.st.last, new_state) {
                    (Some(l), Some(s)) => Some(LastRun {
                        state: s,
                        ..l.clone()
                    }),
                    _ => None,
                };
                // The module says the source still serves `last`'s version.
                let seen = Seen {
                    blob: None,
                    version: before.st.last.as_ref().map(|l| l.version.clone()),
                    full: crate::modules::download::is_full_download(method),
                };
                on_unchanged(&fc, bytes, method, times, new_last, seen).await?
            }
            Ok(CheckOutcome::Changed {
                updated_at,
                version,
                state: fstate,
                change_times,
                file,
                bytes,
                method,
            }) => {
                let c = ChangedFile {
                    updated_at,
                    version,
                    state: fstate,
                    change_times,
                    file,
                    bytes,
                    method,
                };
                on_changed(&fc, c).await?
            }
        };
        if submitted {
            held.keep(&def.id);
        }
    }
    // 3. A listing adds feeds for newly selected files (feeds.md §1), while the source and the
    // selection it was taken for are still the provider's.
    if let Some(l) = listing.filter(|_| selection_ok) {
        let p = provider.clone();
        let r = state
            .config
            .change(move |tx| {
                if !store::provider_source_current(tx, &p, provider_gen).map_err(anyhow::Error::from)?
                    || !store::provider_list_current(tx, &p, list_gen).map_err(anyhow::Error::from)?
                {
                    return Ok(super::select::Applied::default());
                }
                let mut model = crate::config::store::load_kind(tx, crate::config::EntityKind::Feed)?;
                let applied = super::select::apply_in(tx, &mut model, &p, Some(&l))
                    .map_err(crate::error::CoreError::Other)?;
                Ok(applied)
            })
            .await;
        match r {
            Ok(a) if !a.created.is_empty() => {
                tracing::info!(provider = %provider, feeds = ?a.created, "the provider's listing added feeds");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(provider = %provider, error = %e, "cannot add the listing's new feeds"),
        }
    }
    // 4. The provider's next check: the trigger's own next time (cron, sqs backstop) from the
    // provider's current definition, so a trigger edited during the check isn't undone by the
    // one it started under (feed-scheduling.md §5).
    let (trigger_next, trigger_edited) = state.feeds.provider_checked(&provider, now_done, &pdef.trigger);
    if nudged_during {
        // A nudge during the check: due again when it ends (feed-scheduling.md §7).
        state.feeds.want_now(&provider, Cause::Sqs);
    }
    // Busy feeds left out: each makes the provider due at once when its run is stored, for the
    // nudge it kept or the cause of this check (feeds.md §3 step 1). A first check (a new
    // provider, an edit of its module or config) is owed as an edit's: the provider was just
    // checked, so the catch-up waits for `min_interval` like any check (feed-scheduling.md: a hard
    // floor "whatever starts them").
    let owed = (!left_out.is_empty()).then_some(match cause {
        _ if nudge_pending => Cause::Sqs,
        Cause::First => Cause::Edit,
        c => c,
    });
    if let Some(c) = owed {
        state.feeds.owe(&provider, &left_out, c);
    }
    if let Some(u) = pause {
        state
            .feeds
            .set_due(&provider, state.feeds.next_due(&provider).map_or(u, |d| d.max(u)));
    }
    let next = state.feeds.next_due(&provider);
    let p = provider.clone();
    // A cause due at once that busy feeds still wait for survives a restart (a kept nudge does
    // by itself).
    let due_cause = owed.filter(|c| c.now_wanted()).map(Cause::as_str);
    let _ = state
        .db
        .write(move |c| {
            Ok::<_, anyhow::Error>(store::set_provider_next(c, &p, trigger_next.or(next), due_cause)?)
        })
        .await;
    if trigger_edited {
        // The feeds' asks this check stored follow the trigger it started under: derive them
        // again from the current one (the edit's own derivation may have run before them).
        state.feeds.trigger_edited(state, &provider).await;
    }
    Ok(())
}

/// The module's context, its config with secrets resolved, and the redactor for its errors.
async fn prepare(
    state: &SharedState,
    pdef: &FeedProviderDef,
    pstate: &store::ProviderState,
) -> Result<(Ctx, Value, picket_lookup::secrets::Redactor)> {
    let settings = state.settings();
    let http = state.feeds.http(&settings.resolver)?;
    let max = u64::from(settings.feeds.max_download_mib) * 1024 * 1024;
    let staging = state.data_dir.join("staging");
    // Secrets resolved just before the call (providers.md §2), redacted from every message.
    let mut names = Vec::new();
    {
        let mut v = Vec::new();
        collect(&pdef.config, &mut v);
        names.extend(v);
    }
    names.sort();
    names.dedup();
    let values = if names.is_empty() {
        Default::default()
    } else {
        state.config.secret_values(names).await?
    };
    let r = picket_lookup::secrets::resolve(&pdef.config, &values).map_err(|e| anyhow!("{e}"))?;
    let ctx = Ctx::new(http, &pdef.id, &staging, max, state.shutdown.child_token())
        .with_now(Timestamp::now(), pstate.last_ok_at);
    Ok((ctx, r.config, r.redactor))
}

/// The secret names a config references.
fn collect(v: &Value, out: &mut Vec<String>) {
    let p = FeedProviderDef {
        config: v.clone(),
        ..Default::default()
    };
    out.extend(p.secret_refs());
}

/// What an unchanged check saw the source serve.
struct Seen {
    /// The blob of a full download identical to the newest stored one.
    blob: Option<String>,
    /// The module's version.
    version: Option<String>,
    /// The check transferred the whole file.
    full: bool,
}

/// A `Changed` outcome's parts.
struct ChangedFile {
    updated_at: Timestamp,
    version: String,
    state: Value,
    change_times: Vec<ChangeTime>,
    file: StagedFile,
    bytes: u64,
    method: &'static str,
}

/// The change times a check records for a feed. A first check (no `last`: a new, retargeted or
/// restored feed) records a change only if the file's BLAKE3 differs from the feed's
/// `seen_blake3`, and none without one (feed-scheduling.md §3), so a restore, a changed ETag on
/// the same bytes or a new feed fakes no change.
fn change_times_of(b: &FeedBefore, c: &ChangedFile, now: Timestamp) -> Vec<ChangeTime> {
    if b.st.last.is_some() {
        let t = checked_times(&c.change_times, b.st.last_ok_at, now);
        return if t.is_empty() {
            vec![interval_since(b.st.last_ok_at, now)]
        } else {
            t
        };
    }
    match &b.st.seen_blake3 {
        Some(seen) if seen != c.file.blake3() => {
            let t = checked_times(&c.change_times, b.st.last_ok_at, now);
            if t.is_empty() {
                vec![interval_since(b.st.last_ok_at, now)]
            } else {
                t
            }
        }
        _ => vec![],
    }
}

async fn on_changed(fc: &FeedCtx<'_>, c: ChangedFile) -> Result<bool> {
    let state = fc.state;
    let feed = fc.feed().to_string();
    let now = fc.now;
    let identical = fc.before.newest_blob.as_deref() == Some(c.file.blake3());
    let times = change_times_of(fc.before, &c, now);
    let new_last = LastRun {
        updated_at: c.updated_at,
        version: c.version.clone(),
        state: c.state.clone(),
    };
    let b3 = c.file.blake3().to_string();
    if identical {
        // The same blob as the newest run's: unchanged, but the file's state is kept (feeds.md
        // §3 step 3); a full download (the `! Expires:` floor counts from it). A first check
        // whose bytes differ from `seen_blake3` still records its change.
        let seen = Seen {
            blob: Some(b3.clone()),
            version: Some(c.version.clone()),
            full: true,
        };
        drop(c.file);
        let f = feed.clone();
        let b = b3.clone();
        let sgen = fc.source_gen;
        state
            .db
            .write(move |db| {
                let tx = db.transaction()?;
                if store::source_current(&tx, &f, sgen)? {
                    store::set_seen_blake3(&tx, &f, &b)?;
                }
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        return on_unchanged(fc, c.bytes, c.method, times, Some(new_last), seen).await;
    }
    let obs = obs_of(now, &times);
    // The new file's `! Expires:` is known once it is parsed: its run applies the floor
    // (feeds.md §5).
    let download = Download {
        at: Some(now),
        expires_s: None,
    };
    let tr = fc.train(0, Some(&obs), download);
    let data_dir = state.data_dir.clone();
    let rec = CheckRecord {
        feed: feed.clone(),
        at: now,
        duration_ms: fc.duration_ms,
        method: c.method.to_string(),
        ok: true,
        changed: true,
        bytes: c.bytes,
        version: Some(c.version.clone()),
        predicted_rate: tr.predicted,
        error: None,
        changes: times.clone(),
        origin: "check",
        provider_check_id: fc.provider_check_id,
    };
    let f = feed.clone();
    let alerts = state.alerts.clone();
    let sgen = fc.source_gen;
    let summary = tr.summary.clone();
    let stale_in = fc.stale_input(&tr);
    let mut file = c.file;
    let ask = tr.ask;
    let (s2, trained) = (state.clone(), tr.learner);
    let stored = state
        .db
        .write(move |db| {
            let tx = db.transaction()?;
            if !store::source_current(&tx, &f, sgen)? {
                // Deleted or edited meanwhile: the staged file goes with `file`.
                return Ok::<_, anyhow::Error>(None);
            }
            let blob = adopt(&tx, &data_dir, &mut file, crate::blobs::kind::DOWNLOAD)?;
            store::record_check(&tx, &rec)?;
            store::set_ask(&tx, &f, ask)?;
            store::set_seen_blake3(&tx, &f, &blob)?;
            if let Some(s) = &summary {
                tx.execute(
                    "UPDATE feed_state SET learner_json = ?2 WHERE feed_id = ?1",
                    rusqlite::params![f, s.to_string()],
                )?;
            }
            let mut ch = AlertChanges::default();
            alerts.resolve_in(
                &tx,
                &format!("feed_down:{f}"),
                Some(&json!({"cleared": crate::util::now_ts()})),
                &mut ch,
            )?;
            stale::after_check(&tx, &alerts, &stale_in, &mut ch)?;
            tx.commit()?;
            alerts.committed(&ch);
            // In the writer, before any later transaction (a retarget among them) can run.
            if let Some(l) = trained {
                s2.feeds.install_learner(&f, l);
            }
            Ok(Some((blob, ch)))
        })
        .await?;
    let Some((blob, ch)) = stored else {
        tracing::info!(feed = %feed, "the feed was deleted or its source changed during the check; nothing was stored");
        return Ok(false);
    };
    state.alerts.announce(ch);
    state.feeds.set_ask(&feed, ask);
    metrics::check(state, &feed, true).await;
    state.feeds.submit(
        state,
        &feed,
        Work::Download(DownloadInput {
            blob,
            version: c.version,
            updated_at: c.updated_at,
            downloaded_at: now,
            state: c.state,
            source_gen: sgen,
            trigger_cron: matches!(fc.pdef.trigger, Trigger::Cron { .. }),
        }),
    );
    Ok(true)
}

async fn on_unchanged(
    fc: &FeedCtx<'_>,
    bytes: u64,
    method: &'static str,
    times: Vec<ChangeTime>,
    new_last: Option<LastRun>,
    seen: Seen,
) -> Result<bool> {
    let state = fc.state;
    let feed = fc.feed().to_string();
    let now = fc.now;
    let before = fc.before;
    let obs = obs_of(now, &times);
    // A full download moves the `! Expires:` floor (feeds.md §5); the file is the same, so its
    // `! Expires:` is too.
    let download = if seen.full {
        Download {
            at: Some(now),
            expires_s: before.st.expires_s,
        }
    } else {
        Download::previous(before)
    };
    let tr = fc.train(0, Some(&obs), download);
    // The run that read what this check saw (feeds.md §3 step 2): the module's version, or the
    // identical blob.
    let matched = {
        let (f, blob, version) = (feed.clone(), seen.blob.clone(), seen.version.clone());
        state
            .db
            .read(move |c| {
                Ok::<_, anyhow::Error>(store::newest_matching(
                    c,
                    &f,
                    blob.as_deref(),
                    version.as_deref(),
                )?)
            })
            .await?
    };
    let held = before
        .newest_download
        .as_ref()
        .filter(|r| r.status == Some(RunStatus::Held));
    // A held run is confirmed only if it is the run the source still serves, it has waited
    // `confirm_after`, and this wasn't the `http` Range rung (feeds.md §5).
    let confirm = matched
        .as_ref()
        .filter(|m| m.status == Some(RunStatus::Held))
        .and_then(|m| {
            let since = before
                .st
                .held_since
                .or(m.downloaded_at.as_deref().and_then(crate::util::parse_ts))?;
            let waited = now - since
                >= jiff::SignedDuration::from_secs(crate::util::sat_i64(
                    fc.def.sanity.confirm_after.as_secs(),
                ));
            (waited && method != "range").then_some(m.id)
        });
    // `confirmed_at` goes on the matched run; a held one only by its confirmation, which the
    // Confirm run records.
    let confirmed = matched
        .as_ref()
        .filter(|m| m.status != Some(RunStatus::Held))
        .map(|m| m.id);
    // A full download identical to another run while one is held: the source no longer serves
    // the held run, so it can never be confirmed; it is superseded (feeds.md §5).
    let supersede = match (&seen.blob, held, &matched) {
        (Some(_), Some(h), Some(m)) if m.id != h.id => Some(h.id),
        _ => None,
    };
    let rec = CheckRecord {
        feed: feed.clone(),
        at: now,
        duration_ms: fc.duration_ms,
        method: method.to_string(),
        ok: true,
        changed: false,
        bytes,
        version: seen.version.clone(),
        predicted_rate: tr.predicted,
        error: None,
        changes: times,
        origin: "check",
        provider_check_id: fc.provider_check_id,
    };
    let f = feed.clone();
    let alerts = state.alerts.clone();
    let full_at = seen.full.then_some(now);
    let expires = before.st.expires_s;
    let sgen = fc.source_gen;
    let summary = tr.summary.clone();
    let ask = tr.ask;
    let stale_in = fc.stale_input(&tr);
    let (s2, trained) = (state.clone(), tr.learner);
    let stored = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if !store::source_current(&tx, &f, sgen)? {
                return Ok::<_, anyhow::Error>(None);
            }
            store::record_check(&tx, &rec)?;
            store::set_ask(&tx, &f, ask)?;
            if let Some(l) = &new_last {
                store::set_last(&tx, &f, Some(l))?;
            }
            if let Some(at) = full_at {
                store::set_download(&tx, &f, at, expires)?;
            }
            if let Some(id) = confirmed {
                store::confirm_run(&tx, id, now)?;
            }
            if let Some(s) = &summary {
                tx.execute(
                    "UPDATE feed_state SET learner_json = ?2 WHERE feed_id = ?1",
                    rusqlite::params![f, s.to_string()],
                )?;
            }
            let mut ch = AlertChanges::default();
            if let Some(h) = supersede {
                let n = tx.execute(
                    "UPDATE feed_runs SET status = 'rejected', gate = 'superseded', error = ?2 WHERE id = ?1 AND status = 'held'",
                    rusqlite::params![h, "superseded: the source serves an earlier version again"],
                )?;
                if n > 0 {
                    store::set_held_since(&tx, &f, None)?;
                    alerts.resolve_in(
                        &tx,
                        &format!("feed_held:{f}"),
                        Some(&json!({"superseded": h, "by": "the source serves an earlier version again"})),
                        &mut ch,
                    )?;
                }
            }
            alerts.resolve_in(
                &tx,
                &format!("feed_down:{f}"),
                Some(&json!({"cleared": crate::util::now_ts()})),
                &mut ch,
            )?;
            stale::after_check(&tx, &alerts, &stale_in, &mut ch)?;
            tx.commit()?;
            alerts.committed(&ch);
            if let Some(l) = trained {
                s2.feeds.install_learner(&f, l);
            }
            Ok(Some(ch))
        })
        .await?;
    let Some(ch) = stored else {
        tracing::info!(feed = %feed, "the feed was deleted or its source changed during the check; nothing was stored");
        return Ok(false);
    };
    state.alerts.announce(ch);
    state.feeds.set_ask(&feed, ask);
    if let Some(at) = full_at {
        state.feeds.set_floor(
            &feed,
            Download {
                at: Some(at),
                expires_s: expires,
            }
            .floor(),
        );
    }
    metrics::check(state, &feed, true).await;
    if let Some(run_id) = confirm {
        state.feeds.submit(
            state,
            &feed,
            Work::Confirm {
                run_id,
                at: now,
                source_gen: sgen,
            },
        );
        return Ok(true);
    }
    Ok(false)
}

fn feed_down_spec(
    feed: &str,
    def: &FeedDef,
    provider: &str,
    error: &str,
    missing: bool,
    since: Timestamp,
) -> RaiseSpec {
    RaiseSpec::new(
        "feed_down",
        Severity::Warning,
        format!("feed_down:{feed}"),
        format!("Feed {}: every check has failed for an hour", def.name),
        json!({"since": crate::util::ts(&since), "last_error": error, "file_gone": missing, "provider": provider}),
    )
    .feed(feed.to_string())
    .feed_provider(provider.to_string())
}

/// A failed check of a feed: recorded, its error backoff, and `feed_down` once every check of
/// it has failed for its threshold, unless the provider is failing as a whole (core.md §9).
async fn on_failure(fc: &FeedCtx<'_>, e: CheckError, suppress_down: bool) -> Result<()> {
    let state = fc.state;
    let feed = fc.feed().to_string();
    let now = fc.now;
    let before = fc.before;
    let failures = before.st.failures.saturating_add(1);
    let since = before.st.failing_since.unwrap_or(now);
    let missing = matches!(e, CheckError::Missing);
    let error = match &e {
        CheckError::RateLimited { until } => {
            let until = (*until).min(now + jiff::SignedDuration::from_hours(1)).max(now);
            format!("rate limited until {}", crate::util::ts(&until))
        }
        CheckError::Missing => "the provider no longer has this file".to_string(),
        CheckError::Failed(err) => crate::util::sanitize_for_message(&format!("{err:#}"), MAX_ERROR),
    };
    // Failed checks never train the model (feed-scheduling.md §4); the ask is the backoff.
    let tr = fc.train(failures, None, Download::previous(before));
    let rec = CheckRecord {
        feed: feed.clone(),
        at: now,
        duration_ms: fc.duration_ms,
        method: "error".to_string(),
        ok: false,
        changed: false,
        bytes: 0,
        version: None,
        predicted_rate: None,
        error: Some(error.clone()),
        changes: vec![],
        origin: "check",
        provider_check_id: fc.provider_check_id,
    };
    let f = feed.clone();
    let spec = feed_down_spec(&feed, fc.def, &fc.pdef.id, &error, missing, since);
    let threshold = state.settings().alerts.threshold("feed_down");
    let alerts = state.alerts.clone();
    let sgen = fc.source_gen;
    let ask = tr.ask;
    let stored = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if !store::source_current(&tx, &f, sgen)? {
                return Ok::<_, anyhow::Error>(None);
            }
            store::record_check(&tx, &rec)?;
            store::set_ask(&tx, &f, ask)?;
            let mut ch = AlertChanges::default();
            if !suppress_down {
                alerts.condition_in(&tx, &spec, Some(since), threshold, now, &mut ch)?;
            }
            tx.commit()?;
            alerts.committed(&ch);
            Ok(Some(ch))
        })
        .await?;
    let Some(ch) = stored else {
        return Ok(());
    };
    state.alerts.announce(ch);
    state.feeds.set_ask(&feed, ask);
    metrics::check(state, &feed, false).await;
    tracing::info!(feed = %feed, failures, error = %error, "feed check failed");
    Ok(())
}

/// How long a voided check's provider waits before its next check (the config reload that
/// follows the change makes it due as the edit needs).
const VOID_RETRY: jiff::SignedDuration = jiff::SignedDuration::from_secs(5);

/// A check whose provider changed or was deleted while it ran: nothing it observed was stored.
/// The retry holds through the check's end until the edit's reload replaces it (#45).
fn void(state: &SharedState, provider: &str) {
    tracing::info!(provider = %provider, "the feed provider was deleted or its source changed during the check; nothing was stored");
    state.feeds.retry_at(provider, Timestamp::now() + VOID_RETRY);
}

/// Records a feed's warm start for its epoch (feed-scheduling.md §6), read in the check's
/// light-lane job: each change becomes an exact change time, between two `bootstrap` checks (the
/// start of the span read, and now) so the span counts as observed, and the staleness reference
/// is frozen from the warm-started model (§8). A module without history (`http`) starts from
/// the provider's other feeds at ⅕ weight instead.
async fn warm_start(
    state: &SharedState,
    pdef: &FeedProviderDef,
    def: &FeedDef,
    source_gen: Option<i64>,
    now: Timestamp,
    times: &[ChangeTime],
) {
    let feed = def.id.as_str();
    let mut exact: Vec<Timestamp> = times
        .iter()
        .filter_map(|t| match t {
            ChangeTime::Exact(x) if *x < now => Some(*x),
            _ => None,
        })
        .collect();
    exact.sort();
    if exact.is_empty() {
        // No history: the provider's other feeds' tables at ⅕ weight, if any, on a copy put in
        // place with the warm start's record.
        let sibling = state
            .feeds
            .provider_feeds(&pdef.id)
            .into_iter()
            .filter(|f| f.id != feed)
            .find_map(|f| state.feeds.learner(&f.id).filter(|l| l.prev_ok.is_some()));
        let warmed = sibling.and_then(|s| {
            let mut l = state.feeds.learner(feed).unwrap_or_default();
            l.prev_ok.is_none().then(|| {
                l.warm_from(&s);
                l
            })
        });
        let (f, sgen, s2) = (feed.to_string(), source_gen, state.clone());
        let _ = state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                if store::source_current(&tx, &f, sgen)? {
                    store::set_warm_started(&tx, &f, now)?;
                    tx.commit()?;
                    if let Some(l) = warmed {
                        s2.feeds.install_learner(&f, l);
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await;
        return;
    }
    let span_start = if exact.len() >= crate::modules::download::github::HISTORY_CHANGES {
        picket_api::time::saturating_sub(exact[0], jiff::SignedDuration::from_secs(1))
    } else {
        now - jiff::SignedDuration::from_hours(24 * (crate::modules::download::github::HISTORY_DAYS))
    };
    let end = now - jiff::SignedDuration::from_millis(1);
    let a = CheckRecord {
        feed: feed.to_string(),
        at: span_start,
        duration_ms: 0,
        method: "bootstrap".into(),
        ok: true,
        changed: false,
        bytes: 0,
        version: None,
        predicted_rate: None,
        error: None,
        changes: vec![],
        origin: "bootstrap",
        provider_check_id: None,
    };
    let b = CheckRecord {
        at: end,
        changed: true,
        changes: exact.iter().map(|t| ChangeTime::Exact(*t)).collect(),
        origin: "history",
        ..a.clone()
    };
    // Train a fresh model first (a copy, put in place once stored), so the reference is the
    // warm-started model.
    let mut l = super::Learner::new();
    if let Some(k) = state.feeds.learner(feed).map(|o| o.k) {
        l.k = k;
    }
    l.observe(
        &Obs {
            t: schedule::to_secs(span_start),
            exact: vec![],
            interval: false,
        },
        false,
    );
    l.observe(&obs_of(end, &b.changes), true);
    // The staleness reference is the model as it stood right after the last change
    // (feed-scheduling.md §8), not the one above, which has also observed the quiet span since
    // (so the silence would explain itself); `n` is averaged over the part of the 60 days before
    // that change the warm start read, not over 60 days (about one false alert per D days).
    let reference = exact.last().map(|last| {
        let t = schedule::to_secs(*last);
        let mut at_change = super::Learner::new();
        at_change.observe(
            &Obs {
                t: schedule::to_secs(span_start),
                exact: vec![],
                interval: false,
            },
            false,
        );
        at_change.observe(
            &Obs {
                t,
                exact: exact.iter().map(|x| schedule::to_secs(*x)).collect(),
                interval: false,
            },
            true,
        );
        stale::Reference::new(
            at_change.frozen(),
            t,
            exact.len(),
            (t - schedule::to_secs(span_start)) / 86_400.0,
            at_change.describe(t),
        )
    });
    let (a2, b2, f, s2) = (a.clone(), b.clone(), feed.to_string(), state.clone());
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            if !store::source_current(&tx, &f, source_gen)? {
                return Ok::<_, anyhow::Error>(false);
            }
            store::record_check(&tx, &a2)?;
            store::record_check(&tx, &b2)?;
            store::set_warm_started(&tx, &f, now)?;
            store::set_warm_span(&tx, &f, Some(span_start))?;
            if let Some(r) = &reference {
                store::set_stale_ref(&tx, &f, Some(&r.to_json()))?;
            }
            tx.commit()?;
            s2.feeds.install_learner(&f, l);
            Ok(true)
        })
        .await;
    if !matches!(r, Ok(true)) {
        return;
    }
    tracing::info!(feed = %feed, changes = exact.len(), "warm-started the feed's schedule from its history");
}

/// Picks each `dynamic` provider's `k` once a week (feed-scheduling.md §5): each feed replays its
/// last 28 days alone with simulated checks, from no earlier than its own checks
/// ([`schedule::learner::k_replay_starts`]), and the provider takes the most aggressive of the
/// feeds' choices that keeps the provider's own replay within the budget
/// ([`schedule::learner::provider_k`]). A feed without a successful check, or with less than a
/// day of them, sits the choice out; with no feed left, the provider keeps its `k` and tries
/// again at the next daily run.
pub async fn choose_ks(state: &SharedState) {
    let providers: Vec<FeedProviderDef> = state
        .feeds
        .with(|i| {
            i.providers
                .values()
                .filter_map(|p| p.def.clone())
                .filter(|d| d.enabled && matches!(d.trigger, Trigger::Dynamic { .. }))
                .collect()
        })
        .unwrap_or_default();
    let now = Timestamp::now();
    for p in providers {
        let feeds: Vec<FeedDef> = state
            .feeds
            .provider_feeds(&p.id)
            .into_iter()
            .filter(|f| f.enabled)
            .collect();
        let due = feeds.iter().any(|f| {
            state.feeds.learner(&f.id).is_some_and(|l| {
                l.k_chosen_at
                    .is_none_or(|t| schedule::to_secs(now) - t >= 7.0 * 86_400.0)
            })
        });
        if !due {
            continue;
        }
        let Ok(inputs) = replay_inputs(state, &p, now).await else {
            continue;
        };
        let end = schedule::to_secs(now);
        let own: Vec<_> = inputs.iter().map(|f| (f.first_check, f.warm_started)).collect();
        let replays: Vec<(FeedReplay, f64)> = inputs
            .into_iter()
            .zip(schedule::learner::k_replay_starts(end, &own))
            .filter_map(|(f, start)| Some((f, start?)))
            .collect();
        if replays.is_empty() {
            continue;
        }
        let min = p.trigger.min_interval().as_secs() as f64;
        let replayed = tokio::task::spawn_blocking(move || {
            let ks = schedule::learner::K_CHOICES;
            let per_feed: Vec<_> = replays
                .iter()
                .map(|(f, start)| {
                    let cost = schedule::cost_factor(f.mean_unchanged_bytes);
                    schedule::backtest::replay(std::slice::from_ref(&f.obs), *start, end, &ks, cost, min)
                })
                .collect();
            // The voting feeds together, for the provider's budget, from the latest of their
            // starts.
            let pooled = if replays.len() > 1 {
                let start = replays.iter().map(|r| r.1).fold(f64::MIN, f64::max);
                let bytes: Vec<f64> = replays.iter().filter_map(|r| r.0.mean_unchanged_bytes).collect();
                let mean = (!bytes.is_empty()).then(|| bytes.iter().sum::<f64>() / bytes.len() as f64);
                let obs: Vec<Vec<Obs>> = replays.into_iter().map(|r| r.0.obs).collect();
                schedule::backtest::replay(&obs, start, end, &ks, schedule::cost_factor(mean), min)
            } else {
                per_feed.first().cloned().unwrap_or_default()
            };
            (per_feed, pooled)
        })
        .await;
        let Ok((per_feed, pooled)) = replayed else {
            continue;
        };
        let k = schedule::learner::provider_k(per_feed.iter().map(Vec::as_slice), &pooled);
        for f in &feeds {
            state.feeds.with_learner(&f.id, |l| {
                if let Some(k) = k {
                    l.k = k;
                }
                l.k_chosen_at = Some(end);
            });
        }
        if let Some(k) = k {
            let pid = p.id.clone();
            let _ = state
                .db
                .write(move |c| {
                    store::ensure_provider_state(c, &pid)?;
                    c.execute(
                        "UPDATE feed_provider_state SET k = ?2 WHERE provider_id = ?1",
                        rusqlite::params![pid, k],
                    )?;
                    Ok::<_, anyhow::Error>(())
                })
                .await;
            tracing::info!(provider = %p.id, k, "chose the provider's schedule aggressiveness");
        }
    }
}

/// Replays the last `days` of a provider's feeds' recorded histories (each feed's current
/// epoch) with simulated checks, for each `k` in [`super::schedule::learner::K_CHOICES`] (or
/// just `k`), the provider checked as core checks it (feed-scheduling.md §5).
pub async fn backtest(
    state: &SharedState,
    pdef: &FeedProviderDef,
    days: i64,
    k: Option<f64>,
) -> Result<Vec<super::schedule::learner::SimResult>> {
    let now = Timestamp::now();
    let inputs = replay_inputs(state, pdef, now).await?;
    let bytes: Vec<f64> = inputs.iter().filter_map(|f| f.mean_unchanged_bytes).collect();
    let mean_bytes = (!bytes.is_empty()).then(|| bytes.iter().sum::<f64>() / bytes.len() as f64);
    let cost = schedule::cost_factor(mean_bytes);
    let min = pdef.trigger.min_interval().as_secs() as f64;
    let end = schedule::to_secs(now);
    let start = end - days.clamp(1, 60) as f64 * 86_400.0;
    let obs: Vec<Vec<Obs>> = inputs.into_iter().map(|f| f.obs).collect();
    tokio::task::spawn_blocking(move || {
        let ks: Vec<f64> = match k {
            Some(k) => vec![k],
            None => super::schedule::learner::K_CHOICES.to_vec(),
        };
        schedule::backtest::replay(&obs, start, end, &ks, cost, min)
    })
    .await
    .map_err(|e| anyhow!("backtest failed: {e}"))
}

/// What a replay reads of one enabled feed of a provider (its current epoch, feed-scheduling.md
/// §4).
struct FeedReplay {
    obs: Vec<Obs>,
    mean_unchanged_bytes: Option<f64>,
    /// Its first successful check in the epoch that wasn't its warm start, and when that warm
    /// start was read (Unix seconds).
    first_check: Option<f64>,
    warm_started: Option<f64>,
}

async fn replay_inputs(
    state: &SharedState,
    pdef: &FeedProviderDef,
    now: Timestamp,
) -> Result<Vec<FeedReplay>> {
    let feeds: Vec<String> = state
        .feeds
        .provider_feeds(&pdef.id)
        .into_iter()
        .filter(|f| f.enabled)
        .map(|f| f.id)
        .collect();
    state
        .db
        .read(move |c| {
            let mut out = Vec::new();
            for f in &feeds {
                let obs = schedule::epoch_observations(c, f, now)?;
                let mean_unchanged_bytes: Option<f64> = c.query_row(
                    "SELECT avg(bytes) FROM feed_checks WHERE feed_id = ?1 AND ok = 1 AND changed = 0 AND method <> 'bootstrap'",
                    [f],
                    |r| r.get(0),
                )?;
                let since = crate::util::ts(&store::history_since(c, f, now)?);
                let first: Option<String> = c.query_row(
                    "SELECT min(t) FROM feed_checks WHERE feed_id = ?1 AND ok = 1 AND method <> 'bootstrap' AND t >= ?2",
                    rusqlite::params![f, since],
                    |r| r.get(0),
                )?;
                let warm = store::load_state(c, f)?.warm_started_at;
                out.push(FeedReplay {
                    obs,
                    mean_unchanged_bytes,
                    first_check: first.as_deref().and_then(crate::util::parse_ts).map(schedule::to_secs),
                    warm_started: warm.map(schedule::to_secs),
                });
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await
}
