//! Feeds (feeds.md, feed-scheduling.md, providers.md §2–§3): feed providers and their triggers,
//! checks and downloads through the download modules ([`crate::modules::download`]), new
//! provider feeds, parse, classify, ingest and diff.
//!
//! | Module | Job |
//! |---|---|
//! | this one | the runtime: providers' due times and triggers, feeds' busy marks and asks, job guards, timers |
//! | [`check`] | one check of a feed provider: secrets, the module in the light lane, per-file outcomes, recording, confirmation, the runs it starts, the listing (feeds.md §3 steps 1–3) |
//! | [`manual`], [`body`] | manual feeds: save, append, read, and the run a save starts (feeds.md §1 "Manual feeds", api.md §7) |
//! | [`ingest`] | one run in the heavy lane: parse → staging → gates → diff → `feed_runs` (feeds.md §3 step 4, §2, §5, §8), imports included |
//! | [`gates`] | the sanity gates (feeds.md §5) |
//! | [`undo`] | reverting a run that didn't finish (feeds.md §3) |
//! | [`schedule`] | asks, triggers, due times, backoff, the learner (feed-scheduling.md §3–§6) |
//! | [`select`] | which files a provider's `files` and `exclude` select, the feeds core creates, `feed_added` (feeds.md §1) |
//! | [`stale`] | `feed_stale` (feed-scheduling.md §8) |
//! | [`sqs`] | the `sqs` trigger's long polls (feed-scheduling.md §7) |
//! | [`transfer`] | export and import of a feed's entries (feeds.md §4) |
//! | [`restore`] | the feed side of the config export and restore (core.md §2) |
//! | [`dirty`] | bundles a feed change made dirty, for the compiler (bundles.md §2) |
//! | [`presets`] | bundled feed presets (feeds.md §9) |
//! | [`api`] | the UI API routes for feed providers and feeds |
//! | [`retention`] | closed entries, old runs, raw downloads, resolved policy drops, deleted feeds' data (storage.md §4) |
//! | [`purge`] | retiring a deleted feed's data, so a feed created again with its id starts clean |
//! | [`metrics`] | feed time series (feeds.md §6) |
//!
//! **One check per provider** (providers.md §2): a provider is due by its trigger and its feeds'
//! asks ([`schedule::provider_due`]); one check covers every enabled feed of it that isn't busy.
//! **One thing at a time per feed:** a feed is *busy* while a check that includes it runs or a run
//! of it is queued or running in the heavy lane; a busy feed is left out of a provider's check,
//! with no check recorded, until its run is stored: it keeps what made the provider due (the
//! nudges recorded before the check stay) and, once freed, makes its provider due again for the
//! same cause ([`Feeds::owe`]), so "Check now", a nudge or a cron slot waits for it (feeds.md §3
//! step 1; each file is judged against its own `last`). A trigger edit takes effect at once: the
//! trigger's next time and the feeds' asks are re-derived ([`Feeds::reload`]). Accepted imports
//! into provider feeds wait durably in `feed_imports` and run when the feed is free
//! ([`Feeds::resume_import`]). Config edits that need a re-ingest or a re-gate are derived from durable state (the
//! parameters stored on the latest applied run, and on the newest held or rejected one), so a
//! restart never loses one.
//!
//! **Source generations** (feeds.md §3 "Editing a feed provider"; storage.md §4): each creation
//! of a feed, and each edit of its provider's `module` or `config`, gives it a new
//! `feed_state.source_gen` in the config transaction (the provider gets one too). A check reads
//! them with the stored sources (which must be the ones it runs), and each transaction that
//! stores what it observed checks, inside the writer, that they are still current
//! ([`store::source_current`], [`store::provider_source_current`]). A check or run in flight
//! across a deletion, a re-creation or a source edit so stores nothing of the old source.
//!
//! **Run ids** follow the order runs change a feed's entries: every run takes a new id when it
//! starts, a confirmation or re-gate of a waiting run included (the waiting row moves to it,
//! `source_run` keeping its old id). Replay (`first_run ≤ r < removed_run`, storage.md §3), "the
//! latest applied run" and retention compare ids.
//!
//! `feed_hits` comes from attribution (`logs::analysis`, core.md §6). The learner's acceptance
//! backtests on recorded OISD, AdGuard and jpgpi250 histories are [`schedule::backtest`]'s tests
//! (feed-scheduling.md §6). The config export document and restore endpoint are
//! `config::export`'s ([`restore`] holds the feed side).
//!
//! **Clocks:** due times are wall-clock (cron, phases), but the loop sleeps for durations and
//! re-reads the clock at least every 30 s. The expiry sweep waits for a synchronised clock (it
//! closes entries by age).

pub mod api;
pub mod body;
pub mod check;
pub mod dirty;
pub mod gates;
pub mod ingest;
pub mod manual;
pub mod metrics;
pub mod misp;
pub mod presets;
pub mod purge;
pub mod restore;
pub mod retention;
pub mod schedule;
pub mod select;
pub mod sqs;
pub mod stale;
pub mod store;
pub mod transfer;
pub mod types;
pub mod undo;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::Timestamp;
use tokio::sync::Notify;

use crate::config::model::{FeedDef, FeedProviderDef, Trigger};
use crate::modules::download::Registry;
use crate::modules::download::client::{Http, HttpOptions};
use crate::scheduler::Priority;
use crate::settings::{Resolver, ResolverUpstream};
use crate::state::SharedState;
use ingest::{IngestJob, Work};
pub use schedule::learner::Learner;
use types::{IngestParams, RunStatus, TypeCounts};

/// The download module ids providers may name (validation before a registry instance exists).
pub fn known_download_modules() -> &'static [&'static str] {
    crate::modules::download::known_ids()
}

/// What started a check of a provider (`feed_provider_checks.cause`, `due_cause`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The provider's trigger, or a feed's ask.
    Trigger,
    /// An SQS message (feed-scheduling.md §7).
    Sqs,
    /// The `sqs` backstop.
    Backstop,
    /// "Check now" (`POST feed-providers/{id}/check`): bypasses the trigger, not `min_interval`.
    CheckNow,
    /// The provider's first check.
    First,
    /// An edit of its `module`, `config`, `files` or `exclude`.
    Edit,
}

impl Cause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trigger => "trigger",
            Self::Sqs => "sqs",
            Self::Backstop => "backstop",
            Self::CheckNow => "check_now",
            Self::First => "first",
            Self::Edit => "edit",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "sqs" => Self::Sqs,
            "backstop" => Self::Backstop,
            "check_now" => Self::CheckNow,
            "first" => Self::First,
            "edit" => Self::Edit,
            _ => Self::Trigger,
        }
    }

    /// Due at once (within `min_interval`), whatever the trigger says.
    fn now_wanted(self) -> bool {
        matches!(self, Self::Sqs | Self::CheckNow | Self::First | Self::Edit)
    }

    /// Of two causes waiting for one check, the one it runs for: "Check now" (it bypasses a
    /// cron feed's `! Expires:` floor), then any cause due at once, then the others; the newer
    /// on a tie.
    fn merge(old: Option<Self>, new: Self) -> Self {
        let rank = |c: Self| match c {
            Self::CheckNow => 2,
            c if c.now_wanted() => 1,
            _ => 0,
        };
        match old {
            Some(o) if rank(o) > rank(new) => o,
            _ => new,
        }
    }
}

/// What a trigger did.
#[derive(Clone, Debug, PartialEq)]
pub enum Triggered {
    Started,
    /// A check of the provider (or a run of the manual feed) is in progress; this one runs when
    /// it ends.
    Queued,
    /// `min_interval` (or a module's rate-limit pause) puts the check at this time.
    Scheduled(Timestamp),
    Disabled,
    Unknown,
}

#[derive(Clone, Debug, Default)]
struct FeedRt {
    def: Option<FeedDef>,
    busy: bool,
    pending_reingest: bool,
    pending_regate: bool,
    /// The feed's ask (feed-scheduling.md §5): its model's, or its error backoff.
    ask: Option<Timestamp>,
    /// The feed id is busy with the purge of a deleted feed's data (its run id).
    purging: Option<i64>,
    /// A purge waits for the feed id to be free (its run id).
    pending_purge: Option<i64>,
    /// The earliest next full download the last list's `! Expires:` allows (its download time
    /// plus the header's interval): a `cron` provider's check leaves the feed out until then
    /// (feeds.md §5).
    floor: Option<Timestamp>,
    /// A manual feed's save waits for the feed to be free.
    queued_save: bool,
    /// A manual feed's run that couldn't start or failed runs again at this time: a saved file
    /// is never left waiting for the next save or a restart (feeds.md §1).
    manual_retry: Option<Timestamp>,
    /// A check of its provider left this busy feed out (feeds.md §3 step 1): when it is freed,
    /// its provider is due at once for this cause, so the feed is checked once its run is stored
    /// ("Check now" and a nudge wait the same way).
    owed: Option<Cause>,
    /// Accepted imports wait in `feed_imports` (feeds.md §4): when the feed is freed, the oldest
    /// one's run starts ([`Feeds::resume_import`]).
    imports: bool,
    /// The import whose run was queued last: still pending when the feed is freed again, its run
    /// failed or couldn't be queued, and it waits for `import_retry`.
    import_last: Option<i64>,
    /// When a pending import whose run failed or couldn't be queued is tried again.
    import_retry: Option<Timestamp>,
}

#[derive(Clone, Debug, Default)]
struct ProviderRt {
    def: Option<FeedProviderDef>,
    /// When the next check is due (`None`: not scheduled, e.g. disabled).
    due: Option<Timestamp>,
    /// What makes it due.
    cause: Option<Cause>,
    checking: bool,
    /// "Check now" or a nudge while a check runs: another check when it ends.
    queued: Option<Cause>,
    /// No check is dispatched before this ([`Feeds::retry_at`]): a full light lane's retry, a
    /// voided check's wait for its configuration reload, a failed setup's backoff. Recomputing
    /// the schedule never puts `due` earlier; it ends when a check starts or an edit of the
    /// provider's source makes it due.
    retry_at: Option<Timestamp>,
    /// An edit of the provider (`module`, `config`, `files`, `exclude`, enabling it) arrived
    /// during the running check: when the check ends, its edit replaces any `retry_at` the check
    /// left (a voided check's wait is for exactly that edit).
    edited_during: bool,
    /// Due at once (within `min_interval`) whatever `cause` is: a cause made it due now
    /// ([`Feeds::want_now`]), until its check is taken.
    force: bool,
    /// A first check is wanted (a new provider, or a feed created again once its purge is done):
    /// it carries no `min_interval` over, whatever other cause joins it, until a check is taken.
    first: bool,
    last_check: Option<Timestamp>,
    /// The trigger's own next time: the next cron time, or the `sqs` backstop.
    trigger_next: Option<Timestamp>,
    /// Checks in a row that failed before anything could be recorded (in-memory backoff).
    setup_failures: u32,
    /// Loaded from the stored state at start, before the first reload gave it its definition.
    restored: bool,
    /// The provider's source generation as the runtime last loaded it: another one with the
    /// same config means the provider was deleted and created again between two reloads.
    source_gen: Option<i64>,
}

impl ProviderRt {
    /// An edit of the provider's source (`module`, `config`, `files`, `exclude`, enabling it)
    /// makes it due at once. During a check, the edit's check follows it (the running check's
    /// end would otherwise drop the cause) and replaces the retry the check leaves: a voided
    /// check's wait is for this edit (#45).
    fn edited(&mut self) {
        if self.checking {
            self.queued = Some(Cause::merge(self.queued, Cause::Edit));
            self.edited_during = true;
        } else {
            self.cause = Some(Cause::merge(self.cause, Cause::Edit));
            self.force = true;
            self.retry_at = None;
        }
    }
}

#[derive(Default)]
struct Inner {
    feeds: HashMap<String, FeedRt>,
    providers: HashMap<String, ProviderRt>,
    /// Module id → no check through it starts until then (providers.md §2).
    pauses: HashMap<String, Timestamp>,
}

/// The feeds runtime, one per running core.
pub struct Feeds {
    registry: Registry,
    http_opts: HttpOptions,
    http: Mutex<Option<(Option<ResolverUpstream>, Http)>>,
    inner: Mutex<Inner>,
    wake: Notify,
    dirty: dirty::Dirty,
    save_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    learners: Mutex<HashMap<String, Learner>>,
    /// Manual feed uploads and imports in progress ([`manual::MAX_UPLOADS`]).
    uploads: Arc<tokio::sync::Semaphore>,
    /// Request-body bytes spooled now, across uploads ([`manual`]).
    spooled: Arc<std::sync::atomic::AtomicU64>,
    /// The SQS long-poll tasks ([`sqs`]).
    pub(crate) sqs: sqs::Tasks,
    /// Held by [`Feeds::reload`] from its read of the definitions to its last step: reloads run
    /// one at a time, in the order they read the configuration.
    reloading: tokio::sync::Mutex<()>,
}

impl Default for Feeds {
    fn default() -> Self {
        Self::new(HttpOptions::default())
    }
}

/// The longest the loop sleeps before it reads the clock again.
const MAX_SLEEP: Duration = Duration::from_secs(30);
/// First checks after a start are spread over this long.
const START_SPREAD_S: i64 = 60;

impl Feeds {
    /// A runtime whose HTTP client uses `http_opts` (tests add a root and host overrides).
    pub fn new(http_opts: HttpOptions) -> Self {
        Self {
            registry: Registry::builtin(),
            http_opts,
            http: Mutex::new(None),
            inner: Mutex::new(Inner::default()),
            wake: Notify::new(),
            dirty: dirty::Dirty::default(),
            save_locks: Mutex::new(HashMap::new()),
            learners: Mutex::new(HashMap::new()),
            uploads: Arc::new(tokio::sync::Semaphore::new(manual::MAX_UPLOADS)),
            spooled: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sqs: sqs::Tasks::default(),
            reloading: tokio::sync::Mutex::new(()),
        }
    }

    /// A slot for one manual feed upload or import, if one is free (README §2 Bounded).
    pub(crate) fn upload_slot(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.uploads.clone().try_acquire_owned().ok()
    }

    /// The shared count of spooled request-body bytes.
    pub(crate) fn spooled(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.spooled.clone()
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The bundles waiting for the compiler (bundles.md §2).
    pub fn dirty(&self) -> &dirty::Dirty {
        &self.dirty
    }

    /// The HTTP client for the current `resolver` setting (rebuilt when it changes).
    pub fn http(&self, resolver: &Resolver) -> anyhow::Result<Http> {
        let want = match resolver {
            Resolver::Upstream(u) => Some(u.clone()),
            Resolver::Named(_) => None,
        };
        let mut g = self
            .http
            .lock()
            .map_err(|_| anyhow::anyhow!("http client lock poisoned"))?;
        if let Some((r, h)) = g.as_ref()
            && *r == want
        {
            return Ok(h.clone());
        }
        let h = Http::new(HttpOptions {
            resolver: want.clone(),
            ..self.http_opts.clone()
        })?;
        *g = Some((want, h.clone()));
        Ok(h)
    }

    /// The save lock of a manual feed (saves to one feed run one at a time, feeds.md §1).
    pub fn save_lock(&self, feed: &str) -> Arc<tokio::sync::Mutex<()>> {
        let Ok(mut m) = self.save_locks.lock() else {
            return Arc::new(tokio::sync::Mutex::new(()));
        };
        if m.len() > 4096 {
            m.retain(|_, l| Arc::strong_count(l) > 1);
        }
        m.entry(feed.to_string()).or_default().clone()
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> Option<T> {
        self.inner.lock().ok().map(|mut g| f(&mut g))
    }

    /// The feed's definition as the runtime last loaded it.
    pub fn def(&self, feed: &str) -> Option<FeedDef> {
        self.with(|i| i.feeds.get(feed).and_then(|f| f.def.clone()))
            .flatten()
    }

    /// The provider's definition as the runtime last loaded it.
    pub fn provider_def(&self, provider: &str) -> Option<FeedProviderDef> {
        self.with(|i| i.providers.get(provider).and_then(|p| p.def.clone()))
            .flatten()
    }

    /// The feeds of a provider the runtime knows, sorted by id.
    pub fn provider_feeds(&self, provider: &str) -> Vec<FeedDef> {
        let mut v: Vec<FeedDef> = self
            .with(|i| {
                i.feeds
                    .values()
                    .filter_map(|f| f.def.clone())
                    .filter(|d| d.provider.as_deref() == Some(provider))
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// The feed's definition, reloading the runtime first when it doesn't know the feed yet (a
    /// request right after the feed's creation, before the config watcher ran).
    pub async fn def_or_reload(&self, state: &SharedState, feed: &str) -> Option<FeedDef> {
        self.or_reload(state, |f| f.def(feed)).await
    }

    /// [`Feeds::def_or_reload`] for a provider.
    pub async fn provider_or_reload(&self, state: &SharedState, provider: &str) -> Option<FeedProviderDef> {
        self.or_reload(state, |f| f.provider_def(provider)).await
    }

    /// `get`, after one reload of the runtime when it finds nothing.
    async fn or_reload<T>(&self, state: &SharedState, get: impl Fn(&Self) -> Option<T>) -> Option<T> {
        if let Some(d) = get(self) {
            return Some(d);
        }
        self.reload(state).await;
        get(self)
    }

    /// True while a check including the feed, or a run of it, is in progress.
    pub fn is_busy(&self, feed: &str) -> bool {
        self.with(|i| i.feeds.get(feed).is_some_and(|f| f.busy))
            .unwrap_or(false)
    }

    /// True while an SQS long-poll task runs for the provider (tests).
    #[doc(hidden)]
    pub fn sqs_running(&self, provider: &str) -> bool {
        self.sqs.running(provider)
    }

    /// Holds the SQS task machinery once at `point` (tests drive races with it).
    #[doc(hidden)]
    pub fn sqs_pause_once(&self, point: sqs::PausePoint, f: sqs::Pause) {
        self.sqs.pause_once(point, f);
    }

    /// True while a check of the provider is in progress.
    pub fn is_checking(&self, provider: &str) -> bool {
        self.with(|i| i.providers.get(provider).is_some_and(|p| p.checking))
            .unwrap_or(false)
    }

    /// When the provider's next check is due.
    pub fn next_due(&self, provider: &str) -> Option<Timestamp> {
        self.with(|i| i.providers.get(provider).and_then(|p| p.due))
            .flatten()
    }

    /// The feed's ask (feed-scheduling.md §5).
    pub fn ask(&self, feed: &str) -> Option<Timestamp> {
        self.with(|i| i.feeds.get(feed).and_then(|f| f.ask)).flatten()
    }

    /// Moves the provider's last check back by its `min_interval`, so the next "Check now", or
    /// a check something already asked for (an edit, a nudge, a due ask), isn't held back by it
    /// (tests drive several checks in a row; not used by core itself). A provider checked before
    /// stays one: this alone makes no check due.
    #[doc(hidden)]
    pub fn clear_last_check(&self, provider: &str) {
        let now = Timestamp::now();
        self.with(|i| {
            if let Some(p) = i.providers.get_mut(provider)
                && p.last_check.is_some()
            {
                let min =
                    crate::util::sat_i64(p.def.as_ref().map_or(0, |d| d.trigger.min_interval().as_secs()));
                let back =
                    jiff::SignedDuration::from_secs(min).saturating_add(jiff::SignedDuration::from_millis(1));
                p.last_check = Some(picket_api::time::saturating_sub(now, back));
            }
        });
        self.recompute_due(provider);
    }

    /// The module's rate-limit pause, if one is running.
    pub fn paused_until(&self, module: &str) -> Option<Timestamp> {
        let now = Timestamp::now();
        self.with(|i| i.pauses.get(module).copied().filter(|u| *u > now))
            .flatten()
    }

    pub(crate) fn set_pause(&self, module: &str, until: Timestamp) {
        self.with(|i| {
            let e = i.pauses.entry(module.to_string()).or_insert(until);
            *e = (*e).max(until);
        });
        self.wake.notify_one();
    }

    /// Sets a feed's ask and recomputes its provider's due time.
    pub(crate) fn set_ask(&self, feed: &str, ask: Option<Timestamp>) {
        let provider = self
            .with(|i| {
                let f = i.feeds.entry(feed.to_string()).or_default();
                f.ask = ask;
                f.def.as_ref().and_then(|d| d.provider.clone())
            })
            .flatten();
        if let Some(p) = provider {
            self.recompute_due(&p);
        }
    }

    /// The earliest next full download the feed's last list allows (`! Expires:`, feeds.md §5).
    pub(crate) fn set_floor(&self, feed: &str, floor: Option<Timestamp>) {
        let provider = self
            .with(|i| {
                let f = i.feeds.get_mut(feed)?;
                f.floor = floor;
                f.def.as_ref().and_then(|d| d.provider.clone())
            })
            .flatten();
        if let Some(p) = provider {
            self.recompute_due(&p);
        }
    }

    /// The feed's `! Expires:` floor, if one holds now.
    pub(crate) fn floor(&self, feed: &str) -> Option<Timestamp> {
        self.with(|i| i.feeds.get(feed).and_then(|f| f.floor)).flatten()
    }

    /// Sets what a provider check that started under trigger `used` left: its time, and the
    /// trigger's next time, from the provider's current definition (a trigger edited during the
    /// check decides at once, feed-scheduling.md §5), and makes the provider's due time follow
    /// its feeds' asks. Returns the trigger's next time, and whether the trigger is no longer
    /// `used` (the feeds' asks the check stored are then the old trigger's:
    /// [`Feeds::trigger_edited`] derives them again).
    pub(crate) fn provider_checked(
        &self,
        provider: &str,
        at: Timestamp,
        used: &Trigger,
    ) -> (Option<Timestamp>, bool) {
        let r = self
            .with(|i| {
                let p = i.providers.entry(provider.to_string()).or_default();
                let trigger = p.def.as_ref().map_or(used, |d| &d.trigger);
                let changed = trigger != used;
                p.trigger_next = schedule::trigger_next(trigger, at, Some(at));
                p.last_check = Some(at);
                p.cause = None;
                p.force = false;
                (p.trigger_next, changed)
            })
            .unwrap_or((None, false));
        self.recompute_due(provider);
        r
    }

    /// Makes a provider due at once (within `min_interval`) for `cause`.
    pub(crate) fn want_now(&self, provider: &str, cause: Cause) {
        self.with(|i| {
            let p = i.providers.entry(provider.to_string()).or_default();
            if cause == Cause::First {
                p.first = true;
            }
            if p.checking {
                p.queued = Some(Cause::merge(p.queued, cause));
            } else {
                p.cause = Some(Cause::merge(p.cause, cause));
                p.force = true;
            }
        });
        self.recompute_due(provider);
    }

    /// A check of `provider` for `cause` left these busy feeds out (feeds.md §3 step 1: a feed
    /// whose run is staged or waiting is left out until its run is stored; "Check now" waits the
    /// same way): each makes its provider due at once when it is freed ([`Feeds::release`]); one
    /// freed meanwhile does so now.
    pub(crate) fn owe(&self, provider: &str, feeds: &[String], cause: Cause) {
        let freed = self
            .with(|i| {
                let mut freed = false;
                for id in feeds {
                    match i.feeds.get_mut(id) {
                        Some(f) if f.busy && f.def.is_some() => f.owed = Some(Cause::merge(f.owed, cause)),
                        Some(f) if f.def.is_some() => freed = true,
                        _ => {}
                    }
                }
                freed
            })
            .unwrap_or(false);
        if freed {
            self.want_now(provider, cause);
        }
    }

    /// The cause a freed feed owes its provider, if a check left it out (tests).
    #[doc(hidden)]
    pub fn owed(&self, feed: &str) -> Option<&'static str> {
        self.with(|i| i.feeds.get(feed).and_then(|f| f.owed).map(Cause::as_str))
            .flatten()
    }

    /// Holds a provider's next check until `at` at the earliest: a full light lane's retry, a
    /// voided check's wait for its configuration reload, a failed setup's backoff. Set before
    /// the check ends ([`Feeds::provider_done`]), so the scheduler never sees the provider free
    /// without it, and kept through every recomputation of the schedule until a check starts or
    /// an edit of the provider's source makes it due (feeds.md §3; #45).
    pub(crate) fn retry_at(&self, provider: &str, at: Timestamp) {
        self.with(|i| {
            if let Some(p) = i.providers.get_mut(provider) {
                p.retry_at = Some(p.retry_at.map_or(at, |r| r.max(at)));
                p.due = Some(p.due.map_or(at, |d| d.max(at)));
            }
        });
        self.wake.notify_one();
    }

    /// The retry a provider's next check waits for, if one holds ([`Feeds::retry_at`]; tests).
    #[doc(hidden)]
    pub fn retry_pending(&self, provider: &str) -> Option<Timestamp> {
        let now = Timestamp::now();
        self.with(|i| {
            i.providers
                .get(provider)
                .and_then(|p| p.retry_at)
                .filter(|r| *r > now)
        })
        .flatten()
    }

    /// Puts a provider's next check at `at` (a module pause).
    pub(crate) fn set_due(&self, provider: &str, at: Timestamp) {
        self.with(|i| {
            if let Some(p) = i.providers.get_mut(provider) {
                p.due = Some(at);
            }
        });
        self.wake.notify_one();
    }

    /// Recomputes a provider's due time from its trigger, its feeds' asks and what made it due
    /// (feed-scheduling.md §5).
    pub(crate) fn recompute_due(&self, provider: &str) {
        let now = Timestamp::now();
        self.with(|i| {
            let mine: Vec<&FeedRt> = i
                .feeds
                .values()
                .filter(|f| {
                    f.def
                        .as_ref()
                        .is_some_and(|d| d.enabled && d.provider.as_deref() == Some(provider))
                })
                .collect();
            let asks: Vec<Timestamp> = mine.iter().filter_map(|f| f.ask).collect();
            // Under cron, a feed before its list's `! Expires:` floor waits for it (feeds.md
            // §5): the trigger's next time is the earliest at which some feed may be checked.
            let floors: Vec<Option<Timestamp>> = mine.iter().map(|f| f.floor).collect();
            let Some(p) = i.providers.get_mut(provider) else {
                return;
            };
            let Some(def) = p.def.clone() else {
                p.due = None;
                return;
            };
            if !def.enabled {
                p.due = None;
                return;
            }
            let trigger_next = match (&def.trigger, p.trigger_next) {
                (Trigger::Cron { .. }, Some(t)) if !floors.is_empty() => {
                    floors.iter().map(|f| f.map_or(t, |f| f.max(t))).min().or(Some(t))
                }
                (_, t) => t,
            };
            let due = schedule::provider_due(&schedule::ProviderDue {
                now,
                trigger: &def.trigger,
                // A first check (a new provider, or a feed created again once its purge is done)
                // carries no `min_interval` over.
                last_check: if p.first { None } else { p.last_check },
                asks,
                trigger_next,
                globs: def.has_globs(),
                now_wanted: p.force || p.cause.is_some_and(Cause::now_wanted),
            });
            // An explicit retry holds whatever the schedule says (#45).
            p.due = Some(match p.retry_at {
                Some(r) if r > now => due.max(r),
                Some(_) => {
                    p.retry_at = None;
                    due
                }
                None => due,
            });
        });
        self.wake.notify_one();
    }

    /// A check failed before anything could be recorded: the streak, for the backoff.
    pub(crate) fn setup_failed(&self, provider: &str) -> u32 {
        self.with(|i| {
            let p = i.providers.entry(provider.to_string()).or_default();
            p.setup_failures = p.setup_failures.saturating_add(1);
            p.setup_failures
        })
        .unwrap_or(1)
    }

    pub(crate) fn setup_ok(&self, provider: &str) {
        self.with(|i| {
            if let Some(p) = i.providers.get_mut(provider) {
                p.setup_failures = 0;
            }
        });
    }

    /// Marks the feed busy; false when it already is.
    fn try_acquire(&self, feed: &str) -> bool {
        self.with(|i| {
            let f = i.feeds.entry(feed.to_string()).or_default();
            if f.busy {
                false
            } else {
                f.busy = true;
                true
            }
        })
        .unwrap_or(false)
    }

    /// Marks each of `feeds` busy that isn't; returns the ones taken.
    pub(crate) fn acquire_many(&self, feeds: &[String]) -> Vec<String> {
        self.with(|i| {
            feeds
                .iter()
                .filter(|id| {
                    let f = i.feeds.entry((*id).clone()).or_default();
                    if f.busy || f.def.is_none() {
                        false
                    } else {
                        f.busy = true;
                        true
                    }
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
    }

    /// A provider check ended: frees the provider, and runs a check queued meanwhile
    /// ([`Feeds::complete`]).
    pub(crate) fn provider_done(&self, state: &SharedState, provider: &str) {
        if let Some(cause) = self.complete(provider, Timestamp::now()) {
            spawn_check(state, provider, cause);
        }
    }

    /// The end of a provider check, in one step under the runtime's lock (#45): the provider
    /// is freed, a retry the check left is kept (or replaced by an edit that arrived meanwhile),
    /// and the follow-up queued during the check is consumed once. A queued "Check now" starts
    /// here, in the same step, when it may (else it is scheduled as [`Feeds::trigger_provider`]
    /// would); any other queued cause makes the provider due at once. Neither the scheduler nor
    /// another explicit start can see the provider free with its follow-up still queued, so the
    /// follow-up runs once. A provider deleted during the check leaves the runtime now (one
    /// created again with its id meanwhile has its definition back, and stays). Returns the
    /// cause of the check this started: the caller spawns it.
    pub(crate) fn complete(&self, provider: &str, now: Timestamp) -> Option<Cause> {
        let started = self
            .with(|i| {
                let p = i.providers.get_mut(provider)?;
                p.checking = false;
                if std::mem::take(&mut p.edited_during) {
                    p.retry_at = None;
                }
                if p.def.is_none() {
                    // Deleted while it ran (`reload` kept it for this check): nothing waits.
                    i.providers.remove(provider);
                    return None;
                }
                let c = p.queued.take()?;
                if c == Cause::First {
                    p.first = true;
                }
                p.cause = Some(Cause::merge(p.cause, c));
                p.force = true;
                if c == Cause::CheckNow && start_decision(i, provider, c, now).is_ok() {
                    return Some(c);
                }
                None
            })
            .flatten();
        self.recompute_due(provider);
        started
    }

    /// Queues the purge of a deleted feed's data ([`purge`]) once the feed id is free; a feed
    /// created again with that id waits for it.
    pub(crate) fn submit_purge(&self, state: &SharedState, feed: &str, run: i64) {
        let start = self
            .with(|i| mark_purge(i.feeds.entry(feed.to_string()).or_default(), run))
            .unwrap_or(false);
        if start {
            queue_purge(state, feed, run);
        }
    }

    /// A purge ended: the feed id is free, unless another deletion asked for a newer purge. A
    /// feed created again with the id is a new feed (a manual one runs its start check).
    pub(crate) fn purge_done(&self, state: &SharedState, feed: &str) {
        let (manual, provider) = self
            .with(|i| {
                let f = i.feeds.get_mut(feed)?;
                f.purging = None;
                // Nothing the deleted feed's checks left in memory carries over.
                f.floor = None;
                f.manual_retry = None;
                f.ask = None;
                let def = f.def.as_ref()?;
                Some((def.is_manual(), def.provider.clone()))
            })
            .flatten()
            .unwrap_or((false, None));
        self.release(state, feed);
        if manual {
            let _ = self.trigger_manual(state, feed);
        }
        if let Some(p) = provider {
            // A feed created again is a new feed: due at once, with no `min_interval` carried
            // over from checks that left it out while its id was being purged.
            self.want_now(&p, Cause::First);
        }
    }

    /// Frees a busy feed and starts what waited for it: a purge, a queued save, and a re-ingest
    /// or re-gate an edit asked for meanwhile (re-derived from the stored runs, so a run that
    /// already used the new parameters isn't repeated).
    pub(crate) fn release(&self, state: &SharedState, feed: &str) {
        let purge = self
            .with(|i| {
                let f = i.feeds.get_mut(feed)?;
                let run = f.pending_purge.take()?;
                f.busy = false;
                Some(run)
            })
            .flatten();
        if let Some(run) = purge {
            self.submit_purge(state, feed, run);
            return;
        }
        let (save, reingest, regate, owed) = self
            .with(|i| {
                let Some(f) = i.feeds.get_mut(feed) else {
                    return (false, false, false, None);
                };
                f.busy = false;
                if f.def.is_none() {
                    // A deleted feed: nothing waits for it any more.
                    i.feeds.remove(feed);
                    return (false, false, false, None);
                }
                let owed = f
                    .owed
                    .take()
                    .and_then(|c| Some((f.def.as_ref()?.provider.clone()?, c)));
                (
                    std::mem::take(&mut f.queued_save),
                    std::mem::take(&mut f.pending_reingest),
                    std::mem::take(&mut f.pending_regate),
                    owed,
                )
            })
            .unwrap_or((false, false, false, None));
        if let Some((provider, cause)) = owed {
            // Its run is stored: the check that left it out catches it up (feeds.md §3 step 1).
            self.want_now(&provider, cause);
        }
        let imports = self
            .with(|i| {
                i.feeds
                    .get(feed)
                    .is_some_and(|f| f.imports && f.import_retry.is_none() && f.def.is_some())
            })
            .unwrap_or(false);
        if imports {
            let (s, f) = (state.clone(), feed.to_string());
            tokio::spawn(async move { s.feeds.resume_import(&s, &f, false).await });
        }
        if reingest || regate {
            let (s, f) = (state.clone(), feed.to_string());
            tokio::spawn(async move {
                if reingest {
                    s.feeds.maybe_reingest(&s, &f).await;
                }
                if regate {
                    s.feeds.maybe_regate(&s, &f).await;
                }
                if save {
                    let _ = s.feeds.trigger_manual(&s, &f);
                }
            });
        } else if save {
            let _ = self.trigger_manual(state, feed);
        }
        self.wake.notify_one();
    }

    /// Queues a run of a feed the caller holds busy. A job the heavy lane refuses frees it.
    pub(crate) fn submit(&self, state: &SharedState, feed: &str, work: Work) {
        let import = match &work {
            Work::Import { import, source_gen } => Some((*import, *source_gen)),
            _ => None,
        };
        let guard = JobGuard::new(state.clone(), feed);
        let job = IngestJob::new(state.clone(), feed, work, guard);
        if state.scheduler.heavy.submit(Priority::P1, Box::new(job)) == crate::scheduler::Submitted::Dropped {
            tracing::warn!(feed = %feed, "the heavy lane is full; the feed's run waits for its next check");
            // A manual feed has no next scheduled check: its run is tried again in a minute.
            self.retry_manual(feed, Timestamp::now() + jiff::SignedDuration::from_mins(1));
            if let Some((id, sgen)) = import {
                // An import's run refused counts as an attempt, so its retries are bounded too
                // (README §2 Bounded): past the attempts its run would be rejected at its start,
                // and one that can't even be queued then is dropped, and counted as a rejected
                // run of the feed that says why (`ingest::record_dropped_import`).
                let (s, f) = (state.clone(), feed.to_string());
                let def = self.def(feed);
                tokio::spawn(async move {
                    let alerts = s.alerts.clone();
                    let coalesced = s.events.coalesced().clone();
                    let f2 = f.clone();
                    let r =
                        s.db.write(move |c| {
                            let tx = c.transaction()?;
                            let n = store::import_attempt(&tx, id, &f2, sgen, true)?;
                            let mut ch = crate::alerts::Changes::default();
                            let mut event = None;
                            let dropped = n.filter(|n| n.attempts > ingest::MAX_IMPORT_ATTEMPTS);
                            if let Some(n) = dropped {
                                let reason = ingest::dropped_reason(n.started(), n.refused);
                                event = match &def {
                                    Some(def) => ingest::record_dropped_import(
                                        &tx, &alerts, def, id, sgen, &reason, &mut ch,
                                    )?,
                                    None => {
                                        store::delete_import(&tx, id, &f2, sgen)?;
                                        None
                                    }
                                };
                            }
                            tx.commit()?;
                            alerts.committed(&ch);
                            // On the writer, right after the commit (`web::events` module docs).
                            if let Some(e) = &event {
                                coalesced.feed_run(e.clone());
                            }
                            Ok::<_, anyhow::Error>((dropped.is_some(), event.is_some(), ch))
                        })
                        .await;
                    match r {
                        Ok((true, stored, ch)) => {
                            tracing::warn!(feed = %f, import = id,
                                "an import's run was refused or failed too often; the import is dropped");
                            s.alerts.announce(ch);
                            if stored {
                                metrics::run_stored(
                                    &s,
                                    &f,
                                    RunStatus::Rejected,
                                    &TypeCounts::default(),
                                    &TypeCounts::default(),
                                    &TypeCounts::default(),
                                    0,
                                    false,
                                )
                                .await;
                            }
                        }
                        Ok((false, _, _)) => {}
                        Err(e) => tracing::warn!(feed = %f, import = id, error = %format!("{e:#}"),
                            "cannot count an import's refused run"),
                    }
                });
            }
        }
    }

    /// When a manual feed's run that couldn't start or failed runs again, if one waits.
    pub fn manual_retry(&self, feed: &str) -> Option<Timestamp> {
        self.with(|i| i.feeds.get(feed).and_then(|f| f.manual_retry))
            .flatten()
    }

    /// A manual feed's run couldn't start or failed: it runs again at `at`, or earlier if a
    /// retry already waits (no-op for provider feeds). Public for tests, which move a retry
    /// earlier.
    pub fn retry_manual(&self, feed: &str, at: Timestamp) {
        self.with(|i| {
            if let Some(f) = i.feeds.get_mut(feed)
                && f.def.as_ref().is_some_and(FeedDef::is_manual)
            {
                f.manual_retry = Some(f.manual_retry.map_or(at, |r| r.min(at)));
            }
        });
        self.wake.notify_one();
    }

    /// After a config restore (core.md §2), on the writer right after its commit: forgets the
    /// providers and feeds this runtime holds that aren't checking or busy, so the next reload
    /// loads every one as new (each provider's first check due at once, each manual feed's file
    /// run). The feeds in `busy` come back busy with their save queued: the restore applies their
    /// applied blob first, then their file runs.
    pub(crate) fn forget_for_restore(&self, busy: &[String]) {
        self.with(|i| {
            i.providers.retain(|_, p| p.checking);
            i.feeds.retain(|_, f| f.busy);
            for f in busy {
                let e = i.feeds.entry(f.clone()).or_default();
                e.busy = true;
                e.queued_save = true;
            }
        });
        if let Ok(mut l) = self.learners.lock() {
            l.clear();
        }
        self.wake.notify_one();
    }

    /// Runs the manual feed's saved file once its current run ends (after a restored applied
    /// blob's run, core.md §2).
    pub(crate) fn queue_save(&self, feed: &str) {
        self.with(|i| {
            if let Some(f) = i.feeds.get_mut(feed) {
                f.queued_save = true;
            }
        });
    }

    /// Starts (or queues) the run of a manual feed's current file (a save, or the run core makes
    /// at start and after a restore for a file no run has read yet; feeds.md §1).
    pub fn trigger_manual(&self, state: &SharedState, feed: &str) -> Triggered {
        let decision = self.with(|i| {
            let Some(f) = i.feeds.get_mut(feed) else {
                return Triggered::Unknown;
            };
            let Some(def) = &f.def else {
                return Triggered::Unknown;
            };
            if !def.is_manual() {
                return Triggered::Unknown;
            }
            if !def.enabled {
                // A disabled feed gets no runs; its saves are kept and ingested when it is
                // enabled again.
                return Triggered::Disabled;
            }
            if f.busy {
                f.queued_save = true;
                return Triggered::Queued;
            }
            f.busy = true;
            f.manual_retry = None;
            Triggered::Started
        });
        match decision {
            Some(Triggered::Started) => {
                let (s, f) = (state.clone(), feed.to_string());
                tokio::spawn(async move { manual::run(s, f).await });
                Triggered::Started
            }
            Some(other) => other,
            None => Triggered::Unknown,
        }
    }

    /// "Check now" and the other causes that make a provider due at once: starts the check, or
    /// queues it behind a running one, or schedules it at `min_interval` (or a module pause).
    pub fn trigger_provider(&self, state: &SharedState, provider: &str, cause: Cause) -> Triggered {
        let now = Timestamp::now();
        match self.with(|i| start_decision(i, provider, cause, now)) {
            None => Triggered::Unknown,
            Some(Err(r)) => {
                self.wake.notify_one();
                r
            }
            Some(Ok(())) => {
                spawn_check(state, provider, cause);
                Triggered::Started
            }
        }
    }

    /// Re-ingests the latest applied blob when the feed's ingest parameters no longer match the
    /// ones it was applied with (feeds.md §3 "Editing a feed", §8). The comparison is with the
    /// latest *applied* source run, not the newest run: a run that read the new parameters but
    /// ended held or rejected changed no entries, so the applied set still has the old ones.
    pub(crate) async fn maybe_reingest(&self, state: &SharedState, feed: &str) {
        let Some(def) = self.def(feed) else { return };
        let want = IngestParams::of(&def);
        let f = feed.to_string();
        let need = state
            .db
            .read(move |c| {
                let applied = store::latest_applied_blob(c, &f)?;
                Ok::<_, anyhow::Error>(
                    applied.is_some_and(|r| r.params.is_none_or(|p| p.reads_differently(&want))),
                )
            })
            .await
            .unwrap_or(false);
        if !need {
            return;
        }
        if self.try_acquire(feed) {
            self.submit(state, feed, Work::Reingest);
        } else {
            self.with(|i| {
                if let Some(f) = i.feeds.get_mut(feed) {
                    f.pending_reingest = true;
                }
            });
        }
    }

    /// Judges the newest held or rejected run again after a `sanity` edit (feeds.md §3).
    pub(crate) async fn maybe_regate(&self, state: &SharedState, feed: &str) {
        let Some(def) = self.def(feed) else { return };
        let f = feed.to_string();
        let sanity = def.sanity.clone();
        let run = state
            .db
            .read(move |c| {
                let newest = store::newest_download(c, &f)?;
                Ok::<_, anyhow::Error>(newest.filter(|r| {
                    matches!(r.status, Some(RunStatus::Held | RunStatus::Rejected))
                        && r.gate.as_deref() != Some("superseded")
                        && r.params.as_ref().is_some_and(|p| p.sanity != sanity)
                }))
            })
            .await
            .ok()
            .flatten();
        let Some(run) = run else { return };
        if self.try_acquire(feed) {
            self.submit(state, feed, Work::Regate { run_id: run.id });
        } else {
            self.with(|i| {
                if let Some(f) = i.feeds.get_mut(feed) {
                    f.pending_regate = true;
                }
            });
        }
    }

    /// Takes a feed busy for an import merged into it (feeds.md §4: it waits for any run of the
    /// feed in progress); false while busy.
    pub(crate) fn acquire_for_import(&self, feed: &str) -> bool {
        self.try_acquire(feed)
    }

    /// When a pending import of the feed whose run failed or couldn't be queued runs again
    /// (tests).
    #[doc(hidden)]
    pub fn import_retry_at(&self, feed: &str) -> Option<Timestamp> {
        self.with(|i| i.feeds.get(feed).and_then(|f| f.import_retry))
            .flatten()
    }

    /// An import into the feed was accepted (its record is in `feed_imports`) and its run is
    /// being queued now.
    pub(crate) fn import_accepted(&self, feed: &str, import: i64) {
        self.with(|i| {
            let f = i.feeds.entry(feed.to_string()).or_default();
            f.imports = true;
            f.import_last = Some(import);
        });
    }

    /// Starts the run of the feed's oldest pending import once the feed is free (feeds.md §4): at
    /// start, when the feed is freed, or at `import_retry` (`retry`) after a run of it failed or
    /// couldn't be queued, which waits a minute instead of retrying at once.
    pub(crate) async fn resume_import(&self, state: &SharedState, feed: &str, retry: bool) {
        if !self.try_acquire(feed) {
            return; // freed later, it comes back here
        }
        let f = feed.to_string();
        let row = state
            .db
            .read(move |c| Ok::<_, anyhow::Error>(store::oldest_import(c, &f)?))
            .await;
        let later = Timestamp::now() + jiff::SignedDuration::from_mins(1);
        match row {
            Err(e) => {
                tracing::warn!(feed = %feed, error = %format!("{e:#}"), "cannot read the feed's pending imports");
                self.with(|i| {
                    if let Some(f) = i.feeds.get_mut(feed) {
                        f.import_retry = Some(later);
                    }
                });
                self.release(state, feed);
            }
            Ok(None) => {
                self.with(|i| {
                    if let Some(f) = i.feeds.get_mut(feed) {
                        f.imports = false;
                        f.import_last = None;
                        f.import_retry = None;
                    }
                });
                self.release(state, feed);
            }
            Ok(Some(r)) => {
                let again = self
                    .with(|i| i.feeds.get(feed).and_then(|f| f.import_last) == Some(r.id))
                    .unwrap_or(false);
                if again && !retry {
                    tracing::warn!(feed = %feed, import = r.id, "an import's run failed or couldn't be queued; it runs again in a minute");
                    self.with(|i| {
                        if let Some(f) = i.feeds.get_mut(feed) {
                            f.import_retry = Some(later);
                        }
                    });
                    self.release(state, feed);
                    self.wake.notify_one();
                    return;
                }
                self.with(|i| {
                    if let Some(f) = i.feeds.get_mut(feed) {
                        f.imports = true;
                        f.import_last = Some(r.id);
                        f.import_retry = None;
                    }
                });
                self.submit(
                    state,
                    feed,
                    Work::Import {
                        import: r.id,
                        source_gen: r.source_gen,
                    },
                );
            }
        }
    }

    /// Providers due now, with what made them due: marked checking and returned; manual feeds
    /// whose retry is due; and when the loop should wake next.
    #[expect(
        clippy::type_complexity,
        reason = "the loop's four outputs, taken apart at once by its one caller"
    )]
    fn take_due(
        &self,
        now: Timestamp,
    ) -> (Vec<(String, Cause)>, Vec<String>, Vec<String>, Option<Timestamp>) {
        self.with(|i| {
            let pauses = i.pauses.clone();
            let mut due = Vec::new();
            let mut manual = Vec::new();
            let mut imports = Vec::new();
            let mut next: Option<Timestamp> = None;
            for (id, p) in i.providers.iter_mut() {
                let Some(def) = &p.def else { continue };
                if !def.enabled || p.checking {
                    continue;
                }
                let Some(mut d) = p.due else { continue };
                if let Some(u) = pauses.get(&def.module).filter(|u| **u > d) {
                    d = *u;
                }
                if d <= now {
                    p.checking = true;
                    p.force = false;
                    p.retry_at = None;
                    p.edited_during = false;
                    let first = std::mem::take(&mut p.first);
                    let cause = match p.cause.take() {
                        // "Check now" keeps its name (it bypasses a cron `! Expires:` floor).
                        Some(Cause::CheckNow) => Cause::CheckNow,
                        _ if first || p.last_check.is_none() => Cause::First,
                        Some(c) => c,
                        None if matches!(def.trigger, Trigger::Sqs { .. })
                            && p.trigger_next.is_some_and(|t| t <= now) =>
                        {
                            Cause::Backstop
                        }
                        None => Cause::Trigger,
                    };
                    due.push((id.clone(), cause));
                } else {
                    next = Some(next.map_or(d, |n| n.min(d)));
                }
            }
            for (id, f) in i.feeds.iter_mut() {
                if f.def.is_none() || f.busy {
                    continue;
                }
                match f.import_retry {
                    Some(r) if r <= now => {
                        f.import_retry = None;
                        imports.push(id.clone());
                    }
                    Some(r) => next = Some(next.map_or(r, |n| n.min(r))),
                    None => {}
                }
                let Some(def) = &f.def else { continue };
                if !def.is_manual() || !def.enabled {
                    continue;
                }
                match f.manual_retry {
                    Some(r) if r <= now => {
                        f.busy = true;
                        f.manual_retry = None;
                        manual.push(id.clone());
                    }
                    Some(r) => next = Some(next.map_or(r, |n| n.min(r))),
                    None => {}
                }
            }
            due.sort_by(|a, b| a.0.cmp(&b.0));
            manual.sort();
            imports.sort();
            (due, manual, imports, next)
        })
        .unwrap_or_default()
    }

    /// Loads the learners from the stored history (feed-scheduling.md §4 "Rebuild": the current
    /// epoch's last 60 days), with each provider's `k`.
    async fn rebuild_learners(&self, state: &SharedState) {
        let feeds: Vec<(String, String)> = self
            .with(|i| {
                i.feeds
                    .iter()
                    .filter_map(|(id, f)| {
                        let d = f.def.as_ref()?;
                        Some((id.clone(), d.provider.clone()?))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (id, provider) in feeds {
            let (f, p) = (id.clone(), provider.clone());
            let loaded = state
                .db
                .read(move |c| {
                    let obs = schedule::epoch_observations(c, &f, Timestamp::now())?;
                    let k = store::load_provider_state(c, &p)?.k;
                    Ok::<_, anyhow::Error>((obs, k))
                })
                .await;
            let Ok((obs, k)) = loaded else { continue };
            let l = tokio::task::spawn_blocking(move || Learner::replay(&obs))
                .await
                .unwrap_or_default();
            if let Ok(mut m) = self.learners.lock() {
                let prev_chosen = m.get(&id).and_then(|l| l.k_chosen_at);
                let mut l = l;
                if let Some(k) = k.filter(|k| (0.1..=50.0).contains(k)) {
                    l.k = k;
                }
                l.k_chosen_at = prev_chosen;
                m.insert(id, l);
            }
        }
    }

    /// Puts a trained copy of the feed's learner in place (a check's transaction, once it
    /// committed with the feed's source current), keeping the `k` chosen meanwhile.
    pub(crate) fn install_learner(&self, feed: &str, mut l: Learner) {
        if let Ok(mut m) = self.learners.lock() {
            if let Some(cur) = m.get(feed) {
                l.k = cur.k;
                l.k_chosen_at = cur.k_chosen_at;
            }
            m.insert(feed.to_string(), l);
        }
    }

    /// Rebuilds every feed's learner from the stored history now, as core does at start and
    /// daily (tests).
    #[doc(hidden)]
    pub async fn rebuild_learners_now(&self, state: &SharedState) {
        self.rebuild_learners(state).await;
    }

    /// Runs `f` on the feed's learner (created on first use).
    pub(crate) fn with_learner<T>(&self, feed: &str, f: impl FnOnce(&mut Learner) -> T) -> Option<T> {
        let mut m = self.learners.lock().ok()?;
        Some(f(m.entry(feed.to_string()).or_default()))
    }

    /// A copy of the feed's learner.
    pub fn learner(&self, feed: &str) -> Option<Learner> {
        self.learners.lock().ok()?.get(feed).cloned()
    }

    /// Drops a feed's learner (a new model epoch, a deletion).
    pub(crate) fn drop_learner(&self, feed: &str) {
        if let Ok(mut m) = self.learners.lock() {
            m.remove(feed);
        }
    }

    /// Applies the current definitions: new, changed and removed feed providers and feeds
    /// (core.md §2 edits).
    ///
    /// Reloads run one at a time, each holding [`Feeds::reloading`] from its read of the model to
    /// its end. The config watcher's reload and a one-off one (a request for a feed not loaded
    /// yet, a preset install, an import) can be called at once, and an older reload applying the
    /// model it read after a newer one applied its own would put older definitions back until
    /// the next edit: a task for an `sqs` trigger already edited away, say, which ends at once
    /// and leaves the provider's queue unread (feed-scheduling.md §7: one task per enabled `sqs`
    /// provider). A reload reads the model only once it holds the lock, so the last one applies
    /// the newest definitions.
    pub(crate) async fn reload(&self, state: &SharedState) {
        let _serial = self.reloading.lock().await;
        let model = match state.config.model_of(crate::config::EntityKind::Feed).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "cannot reload feeds");
                return;
            }
        };
        // Deleted feeds' data to retire (written with each deletion): the feed id is taken for
        // the purge in the same step that loads a feed created again with that id, so the new
        // feed's first check can't start before the purge is done.
        let purges = purge::pending(&state.db).await.unwrap_or_else(|e| {
            tracing::warn!(error = %format!("{e:#}"), "cannot read the pending feed purges");
            vec![]
        });
        let gens: HashMap<String, Option<i64>> = state
            .db
            .read(|c| {
                let mut st = c.prepare("SELECT provider_id, source_gen FROM feed_provider_state")?;
                let v = st
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)))?
                    .collect::<rusqlite::Result<HashMap<_, _>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
            .unwrap_or_default();
        let mut start_purges = Vec::new();
        let mut reingest = Vec::new();
        let mut regate = Vec::new();
        let mut start_manual = Vec::new();
        let mut removed = Vec::new();
        let mut disabled = Vec::new();
        let mut providers_gone = Vec::new();
        let mut providers_disabled = Vec::new();
        let mut retargeted: Vec<String> = Vec::new();
        let mut touched: Vec<String> = Vec::new();
        let mut trigger_edits: Vec<String> = Vec::new();
        // Providers whose `sqs` task stops for good: their trigger state ends (and why).
        let mut left_sqs: Vec<(String, &'static str)> = Vec::new();
        let now = Timestamp::now();
        self.with(|i| {
            // Providers.
            let gone: Vec<String> = i
                .providers
                .iter()
                .filter(|(k, p)| p.def.is_some() && !model.feed_providers.contains_key(*k))
                .map(|(k, _)| k.clone())
                .collect();
            for k in &gone {
                let checking = i.providers.get(k).is_some_and(|p| p.checking);
                if checking {
                    if let Some(p) = i.providers.get_mut(k) {
                        p.def = None;
                        p.due = None;
                    }
                } else {
                    i.providers.remove(k);
                }
            }
            providers_gone = gone;
            let reg = crate::modules::download::builtin();
            let key = |d: &FeedProviderDef| {
                reg.get(&d.module)
                    .map(|m| format!("{}|{}", d.module, m.epoch_key(&d.config)))
                    .unwrap_or_default()
            };
            for (id, def) in &model.feed_providers {
                let p = i.providers.entry(id.clone()).or_default();
                let sgen = gens.get(id).copied().flatten();
                let recreated = p.def.as_ref().is_some_and(|old| {
                    old.module == def.module
                        && old.config == def.config
                        && p.source_gen.is_some()
                        && p.source_gen != sgen
                });
                p.source_gen = sgen;
                if recreated {
                    // Deleted and created again between two reloads: a new provider.
                    p.def = None;
                }
                match p.def.replace(def.clone()) {
                    None if std::mem::take(&mut p.restored) => {
                        // Its stored state after a start: its due time stands.
                    }
                    None => {
                        // A new provider (one created again with a deleted one's id too): its
                        // first check is due at once.
                        p.last_check = None;
                        p.trigger_next = None;
                        p.cause = Some(Cause::First);
                        p.first = true;
                        // A retry or back-off is the old provider's: the end of its check, if it
                        // still runs, drops the one it leaves too ([`Feeds::complete`]).
                        p.retry_at = None;
                        if p.checking {
                            p.edited_during = true;
                        }
                    }
                    Some(old) => {
                        let mut edit = false;
                        if old.module != def.module || old.config != def.config {
                            edit = true;
                            p.last_check = None;
                            if key(&old) != key(def) {
                                retargeted.push(id.clone());
                            }
                        }
                        if old.files != def.files || old.exclude != def.exclude {
                            edit = true;
                        }
                        if old.trigger != def.trigger {
                            // The new trigger decides at once (feed-scheduling.md §5): its own
                            // next time now, the feeds' asks re-derived below.
                            p.trigger_next = schedule::trigger_next(&def.trigger, now, p.last_check);
                            trigger_edits.push(id.clone());
                            if matches!(old.trigger, Trigger::Sqs { .. })
                                && !matches!(def.trigger, Trigger::Sqs { .. })
                            {
                                left_sqs.push((id.clone(), "trigger changed"));
                            }
                        }
                        if !old.enabled && def.enabled {
                            edit = true;
                        }
                        if old.enabled && !def.enabled {
                            providers_disabled.push(id.clone());
                            // Its task stops: the trigger state ends as on a trigger change, so
                            // enabling it again starts no streak where this one left off
                            // (feed-scheduling.md §7).
                            if matches!(old.trigger, Trigger::Sqs { .. })
                                && !left_sqs.iter().any(|(p, _)| p == id)
                            {
                                left_sqs.push((id.clone(), "feed provider disabled"));
                            }
                        }
                        if edit {
                            p.edited();
                        }
                    }
                }
                touched.push(id.clone());
            }
            // Feeds.
            removed = i
                .feeds
                .iter()
                .filter(|(k, f)| f.def.is_some() && !model.feeds.contains_key(*k))
                .map(|(k, _)| k.clone())
                .collect();
            for k in &removed {
                // A busy entry stays (without its definition) until its job ends: the purge of
                // the deleted feed's data waits for it.
                let busy = i.feeds.get(k).is_some_and(|f| f.busy);
                if busy {
                    if let Some(f) = i.feeds.get_mut(k) {
                        f.def = None;
                        f.queued_save = false;
                        f.pending_reingest = false;
                        f.pending_regate = false;
                    }
                } else {
                    i.feeds.remove(k);
                }
            }
            let mut new_provider_feeds: Vec<String> = Vec::new();
            for (id, def) in &model.feeds {
                let f = i.feeds.entry(id.clone()).or_default();
                match f.def.replace(def.clone()) {
                    None => {
                        if def.is_manual() {
                            start_manual.push(id.clone());
                        } else if let Some(p) = &def.provider {
                            // A new provider feed is checked like any feed: its provider is due
                            // at once (within min_interval).
                            new_provider_feeds.push(p.clone());
                        }
                        reingest.push(id.clone());
                        regate.push(id.clone());
                    }
                    Some(old) => {
                        if IngestParams::of(&old).reads_differently(&IngestParams::of(def)) {
                            reingest.push(id.clone());
                        }
                        if old.sanity != def.sanity {
                            regate.push(id.clone());
                        }
                        if !old.enabled && def.enabled && def.is_manual() {
                            start_manual.push(id.clone());
                        }
                        if old.enabled && !def.enabled {
                            disabled.push(id.clone());
                        }
                    }
                }
            }
            for p in new_provider_feeds {
                if let Some(pr) = i.providers.get_mut(&p) {
                    if pr.checking {
                        pr.queued.get_or_insert(Cause::Edit);
                    } else if pr.cause.is_none() {
                        pr.cause = Some(Cause::Edit);
                    }
                }
            }
            for (feed, run) in &purges {
                if mark_purge(i.feeds.entry(feed.clone()).or_default(), *run) {
                    start_purges.push((feed.clone(), *run));
                }
            }
            // A retargeted provider's feeds start new epochs: no old floor or ask carries over.
            for p in &retargeted {
                for f in i.feeds.values_mut() {
                    if f.def.as_ref().and_then(|d| d.provider.as_deref()) == Some(p.as_str()) {
                        f.floor = None;
                        f.ask = None;
                    }
                }
            }
        });
        for (feed, run) in start_purges {
            queue_purge(state, &feed, run);
        }
        // The SQS tasks follow the definitions first: a task stopped here is cancelled before the
        // alerts below resolve and its trigger state ends, so a result of a request it still had
        // in flight writes nothing after that (`sqs::record`).
        sqs::sync(state);
        let mut resolve: Vec<(String, &'static str)> = Vec::new();
        for id in &removed {
            self.drop_learner(id);
            for kind in ["feed_down", "feed_held", "feed_stale"] {
                resolve.push((format!("{kind}:{id}"), "feed deleted"));
            }
        }
        for id in &disabled {
            // A disabled feed isn't checked: its source can't be "down" or stale.
            resolve.push((format!("feed_down:{id}"), "feed disabled"));
            resolve.push((format!("feed_stale:{id}"), "feed disabled"));
        }
        for p in providers_gone.iter().chain(providers_disabled.iter()) {
            let by = if providers_gone.contains(p) {
                "feed provider deleted"
            } else {
                "feed provider disabled"
            };
            for kind in [
                "feed_provider_down",
                "feed_provider_trigger_down",
                "feed_provider_listing_incomplete",
            ] {
                resolve.push((format!("{kind}:{p}"), by));
            }
            for f in model
                .feeds
                .values()
                .filter(|f| f.provider.as_deref() == Some(p.as_str()))
            {
                resolve.push((format!("feed_down:{}", f.id), by));
                resolve.push((format!("feed_stale:{}", f.id), by));
            }
        }
        for p in &retargeted {
            for f in model
                .feeds
                .values()
                .filter(|f| f.provider.as_deref() == Some(p.as_str()))
            {
                self.drop_learner(&f.id);
            }
        }
        for (key, by) in resolve {
            let _ = state
                .alerts
                .resolve(&key, Some(serde_json::json!({"by": by})))
                .await;
        }
        // A new epoch drops the staleness reference in the config transaction; an open
        // `feed_stale` without one resolves (feed-scheduling.md §8: reason retargeted).
        stale::resolve_retargeted(state).await;
        for p in &touched {
            self.recompute_due(p);
        }
        for (p, by) in &left_sqs {
            sqs::trigger_left(state, p, by).await;
        }
        for p in &trigger_edits {
            self.trigger_edited(state, p).await;
        }
        for id in reingest {
            self.maybe_reingest(state, &id).await;
        }
        for id in regate {
            self.maybe_regate(state, &id).await;
        }
        for id in start_manual {
            let _ = self.trigger_manual(state, &id);
        }
        select::announce(state).await;
        select::resolve_reviewed(state).await;
        self.wake.notify_one();
    }
}

impl Feeds {
    /// A trigger edit (feed-scheduling.md §5): each enabled feed's ask follows the new trigger at
    /// once, from its stored state (a failing feed keeps its error backoff, a `dynamic` one asks
    /// by its model, under `cron` or `sqs` the others ask nothing), so no ask of the old trigger
    /// holds the provider; the asks and the trigger's own next time are stored for a restart.
    pub(crate) async fn trigger_edited(&self, state: &SharedState, provider: &str) {
        let Some(pdef) = self.provider_def(provider) else {
            return;
        };
        let fids: Vec<String> = self
            .provider_feeds(provider)
            .into_iter()
            .filter(|f| f.enabled)
            .map(|f| f.id)
            .collect();
        let since = crate::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(24 * 7)));
        let loaded = state
            .db
            .read(move |c| {
                let mut v = Vec::new();
                for f in &fids {
                    let st = store::load_state(c, f)?;
                    let bytes: Option<f64> = c.query_row(
                        "SELECT avg(bytes) FROM feed_checks WHERE feed_id = ?1 AND ok = 1 AND changed = 0 AND t >= ?2 AND method <> 'bootstrap'",
                        rusqlite::params![f, since],
                        |r| r.get(0),
                    )?;
                    v.push((f.clone(), st, bytes));
                }
                Ok::<_, anyhow::Error>(v)
            })
            .await;
        let rows = match loaded {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(provider = %provider, error = %format!("{e:#}"), "cannot re-derive the feeds' asks after a trigger edit");
                return;
            }
        };
        let now = Timestamp::now();
        let asks: Vec<(String, Option<Timestamp>)> = rows
            .into_iter()
            .map(|(f, st, bytes)| {
                let learner = self.learner(&f);
                let ask = schedule::feed_ask(&schedule::Inputs {
                    now,
                    schedule: &pdef.trigger,
                    last_check: st.last_check_at,
                    failures: st.failures,
                    expires_s: st.expires_s,
                    last_download: st.last_download_at,
                    learner: learner.as_ref(),
                    cost_factor: schedule::cost_factor(bytes),
                });
                (f, ask)
            })
            .collect();
        let trigger_next = self
            .with(|i| i.providers.get(provider).and_then(|p| p.trigger_next))
            .flatten();
        let (a2, p) = (asks.clone(), provider.to_string());
        let _ = state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                for (f, ask) in &a2 {
                    store::set_ask(&tx, f, *ask)?;
                }
                store::ensure_provider_state(&tx, &p)?;
                tx.execute(
                    "UPDATE feed_provider_state SET next_check_at = ?2 WHERE provider_id = ?1",
                    rusqlite::params![p, trigger_next.as_ref().map(crate::util::ts)],
                )?;
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await;
        for (f, ask) in asks {
            self.set_ask(&f, ask);
        }
        self.recompute_due(provider);
    }
}

/// Whether an explicit cause may start a check of `provider` now, decided under the runtime's
/// lock ([`Feeds::trigger_provider`], a queued "Check now" at [`Feeds::complete`]): `Ok` marks it
/// checking (the caller spawns the check); otherwise it is queued behind a running check, or
/// scheduled at `min_interval` or the end of a module pause. An explicit cause doesn't wait
/// for a retry ([`Feeds::retry_at`]); the check it starts ends that retry.
fn start_decision(i: &mut Inner, provider: &str, cause: Cause, now: Timestamp) -> Result<(), Triggered> {
    let module = {
        let Some(p) = i.providers.get(provider) else {
            return Err(Triggered::Unknown);
        };
        let Some(def) = &p.def else {
            return Err(Triggered::Unknown);
        };
        if !def.enabled {
            return Err(Triggered::Disabled);
        }
        def.module.clone()
    };
    let pause = i.pauses.get(&module).copied().filter(|u| *u > now);
    let p = i.providers.get_mut(provider).ok_or(Triggered::Unknown)?;
    let Some(def) = p.def.clone() else {
        return Err(Triggered::Unknown);
    };
    if p.checking {
        p.queued = Some(Cause::merge(p.queued, cause));
        return Err(Triggered::Queued);
    }
    let min = jiff::SignedDuration::from_secs(crate::util::sat_i64(def.trigger.min_interval().as_secs()));
    if let Some(lc) = p.last_check
        && picket_api::time::saturating_add(lc, min) > now
    {
        let at = picket_api::time::saturating_add(lc, min);
        p.cause = Some(cause);
        p.force = true;
        p.retry_at = None;
        p.due = Some(p.due.map_or(at, |d| d.min(at)));
        return Err(Triggered::Scheduled(at));
    }
    if let Some(u) = pause {
        p.cause = Some(cause);
        p.force = true;
        p.retry_at = None;
        p.due = Some(u);
        return Err(Triggered::Scheduled(u));
    }
    p.checking = true;
    p.cause = None;
    p.force = false;
    p.first = false;
    p.retry_at = None;
    p.edited_during = false;
    Ok(())
}

/// Spawns the check of a provider just marked checking.
fn spawn_check(state: &SharedState, provider: &str, cause: Cause) {
    let (s, p) = (state.clone(), provider.to_string());
    tokio::spawn(async move { check::run(s, p, cause).await });
}

/// Takes the feed id for a purge: true when the caller queues it now; a busy feed runs it when
/// freed; one under way is left alone (another deletion's newer run id is picked up after it).
fn mark_purge(f: &mut FeedRt, run: i64) -> bool {
    if let Some(cur) = f.purging {
        if run > cur {
            f.pending_purge = Some(f.pending_purge.map_or(run, |r| r.max(run)));
        }
        return false;
    }
    if f.busy {
        f.pending_purge = Some(f.pending_purge.map_or(run, |r| r.max(run)));
        return false;
    }
    f.busy = true;
    f.purging = Some(run);
    true
}

/// Queues a purge whose feed id [`mark_purge`] took (or a failed purge's retry: the id stays
/// taken), in the heavy lane's reserved places when the queue is full.
pub(crate) fn queue_purge(state: &SharedState, feed: &str, run: i64) {
    let job = Box::new(purge::PurgeJob::new(state.clone(), feed, run));
    if let Err(job) = state.scheduler.heavy.try_submit_reserved(Priority::P1, job) {
        // Even the reserve is full: its drop retries a minute later, the feed id kept busy.
        drop(job);
    }
}

/// Keeps a feed busy for a queued or running heavy job; when dropped it frees the feed, after
/// undoing the job's run if it didn't finish (a failure, a panic, a full queue): the undo is a
/// heavy job of its own ([`undo::UndoJob`]) that frees the feed when done, and it changes
/// nothing when the run turns out finished (its final transaction committed). At shutdown
/// nothing runs: the next start undoes a run still open.
pub struct JobGuard {
    state: Option<SharedState>,
    feed: String,
    run: Option<i64>,
    done: bool,
}

impl JobGuard {
    pub fn new(state: SharedState, feed: &str) -> Self {
        Self {
            state: Some(state),
            feed: feed.to_string(),
            run: None,
            done: false,
        }
    }

    /// The run the job opened.
    pub fn set_run(&mut self, run: i64) {
        self.run = Some(run);
    }

    /// The run is stored (or there was nothing to do).
    pub fn finished(&mut self) {
        self.done = true;
    }

    /// The job undid its own run (in the step that failed): only the feed is left to free.
    pub fn undone(&mut self) {
        self.run = None;
    }

    /// The run the job opened, if any.
    pub fn run(&self) -> Option<i64> {
        self.run
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else { return };
        let feed = std::mem::take(&mut self.feed);
        let undo = if self.done { None } else { self.run };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => match undo {
                Some(run) => undo::UndoJob::new(state, &feed, run).submit(),
                None => {
                    h.spawn(async move { state.feeds.release(&state, &feed) });
                }
            },
            Err(_) => {
                // Shutting down: the next start undoes an open run.
            }
        }
    }
}

/// Starts the feeds runtime (after the database is open, before serving): undoes runs a crash
/// left open, loads the providers and feeds and their schedules, rebuilds the learners, and
/// starts the loop, the config watcher, the SQS polls and the timers.
pub async fn start(state: &SharedState) -> anyhow::Result<()> {
    // Each module's share of the light lane, inside the feed checks' share (core.md §3:
    // per-provider limits; README §2 capped shares).
    let reg = state.feeds.registry();
    for id in reg.ids() {
        if let Some(m) = reg.get(id) {
            state
                .scheduler
                .light
                .set_limit(&format!("feed:{id}"), m.max_concurrent());
        }
    }
    state.scheduler.light.set_limit(
        crate::modules::download::FEED_SHARE_KEY,
        crate::modules::download::FEED_SHARE,
    );
    let n = undo::undo_open_runs(&state.db).await?;
    if n > 0 {
        tracing::info!(runs = n, "undid feed runs a stop interrupted");
    }
    ingest::drop_temp(&state.db, None).await;
    let pauses = state
        .db
        .read(|c| Ok::<_, anyhow::Error>(store::load_pauses(c)?))
        .await?;
    let states = state
        .db
        .read(|c| Ok::<_, anyhow::Error>(store::load_states(c)?))
        .await?;
    let pstates = state
        .db
        .read(|c| Ok::<_, anyhow::Error>(store::load_provider_states(c)?))
        .await?;
    let now = Timestamp::now();
    state.feeds.with(|i| {
        for (m, u) in pauses {
            if u > now {
                i.pauses
                    .insert(m, u.min(now + jiff::SignedDuration::from_hours(1)));
            }
        }
        for (id, st) in states {
            let f = i.feeds.entry(id).or_default();
            f.ask = st.next_ask_at;
            f.floor = schedule::expires_floor(st.last_download_at, st.expires_s);
        }
        for (n, (id, st)) in pstates.into_iter().enumerate() {
            let p = i.providers.entry(id).or_default();
            p.restored = true;
            p.last_check = st.last_check_at;
            // A due time in the past (core was down) spreads over the first minute.
            let spread =
                jiff::SignedDuration::from_secs(crate::util::sat_i64(n).saturating_mul(7) % START_SPREAD_S);
            p.trigger_next = st.next_check_at;
            p.cause = match (st.nudged_at, st.due_cause.as_deref()) {
                // A nudge recorded before a restart: due at once (feed-scheduling.md §7).
                (Some(_), _) => Some(Cause::Sqs),
                (None, Some(c)) if Cause::parse(c).now_wanted() => Some(Cause::parse(c)),
                _ => None,
            };
            p.due = Some(st.next_check_at.unwrap_or(now).max(now + spread));
        }
    });
    state.feeds.reload(state).await;
    state.feeds.rebuild_learners(state).await;
    resume_imports(state).await;
    spawn_loop(state.clone());
    spawn_config_watch(state.clone());
    spawn_timers(state.clone());
    Ok(())
}

/// Imports accepted before a stop whose runs weren't stored (feeds.md §4; README §2 Restarts):
/// those of feeds deleted, created again or retargeted since go, the others run again.
async fn resume_imports(state: &SharedState) {
    let feeds = state
        .db
        .write(|c| {
            c.execute(
                "DELETE FROM feed_imports WHERE feed_id NOT IN (SELECT id FROM feeds)
                   OR source_gen IS NOT (SELECT s.source_gen FROM feed_state s WHERE s.feed_id = feed_imports.feed_id)",
                [],
            )?;
            Ok::<_, anyhow::Error>(store::feeds_with_imports(c)?)
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %format!("{e:#}"), "cannot read the pending feed imports");
            vec![]
        });
    for feed in feeds {
        state.feeds.with(|i| {
            if let Some(f) = i.feeds.get_mut(&feed) {
                // As at a start: nothing in memory about earlier attempts.
                f.imports = true;
                f.import_last = None;
                f.import_retry = None;
            }
        });
        let s = state.clone();
        tokio::spawn(async move { s.feeds.resume_import(&s, &feed, false).await });
    }
}

/// [`resume_imports`] as a start runs it (tests drive it to stand for a restart; core runs it
/// only at start).
#[doc(hidden)]
pub async fn resume_imports_now(state: &SharedState) {
    resume_imports(state).await;
}

fn spawn_loop(state: SharedState) {
    tokio::spawn(async move {
        loop {
            let now = Timestamp::now();
            let (due, manual, imports, next) = state.feeds.take_due(now);
            for feed in imports {
                let s = state.clone();
                tokio::spawn(async move { s.feeds.resume_import(&s, &feed, true).await });
            }
            for (provider, cause) in due {
                spawn_check(&state, &provider, cause);
            }
            for feed in manual {
                let s = state.clone();
                tokio::spawn(async move { manual::run(s, feed).await });
            }
            let sleep = next
                .map(|n| std::time::Duration::try_from(n - Timestamp::now()).unwrap_or(Duration::ZERO))
                .unwrap_or(MAX_SLEEP)
                .min(MAX_SLEEP);
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                _ = state.feeds.wake.notified() => {}
                _ = tokio::time::sleep(sleep) => {}
            }
        }
    });
}

fn spawn_config_watch(state: SharedState) {
    tokio::spawn(async move {
        let mut rx = state.config.subscribe();
        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                r = rx.changed() => if r.is_err() { return },
            }
            state.feeds.reload(&state).await;
        }
    });
}

/// The hourly expiry sweep (feeds.md §2), the daily learner rebuild and the weekly `k` choice
/// (feed-scheduling.md §4–§5).
fn spawn_timers(state: SharedState) {
    let s = state.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(3600));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t.tick().await;
        loop {
            tokio::select! {
                _ = s.shutdown.cancelled() => return,
                _ = t.tick() => {}
            }
            sweep_expired(&s);
        }
    });
    let s = state.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(86_400));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t.tick().await;
        loop {
            tokio::select! {
                _ = s.shutdown.cancelled() => return,
                _ = t.tick() => {}
            }
            s.feeds.rebuild_learners(&s).await;
            check::choose_ks(&s).await;
        }
    });
}

/// Submits an expiry sweep for every free feed with an `expire_after` type. Waits for a
/// synchronised clock: the sweep closes entries by age (README §2 Clocks).
pub fn sweep_expired(state: &SharedState) {
    if !state.clock.synced() {
        tracing::debug!("the aggregate expiry sweep waits for a synchronised clock");
        return;
    }
    let feeds: Vec<String> = state
        .feeds
        .with(|i| {
            i.feeds
                .iter()
                .filter(|(_, f)| {
                    f.def.as_ref().is_some_and(|d| {
                        let p = IngestParams::of(d);
                        picket_rules::RuleType::ALL
                            .iter()
                            .any(|t| p.expire_after(*t).is_some())
                    })
                })
                .map(|(id, _)| id.clone())
                .collect()
        })
        .unwrap_or_default();
    for feed in feeds {
        if state.feeds.try_acquire(&feed) {
            state.feeds.submit(state, &feed, Work::Expire);
        }
    }
}

/// The provider runtime's check lifecycle (#45), driven step by step on a bare [`Feeds`]: no
/// timers or sleeps, each interleaving is the order of the calls.
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use jiff::SignedDuration;
    use picket_api::DurationStr;

    const P: &str = "prov";

    fn feeds_with(min_interval_s: u64) -> Feeds {
        let f = Feeds::default();
        f.with(|i| {
            i.providers.insert(
                P.into(),
                ProviderRt {
                    def: Some(FeedProviderDef {
                        id: P.into(),
                        module: "http".into(),
                        trigger: Trigger::Dynamic {
                            min_interval: DurationStr::secs(min_interval_s),
                        },
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        });
        f
    }

    fn rt<T>(f: &Feeds, g: impl FnOnce(&mut ProviderRt) -> T) -> T {
        f.with(|i| g(i.providers.get_mut(P).unwrap())).unwrap()
    }

    fn secs(n: i64) -> SignedDuration {
        SignedDuration::from_secs(n)
    }

    /// Claims the provider as the scheduler loop would at `now`: the causes it dispatched.
    fn tick(f: &Feeds, now: Timestamp) -> Vec<Cause> {
        f.take_due(now).0.into_iter().map(|(_, c)| c).collect()
    }

    /// A due provider claimed by the scheduler, then checked: its check is under way.
    fn claimed(f: &Feeds, now: Timestamp) {
        rt(f, |p| {
            p.due = Some(now - secs(1));
            p.last_check = Some(now - secs(3600));
        });
        assert_eq!(tick(f, now).len(), 1, "claimed");
        assert!(f.is_checking(P));
    }

    #[test]
    fn a_retry_holds_through_completion_and_recomputation() {
        let f = feeds_with(0);
        let now = Timestamp::now();
        claimed(&f, now);
        // A full light lane (1 min), set before the check ends, as `check::run` does.
        f.retry_at(P, now + secs(60));
        assert_eq!(f.complete(P, now), None);
        assert!(!f.is_checking(P));
        // The schedule still says "due" (the check stored nothing): the retry holds anyway.
        f.recompute_due(P);
        assert!(f.next_due(P).unwrap() >= now + secs(60), "{:?}", f.next_due(P));
        assert!(tick(&f, now).is_empty(), "no rapid retry");
        assert!(tick(&f, now + secs(30)).is_empty());
        assert_eq!(tick(&f, now + secs(61)).len(), 1, "due once the retry passed");
        assert_eq!(
            rt(&f, |p| p.retry_at),
            None,
            "the check that started ended the retry"
        );
    }

    #[test]
    fn a_setup_backoff_is_in_place_before_the_provider_is_free() {
        let f = feeds_with(0);
        let now = Timestamp::now();
        claimed(&f, now);
        f.retry_at(P, now + schedule::backoff(1));
        // The scheduler runs between the two steps: still checking, nothing to claim.
        assert!(tick(&f, now).is_empty());
        f.complete(P, now);
        assert!(tick(&f, now).is_empty(), "free, but backing off");
        assert_eq!(tick(&f, now + schedule::backoff(1) + secs(1)).len(), 1);
    }

    #[test]
    fn an_edit_replaces_a_voided_checks_retry() {
        // The edit's reload arrives during the check: it replaces the retry the void leaves.
        let f = feeds_with(0);
        let now = Timestamp::now();
        claimed(&f, now);
        rt(&f, ProviderRt::edited);
        f.retry_at(P, now + secs(5));
        assert_eq!(f.complete(P, now), None);
        assert_eq!(rt(&f, |p| p.retry_at), None);
        // (`recompute_due` reads the clock: "at once" is a moment after `now`.)
        assert_eq!(
            tick(&f, now + secs(1)),
            vec![Cause::Edit],
            "the edit's check, at once"
        );
        // The reload arrives after the check ended: it replaces the retry then.
        let f = feeds_with(0);
        claimed(&f, now);
        f.retry_at(P, now + secs(5));
        f.complete(P, now);
        assert!(tick(&f, now).is_empty(), "waiting for the reload");
        rt(&f, ProviderRt::edited);
        f.recompute_due(P);
        assert_eq!(tick(&f, now + secs(1)), vec![Cause::Edit]);
    }

    #[test]
    fn a_queued_check_now_runs_once_when_completion_races_the_scheduler() {
        let f = feeds_with(120);
        let now = Timestamp::now();
        claimed(&f, now);
        // Timer ticks during the check skip it; "Check now" twice coalesces into one follow-up.
        assert!(tick(&f, now).is_empty());
        for _ in 0..2 {
            let r = f.with(|i| start_decision(i, P, Cause::CheckNow, now)).unwrap();
            assert_eq!(r, Err(Triggered::Queued));
        }
        // An early exit records no check: `min_interval` doesn't hold the follow-up, so the end
        // starts it in the same step; neither the scheduler nor another explicit start sees
        // the provider free with it still queued.
        assert_eq!(f.complete(P, now), Some(Cause::CheckNow));
        assert!(f.is_checking(P), "the follow-up is under way");
        assert_eq!(rt(&f, |p| p.queued), None, "consumed");
        assert!(tick(&f, now).is_empty(), "the scheduler can't claim it again");
        let r = f.with(|i| start_decision(i, P, Cause::Sqs, now)).unwrap();
        assert_eq!(r, Err(Triggered::Queued), "at most one check at a time");
        // That follow-up ends with nothing queued but the nudge: one more check, no more.
        assert_eq!(f.complete(P, now), None);
        assert_eq!(tick(&f, now + secs(1)), vec![Cause::Sqs]);
        // This one records its check: nothing more is due within `min_interval`.
        rt(&f, |p| p.last_check = Some(now + secs(1)));
        f.complete(P, now + secs(1));
        assert!(tick(&f, now + secs(2)).is_empty());
    }

    #[test]
    fn a_queued_check_now_within_min_interval_is_scheduled_once() {
        let f = feeds_with(120);
        let now = Timestamp::now();
        claimed(&f, now);
        let _ = f.with(|i| start_decision(i, P, Cause::CheckNow, now));
        // The check recorded its time: the follow-up waits for `min_interval`.
        rt(&f, |p| p.last_check = Some(now));
        assert_eq!(f.complete(P, now), None);
        assert!(!f.is_checking(P));
        assert!(tick(&f, now + secs(60)).is_empty());
        assert_eq!(tick(&f, now + secs(121)), vec![Cause::CheckNow]);
        f.complete(P, now + secs(121));
        assert!(tick(&f, now + secs(121)).is_empty(), "once");
    }

    /// An explicit cause doesn't wait for a retry, even when `min_interval` or a module pause
    /// schedules it: a recompute before then keeps the time it reported.
    #[test]
    fn a_scheduled_check_now_drops_the_retry() {
        let now = Timestamp::now();
        for paused in [false, true] {
            let f = feeds_with(if paused { 0 } else { 600 });
            claimed(&f, now - secs(500));
            f.retry_at(P, now + secs(960));
            rt(&f, |p| p.last_check = Some(now - secs(500)));
            f.complete(P, now);
            if paused {
                f.set_pause("http", now + secs(100));
            }
            let r = f.with(|i| start_decision(i, P, Cause::CheckNow, now)).unwrap();
            assert_eq!(r, Err(Triggered::Scheduled(now + secs(100))), "paused: {paused}");
            f.recompute_due(P);
            assert_eq!(
                tick(&f, now + secs(101)),
                vec![Cause::CheckNow],
                "paused: {paused}"
            );
        }
    }

    #[test]
    fn a_queued_check_now_waits_for_a_module_pause() {
        let f = feeds_with(0);
        let now = Timestamp::now();
        claimed(&f, now);
        f.set_pause("http", now + secs(300));
        let _ = f.with(|i| start_decision(i, P, Cause::CheckNow, now));
        assert_eq!(f.complete(P, now), None, "paused: not started");
        assert!(tick(&f, now + secs(299)).is_empty());
        assert_eq!(tick(&f, now + secs(301)), vec![Cause::CheckNow]);
    }

    #[test]
    fn a_provider_deleted_during_its_check_leaves_when_the_check_ends() {
        let f = feeds_with(0);
        let now = Timestamp::now();
        claimed(&f, now);
        // `reload` keeps a deleted provider while it checks, without its definition.
        rt(&f, |p| {
            p.def = None;
            p.due = None;
        });
        let _ = f.with(|i| start_decision(i, P, Cause::CheckNow, now));
        assert_eq!(f.complete(P, now), None);
        assert!(!f.with(|i| i.providers.contains_key(P)).unwrap(), "retired");
        // Created again with the same id during the check: the new provider stays, and its
        // first check is the next.
        let f = feeds_with(0);
        claimed(&f, now);
        let def = rt(&f, |p| p.def.take());
        rt(&f, |p| {
            p.def = def;
            p.cause = Some(Cause::First);
            p.first = true;
        });
        assert_eq!(f.complete(P, now), None);
        assert!(f.with(|i| i.providers.contains_key(P)).unwrap(), "kept");
        assert_eq!(tick(&f, now + secs(1)), vec![Cause::First]);
    }

    /// A check task that panics or is cancelled frees its provider, but only once its
    /// light-lane job has ended.
    #[tokio::test]
    async fn a_cancelled_or_panicking_check_frees_the_provider_after_its_download() {
        for panics in [false, true] {
            let f = Arc::new(feeds_with(0));
            let now = Timestamp::now();
            claimed(&f, now);
            let (lane_gate, lane_wait) = tokio::sync::oneshot::channel::<()>();
            let lane = tokio::spawn(async move {
                let _ = lane_wait.await;
            });
            let (in_lane, mut reached) = tokio::sync::mpsc::channel::<()>(1);
            let f2 = Arc::clone(&f);
            let task = tokio::spawn(async move {
                let f3 = Arc::clone(&f2);
                let mut release = check::Release::new(move || {
                    f3.complete(P, Timestamp::now());
                });
                release.lane(lane);
                let _ = in_lane.send(()).await;
                if panics {
                    panic!("injected fault outside the light worker");
                }
                std::future::pending::<()>().await;
                release.now();
            });
            reached.recv().await.unwrap();
            if !panics {
                task.abort();
            }
            assert!(task.await.is_err());
            tokio::task::yield_now().await;
            assert!(
                f.is_checking(P),
                "the download still runs: not freed (panics {panics})"
            );
            assert!(tick(&f, now).is_empty());
            lane_gate.send(()).unwrap();
            for _ in 0..100 {
                if !f.is_checking(P) {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(
                !f.is_checking(P),
                "freed once the download ended (panics {panics})"
            );
            rt(&f, |p| p.due = Some(now - secs(1)));
            assert_eq!(tick(&f, now).len(), 1, "a later check starts without a restart");
        }
        // Without a running download, the provider is freed at once.
        let f = Arc::new(feeds_with(0));
        let now = Timestamp::now();
        claimed(&f, now);
        let f2 = Arc::clone(&f);
        drop(check::Release::new(move || {
            f2.complete(P, Timestamp::now());
        }));
        assert!(!f.is_checking(P));
    }

    #[test]
    fn different_providers_check_at_once() {
        let f = feeds_with(0);
        let now = Timestamp::now();
        f.with(|i| {
            let mut q = i.providers.get(P).unwrap().clone();
            q.def.as_mut().unwrap().id = "other".into();
            i.providers.insert("other".into(), q);
            for p in i.providers.values_mut() {
                p.due = Some(now - secs(1));
            }
        });
        assert_eq!(tick(&f, now).len(), 2);
    }
}
