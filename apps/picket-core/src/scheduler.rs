//! Job lanes (core.md §3).
//!
//! | Lane | Concurrency |
//! |---|---|
//! | realtime | not queued: plain `tokio::spawn` (sessions, ingest, UI, alerts) |
//! | [`LightLane`] | 8 in total, plus per-key (per-provider) limits |
//! | [`HeavyLane`] | 1 at a time; priority queue P0–P3 |
//!
//! Heavy jobs run in **steps** ([`HeavyJob::step`]) and the lane re-checks the queue between
//! steps, so a P0 delta runs between two shards of a P2 rebuild. A queued job of the same kind
//! for the same target is **replaced** (coalesced), not duplicated. A job that has started is
//! not queued: a newer one of its kind and target waits behind it and it keeps its progress,
//! unless it says a newer one makes its remaining steps useless ([`HeavyJob::supersedable`]).
//! A waiting job **ages** one priority level per 10 min of waiting, up to P1; time spent running
//! its steps doesn't count (core.md §3). Feed → bundle builds are **debounced** 10 s
//! ([`Debouncer`]). Admission is bounded: a job that doesn't fit is dropped and counted.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::FutureExt;
use serde::Serialize;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Heavy-lane priorities; P0 runs first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Priority {
    /// Incremental bundle deltas, verdict-set deltas, browser-list rewrites.
    P0 = 0,
    /// Feed parse, ingest and diff.
    P1 = 1,
    /// Full shard rebuilds, compaction, verdict-set base rebuilds, the daily re-rank.
    P2 = 2,
    /// Retention deletes, `incremental_vacuum`, `ANALYZE`.
    P3 = 3,
}

/// What a step left to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    More,
    Done,
}

/// A heavy job, run one step at a time.
pub trait HeavyJob: Send + 'static {
    /// The job kind (e.g. `bundle_delta`), for coalescing and metrics.
    fn kind(&self) -> &str;
    /// The target (e.g. the bundle id); same kind + target coalesce.
    fn target(&self) -> &str;
    /// Runs one bounded step (one shard, one chunk).
    fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>>;
    /// True when a newer job of the same kind and target makes this one's remaining steps
    /// useless (a rebuild whose inputs changed): the newer job then replaces it between steps.
    /// By default a started job runs to its end and the newer one waits behind it.
    fn supersedable(&self) -> bool {
        false
    }
}

/// A one-step heavy job from a closure.
pub struct FnJob<F> {
    kind: String,
    target: String,
    f: Option<F>,
}

impl<F, Fut> FnJob<F>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    pub fn new(kind: impl Into<String>, target: impl Into<String>, f: F) -> Self {
        Self {
            kind: kind.into(),
            target: target.into(),
            f: Some(f),
        }
    }
}

impl<F, Fut> HeavyJob for FnJob<F>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    fn kind(&self) -> &str {
        &self.kind
    }
    fn target(&self) -> &str {
        &self.target
    }
    fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
        let f = self.f.take();
        Box::pin(async move {
            if let Some(f) = f {
                f().await?;
            }
            Ok(Step::Done)
        })
    }
}

/// The result of a submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submitted {
    Queued,
    /// A queued job of the same kind and target was replaced.
    Coalesced,
    /// The queue was full; the job was dropped and counted.
    Dropped,
}

struct Entry {
    base: Priority,
    /// When the job was first queued: the order among equal priorities.
    enqueued: Instant,
    /// When its current wait began (first queued, or put back after a step).
    wait_start: Instant,
    /// Time spent waiting before the current wait: aging counts waiting only (core.md §3).
    waited: Duration,
    /// It has run a step: no longer replaced by a newer submission.
    started: bool,
    /// When its first step began (a job run's duration, [`JobRun::ms`]).
    first_step: Option<Instant>,
    seq: u64,
    job: Box<dyn HeavyJob>,
}

impl Entry {
    fn key(&self) -> (String, String) {
        (self.job.kind().to_string(), self.job.target().to_string())
    }
}

/// A heavy job's run as the lane reports it to its observer ([`HeavyLane::observe`]): when it
/// takes its first step, and when it ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRun {
    /// The lane's id of this run (its queue entry's sequence number): a run's start and end carry
    /// the same one, and another run of the same job (`kind:target`) another, so reports of two
    /// runs never stand for each other (a newer run can take steps between two of an older one's:
    /// core.md §3 preemption by splitting).
    pub run: u64,
    /// `kind:target`.
    pub job: String,
    pub kind: String,
    pub target: String,
    /// `None` at the start; at the end `ok`, `failed`, or `superseded` (a newer job of its kind
    /// and target replaced it between steps).
    pub outcome: Option<&'static str>,
    /// At the end: from its first step to its end, in milliseconds.
    pub ms: Option<u64>,
}

/// Called with each job run; it must not block (the lane's worker calls it).
pub type JobObserver = Arc<dyn Fn(JobRun) + Send + Sync>;

/// Heavy-lane counters.
#[derive(Clone, Debug, Default, Serialize)]
pub struct HeavyStats {
    pub queued: usize,
    pub dropped: u64,
    pub coalesced: u64,
    pub steps: u64,
    pub completed: u64,
    pub failed: u64,
    /// The job running now, as `kind:target`.
    pub running: Option<String>,
}

struct HeavyInner {
    queue: Mutex<Vec<Entry>>,
    notify: Notify,
    cap: usize,
    aging_step: Duration,
    seq: AtomicU64,
    stats: Mutex<HeavyStats>,
    observer: Mutex<Option<JobObserver>>,
}

/// The heavy lane: one job at a time from a priority queue.
#[derive(Clone)]
pub struct HeavyLane {
    inner: Arc<HeavyInner>,
}

impl HeavyLane {
    /// Default admission cap.
    pub const CAP: usize = 4096;
    /// Places past the cap kept for jobs that must run in the lane and may not be dropped
    /// ([`HeavyLane::try_submit_reserved`]): a failed feed run's undo and a deleted feed's purge,
    /// at most one per feed (the feed stays busy until it ran), so another heavy job never runs
    /// next to them (core.md §3).
    pub const RESERVE: usize = 256;
    /// One priority level per 10 minutes of waiting (core.md §3).
    pub const AGING_STEP: Duration = Duration::from_secs(600);

    pub fn new(cap: usize, aging_step: Duration) -> Self {
        Self {
            inner: Arc::new(HeavyInner {
                queue: Mutex::new(Vec::new()),
                notify: Notify::new(),
                cap,
                aging_step,
                seq: AtomicU64::new(0),
                stats: Mutex::new(HeavyStats::default()),
                observer: Mutex::new(None),
            }),
        }
    }

    /// Queues a job, replacing a queued one of the same kind and target that hasn't started (it
    /// keeps the earlier queue time and the higher priority of the two).
    pub fn submit(&self, priority: Priority, job: Box<dyn HeavyJob>) -> Submitted {
        match self.try_submit(priority, job) {
            Ok(s) => s,
            Err(_) => Submitted::Dropped,
        }
    }

    /// [`HeavyLane::submit`], but a job the full queue refuses comes back to the caller (counted
    /// as dropped), for work that must not be lost.
    pub fn try_submit(
        &self,
        priority: Priority,
        job: Box<dyn HeavyJob>,
    ) -> Result<Submitted, Box<dyn HeavyJob>> {
        self.admit(priority, job, self.inner.cap)
    }

    /// [`HeavyLane::try_submit`] with [`HeavyLane::RESERVE`] more places, for jobs that may be
    /// neither dropped nor run outside the lane (an undo, a purge). A job even the reserve
    /// refuses comes back; its caller retries admission later.
    pub fn try_submit_reserved(
        &self,
        priority: Priority,
        job: Box<dyn HeavyJob>,
    ) -> Result<Submitted, Box<dyn HeavyJob>> {
        self.admit(priority, job, self.inner.cap.saturating_add(Self::RESERVE))
    }

    fn admit(
        &self,
        priority: Priority,
        job: Box<dyn HeavyJob>,
        cap: usize,
    ) -> Result<Submitted, Box<dyn HeavyJob>> {
        let Ok(mut q) = self.inner.queue.lock() else {
            return Err(job);
        };
        let key = (job.kind().to_string(), job.target().to_string());
        let result = if let Some(e) = q.iter_mut().find(|e| !e.started && e.key() == key) {
            e.job = job;
            e.base = e.base.min(priority);
            self.bump(|s| s.coalesced += 1);
            Submitted::Coalesced
        } else if q.len() >= cap {
            self.bump(|s| s.dropped += 1);
            tracing::warn!(kind = %key.0, target = %key.1, "heavy queue full; job dropped");
            return Err(job);
        } else {
            let now = Instant::now();
            q.push(Entry {
                base: priority,
                enqueued: now,
                wait_start: now,
                waited: Duration::ZERO,
                started: false,
                first_step: None,
                seq: self.inner.seq.fetch_add(1, Ordering::Relaxed),
                job,
            });
            Submitted::Queued
        };
        let len = q.len();
        drop(q);
        self.bump(|s| s.queued = len);
        self.inner.notify.notify_one();
        Ok(result)
    }

    /// Queues a one-step job from a closure.
    pub fn submit_fn<F, Fut>(&self, kind: &str, target: &str, priority: Priority, f: F) -> Submitted
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.submit(priority, Box::new(FnJob::new(kind, target, f)))
    }

    pub fn depth(&self) -> usize {
        self.inner.queue.lock().map(|q| q.len()).unwrap_or(0)
    }

    pub fn stats(&self) -> HeavyStats {
        self.inner.stats.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Reports each job's start (its first step) and end to `f` (the UI's `job` events).
    pub fn observe(&self, f: JobObserver) {
        if let Ok(mut o) = self.inner.observer.lock() {
            *o = Some(f);
        }
    }

    fn report(
        &self,
        run: u64,
        label: &str,
        kind: &str,
        target: &str,
        outcome: Option<&'static str>,
        ms: Option<u64>,
    ) {
        let f = self.inner.observer.lock().ok().and_then(|o| o.clone());
        if let Some(f) = f {
            f(JobRun {
                run,
                job: label.to_string(),
                kind: kind.to_string(),
                target: target.to_string(),
                outcome,
                ms,
            });
        }
    }

    fn bump(&self, f: impl FnOnce(&mut HeavyStats)) {
        if let Ok(mut s) = self.inner.stats.lock() {
            f(&mut s);
        }
    }

    /// The priority a waiting job has now: one level better per aging step, never better than
    /// P1 (P0 stays P0).
    pub fn effective(&self, base: Priority, waited: Duration) -> u8 {
        let b = base as u8;
        if b <= 1 {
            return b;
        }
        let levels = (waited.as_nanos() / self.inner.aging_step.as_nanos().max(1)).min(3) as u8;
        b.saturating_sub(levels).max(1)
    }

    fn pick(&self) -> Option<Entry> {
        let mut q = self.inner.queue.lock().ok()?;
        let now = Instant::now();
        let best = q
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| {
                let waited = e.waited + now.saturating_duration_since(e.wait_start);
                (self.effective(e.base, waited), e.enqueued, e.seq)
            })
            .map(|(i, _)| i)?;
        // Marked running before it leaves the queue (queue lock, then stats lock: nothing takes
        // them the other way round): at every instant the job is queued or running, so an
        // observer reading `depth()` and `stats().running` never sees an idle lane while a job
        // is picked but not yet started.
        let label = format!("{}:{}", q[best].job.kind(), q[best].job.target());
        self.bump(|s| s.running = Some(label));
        let mut e = q.swap_remove(best);
        e.waited += now.saturating_duration_since(e.wait_start);
        let len = q.len();
        drop(q);
        self.bump(|s| s.queued = len);
        Some(e)
    }

    /// Puts a partly done job back for its next step; its wait starts again now, so the time
    /// its step ran doesn't age it. A supersedable job is dropped instead when a newer one of
    /// its kind and target is queued (false).
    fn requeue(&self, mut e: Entry) -> bool {
        let Ok(mut q) = self.inner.queue.lock() else {
            return false;
        };
        if e.job.supersedable() && q.iter().any(|x| !x.started && x.key() == e.key()) {
            return false;
        }
        e.started = true;
        e.wait_start = Instant::now();
        q.push(e);
        let len = q.len();
        drop(q);
        self.bump(|s| s.queued = len);
        true
    }

    /// The lane's worker: runs until `shutdown`. Spawn it once.
    pub async fn run(self, shutdown: CancellationToken) {
        loop {
            let entry = loop {
                if let Some(e) = self.pick() {
                    break e;
                }
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = self.inner.notify.notified() => {}
                }
            };
            let mut entry = entry;
            let (kind, target) = (entry.job.kind().to_string(), entry.job.target().to_string());
            let label = format!("{kind}:{target}");
            // One entry is one run: a submission replaces only an entry that hasn't started.
            // (`pick` marked it running already.)
            let run = entry.seq;
            let started = Instant::now();
            let first = !entry.started;
            if first {
                entry.first_step = Some(started);
                self.report(run, &label, &kind, &target, None, None);
            }
            let since = entry.first_step.unwrap_or(started);
            // A panicking step costs its job, never the lane (README §2: a bad item never stalls
            // the receiver).
            let r = tokio::select! {
                r = AssertUnwindSafe(entry.job.step()).catch_unwind() => match r {
                    Ok(r) => r,
                    Err(_) => Err(anyhow::anyhow!("the job panicked")),
                },
                _ = shutdown.cancelled() => return,
            };
            self.bump(|s| s.steps += 1);
            let ms = || Some(picket_api::duration::as_millis_u64(since.elapsed()));
            let ended = match r {
                Ok(Step::More) => (!self.requeue(entry)).then_some("superseded"),
                Ok(Step::Done) => {
                    self.bump(|s| s.completed += 1);
                    tracing::debug!(job = %label, ms = picket_api::duration::as_millis_u64(started.elapsed()), "heavy job done");
                    Some("ok")
                }
                Err(e) => {
                    self.bump(|s| s.failed += 1);
                    tracing::warn!(job = %label, error = %format!("{e:#}"), "heavy job failed");
                    Some("failed")
                }
            };
            // Only now: a job between two steps is always counted as queued or running, so the
            // stats never show an idle lane while a job still has steps left.
            self.bump(|s| s.running = None);
            if let Some(outcome) = ended {
                self.report(run, &label, &kind, &target, Some(outcome), ms());
            }
            tokio::task::yield_now().await;
        }
    }
}

/// The light lane: at most 8 jobs at once, plus per-key limits (per provider).
#[derive(Clone)]
pub struct LightLane {
    global: Arc<Semaphore>,
    keyed: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    waiting: Arc<AtomicUsize>,
    dropped: Arc<AtomicU64>,
    cap: usize,
    /// Told each job's duration once it ends: its kind ([`job_kind`] of its first key, else
    /// `light`) and milliseconds (`job_ms`, core.md §10).
    timer: Arc<Mutex<Option<JobTimer>>>,
}

/// Receives a light-lane job's kind and duration in milliseconds; it must not block.
pub type JobTimer = Arc<dyn Fn(&str, u64) + Send + Sync>;

/// A light-lane job's kind for `job_ms{kind}` (core.md §10) from its first key: the part before
/// a `:` (`lookup:<provider>` is `lookup`, `feed:<module>` is `feed_check`), else the key itself
/// (`dnssec`, `crosscheck`, `retro_match`), so the kinds are a small fixed set, not one per
/// provider.
pub fn job_kind(key: &str) -> String {
    match key.split_once(':').map(|(k, _)| k).unwrap_or(key) {
        "feed" | crate::modules::download::FEED_SHARE_KEY => "feed_check".to_string(),
        k => k.to_string(),
    }
}

impl LightLane {
    /// Total concurrency (core.md §3).
    pub const CONCURRENCY: usize = 8;
    /// Admission cap: jobs waiting or running.
    pub const CAP: usize = 10_000;
    /// The per-key limit when none was set.
    pub const DEFAULT_KEY_LIMIT: usize = 4;

    pub fn new(concurrency: usize, cap: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(concurrency)),
            keyed: Arc::new(Mutex::new(HashMap::new())),
            waiting: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
            cap,
            timer: Arc::new(Mutex::new(None)),
        }
    }

    /// Reports each job's duration to `f` when it ends.
    pub fn time_jobs(&self, f: JobTimer) {
        if let Ok(mut g) = self.timer.lock() {
            *g = Some(f);
        }
    }

    /// Sets the concurrency limit for `key` (e.g. a provider's `max_inflight` share). Takes
    /// effect for jobs that start waiting after the call.
    pub fn set_limit(&self, key: &str, limit: usize) {
        if let Ok(mut m) = self.keyed.lock() {
            m.insert(key.to_string(), Arc::new(Semaphore::new(limit.max(1))));
        }
    }

    fn key_semaphore(&self, key: &str) -> Option<Arc<Semaphore>> {
        let mut m = self.keyed.lock().ok()?;
        Some(
            m.entry(key.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(Self::DEFAULT_KEY_LIMIT)))
                .clone(),
        )
    }

    /// Runs `fut` when a slot (and `key`'s slot) is free. `None` when the lane is at its
    /// admission cap: the job is dropped and counted.
    pub fn spawn<F>(&self, key: Option<&str>, fut: F) -> Option<JoinHandle<F::Output>>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let keys: Vec<&str> = key.into_iter().collect();
        self.spawn_slotted(&keys, move |_| fut)
    }

    /// Runs the future `f` makes once a slot of each of `keys` (in that order: a provider's
    /// share, then a group's share such as all feed checks) and a global slot are free. The
    /// [`LightSlot`] lets the job give its slots back while it waits on another job (and take
    /// them again after), so waiting never holds a slot. `None` when the lane is at its
    /// admission cap: the job is dropped and counted.
    pub fn spawn_slotted<F, Fut>(&self, keys: &[&str], f: F) -> Option<JoinHandle<Fut::Output>>
    where
        F: FnOnce(LightSlot) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        if self.waiting.fetch_add(1, Ordering::AcqRel) >= self.cap {
            self.waiting.fetch_sub(1, Ordering::AcqRel);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let lane = self.clone();
        let timer = self.timer.clone();
        let kind = keys
            .first()
            .map(|k| job_kind(k))
            .unwrap_or_else(|| "light".into());
        let keys: Arc<[String]> = keys.iter().map(|k| k.to_string()).collect();
        let waiting = self.waiting.clone();
        Some(tokio::spawn(async move {
            // Frees the admission slot when the job ends, panics or is cancelled.
            let _admitted = Admitted(waiting);
            let permit = lane.acquire(&keys).await;
            let slot = LightSlot {
                lane,
                keys,
                permit: Arc::new(tokio::sync::Mutex::new(Some(permit))),
            };
            // The job's slots are held until it ends, whatever `f` does with its handle.
            let _held = slot.clone();
            let started = Instant::now();
            let out = f(slot).await;
            if let Some(t) = timer.lock().ok().and_then(|g| g.clone()) {
                t(&kind, picket_api::duration::as_millis_u64(started.elapsed()));
            }
            out
        }))
    }

    /// Waits for a slot of each key, in order, then a global one: the keys' slots first, so a
    /// provider at its limit holds no global slot.
    async fn acquire(&self, keys: &[String]) -> LightPermit {
        let mut held = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(s) = self.key_semaphore(k)
                && let Ok(p) = s.acquire_owned().await
            {
                held.push(p);
            }
        }
        let global = self.global.clone().acquire_owned().await.ok();
        LightPermit {
            _keyed: held,
            _global: global,
        }
    }

    /// Jobs waiting or running.
    pub fn depth(&self) -> usize {
        self.waiting.load(Ordering::Acquire)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A light-lane job's slots (its keys' and a global one); dropping it frees them.
struct LightPermit {
    _keyed: Vec<tokio::sync::OwnedSemaphorePermit>,
    _global: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// A running light-lane job's hold on its slots.
#[derive(Clone)]
pub struct LightSlot {
    lane: LightLane,
    keys: Arc<[String]>,
    permit: Arc<tokio::sync::Mutex<Option<LightPermit>>>,
}

impl LightSlot {
    /// Runs `fut` (a wait on another job, such as a shared request in flight) without holding
    /// the job's slots, then waits for them again (README §2 capped shares: waiting holds no
    /// slot another job could use).
    pub async fn released<T>(&self, fut: impl Future<Output = T>) -> T {
        let mut g = self.permit.lock().await;
        *g = None;
        let out = fut.await;
        *g = Some(self.lane.acquire(&self.keys).await);
        out
    }
}

/// One admitted light-lane job; dropping it frees its admission slot.
struct Admitted(Arc<AtomicUsize>);

impl Drop for Admitted {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Trailing debounce: `trigger(k)` runs the callback once `delay` has passed without another
/// trigger for `k` (feed → bundle builds, 10 s), and at the latest `max_wait` after the first
/// trigger of a burst, so a key that keeps changing still runs (bounded wait).
pub struct Debouncer<K> {
    delay: Duration,
    max_wait: Duration,
    /// Key → (deadline, first trigger of the burst).
    deadlines: Arc<Mutex<HashMap<K, (Instant, Instant)>>>,
    callback: Arc<dyn Fn(K) + Send + Sync>,
    cap: usize,
}

impl<K> Clone for Debouncer<K> {
    fn clone(&self) -> Self {
        Self {
            delay: self.delay,
            max_wait: self.max_wait,
            deadlines: self.deadlines.clone(),
            callback: self.callback.clone(),
            cap: self.cap,
        }
    }
}

impl<K: Eq + Hash + Clone + Send + 'static> Debouncer<K> {
    /// Feed → bundle build delay (core.md §3).
    pub const BUILD_DELAY: Duration = Duration::from_secs(10);
    /// The longest a build waits while its feeds keep changing.
    pub const BUILD_MAX_WAIT: Duration = Duration::from_secs(60);

    /// A debouncer whose bursts wait at most six delays.
    pub fn new(delay: Duration, callback: impl Fn(K) + Send + Sync + 'static) -> Self {
        Self::with_max_wait(delay, delay.saturating_mul(6), callback)
    }

    pub fn with_max_wait(
        delay: Duration,
        max_wait: Duration,
        callback: impl Fn(K) + Send + Sync + 'static,
    ) -> Self {
        Self {
            delay,
            max_wait: max_wait.max(delay),
            deadlines: Arc::new(Mutex::new(HashMap::new())),
            callback: Arc::new(callback),
            cap: 100_000,
        }
    }

    /// (Re)starts `key`'s timer. Returns false when the key table is full (the trigger is
    /// dropped and the caller should run the work directly).
    pub fn trigger(&self, key: K) -> bool {
        let now = Instant::now();
        let spawn = {
            let Ok(mut m) = self.deadlines.lock() else {
                return false;
            };
            match m.get_mut(&key) {
                Some((deadline, first)) => {
                    *deadline = (now + self.delay).min(*first + self.max_wait);
                    false
                }
                None => {
                    if m.len() >= self.cap {
                        return false;
                    }
                    m.insert(key.clone(), (now + self.delay, now));
                    true
                }
            }
        };
        if spawn {
            let this = self.clone();
            tokio::spawn(async move {
                loop {
                    let due = this.deadlines.lock().ok().and_then(|m| m.get(&key).map(|d| d.0));
                    let Some(due) = due else { return };
                    if Instant::now() >= due {
                        let fire = this
                            .deadlines
                            .lock()
                            .map(|mut m| match m.get(&key) {
                                Some((d, _)) if *d <= Instant::now() => m.remove(&key).is_some(),
                                _ => false,
                            })
                            .unwrap_or(false);
                        if fire {
                            (this.callback)(key);
                            return;
                        }
                        continue;
                    }
                    tokio::time::sleep_until(due).await;
                }
            });
        }
        true
    }

    pub fn pending(&self) -> usize {
        self.deadlines.lock().map(|m| m.len()).unwrap_or(0)
    }
}

/// The lanes core runs.
#[derive(Clone)]
pub struct Scheduler {
    pub light: LightLane,
    pub heavy: HeavyLane,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            light: LightLane::new(LightLane::CONCURRENCY, LightLane::CAP),
            heavy: HeavyLane::new(HeavyLane::CAP, HeavyLane::AGING_STEP),
        }
    }

    /// Starts the heavy worker.
    pub fn start(&self, shutdown: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(self.heavy.clone().run(shutdown))
    }

    /// Calls `submit` every `every` (first after `first`), until shutdown: the periodic jobs
    /// (retention hourly, re-rank daily) submit heavy jobs from here.
    pub fn every(
        &self,
        first: Duration,
        every: Duration,
        shutdown: CancellationToken,
        submit: impl Fn(&HeavyLane) + Send + 'static,
    ) -> JoinHandle<()> {
        let heavy = self.heavy.clone();
        tokio::spawn(async move {
            let mut next = Instant::now() + first;
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep_until(next) => {}
                }
                submit(&heavy);
                next += every;
                if next < Instant::now() {
                    next = Instant::now() + every;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_kinds_are_not_per_entity() {
        assert_eq!(job_kind("lookup:quad9"), "lookup");
        assert_eq!(job_kind("lookup:spamhaus"), "lookup");
        assert_eq!(job_kind("feed:http"), "feed_check");
        assert_eq!(job_kind("dnssec"), "dnssec");
    }

    /// A job that logs each step into a shared vec and takes `steps` steps.
    struct Logged {
        kind: String,
        target: String,
        steps: usize,
        done: usize,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl HeavyJob for Logged {
        fn kind(&self) -> &str {
            &self.kind
        }
        fn target(&self) -> &str {
            &self.target
        }
        fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
            Box::pin(async move {
                self.done += 1;
                self.log
                    .lock()
                    .unwrap()
                    .push(format!("{}:{}#{}", self.kind, self.target, self.done));
                tokio::task::yield_now().await;
                Ok(if self.done >= self.steps {
                    Step::Done
                } else {
                    Step::More
                })
            })
        }
    }

    fn job(kind: &str, target: &str, steps: usize, log: &Arc<Mutex<Vec<String>>>) -> Box<dyn HeavyJob> {
        Box::new(Logged {
            kind: kind.into(),
            target: target.into(),
            steps,
            done: 0,
            log: log.clone(),
        })
    }

    async fn wait_idle(lane: &HeavyLane) {
        for _ in 0..1000 {
            if lane.depth() == 0 && lane.stats().running.is_none() {
                tokio::task::yield_now().await;
                if lane.depth() == 0 && lane.stats().running.is_none() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("lane never went idle");
    }

    /// A job whose `kind()` blocks once it is armed (the worker thread stalls inside it), and
    /// whose step waits for `go`.
    struct Sticky {
        armed: Arc<std::sync::atomic::AtomicBool>,
        started: Arc<std::sync::atomic::AtomicBool>,
        go: Arc<tokio::sync::Notify>,
    }

    impl HeavyJob for Sticky {
        fn kind(&self) -> &str {
            if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(400));
            }
            "sticky"
        }
        fn target(&self) -> &str {
            "t"
        }
        fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
            Box::pin(async move {
                self.started.store(true, std::sync::atomic::Ordering::SeqCst);
                self.go.notified().await;
                Ok(Step::Done)
            })
        }
    }

    /// C12 (the `idle` checks tests and core rely on): from submit to its start a job is always
    /// queued or running, even when the worker thread stalls between taking the job and
    /// starting it (a host stall; here a blocking `kind()`), so the lane never looks idle then.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_picked_job_is_never_seen_idle() {
        let lane = HeavyLane::new(100, Duration::from_secs(600));
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = CancellationToken::new();
        // A first job holds the worker while the sticky one is queued and armed.
        let hold = Arc::new(tokio::sync::Notify::new());
        let held_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        lane.submit(
            Priority::P0,
            Box::new(Sticky {
                armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                started: held_started.clone(),
                go: hold.clone(),
            }),
        );
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        while !held_started.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let go = Arc::new(tokio::sync::Notify::new());
        lane.submit(
            Priority::P1,
            Box::new(Sticky {
                armed: armed.clone(),
                started: started.clone(),
                go: go.clone(),
            }),
        );
        armed.store(true, std::sync::atomic::Ordering::SeqCst);
        hold.notify_one();
        let mut seen_idle = false;
        while !started.load(std::sync::atomic::Ordering::SeqCst) {
            if lane.depth() == 0 && lane.stats().running.is_none() {
                seen_idle = true;
            }
            tokio::task::yield_now().await;
        }
        assert!(!seen_idle, "the lane looked idle while a job was picked");
        go.notify_one();
        lane.submit(Priority::P3, job("after", "x", 1, &log));
        wait_idle(&lane).await;
        stop.cancel();
        h.await.unwrap();
    }

    #[tokio::test]
    async fn priority_order_and_coalescing() {
        let lane = HeavyLane::new(100, Duration::from_secs(600));
        let log = Arc::new(Mutex::new(Vec::new()));
        assert_eq!(
            lane.submit(Priority::P3, job("retention", "all", 1, &log)),
            Submitted::Queued
        );
        assert_eq!(
            lane.submit(Priority::P1, job("ingest", "f1", 1, &log)),
            Submitted::Queued
        );
        assert_eq!(
            lane.submit(Priority::P1, job("policy", "f1", 1, &log)),
            Submitted::Queued
        );
        assert_eq!(
            lane.submit(Priority::P0, job("delta", "b1", 1, &log)),
            Submitted::Queued
        );
        // Same kind + target: replaced, not duplicated.
        assert_eq!(
            lane.submit(Priority::P0, job("delta", "b1", 1, &log)),
            Submitted::Coalesced
        );
        assert_eq!(lane.depth(), 4);
        let stop = CancellationToken::new();
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        wait_idle(&lane).await;
        stop.cancel();
        h.await.unwrap();
        let log = log.lock().unwrap().clone();
        // P0 first; ingest before policy (same priority, in order); P3 last.
        assert_eq!(
            log,
            vec!["delta:b1#1", "ingest:f1#1", "policy:f1#1", "retention:all#1"]
        );
        assert_eq!(lane.stats().coalesced, 1);
    }

    /// F6 (api.md §7 `job` events): the observer hears each job once at its first step and once
    /// at its end, with the outcome; a job's further steps report nothing.
    #[tokio::test]
    async fn the_observer_hears_each_jobs_start_and_end() {
        let lane = HeavyLane::new(100, Duration::from_secs(600));
        let heard = Arc::new(Mutex::new(Vec::new()));
        let h2 = heard.clone();
        lane.observe(Arc::new(move |r: JobRun| {
            h2.lock().unwrap().push((r.job, r.outcome, r.ms.is_some()));
        }));
        let log = Arc::new(Mutex::new(Vec::new()));
        lane.submit(Priority::P1, job("rebuild", "b1", 3, &log));
        lane.submit_fn("bad", "x", Priority::P2, || async { anyhow::bail!("no") });
        let stop = CancellationToken::new();
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        wait_idle(&lane).await;
        stop.cancel();
        h.await.unwrap();
        assert_eq!(
            heard.lock().unwrap().clone(),
            vec![
                ("rebuild:b1".to_string(), None, false),
                ("rebuild:b1".to_string(), Some("ok"), true),
                ("bad:x".to_string(), None, false),
                ("bad:x".to_string(), Some("failed"), true),
            ]
        );
    }

    /// R4 (api.md §7 `job` events; core.md §3 preemption by splitting): a newer run of a job
    /// with a better priority takes steps between two of an older run's; each run's start and
    /// end carry its own run id, so the older run's end never stands for the newer one's start.
    #[tokio::test]
    async fn each_run_of_a_job_reports_its_own_run_id() {
        let lane = HeavyLane::new(100, Duration::from_secs(600));
        let heard = Arc::new(Mutex::new(Vec::new()));
        let h2 = heard.clone();
        lane.observe(Arc::new(move |r: JobRun| {
            h2.lock().unwrap().push((r.run, r.job, r.outcome));
        }));
        let log = Arc::new(Mutex::new(Vec::new()));
        lane.submit(Priority::P2, job("rebuild", "b1", 5, &log));
        let stop = CancellationToken::new();
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        while log.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        // The first run has started: a newer one of the same job is queued beside it.
        assert_eq!(
            lane.submit(Priority::P0, job("rebuild", "b1", 1, &log)),
            Submitted::Queued
        );
        wait_idle(&lane).await;
        stop.cancel();
        h.await.unwrap();
        let heard = heard.lock().unwrap().clone();
        let phases: Vec<_> = heard.iter().map(|(r, j, o)| (*r, j.as_str(), *o)).collect();
        let (first, second) = (heard[0].0, heard[1].0);
        assert_ne!(first, second, "{heard:?}");
        assert_eq!(
            phases,
            vec![
                (first, "rebuild:b1", None),
                (second, "rebuild:b1", None),
                (second, "rebuild:b1", Some("ok")),
                (first, "rebuild:b1", Some("ok")),
            ]
        );
    }

    #[tokio::test]
    async fn p0_runs_between_steps_of_p2() {
        let lane = HeavyLane::new(100, Duration::from_secs(600));
        let log = Arc::new(Mutex::new(Vec::new()));
        lane.submit(Priority::P2, job("rebuild", "b1", 3, &log));
        let stop = CancellationToken::new();
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        // Wait for the first step, then submit a P0.
        while log.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        lane.submit(Priority::P0, job("delta", "b2", 1, &log));
        wait_idle(&lane).await;
        stop.cancel();
        h.await.unwrap();
        let log = log.lock().unwrap().clone();
        let delta = log.iter().position(|s| s == "delta:b2#1").unwrap();
        let last = log.iter().position(|s| s == "rebuild:b1#3").unwrap();
        assert!(delta < last, "{log:?}");
        assert_eq!(log.len(), 4);
    }

    #[test]
    fn aging() {
        let lane = HeavyLane::new(10, Duration::from_secs(600));
        let m = |x: u64| Duration::from_secs(x * 60);
        assert_eq!(lane.effective(Priority::P3, m(0)), 3);
        assert_eq!(lane.effective(Priority::P3, m(10)), 2);
        assert_eq!(lane.effective(Priority::P3, m(20)), 1);
        assert_eq!(lane.effective(Priority::P3, m(500)), 1, "never better than P1");
        assert_eq!(lane.effective(Priority::P2, m(15)), 1);
        assert_eq!(lane.effective(Priority::P1, m(500)), 1);
        assert_eq!(lane.effective(Priority::P0, m(0)), 0);
    }

    #[tokio::test]
    async fn aged_job_overtakes_newer_same_level() {
        let lane = HeavyLane::new(100, Duration::from_millis(20));
        let log = Arc::new(Mutex::new(Vec::new()));
        lane.submit(Priority::P3, job("old", "x", 1, &log));
        tokio::time::sleep(Duration::from_millis(50)).await; // aged to P1
        lane.submit(Priority::P2, job("new", "y", 1, &log));
        let stop = CancellationToken::new();
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        wait_idle(&lane).await;
        stop.cancel();
        h.await.unwrap();
        assert_eq!(log.lock().unwrap()[0], "old:x#1");
    }

    #[tokio::test]
    async fn time_spent_running_does_not_age_a_job() {
        // core.md §3: aging is for waiting jobs. A long P2 job between two of its steps must not
        // outrank a P1 ingest queued after it started.
        let lane = HeavyLane::new(100, Duration::from_millis(20));
        let log = Arc::new(Mutex::new(Vec::new()));
        struct Slow(Arc<Mutex<Vec<String>>>, usize);
        impl HeavyJob for Slow {
            fn kind(&self) -> &str {
                "rebuild"
            }
            fn target(&self) -> &str {
                "b1"
            }
            fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
                Box::pin(async move {
                    self.1 += 1;
                    self.0.lock().unwrap().push(format!("rebuild#{}", self.1));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok(if self.1 >= 3 { Step::Done } else { Step::More })
                })
            }
        }
        lane.submit(Priority::P2, Box::new(Slow(log.clone(), 0)));
        let stop = CancellationToken::new();
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        while log.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        lane.submit(Priority::P1, job("ingest", "f1", 1, &log));
        wait_idle(&lane).await;
        stop.cancel();
        h.await.unwrap();
        let log = log.lock().unwrap().clone();
        assert_eq!(log, vec!["rebuild#1", "ingest:f1#1", "rebuild#2", "rebuild#3"]);
    }

    #[tokio::test]
    async fn a_newer_submission_does_not_throw_away_a_running_job() {
        // core.md §3: coalescing replaces queued jobs; a started job keeps its progress (an
        // hourly retention run doesn't restart from its first table) and the newer one runs
        // after it.
        struct Tagged(&'static str, usize, usize, Arc<Mutex<Vec<String>>>);
        impl HeavyJob for Tagged {
            fn kind(&self) -> &str {
                "retention"
            }
            fn target(&self) -> &str {
                "core"
            }
            fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
                Box::pin(async move {
                    self.1 += 1;
                    self.3.lock().unwrap().push(format!("{}#{}", self.0, self.1));
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok(if self.1 >= self.2 { Step::Done } else { Step::More })
                })
            }
        }
        let lane = HeavyLane::new(100, Duration::from_secs(600));
        let log = Arc::new(Mutex::new(Vec::new()));
        lane.submit(Priority::P3, Box::new(Tagged("first", 0, 3, log.clone())));
        let stop = CancellationToken::new();
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        while log.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            lane.submit(Priority::P3, Box::new(Tagged("second", 0, 1, log.clone()))),
            Submitted::Queued
        );
        // A third one coalesces into the queued second, not into the running first.
        assert_eq!(
            lane.submit(Priority::P3, Box::new(Tagged("third", 0, 1, log.clone()))),
            Submitted::Coalesced
        );
        wait_idle(&lane).await;
        stop.cancel();
        h.await.unwrap();
        let log = log.lock().unwrap().clone();
        assert_eq!(log, vec!["first#1", "first#2", "first#3", "third#1"]);
    }

    #[tokio::test]
    async fn bounded_queue_drops() {
        let lane = HeavyLane::new(2, Duration::from_secs(600));
        let log = Arc::new(Mutex::new(Vec::new()));
        lane.submit(Priority::P3, job("a", "1", 1, &log));
        lane.submit(Priority::P3, job("a", "2", 1, &log));
        assert_eq!(
            lane.submit(Priority::P3, job("a", "3", 1, &log)),
            Submitted::Dropped
        );
        assert_eq!(lane.stats().dropped, 1);
    }

    #[tokio::test]
    async fn light_lane_limits() {
        let lane = LightLane::new(8, 100);
        lane.set_limit("prov", 2);
        let running = Arc::new(AtomicUsize::new(0));
        let max_prov = Arc::new(AtomicUsize::new(0));
        let mut hs = Vec::new();
        for _ in 0..10 {
            let r = running.clone();
            let m = max_prov.clone();
            hs.push(
                lane.spawn(Some("prov"), async move {
                    let n = r.fetch_add(1, Ordering::SeqCst) + 1;
                    m.fetch_max(n, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    r.fetch_sub(1, Ordering::SeqCst);
                })
                .unwrap(),
            );
        }
        for h in hs {
            h.await.unwrap();
        }
        assert!(max_prov.load(Ordering::SeqCst) <= 2);
        assert_eq!(lane.depth(), 0);

        // Global limit of 8.
        let running = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));
        let mut hs = Vec::new();
        for i in 0..30 {
            let r = running.clone();
            let m = max.clone();
            let key = format!("k{i}");
            hs.push(
                lane.spawn(Some(&key), async move {
                    let n = r.fetch_add(1, Ordering::SeqCst) + 1;
                    m.fetch_max(n, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    r.fetch_sub(1, Ordering::SeqCst);
                })
                .unwrap(),
            );
        }
        for h in hs {
            h.await.unwrap();
        }
        assert!(max.load(Ordering::SeqCst) <= 8);

        let small = LightLane::new(1, 1);
        let gate = Arc::new(Notify::new());
        let g = gate.clone();
        let h = small.spawn(None, async move { g.notified().await }).unwrap();
        assert!(small.spawn(None, async {}).is_none());
        assert_eq!(small.dropped(), 1);
        gate.notify_one();
        h.await.unwrap();
    }

    /// core.md §3, README §2 capped shares: jobs under a group key (all feed checks) never take
    /// more than the group's share of the lane, whatever their own keys (providers); other light
    /// work always finds the rest free.
    #[tokio::test]
    async fn light_lane_group_share_leaves_room_for_other_work() {
        let lane = LightLane::new(8, 100);
        lane.set_limit("feeds", 4);
        for p in ["a", "b", "c", "d"] {
            lane.set_limit(&format!("feed:{p}"), 2);
        }
        let gate = Arc::new(Notify::new());
        let running = Arc::new(AtomicUsize::new(0));
        let mut hs = Vec::new();
        for i in 0..16 {
            let (g, r) = (gate.clone(), running.clone());
            let key = format!("feed:{}", ["a", "b", "c", "d"][i % 4]);
            hs.push(
                lane.spawn_slotted(&[key.as_str(), "feeds"], move |_| async move {
                    r.fetch_add(1, Ordering::SeqCst);
                    g.notified().await;
                    r.fetch_sub(1, Ordering::SeqCst);
                })
                .unwrap(),
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            running.load(Ordering::SeqCst),
            4,
            "feed checks hold at most half the lane"
        );
        // Other light work still runs at once.
        let other = tokio::time::timeout(Duration::from_secs(5), lane.spawn(None, async { 7 }).unwrap())
            .await
            .expect("not starved")
            .unwrap();
        assert_eq!(other, 7);
        for _ in 0..2000 {
            if hs.iter().all(|h| h.is_finished()) {
                break;
            }
            gate.notify_waiters();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        for h in hs {
            h.await.unwrap();
        }
        assert_eq!(lane.depth(), 0);
    }

    /// A job waiting on another job ([`LightSlot::released`]) holds no slot meanwhile.
    #[tokio::test]
    async fn light_slot_released_while_waiting() {
        let lane = LightLane::new(1, 10);
        let gate = Arc::new(Notify::new());
        let g = gate.clone();
        let waiter = lane
            .spawn_slotted(&[], move |slot| async move {
                slot.released(g.notified()).await;
                "woke"
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        // The only slot is free while the first job waits.
        let other = tokio::time::timeout(Duration::from_secs(5), lane.spawn(None, async { 1 }).unwrap())
            .await
            .expect("the waiting job gave its slot back")
            .unwrap();
        assert_eq!(other, 1);
        gate.notify_one();
        assert_eq!(waiter.await.unwrap(), "woke");
    }

    /// A job whose step panics.
    struct Panics;

    impl HeavyJob for Panics {
        fn kind(&self) -> &str {
            "panics"
        }
        fn target(&self) -> &str {
            "x"
        }
        fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
            Box::pin(async { panic!("boom") })
        }
    }

    #[tokio::test]
    async fn heavy_lane_survives_a_panicking_job() {
        let lane = HeavyLane::new(100, Duration::from_secs(600));
        let log = Arc::new(Mutex::new(Vec::new()));
        lane.submit(Priority::P0, Box::new(Panics));
        lane.submit(Priority::P1, job("after", "y", 1, &log));
        let stop = CancellationToken::new();
        let h = tokio::spawn(lane.clone().run(stop.clone()));
        for _ in 0..1000 {
            if !log.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            log.lock().unwrap().clone(),
            vec!["after:y#1"],
            "the lane kept running"
        );
        assert_eq!(lane.stats().failed, 1);
        assert!(!h.is_finished());
        stop.cancel();
        h.await.unwrap();
    }

    #[tokio::test]
    async fn light_lane_panic_frees_its_slot() {
        let lane = LightLane::new(2, 2);
        let h = lane
            .spawn(None, async {
                if lane_panics() {
                    panic!("boom");
                }
            })
            .unwrap();
        assert!(h.await.is_err());
        assert_eq!(lane.depth(), 0, "a panicking job leaves no phantom entry");
        assert!(lane.spawn(None, async {}).unwrap().await.is_ok());
        assert!(lane.spawn(None, async {}).unwrap().await.is_ok());
    }

    fn lane_panics() -> bool {
        true
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_is_bounded_by_max_wait() {
        let fired = Arc::new(Mutex::new(Vec::new()));
        let f = fired.clone();
        let t0 = Instant::now();
        let d = Debouncer::with_max_wait(
            Duration::from_secs(10),
            Duration::from_secs(30),
            move |k: String| f.lock().unwrap().push((k, Instant::now())),
        );
        // A key triggered every 5 s never goes quiet for 10 s, yet still fires within 30 s.
        for i in 0..12u64 {
            tokio::time::sleep_until(t0 + Duration::from_secs(i * 5)).await;
            d.trigger("busy".to_string());
        }
        tokio::time::sleep_until(t0 + Duration::from_secs(80)).await;
        let f = fired.lock().unwrap().clone();
        assert!(f.len() >= 2, "{f:?}");
        assert!(f[0].1 - t0 <= Duration::from_secs(31), "{:?}", f[0].1 - t0);
    }

    #[tokio::test(start_paused = true)]
    async fn debounce() {
        let fired = Arc::new(Mutex::new(Vec::new()));
        let f = fired.clone();
        let d = Debouncer::new(Duration::from_secs(10), move |k: String| {
            f.lock().unwrap().push(k)
        });
        d.trigger("b1".to_string());
        tokio::time::sleep(Duration::from_secs(5)).await;
        d.trigger("b1".to_string()); // restarts the timer
        d.trigger("b2".to_string());
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(fired.lock().unwrap().is_empty(), "nothing yet at 11 s");
        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut got = fired.lock().unwrap().clone();
        got.sort();
        assert_eq!(got, vec!["b1", "b2"]);
        assert_eq!(d.pending(), 0);
    }
}
