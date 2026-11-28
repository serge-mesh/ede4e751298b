//! The log shipper (edge.md §11): memory buffer → `POST /v1/logs`; the disk spool while core
//! doesn't ack.
//!
//! - Batches go every second, or sooner once `logging.batch_max` lines are waiting, counting the
//!   `answer` records each carries; each batch holds every answer its records reference, once,
//!   ahead of the first such record.
//! - HTTP 200 is the ack. A batch core rejects whole (400 or 413) is split in half and each half
//!   resent with the answers its records reference; a single record still rejected is dropped
//!   and counted (`rejected`). A 5xx or no answer is retried.
//! - If a batch isn't acked within `spool_after_s` of its first attempt, or core is unreachable,
//!   the buffer goes to the spool and new records append there, keeping order, until it drains;
//!   then shipping returns to memory. A POST still waiting at that deadline is abandoned (core
//!   deduplicates whatever it did store). Records count as delivered only once acked or fsynced
//!   into a segment.
//! - While a drain POST waits for core, new records still go to the spool every tick: the drain
//!   never holds them in the memory buffer until it fills.
//! - The spool drains the two classes' oldest segments together, merged by record order (`seq`
//!   within a run, segment number across runs), so records reach core in the order they were
//!   made.
//! - SIGTERM flushes the buffer to the spool.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use tokio::sync::{Notify, watch};
use tokio::time::Instant;

use picket_api::edge_config::LoggingConfig;
use picket_api::time::Timestamp;

use super::spool::{self, Head, Limits, Line, LineKind, SegContent, SegKey, Spool, SpoolEnv};
use super::{Answer, Class, Delivery, DropCounters, DropReason, Entry, HeaderGen, ProducerRx};

/// Uncompressed bytes per batch at most (keeps a batch well under core's body cap).
const BATCH_RAW_MAX: usize = 4 << 20;
/// Drain rounds per tick at most; each finishes at least one segment.
const DRAIN_PER_TICK: usize = 8;

/// What a `POST /v1/logs` came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostOutcome {
    /// HTTP 200.
    Acked,
    /// HTTP 400 or 413: core couldn't read the batch at all.
    Rejected,
    /// A 5xx or other status: retry later.
    Retry(String),
    /// No answer (connect, TLS or timeout): retry later; core counts as unreachable.
    Unreachable(String),
}

/// Where batches go.
#[async_trait::async_trait]
pub trait LogSink: Send + Sync {
    async fn post(&self, gz_body: Bytes) -> PostOutcome;
}

/// Shipper timing; tests shorten it.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    pub tick: Duration,
    pub retry_min: Duration,
    pub retry_max: Duration,
    pub expire_every: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            tick: Duration::from_secs(1),
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
            expire_every: Duration::from_secs(60),
        }
    }
}

/// Shared control and status: the logging settings in force, published status, and a wake-up.
pub struct LogControl {
    pub config: ArcSwap<LoggingConfig>,
    pub status: ArcSwap<ShipperStatus>,
    wake: Notify,
    /// Set when the core session comes up: the next step retries at once.
    retry_now: AtomicBool,
}

impl Default for LogControl {
    fn default() -> Self {
        Self {
            config: ArcSwap::from_pointee(LoggingConfig::default()),
            status: ArcSwap::from_pointee(ShipperStatus::default()),
            wake: Notify::new(),
            retry_now: AtomicBool::new(false),
        }
    }
}

impl LogControl {
    /// Applies `EdgeConfig.logging` (settings reach their user, README §2), each value clamped
    /// into its range ([`super::bounds`]) so nothing core sends can overflow the shipper's
    /// arithmetic.
    pub fn set_config(&self, c: LoggingConfig) {
        self.config.store(Arc::new(super::clamp_logging(c)));
        self.wake.notify_one();
    }

    /// The core session is up again (`welcome`): the spool drains now rather than after the
    /// shipper's backoff, which can have grown to a minute during the outage (edge.md §11: on
    /// reconnect the spool drains).
    pub fn core_reachable(&self) {
        self.retry_now.store(true, Ordering::Relaxed);
        self.wake.notify_one();
    }
}

/// Runs synchronous spool work (gzip, writes, fsync, deletes) without stalling the runtime's
/// other tasks: on a multi-thread runtime the scheduler moves them off this worker meanwhile.
fn blocking<R>(f: impl FnOnce() -> R) -> R {
    let multi = tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if multi {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct ShipperStatus {
    /// `memory` or `spool`.
    pub mode: &'static str,
    pub buffered: usize,
    pub spool_bytes: u64,
    pub spool_segments: usize,
    #[serde(with = "picket_api::time::micros_opt")]
    pub oldest_ts: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Memory,
    Spool,
}

/// How far the drain got through one segment.
#[derive(Clone, Copy, Debug, Default)]
struct Progress {
    /// Index (in the segment's lines) of the first record not yet acked or rejected. A position,
    /// not a batch number: batches are planned again on each attempt, and records that aged out
    /// meanwhile shift them.
    next: usize,
    /// Planning reached this index: below it, the records made before `counted_cutoff` had
    /// their age drop counted, and the others were planned for delivery (and, unless acked
    /// since, still wait).
    counted: usize,
    /// The latest cutoff the records below `counted` were checked against.
    counted_cutoff: Option<Timestamp>,
    /// The segment's unreadable lines were counted.
    bad_counted: bool,
}

/// The shipper task's state.
pub struct Shipper {
    rx: ProducerRx,
    buffer: VecDeque<Entry>,
    spool: Spool,
    env: Arc<dyn SpoolEnv>,
    sink: Arc<dyn LogSink>,
    control: Arc<LogControl>,
    dropped: Arc<DropCounters>,
    timings: Timings,
    mode: Mode,
    /// Since when the front of the buffer has waited for an ack (its first attempt).
    waiting_since: Option<Instant>,
    retry_at: Option<Instant>,
    backoff: Duration,
    /// Drain progress per segment (the heads being drained, at most one per class).
    progress: HashMap<SegKey, Progress>,
    last_expire: Option<Instant>,
    /// The last spool write failure logged, and when: the same failure is logged at most once a
    /// minute (a full disk would otherwise log every tick).
    last_spool_error: Option<(String, Instant)>,
}

impl Shipper {
    pub fn new(
        rx: ProducerRx,
        env: Arc<dyn SpoolEnv>,
        sink: Arc<dyn LogSink>,
        control: Arc<LogControl>,
        dropped: Arc<DropCounters>,
        timings: Timings,
    ) -> Self {
        let spool = Spool::open(env.as_ref(), Arc::clone(&dropped));
        // Records left in the spool by an earlier run drain first; new ones queue behind them.
        let mode = if spool.is_empty() {
            Mode::Memory
        } else {
            Mode::Spool
        };
        Self {
            rx,
            buffer: VecDeque::new(),
            spool,
            env,
            sink,
            control,
            dropped,
            timings,
            mode,
            waiting_since: None,
            retry_at: None,
            backoff: timings.retry_min,
            progress: HashMap::new(),
            last_expire: None,
            last_spool_error: None,
        }
    }

    /// Runs until `shutdown` turns true, then flushes the buffer to the spool.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(self.timings.tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let control = Arc::clone(&self.control);
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {}
                _ = control.wake.notified() => {}
                e = self.rx.rx.recv() => {
                    match e {
                        Some(e) => self.buffer.push_back(e),
                        None => break,
                    }
                    // Otherwise wait for the tick: batches go every second (memory), and spool
                    // appends are batched too (one fsync per tick, not per record).
                    if self.buffer.len() < self.batch_max() {
                        continue;
                    }
                }
            }
            self.collect();
            let step = self.step();
            tokio::select! {
                _ = step => {}
                _ = shutdown.changed() => break,
            }
            self.publish_status();
        }
        self.shutdown_flush();
        self.publish_status();
    }

    fn batch_max(&self) -> usize {
        (self.control.config.load().batch_max as usize).clamp(1, picket_api::logs::MAX_BATCH_RECORDS)
    }

    fn spool_after(&self) -> Duration {
        // Clamped on the way in (LogControl::set_config); again here, so no path runs 0.
        let s = self.control.config.load().spool_after_s;
        let r = &super::bounds::SPOOL_AFTER_S;
        Duration::from_secs(u64::from(s.clamp(*r.start(), *r.end())))
    }

    fn limits(&self) -> Limits {
        // The values are clamped on the way in (LogControl::set_config); clamp again so no
        // path can overflow.
        let c = super::clamp_logging(**self.control.config.load());
        Limits {
            data_max: c.spool_max_mib << 20,
            ssd_max: c.ssd_spool_max_mib.map(|m| m << 20),
            retention: jiff::SignedDuration::from_hours(i64::from(c.retention_h)),
        }
    }

    /// Records made before this are past the retention window (`None`: no age decision).
    fn cutoff(&self, now: Timestamp) -> Option<Timestamp> {
        if !self.env.clock_synced() {
            return None;
        }
        now.checked_sub(self.limits().retention).ok()
    }

    /// Moves everything waiting in the channel into the buffer.
    fn collect(&mut self) {
        while let Ok(e) = self.rx.rx.try_recv() {
            self.buffer.push_back(e);
        }
    }

    /// One shipping step.
    pub async fn step(&mut self) {
        let now = Timestamp::now();
        self.purge_buffer(now);
        if self.control.retry_now.swap(false, Ordering::Relaxed) {
            // The core session is back: drain the spool now, not after the backoff.
            self.note_success();
        }
        let env = Arc::clone(&self.env);
        blocking(|| self.spool.sync_ssd(env.as_ref()));
        if self.mode == Mode::Memory && !self.spool.is_empty() {
            // Segments appeared (an SSD that passed its checks after start, holding an earlier
            // run's spool): they drain first, and new records queue behind them.
            self.mode = Mode::Spool;
        }
        if self
            .last_expire
            .is_none_or(|t| t.elapsed() >= self.timings.expire_every)
        {
            let limits = self.limits();
            blocking(|| self.spool.expire(now, env.as_ref(), &limits));
            self.last_expire = Some(Instant::now());
        }
        match self.mode {
            Mode::Memory => self.step_memory().await,
            Mode::Spool => self.step_spool().await,
        }
    }

    fn retry_due(&self) -> bool {
        self.retry_at.is_none_or(|t| Instant::now() >= t)
    }

    fn note_failure(&mut self) {
        self.retry_at = Some(Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(self.timings.retry_max);
    }

    fn note_success(&mut self) {
        self.retry_at = None;
        self.backoff = self.timings.retry_min;
    }

    async fn step_memory(&mut self) {
        loop {
            if self.buffer.is_empty() {
                self.waiting_since = None;
                return;
            }
            if !self.retry_due() {
                break;
            }
            // The batch at the front has until spool_after_s after its first attempt to be
            // acked; a POST still waiting then is abandoned and the buffer spooled.
            let spool_after = self.spool_after();
            let since = *self.waiting_since.get_or_insert_with(Instant::now);
            let n = select_batch(self.buffer.iter(), self.batch_max());
            let items: Vec<Item<'_>> = self.buffer.iter().take(n).map(Item::from_entry).collect();
            let hdr = self.rx.headers();
            let sink = Arc::clone(&self.sink);
            let res = send_with_split(sink.as_ref(), &items, &hdr, Waiting::Until(since + spool_after)).await;
            drop(items);
            let rejected: HashSet<usize> = res.rejected.iter().copied().collect();
            for i in 0..res.done {
                if let Some(mut e) = self.buffer.pop_front() {
                    if rejected.contains(&i) {
                        self.dropped.add(DropReason::Rejected, 1);
                        e.resolve(Delivery::Dropped(DropReason::Rejected));
                    } else {
                        e.resolve(Delivery::Acked);
                    }
                }
            }
            self.rx.release(res.done);
            match res.failure {
                None => {
                    // Each step ships everything waiting, batch by batch.
                    self.note_success();
                    self.waiting_since = None;
                }
                Some(f) => {
                    self.note_failure();
                    let unreachable = matches!(f, PostOutcome::Unreachable(_));
                    if unreachable || since.elapsed() >= spool_after {
                        tracing::warn!(
                            "core isn't acking logs ({}); spooling to disk",
                            crate::diag::cap(match &f {
                                PostOutcome::Retry(s) | PostOutcome::Unreachable(s) => s.as_str(),
                                _ => "",
                            })
                        );
                        self.mode = Mode::Spool;
                        blocking(|| self.flush_to_spool());
                    }
                    break;
                }
            }
        }
        // Still waiting on an earlier failure: spool once the grace period has passed.
        if let Some(since) = self.waiting_since
            && since.elapsed() >= self.spool_after()
            && self.mode == Mode::Memory
        {
            self.mode = Mode::Spool;
            blocking(|| self.flush_to_spool());
        }
    }

    async fn step_spool(&mut self) {
        blocking(|| self.flush_to_spool());
        if !self.retry_due() {
            return;
        }
        let spool = &self.spool;
        self.progress.retain(|k, _| spool.contains(k));
        // Contents read in this step, kept while their segment stays a head: a head being
        // drained is sealed before anything is appended (see `flush_during_drain`), so its
        // content can't change under the drain.
        let mut read: Vec<(SegKey, Arc<SegContent>)> = vec![];
        for _ in 0..DRAIN_PER_TICK {
            let heads = self.spool.heads();
            if heads.is_empty() {
                break;
            }
            read.retain(|(k, _)| heads.iter().any(|h| h.key == *k));
            for h in &heads {
                if read.iter().any(|(k, _)| *k == h.key) {
                    continue;
                }
                match self.read_head(h).await {
                    Some(c) => read.push((h.key, Arc::new(c))),
                    None => return,
                }
            }
            let contents: Vec<Arc<SegContent>> = heads
                .iter()
                .filter_map(|h| read.iter().find(|(k, _)| *k == h.key).map(|(_, c)| Arc::clone(c)))
                .collect();
            match self.drain_heads(&heads, &contents).await {
                DrainResult::Done => continue,
                DrainResult::Stop => return,
            }
        }
        if self.spool.is_empty() {
            // Caught up: whatever is in the buffer is newer than everything shipped.
            self.mode = Mode::Memory;
            self.waiting_since = None;
            self.progress.clear();
        }
    }

    /// Reads a head segment. A failure is transient (EIO, unmounted, permissions): the segment
    /// is kept and the drain retried later.
    async fn read_head(&mut self, h: &Head) -> Option<SegContent> {
        let p = h.path.clone();
        match tokio::task::spawn_blocking(move || spool::read_segment(&p, spool::MAX_SEGMENT_RAW)).await {
            Ok(Ok(c)) => Some(c),
            Ok(Err(e)) => {
                tracing::warn!(
                    "can't read spool segment {}: {}",
                    h.path.display(),
                    crate::diag::cap(&e)
                );
                if h.key.loc == spool::Loc::Ssd {
                    self.env.ssd_failed();
                }
                self.note_failure();
                None
            }
            Err(e) => {
                tracing::warn!("spool read task: {}", crate::diag::cap(e));
                self.note_failure();
                None
            }
        }
    }

    /// One drain round over the classes' oldest segments, merged by record order. It runs
    /// until a head whose class has a later segment runs out (that segment's records may come
    /// before the other head's next ones), or every head does; the heads that ran out are then
    /// deleted.
    async fn drain_heads(&mut self, heads: &[Head], contents: &[Arc<SegContent>]) -> DrainResult {
        let limits = self.limits();
        let cutoff = self.cutoff(Timestamp::now());
        let mut views = Vec::with_capacity(heads.len());
        for (h, c) in heads.iter().zip(contents) {
            let p = self.progress.entry(h.key).or_default();
            if !p.bad_counted {
                p.bad_counted = true;
                self.dropped.add(DropReason::Rejected, c.bad);
            }
            views.push(HeadView {
                key: h.key,
                more: h.more,
                content: c,
                start: p.next,
                counted: p.counted,
                counted_cutoff: p.counted_cutoff,
            });
        }
        let plan = plan_merge(&views, cutoff, self.batch_max());
        self.dropped.add(DropReason::TooOld, plan.too_old);
        for ((h, v), end) in heads.iter().zip(&views).zip(&plan.ends) {
            if let Some(p) = self.progress.get_mut(&h.key) {
                p.counted = v.counted.max(*end);
                p.counted_cutoff = later(v.counted_cutoff, cutoff);
            }
        }
        let hdr = self.rx.headers();
        let sink = Arc::clone(&self.sink);
        let tick = self.timings.tick;
        let draining: Vec<SegKey> = heads.iter().map(|h| h.key).collect();
        // Records arriving meanwhile are spooled (`flush_during_drain`), and making room for
        // them may evict a head these POSTs ship from: its records are counted once the POSTs
        // have their answers, as evicted only where core didn't take them (api.md §3).
        self.spool.begin_flight(&draining);
        let mut unhandled: Option<Vec<&PlannedLine>> = None;
        for (i, batch) in plan.batches.iter().enumerate() {
            let items: Vec<Item<'_>> = batch.iter().map(PlannedLine::item).collect();
            let res = {
                let mut flush = || self.flush_during_drain(&draining);
                send_with_split(
                    sink.as_ref(),
                    &items,
                    &hdr,
                    Waiting::Ticking {
                        every: tick,
                        on_tick: &mut flush,
                    },
                )
                .await
            };
            self.dropped.add(DropReason::Rejected, res.rejected.len() as u64);
            if res.failure.is_some() {
                unhandled = Some(
                    batch[res.done..]
                        .iter()
                        .chain(plan.batches[i + 1..].iter().flatten())
                        .collect(),
                );
                break;
            }
        }
        let evicted = self.spool.end_flight();
        // Records of a head from `from` on that are neither shipped nor already counted too old
        // (the planner counted every record below `counted` made before `counted_cutoff`).
        let unshipped = |hi: usize, v: &HeadView<'_>, from: usize| {
            let counted = v.counted.max(plan.ends[hi]);
            let counted_cutoff = later(v.counted_cutoff, cutoff);
            v.content
                .lines
                .iter()
                .enumerate()
                .skip(from)
                .filter(|(i, l)| {
                    matches!(l.kind, LineKind::Record { .. })
                        && !(*i < counted && made_before_cutoff(l, counted_cutoff))
                })
                .count() as u64
        };
        // Whether part of a head from its resume point on was acked or counted too old: once
        // it has been, the segment takes no more appends, so that what an eviction or the age
        // limit would still drop of it is known (and nothing is counted twice).
        let handled_some = |v: &HeadView<'_>, left: u64| {
            let records = v
                .content
                .lines
                .iter()
                .skip(v.start)
                .filter(|l| matches!(l.kind, LineKind::Record { .. }))
                .count() as u64;
            left < records
        };
        if let Some(unhandled) = unhandled {
            // Partial progress is resent from each head's first unhandled record next time
            // (at-least-once).
            for (hi, (h, v)) in heads.iter().zip(&views).enumerate() {
                let next = unhandled
                    .iter()
                    .find(|l| l.head == hi)
                    .map_or(plan.ends[hi], |l| l.idx);
                let left = unshipped(hi, v, next);
                if evicted.contains(&h.key) {
                    self.dropped.add(DropReason::Evicted, left);
                    self.progress.remove(&h.key);
                    continue;
                }
                if handled_some(v, left) {
                    self.spool.seal(h.key);
                }
                self.spool.set_unshipped(h.key, left);
                if let Some(p) = self.progress.get_mut(&h.key) {
                    p.next = next;
                }
            }
            self.note_failure();
            return DrainResult::Stop;
        }
        self.note_success();
        // Every planned record was acked or rejected: a retry after a failed cleanup below
        // resumes past them (no resend, no rejection counted twice).
        for (h, end) in heads.iter().zip(&plan.ends) {
            if let Some(p) = self.progress.get_mut(&h.key) {
                p.next = *end;
            }
        }
        let env = Arc::clone(&self.env);
        // A failed cleanup stops the drain only after every head's accounting below: an
        // eviction `end_flight` reported is counted once, here, or never.
        let mut failed = false;
        for (hi, ((h, v), end)) in heads.iter().zip(&views).zip(&plan.ends).enumerate() {
            if evicted.contains(&h.key) {
                // Evicted while its records were in flight: what this round shipped arrived;
                // the rest of it is gone.
                self.dropped.add(DropReason::Evicted, unshipped(hi, v, *end));
                self.progress.remove(&h.key);
                continue;
            }
            if *end < v.content.lines.len() {
                // The rest waits for the next round; an eviction or the age limit would drop
                // only that.
                let left = unshipped(hi, v, *end);
                if handled_some(v, left) {
                    self.spool.seal(h.key);
                }
                self.spool.set_unshipped(h.key, left);
                if let Some(p) = self.progress.get_mut(&h.key) {
                    p.next = *end;
                }
                continue;
            }
            if v.content.corrupt {
                tracing::warn!(
                    "spool segment {} was damaged; its readable records were shipped",
                    h.path.display()
                );
            }
            if !blocking(|| self.spool.finish(h.key, env.as_ref(), &limits)) {
                // Every record of it was handled: it takes no more appends, and an eviction
                // or the age limit before the retry deletes it drops nothing.
                self.spool.seal(h.key);
                self.spool.set_unshipped(h.key, 0);
                failed = true;
                continue;
            }
            self.progress.remove(&h.key);
        }
        if failed {
            self.note_failure();
            return DrainResult::Stop;
        }
        DrainResult::Done
    }

    /// While a drain POST waits: new records go to the spool now. The segments being drained
    /// are sealed first, so nothing is appended to a segment whose read-back the drain is
    /// working from (finishing it would delete the new records).
    fn flush_during_drain(&mut self, draining: &[SegKey]) {
        self.collect();
        if self.buffer.is_empty() {
            return;
        }
        for k in draining {
            self.spool.seal(*k);
        }
        blocking(|| self.flush_to_spool());
    }

    /// Drops buffered records past the retention window, once the clock is synchronised.
    fn purge_buffer(&mut self, now: Timestamp) {
        let Some(cutoff) = self.cutoff(now) else {
            return;
        };
        let before = self.buffer.len();
        let mut kept = VecDeque::with_capacity(before);
        for mut e in self.buffer.drain(..) {
            if e.ts < cutoff {
                e.resolve(Delivery::Dropped(DropReason::TooOld));
            } else {
                kept.push_back(e);
            }
        }
        let dropped = before - kept.len();
        self.buffer = kept;
        if dropped > 0 {
            self.dropped.add(DropReason::TooOld, dropped as u64);
            self.rx.release(dropped);
        }
    }

    /// Writes the whole buffer to the spool, class by class, keeping order within each class
    /// (the drain merges the classes back into record order). Entries leave the buffer only
    /// once their segment append is fsynced.
    fn flush_to_spool(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let limits = self.limits();
        let mut written: HashSet<u64> = HashSet::new();
        for class in Class::ALL {
            let refs: Vec<&Entry> = self.buffer.iter().filter(|e| e.class == class).collect();
            if refs.is_empty() {
                continue;
            }
            let hdr = self.rx.headers();
            match self.spool.append(class, &refs, self.env.as_ref(), &limits, &hdr) {
                Ok(()) => written.extend(refs.iter().map(|e| e.seq)),
                Err(e) => {
                    let text = crate::diag::cap(e);
                    let repeat = self
                        .last_spool_error
                        .as_ref()
                        .is_some_and(|(t, at)| *t == text && at.elapsed() < Duration::from_secs(60));
                    if !repeat {
                        tracing::warn!("spool write failed (records stay buffered): {text}");
                        self.last_spool_error = Some((text, Instant::now()));
                    }
                }
            }
        }
        if written.is_empty() {
            return;
        }
        let before = self.buffer.len();
        let mut kept = VecDeque::with_capacity(before - written.len().min(before));
        for mut e in self.buffer.drain(..) {
            if written.contains(&e.seq) {
                e.resolve(Delivery::Spooled);
            } else {
                kept.push_back(e);
            }
        }
        let n = before - kept.len();
        self.buffer = kept;
        self.rx.release(n);
    }

    /// SIGTERM: everything still buffered goes to the spool (a restart loses nothing).
    fn shutdown_flush(&mut self) {
        // A drain cancelled mid-POST never got its answer.
        self.spool.abandon_flight();
        self.collect();
        blocking(|| self.flush_to_spool());
        for mut e in self.buffer.drain(..) {
            e.resolve(Delivery::Dropped(DropReason::BufferFull));
        }
    }

    fn publish_status(&mut self) {
        let s = ShipperStatus {
            mode: match self.mode {
                Mode::Memory => "memory",
                Mode::Spool => "spool",
            },
            buffered: self.buffer.len(),
            spool_bytes: self.spool.bytes(),
            spool_segments: self.spool.segment_count(),
            oldest_ts: self.spool.oldest_ts(),
        };
        self.control.status.store(Arc::new(s));
    }
}

enum DrainResult {
    Done,
    Stop,
}

/// A record to send, with the answer it references.
pub(crate) struct Item<'a> {
    line: &'a str,
    answer: Option<AnswerRef<'a>>,
}

pub(crate) enum AnswerRef<'a> {
    /// A buffered answer: each batch writes a fresh copy (own `(boot, seq)` and `ts`).
    Live(&'a Arc<Answer>),
    /// An answer line read back from a segment.
    Line { id: &'a str, line: &'a str },
}

impl AnswerRef<'_> {
    fn id(&self) -> &str {
        match self {
            Self::Live(a) => &a.id,
            Self::Line { id, .. } => id,
        }
    }
}

impl<'a> Item<'a> {
    fn from_entry(e: &'a Entry) -> Self {
        Self {
            line: &e.line,
            answer: e.answer.as_ref().map(AnswerRef::Live),
        }
    }
}

/// How many leading entries make one batch: at most `max` lines counting each new answer, and
/// at most [`BATCH_RAW_MAX`] bytes; always at least one entry.
fn select_batch<'a>(entries: impl Iterator<Item = &'a Entry>, max: usize) -> usize {
    let mut seen: HashSet<&str> = HashSet::new();
    let (mut lines, mut bytes, mut n) = (0usize, 0usize, 0usize);
    for e in entries {
        let new_answer = e.answer.as_ref().filter(|a| !seen.contains(a.id.as_str()));
        let need = 1 + usize::from(new_answer.is_some());
        let size = e.line.len() + new_answer.map_or(0, |a| a.wire.len() * 4 / 3 + 128);
        if n > 0 && (lines + need > max || bytes + size > BATCH_RAW_MAX) {
            break;
        }
        if let Some(a) = new_answer {
            seen.insert(a.id.as_str());
        }
        lines += need;
        bytes += size;
        n += 1;
    }
    n
}

/// The gzip JSONL body for `items`, every referenced answer once, ahead of its first record.
fn build_body(items: &[Item<'_>], hdr: &HeaderGen) -> Bytes {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut raw = String::new();
    for it in items {
        if let Some(a) = &it.answer
            && seen.insert(a.id())
        {
            match a {
                AnswerRef::Live(a) => raw.push_str(&a.line(hdr.next())),
                AnswerRef::Line { line, .. } => raw.push_str(line),
            }
            raw.push('\n');
        }
        raw.push_str(it.line);
        raw.push('\n');
    }
    let mut enc = GzEncoder::new(Vec::with_capacity(raw.len() / 4 + 64), Compression::fast());
    let _ = enc.write_all(raw.as_bytes());
    Bytes::from(enc.finish().unwrap_or_default())
}

/// The result of sending a run of items with splitting.
pub(crate) struct SplitResult {
    /// Leading items handled (acked or rejected).
    pub done: usize,
    /// Indices (into the run) core still rejected alone: dropped and counted.
    pub rejected: Vec<usize>,
    /// Why sending stopped early, if it did.
    pub failure: Option<PostOutcome>,
}

/// What the shipper does while a POST waits for core.
pub(crate) enum Waiting<'a> {
    /// Memory mode: give up at this instant (`spool_after_s` after the batch's first attempt).
    Until(Instant),
    /// Spool mode: wait for the answer, running `on_tick` every `every` meanwhile.
    Ticking {
        every: Duration,
        on_tick: &'a mut (dyn FnMut() + Send),
    },
}

/// Sends `items` as one batch; a whole-batch 400/413 splits it in half, recursively, each half
/// carrying the answers its own records reference. Ranges go in order, so everything before the
/// first failure is done.
pub(crate) async fn send_with_split(
    sink: &dyn LogSink,
    items: &[Item<'_>],
    hdr: &HeaderGen,
    mut waiting: Waiting<'_>,
) -> SplitResult {
    let mut res = SplitResult {
        done: 0,
        rejected: vec![],
        failure: None,
    };
    let mut ranges: VecDeque<(usize, usize)> = VecDeque::new();
    if !items.is_empty() {
        ranges.push_back((0, items.len()));
    }
    while let Some((a, b)) = ranges.pop_front() {
        let body = build_body(&items[a..b], hdr);
        let outcome = match &mut waiting {
            Waiting::Until(deadline) => tokio::time::timeout_at(*deadline, sink.post(body))
                .await
                .unwrap_or_else(|_| PostOutcome::Unreachable("no ack within spool_after_s".into())),
            Waiting::Ticking { every, on_tick } => {
                let post = sink.post(body);
                tokio::pin!(post);
                let mut tick = tokio::time::interval_at(Instant::now() + *every, *every);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        o = &mut post => break o,
                        _ = tick.tick() => on_tick(),
                    }
                }
            }
        };
        match outcome {
            PostOutcome::Acked => res.done = b,
            PostOutcome::Rejected if b - a == 1 => {
                res.rejected.push(a);
                res.done = b;
            }
            PostOutcome::Rejected => {
                let mid = a + (b - a) / 2;
                ranges.push_front((mid, b));
                ranges.push_front((a, mid));
            }
            other => {
                res.failure = Some(other);
                break;
            }
        }
    }
    res
}

/// One line of a drain batch.
struct PlannedLine {
    /// Which head it comes from (index into the round's heads).
    head: usize,
    /// Its index in that segment's lines (the drain position).
    idx: usize,
    text: Arc<str>,
    answer: Option<(String, Arc<str>)>,
}

impl PlannedLine {
    fn item(&self) -> Item<'_> {
        Item {
            line: &self.text,
            answer: self
                .answer
                .as_ref()
                .map(|(id, line)| AnswerRef::Line { id, line }),
        }
    }
}

/// One head segment as a drain round sees it.
struct HeadView<'a> {
    key: SegKey,
    more: bool,
    content: &'a SegContent,
    /// Where its records resume.
    start: usize,
    /// Planning reached this index in an earlier round ([`Progress::counted`]).
    counted: usize,
    /// Below `counted`, the records made before this had their age drop counted.
    counted_cutoff: Option<Timestamp>,
}

/// A drain round's batches.
struct Plan {
    batches: Vec<Vec<PlannedLine>>,
    /// Per head: the index planning stopped at (its next unplanned record, or the end).
    ends: Vec<usize>,
    /// Records past the retention window, not counted before.
    too_old: u64,
}

/// The later of two cutoffs (`None`: no age decision).
fn later(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, y) => x.or(y),
    }
}

/// Whether a line was made before `cutoff` (a line without a timestamp never is).
fn made_before_cutoff(l: &Line, cutoff: Option<Timestamp>) -> bool {
    matches!((cutoff, l.ts), (Some(c), Some(ts)) if ts < c)
}

/// Whether record `a` (in segment `ka`) was made before record `b` (in segment `kb`): by `seq`
/// within one run (`boot`), else by segment number, which follows run order.
fn made_before(a: &Line, ka: SegKey, b: &Line, kb: SegKey) -> bool {
    match (&a.boot, &b.boot) {
        (Some(x), Some(y)) if x == y => a.seq.unwrap_or(0) <= b.seq.unwrap_or(0),
        _ => ka.n <= kb.n,
    }
}

/// Merges the heads' records from their resume points, in the order they were made, into
/// batches of at most `max` lines (answers counted), dropping records older than `cutoff` (when
/// the clock is synchronised). Planning stops once a head whose class has a later segment runs
/// out. An answer travels only with the records that reference it, from their own segment.
///
/// Age drops are counted once per record: below a head's `counted`, a record made before its
/// `counted_cutoff` was counted in an earlier round (and stays dropped), while one planned for
/// delivery then and aged out since (a failed POST left it unshipped) is counted now. Records
/// below `counted` that this round doesn't reach are checked too, so afterwards every record
/// below the new `counted` made before the new cutoff has been counted, and none other.
///
/// A head's cutoff never moves back: once checked against `counted_cutoff`, its records made
/// before it are dropped (and counted) wherever they are, even if the clock steps back or the
/// retention grows. A record the head's later part holds can't then be planned under an earlier
/// cutoff and taken for counted below the new `counted` (one cutoff describes the whole range).
fn plan_merge(heads: &[HeadView<'_>], cutoff: Option<Timestamp>, max: usize) -> Plan {
    let answers: Vec<HashMap<&str, &Arc<str>>> = heads
        .iter()
        .map(|h| {
            h.content
                .lines
                .iter()
                .filter_map(|l| match &l.kind {
                    LineKind::Answer(id) => Some((id.as_str(), &l.text)),
                    _ => None,
                })
                .collect()
        })
        .collect();
    let mut pos: Vec<usize> = heads.iter().map(|h| h.start).collect();
    let mut batches: Vec<Vec<PlannedLine>> = vec![];
    let mut cur: Vec<PlannedLine> = vec![];
    let mut cur_lines = 0usize;
    let mut cur_answers: HashSet<String> = HashSet::new();
    let mut too_old = 0u64;
    // Each head's cutoff: never earlier than the one it was checked against.
    let cutoffs: Vec<Option<Timestamp>> = heads.iter().map(|h| later(h.counted_cutoff, cutoff)).collect();
    loop {
        // Move each head to its next record still in the window.
        for (hi, h) in heads.iter().enumerate() {
            let lines = &h.content.lines;
            while let Some(l) = lines.get(pos[hi]) {
                let counted = pos[hi] < h.counted && made_before_cutoff(l, h.counted_cutoff);
                match &l.kind {
                    LineKind::Record { .. } if !counted && !made_before_cutoff(l, cutoffs[hi]) => {
                        break;
                    }
                    LineKind::Record { .. } => {
                        if !counted {
                            too_old += 1;
                        }
                    }
                    LineKind::Answer(_) => {}
                }
                pos[hi] += 1;
            }
        }
        if heads
            .iter()
            .enumerate()
            .any(|(hi, h)| h.more && pos[hi] >= h.content.lines.len())
        {
            break;
        }
        let mut pick: Option<usize> = None;
        for (hi, h) in heads.iter().enumerate() {
            let Some(l) = h.content.lines.get(pos[hi]) else {
                continue;
            };
            pick = match pick {
                Some(p) if made_before(&heads[p].content.lines[pos[p]], heads[p].key, l, h.key) => Some(p),
                _ => Some(hi),
            };
        }
        let Some(hi) = pick else { break };
        let idx = pos[hi];
        let l = &heads[hi].content.lines[idx];
        pos[hi] += 1;
        let LineKind::Record { answer_id } = &l.kind else {
            continue;
        };
        let answer = answer_id
            .as_deref()
            .and_then(|id| answers[hi].get(id).map(|t| (id.to_owned(), Arc::clone(t))));
        let need = 1 + usize::from(answer.as_ref().is_some_and(|(id, _)| !cur_answers.contains(id)));
        if !cur.is_empty() && cur_lines + need > max {
            batches.push(std::mem::take(&mut cur));
            cur_lines = 0;
            cur_answers.clear();
        }
        let need = 1 + usize::from(answer.as_ref().is_some_and(|(id, _)| !cur_answers.contains(id)));
        if let Some((id, _)) = &answer {
            cur_answers.insert(id.clone());
        }
        cur_lines += need;
        cur.push(PlannedLine {
            head: hi,
            idx,
            text: Arc::clone(&l.text),
            answer,
        });
    }
    if !cur.is_empty() {
        batches.push(cur);
    }
    // Records an earlier round planned past where this one stopped: those aged out since.
    for (hi, h) in heads.iter().enumerate() {
        too_old += h
            .content
            .lines
            .iter()
            .take(h.counted)
            .skip(pos[hi])
            .filter(|l| {
                matches!(l.kind, LineKind::Record { .. })
                    && !made_before_cutoff(l, h.counted_cutoff)
                    && made_before_cutoff(l, cutoffs[hi])
            })
            .count() as u64;
    }
    Plan {
        batches,
        ends: pos,
        too_old,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::spool::tests::FakeEnv;
    use crate::logs::{LogProducer, event_record, fields};
    use std::io::Read;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    /// A sink that records batches and answers from a script.
    #[derive(Default)]
    pub(crate) struct ScriptSink {
        pub script: Mutex<VecDeque<PostOutcome>>,
        pub default: Mutex<Option<PostOutcome>>,
        pub batches: Mutex<Vec<Vec<String>>>,
        /// Reject any batch with more than this many lines (simulates 413).
        pub max_lines: Mutex<Option<usize>>,
        /// Reject any batch containing a line with this text.
        pub poison: Mutex<Option<String>>,
        /// How long core takes to answer each POST.
        pub delay: Mutex<Option<Duration>>,
        /// Runs while each POST waits for its answer.
        #[allow(clippy::type_complexity, reason = "a test hook")]
        pub during: Mutex<Option<Box<dyn FnMut() + Send>>>,
    }

    pub(crate) fn decode(body: &Bytes) -> Vec<String> {
        let mut s = String::new();
        flate2::read::GzDecoder::new(&body[..])
            .read_to_string(&mut s)
            .unwrap();
        s.lines().map(str::to_owned).collect()
    }

    #[async_trait::async_trait]
    impl LogSink for ScriptSink {
        async fn post(&self, body: Bytes) -> PostOutcome {
            let lines = decode(&body);
            if let Some(f) = self.during.lock().unwrap().as_mut() {
                f();
            }
            let delay = *self.delay.lock().unwrap();
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            if let Some(o) = self.script.lock().unwrap().pop_front() {
                if o == PostOutcome::Acked {
                    self.batches.lock().unwrap().push(lines);
                }
                return o;
            }
            if let Some(max) = *self.max_lines.lock().unwrap()
                && lines.len() > max
            {
                return PostOutcome::Rejected;
            }
            if let Some(p) = self.poison.lock().unwrap().as_ref()
                && lines.iter().any(|l| l.contains(p.as_str()))
            {
                return PostOutcome::Rejected;
            }
            let o = self.default.lock().unwrap().clone().unwrap_or(PostOutcome::Acked);
            if o == PostOutcome::Acked {
                self.batches.lock().unwrap().push(lines);
            }
            o
        }
    }

    /// A sink whose posts wait until the gate opens, then ack and record their lines.
    pub(crate) struct GateSink {
        open: watch::Sender<bool>,
        pub batches: Mutex<Vec<Vec<String>>>,
        pub posts: std::sync::atomic::AtomicUsize,
        /// What each post comes to once the gate opens.
        pub then: Mutex<PostOutcome>,
    }

    impl GateSink {
        fn closed() -> Arc<Self> {
            Arc::new(Self {
                open: watch::channel(false).0,
                batches: Mutex::default(),
                posts: Default::default(),
                then: Mutex::new(PostOutcome::Acked),
            })
        }
        fn open(&self) {
            self.open.send_replace(true);
        }
        fn lines(&self) -> Vec<String> {
            self.batches.lock().unwrap().iter().flatten().cloned().collect()
        }
    }

    #[async_trait::async_trait]
    impl LogSink for GateSink {
        async fn post(&self, body: Bytes) -> PostOutcome {
            self.posts.fetch_add(1, Ordering::Relaxed);
            let mut rx = self.open.subscribe();
            let _ = rx.wait_for(|o| *o).await;
            let o = self.then.lock().unwrap().clone();
            if o == PostOutcome::Acked {
                self.batches.lock().unwrap().push(decode(&body));
            }
            o
        }
    }

    /// `kind` of an event line, else its `t` (answers left out).
    fn names(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .filter_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                match v["t"].as_str().unwrap() {
                    "answer" => None,
                    "event" => Some(v["kind"].as_str().unwrap().to_owned()),
                    t => Some(t.to_owned()),
                }
            })
            .collect()
    }

    fn shipper(
        d: &std::path::Path,
        sink: Arc<ScriptSink>,
    ) -> (
        Shipper,
        LogProducer,
        Arc<FakeEnv>,
        Arc<DropCounters>,
        Arc<LogControl>,
    ) {
        shipper_with(d, sink)
    }

    fn shipper_with(
        d: &std::path::Path,
        sink: Arc<dyn LogSink>,
    ) -> (
        Shipper,
        LogProducer,
        Arc<FakeEnv>,
        Arc<DropCounters>,
        Arc<LogControl>,
    ) {
        let env = Arc::new(FakeEnv::new(d));
        let dropped = Arc::new(DropCounters::default());
        let (p, rx) = LogProducer::new("b00t".into(), Arc::clone(&dropped));
        let control = Arc::new(LogControl::default());
        let s = Shipper::new(
            rx,
            env.clone(),
            sink,
            Arc::clone(&control),
            Arc::clone(&dropped),
            Timings {
                tick: Duration::from_millis(10),
                retry_min: Duration::ZERO,
                retry_max: Duration::ZERO,
                expire_every: Duration::ZERO,
            },
        );
        (s, p, env, dropped, control)
    }

    fn q_with(p: &LogProducer, a: &Arc<Answer>, n: usize) {
        for _ in 0..n {
            assert!(p.emit_query(
                crate::logs::tests::q(picket_api::logs::Decision::Allow),
                crate::logs::AnswerSlot::Attached(Arc::clone(a))
            ));
        }
    }

    fn kinds(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["t"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    #[tokio::test]
    async fn batches_carry_answers_once_ahead_and_count_them() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        let (mut s, p, _env, _dropped, control) = shipper(d.path(), sink.clone());
        control.set_config(LoggingConfig {
            batch_max: 5,
            ..Default::default()
        });
        let a1 = Answer::new(Bytes::from_static(b"one")).unwrap();
        let a2 = Answer::new(Bytes::from_static(b"two")).unwrap();
        q_with(&p, &a1, 3);
        q_with(&p, &a2, 3);
        s.collect();
        s.step().await;
        let batches = sink.batches.lock().unwrap().clone();
        assert!(batches.iter().all(|b| b.len() <= 5), "{batches:?}");
        for b in &batches {
            // every referenced answer present once, before the first referencing record
            let mut seen = HashSet::new();
            for l in b {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                match v["t"].as_str().unwrap() {
                    "answer" => assert!(seen.insert(v["id"].as_str().unwrap().to_owned())),
                    "q" => assert!(seen.contains(v["answer_id"].as_str().unwrap())),
                    _ => {}
                }
            }
        }
        let records: usize = batches
            .iter()
            .map(|b| kinds(b).iter().filter(|k| *k == "q").count())
            .sum();
        assert_eq!(records, 6);
        assert!(s.buffer.is_empty());
    }

    #[tokio::test]
    async fn rejected_batches_split_and_a_lone_reject_is_dropped() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.max_lines.lock().unwrap() = Some(3);
        *sink.poison.lock().unwrap() = Some("\"kind\":\"poison\"".into());
        let (mut s, p, _env, dropped, _control) = shipper(d.path(), sink.clone());
        let a = Answer::new(Bytes::from_static(b"shared")).unwrap();
        q_with(&p, &a, 4);
        let receipt = p.emit_with_receipt(event_record("poison", fields(&[])));
        q_with(&p, &a, 3);
        s.collect();
        s.step().await;
        assert_eq!(receipt.await.unwrap(), Delivery::Dropped(DropReason::Rejected));
        assert_eq!(dropped.snapshot()["rejected"], 1);
        let batches = sink.batches.lock().unwrap().clone();
        let q_count: usize = batches
            .iter()
            .map(|b| kinds(b).iter().filter(|k| *k == "q").count())
            .sum();
        assert_eq!(q_count, 7);
        for b in &batches {
            assert!(b.len() <= 3);
            let k = kinds(b);
            if k.contains(&"q".to_owned()) {
                assert_eq!(k[0], "answer", "each half resent with its answers: {k:?}");
            }
        }
        assert!(s.buffer.is_empty());
    }

    #[tokio::test]
    async fn retries_then_spools_after_spool_after_s_and_drains_in_order() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        // Core answers 503, and takes its time doing so.
        *sink.default.lock().unwrap() = Some(PostOutcome::Retry("503".into()));
        *sink.delay.lock().unwrap() = Some(Duration::from_millis(400));
        let (mut s, p, env, _dropped, control) = shipper(d.path(), sink.clone());
        control.set_config(LoggingConfig {
            spool_after_s: 1,
            ..Default::default()
        });
        let mut r1 = p.emit_with_receipt(event_record("e1", fields(&[])));
        s.collect();
        let start = Instant::now();
        s.step().await; // fails after 0.4 s: retried from memory
        assert_eq!(s.mode, Mode::Memory, "within spool_after_s: no spool");
        assert!(r1.try_recv().is_err(), "still buffered");
        while s.mode == Mode::Memory {
            assert!(start.elapsed() < Duration::from_secs(5));
            s.step().await;
        }
        assert!(start.elapsed() >= Duration::from_secs(1), "{:?}", start.elapsed());
        assert_eq!(
            r1.await.unwrap(),
            Delivery::Spooled,
            "receipt only after the fsynced append"
        );
        assert_eq!(s.mode, Mode::Spool);
        assert!(!s.spool.is_empty());
        assert!(env.data.join("security").is_dir());
        // New records append behind the spool while core is down.
        let r2 = p.emit_with_receipt(event_record("e2", fields(&[])));
        s.collect();
        s.step().await;
        assert_eq!(r2.await.unwrap(), Delivery::Spooled);
        // Core comes back: the spool drains oldest first, then shipping returns to memory.
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.step().await;
        assert!(s.spool.is_empty());
        assert_eq!(s.mode, Mode::Memory);
        let all: Vec<String> = sink.batches.lock().unwrap().iter().flatten().cloned().collect();
        let kinds: Vec<String> = all
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["kind"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned()
            })
            .collect();
        assert_eq!(kinds, vec!["e1", "e2"]);
        // A slow ack within spool_after_s ships from memory.
        let r3 = p.emit_with_receipt(event_record("e3", fields(&[])));
        s.collect();
        s.step().await;
        assert_eq!(r3.await.unwrap(), Delivery::Acked);
    }

    #[tokio::test]
    async fn spool_after_s_zero_never_spools_what_a_healthy_core_acks() {
        // edge.md §11, hard rule 8: core accepts spool_after_s 1–3600. A 0 that reaches the edge
        // anyway must not abandon every POST at its first poll (each batch fsynced to the spool
        // and posted twice).
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.delay.lock().unwrap() = Some(Duration::from_millis(5));
        let (mut s, p, _env, _dropped, control) = shipper(d.path(), sink.clone());
        control.set_config(LoggingConfig {
            spool_after_s: 0,
            ..Default::default()
        });
        for i in 0..3 {
            let r = p.emit_with_receipt(event_record(&format!("e{i}"), fields(&[])));
            s.collect();
            s.step().await;
            assert_eq!(r.await.unwrap(), Delivery::Acked);
        }
        assert_eq!(s.mode, Mode::Memory);
        assert!(s.spool.is_empty());
        assert_eq!(sink.batches.lock().unwrap().len(), 3, "each batch posted once");
        assert!(
            super::super::logging_problem(&LoggingConfig {
                spool_after_s: 0,
                ..Default::default()
            })
            .is_some()
        );
    }

    #[tokio::test]
    async fn unreachable_core_spools_at_once_and_transient_read_errors_keep_segments() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("connect refused".into()));
        let (mut s, p, _env, _dropped, _control) = shipper(d.path(), sink.clone());
        assert!(p.event("e1", fields(&[])));
        s.collect();
        s.step().await;
        assert_eq!(s.mode, Mode::Spool);
        let (key, path) = s.spool.oldest().unwrap();
        // Make the segment unreadable with an OS error: replace it with a directory.
        let saved = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.step().await;
        assert!(
            s.spool.keys().contains(&key),
            "a transient read error never deletes a segment"
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, saved).unwrap();
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        assert_eq!(sink.batches.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failed_drains_keep_one_open_segment_and_partial_progress_seals_it() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, _env, _dropped, control) = shipper(d.path(), sink.clone());
        control.set_config(LoggingConfig {
            batch_max: 1,
            ..Default::default()
        });
        for i in 0..3 {
            assert!(p.event("e", fields(&[("n", i.into())])));
            s.collect();
            s.step().await;
        }
        assert_eq!(
            s.spool.segment_count(),
            1,
            "failed drain attempts don't seal the open segment"
        );
        // Core takes the first batch, then fails: the segment is sealed, so the batches already
        // handled stay the same when new records arrive.
        sink.script
            .lock()
            .unwrap()
            .extend([PostOutcome::Acked, PostOutcome::Retry("503".into())]);
        s.step().await;
        assert!(p.event("e", fields(&[("n", 3.into())])));
        s.collect();
        s.step().await;
        assert_eq!(s.spool.segment_count(), 2, "new records went to a new segment");
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        let ns: Vec<i64> = sink
            .batches
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["n"]
                    .as_i64()
                    .unwrap()
            })
            .collect();
        assert_eq!(ns, vec![0, 1, 2, 3], "every record once, in order");
    }

    #[tokio::test]
    async fn shutdown_flushes_the_buffer_to_the_spool_and_a_restart_drains_it() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Retry("down".into()));
        let (s, p, _env, _dropped, _control) = shipper(d.path(), sink.clone());
        let (tx, rx) = watch::channel(false);
        let a = Answer::new(Bytes::from_static(b"ans")).unwrap();
        q_with(&p, &a, 2);
        let r = p.emit_with_receipt(event_record("last", fields(&[])));
        tx.send(true).unwrap();
        s.run(rx).await;
        assert_eq!(r.await.unwrap(), Delivery::Spooled);
        // The next process starts in spool mode and drains it.
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        let (mut s2, _p2, _env2, _d2, _c2) = shipper(d.path(), sink.clone());
        assert_eq!(s2.mode, Mode::Spool);
        s2.step().await;
        assert!(s2.spool.is_empty());
        let lines: Vec<String> = sink.batches.lock().unwrap().iter().flatten().cloned().collect();
        assert_eq!(kinds(&lines).iter().filter(|k| *k == "q").count(), 2);
        assert_eq!(kinds(&lines).iter().filter(|k| *k == "answer").count(), 1);
    }

    #[tokio::test]
    async fn a_reconnect_drains_the_spool_without_waiting_out_the_backoff() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let env = Arc::new(FakeEnv::new(d.path()));
        let dropped = Arc::new(DropCounters::default());
        let (p, rx) = LogProducer::new("b00t".into(), Arc::clone(&dropped));
        let control = Arc::new(LogControl::default());
        let mut s = Shipper::new(
            rx,
            env,
            sink.clone(),
            Arc::clone(&control),
            dropped,
            Timings {
                tick: Duration::from_millis(10),
                retry_min: Duration::from_secs(600),
                retry_max: Duration::from_secs(600),
                expire_every: Duration::ZERO,
            },
        );
        assert!(p.event("e", fields(&[])));
        s.collect();
        s.step().await;
        assert_eq!(s.mode, Mode::Spool);
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.step().await;
        assert!(!s.spool.is_empty(), "still backing off");
        control.core_reachable();
        s.step().await;
        assert!(s.spool.is_empty(), "drained as soon as the session is back");
    }

    #[tokio::test]
    async fn segments_on_an_ssd_that_passes_after_start_drain_first() {
        let d = tempfile::tempdir().unwrap();
        let ssd = d.path().join("ssd/spool");
        let space = spool::SsdSpace {
            avail: 100 << 30,
            floor: 1 << 30,
        };
        // An earlier run spooled to the SSD.
        {
            let env = FakeEnv::new(d.path());
            *env.ssd.lock().unwrap() = Some(ssd.clone());
            *env.space.lock().unwrap() = Some(space);
            let mut sp = Spool::open(&env, Arc::default());
            let e = spool::tests::entry(1, Class::Security, Timestamp::now(), None, 0);
            let limits = Limits {
                data_max: 256 << 20,
                ssd_max: None,
                retention: jiff::SignedDuration::from_hours(72),
            };
            sp.append(Class::Security, &[&e], &env, &limits, &HeaderGen::for_tests())
                .unwrap();
        }
        // This run starts before the SSD passes its checks (UniFi mounts it after boot).
        let sink = Arc::new(ScriptSink::default());
        let (mut s, p, env, _dropped, _control) = shipper(d.path(), sink.clone());
        assert_eq!(s.mode, Mode::Memory);
        *env.ssd.lock().unwrap() = Some(ssd);
        *env.space.lock().unwrap() = Some(space);
        assert!(p.event("new", fields(&[])));
        s.collect();
        s.step().await;
        assert!(
            s.spool.is_empty(),
            "the SSD's segments drained from where they are"
        );
        let kinds: Vec<String> = sink
            .batches
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["kind"].as_str().unwrap_or(v["t"].as_str().unwrap()).to_owned()
            })
            .collect();
        assert_eq!(kinds, vec!["q", "new"], "the old records first, in order");
    }

    #[tokio::test]
    async fn a_partial_drain_resumes_at_the_first_unshipped_record_when_the_cutoff_moves() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, _env, _dropped, control) = shipper(d.path(), sink.clone());
        control.set_config(LoggingConfig {
            batch_max: 2,
            ..Default::default()
        });
        let older = Timestamp::now() - jiff::SignedDuration::from_hours(2);
        for i in 0..6 {
            let rec = event_record("e", fields(&[("n", i.into())]));
            if i < 2 {
                drop(p.emit_at_with_receipt(rec, older));
            } else {
                assert!(p.emit(rec));
            }
        }
        s.collect();
        s.step().await;
        assert_eq!(s.mode, Mode::Spool);
        // Core takes the first batch (records 0 and 1), then fails.
        sink.script
            .lock()
            .unwrap()
            .extend([PostOutcome::Acked, PostOutcome::Retry("503".into())]);
        s.step().await;
        // Meanwhile records 0 and 1 fall out of the retention window: the next attempt must
        // still start at record 2, not at "batch 1" of a re-planned segment.
        control.set_config(LoggingConfig {
            batch_max: 2,
            retention_h: 1,
            ..Default::default()
        });
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        let ns: Vec<i64> = sink
            .batches
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["n"]
                    .as_i64()
                    .unwrap()
            })
            .collect();
        assert_eq!(ns, vec![0, 1, 2, 3, 4, 5], "no record skipped");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_post_core_never_answers_spools_after_spool_after_s() {
        // edge.md §11: a batch not acked within spool_after_s sends the buffer to the spool, even
        // while its POST is still waiting for an answer (core accepts connections, never replies).
        let d = tempfile::tempdir().unwrap();
        let gate = GateSink::closed();
        let (s, p, _env, dropped, control) = shipper_with(d.path(), gate.clone());
        control.set_config(LoggingConfig {
            spool_after_s: 1,
            ..Default::default()
        });
        let (tx, rx) = watch::channel(false);
        let h = tokio::spawn(s.run(rx));
        let r1 = p.emit_with_receipt(event_record("e1", fields(&[])));
        let got = tokio::time::timeout(Duration::from_secs(5), r1).await;
        assert_eq!(
            got.expect("spooled while the POST hangs").unwrap(),
            Delivery::Spooled
        );
        let r2 = p.emit_with_receipt(event_record("e2", fields(&[])));
        let got = tokio::time::timeout(Duration::from_secs(5), r2).await;
        assert_eq!(got.expect("later records spool too").unwrap(), Delivery::Spooled);
        assert_eq!(dropped.snapshot()["buffer_full"], 0);
        // Core answers again: everything arrives once, in order.
        gate.open();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while names(&gate.lines()).iter().filter(|n| n.starts_with('e')).count() < 2
            && tokio::time::Instant::now() < deadline
        {
            control.core_reachable();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tx.send(true).unwrap();
        h.await.unwrap();
        let got = names(&gate.lines());
        assert_eq!(got.first().map(String::as_str), Some("e1"));
        assert!(got.ends_with(&["e2".to_owned()]), "{got:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn records_arriving_while_a_drain_post_hangs_are_spooled_and_arrive_once_in_order() {
        // edge.md §11: while the spool drains, new records append there; a drain POST that waits
        // for an answer must not hold them in the memory buffer until it fills.
        let d = tempfile::tempdir().unwrap();
        {
            let env = FakeEnv::new(d.path());
            let mut sp = Spool::open(&env, Arc::default());
            let e = spool::tests::entry(1, Class::Security, Timestamp::now(), None, 0);
            let limits = Limits {
                data_max: 256 << 20,
                ssd_max: None,
                retention: jiff::SignedDuration::from_hours(72),
            };
            sp.append(Class::Security, &[&e], &env, &limits, &HeaderGen::for_tests())
                .unwrap();
        }
        let gate = GateSink::closed();
        let (s, p, _env, dropped, _control) = shipper_with(d.path(), gate.clone());
        assert_eq!(s.mode, Mode::Spool);
        let (tx, rx) = watch::channel(false);
        let h = tokio::spawn(s.run(rx));
        // The drain's POST is now waiting on core.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while gate.posts.load(Ordering::Relaxed) == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for i in 1..=3 {
            let r = p.emit_with_receipt(event_record(&format!("e{i}"), fields(&[])));
            let got = tokio::time::timeout(Duration::from_secs(5), r).await;
            assert_eq!(
                got.expect("spooled while the drain POST hangs").unwrap(),
                Delivery::Spooled
            );
        }
        gate.open();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while names(&gate.lines()).len() < 4 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tx.send(true).unwrap();
        h.await.unwrap();
        assert_eq!(names(&gate.lines()), vec!["q", "e1", "e2", "e3"]);
        assert_eq!(dropped.snapshot()["buffer_full"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn evicting_the_segment_a_drain_post_ships_counts_only_what_core_never_took() {
        // api.md §3 logs.dropped.evicted, edge.md §11: records arriving while a drain POST waits
        // are spooled, and making room for them can evict the very segment being shipped. Its
        // records are in that POST: they count as evicted only if it fails.
        for then in [PostOutcome::Acked, PostOutcome::Unreachable("down".into())] {
            let d = tempfile::tempdir().unwrap();
            let held = 250u64;
            {
                // ~1 MiB of random hex allowed queries (~0.5 MiB compressed), in one bulk segment.
                let env = FakeEnv::new(d.path());
                let mut sp = Spool::open(&env, Arc::default());
                let now = Timestamp::now();
                let es: Vec<Entry> = (0..held)
                    .map(|i| spool::tests::entry(i + 1, Class::Bulk, now, None, 4096))
                    .collect();
                let refs: Vec<&Entry> = es.iter().collect();
                let limits = Limits {
                    data_max: 256 << 20,
                    ssd_max: None,
                    retention: jiff::SignedDuration::from_hours(72),
                };
                sp.append(Class::Bulk, &refs, &env, &limits, &HeaderGen::for_tests())
                    .unwrap();
                assert_eq!(sp.segment_count(), 1);
            }
            let gate = GateSink::closed();
            *gate.then.lock().unwrap() = then.clone();
            let (s, p, _env, dropped, control) = shipper_with(d.path(), gate.clone());
            control.set_config(LoggingConfig {
                spool_max_mib: 1,
                ..Default::default()
            });
            let (tx, rx) = watch::channel(false);
            let h = tokio::spawn(s.run(rx));
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while gate.posts.load(Ordering::Relaxed) == 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // ~0.9 MiB (compressed) of security records: over the 1 MiB cap with the segment
            // being shipped.
            for i in 0..8 {
                let pad: String = (0..200 << 10)
                    .map(|_| char::from(b"0123456789abcdef"[rand::random::<u8>() as usize % 16]))
                    .collect();
                let r = p.emit_with_receipt(event_record(&format!("e{i}"), fields(&[("pad", pad.into())])));
                let got = tokio::time::timeout(Duration::from_secs(5), r).await;
                assert_eq!(got.expect("spooled").unwrap(), Delivery::Spooled);
            }
            assert!(
                std::fs::read_dir(d.path().join("data/spool/bulk"))
                    .unwrap()
                    .next()
                    .is_none(),
                "the segment being shipped was evicted"
            );
            assert_eq!(
                dropped.snapshot()["evicted"],
                0,
                "nothing counted while the POST is in flight"
            );
            gate.open();
            let want = match then {
                PostOutcome::Acked => 0,
                _ => held,
            };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while dropped.snapshot()["evicted"] != want && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if then == PostOutcome::Acked {
                while names(&gate.lines()).len() < held as usize + 8 && tokio::time::Instant::now() < deadline
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let got = names(&gate.lines());
                assert_eq!(got.iter().filter(|n| *n == "q").count(), held as usize);
                assert_eq!(got.len(), held as usize + 8, "every record once");
            }
            tx.send(true).unwrap();
            h.await.unwrap();
            assert_eq!(dropped.snapshot()["evicted"], want, "{then:?}");
        }
    }

    #[tokio::test]
    async fn spooled_records_drain_in_record_order_across_classes() {
        // edge.md §11: the spool keeps order and drains oldest first, across both classes.
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, _env, _dropped, _control) = shipper(d.path(), sink.clone());
        let allowed = || crate::logs::tests::q(picket_api::logs::Decision::Allow);
        for i in 1..=2 {
            assert!(p.emit_query(allowed(), crate::logs::AnswerSlot::None));
            assert!(p.event(&format!("e{i}"), fields(&[])));
            s.collect();
            s.step().await;
            assert_eq!(s.mode, Mode::Spool);
        }
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        let lines: Vec<String> = sink.batches.lock().unwrap().iter().flatten().cloned().collect();
        assert_eq!(names(&lines), vec!["q", "e1", "q", "e2"]);
    }

    #[tokio::test]
    async fn segments_written_before_the_ssd_passes_drain_after_its_older_backlog() {
        // edge-unifi.md §1, edge.md §11: after a restart the drive is mounted late; segments this
        // run wrote to data_dir meanwhile are newer than the earlier run's backlog on the SSD.
        let d = tempfile::tempdir().unwrap();
        let ssd = d.path().join("ssd/spool");
        let space = spool::SsdSpace {
            avail: 100 << 30,
            floor: 1 << 30,
        };
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        {
            let (mut s, p, env, _d, _c) = shipper(d.path(), sink.clone());
            *env.ssd.lock().unwrap() = Some(ssd.clone());
            *env.space.lock().unwrap() = Some(space);
            assert!(p.event("old1", fields(&[])));
            assert!(p.event("old2", fields(&[])));
            s.collect();
            s.step().await;
            assert!(s.spool.keys().iter().all(|k| k.loc == spool::Loc::Ssd));
        }
        // The next run starts before UniFi mounts the drive: its spool isn't even visible.
        std::fs::rename(d.path().join("ssd"), d.path().join("away")).unwrap();
        let (mut s, p, env, _d, _c) = shipper(d.path(), sink.clone());
        assert!(p.event("new", fields(&[])));
        s.collect();
        s.step().await;
        assert!(s.spool.keys().iter().all(|k| k.loc == spool::Loc::DataDir));
        // The drive is mounted and passes; core is back.
        std::fs::rename(d.path().join("away"), d.path().join("ssd")).unwrap();
        *env.ssd.lock().unwrap() = Some(ssd);
        *env.space.lock().unwrap() = Some(space);
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        let lines: Vec<String> = sink.batches.lock().unwrap().iter().flatten().cloned().collect();
        assert_eq!(names(&lines), vec!["old1", "old2", "new"]);
    }

    #[tokio::test]
    async fn records_spooled_while_writing_moves_between_locations_drain_in_order() {
        // edge.md §11 (keeping order, oldest first), edge-unifi.md §1: with core down, record 1
        // goes to data_dir, record 2 to the SSD once it passes, record 3 to data_dir again after
        // the SSD fails. Record 3 must not join record 1's segment, which would deliver it
        // before record 2.
        let d = tempfile::tempdir().unwrap();
        let ssd = d.path().join("ssd/spool");
        let space = spool::SsdSpace {
            avail: 100 << 30,
            floor: 1 << 30,
        };
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, env, _d, _c) = shipper(d.path(), sink.clone());
        for (name, ssd_passes) in [("r1", false), ("r2", true), ("r3", false)] {
            *env.ssd.lock().unwrap() = ssd_passes.then(|| ssd.clone());
            *env.space.lock().unwrap() = ssd_passes.then_some(space);
            let r = p.emit_with_receipt(event_record(name, fields(&[])));
            s.collect();
            s.step().await;
            assert_eq!(r.await.unwrap(), Delivery::Spooled);
            let loc = if ssd_passes {
                spool::Loc::Ssd
            } else {
                spool::Loc::DataDir
            };
            assert!(
                s.spool.keys().iter().any(|k| k.loc == loc),
                "{name} went to {loc:?}"
            );
        }
        // The SSD passes again and core is back.
        *env.ssd.lock().unwrap() = Some(ssd);
        *env.space.lock().unwrap() = Some(space);
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        let lines: Vec<String> = sink.batches.lock().unwrap().iter().flatten().cloned().collect();
        assert_eq!(names(&lines), vec!["r1", "r2", "r3"]);
    }

    #[tokio::test]
    async fn a_failed_spool_write_keeps_its_records_and_every_one_arrives() {
        // edge.md §11, edge-unifi.md §1 (no spool record is lost): a record whose append failed
        // part-way stays buffered, and nothing spooled after it is hidden behind the damage.
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, _env, _dropped, _control) = shipper(d.path(), sink.clone());
        assert!(p.event("a", fields(&[])));
        s.collect();
        s.step().await;
        assert_eq!(s.mode, Mode::Spool);
        s.spool.write_fault = Some(10);
        let mut rb = p.emit_with_receipt(event_record("b", fields(&[])));
        s.collect();
        s.step().await;
        assert!(rb.try_recv().is_err(), "not spooled yet");
        assert!(p.event("c", fields(&[])));
        s.collect();
        s.step().await;
        assert_eq!(rb.await.unwrap(), Delivery::Spooled);
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        let lines: Vec<String> = sink.batches.lock().unwrap().iter().flatten().cloned().collect();
        assert_eq!(names(&lines), vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn out_of_range_logging_values_never_panic_the_shipper() {
        // README §2 (untrusted input: core's values are range-checked, never crash the receiver).
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        let (mut s, p, _env, dropped, control) = shipper(d.path(), sink.clone());
        control.set_config(LoggingConfig {
            spool_after_s: u32::MAX,
            spool_max_mib: u64::MAX,
            ssd_spool_max_mib: Some(u64::MAX),
            retention_h: u32::MAX,
            batch_max: u32::MAX,
        });
        let r = p.emit_with_receipt(event_record("e", fields(&[])));
        s.collect();
        s.step().await;
        assert_eq!(r.await.unwrap(), Delivery::Acked);
        // retention_h 0 doesn't drop every record at once.
        control.set_config(LoggingConfig {
            retention_h: 0,
            ..Default::default()
        });
        let r = p.emit_with_receipt(event_record("e", fields(&[])));
        s.collect();
        s.step().await;
        assert_eq!(r.await.unwrap(), Delivery::Acked);
        assert_eq!(dropped.snapshot()["too_old"], 0);
    }

    #[tokio::test]
    async fn too_old_records_drop_only_on_a_synced_clock_and_answers_follow_their_records() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        let (mut s, p, env, dropped, _control) = shipper(d.path(), sink.clone());
        env.synced.store(false, Ordering::Relaxed);
        let old = Timestamp::now() - jiff::SignedDuration::from_hours(100);
        let r = p.emit_at_with_receipt(event_record("old", fields(&[])), old);
        s.collect();
        s.step().await;
        assert_eq!(
            r.await.unwrap(),
            Delivery::Acked,
            "unsynchronised clock: no age decisions"
        );
        env.synced.store(true, Ordering::Relaxed);
        let r = p.emit_at_with_receipt(event_record("old", fields(&[])), old);
        s.collect();
        s.step().await;
        assert_eq!(r.await.unwrap(), Delivery::Dropped(DropReason::TooOld));
        assert_eq!(dropped.snapshot()["too_old"], 1);

        // In a segment: the old record goes, its answer stays only with a kept referencing record.
        let a = Answer::new(Bytes::from_static(b"kept")).unwrap();
        let mut lines = vec![];
        let h = |seq| picket_api::logs::RecordHeader {
            ts: Timestamp::now(),
            boot: "b".into(),
            seq,
        };
        lines.push(a.line(h(1)));
        lines.push(format!(
            r#"{{"t":"q","ts":"{}","boot":"b","seq":2,"answer_id":"{}"}}"#,
            picket_api::time::format_micros(&old),
            a.id
        ));
        let content = spool::SegContent {
            lines: lines
                .iter()
                .map(|t| {
                    let v: serde_json::Value = serde_json::from_str(t).unwrap();
                    spool::Line {
                        boot: Some(Arc::from("b")),
                        seq: v["seq"].as_u64(),
                        text: Arc::from(t.as_str()),
                        kind: if v["t"] == "answer" {
                            LineKind::Answer(a.id.clone())
                        } else {
                            LineKind::Record {
                                answer_id: Some(a.id.clone()),
                            }
                        },
                        ts: Some(if v["t"] == "answer" { Timestamp::now() } else { old }),
                    }
                })
                .collect(),
            ..Default::default()
        };
        let view = HeadView {
            key: SegKey {
                n: 1,
                loc: spool::Loc::DataDir,
                class: Class::Bulk,
            },
            more: false,
            content: &content,
            start: 0,
            counted: 0,
            counted_cutoff: None,
        };
        let plan = plan_merge(
            &[view],
            Some(Timestamp::now() - jiff::SignedDuration::from_hours(72)),
            1000,
        );
        assert_eq!(plan.too_old, 1);
        assert!(
            plan.batches.is_empty(),
            "an answer no kept record references isn't sent"
        );
    }

    fn rec_line(seq: u64, ts: Timestamp) -> spool::Line {
        spool::Line {
            text: Arc::from(format!(r#"{{"t":"q","seq":{seq}}}"#).as_str()),
            kind: LineKind::Record { answer_id: None },
            ts: Some(ts),
            boot: Some(Arc::from("b")),
            seq: Some(seq),
        }
    }

    fn key(n: u64, class: Class) -> SegKey {
        SegKey {
            n,
            loc: spool::Loc::DataDir,
            class,
        }
    }

    #[test]
    fn records_planned_fresh_then_aged_out_are_counted_once() {
        // #88: records at 10 and 30, planned at cutoff 0; the POST fails before either is handled.
        let t = |s| Timestamp::from_second(s).unwrap();
        let content = spool::SegContent {
            lines: vec![rec_line(1, t(10)), rec_line(2, t(30))],
            ..Default::default()
        };
        let view = |counted, counted_cutoff| HeadView {
            key: key(1, Class::Bulk),
            more: false,
            content: &content,
            start: 0,
            counted,
            counted_cutoff,
        };
        let first = plan_merge(&[view(0, None)], Some(t(0)), 1000);
        assert_eq!((first.too_old, first.ends.clone()), (0, vec![2]));
        // The retry at cutoff 20: the older record aged out undelivered.
        let retry = plan_merge(&[view(2, Some(t(0)))], Some(t(20)), 1000);
        assert_eq!(retry.too_old, 1, "the expired undelivered record is counted");
        assert_eq!(
            retry.batches.iter().flatten().map(|l| l.idx).collect::<Vec<_>>(),
            vec![1]
        );
        // Another retry at the same cutoff counts nothing again.
        let again = plan_merge(&[view(2, Some(t(20)))], Some(t(20)), 1000);
        assert_eq!(again.too_old, 0, "counted once");
        // A cutoff moving back doesn't let a later record be planned under it and then taken
        // for counted: the head's cutoff stays at 20, so the record at 10 past `counted` is
        // dropped and counted, once.
        let later_part = spool::SegContent {
            lines: vec![rec_line(1, t(30)), rec_line(2, t(10))],
            ..Default::default()
        };
        let head = |counted, counted_cutoff| HeadView {
            key: key(1, Class::Bulk),
            more: false,
            content: &later_part,
            start: 0,
            counted,
            counted_cutoff,
        };
        let back = plan_merge(&[head(1, Some(t(20)))], Some(t(5)), 1000);
        assert_eq!(back.too_old, 1, "dropped and counted, not silently skipped later");
        assert_eq!(
            back.batches.iter().flatten().map(|l| l.idx).collect::<Vec<_>>(),
            vec![0]
        );
        let again = plan_merge(&[head(2, Some(t(20)))], Some(t(5)), 1000);
        assert_eq!(again.too_old, 0, "counted once");
        // A clock stepping back (or losing sync) doesn't bring a counted record back.
        for cutoff in [Some(t(5)), None] {
            let back = plan_merge(&[view(2, Some(t(20)))], cutoff, 1000);
            assert_eq!(back.too_old, 0);
            assert_eq!(
                back.batches.iter().flatten().map(|l| l.idx).collect::<Vec<_>>(),
                vec![1]
            );
        }
    }

    #[test]
    fn records_planned_past_where_a_round_stops_are_counted_when_they_age_out() {
        let t = |s| Timestamp::from_second(s).unwrap();
        // An earlier round planned both of these records (fresh at cutoff 0) before failing.
        let bulk = spool::SegContent {
            lines: vec![rec_line(1, t(30)), rec_line(2, t(10))],
            ..Default::default()
        };
        // This round stops at once: the security head has a later segment and nothing left.
        let security = spool::SegContent::default();
        let views = [
            HeadView {
                key: key(1, Class::Bulk),
                more: false,
                content: &bulk,
                start: 0,
                counted: 2,
                counted_cutoff: Some(t(0)),
            },
            HeadView {
                key: key(2, Class::Security),
                more: true,
                content: &security,
                start: 0,
                counted: 0,
                counted_cutoff: None,
            },
        ];
        let plan = plan_merge(&views, Some(t(20)), 1000);
        assert_eq!(plan.ends, vec![0, 0], "nothing planned");
        assert_eq!(plan.too_old, 1, "the record at 10 aged out below `counted`");
    }

    /// The `n` field of each acked record.
    fn acked_ns(sink: &ScriptSink) -> Vec<i64> {
        sink.batches
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["n"].as_i64())
            .collect()
    }

    fn retention(control: &LogControl, hours: u32, batch_max: u32) {
        control.set_config(LoggingConfig {
            batch_max,
            retention_h: hours,
            ..Default::default()
        });
    }

    #[tokio::test]
    async fn a_record_aging_out_between_failed_posts_counts_too_old_once() {
        // #88: mixed ages in one segment, a failed first POST, the cutoff moving between attempts.
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, _env, dropped, control) = shipper(d.path(), sink.clone());
        let now = Timestamp::now();
        drop(p.emit_at_with_receipt(
            event_record("e", fields(&[("n", 0.into())])),
            now - jiff::SignedDuration::from_hours(5),
        ));
        drop(p.emit_at_with_receipt(event_record("e", fields(&[("n", 1.into())])), now));
        s.collect();
        s.step().await;
        assert_eq!(s.mode, Mode::Spool);
        s.retry_at = None;
        s.step().await;
        assert_eq!(
            dropped.snapshot()["too_old"],
            0,
            "both fresh at the first attempt"
        );
        retention(&control, 2, 1000);
        for _ in 0..3 {
            s.retry_at = None;
            s.step().await;
            assert_eq!(
                dropped.snapshot()["too_old"],
                1,
                "counted once, whatever the retries"
            );
        }
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        assert_eq!(acked_ns(&sink), vec![1], "the newer record is delivered");
        assert_eq!(dropped.snapshot()["too_old"], 1);
        assert_eq!(dropped.snapshot()["evicted"], 0);
    }

    #[tokio::test]
    async fn after_a_partial_success_only_unshipped_records_that_age_out_count_too_old() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, _env, dropped, control) = shipper(d.path(), sink.clone());
        retention(&control, 72, 1);
        let now = Timestamp::now();
        let old = now - jiff::SignedDuration::from_hours(5);
        for (n, ts) in [(0, old), (1, now), (2, old), (3, now)] {
            drop(p.emit_at_with_receipt(event_record("e", fields(&[("n", n.into())])), ts));
        }
        s.collect();
        s.step().await;
        assert_eq!(s.mode, Mode::Spool);
        // Core takes record 0, then fails.
        sink.script
            .lock()
            .unwrap()
            .extend([PostOutcome::Acked, PostOutcome::Retry("503".into())]);
        s.retry_at = None;
        s.step().await;
        retention(&control, 2, 1);
        s.retry_at = None;
        s.step().await;
        assert_eq!(
            dropped.snapshot()["too_old"],
            1,
            "record 2 only: record 0 arrived"
        );
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        assert_eq!(acked_ns(&sink), vec![0, 1, 3]);
        assert_eq!(dropped.snapshot()["too_old"], 1);
    }

    #[tokio::test]
    async fn a_segment_expiring_after_a_counted_age_drop_counts_only_the_rest() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, _env, dropped, control) = shipper(d.path(), sink.clone());
        let now = Timestamp::now();
        // The first record is the newer: no record is handled before the failure.
        drop(p.emit_at_with_receipt(
            event_record("e", fields(&[("n", 0.into())])),
            now - jiff::SignedDuration::from_hours(3),
        ));
        drop(p.emit_at_with_receipt(
            event_record("e", fields(&[("n", 1.into())])),
            now - jiff::SignedDuration::from_hours(5),
        ));
        s.collect();
        s.step().await;
        assert_eq!(s.mode, Mode::Spool);
        s.retry_at = None;
        s.step().await;
        retention(&control, 4, 1000);
        s.retry_at = None;
        s.step().await;
        assert_eq!(dropped.snapshot()["too_old"], 1, "record 1 aged out");
        // The whole segment ages out: only record 0 is left to count.
        retention(&control, 2, 1000);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        assert_eq!(dropped.snapshot()["too_old"], 2, "each record counted once");
        assert!(acked_ns(&sink).is_empty());
    }

    #[tokio::test]
    async fn a_failed_cleanup_leaves_nothing_to_count_of_a_delivered_segment() {
        let d = tempfile::tempdir().unwrap();
        let sink = Arc::new(ScriptSink::default());
        *sink.default.lock().unwrap() = Some(PostOutcome::Unreachable("down".into()));
        let (mut s, p, _env, dropped, control) = shipper(d.path(), sink.clone());
        drop(p.emit_at_with_receipt(
            event_record("e", fields(&[("n", 0.into())])),
            Timestamp::now() - jiff::SignedDuration::from_hours(3),
        ));
        s.collect();
        s.step().await;
        assert_eq!(s.mode, Mode::Spool);
        let (key, path) = s.spool.oldest().unwrap();
        let saved = std::fs::read(&path).unwrap();
        // Core takes the record, but the segment can't be deleted: a directory took its place.
        *sink.default.lock().unwrap() = Some(PostOutcome::Acked);
        let at = path.clone();
        *sink.during.lock().unwrap() = Some(Box::new(move || {
            if at.is_file() {
                std::fs::remove_file(&at).unwrap();
                std::fs::create_dir(&at).unwrap();
                std::fs::write(at.join("x"), b"x").unwrap();
            }
        }));
        s.retry_at = None;
        s.step().await;
        assert_eq!(acked_ns(&sink).len(), 1);
        assert!(s.spool.keys().contains(&key), "the cleanup failed");
        *sink.during.lock().unwrap() = None;
        std::fs::remove_dir_all(&path).unwrap();
        std::fs::write(&path, saved).unwrap();
        // The segment ages out before the retry deletes it: its record arrived, so no drop.
        retention(&control, 2, 1000);
        s.retry_at = None;
        s.step().await;
        assert!(s.spool.is_empty());
        assert_eq!(dropped.snapshot()["too_old"], 0, "{:?}", dropped.snapshot());
        assert_eq!(dropped.snapshot()["evicted"], 0, "{:?}", dropped.snapshot());
        assert_eq!(acked_ns(&sink).len(), 1);
    }
}
