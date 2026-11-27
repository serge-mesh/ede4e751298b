//! Retention (storage.md §4): an hourly heavy-lane job at P3 that ages data out in small steps.
//!
//! The foundation deletes what it can decide alone: config changes, edge events, provider
//! Blocks, DNSSEC results, temporary-allow history, resolved warnings, feed checks and changes
//! (60 days), cross-check admissions, pending edge keys unseen for 30 days, then runs `PRAGMA incremental_vacuum` in small steps
//! (never a full `VACUUM`, core.md §3) and `ANALYZE` once a day.
//!
//! **Clock gate** (README §2 Clocks): every delete compares against a wall-clock cutoff, so the
//! table rules and hooks run only while the clock is synchronised ([`crate::clock`]); a clock
//! ahead of real time would otherwise delete history irreversibly before NTP corrects it. The
//! vacuum and `ANALYZE` need no wall time and always run. `ANALYZE` runs when the last one is a
//! day old (monotonic), so a run that replaces another can't skip it.
//!
//! Later modules add their own data through [`RetentionHook`]s: query-log partitions
//! (`logs::LogRetention`), metrics points (`metrics::MetricsRetention`), closed feed entries,
//! feed runs, raw downloads and deleted feeds' data (`feeds::retention::FeedRetention`), bundle
//! versions and their blobs (`compiler::retention::BundleRetention`), the `bundle_key_hits` of
//! keys no longer in their bundle (`compiler::retention::KeyHitRetention`), published configs
//! and edge boots (`edges::EdgesRetention`), and edge releases no config core may still serve
//! offers (`edges::releases::ReleaseRetention`). Every blob collector takes only blobs nothing
//! names (`blobs::unreferenced`). Verdict-set versions and their blobs
//! (`lookups::verdict_sets::SetRetention`) and lookup verdicts with their tombstones
//! (`lookups::VerdictRetention`) are hooks of the lookups module. Pins don't age: a `have` report
//! ends them (`edges::publish`) and deleting an edge drops them (`config::store`), storage.md §4
//! Pins.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::Timestamp;

use crate::scheduler::{BoxFuture, HeavyJob, Priority, Step};
use crate::state::{AppState, SharedState};

/// Rows deleted per step, so a P0 job can run between steps.
pub const CHUNK: i64 = 5_000;
/// Pages freed per `incremental_vacuum` step.
const VACUUM_PAGES: i64 = 2_000;
/// At most this many vacuum steps per run.
const MAX_VACUUM_STEPS: usize = 50;

/// A retention hook from another module: one bounded step per call.
pub trait RetentionHook: Send + Sync + 'static {
    fn name(&self) -> &str;
    /// Deletes one chunk of expired data; returns `Step::More` while more remains.
    fn step<'a>(&'a self, state: &'a AppState) -> BoxFuture<'a, anyhow::Result<Step>>;
}

/// `ANALYZE` runs at most this often.
pub const ANALYZE_EVERY: Duration = Duration::from_secs(24 * 3600);

/// Registered hooks, and when `ANALYZE` last ran.
#[derive(Clone, Default)]
pub struct Retention {
    hooks: Arc<Mutex<Vec<Arc<dyn RetentionHook>>>>,
    last_analyze: Arc<Mutex<Option<tokio::time::Instant>>>,
}

impl Retention {
    /// True when no `ANALYZE` ran in this process yet, or the last is [`ANALYZE_EVERY`] old.
    fn analyze_due(&self) -> bool {
        self.last_analyze
            .lock()
            .map(|g| g.is_none_or(|t| t.elapsed() >= ANALYZE_EVERY))
            .unwrap_or(true)
    }

    fn analyzed(&self) {
        if let Ok(mut g) = self.last_analyze.lock() {
            *g = Some(tokio::time::Instant::now());
        }
    }

    pub fn register(&self, hook: Arc<dyn RetentionHook>) {
        if let Ok(mut h) = self.hooks.lock() {
            h.push(hook);
        }
    }

    fn hooks(&self) -> Vec<Arc<dyn RetentionHook>> {
        self.hooks.lock().map(|h| h.clone()).unwrap_or_default()
    }
}

/// One table rule: delete rows of `table` whose `column` is older than the window.
struct Rule {
    table: &'static str,
    /// What picks a chunk of rows: `rowid`, or the primary key of a WITHOUT ROWID table as a row
    /// value (`(a, b)`), which has no rowid to chunk by.
    key: &'static str,
    /// SQL condition with `?1` for the cutoff timestamp.
    condition: &'static str,
    window: fn(&crate::settings::Settings) -> Duration,
}

const RULES: &[Rule] = &[
    Rule {
        table: "config_changes",
        key: "rowid",
        condition: "at < ?1",
        window: |s| s.retention.config_changes.as_duration(),
    },
    Rule {
        table: "edge_events",
        key: "rowid",
        condition: "at < ?1",
        window: |s| s.retention.edge_events.as_duration(),
    },
    Rule {
        table: "lookup_blocks",
        key: "rowid",
        condition: "obtained_at < ?1",
        window: |s| s.retention.lookup_blocks.as_duration(),
    },
    Rule {
        table: "dnssec_results",
        key: "rowid",
        condition: "at < ?1",
        window: |s| s.retention.dnssec_results.as_duration(),
    },
    // Temporary-allow history (storage.md §4): an allow is over when the edge's log shows it
    // ended, when the edge acknowledged a revoke list holding it (an allow core never heard of
    // too), or past its reported expiry; the window runs from then. With none of these, its
    // last news counts. An allow still on the revoke list stays whatever its expiry (api.md §4:
    // the extension can extend it while core can't see it).
    Rule {
        table: "temp_allows",
        key: "(edge_id, allow_id)",
        condition: "NOT (revoke_requested_at IS NOT NULL AND revoke_acked_at IS NULL AND ended_at IS NULL)
            AND coalesce(ended_at, revoke_acked_at, expires_at, updated_at, created_at, revoke_requested_at) < ?1",
        window: |s| s.retention.temp_allows.as_duration(),
    },
    // Hours of records clamped from a later hour (core.md §6), kept as long as that hour's
    // partition, which goes once the whole hour is past the query-log window
    // (`logs::LogRetention`): a retry in between still finds its hour.
    Rule {
        table: "log_clamped",
        key: "(edge_id, boot, lo)",
        condition: "hour < ?1",
        window: |s| s.retention.query_logs.as_duration() + Duration::from_secs(3600),
    },
    Rule {
        table: "warnings",
        key: "rowid",
        condition: "status = 'resolved' AND last_seen < ?1",
        window: |s| s.retention.warnings.as_duration(),
    },
    Rule {
        table: "feed_provider_checks",
        key: "rowid",
        condition: "t < ?1",
        window: |s| s.retention.feed_checks.as_duration(),
    },
    Rule {
        table: "feed_checks",
        key: "rowid",
        condition: "t < ?1",
        window: |s| s.retention.feed_checks.as_duration(),
    },
    Rule {
        table: "feed_changes",
        key: "rowid",
        condition: "t_seen < ?1",
        window: |s| s.retention.feed_checks.as_duration(),
    },
    Rule {
        table: "crosscheck_seen",
        key: "(qname, qtype)",
        condition: "at < ?1",
        window: |s| s.crosscheck.dedupe_window.as_duration(),
    },
    // Unknown keys that stopped trying (Edges → Pending stays a list of live attempts).
    Rule {
        table: "edge_pending",
        key: "rowid",
        condition: "last_seen < ?1",
        window: |_| PENDING_MAX_AGE,
    },
];

/// Pending edge keys not seen for this long are forgotten.
pub const PENDING_MAX_AGE: Duration = Duration::from_secs(30 * 86_400);

enum Task {
    Table(usize),
    Hook(Arc<dyn RetentionHook>),
    Vacuum(usize),
    Analyze,
}

/// One retention run, in steps.
pub struct RetentionJob {
    state: SharedState,
    tasks: VecDeque<Task>,
    /// `ANALYZE` even when the last one is recent.
    force_analyze: bool,
}

impl RetentionJob {
    /// A run: the table rules, the hooks, the vacuum, then `ANALYZE` when it is due (a day after
    /// the last) or `force_analyze`.
    pub fn new(state: SharedState, force_analyze: bool) -> Self {
        let mut tasks: VecDeque<Task> = (0..RULES.len()).map(Task::Table).collect();
        for h in state.retention.hooks() {
            tasks.push_back(Task::Hook(h));
        }
        tasks.push_back(Task::Vacuum(0));
        tasks.push_back(Task::Analyze);
        Self {
            state,
            tasks,
            force_analyze,
        }
    }

    /// Drops the deletes of this run (they need a synchronised clock); vacuum and `ANALYZE`
    /// stay.
    fn skip_deletes(&mut self) {
        let before = self.tasks.len();
        self.tasks
            .retain(|t| !matches!(t, Task::Table(_) | Task::Hook(_)));
        tracing::warn!(
            skipped = before - self.tasks.len() + 1,
            "retention deletes wait until the wall clock is synchronised (README §2 Clocks)"
        );
    }
}

impl HeavyJob for RetentionJob {
    fn kind(&self) -> &str {
        "retention"
    }

    fn target(&self) -> &str {
        "core"
    }

    fn step(&mut self) -> BoxFuture<'_, anyhow::Result<Step>> {
        Box::pin(async move {
            let Some(task) = self.tasks.pop_front() else {
                return Ok(Step::Done);
            };
            if matches!(task, Task::Table(_) | Task::Hook(_)) && !self.state.clock.synced() {
                self.skip_deletes();
                return Ok(if self.tasks.is_empty() {
                    Step::Done
                } else {
                    Step::More
                });
            }
            match task {
                Task::Table(i) => {
                    let rule = &RULES[i];
                    let window = (rule.window)(&self.state.settings());
                    let cutoff = crate::util::window_start(Timestamp::now(), window);
                    let cutoff = crate::util::ts(&cutoff);
                    let sql = format!(
                        "DELETE FROM {t} WHERE {k} IN (SELECT {cols} FROM {t} WHERE {c} LIMIT {CHUNK})",
                        t = rule.table,
                        k = rule.key,
                        cols = rule.key.trim_start_matches('(').trim_end_matches(')'),
                        c = rule.condition
                    );
                    let n = self
                        .state
                        .db
                        .write(move |c| Ok::<_, anyhow::Error>(c.execute(&sql, [cutoff])?))
                        .await?;
                    if crate::util::sat_i64(n) >= CHUNK {
                        self.tasks.push_front(Task::Table(i)); // more to delete
                    }
                }
                Task::Hook(h) => match h.step(&self.state).await {
                    Ok(Step::More) => self.tasks.push_front(Task::Hook(h)),
                    Ok(Step::Done) => {}
                    Err(e) => {
                        tracing::warn!(hook = h.name(), error = %format!("{e:#}"), "retention hook failed")
                    }
                },
                Task::Vacuum(n) => {
                    let free: i64 = self
                        .state
                        .db
                        .write(|c| {
                            c.execute_batch(&format!("PRAGMA incremental_vacuum({VACUUM_PAGES});"))?;
                            Ok::<_, anyhow::Error>(c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?)
                        })
                        .await?;
                    if free > 0 && n + 1 < MAX_VACUUM_STEPS {
                        self.tasks.push_front(Task::Vacuum(n + 1));
                    }
                }
                Task::Analyze => {
                    if self.force_analyze || self.state.retention.analyze_due() {
                        self.state
                            .db
                            .write(|c| Ok::<_, anyhow::Error>(c.execute_batch("ANALYZE;")?))
                            .await?;
                        self.state.retention.analyzed();
                    }
                }
            }
            Ok(if self.tasks.is_empty() {
                Step::Done
            } else {
                Step::More
            })
        })
    }
}

/// Schedules the hourly run (first a few minutes after start); each run decides itself whether
/// `ANALYZE` is due, so a run that replaces a queued one never drops it.
pub fn schedule(state: SharedState) -> tokio::task::JoinHandle<()> {
    let st = state.clone();
    state.scheduler.every(
        Duration::from_secs(300),
        Duration::from_secs(3600),
        state.shutdown.clone(),
        move |heavy| {
            heavy.submit(Priority::P3, Box::new(RetentionJob::new(st.clone(), false)));
        },
    )
}
