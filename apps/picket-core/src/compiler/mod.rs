//! The bundle compiler (bundles.md §1–§7, core.md §1 `compiler`): incremental builds from the
//! feeds' entries, full shard builds, deltas, compaction, hot/cold tiering, guardrails and
//! compile-time warnings, versions and their publication to edges.
//!
//! | Module | Job |
//! |---|---|
//! | this one | the runtime: build requests, one build per bundle at a time, start-time re-derivation, triggers (feed runs, definition changes, timers), failures, retirement |
//! | [`spec`] | what a build compiles: members, definition hash, snapshot runs |
//! | [`source`] | reading rules from `feed_entries` at a snapshot, in bundle order |
//! | [`compile`] | rules → key values, patterns, IP runs; bundle-wide rewrite orders and entities |
//! | [`build`] | the build job: collect, expand, key pass |
//! | [`ipfold`] | the IP pass in bounded steps: staged rules, a resumable fold, changed shards' runs |
//! | [`assemble`] | IP shards, patterns, shard plans, bases, deltas, segments, head |
//! | [`commit`] | the one transaction that publishes a version |
//! | [`tier`] | hot/cold placement, ranking, re-rank, promotions |
//! | [`guard`] | guardrail alerts (`broad_block`, `broad_allow`, `bundle_warning`) |
//! | [`warn`] | compile-time warnings from warn and allow bundles (bundles.md §3) |
//! | [`budget`] | per-edge heads within `bundle_budget_mib`, the overlays on each edge (bundles.md §2 Budget, §5) |
//! | [`retention`] | versions and their blobs, kept while pinned, current or in use (storage.md §4) |
//! | [`api`] | the UI API routes for bundles |
//!
//! **Triggers** (bundles.md §2): a member feed's run (the feeds' dirty set, debounced 10 s,
//! [`crate::feeds::dirty`]), a definition change (the configuration watch), the daily compaction
//! and re-rank timers, a build that pushed the hot part past `hot_max_mib`, the UI's "Build now".
//! At start every bundle whose last build recorded an older run for a member feed than that
//! feed's newest run that changed entries, or another definition hash, builds again.
//!
//! **One build per bundle at a time:** requests for a bundle whose build is running are merged
//! and run when it ends ([`RunGuard`]). Builds of different bundles may interleave step by step in
//! the heavy lane; each has its own work rows.
//!
//! **Failures** keep the previous version (nothing is published), raise `bundle_build_failed`
//! (resolved by the next good build), and retry after [`RETRY_AFTER`].

pub mod api;
pub mod assemble;
pub mod budget;
pub mod build;
pub mod commit;
pub mod compile;
pub mod guard;
pub mod ipfold;
pub mod retention;
pub mod source;
pub mod spec;
pub mod store;
pub mod tier;
pub mod warn;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde_json::json;

use crate::alerts::{Changes, RaiseSpec, Severity};
use crate::scheduler::{Priority, Submitted};
use crate::state::{AppState, SharedState};
pub use build::Request;

/// The heavy-lane job kind of a bundle build (coalesced per bundle).
pub const JOB_KIND: &str = "bundle_build";
/// A failed build is retried after this long.
pub const RETRY_AFTER: Duration = Duration::from_secs(300);
/// How often pending requests, retries and refused submissions are re-checked.
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// The compaction backstop and the re-rank run this often (bundles.md §2, §5).
const DAILY: Duration = Duration::from_secs(86_400);

#[derive(Default)]
struct Inner {
    running: HashSet<String>,
    queued: HashSet<String>,
    requests: HashMap<String, Request>,
    priorities: HashMap<String, Priority>,
    retry_at: HashMap<String, tokio::time::Instant>,
}

/// The compiler runtime, one per running core.
#[derive(Default)]
pub struct Compiler {
    inner: Mutex<Inner>,
    /// A fixed `issued_at` / `created_at` (tests of byte-identical output).
    fixed_time: Mutex<Option<String>>,
    /// Rows per step of urlfilter's exact filing, when not the default (tests of paging).
    order_rows: Mutex<Option<usize>>,
    /// Rows (or work) per step of the IP pass, the re-rank, the bundle-wide inputs and the
    /// pattern admission, when not the defaults (tests: many steps on a small bundle).
    step_rows: Mutex<Option<usize>>,
    /// The last `warn_on` / profile pairing digest seen ([`warn::pairing_digest`]).
    pairing: Mutex<Option<String>>,
    /// Per bundle: the digest of its pattern rules and the reference's admission of them, so a
    /// build whose patterns didn't change skips building every regex to cost it.
    admissions: Mutex<HashMap<String, (String, picket_rules::matcher::PatternAdmission)>>,
    /// Tiering dry runs aren't submitted (tests watching a split held for its dry run).
    dry_runs_paused: std::sync::atomic::AtomicBool,
    /// Per bundle, the lock one tiering dry-run step holds ([`tier::DryRunJob`]).
    dry_run_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Awaited inside the next build's commit, right before its write (tests: a config restore
    /// that commits after the build's step checked the restore generation, core.md §2).
    commit_pause: Mutex<Option<futures_util::future::BoxFuture<'static, ()>>>,
    /// Awaited by the next [`tier::submit_dry_runs`] right before it registers a due proposal
    /// (tests: a pause set while it is suspended there).
    dry_run_register_pause: Mutex<Option<futures_util::future::BoxFuture<'static, ()>>>,
}

impl Compiler {
    /// Awaits `pause` inside the next build's commit, right before its write (tests).
    #[doc(hidden)]
    pub fn pause_next_commit(&self, pause: futures_util::future::BoxFuture<'static, ()>) {
        *self.commit_pause.lock().unwrap_or_else(|p| p.into_inner()) = Some(pause);
    }

    pub(crate) fn take_commit_pause(&self) -> Option<futures_util::future::BoxFuture<'static, ()>> {
        self.commit_pause.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// Awaits `pause` in the next [`tier::submit_dry_runs`], right before it registers a due
    /// proposal (tests).
    #[doc(hidden)]
    pub fn pause_next_dry_run_register(&self, pause: futures_util::future::BoxFuture<'static, ()>) {
        *self
            .dry_run_register_pause
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(pause);
    }

    pub(crate) fn take_dry_run_register_pause(&self) -> Option<futures_util::future::BoxFuture<'static, ()>> {
        self.dry_run_register_pause
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    /// Stops (or resumes) tiering dry runs (tests, which may then step a `DryRunJob` themselves):
    /// from now on none is registered, submitted or released (no build is asked for), whatever
    /// call is in flight: each checks the pause right before each of those side effects (a
    /// registration checks on the writer). SeqCst: a call that reads rows written after the pause
    /// sees it.
    pub fn set_dry_runs_paused(&self, paused: bool) {
        self.dry_runs_paused
            .store(paused, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn dry_runs_paused(&self) -> bool {
        self.dry_runs_paused.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The lock of `bundle`'s dry-run steps.
    pub(crate) fn dry_run_lock(&self, bundle: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut m = self.dry_run_locks.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() > 256 {
            m.retain(|_, l| Arc::strong_count(l) > 1);
        }
        m.entry(bundle.to_string()).or_default().clone()
    }

    /// The cached admission for `bundle`'s patterns with this digest.
    pub(crate) fn admission(
        &self,
        bundle: &str,
        digest: &str,
    ) -> Option<picket_rules::matcher::PatternAdmission> {
        self.admissions
            .lock()
            .ok()?
            .get(bundle)
            .filter(|(d, _)| d == digest)
            .map(|(_, a)| a.clone())
    }

    pub(crate) fn remember_admission(
        &self,
        bundle: &str,
        digest: String,
        a: picket_rules::matcher::PatternAdmission,
    ) {
        if let Ok(mut m) = self.admissions.lock() {
            m.insert(bundle.to_string(), (digest, a));
        }
    }
}

impl Compiler {
    /// The time a build stamps on its head and deltas.
    pub fn now(&self) -> String {
        self.fixed_time
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(crate::util::now_ts)
    }

    /// Rows per step of urlfilter's exact filing set by [`Self::set_order_rows`].
    pub fn order_rows(&self) -> Option<usize> {
        self.order_rows.lock().ok().and_then(|g| *g)
    }

    /// Sets the rows per step of urlfilter's exact filing (tests: several pages on a small
    /// bundle; `None`: the default).
    pub fn set_order_rows(&self, n: Option<usize>) {
        if let Ok(mut g) = self.order_rows.lock() {
            *g = n.map(|n| n.max(1));
        }
    }

    /// The rows (or work) per step for a bounded phase whose default is `default`.
    pub fn step_rows(&self, default: usize) -> usize {
        self.step_rows.lock().ok().and_then(|g| *g).unwrap_or(default)
    }

    /// Sets the rows (or work) per step of the IP pass, the re-rank, the bundle-wide inputs and
    /// the pattern admission (tests: many steps on a small bundle; `None`: the defaults).
    pub fn set_step_rows(&self, n: Option<usize>) {
        if let Ok(mut g) = self.step_rows.lock() {
            *g = n.map(|n| n.max(1));
        }
    }

    /// Makes every build stamp `t` (tests: identical inputs give byte-identical blobs).
    pub fn set_fixed_time(&self, t: Option<String>) {
        if let Ok(mut g) = self.fixed_time.lock() {
            *g = t;
        }
    }

    /// Asks for a build of `bundle` (merged with any pending request; run after the current build
    /// of the bundle ends).
    pub fn request(&self, state: &SharedState, bundle: &str, req: Request, priority: Priority) {
        let submit = {
            let Ok(mut g) = self.inner.lock() else { return };
            g.requests.entry(bundle.to_string()).or_default().merge(req);
            let p = {
                let p = g.priorities.entry(bundle.to_string()).or_insert(priority);
                *p = (*p).min(priority);
                *p
            };
            if g.queued.contains(bundle) {
                // A queued build takes the request; resubmitting raises its priority if needed.
                Some(p)
            } else if g.running.contains(bundle) {
                // The running build resubmits at its end.
                None
            } else {
                g.queued.insert(bundle.to_string());
                Some(p)
            }
        };
        if let Some(p) = submit {
            let r = state
                .scheduler
                .heavy
                .submit(p, Box::new(build::BuildJob::new(state.clone(), bundle)));
            if r == Submitted::Dropped
                && let Ok(mut g) = self.inner.lock()
            {
                g.queued.remove(bundle);
            }
        }
    }

    /// Starts a build of `bundle`: `None` when one is running (its end runs the request).
    pub(crate) fn begin(&self, bundle: &str) -> Option<RunGuard> {
        let mut g = self.inner.lock().ok()?;
        g.queued.remove(bundle);
        if !g.running.insert(bundle.to_string()) {
            return None;
        }
        g.retry_at.remove(bundle);
        Some(RunGuard {
            bundle: bundle.to_string(),
            compiler: Weak::new(),
        })
    }

    /// Takes the merged request for `bundle`.
    pub(crate) fn take_request(&self, bundle: &str) -> Request {
        self.inner
            .lock()
            .ok()
            .and_then(|mut g| {
                g.priorities.remove(bundle);
                g.requests.remove(bundle)
            })
            .unwrap_or_default()
    }

    fn end(&self, bundle: &str) -> Option<Priority> {
        let mut g = self.inner.lock().ok()?;
        g.running.remove(bundle);
        if g.requests.contains_key(bundle) && !g.queued.contains(bundle) {
            g.queued.insert(bundle.to_string());
            return Some(g.priorities.get(bundle).copied().unwrap_or(Priority::P0));
        }
        None
    }

    fn schedule_retry(&self, bundle: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.retry_at
                .insert(bundle.to_string(), tokio::time::Instant::now() + RETRY_AFTER);
        }
    }

    /// True while a build of `bundle` runs or waits.
    pub fn busy(&self, bundle: &str) -> bool {
        self.inner
            .lock()
            .map(|g| {
                g.running.contains(bundle) || g.queued.contains(bundle) || g.requests.contains_key(bundle)
            })
            .unwrap_or(false)
    }

    /// True while any build runs or waits (tests).
    pub fn idle(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.running.is_empty() && g.queued.is_empty() && g.requests.is_empty())
            .unwrap_or(true)
    }
}

/// A bundle's "building" mark; dropping it (the build ended, failed or panicked) clears it and
/// runs the requests that arrived meanwhile.
pub struct RunGuard {
    bundle: String,
    compiler: Weak<AppState>,
}

impl RunGuard {
    pub(crate) fn attach(&mut self, state: &SharedState) {
        self.compiler = Arc::downgrade(state);
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        let Some(state) = self.compiler.upgrade() else {
            return;
        };
        if let Some(p) = state.compiler.end(&self.bundle) {
            state
                .scheduler
                .heavy
                .submit(p, Box::new(build::BuildJob::new(state.clone(), &self.bundle)));
        }
    }
}

/// Asks for a build of `bundle` after one that a config restore ended (it runs once that build's
/// mark is cleared, core.md §2).
pub(crate) fn rebuild_after_restore(state: &SharedState, bundle: &str) {
    state.compiler.request(
        state,
        bundle,
        Request {
            reasons: ["config restore".to_string()].into(),
            ..Request::default()
        },
        Priority::P0,
    );
}

/// Records a failed build: the previous version stays, `bundle_build_failed` is raised, the work
/// rows go, and a retry is scheduled (bundles.md §2; core.md §9).
pub async fn fail(state: &SharedState, bundle: &str, error: &str) {
    let b = bundle.to_string();
    let msg = crate::util::sanitize_for_message(error, 1000);
    let alerts = state.alerts.clone();
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let now = crate::util::now_ts();
            store::record_failure(&tx, &b, &msg, &now)?;
            store::clear_work(&tx, &b)?;
            let mut ch = Changes::default();
            let spec = RaiseSpec::new(
                "bundle_build_failed",
                Severity::Warning,
                format!("bundle_build_failed:{b}"),
                format!("Bundle {b} failed to build; edges keep its previous version"),
                json!({"bundle": b, "error": msg}),
            )
            .bundle(b.clone());
            alerts.raise_in(&tx, &spec, &mut ch)?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await;
    match r {
        Ok(ch) => state.alerts.announce(ch),
        Err(e) => tracing::warn!(bundle = %bundle, error = %format!("{e:#}"), "cannot record a failed build"),
    }
    state.compiler.schedule_retry(bundle);
}

/// A deleted bundle: its compiled state goes (its versions age out with retention, while edges
/// still run them).
pub async fn retire(state: &SharedState, bundle: &str) -> anyhow::Result<()> {
    let b = bundle.to_string();
    let alerts = state.alerts.clone();
    let ch = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let mut ch = Changes::default();
            guard::retire_public_suffix(&tx, &alerts, &b, &mut ch)?;
            for t in [
                "bundle_keys",
                "bundle_ip_ranges",
                "bundle_shards",
                "bundle_ip_shards",
                "bundle_builds",
            ] {
                tx.execute(&format!("DELETE FROM {t} WHERE bundle_id = ?1"), [&b])?;
            }
            store::clear_work(&tx, &b)?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    tracing::info!(bundle = %bundle, "a deleted bundle's compiled state was retired");
    state.edges.publisher.trigger(None);
    // Its warnings resolve (bundles.md §3: no block bundle holds the feed any more).
    warn::bundle_retired(state, bundle).await;
    Ok(())
}

/// The feeds' dirty set hands bundles to the compiler (feeds.md §3; bundles.md §2 "Triggers").
struct Sink(Weak<AppState>);

impl crate::feeds::dirty::BuildSink for Sink {
    fn build(&self, bundle: &str, feeds: Vec<String>) {
        let Some(state) = self.0.upgrade() else { return };
        let req = Request {
            reasons: feeds.into_iter().map(|f| format!("feed {f}")).collect(),
            ..Request::default()
        };
        state.compiler.request(&state, bundle, req, Priority::P0);
    }
}

/// Requests a build of every bundle whose recorded state is behind its feeds or definition.
pub async fn derive_pending(state: &SharedState, reason: &str) -> anyhow::Result<usize> {
    let model = state.config.model().await?;
    let specs: Vec<spec::Spec> = model
        .bundles
        .values()
        .map(|d| spec::Spec::of(d, &model))
        .collect();
    let specs2 = specs;
    let now = jiff::Timestamp::now();
    let (due, gone) = state
        .db
        .read(move |c| {
            let rows = store::build_rows(c)?;
            let mut due = Vec::new();
            for s in &specs2 {
                // The split a build would apply now: a proposed one waits for its dry run.
                let (s, _) = tier::effective_in(c, s, now)?;
                let s = &s;
                let runs = spec::snapshot(c, s)?;
                let behind = match rows.get(&s.id) {
                    None => true,
                    Some(r) => {
                        r.definition_hash != s.def_hash
                            || r.status != "ok"
                            || runs
                                .iter()
                                .any(|(f, run)| r.feed_runs.get(f).copied().unwrap_or(0) < *run)
                    }
                };
                if behind {
                    due.push(s.id.clone());
                }
            }
            let ids: HashSet<&str> = specs2.iter().map(|s| s.id.as_str()).collect();
            let gone: Vec<String> = rows
                .keys()
                .filter(|k| !ids.contains(k.as_str()))
                .cloned()
                .collect();
            Ok::<_, anyhow::Error>((due, gone))
        })
        .await?;
    for b in &gone {
        retire(state, b).await?;
    }
    for b in &due {
        state.compiler.request(
            state,
            b,
            Request {
                reasons: [reason.to_string()].into(),
                ..Request::default()
            },
            Priority::P0,
        );
    }
    // A changed tier or `hot_max_mib` is dry run as soon as it is seen (bundles.md §2 Tiering).
    tier::submit_dry_runs(state).await;
    Ok(due.len())
}

/// What start does after a stop that may have interrupted builds (README §2 Restarts): empties
/// the work tables (scratch of builds that will start over) and requests a build of every bundle
/// behind its feeds or definition. Returns how many were requested.
pub async fn recover(state: &SharedState) -> anyhow::Result<usize> {
    state
        .db
        .write(|c| {
            for t in store::WORK_TABLES {
                c.execute(&format!("DELETE FROM {t}"), [])?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    derive_pending(state, "start").await
}

/// Starts the compiler: empties the work tables, registers with the feeds' dirty set, builds what
/// is behind, and keeps the triggers and timers running.
pub async fn start(state: &SharedState) -> anyhow::Result<()> {
    state
        .feeds
        .dirty()
        .set_sink(Box::new(Sink(Arc::downgrade(state))));
    let n = recover(state).await?;
    if n > 0 {
        tracing::info!(bundles = n, "bundles behind their feeds or definition build now");
    }
    state.retention.register(Arc::new(retention::BundleRetention));
    state
        .retention
        .register(Arc::new(retention::KeyHitRetention::default()));
    // Warning re-checks a stop interrupted, and a pairing change made while core was down
    // (README §2 Restarts; bundles.md §3 When).
    let model = state.config.model().await?;
    let digest = warn::resume(state, &model).await?;
    if let Ok(mut g) = state.compiler.pairing.lock() {
        *g = Some(digest);
    }
    spawn_config_watch(state.clone());
    spawn_sweep(state.clone());
    spawn_daily(state.clone());
    Ok(())
}

/// A definition change builds the bundle (bundles.md §2 "Triggers"); a deleted bundle retires.
fn spawn_config_watch(state: SharedState) {
    tokio::spawn(async move {
        let mut rx = state.config.subscribe();
        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                r = rx.changed() => if r.is_err() { return },
            }
            if let Err(e) = derive_pending(&state, "definition change").await {
                tracing::warn!(error = %format!("{e:#}"), "cannot check bundles after a configuration change");
            }
            // A changed warn_on or allow/block pairing re-checks every warning (bundles.md §3).
            if let Ok(model) = state.config.model().await {
                let d = warn::pairing_digest(&model);
                let changed = state
                    .compiler
                    .pairing
                    .lock()
                    .map(|mut g| {
                        let changed = g.as_deref().is_some_and(|old| old != d);
                        *g = Some(d.clone());
                        changed
                    })
                    .unwrap_or(false);
                if changed {
                    warn::pairing_changed(&state, d).await;
                }
            }
        }
    });
}

/// Retries failed builds and submissions the full heavy queue refused.
fn spawn_sweep(state: SharedState) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(SWEEP_EVERY);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => return,
                _ = t.tick() => {}
            }
            let now = tokio::time::Instant::now();
            let (retry, resubmit): (Vec<String>, Vec<(String, Priority)>) = {
                let Ok(mut g) = state.compiler.inner.lock() else {
                    continue;
                };
                let retry: Vec<String> = g
                    .retry_at
                    .iter()
                    .filter(|(_, at)| **at <= now)
                    .map(|(b, _)| b.clone())
                    .collect();
                for b in &retry {
                    g.retry_at.remove(b);
                }
                let resubmit: Vec<(String, Priority)> = g
                    .requests
                    .keys()
                    .filter(|b| !g.running.contains(*b) && !g.queued.contains(*b))
                    .map(|b| (b.clone(), g.priorities.get(b).copied().unwrap_or(Priority::P0)))
                    .collect();
                (retry, resubmit)
            };
            for b in retry {
                state.compiler.request(
                    &state,
                    &b,
                    Request {
                        reasons: ["retry after a failed build".into()].into(),
                        ..Request::default()
                    },
                    Priority::P0,
                );
            }
            for (b, p) in resubmit {
                state.compiler.request(&state, &b, Request::default(), p);
            }
        }
    });
}

/// The daily compaction backstop (old bases, long chains) and the daily re-rank (P2).
fn spawn_daily(state: SharedState) {
    let st = state.clone();
    state.scheduler.every(
        Duration::from_secs(3600),
        DAILY,
        state.shutdown.clone(),
        move |_| {
            let st = st.clone();
            tokio::spawn(async move {
                let Ok(model) = st.config.model().await else {
                    return;
                };
                for (id, def) in &model.bundles {
                    let spec = spec::Spec::of(def, &model);
                    if !spec.has_edge_bundle() {
                        continue;
                    }
                    let rerank = spec.cold_capable() && spec.hot_max_mib.is_some();
                    st.compiler.request(
                        &st,
                        id,
                        Request {
                            reasons: ["daily compaction and re-rank".into()].into(),
                            rerank,
                            force: true,
                            ..Request::default()
                        },
                        Priority::P2,
                    );
                }
            });
        },
    );
}

/// What the UI shows for one bundle (core.md §12 Bundles).
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct BundleStatus {
    pub bundle: String,
    pub action: String,
    /// `ok`, `failed`, or `never` (not built yet).
    pub status: String,
    pub error: Option<String>,
    /// A build is running or waiting.
    pub building: bool,
    /// The head core names (null: no edge bundle, or none yet).
    pub head: Option<String>,
    pub built_at: Option<String>,
    /// The feed runs the last build read, by feed id.
    pub feed_runs: BTreeMap<String, i64>,
    /// The last build's counts and sizes.
    pub stats: Option<serde_json::Value>,
    /// The browser list's URL path, when the bundle has one.
    pub browser_list: Option<String>,
    /// Open guardrail and build alerts of the bundle.
    pub open_alerts: i64,
}

/// Every bundle's status.
pub async fn statuses(state: &SharedState) -> anyhow::Result<Vec<BundleStatus>> {
    let model = state.config.model().await?;
    let rows = state
        .db
        .read(|c| Ok::<_, anyhow::Error>(store::build_rows(c)?))
        .await?;
    let open: BTreeMap<String, i64> = state
        .db
        .read(|c| {
            let mut st = c.prepare(
                "SELECT bundle_id, count(*) FROM alerts WHERE state = 'open' AND bundle_id IS NOT NULL GROUP BY bundle_id",
            )?;
            let v = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    Ok(model
        .bundles
        .values()
        .map(|d| {
            let s = spec::Spec::of(d, &model);
            let r = rows.get(&d.id);
            BundleStatus {
                bundle: d.id.clone(),
                action: d.action.as_str().into(),
                status: r.map_or("never".into(), |r| r.status.clone()),
                error: r.and_then(|r| r.error.clone()),
                building: state.compiler.busy(&d.id),
                head: r.and_then(|r| r.head_id.clone()),
                built_at: r.and_then(|r| r.built_at.clone()),
                feed_runs: r.map(|r| r.feed_runs.clone()).unwrap_or_default(),
                stats: r.and_then(|r| r.stats.clone()),
                browser_list: s.has_browser_list().then(|| format!("/lists/{}.txt", d.id)),
                open_alerts: open.get(&d.id).copied().unwrap_or(0),
            }
        })
        .collect())
}
