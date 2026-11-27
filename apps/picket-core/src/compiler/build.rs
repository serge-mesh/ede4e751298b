//! One bundle build (bundles.md §2), a heavy-lane job run in bounded steps (core.md §3: P0 for an
//! incremental build, re-checking the queue between steps so other jobs run between them).
//!
//! | Phase | Step(s) |
//! |---|---|
//! | setup | definition, snapshot runs, mode, previous head, bundle-wide inputs (rewrite ranks, entities) |
//! | order | urlfilter's exact filing when two rewrites can match one query: the bundle in bundle order, a page per step ([`OrderPass`]) |
//! | collect | the changed entries' keys (or every key) into `bundle_build_keys`, guardrail checks |
//! | expand | each changed key's listed descendants (a prefix scan of `feed_entries`), bounded rows per step |
//! | keys | per chunk of changed keys: compile, place (hot/cold), prune, diff → `bundle_build_ops` |
//! | ips, ipfold | the IP rules staged a page per step, then folded into runs a page per step ([`super::ipfold`]), when they may have changed |
//! | patterns | every pattern read, admitted a few per step when the cached admission misses, compiled |
//! | cancellations | the cross-feed guardrail, a chunk of cancellers per step |
//! | warnings | compile-time warnings: matchers a page per step, then the changed keys a page per step ([`super::warn::WarnCheck`]) |
//! | plan … commit | [`super::assemble`]: shard plans, a base per step, a delta per step, segments, head, one commit |
//!
//! **Modes.** *Fresh* (no published head, or one in another format): every key, staged in
//! `bundle_build_fresh` and swapped into `bundle_keys` by the commit (readers such as the browser
//! lists never see a partial table, README §2 Restarts), every shard a new base. *Full* (a definition
//! change): every key of the old and new state, diffed like an incremental build. *Incremental*:
//! the keys the member feeds' runs since the last build changed, plus their listed descendants,
//! the keys of the bundle-wide rules (rewrites, entities) and pending hit promotions.
//!
//! **Snapshot reads.** Each feed is read at the run the setup took ([`super::spec::snapshot`]), so
//! a feed run that lands between steps doesn't show; its dirty mark builds the bundle again
//! afterwards. Work tables are scratch: a restart empties them and re-derives the build
//! (README §2 Restarts).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use picket_bundle::Head;
use picket_bundle::hash::{KeyHash, bundle_hash_seed};
use picket_bundle::rich::RichBuilder;
use picket_bundle::shard_dir::ShardDir;
use picket_rules::compile::{Part, covering_subs, is_subsumed};
use picket_rules::{Flags, RuleType};
use rusqlite::{OptionalExtension, params};

use super::compile::{self, Action, BundleWide, CompileCounts};
use super::guard::Findings;
use super::source::{self, View};
use super::spec::{self, Runs, Spec};
use super::store::{self, BuildState, KeyState, Op};
use crate::config::model::Tier;
use crate::scheduler::{BoxFuture, HeavyJob, Step};
use crate::state::SharedState;

/// Keys compiled per step.
pub const KEYS_PER_STEP: usize = 10_000;
/// `feed_entries` rows one expand step scans for descendants (core.md §3: bounded steps).
pub const DESCENDANT_ROWS_PER_STEP: usize = 20_000;
/// Entries read per collect step.
pub const ENTRIES_PER_STEP: usize = 20_000;
/// Changed keys whose descendants one expand step looks for (at most).
pub const DESCENDANTS_PER_STEP: usize = 5_000;
/// The most pattern rules a bundle compiles (the `patterns.bin` reader's cap).
pub const MAX_PATTERN_RULES: usize = picket_bundle::patterns::MAX_ENTRIES;
/// The most IP rules a bundle folds in one build (README §2 Bounded; ~64 B each in RAM).
pub const MAX_IP_RULES: usize = 2_000_000;
/// Rows one step of urlfilter's exact filing reads (core.md §3: bounded steps).
pub const ORDER_ROWS_PER_STEP: usize = 100_000;
/// The most `$dnsrewrite` or entity rules read for the bundle-wide pass.
pub const MAX_WIDE_RULES: usize = 100_000;
/// Provisional shard numbers of a fresh build: 1000 + the key's directory index, until the
/// directory is planned.
pub const PROVISIONAL: u32 = 1000;

/// How a build reads its keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Fresh,
    Full,
    Incremental,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Fresh => "fresh",
            Mode::Full => "full",
            Mode::Incremental => "incremental",
        }
    }
}

/// What the build's changed entries touched beyond domain keys.
#[derive(Clone, Copy, Debug, Default)]
pub struct Touched {
    pub pattern: bool,
    pub ip: bool,
    pub browser: bool,
}

/// The previous version a build continues from.
pub struct Prev {
    pub head: Head,
    pub head_id: String,
    pub rich_bytes: Vec<u8>,
}

/// What a build requests besides its feeds (the runtime merges requests while one waits).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub reasons: BTreeSet<String>,
    /// Re-rank intelligent-tiering keys (bundles.md §2 Tiering).
    pub rerank: bool,
    /// Build even when nothing changed (the UI's "Build now").
    pub force: bool,
    /// Parts to rebuild as bases (`hot/<shard>`, `cold/<shard>`, `ip/<ip shard>`): another
    /// bundle's build found them the largest overlays on an edge past its `overlay_budget_mib`
    /// (bundles.md §5).
    pub compact: BTreeSet<String>,
}

impl Request {
    pub fn merge(&mut self, o: Request) {
        self.reasons.extend(o.reasons);
        self.rerank |= o.rerank;
        self.force |= o.force;
        self.compact.extend(o.compact);
    }
}

/// Everything a build carries between steps.
pub struct Ctx {
    /// The restore generation when the setup read the feeds (core.md §2 "the old state until it
    /// completes, then only the new one"): once a config restore commits, the build stops, and
    /// its commit writes nothing ([`crate::config::export::RestoreGate`]).
    pub generation: u64,
    /// The bundle-wide digest the last build recorded.
    pub last_digest: Option<String>,
    /// urlfilter's exact filing while the order phase runs.
    pub order: Option<OrderPass>,
    /// The re-rank while it runs.
    pub rerank: Option<super::tier::Rerank>,
    /// The bundle-wide inputs while they are read.
    pub wide_pass: Option<WidePass>,
    pub spec: Spec,
    pub runs: Runs,
    pub old_runs: Runs,
    pub mode: Mode,
    pub prev: Option<Prev>,
    pub seed: u64,
    pub now: String,
    pub wide: Arc<BundleWide>,
    pub wide_digest: String,
    pub wide_changed: bool,
    pub rich: Option<RichBuilder>,
    pub state: BuildState,
    pub touched: Touched,
    pub request: Request,
    /// The hot and cold directories keys are placed with during the key pass.
    pub hot_dir: ShardDir,
    pub cold_dir: Option<ShardDir>,
    pub next_cold_shard: u32,
    pub counts: CompileCounts,
    pub stats: BuildStats,
    pub findings: Findings,
    /// The compile-time warning check while it runs (bundles.md §3; each step applies what it
    /// found).
    pub warn: Option<super::warn::WarnCheck>,
    /// The cross-feed scan while it runs.
    pub cancel: Option<super::guard::CancelScan>,
    /// The warning check was set up.
    pub warn_started: bool,
    pub bad_rows: u64,
    pub ips: Option<super::assemble::IpOutcome>,
    /// The IP pass while it runs: staging, then the fold ([`super::ipfold`]).
    pub ip_load: super::ipfold::LoadAt,
    pub ip_fold: Option<super::ipfold::IpFold>,
    /// The patterns pass while it runs.
    pub pattern_pass: Option<super::assemble::PatternPass>,
    pub patterns: Option<super::assemble::PatternOutcome>,
    pub assembly: Option<super::assemble::Assembly>,
}

/// Counts a build reports (stats_json).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct BuildStats {
    pub changed_keys: u64,
    pub keys_added: u64,
    pub keys_deleted: u64,
    pub keys_changed: u64,
    pub moves: u64,
    pub pruned: u64,
    pub entries_read: u64,
}

enum Phase {
    Setup,
    /// The re-rank, a page per step ([`super::tier::Rerank`]).
    Rank,
    /// The bundle-wide inputs, a bounded step at a time ([`WidePass`]).
    Wide,
    Order,
    Collect(CollectAt),
    Expand(ExpandAt),
    Keys {
        cursor: String,
    },
    Ips,
    IpFold,
    Patterns,
    Cancellations,
    Warnings,
    Assemble(super::assemble::Stage),
    Commit,
    Done,
}

impl CollectAt {
    fn start() -> Self {
        CollectAt {
            member: 0,
            pass: 0,
            run_cursor: (0, 0),
            key_cursor: source::KEYS_START,
            extras: false,
        }
    }
}

/// Where collecting stands: member index, sub-pass and cursor.
#[derive(Clone, Debug)]
struct CollectAt {
    member: usize,
    /// Incremental: 0 = by first_run, 1 = by removed_run; full: index into the member's types.
    pass: usize,
    run_cursor: (i64, i64),
    key_cursor: source::KeyCursor,
    /// The bundle-wide keys and promotions were added.
    extras: bool,
}

/// One build of one bundle.
pub struct BuildJob {
    state: SharedState,
    bundle: String,
    phase: Phase,
    ctx: Option<Box<Ctx>>,
    started: std::time::Instant,
    /// Holds the bundle's "building" mark; dropping it (end, failure, panic) clears it.
    guard: Option<super::RunGuard>,
}

impl BuildJob {
    pub fn new(state: SharedState, bundle: &str) -> Self {
        Self {
            state,
            bundle: bundle.to_string(),
            phase: Phase::Setup,
            ctx: None,
            started: std::time::Instant::now(),
            guard: None,
        }
    }

    /// The phase the next step runs (tests drive builds step by step).
    pub fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::Setup => "setup",
            Phase::Rank => "rank",
            Phase::Wide => "wide",
            Phase::Order => "order",
            Phase::Collect(_) => "collect",
            Phase::Expand(_) => "expand",
            Phase::Keys { .. } => "keys",
            Phase::Ips => "ips",
            Phase::IpFold => "ipfold",
            Phase::Patterns => "patterns",
            Phase::Cancellations => "cancellations",
            Phase::Warnings => "warnings",
            Phase::Assemble(super::assemble::Stage::Plan) => "plan",
            Phase::Assemble(super::assemble::Stage::Base(_)) => "base",
            Phase::Assemble(super::assemble::Stage::Delta(_)) => "delta",
            Phase::Assemble(super::assemble::Stage::Ip(_)) => "ipshard",
            Phase::Assemble(super::assemble::Stage::Segments) => "segments",
            Phase::Assemble(super::assemble::Stage::Finish) => "finish",
            Phase::Commit => "commit",
            Phase::Done => "done",
        }
    }

    fn ctx(&mut self) -> Result<&mut Ctx> {
        self.ctx
            .as_deref_mut()
            .ok_or_else(|| anyhow!("build context missing"))
    }

    async fn run_step(&mut self) -> Result<Step> {
        if let Some(ctx) = self.ctx.as_deref()
            && !self.state.restore.is_current(ctx.generation)
        {
            self.restored().await?;
            return Ok(Step::Done);
        }
        let phase = std::mem::replace(&mut self.phase, Phase::Done);
        self.phase = match phase {
            Phase::Setup => match self.setup().await? {
                None => Phase::Done,
                Some(p) => p,
            },
            Phase::Rank => self.rank().await?,
            Phase::Wide => self.wide().await?,
            Phase::Order => self.order().await?,
            Phase::Collect(at) => self.collect(at).await?,
            Phase::Expand(at) => self.expand(at).await?,
            Phase::Keys { cursor } => self.keys(cursor).await?,
            Phase::Ips => {
                let st = self.state.clone();
                let ctx = self.ctx()?;
                if !super::assemble::ips_needed(ctx) {
                    ctx.ips = Some(super::assemble::IpOutcome::default());
                    Phase::Patterns
                } else if super::ipfold::load_step(&st, ctx).await? {
                    let f = super::ipfold::IpFold::new(ctx);
                    ctx.ip_fold = Some(f);
                    Phase::IpFold
                } else {
                    Phase::Ips
                }
            }
            Phase::IpFold => {
                let st = self.state.clone();
                if super::ipfold::fold_step(&st, self.ctx()?).await? {
                    Phase::Patterns
                } else {
                    Phase::IpFold
                }
            }
            Phase::Patterns => {
                let st = self.state.clone();
                if super::assemble::patterns_step(&st, self.ctx()?).await? {
                    Phase::Cancellations
                } else {
                    Phase::Patterns
                }
            }
            Phase::Cancellations => {
                let st = self.state.clone();
                if super::guard::cancellations_step(&st, self.ctx()?).await? {
                    Phase::Warnings
                } else {
                    Phase::Cancellations
                }
            }
            Phase::Warnings => {
                let state = self.state.clone();
                if !self.ctx()?.warn_started {
                    let check = super::warn::WarnCheck::new(&state, self.ctx()?).await?;
                    let ctx = self.ctx()?;
                    ctx.warn = check;
                    ctx.warn_started = true;
                }
                if !super::warn::check_step(&state, self.ctx()?).await? {
                    Phase::Warnings
                } else if self.ctx()?.spec.has_edge_bundle() {
                    Phase::Assemble(super::assemble::Stage::Plan)
                } else {
                    Phase::Commit
                }
            }
            Phase::Assemble(stage) => {
                let state = self.state.clone();
                match super::assemble::step(&state, self.ctx()?, stage).await? {
                    Some(next) => Phase::Assemble(next),
                    None => Phase::Commit,
                }
            }
            Phase::Commit => {
                let ctx = self.ctx.take().ok_or_else(|| anyhow!("build context missing"))?;
                super::commit::commit(&self.state, &self.bundle, *ctx, self.started).await?;
                Phase::Done
            }
            Phase::Done => Phase::Done,
        };
        Ok(if matches!(self.phase, Phase::Done) {
            Step::Done
        } else {
            Step::More
        })
    }

    /// A config restore committed since the setup (core.md §2): the build read pre-restore
    /// entries, so it ends without a commit, its work rows go, and the bundle builds again from
    /// the restored state once this build's mark is cleared.
    async fn restored(&mut self) -> Result<()> {
        self.ctx = None;
        self.phase = Phase::Done;
        let bundle = self.bundle.clone();
        self.state
            .db
            .write(move |c| Ok::<_, anyhow::Error>(store::clear_work(c, &bundle)?))
            .await?;
        tracing::info!(bundle = %self.bundle, "bundle build ended by a config restore; it builds again");
        super::rebuild_after_restore(&self.state, &self.bundle);
        Ok(())
    }

    /// Reads the definition, snapshot and previous state; decides the mode. `None`: nothing to
    /// build (or another build of the bundle runs: it takes the request when it ends).
    async fn setup(&mut self) -> Result<Option<Phase>> {
        let Some(mut guard) = self.state.compiler.begin(&self.bundle) else {
            return Ok(None);
        };
        // Taken before anything is read: a restore committing from here on ends the build.
        let generation = self.state.restore.generation();
        guard.attach(&self.state);
        self.guard = Some(guard);
        let request = self.state.compiler.take_request(&self.bundle);
        let model = self.state.config.model().await?;
        let Some(def) = model.bundles.get(&self.bundle).cloned() else {
            // Deleted: its rows go (versions age out with retention).
            super::retire(&self.state, &self.bundle).await?;
            return Ok(None);
        };
        // A proposed split (a tier or `hot_max_mib` change) waits for its dry run (bundles.md §2
        // Tiering): meanwhile the build applies the split the bundle's builds last applied.
        let spec = super::tier::effective_spec(&self.state, Spec::of(&def, &model)).await?;
        let bundle = self.bundle.clone();
        let dd = self.state.data_dir.clone();
        let spec2 = spec.clone();
        let (runs, row, prev) = self
            .state
            .db
            .read(move |c| {
                let runs = spec::snapshot(c, &spec2)?;
                let row = store::build_row(c, &bundle)?;
                let prev = match row.as_ref().and_then(|r| r.head_id.clone()) {
                    Some(h) => match store::read_head(c, &dd, &h)? {
                        Some((head, _)) => {
                            let rich_id = head.segment(picket_bundle::head::RICH).unwrap_or("").to_string();
                            let rich_bytes = crate::blobs::read(c, &dd, &rich_id)?.unwrap_or_default();
                            Some(Prev {
                                head,
                                head_id: h,
                                rich_bytes,
                            })
                        }
                        None => None,
                    },
                    None => None,
                };
                Ok::<_, anyhow::Error>((runs, row, prev))
            })
            .await?;
        let seed = bundle_hash_seed(&self.bundle);
        let ok_row = row.as_ref().filter(|r| r.status == "ok" || r.head_id.is_some());
        let prev = prev.filter(|p| p.head.format == picket_bundle::FORMAT && p.head.hash_seed == seed);
        let has_state = if spec.has_edge_bundle() {
            prev.is_some()
        } else {
            ok_row.is_some_and(|r| r.built_at.is_some())
        };
        let old_runs = row.as_ref().map(|r| r.feed_runs.clone()).unwrap_or_default();
        let old_hash = row
            .as_ref()
            .map(|r| r.definition_hash.clone())
            .unwrap_or_default();
        let state = row.as_ref().map(|r| r.state.clone()).unwrap_or_default();
        let promotions = spec.cold_capable()
            && has_state
            && super::tier::pending_promotions(&self.state, &self.bundle, &state).await?;
        let mode = if !has_state {
            Mode::Fresh
        } else if old_hash != spec.def_hash {
            Mode::Full
        } else {
            Mode::Incremental
        };
        if mode == Mode::Incremental
            && runs == old_runs
            && !request.force
            && !request.rerank
            && request.compact.is_empty()
            && !promotions
            && row.as_ref().is_some_and(|r| r.status == "ok")
        {
            tracing::debug!(bundle = %self.bundle, "bundle up to date");
            return Ok(None);
        }
        let mut state = state;
        let rerank = if request.rerank && spec.cold_capable() {
            super::tier::Rerank::new(&spec)
        } else {
            None
        };
        if request.rerank && spec.cold_capable() && rerank.is_none() {
            // No `hot_max_mib` any more: no cutoffs.
            state.tier = None;
        }
        // The bundle-wide inputs (rewrite orders, the entity table) are read in the wide phase;
        // the exact orders follow in the order phase.
        let last_digest = state_digest(&row);
        let rich = match (&prev, mode) {
            (Some(p), Mode::Full | Mode::Incremental) => {
                RichBuilder::from_previous(&p.rich_bytes).map_err(|e| anyhow!("previous rich.json: {e}"))?
            }
            _ => RichBuilder::new(),
        };
        let (hot_dir, cold_dir, next_cold_shard) = match (&prev, mode) {
            (Some(p), Mode::Full | Mode::Incremental) => {
                let hot = p
                    .head
                    .dir()
                    .map_err(|e| anyhow!("previous head's directory: {e}"))?;
                let cold = p
                    .head
                    .cold_dir()
                    .map_err(|e| anyhow!("previous head's cold directory: {e}"))?;
                let next_cold = p.head.next_cold_shard;
                match cold {
                    Some(c) => (hot, Some(c), next_cold),
                    None => (
                        hot,
                        Some(ShardDir::single(next_cold)),
                        next_cold.saturating_add(1),
                    ),
                }
            }
            _ => (ShardDir::single(0), Some(ShardDir::single(0)), 1),
        };
        // A definition change may add or take away the `browser` rules a member gives: the
        // bundle's and its profiles' lists are rewritten (bundles.md §8 Builds).
        let touched = Touched {
            browser: mode == Mode::Full,
            ..Touched::default()
        };
        tracing::info!(bundle = %self.bundle, mode = mode.as_str(), reasons = ?request.reasons, "bundle build started");
        let now = self.state.compiler.now();
        let action = Action(spec.rules_action());
        self.ctx = Some(Box::new(Ctx {
            generation,
            last_digest,
            order: None,
            rerank,
            wide_pass: Some(WidePass::new(action)),
            spec,
            runs,
            old_runs,
            mode,
            prev,
            seed,
            now,
            wide: Arc::new(BundleWide {
                action,
                ..BundleWide::default()
            }),
            wide_digest: String::new(),
            wide_changed: true,
            rich: Some(rich),
            state,
            touched,
            request,
            hot_dir,
            cold_dir,
            next_cold_shard,
            counts: CompileCounts::default(),
            stats: BuildStats::default(),
            findings: Findings::default(),
            warn: None,
            warn_started: false,
            cancel: None,
            bad_rows: 0,
            ips: None,
            ip_load: super::ipfold::LoadAt::default(),
            ip_fold: None,
            pattern_pass: None,
            patterns: None,
            assembly: None,
        }));
        let bundle = self.bundle.clone();
        self.state
            .db
            .write(move |c| Ok::<_, anyhow::Error>(store::clear_work(c, &bundle)?))
            .await?;
        Ok(Some(if self.ctx()?.rerank.is_some() {
            Phase::Rank
        } else {
            Phase::Wide
        }))
    }

    /// One re-rank step; at its end the new cutoffs place this build's keys.
    async fn rank(&mut self) -> Result<Phase> {
        let st = self.state.clone();
        let bundle = self.bundle.clone();
        let ctx = self.ctx()?;
        let mut rr = ctx.rerank.take().ok_or_else(|| anyhow!("re-rank missing"))?;
        match super::tier::rerank_step(&st, &bundle, &mut rr).await? {
            Some(cutoffs) => {
                ctx.state.tier = cutoffs;
                Ok(Phase::Wide)
            }
            None => {
                ctx.rerank = Some(rr);
                Ok(Phase::Rank)
            }
        }
    }

    /// One step of the bundle-wide inputs; at their end, urlfilter's exact filing when two
    /// rewrites can match one query, else the collect phase.
    async fn wide(&mut self) -> Result<Phase> {
        let st = self.state.clone();
        let ctx = self.ctx()?;
        let mut pass = ctx
            .wide_pass
            .take()
            .ok_or_else(|| anyhow!("bundle-wide pass missing"))?;
        let Some((wide, wanted)) = pass.step(&st, ctx).await? else {
            ctx.wide_pass = Some(pass);
            return Ok(Phase::Wide);
        };
        let digest = wide_digest(&wide);
        ctx.wide_changed = ctx.last_digest != Some(digest.clone());
        ctx.wide_digest = digest;
        if let Some(r) = ctx.rich.as_mut() {
            r.set_entities(wide.entities.clone());
        }
        ctx.order = wide.exact_orders.then(|| OrderPass {
            filer: picket_rules::order::OrderFiler::default(),
            wanted,
            orders: HashMap::new(),
            feed: 0,
            cursor: None,
            wide: wide.clone(),
        });
        ctx.wide = Arc::new(wide);
        Ok(if ctx.order.is_some() {
            Phase::Order
        } else {
            Phase::Collect(CollectAt::start())
        })
    }

    /// One page of urlfilter's exact filing ([`OrderPass`]); at the end the orders join the
    /// bundle-wide inputs.
    async fn order(&mut self) -> Result<Phase> {
        let ctx = self.ctx()?;
        let mut pass = ctx.order.take().ok_or_else(|| anyhow!("order pass missing"))?;
        let (spec, runs) = (ctx.spec.clone(), ctx.runs.clone());
        let (feed, cursor) = (pass.feed, pass.cursor.clone());
        let page_rows = self.state.compiler.order_rows().unwrap_or(ORDER_ROWS_PER_STEP);
        let page = self
            .state
            .db
            .read(move |c| {
                let view = View::with_browser(&spec, &runs);
                let Some((f, _)) = view.feeds().nth(feed) else {
                    return Ok::<_, anyhow::Error>(None);
                };
                let mut bad = 0u64;
                let (rows, next) = view.order_page(c, f, cursor.as_ref(), page_rows, &mut bad)?;
                Ok(Some((rows, next, bad)))
            })
            .await?;
        let ctx = self.ctx()?;
        match page {
            Some((rows, next, bad)) => {
                ctx.bad_rows += bad;
                for row in &rows {
                    let o = pass.filer.push(&row.rule);
                    if pass.wanted.contains(&row.order)
                        && let Some(o) = o
                    {
                        pass.orders.insert(row.order.clone(), o);
                    }
                }
                match next {
                    Some(c) => pass.cursor = Some(c),
                    None => {
                        pass.feed += 1;
                        pass.cursor = None;
                    }
                }
                ctx.order = Some(pass);
                Ok(Phase::Order)
            }
            None => {
                let mut wide = pass.wide;
                wide.orders = pass.orders;
                let digest = wide_digest(&wide);
                ctx.wide_changed = ctx.last_digest.as_deref() != Some(digest.as_str());
                ctx.wide_digest = digest;
                ctx.wide = Arc::new(wide);
                Ok(Phase::Collect(CollectAt::start()))
            }
        }
    }

    /// Fills `bundle_build_keys` (bundles.md §2 "Changed entries", "Changed keys").
    async fn collect(&mut self, mut at: CollectAt) -> Result<Phase> {
        let bundle = self.bundle.clone();
        let ctx = self.ctx()?;
        if !at.extras {
            // Bundle-wide keys (rewrites, entities), promotions, and in a full build the old
            // state's keys.
            let keys: Vec<String> = ctx.wide_keys();
            let mode = ctx.mode;
            let cold = ctx.spec.cold_capable();
            let rerank = ctx.request.rerank && cold;
            let last = ctx.state.last_build_at.clone();
            self.state
                .db
                .write(move |c| {
                    let tx = c.transaction()?;
                    insert_keys(&tx, &bundle, &keys)?;
                    if mode == Mode::Full {
                        tx.execute(
                            "INSERT OR IGNORE INTO bundle_build_keys(bundle_id, key) SELECT bundle_id, key FROM bundle_keys WHERE bundle_id = ?1",
                            [&bundle],
                        )?;
                    }
                    if cold && mode == Mode::Incremental {
                        super::tier::insert_promotions(&tx, &bundle, last.as_deref())?;
                    }
                    // New cutoffs: every intelligent-tiering key may change part (its
                    // descendants follow in the expand phase).
                    if rerank && mode == Mode::Incremental {
                        tx.execute(
                            "INSERT OR IGNORE INTO bundle_build_keys(bundle_id, key)
                             SELECT bundle_id, key FROM bundle_keys WHERE bundle_id = ?1 AND tier = 'intelligent-tiering'",
                            [&bundle],
                        )?;
                    }
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(())
                })
                .await?;
            at.extras = true;
            return Ok(Phase::Collect(at));
        }
        let ctx = self.ctx()?;
        let Some(m) = ctx.spec.members.get(at.member).cloned() else {
            return Ok(match ctx.mode {
                Mode::Incremental => Phase::Expand(ExpandAt::default()),
                Mode::Fresh | Mode::Full => Phase::Keys {
                    cursor: String::new(),
                },
            });
        };
        let next_member = |at: &CollectAt| CollectAt {
            member: at.member + 1,
            pass: 0,
            run_cursor: (0, 0),
            key_cursor: source::KEYS_START,
            extras: true,
        };
        let new_run = ctx.runs.get(&m.feed).copied().unwrap_or(0);
        let mode = ctx.mode;
        let compiled = ctx.spec.compiled_types(&m);
        if mode == Mode::Incremental {
            let old_run = ctx.old_runs.get(&m.feed).copied().unwrap_or(0);
            if new_run <= old_run || at.pass > 1 {
                return Ok(Phase::Collect(next_member(&at)));
            }
            let (feed, by_removed, cursor) = (m.feed.clone(), at.pass == 1, at.run_cursor);
            let (page, next) = self
                .state
                .db
                .read(move |c| {
                    Ok::<_, anyhow::Error>(source::changed_page(
                        c,
                        &feed,
                        old_run,
                        new_run,
                        by_removed,
                        cursor,
                        ENTRIES_PER_STEP,
                    )?)
                })
                .await?;
            self.absorb(&m, &compiled, page.into_iter().map(Entry::Changed).collect())
                .await?;
            match next {
                Some(c) => at.run_cursor = c,
                None => {
                    at.pass += 1;
                    at.run_cursor = (0, 0);
                }
            }
            return Ok(Phase::Collect(at));
        }
        // Fresh / full: every key of the member's types.
        let types: Vec<RuleType> = {
            let mut t = compiled.clone();
            if m.takes(RuleType::Browser) && ctx.spec.has_browser_list() {
                ctx.touched.browser = true;
            }
            t.dedup();
            t
        };
        let Some(rt) = types.get(at.pass).copied() else {
            return Ok(Phase::Collect(next_member(&at)));
        };
        let (feed, cursor) = (m.feed.clone(), at.key_cursor.clone());
        let (page, next) = self
            .state
            .db
            .read(move |c| {
                Ok::<_, anyhow::Error>(source::keys_page(
                    c,
                    &feed,
                    new_run,
                    rt.as_str(),
                    &cursor,
                    ENTRIES_PER_STEP,
                )?)
            })
            .await?;
        let entries = page
            .into_iter()
            .map(|(key, kind, flags, value_json)| Entry::Current {
                rule_type: rt,
                key,
                kind,
                flags,
                value_json,
            })
            .collect();
        self.absorb(&m, &compiled, entries).await?;
        match next {
            Some(c) => at.key_cursor = c,
            None => {
                at.pass += 1;
                at.key_cursor = source::KEYS_START;
            }
        }
        Ok(Phase::Collect(at))
    }

    /// Classifies a page of entries: keys into the work table, touched parts, guardrail checks.
    async fn absorb(&mut self, m: &spec::Member, compiled: &[RuleType], entries: Vec<Entry>) -> Result<()> {
        let bundle = self.bundle.clone();
        let ctx = self.ctx()?;
        let mut keys: Vec<String> = Vec::new();
        ctx.stats.entries_read += entries.len() as u64;
        for e in &entries {
            let (rule_type, kind, key, flags, value_json, added) = match e {
                Entry::Changed(c) => (
                    RuleType::parse(&c.rule_type),
                    c.kind.as_str(),
                    c.key.as_str(),
                    c.flags,
                    c.value_json.as_str(),
                    c.added,
                ),
                Entry::Current {
                    rule_type,
                    key,
                    kind,
                    flags,
                    value_json,
                } => (
                    Some(*rule_type),
                    kind.as_str(),
                    key.as_str(),
                    *flags,
                    value_json.as_str(),
                    true,
                ),
            };
            let Some(rt) = rule_type else { continue };
            if rt == RuleType::Browser {
                if m.takes(RuleType::Browser) {
                    ctx.touched.browser = true;
                }
                continue;
            }
            if !compiled.contains(&rt) {
                continue;
            }
            let t = source::touch(kind, key, rt.as_str(), flags, value_json);
            if let Some(k) = t.key {
                keys.push(k);
            }
            ctx.touched.pattern |= t.pattern;
            ctx.touched.ip |= t.ip;
            if added {
                super::guard::check_entry(ctx, m, rt, kind, key, flags, value_json);
            }
        }
        keys.sort();
        keys.dedup();
        ctx.stats.changed_keys += keys.len() as u64;
        self.state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                insert_keys(&tx, &bundle, &keys)?;
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        Ok(())
    }

    /// Adds each changed key's listed descendants (bundles.md §2 "Changed keys": a prefix scan of
    /// `feed_entries` on the reversed name), bounded per step (core.md §3): at most
    /// [`DESCENDANTS_PER_STEP`] changed keys and [`DESCENDANT_ROWS_PER_STEP`] scanned rows, a key
    /// with more descendants continuing in the next step from where its scan stopped. A changed key
    /// below another changed key is skipped: its descendants are among its ancestor's, which sorts
    /// first; so are the descendants this phase adds.
    async fn expand(&mut self, at: ExpandAt) -> Result<Phase> {
        let bundle = self.bundle.clone();
        let ctx = self.ctx()?;
        // Member feeds whose `dns` rules the bundle compiles, with their snapshot runs.
        let feeds: HashMap<String, i64> = {
            let view = View::new(&ctx.spec, &ctx.runs);
            view.feeds()
                .filter(|(f, _)| {
                    ctx.spec
                        .member(f)
                        .is_some_and(|m| ctx.spec.compiled_types(m).contains(&RuleType::Dns))
                })
                .map(|(f, r)| (f.to_string(), r))
                .collect()
        };
        if feeds.is_empty() {
            return Ok(Phase::Keys {
                cursor: String::new(),
            });
        }
        let (next, added) = self
            .state
            .db
            .read(move |c| expand_step(c, &bundle, &feeds, at))
            .await?;
        if !added.is_empty() {
            self.insert_descendants(added).await?;
        }
        Ok(match next {
            Some(at) => Phase::Expand(at),
            None => Phase::Keys {
                cursor: String::new(),
            },
        })
    }

    /// Adds descendants found by an expand step to the changed keys.
    async fn insert_descendants(&mut self, keys: Vec<String>) -> Result<()> {
        let bundle = self.bundle.clone();
        let n = self
            .state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let mut st = tx.prepare_cached(
                    "INSERT OR IGNORE INTO bundle_build_keys(bundle_id, key) VALUES (?1, ?2)",
                )?;
                let mut n = 0usize;
                for k in &keys {
                    n += st.execute(params![bundle, k])?;
                }
                drop(st);
                tx.commit()?;
                Ok::<_, anyhow::Error>(n)
            })
            .await?;
        self.ctx()?.stats.changed_keys += n as u64;
        Ok(())
    }

    /// Compiles one chunk of changed keys (bundles.md §2 steps 1–3).
    async fn keys(&mut self, cursor: String) -> Result<Phase> {
        let bundle = self.bundle.clone();
        let ctx = self.ctx()?;
        let input = KeyPass {
            bundle: bundle.clone(),
            spec: ctx.spec.clone(),
            runs: ctx.runs.clone(),
            wide: ctx.wide.clone(),
            seed: ctx.seed,
            mode: ctx.mode,
            hot_dir: ctx.hot_dir.clone(),
            cold_dir: ctx.cold_dir.clone(),
            cutoffs: ctx.state.tier.clone(),
            edge: ctx.spec.has_edge_bundle(),
        };
        let mut rich = ctx.rich.take().ok_or_else(|| anyhow!("rich builder missing"))?;
        let cur = cursor.clone();
        let (out, rich_back) = self
            .state
            .db
            .read(move |c| {
                let r = key_pass(c, &input, &cur, &mut rich);
                Ok::<_, anyhow::Error>((r, rich))
            })
            .await?;
        let ctx = self.ctx()?;
        ctx.rich = Some(rich_back);
        let out = out?;
        ctx.counts.badfiltered += out.counts.badfiltered;
        ctx.counts.entity_refused += out.counts.entity_refused;
        ctx.counts.unlinked += out.counts.unlinked;
        ctx.bad_rows += out.bad;
        ctx.stats.pruned += out.pruned;
        for o in &out.ops {
            match (o.old, o.new) {
                (None, Some(_)) => ctx.stats.keys_added += 1,
                (Some(_), None) => ctx.stats.keys_deleted += 1,
                (Some(a), Some(b)) => {
                    if a.0 != b.0 {
                        ctx.stats.moves += 1;
                    }
                    if a.2 != b.2 {
                        ctx.stats.keys_changed += 1;
                    }
                }
                (None, None) => {}
            }
        }
        let direct = ctx.mode == Mode::Fresh;
        let last = out.last.clone();
        let ops = out.ops;
        self.state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                if direct {
                    store::insert_keys_direct(&tx, &bundle, &ops)?;
                } else {
                    store::insert_ops(&tx, &bundle, &ops)?;
                }
                tx.commit()?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        Ok(match last {
            Some(k) => Phase::Keys { cursor: k },
            None => Phase::Ips,
        })
    }
}

/// Where expanding stands: the last changed key taken, and the scan of the one in progress.
#[derive(Clone, Debug, Default)]
pub struct ExpandAt {
    /// The last changed key taken (keys after it are still to look at).
    cursor: String,
    /// The changed key whose descendants are being scanned, and the scan's position in
    /// `feed_entries` (key, rowid).
    root: Option<(String, String, i64)>,
}

/// One expand step: returns where to go on (`None`: done) and the descendants found.
fn expand_step(
    c: &rusqlite::Connection,
    bundle: &str,
    feeds: &HashMap<String, i64>,
    mut at: ExpandAt,
) -> Result<(Option<ExpandAt>, Vec<String>)> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut rows_left = DESCENDANT_ROWS_PER_STEP;
    let mut roots_left = DESCENDANTS_PER_STEP;
    let mut next_key = c.prepare_cached(
        "SELECT key FROM bundle_build_keys WHERE bundle_id = ?1 AND key > ?2 ORDER BY key LIMIT 1",
    )?;
    let mut is_key = c.prepare_cached("SELECT 1 FROM bundle_build_keys WHERE bundle_id = ?1 AND key = ?2")?;
    // The key index's range in key order; other rule types are skipped here, not in SQL, so the
    // planner keeps to that index and every row read counts against the step.
    let mut scan = c.prepare_cached(
        "SELECT key, id, feed_id, first_run, removed_run, rule_type FROM feed_entries
         WHERE key >= ?1 AND key < ?2 AND (key > ?1 OR id > ?3)
         ORDER BY key, id LIMIT ?4",
    )?;
    while rows_left > 0 {
        let (root, mut from_key, mut from_id) = match at.root.take() {
            Some(r) => r,
            None => {
                if roots_left == 0 {
                    break;
                }
                let Some(k): Option<String> = next_key
                    .query_row(params![bundle, at.cursor], |r| r.get(0))
                    .optional()?
                else {
                    return Ok((None, found.into_iter().collect()));
                };
                at.cursor = k.clone();
                roots_left -= 1;
                // Below a changed key (or a descendant just added): covered by that key's scan.
                let mut covered = false;
                let mut s: &str = &k;
                while let Some(i) = s.rfind('.') {
                    s = &s[..i];
                    if found.contains(s) || is_key.exists(params![bundle, s])? {
                        covered = true;
                        break;
                    }
                }
                if covered {
                    continue;
                }
                (k.clone(), format!("{k}."), -1)
            }
        };
        let hi = format!("{root}/");
        let limit = rows_left;
        let mut n = 0usize;
        let mut rows = scan.query(params![from_key, hi, from_id, limit])?;
        while let Some(r) = rows.next()? {
            n += 1;
            let key: String = r.get(0)?;
            let id: i64 = r.get(1)?;
            let feed: String = r.get(2)?;
            let first_run: i64 = r.get(3)?;
            let removed: Option<i64> = r.get(4)?;
            let rule_type: String = r.get(5)?;
            if rule_type == "dns"
                && let Some(run) = feeds.get(&feed)
                && first_run <= *run
                && removed.is_none_or(|x| x > *run)
            {
                found.insert(key.clone());
            }
            from_key = key;
            from_id = id;
        }
        rows_left -= n;
        if n == limit {
            // The budget ran out inside this key's scan: it goes on from here next step.
            at.root = Some((root, from_key, from_id));
            break;
        }
    }
    Ok((Some(at), found.into_iter().collect()))
}

/// One page entry the collect phase classifies.
enum Entry {
    Changed(source::Changed),
    Current {
        rule_type: RuleType,
        key: String,
        kind: String,
        flags: u16,
        value_json: String,
    },
}

fn insert_keys(tx: &rusqlite::Transaction<'_>, bundle: &str, keys: &[String]) -> rusqlite::Result<()> {
    let mut st =
        tx.prepare_cached("INSERT OR IGNORE INTO bundle_build_keys(bundle_id, key) VALUES (?1, ?2)")?;
    for k in keys {
        st.execute(params![bundle, k])?;
    }
    Ok(())
}

impl Ctx {
    /// The domain keys of the bundle-wide rules (their rich rules follow the orders and the
    /// entity table, so every build recomputes them).
    fn wide_keys(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .wide
            .orders
            .keys()
            .chain(self.wide.refused.iter())
            .filter_map(|o| match o.kind {
                "name" | "host_mapping" => Some(o.key.clone()),
                "ip_literal" => Some(picket_rules::name::reverse_dotted(&o.key)),
                _ => None,
            })
            .collect();
        v.extend(self.wide.entity_keys.iter().cloned());
        v.sort();
        v.dedup();
        v
    }
}

/// The digest of the bundle-wide inputs the last build used.
fn state_digest(row: &Option<store::BuildRow>) -> Option<String> {
    row.as_ref()?
        .stats
        .as_ref()?
        .get("wide_digest")?
        .as_str()
        .map(str::to_string)
}

/// Entity keys one step of the bundle-wide pass reads the rules of.
pub const WIDE_KEYS_PER_STEP: usize = 2_000;

/// Where the bundle-wide pass stands.
enum WideAt {
    /// The `$dnsrewrite` rules (at most [`MAX_WIDE_RULES`]).
    Rewrites,
    /// The `$denyallow` entity rules (at most [`MAX_WIDE_RULES`]).
    Entities,
    /// The rules at the entity rules' keys, after this key.
    Keys(String),
    /// The patterns, when an entity rule is one.
    Patterns,
    /// The IP rules, when an entity rule is one: staged ([`super::ipfold`]), then read a range
    /// group at a time from this position.
    Ips(Option<super::ipfold::StageCursor>),
    Done,
}

/// The bundle-wide inputs (urlfilter's rewrite orders and the entity table, bundles.md §2;
/// rules.md §3) read a bounded step at a time (core.md §3): the rewrites, the entity rules, the
/// rules of their keys a page per step, their pattern and IP groups when there are any, then the
/// expansion. The same inputs as one read of everything.
pub struct WidePass {
    at: WideAt,
    action: Action,
    exact: bool,
    orders: HashMap<source::OrderKey, picket_rules::order::MatchOrder>,
    wanted: HashSet<source::OrderKey>,
    keys: BTreeSet<String>,
    pattern_group: bool,
    ip_group: bool,
    candidates: Vec<(source::OrderKey, picket_rules::rule::RichRule)>,
}

impl WidePass {
    pub fn new(action: Action) -> WidePass {
        WidePass {
            at: WideAt::Rewrites,
            action,
            exact: false,
            orders: HashMap::new(),
            wanted: HashSet::new(),
            keys: BTreeSet::new(),
            pattern_group: false,
            ip_group: false,
            candidates: Vec::new(),
        }
    }

    /// One step; the inputs and the rewrite rules the exact filing wants once done.
    async fn step(
        &mut self,
        state: &SharedState,
        ctx: &mut Ctx,
    ) -> Result<Option<(BundleWide, HashSet<source::OrderKey>)>> {
        let (spec, runs) = (ctx.spec.clone(), ctx.runs.clone());
        let action = self.action.0;
        match std::mem::replace(&mut self.at, WideAt::Done) {
            WideAt::Rewrites => {
                let (rewrites, bad) = state
                    .db
                    .read(move |c| {
                        let view = View::new(&spec, &runs);
                        let mut bad = 0u64;
                        let r = view
                            .rewrites(c, MAX_WIDE_RULES, &mut bad)?
                            .map_err(|n| anyhow!("more than {n} $dnsrewrite rules"))?;
                        Ok::<_, anyhow::Error>((r, bad))
                    })
                    .await?;
                ctx.bad_rows += bad;
                self.exact = compile::rewrites_may_overlap(&rewrites);
                // urlfilter's exact filing needs the whole bundle in bundle order: the order
                // phase streams it in bounded steps ([`OrderPass`]); otherwise ranks among the
                // rewrites do.
                if self.exact {
                    self.wanted = rewrites.iter().map(|r| r.order.clone()).collect();
                } else {
                    self.orders = compile::rank_orders(&rewrites);
                }
                self.at = WideAt::Entities;
            }
            WideAt::Entities => {
                let (rows, bad) = state
                    .db
                    .read(move |c| {
                        let view = View::new(&spec, &runs);
                        let mut bad = 0u64;
                        let r = view
                            .entity_rules(c, MAX_WIDE_RULES, &mut bad)?
                            .map_err(|n| anyhow!("more than {n} $denyallow entity rules"))?;
                        Ok::<_, anyhow::Error>((r, bad))
                    })
                    .await?;
                ctx.bad_rows += bad;
                for r in &rows {
                    match source::domain_key(&r.rule) {
                        Some(k) => {
                            self.keys.insert(k);
                        }
                        None => match r.rule.key_kind() {
                            picket_rules::Kind::Pattern | picket_rules::Kind::Regex => {
                                self.pattern_group = true
                            }
                            _ => self.ip_group = true,
                        },
                    }
                }
                self.at = WideAt::Keys(String::new());
            }
            WideAt::Keys(after) => {
                use std::ops::Bound::{Excluded, Unbounded};
                let page: Vec<String> = self
                    .keys
                    .range::<str, _>((Excluded(after.as_str()), Unbounded))
                    .take(state.compiler.step_rows(WIDE_KEYS_PER_STEP))
                    .cloned()
                    .collect();
                let last = page.last().cloned();
                let (cands, bad) = state
                    .db
                    .read(move |c| {
                        let view = View::new(&spec, &runs);
                        let mut bad = 0u64;
                        let mut out = Vec::new();
                        for k in &page {
                            let group = view.key_rules(c, k, &mut bad)?;
                            out.extend(compile::entity_candidates(action, &group));
                        }
                        Ok::<_, anyhow::Error>((out, bad))
                    })
                    .await?;
                ctx.bad_rows += bad;
                self.candidates.extend(cands);
                self.at = match last {
                    Some(k) => WideAt::Keys(k),
                    None if self.pattern_group => WideAt::Patterns,
                    None if self.ip_group => WideAt::Ips(None),
                    None => return Ok(Some(self.finish())),
                };
            }
            WideAt::Patterns => {
                let (cands, bad) = state
                    .db
                    .read(move |c| {
                        let view = View::new(&spec, &runs);
                        let mut bad = 0u64;
                        let pats = view
                            .patterns(c, MAX_PATTERN_RULES, &mut bad)?
                            .map_err(|n| anyhow!("more than {n} pattern rules"))?;
                        Ok::<_, anyhow::Error>((compile::entity_candidates(action, &pats), bad))
                    })
                    .await?;
                ctx.bad_rows += bad;
                self.candidates.extend(cands);
                self.at = if self.ip_group {
                    WideAt::Ips(None)
                } else {
                    return Ok(Some(self.finish()));
                };
            }
            WideAt::Ips(None) => {
                // `$badfilter` only relates rules of one range: the staged groups give the
                // candidates the whole IP group would.
                self.at = if super::ipfold::load_step(state, ctx).await? {
                    WideAt::Ips(Some(super::ipfold::fam_start(0)))
                } else {
                    WideAt::Ips(None)
                };
            }
            WideAt::Ips(Some(cursor)) => {
                let bundle = ctx.spec.id.clone();
                let rows = state.compiler.step_rows(super::ipfold::FOLD_ROWS);
                let (cands, next, bad) = state
                    .db
                    .read(move |c| {
                        let mut bad = 0u64;
                        let (groups, cur, next) =
                            super::ipfold::read_groups(c, &bundle, &cursor, rows, &mut bad)?;
                        let mut out = Vec::new();
                        for g in &groups {
                            out.extend(compile::entity_candidates(action, g));
                        }
                        let next = next.map(|(fam, _)| {
                            if fam == cur.0 {
                                cur
                            } else {
                                super::ipfold::fam_start(fam)
                            }
                        });
                        Ok::<_, anyhow::Error>((out, next, bad))
                    })
                    .await?;
                ctx.bad_rows += bad;
                self.candidates.extend(cands);
                self.at = match next {
                    Some(c) => WideAt::Ips(Some(c)),
                    None => return Ok(Some(self.finish())),
                };
            }
            WideAt::Done => return Ok(Some(self.finish())),
        }
        Ok(None)
    }

    /// The expansion of the candidates' entities within the cap, and the inputs.
    fn finish(&mut self) -> (BundleWide, HashSet<source::OrderKey>) {
        let mut candidates = std::mem::take(&mut self.candidates);
        let (entities, refused) = compile::expand_entities(crate::psl::rules_list(), &mut candidates);
        (
            BundleWide {
                action: self.action,
                orders: std::mem::take(&mut self.orders),
                exact_orders: self.exact,
                entities,
                refused,
                entity_keys: std::mem::take(&mut self.keys).into_iter().collect(),
            },
            std::mem::take(&mut self.wanted),
        )
    }
}

/// The digest of everything the bundle-wide inputs decide.
fn wide_digest(w: &BundleWide) -> String {
    let mut d: Vec<String> = w.orders.iter().map(|(k, o)| format!("{k:?}={o:?}")).collect();
    d.sort();
    let mut r: Vec<String> = w.refused.iter().map(|k| format!("{k:?}")).collect();
    r.sort();
    let ent = serde_json::to_string(&w.entities).unwrap_or_default();
    picket_api::ids::object_id(format!("{}|{d:?}|{r:?}|{ent}", w.exact_orders).as_bytes())
}

/// urlfilter's exact filing of the bundle's rules (rules.md §3–§4), streamed in bundle order a page
/// per step (core.md §3): the filer's state carries over between steps, and the orders of the
/// `$dnsrewrite` rules are kept. The same result as one pass over the whole bundle.
pub struct OrderPass {
    filer: picket_rules::order::OrderFiler,
    wanted: HashSet<source::OrderKey>,
    orders: HashMap<source::OrderKey, picket_rules::order::MatchOrder>,
    /// The member feed being read (index into the view's feeds) and its cursor.
    feed: usize,
    cursor: Option<source::OrderCursor>,
    wide: BundleWide,
}

/// The key pass's inputs (owned: it runs on a read connection's thread).
struct KeyPass {
    bundle: String,
    spec: Spec,
    runs: Runs,
    wide: Arc<BundleWide>,
    seed: u64,
    mode: Mode,
    hot_dir: ShardDir,
    cold_dir: Option<ShardDir>,
    cutoffs: Option<store::TierCutoffs>,
    edge: bool,
}

struct KeyPassOut {
    ops: Vec<Op>,
    /// The last key of the chunk (`None`: the pass is done).
    last: Option<String>,
    counts: CompileCounts,
    bad: u64,
    pruned: u64,
}

/// Compiles the chunk of changed keys after `cursor` (sorted, so a key's ancestors come before
/// it): each key's merged value, its part, subsumption pruning against its ancestors' new kept
/// state, and an op where its (part, value), tier or rank changes.
fn key_pass(
    c: &rusqlite::Connection,
    p: &KeyPass,
    cursor: &str,
    rich: &mut RichBuilder,
) -> Result<KeyPassOut> {
    let keys: Vec<String> = {
        let mut st = c.prepare_cached(
            "SELECT key FROM bundle_build_keys WHERE bundle_id = ?1 AND key > ?2 ORDER BY key LIMIT ?3",
        )?;
        st.query_map(params![p.bundle, cursor, KEYS_PER_STEP], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let view = View::new(&p.spec, &p.runs);
    let mut out = KeyPassOut {
        ops: Vec::new(),
        last: if keys.len() >= KEYS_PER_STEP {
            keys.last().cloned()
        } else {
            None
        },
        counts: CompileCounts::default(),
        bad: 0,
        pruned: 0,
    };
    // Kept (part, flags) of keys this chunk computed: their descendants later in the chunk read
    // them here.
    let mut local: HashMap<String, Option<(Part, Flags)>> = HashMap::new();
    let tiers: HashMap<&str, Tier> = p.spec.members.iter().map(|m| (m.feed.as_str(), m.tier)).collect();
    for key in keys {
        if !picket_bundle::delta::valid_key(key.as_bytes()) {
            out.bad += 1;
            continue;
        }
        let rows = view.key_rules(c, &key, &mut out.bad)?;
        let kv = compile::compile_key(&p.wide, &rows, &mut out.counts);
        let old = if p.mode == Mode::Fresh {
            None
        } else {
            store::key_state(c, &p.bundle, &key)?
        };
        let hash = KeyHash::of(p.seed, key.as_bytes());
        let new = match &kv {
            None => None,
            Some(kv) => {
                let (part, tier, rank_at) = super::tier::place(
                    c,
                    &p.bundle,
                    &p.spec,
                    p.cutoffs.as_ref(),
                    kv,
                    &rows,
                    &tiers,
                    old.as_ref(),
                    hash,
                )?;
                // Ancestors' kept state (bundles.md §2 subsumption pruning).
                let mut ancestors: Vec<(Flags, Part)> = Vec::new();
                let mut s: &str = &key;
                while let Some(i) = s.rfind('.') {
                    s = &s[..i];
                    if let Some(st) = ancestor_state(c, p, &local, s)? {
                        ancestors.push((st.1, st.0));
                    }
                }
                let flags = kv.flags;
                if is_subsumed(flags, covering_subs(part, &ancestors)) {
                    out.pruned += 1;
                    None
                } else {
                    let value = if kv.rich.is_empty() {
                        picket_bundle::Value::flags_only(flags)
                    } else {
                        picket_bundle::Value::new(flags | Flags::HAS_RICH, rich.set(&kv.rich))
                    };
                    Some((part, value.0, tier, rank_at))
                }
            }
        };
        local.insert(
            key.clone(),
            new.as_ref()
                .map(|(pt, v, _, _)| (*pt, picket_bundle::Value::from_stored(*v).flags())),
        );
        let shard_for = |part: Part| -> u32 {
            if !p.edge {
                0
            } else if p.mode == Mode::Fresh {
                PROVISIONAL + u32::from(hash.dir_index())
            } else {
                match part {
                    Part::Hot => p.hot_dir.shard_of(hash),
                    Part::Cold => p.cold_dir.as_ref().map_or(0, |d| d.shard_of(hash)),
                }
            }
        };
        let new_state = new.as_ref().map(|(pt, v, _, _)| {
            // A key keeping its part keeps its shard (the directory only changes in a plan).
            let shard = match &old {
                Some(o) if o.part == *pt => o.shard,
                _ => shard_for(*pt),
            };
            (*pt, shard, *v)
        });
        let old_state = old.as_ref().map(|o| (o.part, o.shard, o.value));
        let (tier, rank_at) = new
            .as_ref()
            .map(|(_, _, t, r)| (t.clone(), r.clone()))
            .unwrap_or((None, None));
        let meta_changed = old
            .as_ref()
            .is_some_and(|o| o.tier != tier || o.rank_at != rank_at);
        if old_state != new_state || meta_changed {
            out.ops.push(Op {
                key: key.clone(),
                hash128: hash.0.to_be_bytes(),
                old: old_state,
                new: new_state,
                tier,
                rank_at,
            });
        }
    }
    Ok(out)
}

/// An ancestor's new kept (part, flags): this chunk's result, else the build's op, else its
/// unchanged materialised state.
fn ancestor_state(
    c: &rusqlite::Connection,
    p: &KeyPass,
    local: &HashMap<String, Option<(Part, Flags)>>,
    key: &str,
) -> Result<Option<(Part, Flags)>> {
    if let Some(s) = local.get(key) {
        return Ok(*s);
    }
    let fresh = p.mode == Mode::Fresh;
    if !fresh && let Some(op) = store::op_new(c, &p.bundle, key)? {
        return Ok(op.map(|(pt, v)| (pt, picket_bundle::Value::from_stored(v).flags())));
    }
    Ok(store::key_state_in(c, store::keys_table(fresh), &p.bundle, key)?
        .map(|s: KeyState| (s.part, picket_bundle::Value::from_stored(s.value).flags())))
}

impl HeavyJob for BuildJob {
    fn kind(&self) -> &str {
        super::JOB_KIND
    }

    fn target(&self) -> &str {
        &self.bundle
    }

    fn step(&mut self) -> BoxFuture<'_, Result<Step>> {
        Box::pin(async move {
            match self.run_step().await {
                Ok(s) => Ok(s),
                // A step that failed because a config restore took its rows away: the build
                // ends as one a restore ended, not as a failure (core.md §2).
                Err(_)
                    if self
                        .ctx
                        .as_deref()
                        .is_some_and(|c| !self.state.restore.is_current(c.generation)) =>
                {
                    self.restored().await?;
                    Ok(Step::Done)
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    tracing::warn!(bundle = %self.bundle, error = %msg, "bundle build failed; the previous version stays");
                    super::fail(&self.state, &self.bundle, &msg).await;
                    self.ctx = None;
                    self.phase = Phase::Done;
                    Ok(Step::Done)
                }
            }
        })
    }
}
