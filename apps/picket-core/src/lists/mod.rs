//! Browser lists (bundles.md §8; core.md §1 `lists`, §12): one per bundle that takes `browser`
//! rules, and two (pruned and full) per profile with `browser_list` on, served under `/lists/*`
//! on the web port and the plain-HTTP port behind `lists.allow_cidrs`.
//!
//! | Module | Job |
//! |---|---|
//! | this one | the runtime: rebuild triggers and debounce, the DNS-change tracking of pruned lists, the jobs that write the files, the DNS oracle over `bundle_keys` |
//! | [`render`] | the list text: conversion, exact cancellation, pruning, warnings (pure) |
//! | [`serve`] | `GET /lists/<bundle>.txt`, `/lists/profiles/<profile>.txt`, `…-full.txt` |
//!
//! **Builds** (heavy lane P0, debounced 10 s): a bundle list after a build that read changed
//! `browser` entries; a profile's lists when one of its bundles' `browser` rules change, or its
//! allow or block bundles, `browser_list`, or forward zones change. Each build is a [`ListJob`] in
//! bounded steps (core.md §3): a page of rules per step, the pruning check a bundle per step, the
//! list itself a bounded amount of work per step ([`render`]'s builders), then the files.
//! **DNS changes** rebuild pruned lists by name: core keeps the names each profile's rules refer
//! to ([`Tracked`]; past [`MAX_NAMES`], every change counts), and a build whose changed keys hold
//! one of them, a parent or a name below one (or too many keys to tell), or that wrote a new
//! `patterns.bin` or `rich.json`, schedules a rebuild, at most once per
//! `lists.profile_recheck_interval` and no later than one interval after the change. At start
//! every list is rebuilt once, which also fills the name sets.
//!
//! **DNS-blocked names** ([`DbDns`]): conditions 1–4 of bundles.md §8 over `bundle_keys`; an IP
//! host is never DNS-blocked (a browser never resolves it), and a name's scope isn't when an
//! allow-level subdomain flag at the name or a parent outranks the block for names below it.
//!
//! **Files:** `lists/<bundle>.txt` and `lists/profiles/<profile>.txt` / `<profile>-full.txt`, each
//! with a gzip copy, written atomically; `browser_lists` holds each served list's BLAKE3 (its
//! ETag), time and counts (rules, added, removed; profile lists also the blocks an allow cancels,
//! the rules dropped in conversion and, pruned, the rules left out as DNS-blocked).

pub mod render;
pub mod serve;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use anyhow::Result;
use picket_rules::compile::decide_keys;
use picket_rules::{Flags, RuleName};
use rusqlite::{Connection, params};
use serde_json::json;

use crate::alerts::{Changes, RaiseSpec, Severity};
use crate::compiler::spec::{self, Spec};
use crate::config::model::{BundleAction, Model};
use crate::scheduler::{Debouncer, Priority};
use crate::state::{AppState, SharedState};
use render::{DnsOracle, Source};

/// Debounce of list rebuilds (bundles.md §8).
pub const DEBOUNCE: Duration = Duration::from_secs(10);
/// The most `browser` rules one list reads (README §2 Bounded).
pub const MAX_RULES: usize = 2_000_000;
/// Names kept per profile for DNS-change tracking (README §2 Bounded; ~60 B each). A profile
/// whose rules refer to more is tracked as "every DNS change" instead ([`Tracked::All`]).
pub const MAX_NAMES: usize = 500_000;
/// Changed keys a build hands over for DNS-change tracking; past it every pruned list using the
/// bundle is rebuilt (rate-limited).
pub const MAX_CHANGED_KEYS: usize = 100_000;

/// What a profile's pruned list tracks for DNS changes (bundles.md §8 Builds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tracked {
    /// The reversed names its rules refer to.
    Names(BTreeSet<String>),
    /// More names than [`MAX_NAMES`]: any DNS change of one of its bundles rebuilds it
    /// (rate-limited like the others), so no rule stays pruned after its block goes.
    All,
}

impl Tracked {
    /// Tracking for these names (as the rules write them).
    pub fn of<'a>(names: impl IntoIterator<Item = &'a String>) -> Tracked {
        let mut set = BTreeSet::new();
        for n in names {
            let Ok(r) = RuleName::parse(n) else { continue };
            if set.len() >= MAX_NAMES && !set.contains(&r.reversed()) {
                return Tracked::All;
            }
            set.insert(r.reversed());
        }
        Tracked::Names(set)
    }

    /// True when changed key `k` may change the list.
    pub fn touched_by(&self, k: &str) -> bool {
        match self {
            Tracked::All => true,
            Tracked::Names(n) => touches(n, k),
        }
    }
}

/// The lists runtime, one per running core.
#[derive(Default)]
pub struct Lists {
    debounce: OnceLock<Debouncer<String>>,
    /// Profile → what its pruned list tracks for DNS changes.
    names: Mutex<HashMap<String, Tracked>>,
    /// Profile → when its pruned list was last rebuilt for a DNS change.
    last_dns: Mutex<HashMap<String, tokio::time::Instant>>,
    /// Profiles with a DNS-change rebuild scheduled.
    pending_dns: Mutex<HashSet<String>>,
    /// A digest of each profile's list inputs, to see configuration changes.
    profile_digests: Mutex<HashMap<String, String>>,
}

impl Lists {
    fn trigger(&self, key: String) {
        if let Some(d) = self.debounce.get()
            && !d.trigger(key.clone())
        {
            tracing::warn!(list = %key, "too many browser-list rebuilds pending");
        }
    }

    /// After a bundle's build: rewrite its list if its `browser` rules changed, the lists of the
    /// profiles using it, and schedule DNS-change rebuilds of pruned lists whose names the
    /// changed keys touch (`None`: too many keys to tell), or of every pruned list using the
    /// bundle when its `patterns.bin` or `rich.json` changed (`segments_changed`, bundles.md §8
    /// Builds).
    pub async fn bundle_built(
        &self,
        state: &SharedState,
        bundle: &str,
        browser_changed: bool,
        changed_keys: Option<&[String]>,
        segments_changed: bool,
    ) {
        let Ok(model) = state.config.model().await else {
            self.trigger(format!("bundle:{bundle}"));
            return;
        };
        let profiles: Vec<String> = model
            .profiles
            .values()
            .filter(|p| p.browser_list.enabled)
            .filter(|p| {
                p.edge
                    .allow
                    .iter()
                    .chain(p.edge.block.iter())
                    .any(|b| b == bundle)
            })
            .map(|p| p.id.clone())
            .collect();
        if browser_changed {
            self.trigger(format!("bundle:{bundle}"));
            for p in &profiles {
                self.trigger(format!("profile:{p}"));
            }
        }
        if let Some(keys) = changed_keys
            && keys.is_empty()
            && !segments_changed
        {
            return;
        }
        for p in profiles {
            let touches = match changed_keys {
                _ if segments_changed => true,
                None => true,
                Some(keys) => self
                    .names
                    .lock()
                    .map(|m| m.get(&p).is_some_and(|t| keys.iter().any(|k| t.touched_by(k))))
                    .unwrap_or(true),
            };
            if touches {
                self.dns_changed(state, &p);
            }
        }
    }

    /// A DNS change for profile `p`'s pruned list: rebuild at most once per recheck interval, no
    /// later than one interval after the change.
    fn dns_changed(&self, state: &SharedState, p: &str) {
        let interval = state.settings().lists.profile_recheck_interval.as_duration();
        let now = tokio::time::Instant::now();
        let last = self.last_dns.lock().ok().and_then(|m| m.get(p).copied());
        let due = last.map_or(now, |l| l + interval);
        if due <= now {
            if let Ok(mut m) = self.last_dns.lock() {
                m.insert(p.to_string(), now);
            }
            self.trigger(format!("profile:{p}"));
            return;
        }
        let first = self
            .pending_dns
            .lock()
            .map(|mut s| s.insert(p.to_string()))
            .unwrap_or(false);
        if !first {
            return;
        }
        let st = state.clone();
        let p = p.to_string();
        tokio::spawn(async move {
            tokio::select! {
                _ = st.shutdown.cancelled() => return,
                _ = tokio::time::sleep_until(due) => {}
            }
            if let Ok(mut s) = st.lists.pending_dns.lock() {
                s.remove(&p);
            }
            if let Ok(mut m) = st.lists.last_dns.lock() {
                m.insert(p.clone(), tokio::time::Instant::now());
            }
            st.lists.trigger(format!("profile:{p}"));
        });
    }
}

/// True when changed key `k` is one of the names, a parent of one, or a name below one (all
/// reversed).
fn touches(names: &BTreeSet<String>, k: &str) -> bool {
    if names.contains(k) {
        return true;
    }
    // A name below k: names in (k., k/).
    let lo = format!("{k}.");
    let hi = format!("{k}/");
    if names.range(lo..hi).next().is_some() {
        return true;
    }
    // k below a name: some proper prefix of k at a label boundary is a name.
    let mut s: &str = k;
    while let Some(i) = s.rfind('.') {
        s = &s[..i];
        if names.contains(s) {
            return true;
        }
    }
    false
}

/// The lists directory.
pub fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join("lists")
}

/// Starts the lists runtime: the debounce, the configuration watch, and a rebuild of every list.
pub async fn start(state: &SharedState) -> Result<()> {
    let weak: Weak<AppState> = Arc::downgrade(state);
    let d = Debouncer::with_max_wait(DEBOUNCE, DEBOUNCE.saturating_mul(6), move |key: String| {
        let Some(st) = weak.upgrade() else { return };
        submit(&st, &key);
    });
    let _ = state.lists.debounce.set(d);
    crate::util::ensure_dir(&dir(&state.data_dir).join("profiles"))?;
    // At start, every list once (fills the name sets).
    let model = state.config.model().await?;
    for id in model.bundles.keys() {
        submit(state, &format!("bundle:{id}"));
    }
    for p in model.profiles.keys() {
        submit(state, &format!("profile:{p}"));
    }
    remember_digests(state, &model);
    let st = state.clone();
    tokio::spawn(async move {
        let mut rx = st.config.subscribe();
        loop {
            tokio::select! {
                _ = st.shutdown.cancelled() => return,
                r = rx.changed() => if r.is_err() { return },
            }
            let Ok(model) = st.config.model().await else {
                continue;
            };
            for p in changed_profiles(&st, &model) {
                st.lists.trigger(format!("profile:{p}"));
            }
            // Deleted bundles' lists go; bundles whose browser selection changed rebuild with
            // their build.
            for id in stale_bundle_lists(&st, &model).await {
                st.lists.trigger(format!("bundle:{id}"));
            }
        }
    });
    Ok(())
}

/// A digest of what a profile's lists depend on in the configuration.
fn profile_digest(model: &Model, p: &crate::config::model::ProfileDef) -> String {
    let zones: Vec<Option<String>> = p
        .edge
        .forward_zones
        .iter()
        .map(|z| model.forward_zones.get(z).map(|d| d.zone.clone()))
        .collect();
    // Each bundle's action and members with the rule types it takes from each: a member that
    // stops (or starts) giving `browser` rules changes the lists (bundles.md §8 Builds).
    type Members = Vec<(String, Vec<&'static str>)>;
    let bundles: Vec<Option<(String, Members)>> = p
        .edge
        .allow
        .iter()
        .chain(p.edge.block.iter())
        .map(|b| {
            model.bundles.get(b).map(|d| {
                let spec = Spec::of(d, model);
                (
                    d.action.as_str().to_string(),
                    spec.members
                        .iter()
                        .map(|m| (m.feed.clone(), m.types.iter().map(|t| t.as_str()).collect()))
                        .collect(),
                )
            })
        })
        .collect();
    let v = json!({
        "enabled": p.browser_list.enabled, "allow": p.edge.allow, "block": p.edge.block,
        "trial": p.trial_bundles, "zones": zones, "bundles": bundles,
    });
    picket_api::ids::object_id(&picket_api::ids::canonical_json(&v))
}

fn remember_digests(state: &SharedState, model: &Model) {
    if let Ok(mut m) = state.lists.profile_digests.lock() {
        *m = model
            .profiles
            .values()
            .map(|p| (p.id.clone(), profile_digest(model, p)))
            .collect();
    }
}

/// Profiles whose list inputs changed (or that were added or deleted) since the last look.
fn changed_profiles(state: &SharedState, model: &Model) -> Vec<String> {
    let Ok(mut m) = state.lists.profile_digests.lock() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let now: HashMap<String, String> = model
        .profiles
        .values()
        .map(|p| (p.id.clone(), profile_digest(model, p)))
        .collect();
    for (id, d) in &now {
        if m.get(id) != Some(d) {
            out.push(id.clone());
        }
    }
    for id in m.keys() {
        if !now.contains_key(id) {
            out.push(id.clone());
        }
    }
    *m = now;
    out
}

/// Bundle lists whose bundle is gone or no longer takes `browser` rules.
async fn stale_bundle_lists(state: &SharedState, model: &Model) -> Vec<String> {
    let rows: Vec<String> = state
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT target FROM browser_lists WHERE kind = 'bundle'")?;
            let v = st
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap_or_default();
    rows.into_iter()
        .filter(|b| {
            model
                .bundles
                .get(b)
                .is_none_or(|d| !Spec::of(d, model).has_browser_list())
        })
        .collect()
}

/// Queues the job for `key` (`bundle:<id>` or `profile:<id>`).
fn submit(state: &SharedState, key: &str) {
    state
        .scheduler
        .heavy
        .submit(Priority::P0, Box::new(ListJob::new(state.clone(), key)));
}

/// `browser` rows one step of a list job reads (core.md §3: bounded steps).
pub const LIST_ROWS_PER_STEP: usize = 50_000;

/// A list's `browser` rules read a page per step (core.md §3), each bundle at its feeds' runs
/// when the job started, in bundle order: member position, line, text. Each page is sorted and
/// merged into its feed's rules so far in linear time (no step sorts a whole feed).
struct SourceRead {
    specs: Vec<(Spec, Runs, Vec<usize>)>,
    si: usize,
    mi: usize,
    cursor: (String, i64),
    feed: Vec<(i64, String)>,
    out: Vec<Vec<Source>>,
    total: usize,
}

type Runs = crate::compiler::spec::Runs;

impl SourceRead {
    fn new(c: &Connection, specs: &[Spec]) -> Result<SourceRead> {
        let mut v = Vec::new();
        for s in specs {
            let runs = spec::snapshot(c, s)?;
            let mut members: Vec<usize> = (0..s.members.len())
                .filter(|i| s.members[*i].takes(picket_rules::RuleType::Browser))
                .collect();
            members.sort_by_key(|i| s.members[*i].position);
            v.push((s.clone(), runs, members));
        }
        Ok(SourceRead {
            out: vec![Vec::new(); v.len()],
            specs: v,
            si: 0,
            mi: 0,
            cursor: (String::new(), -1),
            feed: Vec::new(),
            total: 0,
        })
    }

    /// One page; `true` when every bundle is read.
    fn step(&mut self, c: &Connection) -> Result<bool> {
        let Some((spec, runs, members)) = self.specs.get(self.si) else {
            return Ok(true);
        };
        let Some(m) = members.get(self.mi).map(|i| &spec.members[*i]) else {
            self.si += 1;
            self.mi = 0;
            return Ok(self.si >= self.specs.len());
        };
        let run = runs.get(&m.feed).copied().unwrap_or(0);
        let mut st = c.prepare_cached(
            "SELECT key, id, coalesce(line_no, 0) FROM feed_entries WHERE feed_id = ?1 AND rule_type = 'browser'
               AND key >= ?3 AND (key > ?3 OR id > ?4)
               AND first_run <= ?2 AND (removed_run IS NULL OR removed_run > ?2) ORDER BY key, id LIMIT ?5",
        )?;
        let mut rows = st.query(params![
            m.feed,
            run,
            self.cursor.0,
            self.cursor.1,
            LIST_ROWS_PER_STEP
        ])?;
        let mut page: Vec<(i64, String)> = Vec::new();
        while let Some(r) = rows.next()? {
            let key: String = r.get(0)?;
            self.cursor = (key.clone(), r.get(1)?);
            page.push((r.get(2)?, key));
        }
        let n = page.len();
        self.total += n;
        if self.total > MAX_RULES {
            anyhow::bail!("bundle {} has more than {MAX_RULES} browser rules", spec.id);
        }
        page.sort();
        let old = std::mem::take(&mut self.feed);
        let mut merged = Vec::with_capacity(old.len() + page.len());
        let (mut a, mut b) = (old.into_iter().peekable(), page.into_iter().peekable());
        loop {
            let take_a = match (a.peek(), b.peek()) {
                (Some(x), Some(y)) => x <= y,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            merged.extend(if take_a { a.next() } else { b.next() });
        }
        self.feed = merged;
        if n < LIST_ROWS_PER_STEP {
            let feed = std::mem::take(&mut self.feed);
            let out = &mut self.out[self.si];
            out.extend(feed.into_iter().map(|(_, text)| Source {
                bundle: spec.id.clone(),
                feed: m.feed.clone(),
                text,
            }));
            self.mi += 1;
            self.cursor = (String::new(), -1);
        }
        Ok(false)
    }
}

/// Where a list job stands.
enum LPhase {
    Setup,
    /// Reading the bundles' rules (a bundle list: its own; a profile list: its allow bundles,
    /// then its block bundles).
    Read(Box<SourceRead>),
    /// A profile list: which bundles' patterns keep pruning off (one bundle per step).
    NoPrune {
        i: usize,
    },
    Bundle(Box<render::BundleListBuild>),
    Profile(Box<render::ProfileListBuild>),
    Done,
}

/// One list build (bundles.md §8 Builds), a heavy-lane P0 job in bounded steps (core.md §3):
/// set-up, a page of rules per step, the pruning check per bundle, the list built a bounded
/// amount of work per step ([`render::STEP_WORK`]), then the files.
pub struct ListJob {
    state: SharedState,
    key: String,
    phase: LPhase,
    model: Option<Arc<Model>>,
    /// A bundle list of an allow bundle (its rules written as exceptions).
    allow_list: bool,
    allow_specs: Vec<Spec>,
    block_specs: Vec<Spec>,
    /// A profile list's rules once read, until the pruning check is done: (allow, block).
    pending: Option<(Vec<Source>, Vec<Source>)>,
    dns: DnsCarry,
}

impl ListJob {
    pub fn new(state: SharedState, key: &str) -> Self {
        Self {
            state,
            key: key.to_string(),
            phase: LPhase::Setup,
            model: None,
            allow_list: false,
            allow_specs: Vec::new(),
            block_specs: Vec::new(),
            pending: None,
            dns: DnsCarry::default(),
        }
    }

    /// Runs every step (the triggers queue the job; tests and callers that need the list now).
    pub async fn run(mut self) -> Result<()> {
        while self.run_step().await? == crate::scheduler::Step::More {}
        Ok(())
    }

    async fn run_step(&mut self) -> Result<crate::scheduler::Step> {
        use crate::scheduler::Step;
        let phase = std::mem::replace(&mut self.phase, LPhase::Done);
        self.phase = match phase {
            LPhase::Setup => {
                let key = self.key.clone();
                match key.split_once(':') {
                    Some(("bundle", b)) => self.setup_bundle(b).await?,
                    Some(("profile", p)) => self.setup_profile(p).await?,
                    _ => LPhase::Done,
                }
            }
            LPhase::Read(mut r) => {
                let (r2, done) = self
                    .state
                    .db
                    .read(move |c| {
                        let done = r.step(c)?;
                        Ok::<_, anyhow::Error>((r, done))
                    })
                    .await?;
                if !done {
                    LPhase::Read(r2)
                } else {
                    let mut out = r2.out;
                    if self.key.starts_with("bundle:") {
                        LPhase::Bundle(Box::new(render::BundleListBuild::new(
                            self.allow_list,
                            out.pop().unwrap_or_default(),
                        )))
                    } else {
                        let block: Vec<Source> = out
                            .split_off(self.allow_specs.len())
                            .into_iter()
                            .flatten()
                            .collect();
                        let allow: Vec<Source> = out.into_iter().flatten().collect();
                        self.pending = Some((allow, block));
                        LPhase::NoPrune { i: 0 }
                    }
                }
            }
            LPhase::NoPrune { i } => {
                let spec = self
                    .allow_specs
                    .iter()
                    .chain(self.block_specs.iter())
                    .nth(i)
                    .cloned();
                match spec {
                    Some(s) if !self.dns.no_prune => {
                        let no = self.state.db.read(move |c| prevents_pruning(c, &s)).await?;
                        self.dns.no_prune |= no;
                        LPhase::NoPrune { i: i + 1 }
                    }
                    _ => {
                        let (allow, block) = self.pending.take().unwrap_or_default();
                        LPhase::Profile(Box::new(render::ProfileListBuild::new(allow, block)))
                    }
                }
            }
            LPhase::Bundle(mut b) => {
                if b.step(render::STEP_WORK) {
                    self.write_bundle(b.finish()).await?;
                    LPhase::Done
                } else {
                    LPhase::Bundle(b)
                }
            }
            LPhase::Profile(b) => {
                let carry = std::mem::take(&mut self.dns);
                let (b, carry, done) = self
                    .state
                    .db
                    .read(move |c| {
                        let mut b = b;
                        let mut dns = DbDns { c, s: carry };
                        let done = b.step(&mut dns, render::STEP_WORK);
                        Ok::<_, anyhow::Error>((b, dns.s, done))
                    })
                    .await?;
                self.dns = carry;
                if done {
                    self.write_profile(b.finish()).await?;
                    LPhase::Done
                } else {
                    LPhase::Profile(b)
                }
            }
            LPhase::Done => LPhase::Done,
        };
        Ok(if matches!(self.phase, LPhase::Done) {
            Step::Done
        } else {
            Step::More
        })
    }

    async fn setup_bundle(&mut self, bundle: &str) -> Result<LPhase> {
        let model = self.state.config.model().await?;
        let path = format!("lists/{bundle}.txt");
        let spec = model.bundles.get(bundle).map(|d| Spec::of(d, &model));
        let Some(spec) = spec.filter(Spec::has_browser_list) else {
            write_lists(
                &self.state,
                vec![],
                vec![],
                format!("bundle/{bundle}"),
                vec![path],
            )
            .await?;
            return Ok(LPhase::Done);
        };
        self.allow_list = spec.action == BundleAction::Allow;
        self.model = Some(Arc::new(model));
        let specs = vec![spec];
        let r = self.state.db.read(move |c| SourceRead::new(c, &specs)).await?;
        Ok(LPhase::Read(Box::new(r)))
    }

    async fn setup_profile(&mut self, profile: &str) -> Result<LPhase> {
        let model = self.state.config.model().await?;
        let pruned_path = format!("lists/profiles/{profile}.txt");
        let full_path = format!("lists/profiles/{profile}-full.txt");
        let Some(p) = model
            .profiles
            .get(profile)
            .filter(|p| p.browser_list.enabled)
            .cloned()
        else {
            if let Ok(mut m) = self.state.lists.names.lock() {
                m.remove(profile);
            }
            write_lists(
                &self.state,
                vec![],
                vec![],
                format!("profile/{profile}"),
                vec![pruned_path, full_path],
            )
            .await?;
            return Ok(LPhase::Done);
        };
        let specs = |ids: &[String], action: BundleAction| -> Vec<Spec> {
            ids.iter()
                .filter(|b| !p.trial_bundles.contains(b))
                .filter_map(|b| model.bundles.get(b))
                .filter(|d| d.action == action)
                .map(|d| Spec::of(d, &model))
                .collect()
        };
        self.allow_specs = specs(&p.edge.allow, BundleAction::Allow);
        self.block_specs = specs(&p.edge.block, BundleAction::Block);
        self.dns = DnsCarry {
            allow: self.allow_specs.iter().map(|s| s.id.clone()).collect(),
            block: self.block_specs.iter().map(|s| s.id.clone()).collect(),
            zones: p
                .edge
                .forward_zones
                .iter()
                .filter_map(|z| model.forward_zones.get(z).map(|d| d.zone.clone()))
                .collect(),
            ..DnsCarry::default()
        };
        self.model = Some(Arc::new(model));
        let all: Vec<Spec> = self
            .allow_specs
            .iter()
            .chain(self.block_specs.iter())
            .cloned()
            .collect();
        let r = self.state.db.read(move |c| SourceRead::new(c, &all)).await?;
        Ok(LPhase::Read(Box::new(r)))
    }

    async fn write_bundle(&self, out: render::BundleList) -> Result<()> {
        let bundle = self.key.trim_start_matches("bundle:").to_string();
        let warnings = out
            .warnings
            .iter()
            .map(|w| {
                (
                    format!(
                        "Bundle {bundle}'s browser list: a rule of feed {} cancels rules of other feeds",
                        w.feed
                    ),
                    None,
                    w.clone(),
                )
            })
            .collect();
        write_lists(
            &self.state,
            vec![Written {
                path: format!("lists/{bundle}.txt"),
                kind: "bundle",
                target: bundle.clone(),
                lines: out.lines,
                title: format!("Picket {bundle}"),
                extra: json!({"dropped": out.dropped}),
            }],
            warnings,
            format!("bundle/{bundle}"),
            vec![],
        )
        .await
    }

    async fn write_profile(&self, out: render::ProfileLists) -> Result<()> {
        let profile = self.key.trim_start_matches("profile:").to_string();
        // Names for DNS-change tracking (reversed, as keys; past the cap, every change).
        let tracked = Tracked::of(out.names.iter());
        if tracked == Tracked::All {
            tracing::info!(profile = %profile, limit = MAX_NAMES,
                "a profile's browser rules name too many hosts to track; every DNS change rebuilds its pruned list");
        }
        if let Ok(mut m) = self.state.lists.names.lock() {
            m.insert(profile.clone(), tracked);
        }
        let warnings = out
            .warnings
            .iter()
            .map(|w| {
                let title = match w.kind {
                    "allow_defeated" => format!(
                        "Profile {profile}: an allow in bundle {} is defeated by DNS; allow the name in an allow bundle",
                        w.bundle
                    ),
                    _ => format!(
                        "Profile {profile}: an exception in bundle {} cancels rules of another block bundle",
                        w.bundle
                    ),
                };
                (title, Some(profile.clone()), w.clone())
            })
            .collect();
        let extra = json!({"cancelled": out.cancelled, "dropped": out.dropped});
        let mut pruned_extra = extra.clone();
        if let Some(o) = pruned_extra.as_object_mut() {
            o.insert("dns_blocked".into(), json!(out.dns_blocked));
        }
        write_lists(
            &self.state,
            vec![
                Written {
                    path: format!("lists/profiles/{profile}.txt"),
                    kind: "profile",
                    target: profile.clone(),
                    lines: out.pruned,
                    title: format!("Picket profile {profile}"),
                    extra: pruned_extra,
                },
                Written {
                    path: format!("lists/profiles/{profile}-full.txt"),
                    kind: "profile_full",
                    target: profile.clone(),
                    lines: out.full,
                    title: format!("Picket profile {profile} (full)"),
                    extra,
                },
            ],
            warnings,
            format!("profile/{profile}"),
            vec![],
        )
        .await
    }
}

impl crate::scheduler::HeavyJob for ListJob {
    fn kind(&self) -> &str {
        "browser_list"
    }

    fn target(&self) -> &str {
        &self.key
    }

    fn step(&mut self) -> crate::scheduler::BoxFuture<'_, Result<crate::scheduler::Step>> {
        Box::pin(self.run_step())
    }

    /// A newer build of the same list reads everything again.
    fn supersedable(&self) -> bool {
        true
    }
}

/// True when bundle `s`'s patterns keep a profile list from pruning (bundles.md §8 condition 3:
/// any pattern in an allow bundle, an exception or `$dnsrewrite` pattern in a block bundle; core
/// doesn't analyse patterns, which only keeps rules).
fn prevents_pruning(c: &Connection, s: &Spec) -> Result<bool> {
    let runs = spec::snapshot(c, s)?;
    let view = crate::compiler::source::View::new(s, &runs);
    let mut bad = 0u64;
    let Ok(pats) = view.patterns(c, crate::compiler::build::MAX_PATTERN_RULES, &mut bad)? else {
        return Ok(true);
    };
    Ok(if s.action == BundleAction::Allow {
        !pats.is_empty()
    } else {
        pats.iter().any(|r| r.rule.is_exception() || r.rule.is_rewrite())
    })
}

/// What one written list records.
struct Written {
    path: String,
    kind: &'static str,
    target: String,
    lines: Vec<String>,
    title: String,
    extra: serde_json::Value,
}

/// Writes lists (text and gzip copy) and their rows, and applies their warnings: new ones raise
/// `bundle_warning`, the list's others resolve.
async fn write_lists(
    state: &SharedState,
    lists: Vec<Written>,
    warnings: Vec<(String, Option<String>, render::ListWarning)>,
    warning_scope: String,
    removed: Vec<String>,
) -> Result<()> {
    let at = jiff::Timestamp::now();
    let dd = state.data_dir.clone();
    let mut rows = Vec::new();
    for l in lists {
        let path = dd.join(&l.path);
        // Reading the old list, rendering, gzipping, hashing and writing are blocking work: off
        // the async workers, so a large list doesn't stall the runtime (README §2 Bounded).
        let n_rules = l.lines.len();
        let (title, lines) = (l.title, l.lines);
        let (added, removed_n, b3) =
            tokio::task::spawn_blocking(move || -> Result<(usize, usize, String)> {
                let previous: HashSet<String> = std::fs::read_to_string(&path)
                    .map(|t| {
                        t.lines()
                            .filter(|x| !x.starts_with('!'))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let text = render::text(&title, at, &lines);
                let now_set: HashSet<&String> = lines.iter().collect();
                let added = lines.iter().filter(|x| !previous.contains(*x)).count();
                let removed_n = previous.iter().filter(|x| !now_set.contains(x)).count();
                let bytes = text.into_bytes();
                let gz = {
                    use std::io::Write;
                    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    e.write_all(&bytes)?;
                    e.finish()?
                };
                if let Some(parent) = path.parent() {
                    crate::util::ensure_dir(parent)?;
                }
                crate::util::write_atomic(&path, &bytes, 0o644)?;
                let mut gzp = path.clone().into_os_string();
                gzp.push(".gz");
                crate::util::write_atomic(Path::new(&gzp), &gz, 0o644)?;
                Ok((added, removed_n, picket_api::ids::object_id(&bytes)))
            })
            .await??;
        let mut stats = json!({"rules": n_rules, "added": added, "removed": removed_n});
        if let (Some(o), Some(e)) = (stats.as_object_mut(), l.extra.as_object()) {
            o.extend(e.clone());
        }
        rows.push((
            l.path,
            l.kind,
            l.target,
            b3,
            render::version(&at),
            stats.to_string(),
        ));
    }
    let alerts = state.alerts.clone();
    let now = crate::util::ts(&at);
    let removed_paths = removed.clone();
    let ch = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            for (path, kind, target, b3, version, stats) in &rows {
                tx.execute(
                    "INSERT INTO browser_lists(path, kind, target, blake3, written_at, version, stats_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(path) DO UPDATE SET kind = ?2, target = ?3, blake3 = ?4, written_at = ?5,
                       version = ?6, stats_json = ?7",
                    params![path, kind, target, b3, now, version, stats],
                )?;
            }
            for p in &removed_paths {
                tx.execute("DELETE FROM browser_lists WHERE path = ?1", [p])?;
            }
            // Warnings: raise the new, resolve this list's others.
            let mut ch = Changes::default();
            let prefix = format!("bundle_warning:list:{warning_scope}:");
            let mut keep: BTreeSet<String> = BTreeSet::new();
            for (title, profile, w) in &warnings {
                let id = picket_api::ids::object_id(format!("{}|{}|{}", w.kind, w.rule, w.feed).as_bytes());
                let key = format!("{prefix}{}", &id[..16]);
                keep.insert(key.clone());
                if crate::alerts::Alerts::is_open_in(&tx, &key)? {
                    continue;
                }
                let spec = RaiseSpec::new(
                    "bundle_warning",
                    Severity::Warning,
                    key,
                    title.clone(),
                    json!({"warning": format!("browser_{}", w.kind), "rule": w.rule, "feed": w.feed,
                           "bundle": w.bundle, "profile": profile, "detail": w.detail}),
                )
                .bundle(w.bundle.clone());
                alerts.raise_in(&tx, &spec, &mut ch)?;
            }
            let open: Vec<String> = {
                let mut st = tx.prepare(
                    "SELECT dedupe_key FROM alerts WHERE state = 'open' AND kind = 'bundle_warning'
                       AND substr(dedupe_key, 1, length(?1)) = ?1",
                )?;
                st.query_map([&prefix], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for k in open {
                if !keep.contains(&k) {
                    alerts.resolve_in(&tx, &k, Some(&json!({"cleared": now})), &mut ch)?;
                }
            }
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    if !removed.is_empty() {
        // Unlinks are blocking calls too: off the async workers with the rest.
        tokio::task::spawn_blocking(move || {
            for p in removed {
                let path = dd.join(&p);
                let _ = std::fs::remove_file(&path);
                let mut gz = path.into_os_string();
                gz.push(".gz");
                let _ = std::fs::remove_file(gz);
            }
        })
        .await?;
    }
    Ok(())
}

/// Writes (or removes) a bundle's list now (every step of its job).
pub async fn build_bundle_list(state: &SharedState, bundle: &str) -> Result<()> {
    ListJob::new(state.clone(), &format!("bundle:{bundle}"))
        .run()
        .await
}

/// Writes (or removes) a profile's two lists now (every step of its job).
pub async fn build_profile_lists(state: &SharedState, profile: &str) -> Result<()> {
    ListJob::new(state.clone(), &format!("profile:{profile}"))
        .run()
        .await
}

/// A name's verdict: the bundle blocking its whole scope, and the one blocking the name itself
/// with whether that block covers every subdomain.
type Verdict = (Option<String>, Option<(String, bool)>);

/// What a profile list's DNS oracle carries between the job's steps: the bundles, the forward
/// zones, whether patterns keep pruning off, and the verdicts so far.
#[derive(Default)]
struct DnsCarry {
    allow: Vec<String>,
    block: Vec<String>,
    zones: Vec<String>,
    no_prune: bool,
    cache: HashMap<String, Verdict>,
}

/// DNS-blocked names over the profile's bundles' materialised keys (bundles.md §8 "DNS-blocked
/// names"). Patterns aren't analysed: if an allow bundle has any, or a block bundle an exception
/// or `$dnsrewrite` pattern, nothing counts as DNS-blocked (that only keeps rules).
struct DbDns<'a> {
    c: &'a Connection,
    s: DnsCarry,
}

impl<'a> DbDns<'a> {
    fn flags(&self, bundle: &str, key: &str) -> Flags {
        self.c
            .query_row(
                "SELECT value FROM bundle_keys WHERE bundle_id = ?1 AND key = ?2 LIMIT 1",
                params![bundle, key],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| picket_bundle::Value::from_stored(v.cast_unsigned()).flags())
            .unwrap_or(Flags::NONE)
    }

    fn any_below(&self, bundle: &str, key: &str, mask: i64) -> bool {
        self.c
            .query_row(
                "SELECT 1 FROM bundle_keys WHERE bundle_id = ?1 AND key > ?2 AND key < ?3 AND (value & ?4) <> 0 LIMIT 1",
                params![bundle, format!("{key}."), format!("{key}/"), mask],
                |_| Ok(()),
            )
            .is_ok()
    }

    /// Condition 1: the block bundle that blocks the name by flag level, and whether that block
    /// covers every subdomain (condition 2).
    fn name_decision(&mut self, key: &str) -> Option<(String, bool)> {
        let parents: Vec<String> = {
            let mut v = Vec::new();
            let mut s: &str = key;
            while let Some(i) = s.rfind('.') {
                s = &s[..i];
                v.push(s.to_string());
            }
            v
        };
        // An allow-bundle key at the name (any flags) or above it with a subdomain flag.
        for a in &self.s.allow {
            if !self.flags(a, key).and(Flags::ALL_LEVELS).is_empty()
                || self.flags(a, key).contains(Flags::HAS_RICH)
            {
                return None;
            }
            if parents.iter().any(|p| !self.flags(a, p).subs().is_empty()) {
                return None;
            }
        }
        for b in &self.s.block {
            let at = self.flags(b, key);
            let up = parents
                .iter()
                .fold(Flags::NONE, |acc, p| acc.union(self.flags(b, p)));
            match decide_keys(at, up) {
                Some(d) if !d.level.is_allow() => return Some((b.clone(), d.covers_subdomains)),
                Some(_) | None => continue,
            }
        }
        None
    }

    /// Whether a generic name below `key` resolves to a block (condition 2 below the name): in
    /// the first block bundle that decides it, from the subdomain flags at the name and its
    /// parents, by flag level. An allow-level subdomain flag at the name (`@@*.tracker.example^`
    /// beside `||tracker.example^`) lets every subdomain resolve.
    fn subdomains_blocked(&self, key: &str, parents: &[String]) -> bool {
        for b in &self.s.block {
            let up = parents
                .iter()
                .fold(self.flags(b, key), |acc, p| acc.union(self.flags(b, p)));
            match decide_keys(Flags::NONE, up) {
                Some(d) => return !d.level.is_allow(),
                None => continue,
            }
        }
        false
    }

    fn evaluate(&mut self, name: &str) -> Verdict {
        if let Some(r) = self.s.cache.get(name) {
            return r.clone();
        }
        // A browser never asks DNS for an IP host (`||1.2.3.4^`, `1.2.3.4##.ad`), whatever key
        // its address folds into: it is never DNS-blocked (bundles.md §8, a rule goes only when
        // DNS blocks its whole scope).
        if is_ip_host(name) {
            return (None, None);
        }
        let Ok(rn) = RuleName::parse(name) else {
            return (None, None);
        };
        let key = rn.reversed();
        let decision = self.name_decision(&key);
        let scope = (|| {
            if self.s.no_prune {
                return None;
            }
            let (b, covers) = decision.clone()?;
            if !covers {
                return None;
            }
            let parents: Vec<String> = {
                let mut v = Vec::new();
                let mut s: &str = &key;
                while let Some(i) = s.rfind('.') {
                    s = &s[..i];
                    v.push(s.to_string());
                }
                v
            };
            if !self.subdomains_blocked(&key, &parents) {
                return None;
            }
            // Condition 4: no forward zone is the name, a parent, or below it.
            if self.s.zones.iter().any(|z| {
                let z = z.trim_end_matches('.').to_ascii_lowercase();
                z == name || name.ends_with(&format!(".{z}")) || z.ends_with(&format!(".{name}"))
            }) {
                return None;
            }
            // Condition 3: nothing in the scope can resolve.
            let all: Vec<String> = self.s.allow.iter().chain(self.s.block.iter()).cloned().collect();
            for a in &self.s.allow {
                if self.any_below(a, &key, 0xffff) {
                    return None;
                }
            }
            for bb in &self.s.block {
                if self.any_below(bb, &key, i64::from(Flags::ALL_ALLOW.bits())) {
                    return None;
                }
            }
            let mut s: &str = &key;
            loop {
                if all.iter().any(|x| self.flags(x, s).contains(Flags::HAS_RICH)) {
                    return None;
                }
                match s.rfind('.') {
                    Some(i) => s = &s[..i],
                    None => break,
                }
            }
            if all
                .iter()
                .any(|x| self.any_below(x, &key, i64::from(Flags::HAS_RICH.bits())))
            {
                return None;
            }
            Some(b)
        })();
        let r = (scope, decision);
        if self.s.cache.len() < MAX_NAMES {
            self.s.cache.insert(name.to_string(), r.clone());
        }
        r
    }
}

/// True when a browser takes `host` as an IP address and never resolves it: an IPv4 or IPv6
/// literal, or a name ending in a number (WHATWG URL host parsing reads `1.2.3`, `10.0x1` and
/// `example.123` as IPv4 or refuses them).
fn is_ip_host(host: &str) -> bool {
    let h = host.strip_suffix('.').unwrap_or(host);
    if h.starts_with('[') || h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let last = h.rsplit('.').next().unwrap_or("");
    let hex = last.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("0x"))
        && last.bytes().skip(2).all(|b| b.is_ascii_hexdigit());
    !last.is_empty() && (last.bytes().all(|b| b.is_ascii_digit()) || hex)
}

impl DnsOracle for DbDns<'_> {
    fn scope_blocked(&mut self, name: &str) -> Option<String> {
        self.evaluate(name).0
    }
    fn name_blocked(&mut self, name: &str) -> Option<String> {
        self.evaluate(name).1.map(|(b, _)| b)
    }
}

/// Every served list's row (UI).
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct ListView {
    /// The URL path (`/lists/…`).
    pub url: String,
    /// `bundle`, `profile` (pruned) or `profile_full`.
    pub kind: String,
    pub target: String,
    pub blake3: String,
    pub written_at: String,
    pub version: String,
    pub stats: Option<serde_json::Value>,
}

/// Every served list.
pub async fn views(state: &SharedState) -> Result<Vec<ListView>> {
    state
        .db
        .read(|c| {
            let mut st = c.prepare(
                "SELECT path, kind, target, blake3, written_at, version, stats_json FROM browser_lists ORDER BY path",
            )?;
            let v = st
                .query_map([], |r| {
                    Ok(ListView {
                        url: format!("/{}", r.get::<_, String>(0)?),
                        kind: r.get(1)?,
                        target: r.get(2)?,
                        blake3: r.get(3)?,
                        written_at: r.get(4)?,
                        version: r.get(5)?,
                        stats: r.get::<_, Option<String>>(6)?.and_then(|s| serde_json::from_str(&s).ok()),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_hosts_are_never_resolved() {
        for h in [
            "1.2.3.4",
            "1.2.3.4.",
            "[2001:db8::1]",
            "1.2.3",
            "10.0x1f",
            "example.123",
            "a.0x",
        ] {
            assert!(is_ip_host(h), "{h}");
        }
        for h in [
            "example.com",
            "1.2.3.example",
            "0xexample.com",
            "x123.example",
            "example.x123",
        ] {
            assert!(!is_ip_host(h), "{h}");
        }
    }

    /// Past the cap, every DNS change counts (review round 2, CR4): a rule for a host past it
    /// is never left pruned after its block goes.
    #[test]
    fn tracking_past_the_cap_takes_every_change() {
        let names: Vec<String> = (0..=MAX_NAMES).map(|i| format!("h{i}.example")).collect();
        let t = Tracked::of(names.iter());
        assert_eq!(t, Tracked::All);
        assert!(t.touched_by("org.unrelated"));
        let t = Tracked::of(names[..10].iter());
        assert!(matches!(&t, Tracked::Names(n) if n.len() == 10));
        assert!(t.touched_by("example.h3") && !t.touched_by("org.unrelated"));
    }

    #[test]
    fn dns_change_tracking_by_name() {
        let names: BTreeSet<String> = ["com.example.ads".to_string()].into();
        assert!(touches(&names, "com.example.ads"), "the name");
        assert!(touches(&names, "com.example"), "a parent");
        assert!(touches(&names, "com.example.ads.x"), "below it");
        assert!(!touches(&names, "com.example.adsx"));
        assert!(!touches(&names, "org.example"));
    }
}
