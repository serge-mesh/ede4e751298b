//! Compile-time warnings (bundles.md §3, feeds.md §7; storage.md §3 `warnings`).
//!
//! A block-bundle key gets a **warning** for each warn bundle named in the `warn_on` of a feed
//! that lists it (kind `warn`), and for each allow bundle a profile lists with the block bundle
//! whose downloaded feeds match it (kind `allow`). A warn or allow bundle matches a key as it
//! would a query for the key's name (its rule at the name, or a subdomain rule above it, or one
//! of its patterns), and an IP rule when its range overlaps one of the bundle's IPs or CIDRs; it
//! takes from each member only the rule types the member selects (bundles.md §1 `rule_types`).
//! The key keeps blocking. A warning is keyed on (warn or allow bundle, value, feed) **per block
//! bundle** (two block bundles taking one feed with different rule types never clear or relabel
//! each other's); a new one raises `warninglist_hit` (per warn bundle and block feed) or
//! `allow_override` (per allow and block bundle). It resolves on its own once any of these stops
//! holding ([`holds`]): its block bundle exists and holds the feed, taking the entry's rule type;
//! the feed lists the entry; the feed's `warn_on` names the warn bundle (or some profile pairs
//! the allow bundle with the block bundle); some feed of the warn or allow bundle matches it.
//!
//! **When:** a block bundle's build checks every key it changed and, when IP rules may have
//! changed, its IP rules ([`WarnCheck`], build steps before assembly); after the build, a build
//! that changed its definition or its IP rules re-checks its open warnings ([`ResolveJob`]: the
//! feed left, an IP rule went), and so does its deletion. A build of a warn bundle or of an allow
//! bundle (with a downloaded feed, or warnings to resolve), and a configuration change of a
//! `warn_on` or of which allow bundles a profile pairs with which block bundles, re-check
//! ([`RecheckJob`], heavy lane P2): for each rule of the warn or allow bundle, the keys at (and
//! below, for a subdomain rule) its name; when it has patterns, every key of the block bundle;
//! its IP rules against the block bundle's; then its open warnings that no longer hold. These
//! checks add or resolve warnings only: no bundle is rebuilt.
//!
//! **Restarts** (README §2): every re-check is recorded in `warning_rechecks` before it is
//! queued and dropped when it finishes with no newer request; at start each recorded one runs
//! again, and a `warn_on` / pairing digest other than the stored one re-checks everything
//! ([`resume`]).
//!
//! **Bounded steps** (core.md §3): matchers load a page of keyed rules or IP rules per step
//! ([`MatcherLoad`], IP ranges merged in sorted pages), checks take a page of keys or IP rules
//! per step, and every step applies the warning changes it found in its own transaction, so no
//! check drops or caps keys (a warning reflects the feeds, not a version: a build that fails later
//! leaves correct warnings).
//!
//! Matching reads the warn or allow bundle's keyed rules into memory (at most
//! [`MAX_MATCHER_KEYS`]; past it the check is skipped and logged), its patterns through the
//! reference matcher, and its IP rules as a range index. `$badfilter` inside a warninglist is not
//! applied (a warninglist only warns).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use picket_rules::ip::IpRange;
use picket_rules::name::reverse_dotted;
use picket_rules::{BundleMatcher, Flags};
use rusqlite::{Connection, params};
use serde_json::json;

use super::source::View;
use super::spec::{self, Runs, Spec};
use crate::alerts::{Changes, RaiseSpec, Severity};
use crate::config::model::{BundleAction, Model};
use crate::scheduler::{BoxFuture, HeavyJob, Priority, Step};
use crate::state::SharedState;

/// Keyed rules one warn or allow bundle may hold in memory for matching.
pub const MAX_MATCHER_KEYS: usize = 2_000_000;
/// `feed_entries` rows one step reads while loading a matcher's keyed rules.
pub const MATCHER_ROWS_PER_STEP: usize = 100_000;
/// Keys (or candidates) one check step looks at.
pub const KEYS_PER_STEP: usize = 2_000;
/// `feed_entries` rows one step of a pattern re-check reads.
pub const SCAN_ROWS_PER_STEP: usize = 50_000;
/// Open warnings one resolve step re-checks.
pub const OPEN_PER_STEP: usize = 2_000;
/// IP rules one step reads: a matcher's while loading, or a block bundle's while checking them.
pub const IP_ROWS_PER_STEP: usize = 50_000;

/// One indexed range: first, last, feed index.
type Ranged = (u128, u128, u32);

/// A warn or allow bundle's IP rules, indexed for overlap queries.
#[derive(Default)]
struct IpIndex {
    feeds: Vec<String>,
    /// Per family (IPv4, IPv6): ranges sorted by first address, and for each position the range
    /// with the highest last address so far.
    v4: (Vec<Ranged>, Vec<usize>),
    v6: (Vec<Ranged>, Vec<usize>),
}

impl IpIndex {
    /// From ranges sorted by (first, last), equal ones in bundle order (linear: no sort here).
    fn from_sorted(feeds: Vec<String>, v4: Vec<Ranged>, v6: Vec<Ranged>) -> IpIndex {
        let index = |v: Vec<Ranged>| {
            let mut best: Vec<usize> = Vec::with_capacity(v.len());
            for i in 0..v.len() {
                let keep = match best.last() {
                    Some(&j) if v[j].1 >= v[i].1 => j,
                    _ => i,
                };
                best.push(keep);
            }
            (v, best)
        };
        IpIndex {
            feeds,
            v4: index(v4),
            v6: index(v6),
        }
    }

    fn is_empty(&self) -> bool {
        self.v4.0.is_empty() && self.v6.0.is_empty()
    }

    /// The feed of a range overlapping `r`, if any: among the ranges starting at or before `r`'s
    /// end, the one reaching furthest.
    fn find(&self, r: &IpRange) -> Option<&str> {
        let (v, best) = if r.v4 { &self.v4 } else { &self.v6 };
        let n = v.partition_point(|x| x.0 <= r.last);
        let j = *best.get(n.checked_sub(1)?)?;
        let (_, last, feed) = v.get(j)?;
        (*last >= r.first)
            .then(|| self.feeds.get(*feed as usize).map(String::as_str))
            .flatten()
    }
}

/// IP ranges gathered a page at a time (core.md §3: no step sorts the whole set): each page is
/// sorted and merged into the sorted ranges so far in linear time; on equal ranges the earlier
/// page stays first, so the order among them is bundle order (feeds in definition order).
#[derive(Default)]
struct IpAcc {
    feeds: Vec<String>,
    v4: Vec<Ranged>,
    v6: Vec<Ranged>,
}

impl IpAcc {
    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    fn add_page(&mut self, page: Vec<(IpRange, &str)>) {
        let (mut p4, mut p6): (Vec<Ranged>, Vec<Ranged>) = (Vec::new(), Vec::new());
        for (r, f) in page {
            let fi = match self.feeds.iter().position(|x| x == f) {
                Some(i) => i,
                None => {
                    self.feeds.push(f.to_string());
                    self.feeds.len() - 1
                }
            };
            let fi = u32::try_from(fi).unwrap_or(u32::MAX);
            if r.v4 {
                p4.push((r.first, r.last, fi));
            } else {
                p6.push((r.first, r.last, fi));
            }
        }
        for (acc, mut p) in [(&mut self.v4, p4), (&mut self.v6, p6)] {
            if p.is_empty() {
                continue;
            }
            p.sort_by_key(|a| (a.0, a.1));
            let old = std::mem::take(acc);
            let mut out = Vec::with_capacity(old.len() + p.len());
            let (mut i, mut j) = (0usize, 0usize);
            while i < old.len() || j < p.len() {
                let take_old = match (old.get(i), p.get(j)) {
                    (Some(a), Some(b)) => (a.0, a.1) <= (b.0, b.1),
                    (Some(_), None) => true,
                    _ => false,
                };
                if take_old {
                    out.push(old[i]);
                    i += 1;
                } else {
                    out.push(p[j]);
                    j += 1;
                }
            }
            *acc = out;
        }
    }

    fn finish(self) -> IpIndex {
        IpIndex::from_sorted(self.feeds, self.v4, self.v6)
    }
}

/// What matches for one warn or allow bundle.
pub struct Matcher {
    pub bundle: String,
    /// `warn` or `allow`.
    pub kind: &'static str,
    /// Reversed name → (union of level flags, the first feed listing it), in key order (the
    /// inverted re-check walks it from a cursor).
    keys: BTreeMap<String, (Flags, String)>,
    patterns: Option<BundleMatcher>,
    pattern_feeds: Vec<String>,
    ips: IpIndex,
}

impl Matcher {
    /// Reads `spec`'s rules at its current snapshot in one go (an allow bundle: its downloaded
    /// feeds only). Tests and small bundles; checks load through [`MatcherLoad`].
    pub fn load(c: &Connection, model: &Model, spec: &Spec) -> Result<Matcher> {
        let mut l = MatcherLoad::of(c, model, spec)?;
        loop {
            if let Some(m) = l.step(c)? {
                return m.ok_or_else(|| anyhow!("more than {MAX_MATCHER_KEYS} keyed rules"));
            }
        }
    }

    /// The feed of this bundle that matches the key's name, if any.
    pub fn matches_key(&self, key: &str) -> Option<String> {
        let mut applying = Flags::NONE;
        let mut feed: Option<&str> = None;
        if let Some((f, fd)) = self.keys.get(key) {
            if !f.exact().is_empty() {
                feed = Some(fd);
            }
            applying = applying.union(f.exact());
        }
        let mut s: &str = key;
        while let Some(i) = s.rfind('.') {
            s = &s[..i];
            if let Some((f, fd)) = self.keys.get(s) {
                if !f.subs().is_empty() && feed.is_none() {
                    feed = Some(fd);
                }
                applying = applying.union(f.subs_as_exact());
            }
        }
        let keyed = match applying.top_level() {
            None => false,
            Some(level) => self.kind == "allow" || !level.is_allow(),
        };
        if keyed {
            return feed.map(str::to_string);
        }
        let p = self.patterns.as_ref()?;
        let name = picket_rules::RuleName::from_reversed(key).ok()?;
        let r = p.match_key_any(&name);
        let decided = match self.kind {
            "allow" => r.decisive().next().is_some(),
            _ => r.outcome == picket_rules::Outcome::Block,
        };
        if !decided {
            return None;
        }
        r.decisive()
            .next()
            .and_then(|m| self.pattern_feeds.get(m.rule).cloned())
    }

    /// The feed of this bundle whose IP rule overlaps `range`, if any.
    pub fn matches_ip(&self, range: &IpRange) -> Option<String> {
        self.ips.find(range).map(str::to_string)
    }

    /// The first keyed rule after `after` (reversed name, flags), for the inverted re-check.
    fn keyed_after(&self, after: &str) -> Option<(&String, Flags)> {
        use std::ops::Bound::{Excluded, Unbounded};
        self.keys
            .range::<str, _>((Excluded(after), Unbounded))
            .next()
            .map(|(k, (f, _))| (k, *f))
    }

    fn has_patterns(&self) -> bool {
        self.patterns.is_some()
    }
}

/// Where a [`MatcherLoad`] stands.
enum LoadStage {
    /// Keyed rules of the members taking `dns` rules: member index and cursor (key, id).
    Keys { feed: usize, cursor: (String, i64) },
    /// The patterns, in one step (at most [`super::build::MAX_PATTERN_RULES`] rows).
    Patterns,
    /// IP rules of the members taking `ip` rules: member index, stored kind and entry id.
    Ips { feed: usize, kind: usize, cursor: i64 },
}

/// A [`Matcher`] read a page of keyed rules or IP rules per step (core.md §3), at one snapshot.
pub struct MatcherLoad {
    id: String,
    kind: &'static str,
    spec: Spec,
    runs: Runs,
    stage: LoadStage,
    keys: BTreeMap<String, (Flags, String)>,
    patterns: Option<BundleMatcher>,
    pattern_feeds: Vec<String>,
    ips: IpAcc,
}

impl MatcherLoad {
    /// Starts loading bundle `id` (`None` when it is gone).
    pub fn new(c: &Connection, model: &Model, id: &str) -> Result<Option<MatcherLoad>> {
        let Some(def) = model.bundles.get(id) else {
            return Ok(None);
        };
        Ok(Some(MatcherLoad::of(c, model, &Spec::of(def, model))?))
    }

    fn of(c: &Connection, _model: &Model, spec: &Spec) -> Result<MatcherLoad> {
        let kind = if spec.action == BundleAction::Allow {
            "allow"
        } else {
            "warn"
        };
        let mut s = spec.clone();
        if kind == "allow" {
            s.members.retain(|m| m.downloaded);
        }
        let runs = spec::snapshot(c, &s)?;
        Ok(MatcherLoad {
            id: spec.id.clone(),
            kind,
            spec: s,
            runs,
            stage: LoadStage::Keys {
                feed: 0,
                cursor: (String::new(), -1),
            },
            keys: BTreeMap::new(),
            patterns: None,
            pattern_feeds: Vec::new(),
            ips: IpAcc::default(),
        })
    }

    /// One step: `Some(Some(m))` when loaded, `Some(None)` when the bundle is too large to check,
    /// `None` while there is more to read.
    pub fn step(&mut self, c: &Connection) -> Result<Option<Option<Matcher>>> {
        let view = View::new(&self.spec, &self.runs);
        let mut bad = 0u64;
        match &mut self.stage {
            LoadStage::Keys { feed, cursor } => {
                // The members whose `dns` rules the bundle takes (bundles.md §1 rule_types): a
                // member selected only for its IP rules contributes no names.
                let feeds = feeds_taking(&self.spec, &view, picket_rules::RuleType::Dns);
                let Some((f, run)) = feeds.get(*feed) else {
                    self.stage = LoadStage::Patterns;
                    return Ok(None);
                };
                let mut st = c.prepare_cached(
                    "SELECT key, id, kind, flags, first_run, removed_run FROM feed_entries
                     WHERE feed_id = ?1 AND rule_type = 'dns' AND key >= ?2 AND (key > ?2 OR id > ?3)
                     ORDER BY key, id LIMIT ?4",
                )?;
                let mut rows = st.query(params![f, cursor.0, cursor.1, MATCHER_ROWS_PER_STEP])?;
                let mut n = 0usize;
                while let Some(r) = rows.next()? {
                    n += 1;
                    let key: String = r.get(0)?;
                    *cursor = (key.clone(), r.get(1)?);
                    let kind: String = r.get(2)?;
                    let first_run: i64 = r.get(4)?;
                    let removed: Option<i64> = r.get(5)?;
                    if (kind != "name" && kind != "host_mapping")
                        || first_run > *run
                        || removed.is_some_and(|x| x <= *run)
                    {
                        continue;
                    }
                    let flags = Flags(r.get(3)?).and(Flags::ALL_LEVELS);
                    if self.keys.len() >= MAX_MATCHER_KEYS && !self.keys.contains_key(&key) {
                        tracing::warn!(bundle = %self.id, limit = MAX_MATCHER_KEYS, "warn/allow bundle too large to check");
                        return Ok(Some(None));
                    }
                    let e = self.keys.entry(key).or_insert((Flags::NONE, f.clone()));
                    e.0 = e.0.union(flags);
                }
                if n < MATCHER_ROWS_PER_STEP {
                    *feed += 1;
                    *cursor = (String::new(), -1);
                }
                Ok(None)
            }
            LoadStage::Patterns => {
                let pats = match view.patterns(c, super::build::MAX_PATTERN_RULES, &mut bad)? {
                    Ok(p) => p,
                    Err(n) => {
                        tracing::warn!(bundle = %self.id, limit = n, "warn/allow bundle has too many patterns to check");
                        return Ok(Some(None));
                    }
                };
                self.pattern_feeds = pats.iter().map(|r| r.feed.clone()).collect();
                self.patterns = (!pats.is_empty()).then(|| {
                    BundleMatcher::new(
                        super::spec::rules_action(if self.kind == "allow" {
                            BundleAction::Allow
                        } else {
                            BundleAction::Block
                        }),
                        pats.into_iter().map(|r| r.rule).collect(),
                    )
                    .with_public_suffix_list(crate::psl::rules_list())
                });
                self.stage = LoadStage::Ips {
                    feed: 0,
                    kind: 0,
                    cursor: -1,
                };
                Ok(None)
            }
            LoadStage::Ips { feed, kind, cursor } => {
                let feeds = feeds_taking(&self.spec, &view, picket_rules::RuleType::Ip);
                let Some((f, _)) = feeds.get(*feed) else {
                    return Ok(Some(Some(Matcher {
                        bundle: self.id.clone(),
                        kind: self.kind,
                        keys: std::mem::take(&mut self.keys),
                        patterns: self.patterns.take(),
                        pattern_feeds: std::mem::take(&mut self.pattern_feeds),
                        ips: std::mem::take(&mut self.ips).finish(),
                    })));
                };
                let Some(k) = super::source::IP_KINDS.get(*kind) else {
                    *feed += 1;
                    *kind = 0;
                    *cursor = -1;
                    return Ok(None);
                };
                let (rows, next) = view.ip_page(c, f, k, *cursor, IP_ROWS_PER_STEP, &mut bad)?;
                let page: Vec<(IpRange, &str)> = rows
                    .iter()
                    .filter(|r| !r.rule.is_badfilter())
                    .filter_map(|r| r.rule.ip_range().map(|ip| (ip, r.feed.as_str())))
                    .collect();
                if self.ips.len() + page.len() > MAX_MATCHER_KEYS {
                    tracing::warn!(bundle = %self.id, limit = MAX_MATCHER_KEYS, "warn/allow bundle has too many IP rules to check");
                    return Ok(Some(None));
                }
                self.ips.add_page(page);
                match next {
                    Some(n) => *cursor = n,
                    None => {
                        *kind += 1;
                        *cursor = -1;
                    }
                }
                Ok(None)
            }
        }
    }
}

/// The view's member feeds whose `rt` rules the bundle compiles, with their snapshot runs.
fn feeds_taking(spec: &Spec, view: &View<'_>, rt: picket_rules::RuleType) -> Vec<(String, i64)> {
    view.feeds()
        .filter(|(f, _)| {
            spec.member(f)
                .is_some_and(|m| spec.compiled_types(m).contains(&rt))
        })
        .map(|(f, r)| (f.to_string(), r))
        .collect()
}

/// One warning change, applied in a transaction. Every warning belongs to one block bundle
/// (`bundle`): its identity is (kind, warn or allow bundle, value, feed, block bundle).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WarnOp {
    /// The warning holds (inserted when new, else `last_seen` refreshed).
    Hold {
        kind: &'static str,
        by_bundle: String,
        by_feed: String,
        value: String,
        feed: String,
        raw: String,
        bundle: String,
    },
    /// The warning no longer holds.
    Clear {
        kind: &'static str,
        by_bundle: String,
        value: String,
        feed: String,
        bundle: String,
    },
}

/// The warn bundles and allow bundles concerned with block bundle `bundle`: the warn bundles its
/// feeds' `warn_on` name (with those feeds), and the allow bundles a profile pairs with it.
pub fn concerned(model: &Model, bundle: &str) -> (BTreeMap<String, BTreeSet<String>>, BTreeSet<String>) {
    let mut warn: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Some(def) = model.bundles.get(bundle) else {
        return (warn, BTreeSet::new());
    };
    if def.action != BundleAction::Block {
        return (warn, BTreeSet::new());
    }
    for f in &def.feeds {
        if let Some(fd) = model.feeds.get(&f.feed) {
            for w in fd.effective_warn_on() {
                if model
                    .bundles
                    .get(&w)
                    .is_some_and(|b| b.action == BundleAction::Warn)
                {
                    warn.entry(w).or_default().insert(f.feed.clone());
                }
            }
        }
    }
    let mut allow = BTreeSet::new();
    for p in model.profiles.values() {
        if p.edge.block.iter().any(|b| b == bundle) || p.trial_bundles.iter().any(|b| b == bundle) {
            for a in &p.edge.allow {
                if model
                    .bundles
                    .get(a)
                    .is_some_and(|b| b.action == BundleAction::Allow)
                {
                    allow.insert(a.clone());
                }
            }
        }
    }
    (warn, allow)
}

/// Where a block bundle's IP rules are being read: member index (among those taking `ip`
/// rules), stored kind and entry id.
#[derive(Clone, Copy, Debug)]
struct IpAt {
    feed: usize,
    kind: usize,
    cursor: i64,
}

impl IpAt {
    const START: IpAt = IpAt {
        feed: 0,
        kind: 0,
        cursor: -1,
    };
}

/// One page of `view`'s IP rules from `at`; returns the rows and where to go on (`None`: done).
fn ip_rules_page(
    c: &Connection,
    view: &View<'_>,
    at: IpAt,
) -> Result<(Vec<super::source::Row>, Option<IpAt>)> {
    let feeds = feeds_taking(view.spec, view, picket_rules::RuleType::Ip);
    let mut at = at;
    loop {
        let Some((f, _)) = feeds.get(at.feed) else {
            return Ok((Vec::new(), None));
        };
        let Some(k) = super::source::IP_KINDS.get(at.kind) else {
            at = IpAt {
                feed: at.feed + 1,
                ..IpAt::START
            };
            continue;
        };
        let mut bad = 0u64;
        let (rows, next) = view.ip_page(c, f, k, at.cursor, IP_ROWS_PER_STEP, &mut bad)?;
        let next = match next {
            Some(n) => IpAt { cursor: n, ..at },
            None => IpAt {
                kind: at.kind + 1,
                cursor: -1,
                ..at
            },
        };
        return Ok((rows, Some(next)));
    }
}

/// A block bundle build's warning check (bundles.md §3 "When"; build step 2), a bounded step at a
/// time: the matchers of the warn and allow bundles concerned load page by page, then every
/// changed key is checked a page per step, then (when IP rules may have changed) its IP rules a
/// page per step. Each step applies what it found.
pub struct WarnCheck {
    warn: BTreeMap<String, BTreeSet<String>>,
    ids: Vec<String>,
    next: usize,
    loading: Option<MatcherLoad>,
    loaded: BTreeMap<String, Option<Matcher>>,
    matchers: Option<Arc<BTreeMap<String, Option<Matcher>>>>,
    cursor: String,
    keys_done: bool,
    ip_too: bool,
    ip_at: IpAt,
    model: Arc<Model>,
}

impl WarnCheck {
    /// The check for a build of `ctx`'s bundle (`None`: nothing concerns it).
    pub async fn new(state: &SharedState, ctx: &super::build::Ctx) -> Result<Option<WarnCheck>> {
        if ctx.spec.action != BundleAction::Block {
            return Ok(None);
        }
        let model = state.config.model().await?;
        let (warn, allow) = concerned(&model, &ctx.spec.id);
        if warn.is_empty() && allow.is_empty() {
            return Ok(None);
        }
        let mut ids: Vec<String> = warn.keys().cloned().collect();
        ids.extend(allow.into_iter().filter(|a| !warn.contains_key(a)));
        Ok(Some(WarnCheck {
            warn,
            ids,
            next: 0,
            loading: None,
            loaded: BTreeMap::new(),
            matchers: None,
            cursor: String::new(),
            keys_done: false,
            ip_too: ctx.touched.ip || ctx.mode != super::build::Mode::Incremental,
            ip_at: IpAt::START,
            model: Arc::new(model),
        }))
    }
}

/// One step of a build's warning check; `Ok(true)` when it is done.
pub async fn check_step(state: &SharedState, ctx: &mut super::build::Ctx) -> Result<bool> {
    let Some(mut w) = ctx.warn.take() else {
        return Ok(true);
    };
    // Load the matchers, a page per step.
    if w.matchers.is_none() {
        if w.next < w.ids.len() {
            let id = w.ids[w.next].clone();
            let model = w.model.clone();
            let loading = w.loading.take();
            let (loading, done) = state
                .db
                .read(move |c| {
                    let mut l = match loading {
                        Some(l) => l,
                        None => match MatcherLoad::new(c, &model, &id)? {
                            Some(l) => l,
                            None => return Ok::<_, anyhow::Error>((None, Some(None))),
                        },
                    };
                    let r = l.step(c)?;
                    Ok(match r {
                        Some(m) => (None, Some(m)),
                        None => (Some(l), None),
                    })
                })
                .await?;
            w.loading = loading;
            if let Some(m) = done {
                w.loaded.insert(w.ids[w.next].clone(), m);
                w.next += 1;
            }
            ctx.warn = Some(w);
            return Ok(false);
        }
        w.matchers = Some(Arc::new(std::mem::take(&mut w.loaded)));
    }
    let matchers = w.matchers.clone().unwrap_or_default();
    let (spec, runs, bundle) = (ctx.spec.clone(), ctx.runs.clone(), ctx.spec.id.clone());
    let warn = w.warn.clone();
    let no_ips = matchers.values().flatten().all(|m| m.ips.is_empty());
    if !w.keys_done {
        let cursor = w.cursor.clone();
        let (ops, last) = state
            .db
            .read(move |c| {
                let view = View::new(&spec, &runs);
                let keys: Vec<String> = {
                    let mut st = c.prepare_cached(
                        "SELECT key FROM bundle_build_keys WHERE bundle_id = ?1 AND key > ?2 ORDER BY key LIMIT ?3",
                    )?;
                    st.query_map(params![bundle, cursor, KEYS_PER_STEP], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?
                };
                let mut ops = Vec::new();
                for k in &keys {
                    check_key(c, &view, &bundle, &matchers, &warn, k, &mut ops)?;
                }
                let last = (keys.len() >= KEYS_PER_STEP).then(|| keys.last().cloned()).flatten();
                Ok::<_, anyhow::Error>((ops, last))
            })
            .await?;
        apply_ops_at(state, ops, Some(ctx.generation)).await?;
        match last {
            Some(k) => w.cursor = k,
            None => w.keys_done = true,
        }
        let done = w.keys_done && (!w.ip_too || no_ips);
        ctx.warn = (!done).then_some(w);
        return Ok(done);
    }
    // IP rules (the block bundle's against the matchers' ranges), a page per step.
    let at = w.ip_at;
    let (ops, next) = state
        .db
        .read(move |c| {
            let view = View::new(&spec, &runs);
            let (rows, next) = ip_rules_page(c, &view, at)?;
            let ms: Vec<&Matcher> = matchers.values().flatten().collect();
            let mut ops = Vec::new();
            check_ip_rows(c, &bundle, &ms, &warn, &rows, &mut ops)?;
            Ok::<_, anyhow::Error>((ops, next))
        })
        .await?;
    apply_ops_at(state, ops, Some(ctx.generation)).await?;
    match next {
        Some(n) => {
            w.ip_at = n;
            ctx.warn = Some(w);
            Ok(false)
        }
        None => Ok(true),
    }
}

/// Applies warning changes in their own transaction.
async fn apply_ops(state: &SharedState, ops: Vec<WarnOp>) -> Result<()> {
    apply_ops_at(state, ops, None).await
}

/// [`apply_ops`] for a build's warning check: nothing once a config restore committed since the
/// build's setup (`generation`, core.md §2).
async fn apply_ops_at(state: &SharedState, ops: Vec<WarnOp>, generation: Option<u64>) -> Result<()> {
    if ops.is_empty() {
        return Ok(());
    }
    let alerts = state.alerts.clone();
    let gate = state.restore.clone();
    let ch = state
        .db
        .write(move |c| {
            if generation.is_some_and(|g| !gate.is_current(g)) {
                return Ok(Changes::default());
            }
            let tx = c.transaction()?;
            let mut ch = Changes::default();
            apply(&tx, &alerts, &ops, &mut ch)?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await?;
    state.alerts.announce(ch);
    Ok(())
}

/// One block key against the matchers.
fn check_key(
    c: &Connection,
    view: &View<'_>,
    bundle: &str,
    matchers: &BTreeMap<String, Option<Matcher>>,
    warn: &BTreeMap<String, BTreeSet<String>>,
    key: &str,
    ops: &mut Vec<WarnOp>,
) -> Result<()> {
    let mut bad = 0u64;
    let rows = view.key_rules(c, key, &mut bad)?;
    // Feeds listing the key with a block (not an exception).
    let mut listing: BTreeMap<String, i64> = BTreeMap::new();
    for r in &rows {
        if r.rule.is_badfilter() || r.rule.is_exception() {
            continue;
        }
        listing.entry(r.feed.clone()).or_insert(r.entry_id);
    }
    let value = reverse_dotted(key);
    for (id, m) in matchers {
        let Some(m) = m else { continue };
        let hit = m.matches_key(key);
        let feeds: Vec<&String> = match m.kind {
            "warn" => warn.get(id).map(|fs| fs.iter().collect()).unwrap_or_default(),
            _ => view.spec.members.iter().map(|x| &x.feed).collect(),
        };
        for f in feeds {
            match (listing.get(f), &hit) {
                (Some(entry), Some(by_feed)) => {
                    let raw = super::source::raw_of(c, *entry).map(|x| x.0).unwrap_or_default();
                    ops.push(WarnOp::Hold {
                        kind: m.kind,
                        by_bundle: id.clone(),
                        by_feed: by_feed.clone(),
                        value: value.clone(),
                        feed: f.clone(),
                        raw,
                        bundle: bundle.to_string(),
                    });
                }
                _ => ops.push(WarnOp::Clear {
                    kind: m.kind,
                    by_bundle: id.clone(),
                    value: value.clone(),
                    feed: f.clone(),
                    bundle: bundle.to_string(),
                }),
            }
        }
    }
    Ok(())
}

/// A page of the block bundle's IP rules against the matchers' ranges. A rule that left its feed
/// isn't among them: [`ResolveJob`] resolves its warning after the build.
fn check_ip_rows(
    c: &Connection,
    bundle: &str,
    matchers: &[&Matcher],
    warn: &BTreeMap<String, BTreeSet<String>>,
    rows: &[super::source::Row],
    ops: &mut Vec<WarnOp>,
) -> Result<()> {
    if matchers.iter().all(|m| m.ips.is_empty()) {
        return Ok(());
    }
    for r in rows {
        if r.rule.is_badfilter() || r.rule.is_exception() {
            continue;
        }
        let Some(range) = r.rule.ip_range() else { continue };
        for m in matchers {
            let id = &m.bundle;
            if m.kind == "warn" && !warn.get(id).is_some_and(|fs| fs.contains(&r.feed)) {
                continue;
            }
            let value = range.to_text();
            match m.matches_ip(&range) {
                Some(by_feed) => {
                    let raw = super::source::raw_of(c, r.entry_id)
                        .map(|x| x.0)
                        .unwrap_or_default();
                    ops.push(WarnOp::Hold {
                        kind: m.kind,
                        by_bundle: id.clone(),
                        by_feed,
                        value,
                        feed: r.feed.clone(),
                        raw,
                        bundle: bundle.to_string(),
                    });
                }
                None => ops.push(WarnOp::Clear {
                    kind: m.kind,
                    by_bundle: id.clone(),
                    value,
                    feed: r.feed.clone(),
                    bundle: bundle.to_string(),
                }),
            }
        }
    }
    Ok(())
}

/// Applies warning changes in a transaction, raising `warninglist_hit` / `allow_override` for new
/// warnings and resolving them when a pair has none open.
pub fn apply(
    tx: &rusqlite::Transaction<'_>,
    alerts: &crate::alerts::Alerts,
    ops: &[WarnOp],
    ch: &mut Changes,
) -> rusqlite::Result<()> {
    let now = crate::util::now_ts();
    // New warnings per alert pair.
    let mut new: BTreeMap<(String, &'static str, String), Vec<String>> = BTreeMap::new();
    let mut touched: BTreeSet<(String, &'static str, String)> = BTreeSet::new();
    // The alert pair: the block feed for warn bundles, the block bundle for allow bundles.
    let pair_of = |kind: &str, feed: &str, bundle: &str| {
        if kind == "warn" {
            feed.to_string()
        } else {
            bundle.to_string()
        }
    };
    for op in ops {
        match op {
            WarnOp::Hold {
                kind,
                by_bundle,
                by_feed,
                value,
                feed,
                raw,
                bundle,
            } => {
                let pair = pair_of(kind, feed, bundle);
                let existing: Option<(i64, String)> = tx
                    .query_row(
                        "SELECT id, status FROM warnings WHERE value = ?3 AND by_bundle_id = ?2 AND feed_id = ?4 AND kind = ?1
                           AND bundle_id = ?5",
                        params![kind, by_bundle, value, feed, bundle],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .ok();
                match existing {
                    Some((id, status)) => {
                        tx.execute(
                            "UPDATE warnings SET last_seen = ?2, status = 'open', raw = ?3, by_feed_id = ?4 WHERE id = ?1",
                            params![id, now, raw, by_feed],
                        )?;
                        if status != "open" {
                            new.entry((by_bundle.clone(), kind, pair.clone()))
                                .or_default()
                                .push(value.clone());
                        }
                    }
                    None => {
                        tx.execute(
                            "INSERT INTO warnings(kind, by_bundle_id, by_feed_id, value, feed_id, raw, bundle_id, first_seen,
                                last_seen, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 'open')",
                            params![kind, by_bundle, by_feed, value, feed, raw, bundle, now],
                        )?;
                        new.entry((by_bundle.clone(), kind, pair.clone()))
                            .or_default()
                            .push(value.clone());
                    }
                }
                touched.insert((by_bundle.clone(), kind, pair));
            }
            WarnOp::Clear {
                kind,
                by_bundle,
                value,
                feed,
                bundle,
            } => {
                let n = tx.execute(
                    "UPDATE warnings SET status = 'resolved', last_seen = ?5 WHERE value = ?3 AND by_bundle_id = ?2
                       AND feed_id = ?4 AND kind = ?1 AND bundle_id = ?6 AND status = 'open'",
                    params![kind, by_bundle, value, feed, now, bundle],
                )?;
                if n > 0 {
                    touched.insert((by_bundle.clone(), kind, pair_of(kind, feed, bundle)));
                }
            }
        }
    }
    for (by, kind, pair) in touched {
        let (alert_kind, col) = if kind == "warn" {
            ("warninglist_hit", "feed_id")
        } else {
            ("allow_override", "bundle_id")
        };
        let key = format!("{alert_kind}:{by}:{pair}");
        let open: i64 = tx.query_row(
            &format!("SELECT count(*) FROM warnings WHERE kind = ?1 AND by_bundle_id = ?2 AND {col} = ?3 AND status = 'open'"),
            params![kind, by, pair],
            |r| r.get(0),
        )?;
        if open == 0 {
            alerts.resolve_in(tx, &key, Some(&json!({"open_warnings": 0})), ch)?;
            continue;
        }
        if let Some(values) = new.get(&(by.clone(), kind, pair.clone())) {
            let title = if kind == "warn" {
                format!("Feed {pair} lists names warn bundle {by} warns about")
            } else {
                format!("Allow bundle {by} overrides blocks of bundle {pair}")
            };
            let mut spec = RaiseSpec::new(
                alert_kind,
                Severity::Info,
                key,
                title,
                json!({"by_bundle": by, "pair": pair, "new": values.len(), "sample": values.iter().take(5).collect::<Vec<_>>(), "open_warnings": open}),
            );
            spec = if kind == "warn" {
                spec.feed(pair.clone())
            } else {
                spec.bundle(pair.clone())
            };
            alerts.raise_in(tx, &spec, ch)?;
        }
    }
    Ok(())
}

/// After a build: a warn bundle re-checks the block bundles concerned; so does an allow bundle
/// with a downloaded feed, or with warnings of its own to resolve (its last downloaded feed went);
/// a block bundle whose definition or IP rules changed re-checks its open warnings
/// (`structural`: a feed left it, an IP rule went; bundles.md §3 "When").
pub async fn bundle_built(state: &SharedState, bundle: &str, structural: bool) {
    let Ok(model) = state.config.model().await else {
        return;
    };
    let Some(def) = model.bundles.get(bundle) else {
        return;
    };
    let target = match def.action {
        BundleAction::Warn => Some(Target::By(bundle.to_string())),
        BundleAction::Allow => {
            let downloaded = def
                .feeds
                .iter()
                .any(|f| model.feeds.get(&f.feed).is_some_and(|fd| !fd.is_manual()));
            (downloaded || has_open(state, "by_bundle_id", bundle).await)
                .then(|| Target::By(bundle.to_string()))
        }
        BundleAction::Block if structural && has_open(state, "bundle_id", bundle).await => {
            Some(Target::Block(bundle.to_string()))
        }
        _ => None,
    };
    if let Some(t) = target {
        request(state, t).await;
    }
}

/// A deleted bundle: its open warnings (as the block bundle or as the warn or allow bundle)
/// resolve (bundles.md §3).
pub async fn bundle_retired(state: &SharedState, bundle: &str) {
    if has_open(state, "bundle_id", bundle).await {
        request(state, Target::Block(bundle.to_string())).await;
    }
    if has_open(state, "by_bundle_id", bundle).await {
        request(state, Target::By(bundle.to_string())).await;
    }
}

/// True when a warning with `col` = `id` is open.
async fn has_open(state: &SharedState, col: &'static str, id: &str) -> bool {
    let id = id.to_string();
    state
        .db
        .read(move |c| {
            Ok::<_, anyhow::Error>(
                c.query_row(
                    &format!("SELECT 1 FROM warnings WHERE {col} = ?1 AND status = 'open' LIMIT 1"),
                    [id],
                    |_| Ok(()),
                )
                .is_ok(),
            )
        })
        .await
        .unwrap_or(true)
}

/// What a re-check covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Every warn and allow bundle against every block bundle, and every open warning.
    All,
    /// One warn or allow bundle against the block bundles it concerns, and its open warnings.
    By(String),
    /// One block bundle's open warnings whose bundle, feed, pairing or entry went.
    Block(String),
}

impl Target {
    /// The `warning_rechecks` row (and the heavy job's target).
    pub fn key(&self) -> String {
        match self {
            Target::All => "*".into(),
            Target::By(b) => format!("by:{b}"),
            Target::Block(b) => format!("block:{b}"),
        }
    }

    fn parse(s: &str) -> Option<Target> {
        if s == "*" {
            return Some(Target::All);
        }
        match s.split_once(':') {
            Some(("by", b)) => Some(Target::By(b.to_string())),
            Some(("block", b)) => Some(Target::Block(b.to_string())),
            _ => None,
        }
    }
}

/// Records a re-check (README §2 Restarts: it survives a stop) and queues it.
pub async fn request(state: &SharedState, target: Target) {
    let key = target.key();
    let r = state
        .db
        .write(move |c| {
            Ok::<_, anyhow::Error>(c.query_row(
                "INSERT INTO warning_rechecks(target, seq) VALUES (?1, 1)
                 ON CONFLICT(target) DO UPDATE SET seq = seq + 1 RETURNING seq",
                [key],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await;
    match r {
        Ok(seq) => submit(state, target, seq),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "cannot record a warning re-check; it runs now");
            submit(state, target, 0);
        }
    }
}

fn submit(state: &SharedState, target: Target, seq: i64) {
    let job: Box<dyn HeavyJob> = match target {
        Target::Block(b) => Box::new(ResolveJob::new(state.clone(), b, seq)),
        Target::All => Box::new(RecheckJob::new(state.clone(), None).with_seq(seq)),
        Target::By(b) => Box::new(RecheckJob::new(state.clone(), Some(b)).with_seq(seq)),
    };
    if state.scheduler.heavy.submit(Priority::P2, job) == crate::scheduler::Submitted::Dropped {
        tracing::warn!("the heavy queue refused a warning re-check; it runs at the next start");
    }
}

/// Drops a finished re-check's row unless a newer request came meanwhile.
async fn finished(state: &SharedState, key: String, seq: i64) {
    let r = state
        .db
        .write(move |c| {
            c.execute(
                "DELETE FROM warning_rechecks WHERE target = ?1 AND seq = ?2",
                params![key, seq],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await;
    if let Err(e) = r {
        tracing::warn!(error = %format!("{e:#}"), "cannot drop a finished warning re-check");
    }
}

/// At start (README §2 Restarts): runs every recorded re-check again, and re-checks everything
/// when the `warn_on` / pairing digest isn't the one the warnings were last checked against.
/// Returns the digest now in force.
pub async fn resume(state: &SharedState, model: &Model) -> Result<String> {
    let digest = pairing_digest(model);
    let d = digest.clone();
    let (pending, changed) = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let stored: Option<String> = tx
                .query_row("SELECT digest FROM warning_pairing WHERE id = 1", [], |r| r.get(0))
                .ok();
            let changed = stored.as_deref().is_some_and(|s| s != d);
            tx.execute(
                "INSERT INTO warning_pairing(id, digest) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET digest = ?1",
                [&d],
            )?;
            if changed {
                tx.execute(
                    "INSERT INTO warning_rechecks(target, seq) VALUES ('*', 1)
                     ON CONFLICT(target) DO UPDATE SET seq = seq + 1",
                    [],
                )?;
            }
            let pending: Vec<(String, i64)> = {
                let mut st = tx.prepare("SELECT target, seq FROM warning_rechecks ORDER BY target")?;
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            tx.commit()?;
            Ok::<_, anyhow::Error>((pending, changed))
        })
        .await?;
    if changed {
        tracing::info!(
            "warn_on or allow/block pairings changed while core was stopped; every warning is re-checked"
        );
    }
    for (key, seq) in pending {
        match Target::parse(&key) {
            Some(t) => submit(state, t, seq),
            None => finished(state, key, seq).await,
        }
    }
    Ok(digest)
}

/// A configuration change of a `warn_on` or of which allow bundles a profile pairs with which
/// block bundles: the new digest is stored with a full re-check, in one transaction.
pub async fn pairing_changed(state: &SharedState, digest: String) {
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO warning_pairing(id, digest) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET digest = ?1",
                [&digest],
            )?;
            let seq: i64 = tx.query_row(
                "INSERT INTO warning_rechecks(target, seq) VALUES ('*', 1)
                 ON CONFLICT(target) DO UPDATE SET seq = seq + 1 RETURNING seq",
                [],
                |r| r.get(0),
            )?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(seq)
        })
        .await;
    match r {
        Ok(seq) => submit(state, Target::All, seq),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "cannot record a warning re-check; it runs now");
            submit(state, Target::All, 0);
        }
    }
}

/// Re-checks warnings against warn/allow bundle `by` (all of them with `None`) in one go
/// (tests).
pub async fn recheck(state: &SharedState, by: Option<&str>) -> Result<()> {
    let mut job = RecheckJob::new(state.clone(), by.map(str::to_string));
    while job.run_step().await? == Step::More {}
    Ok(())
}

/// Where a re-check stands.
enum RStage {
    Start,
    /// Loading matcher `m` (index into `ids`).
    Load {
        m: usize,
    },
    /// Its keyed rules against block bundle `b` (index into its blocks): the keyed rules after
    /// `after` are still to check, and `below` pages through the descendants of `after` (a
    /// subdomain rule).
    Keyed {
        m: usize,
        b: usize,
        after: String,
        below: Option<String>,
    },
    /// Its patterns against every key of block bundle `b`: member feed and cursor.
    Patterns {
        m: usize,
        b: usize,
        feed: usize,
        cursor: (String, i64),
    },
    /// Its IP rules against block bundle `b`'s, a page at a time.
    Ips {
        m: usize,
        b: usize,
        at: IpAt,
    },
    /// Its open warnings that no longer hold, after warning id `cursor`.
    Resolve {
        m: usize,
        cursor: i64,
    },
    /// Open warnings of warn or allow bundles no longer checked (a full re-check only).
    Orphans {
        cursor: i64,
    },
    Done,
}

/// A re-check of warnings (bundles.md §3 "When"), a heavy-lane P2 job in bounded steps: one
/// warn or allow bundle at a time (its matcher in memory), each block bundle it concerns in
/// pages of candidates, then its open warnings in pages.
pub struct RecheckJob {
    state: SharedState,
    by: Option<String>,
    target: String,
    /// The `warning_rechecks` request this job carries out (0: none recorded).
    seq: i64,
    stage: RStage,
    model: Option<Arc<Model>>,
    /// The warn and allow bundles to check, with the block bundles each concerns.
    ids: Vec<(String, Vec<String>)>,
    loading: Option<MatcherLoad>,
    matcher: Option<Arc<Matcher>>,
    /// The block bundle being checked: its spec and snapshot.
    block: Option<(Spec, Runs)>,
}

impl RecheckJob {
    pub fn new(state: SharedState, by: Option<String>) -> Self {
        let target = match &by {
            Some(b) => Target::By(b.clone()).key(),
            None => Target::All.key(),
        };
        Self {
            state,
            by,
            target,
            seq: 0,
            stage: RStage::Start,
            model: None,
            ids: Vec::new(),
            loading: None,
            matcher: None,
            block: None,
        }
    }

    fn with_seq(mut self, seq: i64) -> Self {
        self.seq = seq;
        self
    }

    fn model(&self) -> Result<Arc<Model>> {
        self.model
            .clone()
            .ok_or_else(|| anyhow!("re-check without a model"))
    }

    /// The block bundle `b` of matcher `m`, with its snapshot taken when it starts.
    async fn block(&mut self, m: usize, b: usize) -> Result<Option<(Spec, Runs, String)>> {
        let Some(id) = self.ids.get(m).and_then(|(_, bs)| bs.get(b)).cloned() else {
            return Ok(None);
        };
        if self.block.as_ref().is_none_or(|(s, _)| s.id != id) {
            let model = self.model()?;
            let Some(def) = model.bundles.get(&id) else {
                return Ok(None);
            };
            let spec = Spec::of(def, &model);
            let s2 = spec.clone();
            let runs = self
                .state
                .db
                .read(move |c| Ok::<_, anyhow::Error>(spec::snapshot(c, &s2)?))
                .await?;
            self.block = Some((spec, runs));
        }
        Ok(self.block.clone().map(|(s, r)| (s, r, id)))
    }

    /// The stage after block bundle `b` of matcher `m`.
    fn next_block(&mut self, m: usize, b: usize) -> RStage {
        self.block = None;
        if self.ids.get(m).is_some_and(|(_, bs)| b + 1 < bs.len()) {
            RStage::Keyed {
                m,
                b: b + 1,
                after: String::new(),
                below: None,
            }
        } else {
            RStage::Resolve { m, cursor: 0 }
        }
    }

    pub async fn run_step(&mut self) -> Result<Step> {
        let stage = std::mem::replace(&mut self.stage, RStage::Done);
        self.stage = match stage {
            RStage::Start => {
                let model = self.state.config.model().await?;
                let mut by_matcher: BTreeMap<String, Vec<String>> = BTreeMap::new();
                for b in model.bundles.values().filter(|b| b.action == BundleAction::Block) {
                    let (warn, allow) = concerned(&model, &b.id);
                    for id in warn.keys().chain(allow.iter()) {
                        if self.by.as_deref().is_none_or(|x| x == id) {
                            let v = by_matcher.entry(id.clone()).or_default();
                            if !v.contains(&b.id) {
                                v.push(b.id.clone());
                            }
                        }
                    }
                }
                if let Some(by) = &self.by {
                    by_matcher.entry(by.clone()).or_default();
                }
                self.ids = by_matcher.into_iter().collect();
                self.model = Some(Arc::new(model));
                if self.ids.is_empty() {
                    RStage::Orphans { cursor: 0 }
                } else {
                    RStage::Load { m: 0 }
                }
            }
            RStage::Load { m } => {
                let Some((id, _)) = self.ids.get(m).cloned() else {
                    return Ok(self.finish_matchers());
                };
                let model = self.model()?;
                let loading = self.loading.take();
                let (loading, done) = self
                    .state
                    .db
                    .read(move |c| {
                        let mut l = match loading {
                            Some(l) => l,
                            None => match MatcherLoad::new(c, &model, &id)? {
                                Some(l) => l,
                                None => return Ok::<_, anyhow::Error>((None, Some(None))),
                            },
                        };
                        Ok(match l.step(c)? {
                            Some(r) => (None, Some(r)),
                            None => (Some(l), None),
                        })
                    })
                    .await?;
                self.loading = loading;
                match done {
                    None => RStage::Load { m },
                    Some(Some(matcher)) => {
                        self.matcher = Some(Arc::new(matcher));
                        if self.ids[m].1.is_empty() {
                            RStage::Resolve { m, cursor: 0 }
                        } else {
                            RStage::Keyed {
                                m,
                                b: 0,
                                after: String::new(),
                                below: None,
                            }
                        }
                    }
                    // Gone, or too large to check: its open warnings are resolved on what can
                    // be checked (a deleted bundle's all go; a too-large one's stay while
                    // paired).
                    Some(None) => {
                        self.matcher = None;
                        RStage::Resolve { m, cursor: 0 }
                    }
                }
            }
            RStage::Keyed { m, b, after, below } => {
                let Some((spec, runs, block)) = self.block(m, b).await? else {
                    let next = self.next_block(m, b);
                    return Ok(self.set(next));
                };
                let matcher = self.matcher.clone().ok_or_else(|| anyhow!("no matcher"))?;
                let model = self.model()?;
                let (ops, next) = self
                    .state
                    .db
                    .read(move |c| {
                        let view = View::new(&spec, &runs);
                        let (warn, _) = concerned(&model, &block);
                        let mut ops = Vec::new();
                        let mut checked = 0usize;
                        let (mut after, mut below) = (after, below);
                        loop {
                            if checked >= KEYS_PER_STEP {
                                return Ok::<_, anyhow::Error>((ops, Some((after, below))));
                            }
                            if let Some(cursor) = below.take() {
                                // Every descendant of a subdomain rule, a page at a time (CP9).
                                let (page, next) = super::source::descendants_page(
                                    c,
                                    &view,
                                    &after,
                                    &cursor,
                                    KEYS_PER_STEP,
                                )?;
                                for d in &page {
                                    check_key_one(c, &view, &block, &matcher, &warn, d, &mut ops)?;
                                }
                                checked += page.len();
                                below = next;
                                continue;
                            }
                            let Some((k, f)) = matcher.keyed_after(&after) else {
                                return Ok((ops, None));
                            };
                            check_key_one(c, &view, &block, &matcher, &warn, k, &mut ops)?;
                            checked += 1;
                            after = k.clone();
                            if !f.subs().is_empty() {
                                below = Some(String::new());
                            }
                        }
                    })
                    .await?;
                apply_ops(
                    &self.state,
                    ops.into_iter()
                        .filter(|o| matches!(o, WarnOp::Hold { .. }))
                        .collect(),
                )
                .await?;
                match next {
                    Some((after, below)) => RStage::Keyed { m, b, after, below },
                    None if matcher_has_patterns(&self.matcher) => RStage::Patterns {
                        m,
                        b,
                        feed: 0,
                        cursor: (String::new(), -1),
                    },
                    None => RStage::Ips {
                        m,
                        b,
                        at: IpAt::START,
                    },
                }
            }
            RStage::Patterns { m, b, feed, cursor } => {
                let Some((spec, runs, block)) = self.block(m, b).await? else {
                    let next = self.next_block(m, b);
                    return Ok(self.set(next));
                };
                let matcher = self.matcher.clone().ok_or_else(|| anyhow!("no matcher"))?;
                let model = self.model()?;
                let (ops, next) = self
                    .state
                    .db
                    .read(move |c| {
                        let view = View::new(&spec, &runs);
                        let (warn, _) = concerned(&model, &block);
                        let feeds = feeds_taking(&spec, &view, picket_rules::RuleType::Dns);
                        let Some((f, run)) = feeds.get(feed) else {
                            return Ok::<_, anyhow::Error>((Vec::new(), None));
                        };
                        let mut st = c.prepare_cached(
                            "SELECT key, id, first_run, removed_run FROM feed_entries
                             WHERE feed_id = ?1 AND rule_type = 'dns' AND key >= ?2 AND (key > ?2 OR id > ?3)
                             ORDER BY key, id LIMIT ?4",
                        )?;
                        let mut rows = st.query(params![f, cursor.0, cursor.1, SCAN_ROWS_PER_STEP])?;
                        let mut ops = Vec::new();
                        let mut n = 0usize;
                        let mut last = cursor.clone();
                        let mut prev_key = String::new();
                        while let Some(r) = rows.next()? {
                            n += 1;
                            let key: String = r.get(0)?;
                            last = (key.clone(), r.get(1)?);
                            let first_run: i64 = r.get(2)?;
                            let removed: Option<i64> = r.get(3)?;
                            if first_run > *run || removed.is_some_and(|x| x <= *run) || key == prev_key {
                                continue;
                            }
                            check_key_one(c, &view, &block, &matcher, &warn, &key, &mut ops)?;
                            prev_key = key;
                        }
                        let next = if n >= SCAN_ROWS_PER_STEP {
                            Some((feed, last))
                        } else {
                            Some((feed + 1, (String::new(), -1)))
                        };
                        Ok((ops, next))
                    })
                    .await?;
                apply_ops(
                    &self.state,
                    ops.into_iter()
                        .filter(|o| matches!(o, WarnOp::Hold { .. }))
                        .collect(),
                )
                .await?;
                match next {
                    Some((feed, cursor)) => RStage::Patterns { m, b, feed, cursor },
                    None => RStage::Ips {
                        m,
                        b,
                        at: IpAt::START,
                    },
                }
            }
            RStage::Ips { m, b, at } => {
                let Some((spec, runs, block)) = self.block(m, b).await? else {
                    let next = self.next_block(m, b);
                    return Ok(self.set(next));
                };
                let matcher = self.matcher.clone().ok_or_else(|| anyhow!("no matcher"))?;
                if matcher.ips.is_empty() {
                    let next = self.next_block(m, b);
                    return Ok(self.set(next));
                }
                let model = self.model()?;
                let (ops, next) = self
                    .state
                    .db
                    .read(move |c| {
                        let view = View::new(&spec, &runs);
                        let (warn, _) = concerned(&model, &block);
                        let (rows, next) = ip_rules_page(c, &view, at)?;
                        let mut ops = Vec::new();
                        check_ip_rows(c, &block, &[&*matcher], &warn, &rows, &mut ops)?;
                        Ok::<_, anyhow::Error>((ops, next))
                    })
                    .await?;
                apply_ops(
                    &self.state,
                    ops.into_iter()
                        .filter(|o| matches!(o, WarnOp::Hold { .. }))
                        .collect(),
                )
                .await?;
                match next {
                    Some(at) => RStage::Ips { m, b, at },
                    None => self.next_block(m, b),
                }
            }
            RStage::Resolve { m, cursor } => {
                let Some((by, _)) = self.ids.get(m).cloned() else {
                    return Ok(self.finish_matchers());
                };
                let matcher = self.matcher.clone();
                let model = self.model()?;
                let (ops, last) = self
                    .state
                    .db
                    .read(move |c| {
                        let open: Vec<OpenWarning> = open_page(c, "by_bundle_id", Some(&by), cursor)?;
                        let last = (open.len() >= OPEN_PER_STEP)
                            .then(|| open.last().map(|o| o.id))
                            .flatten();
                        let mut ops = Vec::new();
                        for o in open {
                            if !holds(c, &model, Some(matcher.as_deref()), &o)? {
                                ops.push(o.clear());
                            }
                        }
                        Ok::<_, anyhow::Error>((ops, last))
                    })
                    .await?;
                apply_ops(&self.state, ops).await?;
                match last {
                    Some(cursor) => RStage::Resolve { m, cursor },
                    None => self.after_matcher(m),
                }
            }
            RStage::Orphans { cursor } => {
                if self.by.is_some() {
                    RStage::Done
                } else {
                    let checked: BTreeSet<String> = self.ids.iter().map(|(id, _)| id.clone()).collect();
                    let model = self.model()?;
                    let (ops, last) = self
                        .state
                        .db
                        .read(move |c| {
                            let open = open_page(c, "by_bundle_id", None, cursor)?;
                            let last = (open.len() >= OPEN_PER_STEP)
                                .then(|| open.last().map(|o| o.id))
                                .flatten();
                            let mut ops = Vec::new();
                            for o in open {
                                if !checked.contains(&o.by_bundle) && !holds(c, &model, None, &o)? {
                                    ops.push(o.clear());
                                }
                            }
                            Ok::<_, anyhow::Error>((ops, last))
                        })
                        .await?;
                    apply_ops(&self.state, ops).await?;
                    match last {
                        Some(cursor) => RStage::Orphans { cursor },
                        None => RStage::Done,
                    }
                }
            }
            RStage::Done => RStage::Done,
        };
        if matches!(self.stage, RStage::Done) {
            self.done().await;
            return Ok(Step::Done);
        }
        Ok(Step::More)
    }

    fn set(&mut self, stage: RStage) -> Step {
        self.stage = stage;
        if matches!(self.stage, RStage::Done) {
            Step::Done
        } else {
            Step::More
        }
    }

    /// The re-check ran to its end: its record goes unless a newer request came.
    async fn done(&mut self) {
        if self.seq > 0 {
            finished(&self.state, self.target.clone(), self.seq).await;
            self.seq = 0;
        }
    }

    /// The stage after matcher `m`: the next matcher, or the orphans.
    fn after_matcher(&mut self, m: usize) -> RStage {
        self.matcher = None;
        self.block = None;
        if m + 1 < self.ids.len() {
            RStage::Load { m: m + 1 }
        } else {
            RStage::Orphans { cursor: 0 }
        }
    }

    fn finish_matchers(&mut self) -> Step {
        self.set(RStage::Orphans { cursor: 0 })
    }
}

fn matcher_has_patterns(m: &Option<Arc<Matcher>>) -> bool {
    m.as_ref().is_some_and(|m| m.has_patterns())
}

impl HeavyJob for RecheckJob {
    fn kind(&self) -> &str {
        "warnings_recheck"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn step(&mut self) -> BoxFuture<'_, Result<Step>> {
        Box::pin(async move {
            let s = self.run_step().await?;
            if s == Step::Done {
                self.done().await;
            }
            Ok(s)
        })
    }

    /// A newer re-check of the same target checks everything again.
    fn supersedable(&self) -> bool {
        true
    }
}

/// One block bundle's open warnings re-checked after its definition or IP rules changed, or after
/// it was deleted (bundles.md §3): each goes once its block bundle, its feed's place in it, its
/// pairing or its entry is gone ([`holds`] without the matcher: the warn or allow bundle's own
/// changes re-check through [`RecheckJob`]). A heavy-lane P2 job, a page of warnings per step.
pub struct ResolveJob {
    state: SharedState,
    bundle: String,
    target: String,
    seq: i64,
    cursor: i64,
    model: Option<Arc<Model>>,
}

impl ResolveJob {
    pub fn new(state: SharedState, bundle: String, seq: i64) -> Self {
        let target = Target::Block(bundle.clone()).key();
        Self {
            state,
            bundle,
            target,
            seq,
            cursor: 0,
            model: None,
        }
    }

    async fn run_step(&mut self) -> Result<Step> {
        let model = match &self.model {
            Some(m) => m.clone(),
            None => {
                let m = Arc::new(self.state.config.model().await?);
                self.model = Some(m.clone());
                m
            }
        };
        let (bundle, cursor) = (self.bundle.clone(), self.cursor);
        let (ops, last) = self
            .state
            .db
            .read(move |c| {
                let open = open_page(c, "bundle_id", Some(&bundle), cursor)?;
                let last = (open.len() >= OPEN_PER_STEP)
                    .then(|| open.last().map(|o| o.id))
                    .flatten();
                let mut ops = Vec::new();
                for o in open {
                    if !holds(c, &model, None, &o)? {
                        ops.push(o.clear());
                    }
                }
                Ok::<_, anyhow::Error>((ops, last))
            })
            .await?;
        apply_ops(&self.state, ops).await?;
        match last {
            Some(c) => {
                self.cursor = c;
                Ok(Step::More)
            }
            None => {
                if self.seq > 0 {
                    finished(&self.state, self.target.clone(), self.seq).await;
                    self.seq = 0;
                }
                Ok(Step::Done)
            }
        }
    }
}

impl HeavyJob for ResolveJob {
    fn kind(&self) -> &str {
        "warnings_resolve"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn step(&mut self) -> BoxFuture<'_, Result<Step>> {
        Box::pin(self.run_step())
    }

    fn supersedable(&self) -> bool {
        true
    }
}

/// An open warning, as the resolve passes read it.
struct OpenWarning {
    id: i64,
    kind: String,
    by_bundle: String,
    value: String,
    feed: String,
    bundle: Option<String>,
}

impl OpenWarning {
    fn clear(self) -> WarnOp {
        WarnOp::Clear {
            kind: if self.kind == "warn" { "warn" } else { "allow" },
            by_bundle: self.by_bundle,
            value: self.value,
            feed: self.feed,
            bundle: self.bundle.unwrap_or_default(),
        }
    }
}

/// A page of open warnings (with `col` = `id`, or all) after id `cursor`, in id order: for one
/// bundle through its `(col, status)` index, so a page never scans other bundles' warnings.
fn open_page(
    c: &Connection,
    col: &'static str,
    id: Option<&str>,
    cursor: i64,
) -> rusqlite::Result<Vec<OpenWarning>> {
    let map = |r: &rusqlite::Row<'_>| {
        Ok(OpenWarning {
            id: r.get(0)?,
            kind: r.get(1)?,
            by_bundle: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            value: r.get(3)?,
            feed: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            bundle: r.get(5)?,
        })
    };
    match id {
        Some(id) => {
            let mut st = c.prepare_cached(&format!(
                "SELECT id, kind, by_bundle_id, value, feed_id, bundle_id FROM warnings
                 WHERE {col} = ?2 AND status = 'open' AND id > ?1 ORDER BY id LIMIT ?3"
            ))?;
            st.query_map(params![cursor, id, OPEN_PER_STEP], map)?.collect()
        }
        None => {
            // In id order from the cursor (`+status` keeps the planner on the rowid range).
            let mut st = c.prepare_cached(
                "SELECT id, kind, by_bundle_id, value, feed_id, bundle_id FROM warnings
                 WHERE id > ?1 AND +status = 'open' ORDER BY id LIMIT ?2",
            )?;
            st.query_map(params![cursor, OPEN_PER_STEP], map)?.collect()
        }
    }
}

/// True while an open warning still holds (bundles.md §3): its block bundle exists and holds the
/// feed with the entry's rule type, the feed lists the entry, the feed's `warn_on` names the warn
/// bundle (or some profile pairs the allow bundle with the block bundle), and the warn or allow
/// bundle matches it. `m`: `None` skips the match (a structural re-check); `Some(None)` when the
/// bundle is gone or too large to load; `Some(Some(m))` its matcher.
fn holds(c: &Connection, model: &Model, m: Option<Option<&Matcher>>, o: &OpenWarning) -> Result<bool> {
    let Some(bundle) = o.bundle.as_deref() else {
        return Ok(false);
    };
    let Some(def) = model
        .bundles
        .get(bundle)
        .filter(|d| d.action == BundleAction::Block)
    else {
        return Ok(false);
    };
    let by_action = if o.kind == "warn" {
        BundleAction::Warn
    } else {
        BundleAction::Allow
    };
    if !model
        .bundles
        .get(&o.by_bundle)
        .is_some_and(|b| b.action == by_action)
    {
        return Ok(false);
    }
    let (warn, allow) = concerned(model, bundle);
    let paired = if o.kind == "warn" {
        warn.get(&o.by_bundle).is_some_and(|fs| fs.contains(&o.feed))
    } else {
        allow.contains(&o.by_bundle)
    };
    if !paired {
        return Ok(false);
    }
    // The block bundle holds the feed, with the rule types it takes from it.
    let spec = Spec::of(def, model);
    let Some(member) = spec.member(&o.feed) else {
        return Ok(false);
    };
    let types = spec.compiled_types(member);
    if !listed(c, &o.feed, &o.value, &types)? {
        return Ok(false);
    }
    let matcher = match m {
        None => return Ok(true),
        Some(m) => m,
    };
    let Some(m) = matcher.filter(|m| m.bundle == o.by_bundle) else {
        // Paired, but not checked here (too large to load): it stays.
        return Ok(true);
    };
    Ok(match IpRange::from_text(&o.value) {
        Some(r) => m.matches_ip(&r).is_some(),
        None => picket_rules::RuleName::parse(&o.value)
            .ok()
            .is_some_and(|n| m.matches_key(&n.reversed()).is_some()),
    })
}

/// [`check_key`] against one matcher (holds only).
fn check_key_one(
    c: &Connection,
    view: &View<'_>,
    bundle: &str,
    m: &Matcher,
    warn: &BTreeMap<String, BTreeSet<String>>,
    key: &str,
    ops: &mut Vec<WarnOp>,
) -> Result<()> {
    let hit = m.matches_key(key);
    let Some(by_feed) = hit else { return Ok(()) };
    let mut bad = 0u64;
    let rows = view.key_rules(c, key, &mut bad)?;
    let value = reverse_dotted(key);
    let mut seen = BTreeSet::new();
    for r in &rows {
        if r.rule.is_badfilter() || r.rule.is_exception() || !seen.insert(r.feed.clone()) {
            continue;
        }
        if m.kind == "warn" && !warn.get(&m.bundle).is_some_and(|fs| fs.contains(&r.feed)) {
            continue;
        }
        let raw = super::source::raw_of(c, r.entry_id)
            .map(|x| x.0)
            .unwrap_or_default();
        ops.push(WarnOp::Hold {
            kind: m.kind,
            by_bundle: m.bundle.clone(),
            by_feed: by_feed.clone(),
            value: value.clone(),
            feed: r.feed.clone(),
            raw,
            bundle: bundle.to_string(),
        });
    }
    Ok(())
}

/// True when `feed` lists `value` (a name or an IP range's text) as an open block entry of one of
/// `types` (not an exception or a `$badfilter`).
fn listed(c: &Connection, feed: &str, value: &str, types: &[picket_rules::RuleType]) -> Result<bool> {
    let mut keys: Vec<String> = Vec::new();
    match IpRange::from_text(value) {
        Some(r) => {
            keys.push(value.to_string());
            // A name rule on an address (`||1.2.3.4^`) is stored under the reversed address.
            if r.v4 && r.first == r.last {
                keys.push(reverse_dotted(value));
            }
        }
        None => match picket_rules::RuleName::parse(value) {
            Ok(n) => keys.push(n.reversed()),
            Err(_) => return Ok(false),
        },
    }
    let mut st = c.prepare_cached(
        "SELECT rule_type FROM feed_entries WHERE feed_id = ?1 AND key = ?2 AND removed_run IS NULL
           AND kind <> 'badfilter' AND (flags & 204) = 0",
    )?;
    for k in &keys {
        let mut rows = st.query(params![feed, k])?;
        while let Some(r) = rows.next()? {
            let rt: String = r.get(0)?;
            if picket_rules::RuleType::parse(&rt).is_some_and(|t| types.contains(&t)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// A digest of what decides which warnings apply: each feed's `warn_on` and each profile's
/// allow/block pairing. A change re-checks every warning.
pub fn pairing_digest(model: &Model) -> String {
    let warn_on: BTreeMap<&str, Vec<String>> = model
        .feeds
        .values()
        .map(|f| (f.id.as_str(), f.effective_warn_on()))
        .collect();
    type Pairing = (Vec<String>, Vec<String>, Vec<String>);
    let pairs: BTreeMap<&str, Pairing> = model
        .profiles
        .values()
        .map(|p| {
            (
                p.id.as_str(),
                (
                    p.edge.allow.clone(),
                    p.edge.block.clone(),
                    p.trial_bundles.clone(),
                ),
            )
        })
        .collect();
    let s = serde_json::to_string(&(warn_on, pairs)).unwrap_or_default();
    picket_api::ids::object_id(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(ranges: Vec<(IpRange, &str)>) -> IpIndex {
        let mut acc = IpAcc::default();
        // Two pages, so the merge runs.
        let (a, b) = ranges.split_at(ranges.len() / 2);
        acc.add_page(a.to_vec());
        acc.add_page(b.to_vec());
        acc.finish()
    }

    #[test]
    fn ip_index_finds_an_overlapping_range() {
        let r = |s: &str| IpRange::from_text(s).unwrap();
        let idx = index(vec![
            (r("10.0.0.0/8"), "a"),
            (r("192.168.1.0/24"), "b"),
            (r("192.168.0.5"), "c"),
            (r("2001:db8::/32"), "d"),
        ]);
        assert_eq!(idx.find(&r("10.1.2.3")), Some("a"));
        assert_eq!(idx.find(&r("192.168.1.200")), Some("b"));
        assert_eq!(idx.find(&r("192.168.0.5")), Some("c"));
        assert!(idx.find(&r("192.168.0.0/16")).is_some());
        assert_eq!(idx.find(&r("11.0.0.1")), None);
        assert_eq!(idx.find(&r("192.168.2.1")), None);
        assert_eq!(idx.find(&r("2001:db8::1")), Some("d"));
        assert_eq!(idx.find(&r("2001:db9::1")), None);
        // A long range before a short one still covers what follows it.
        let idx = index(vec![(r("1.0.0.0/8"), "long"), (r("1.2.3.4"), "short")]);
        assert_eq!(idx.find(&r("1.200.0.1")), Some("long"));
    }

    /// Pages merged one at a time give the order one sort of everything gives (equal ranges in
    /// page order), so the index answers as if built at once.
    #[test]
    fn paged_merges_equal_one_sort() {
        let mut all: Vec<(IpRange, String)> = Vec::new();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..2000 {
            let a = (next() % 5000) as u128;
            let len = (next() % 300) as u128;
            all.push((
                IpRange {
                    v4: next() % 3 != 0,
                    first: a,
                    last: a + len,
                },
                format!("f{}", i % 7),
            ));
        }
        let mut acc = IpAcc::default();
        for chunk in all.chunks(137) {
            acc.add_page(chunk.iter().map(|(r, f)| (*r, f.as_str())).collect());
        }
        let idx = acc.finish();
        let mut v4: Vec<(u128, u128, &str)> = all
            .iter()
            .filter(|(r, _)| r.v4)
            .map(|(r, f)| (r.first, r.last, f.as_str()))
            .collect();
        v4.sort_by_key(|a| (a.0, a.1));
        let got: Vec<(u128, u128, &str)> = idx
            .v4
            .0
            .iter()
            .map(|(a, b, f)| (*a, *b, idx.feeds[*f as usize].as_str()))
            .collect();
        assert_eq!(got, v4);
        for _ in 0..500 {
            let a = (next() % 5600) as u128;
            let q = IpRange {
                v4: true,
                first: a,
                last: a + (next() % 50) as u128,
            };
            let brute = all
                .iter()
                .any(|(r, _)| r.v4 && r.first <= q.last && r.last >= q.first);
            assert_eq!(idx.find(&q).is_some(), brute);
        }
    }
}
