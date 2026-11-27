//! Replay of logged queries against feed entries as they stood (core.md §6, attribution steps 1–3),
//! shared by attribution, trial checks, retro-match and the tiering dry run.
//!
//! - **Published configs** ([`PublishedConfig`]): the profile and client definitions, tags
//!   included, from the record's config version (`versions.config`), never the current ones.
//! - **Versions** ([`VersionInfo`]): a bundle head → its `bundle_versions` row → the member feeds
//!   (as that version took them: `definition_json`) and each one's run. A row or a run that is
//!   gone makes the version [`Unavailable`]: replay never falls back to current entries.
//! - **Parts** ([`BundleAt`]): a domain key is replayed against its shard's head (both heads of a
//!   cold shard logged as `[previous, new]`), an address against its IP shard's head, patterns
//!   against their segment's head; rich rules come with the key or pattern that carries them
//!   (bundles.md §6).
//! - **Candidates** ([`Candidates`]): every rule of every member feed at those runs
//!   (`first_run ≤ run < removed_run`) that can match a value: the keys at each suffix of the
//!   name (whole wire labels, rules.md §3), the address's IP rules (an index probe per prefix
//!   length) and the IP-literal keys of its text, and the patterns whose shortcut and regex hit
//!   the text. Raw feed entries, so rules the compiler dropped (subsumed keys) are found too.
//! - **Caches** ([`ReplayCaches`]): published configs and versions (short-lived, so retention is
//!   seen), each feed run's pattern rows (weighed, [`PATTERN_ROW_BYTES`]), and the candidate LRU
//!   keyed by (the record's `versions`, value, qtype, profile, bundle), which holds candidate
//!   rules only: client conditions and response evidence are evaluated again for every event
//!   (weighed, [`CANDIDATE_BYTES`]). Every compiled pattern regex, whoever matches with it (feed
//!   runs' patterns, candidate matchers, retro-match), is in one cache under one budget
//!   ([`PatternBudget`], [`PATTERN_BUDGET`]: core.md §6 "compiled lazily, LRU-cached …, 32 MB
//!   cap"), least recently used dropped first, each eviction giving its bytes back. An entry that
//!   alone outweighs a cache's bound is never kept.
//! - **Pattern admission** ([`ReplayCaches::admission_cut`]): the patterns a version's compile
//!   left out past the pattern budget match nothing in replay either (bundles.md §2
//!   Determinism).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use picket_api::edge_config::{Client, Profile};
use picket_api::logs::{BundleVersion, ColdShardVersion, Versions};
use picket_bundle::hash::KeyHash;
use picket_bundle::head::Head;
use picket_rules::adguard::{MatchTarget, URL_PREFIX, shortcut_present};
use picket_rules::matcher::{PatternRegex, RegexProvider};
use picket_rules::name::OwnedName;
use picket_rules::rule::PatternSpec;
use picket_rules::{BundleMatcher, MatchResult, QueryCtx, Rule, RuleType};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::compiler::source::{OrderKey, Row, View};
use crate::compiler::spec::{self, Member, Runs, Spec};
use crate::config::model::{BundleAction, Model, Tier};

/// The memory every compiled pattern regex replay holds may take (core.md §6: "compiled lazily,
/// LRU-cached per feed run, 32 MB cap"), whichever feed run or matcher uses it.
pub const PATTERN_BUDGET: usize = 32 * 1024 * 1024;
/// Patterns one feed run may hold in the cache; a feed run with more is matched without its
/// patterns and the attribution is marked incomplete (the compiler warns past 10k patterns,
/// bundles.md §2).
pub const MAX_PATTERNS_PER_RUN: usize = 100_000;
/// Candidate sets the LRU keeps, and the bytes they may take (rows and matchers, weighed).
pub const CANDIDATE_ENTRIES: usize = 8192;
pub const CANDIDATE_BYTES: usize = 64 * 1024 * 1024;
/// Feed runs whose pattern rows the cache keeps, and the bytes those rows may take (their
/// compiled regexes are in [`PATTERN_BUDGET`]).
pub const PATTERN_RUNS: usize = 4096;
pub const PATTERN_ROW_BYTES: usize = 64 * 1024 * 1024;
/// Published configs and versions kept; re-read after [`META_TTL`] so retention is seen.
const META_ENTRIES: usize = 512;
const META_TTL: Duration = Duration::from_secs(300);
/// Rules one value may gather in one bundle (README §2, Bounded).
pub const MAX_CANDIDATES: usize = 20_000;

/// A small LRU with weights: inserting past `cap` (entries) or `max_weight` evicts the least
/// recently used entries.
pub struct Lru<K, V> {
    map: HashMap<K, (V, u64, usize)>,
    tick: u64,
    cap: usize,
    max_weight: usize,
    weight: usize,
}

impl<K: std::hash::Hash + Eq + Clone, V: Clone> Lru<K, V> {
    pub fn new(cap: usize, max_weight: usize) -> Self {
        Self {
            map: HashMap::new(),
            tick: 0,
            cap: cap.max(1),
            max_weight,
            weight: 0,
        }
    }

    pub fn get(&mut self, k: &K) -> Option<V> {
        self.tick = self.tick.wrapping_add(1);
        let t = self.tick;
        self.map.get_mut(k).map(|e| {
            e.1 = t;
            e.0.clone()
        })
    }

    /// Inserts `v` under `k`, evicting the least recently used entries until the cache is within
    /// both bounds. An entry heavier than `max_weight` on its own is refused (and an older value
    /// under `k` dropped): it never fits, and keeping it would hold the cache above its bound
    /// (README §2 Bounded). Returns whether `v` is kept.
    pub fn insert(&mut self, k: K, v: V, weight: usize) -> bool {
        self.tick = self.tick.wrapping_add(1);
        if weight > self.max_weight {
            if let Some(old) = self.map.remove(&k) {
                self.weight = self.weight.saturating_sub(old.2);
            }
            return false;
        }
        if let Some(old) = self.map.insert(k.clone(), (v, self.tick, weight)) {
            self.weight = self.weight.saturating_sub(old.2);
        }
        self.weight = self.weight.saturating_add(weight);
        while self.map.len() > self.cap || self.weight > self.max_weight {
            let Some(oldest) = self
                .map
                .iter()
                .filter(|(key, _)| **key != k)
                .min_by_key(|(_, e)| e.1)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(e) = self.map.remove(&oldest) {
                self.weight = self.weight.saturating_sub(e.2);
            }
        }
        true
    }

    /// The entries with their last use (larger is more recent), in no order.
    pub fn entries(&self) -> impl Iterator<Item = (&K, &V, u64)> {
        self.map.iter().map(|(k, e)| (k, &e.0, e.1))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The summed weight of the entries held.
    pub fn weight(&self) -> usize {
        self.weight
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.weight = 0;
    }
}

// Published configs ---------------------------------------------------------------------------

/// The parts of a published `EdgeConfig` replay reads (core.md §6 "Published configs").
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PublishedConfig {
    /// The full config id.
    #[serde(skip)]
    pub id: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default)]
    pub clients: Vec<Client>,
    #[serde(default)]
    pub cache: Option<PublishedCache>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PublishedCache {
    #[serde(default)]
    pub stale_ttl_s: u32,
}

impl PublishedConfig {
    /// The client entry a record's `device` names (its client name; a MAC names none).
    pub fn client(&self, device: Option<&str>) -> Option<&Client> {
        let d = device?;
        self.clients.iter().find(|c| c.name == d)
    }
}

/// The published config `short` (the record's `versions.config`) of `edge`.
pub fn load_config(c: &Connection, edge: &str, short: &str) -> Result<Option<PublishedConfig>> {
    if short.is_empty() || short.len() > 64 || !short.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let short = short.to_ascii_lowercase();
    let row: Option<(String, String)> = c
        .query_row(
            "SELECT config_id, body_json FROM edge_configs
             WHERE config_id >= ?1 AND config_id < ?1 || 'g' AND edge_id = ?2 ORDER BY published_at DESC LIMIT 1",
            params![short, edge],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((id, body)) = row else { return Ok(None) };
    let mut cfg: PublishedConfig = serde_json::from_str(&body).unwrap_or_default();
    cfg.id = id;
    Ok(Some(cfg))
}

// Versions -------------------------------------------------------------------------------------

/// Why a version can't be replayed (core.md §6 step 1: store `unavailable`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unavailable {
    pub bundle: String,
    pub head: String,
    pub reason: String,
}

/// One bundle version as replay reads it.
#[derive(Debug)]
pub struct VersionInfo {
    pub bundle: String,
    /// The full head id.
    pub head_id: String,
    pub head: Head,
    pub spec: Spec,
    pub runs: Runs,
}

/// The stored form of a version's definition (`bundle_versions.definition_json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDefinition {
    pub action: String,
    pub members: Vec<StoredMember>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMember {
    pub feed: String,
    pub types: Vec<String>,
    pub tier: String,
}

/// The `definition_json` the compiler stores with each version.
pub fn definition_json(spec: &Spec) -> String {
    let d = StoredDefinition {
        action: spec.action.as_str().to_string(),
        members: spec
            .members
            .iter()
            .map(|m| StoredMember {
                feed: m.feed.clone(),
                types: m.types.iter().map(|t| t.as_str().to_string()).collect(),
                tier: m.tier.as_str().to_string(),
            })
            .collect(),
    };
    serde_json::to_string(&d).unwrap_or_else(|_| "{}".into())
}

fn action_of(s: &str) -> BundleAction {
    match s {
        "allow" => BundleAction::Allow,
        "scope" => BundleAction::Scope,
        "warn" => BundleAction::Warn,
        _ => BundleAction::Block,
    }
}

fn tier_of(s: &str) -> Tier {
    match s {
        "cold" => Tier::Cold,
        "intelligent-tiering" => Tier::IntelligentTiering,
        _ => Tier::Hot,
    }
}

/// The spec a version was built from: its stored definition; for a version stored without one,
/// the current definition when its hash matches, else every member feed of its runs, taking
/// every rule type.
fn version_spec(bundle: &str, def_json: Option<&str>, def_hash: &str, runs: &Runs, model: &Model) -> Spec {
    let members: Vec<Member> = match def_json.and_then(|s| serde_json::from_str::<StoredDefinition>(s).ok()) {
        Some(d) => {
            let action = action_of(&d.action);
            let members = d
                .members
                .iter()
                .enumerate()
                .map(|(i, m)| Member {
                    feed: m.feed.clone(),
                    position: u32::try_from(i).unwrap_or(u32::MAX),
                    types: m.types.iter().filter_map(|t| RuleType::parse(t)).collect(),
                    tier: tier_of(&m.tier),
                    downloaded: false,
                    warn_on: Vec::new(),
                })
                .collect();
            return Spec {
                id: bundle.to_string(),
                action,
                members,
                max_shard_keys: 0,
                hot_max_mib: None,
                def_hash: def_hash.to_string(),
            };
        }
        None => match model.bundles.get(bundle) {
            Some(def) => {
                let s = Spec::of(def, model);
                if s.def_hash == def_hash {
                    return s;
                }
                runs.keys()
                    .enumerate()
                    .map(|(i, f)| Member {
                        feed: f.clone(),
                        position: u32::try_from(i).unwrap_or(u32::MAX),
                        types: RuleType::ALL.to_vec(),
                        tier: Tier::Hot,
                        downloaded: false,
                        warn_on: Vec::new(),
                    })
                    .collect()
            }
            None => runs
                .keys()
                .enumerate()
                .map(|(i, f)| Member {
                    feed: f.clone(),
                    position: u32::try_from(i).unwrap_or(u32::MAX),
                    types: RuleType::ALL.to_vec(),
                    tier: Tier::Hot,
                    downloaded: false,
                    warn_on: Vec::new(),
                })
                .collect(),
        },
    };
    let action = model
        .bundles
        .get(bundle)
        .map(|b| b.action)
        .unwrap_or(BundleAction::Block);
    Spec {
        id: bundle.to_string(),
        action,
        members,
        max_shard_keys: 0,
        hot_max_mib: None,
        def_hash: def_hash.to_string(),
    }
}

/// The version of `bundle` whose head id starts with `short` (logs show 16 hex characters).
pub fn load_version(
    c: &Connection,
    bundle: &str,
    short: &str,
    model: &Model,
) -> Result<Result<VersionInfo, Unavailable>> {
    let unavailable = |reason: &str| Unavailable {
        bundle: bundle.to_string(),
        head: short.to_string(),
        reason: reason.to_string(),
    };
    if short.is_empty() || short.len() > 64 || !short.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(Err(unavailable("not a head id")));
    }
    let short_l = short.to_ascii_lowercase();
    let row: Option<(String, String, String, String, Option<String>)> = c
        .query_row(
            "SELECT head_id, heads_json, feed_runs_json, definition_hash, definition_json FROM bundle_versions
             WHERE bundle_id = ?1 AND head_id >= ?2 AND head_id < ?2 || 'g' LIMIT 1",
            params![bundle, short_l],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((head_id, head_json, runs_json, def_hash, def_json)) = row else {
        return Ok(Err(unavailable("the bundle version is gone")));
    };
    let Ok(head) = Head::from_bytes(head_json.as_bytes()) else {
        return Ok(Err(unavailable("the version's head doesn't parse")));
    };
    let runs = spec::parse_runs(&runs_json);
    let mut st = c.prepare_cached("SELECT 1 FROM feed_runs WHERE id = ?1")?;
    for (feed, run) in &runs {
        if *run > 0 && !st.exists([run])? {
            return Ok(Err(unavailable(&format!("feed {feed}'s run {run} is gone"))));
        }
    }
    let spec = version_spec(bundle, def_json.as_deref(), &def_hash, &runs, model);
    Ok(Ok(VersionInfo {
        bundle: bundle.to_string(),
        head_id,
        head,
        spec,
        runs,
    }))
}

// Caches ---------------------------------------------------------------------------------------

type Meta<T> = (Instant, T);

/// A published config, if core still has it.
pub type Config = Option<Arc<PublishedConfig>>;

/// A version, or why it can't be replayed.
pub type Version = Arc<Result<VersionInfo, Unavailable>>;

/// One feed run's patterns (rows read once; their regexes live in the shared [`PatternBudget`]).
pub struct FeedPatterns {
    rows: Vec<(Row, PatternSpec)>,
    /// The rows' approximate heap bytes (the patterns LRU's weight).
    bytes: usize,
    /// Too many patterns: matched without them.
    pub over_cap: bool,
}

impl FeedPatterns {
    /// The rows whose pattern matches the text form `text` (rules.md §3).
    pub fn matching(&self, text: &str, budget: &PatternBudget) -> Vec<Row> {
        self.rows
            .iter()
            .filter(|(_, p)| budget.pattern_hits(p, text))
            .map(|(row, _)| row.clone())
            .collect()
    }
}

/// True when the reference matcher's pattern admission costs `rule`'s pattern `p` (picket-rules'
/// `pattern_entry`, and a pattern that doesn't match everything and has a regex): the patterns
/// a compile can leave out past the budget.
fn admission_costed(action: picket_rules::BundleAction, rule: &Rule, p: &PatternSpec) -> bool {
    !(rule.kind.is_browser()
        || rule.rule_type == RuleType::Browser
        || (action == picket_rules::BundleAction::Scope && rule.rule_type != RuleType::Dns)
        || (rule.is_badfilter() && !rule.is_rewrite())
        || !matches!(
            rule.key_kind(),
            picket_rules::Kind::Pattern | picket_rules::Kind::Regex
        )
        || p.matches_all
        || p.regex.is_none())
}

/// Bytes a stored row takes on the heap, approximately: its strings, and its rule's spec about
/// twice its stored JSON (README §2 Bounded: the caches are weighed by what they hold).
pub fn row_bytes(r: &Row) -> usize {
    std::mem::size_of::<Row>()
        .saturating_add(r.order.key.len())
        .saturating_add(r.order.value_json.len().saturating_mul(3))
        .saturating_add(r.feed.len())
        .saturating_add(r.first_seen_at.len())
        .saturating_add(r.rule.key.len())
        .saturating_add(32)
}

fn pattern_spec_bytes(p: &PatternSpec) -> usize {
    std::mem::size_of::<PatternSpec>()
        .saturating_add(p.source.len())
        .saturating_add(p.regex.as_ref().map_or(0, String::len))
        .saturating_add(p.shortcut.as_ref().map_or(0, String::len))
}

/// Bytes one cached regex entry takes beyond the regex itself (its key and the map entry).
const REGEX_ENTRY_OVERHEAD: usize = 96;
/// The share of the pattern budget (1/n) that holds the regexes' search caches grown past their
/// fresh size, as picket-rules' reference matcher splits its own budget: the rest holds the
/// regexes with fresh caches.
const GROWTH_SHARE: usize = 4;
/// Pattern sources whose resident cost is remembered for the admission of bundle versions
/// ([`ReplayCaches::admission_cut`]); each entry is a source and a number.
const COST_ENTRIES: usize = 1 << 18;
const COST_BYTES: usize = 32 * 1024 * 1024;

/// The compiled pattern regexes of everything replay matches, under one budget (core.md §6:
/// "compiled lazily, LRU-cached …, 32 MB cap"): one entry per regex source, shared by every feed
/// run's patterns, every candidate set's matcher ([`picket_rules::RegexProvider`]: a candidate
/// matcher compiles nothing of its own) and retro-match ([`ReplayCaches::pattern_hits`]).
///
/// The budget is split as the reference matcher splits its own: three quarters hold the regexes,
/// each charged what it holds when kept ([`PatternRegex::resident_cost`]: its heap and a fresh
/// search cache, plus its key), least recently used dropped first when a new one doesn't fit, an
/// evicted or cleared entry's charge given back with it; the last quarter is one pool for the
/// search caches' growth past their fresh size, measured after each search: past the pool, the
/// least recently used grown caches are reset (their regexes stay). A regex costing more than the
/// regexes' share on its own is built for the one use and not kept. A regex that doesn't build
/// matches nothing.
pub struct PatternBudget {
    cache: Mutex<Lru<String, Option<Arc<PatternRegex>>>>,
    max: usize,
    /// The search caches' growth past their fresh size, as last summed (approximate between
    /// trims, exact after one).
    growth: std::sync::atomic::AtomicUsize,
    builds: std::sync::atomic::AtomicU64,
}

impl PatternBudget {
    pub fn new(max: usize) -> Self {
        Self {
            cache: Mutex::new(Lru::new(1 << 20, Self::resident_limit(max))),
            max,
            growth: Default::default(),
            builds: Default::default(),
        }
    }

    /// The share of `max` that holds regexes with fresh caches.
    fn resident_limit(max: usize) -> usize {
        max.saturating_sub(max / GROWTH_SHARE)
    }

    /// The pool for search caches grown past their fresh size.
    fn growth_pool(&self) -> usize {
        self.max / GROWTH_SHARE
    }

    /// The regex built from `source`, from the cache or built now (and kept when it fits).
    fn regex(&self, source: &str) -> Option<Arc<PatternRegex>> {
        if let Ok(mut c) = self.cache.lock()
            && let Some(r) = c.get(&source.to_string())
        {
            return r;
        }
        let built = PatternRegex::build(source).map(Arc::new);
        self.builds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cost = built
            .as_ref()
            .map_or(0, |r| r.resident_cost())
            .saturating_add(source.len())
            .saturating_add(REGEX_ENTRY_OVERHEAD);
        if let Ok(mut c) = self.cache.lock() {
            c.insert(source.to_string(), built.clone(), cost);
        }
        built
    }

    /// The resident cost of the regex `source` builds ([`picket_rules::matcher::pattern_cost`]),
    /// from the cache when it holds it; `None` when it doesn't build.
    fn resident_cost(&self, source: &str) -> Option<usize> {
        if let Ok(mut c) = self.cache.lock()
            && let Some(r) = c.get(&source.to_string())
        {
            return r.map(|r| r.resident_cost());
        }
        picket_rules::matcher::pattern_cost(source)
    }

    /// Searches `hay` with the regex built from `source`, then charges its cache's growth to
    /// the pool, resetting the least recently used grown caches when the pool is full.
    fn search(&self, source: &str, hay: &str) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let Some(r) = self.regex(source) else {
            return false;
        };
        let before = r.growth();
        let hit = r.is_match(hay);
        let after = r.growth();
        if after > before {
            let total = self
                .growth
                .fetch_add(after - before, Relaxed)
                .saturating_add(after - before);
            if total > self.growth_pool() {
                self.trim();
            }
        } else if before > after {
            let d = before - after;
            self.growth.update(Relaxed, Relaxed, |g| g.saturating_sub(d));
        }
        hit
    }

    /// Resets the least recently used grown caches until the kept regexes' growth fits the pool;
    /// the sum is taken again from the entries, so growth of evicted regexes stops counting.
    fn trim(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let Ok(c) = self.cache.lock() else { return };
        let mut grown: Vec<(u64, Arc<PatternRegex>)> = c
            .entries()
            .filter_map(|(_, v, t)| v.as_ref().filter(|r| r.growth() > 0).map(|r| (t, r.clone())))
            .collect();
        let mut total: usize = grown.iter().map(|(_, r)| r.growth()).sum();
        grown.sort_unstable_by_key(|(t, _)| *t);
        for (_, r) in grown {
            if total <= self.growth_pool() {
                break;
            }
            total = total.saturating_sub(r.reset_cache());
        }
        self.growth.store(total, Relaxed);
    }

    /// True when pattern `p` matches the text form `text` (rules.md §3): its shortcut is present
    /// and its regex matches the text (or, for an `HttpHost` pattern, `"http://"` + text); a
    /// pattern without a regex, or whose regex doesn't build, matches nothing.
    pub fn pattern_hits(&self, p: &PatternSpec, text: &str) -> bool {
        if !shortcut_present(p.shortcut.as_deref(), text) {
            return false;
        }
        if p.matches_all {
            return true;
        }
        let Some(src) = p.regex.as_deref() else {
            return false;
        };
        match p.target {
            MatchTarget::Host => self.is_match(src, text),
            MatchTarget::HttpHost => {
                let mut url = String::with_capacity(URL_PREFIX.len().saturating_add(text.len()));
                url.push_str(URL_PREFIX);
                url.push_str(text);
                self.is_match(src, &url)
            }
        }
    }

    /// Bytes charged now: the kept regexes with fresh caches and their caches' growth (at most
    /// the budget once trimmed).
    pub fn used(&self) -> usize {
        let resident = self.cache.lock().map(|c| c.weight()).unwrap_or(0);
        resident.saturating_add(
            self.growth
                .load(std::sync::atomic::Ordering::Relaxed)
                .min(self.growth_pool()),
        )
    }

    /// Regexes kept now.
    pub fn len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Regexes built so far (a rebuild after an eviction counts again).
    pub fn builds(&self) -> u64 {
        self.builds.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The budget in bytes.
    pub fn max(&self) -> usize {
        self.max
    }

    /// Drops every regex, giving back their charge.
    pub fn clear(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
        self.growth.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

impl RegexProvider for PatternBudget {
    fn is_match(&self, source: &str, haystack: &str) -> bool {
        self.search(source, haystack)
    }
}

/// A candidate set: the rules of one bundle that can match one value, with their matcher.
pub struct Candidates {
    pub rows: Vec<Row>,
    pub matcher: BundleMatcher,
    /// Some rules couldn't be read or were cut by a cap (a feed run with too many patterns, more
    /// than [`MAX_CANDIDATES`] rules for the value, more parts than replay reads): the result may
    /// miss them, so the attribution is `incomplete` and skips the self-check (core.md §6).
    pub partial: bool,
}

impl Candidates {
    /// Its rows plus the matcher's copies of their rules and its indexes (about the rows again).
    fn weight(&self) -> usize {
        self.rows
            .iter()
            .map(row_bytes)
            .sum::<usize>()
            .saturating_mul(2)
            .saturating_add(1024)
    }
}

/// The candidate LRU's key (core.md §6): the record's versions, the value, qtype, profile and
/// bundle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CandKey {
    pub versions: String,
    pub value: String,
    pub qtype: u16,
    pub profile: String,
    pub bundle: String,
}

/// Replay's caches, shared by every analysis batch.
pub struct ReplayCaches {
    configs: Mutex<Lru<(String, String), Meta<Config>>>,
    versions: Mutex<Lru<(String, String), Meta<Version>>>,
    patterns: Mutex<Lru<(String, i64, u8), Arc<FeedPatterns>>>,
    /// Every compiled pattern regex (one budget, [`PatternBudget`]).
    pub budget: Arc<PatternBudget>,
    candidates: Mutex<Lru<CandKey, Arc<Candidates>>>,
    /// Per pattern version (bundle, head), the first pattern its compile left out
    /// ([`ReplayCaches::admission_cut`]).
    admissions: Mutex<Lru<(String, String), Option<OrderKey>>>,
    /// Each pattern source's resident cost ([`picket_rules::matcher::pattern_cost`]; `None`: it
    /// doesn't build), for the admissions.
    costs: Mutex<Lru<String, Option<usize>>>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl Default for ReplayCaches {
    fn default() -> Self {
        Self::with_budget(PATTERN_BUDGET)
    }
}

impl ReplayCaches {
    pub fn with_budget(budget: usize) -> Self {
        Self {
            configs: Mutex::new(Lru::new(META_ENTRIES, usize::MAX)),
            versions: Mutex::new(Lru::new(META_ENTRIES, usize::MAX)),
            patterns: Mutex::new(Lru::new(PATTERN_RUNS, PATTERN_ROW_BYTES)),
            budget: Arc::new(PatternBudget::new(budget)),
            candidates: Mutex::new(Lru::new(CANDIDATE_ENTRIES, CANDIDATE_BYTES)),
            admissions: Mutex::new(Lru::new(META_ENTRIES, usize::MAX)),
            costs: Mutex::new(Lru::new(COST_ENTRIES, COST_BYTES)),
            hits: Default::default(),
            misses: Default::default(),
        }
    }

    /// Candidate LRU hits and misses so far.
    pub fn candidate_stats(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (self.hits.load(Relaxed), self.misses.load(Relaxed))
    }

    /// Forgets everything (after a restore or in tests).
    pub fn clear(&self) {
        if let Ok(mut m) = self.configs.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.versions.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.candidates.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.patterns.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.admissions.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.costs.lock() {
            m.clear();
        }
        self.budget.clear();
    }

    /// The resident cost of pattern regex `source` (remembered; `None`: it doesn't build).
    fn cost_of(&self, source: &str) -> Option<usize> {
        if let Ok(mut m) = self.costs.lock()
            && let Some(c) = m.get(&source.to_string())
        {
            return c;
        }
        let c = self.budget.resident_cost(source);
        if let Ok(mut m) = self.costs.lock() {
            m.insert(source.to_string(), c, source.len().saturating_add(64));
        }
        c
    }

    /// The first pattern (in bundle order) that the compile of pattern version `v` left out as
    /// over the pattern budget, if any: the compiler admits patterns as picket-rules' reference
    /// matcher does over the whole bundle ([`picket_rules::matcher::pattern_admission`] under
    /// picket-bundle's budget: in bundle order, each costed and kept while the total fits; at the
    /// first that doesn't, it and every later costed pattern are dropped), so the edge never runs
    /// them. Replay matches one value's candidates, a part of the bundle whose own admission would
    /// keep more, so it applies the whole bundle's (bundles.md §2 Determinism: replay decides as the
    /// compiled bundle does). Computed once per version from each feed run's cached patterns,
    /// each source's cost remembered.
    pub fn admission_cut(&self, c: &Connection, v: &VersionInfo) -> Result<Option<OrderKey>> {
        let k = (v.bundle.clone(), v.head_id.clone());
        if let Ok(mut m) = self.admissions.lock()
            && let Some(cut) = m.get(&k)
        {
            return Ok(cut);
        }
        let action = spec::rules_action(v.spec.action);
        let limit = picket_rules::matcher::pattern_admission_limit(picket_bundle::patterns::DEFAULT_BUDGET);
        let view = View::new(&v.spec, &v.runs);
        let mut feeds: Vec<(&Member, i64)> = view
            .feeds()
            .filter_map(|(f, run)| v.spec.member(f).map(|m| (m, run)))
            .collect();
        feeds.sort_by_key(|(m, _)| m.position);
        let mut used = 0usize;
        let mut cut: Option<OrderKey> = None;
        'feeds: for (m, run) in feeds {
            let fp = self.feed_patterns(c, &v.spec, m, run)?;
            for (row, p) in &fp.rows {
                if !admission_costed(action, &row.rule, p) {
                    continue;
                }
                let Some(cost) = p.regex.as_deref().and_then(|src| self.cost_of(src)) else {
                    continue;
                };
                if used.saturating_add(cost) > limit {
                    let mut o = row.order.clone();
                    o.position = m.position;
                    cut = Some(o);
                    break 'feeds;
                }
                used = used.saturating_add(cost);
            }
        }
        if let Ok(mut m) = self.admissions.lock() {
            m.insert(k, cut.clone(), 1);
        }
        Ok(cut)
    }

    /// True when pattern `p` matches the text form `text` (rules.md §3), its regex from the
    /// shared budget ([`PatternBudget::pattern_hits`]); conditions aren't looked at.
    pub fn pattern_hits(&self, p: &PatternSpec, text: &str) -> bool {
        self.budget.pattern_hits(p, text)
    }

    /// A matcher over `rules` for replay's callers: the public suffix list given, and its pattern
    /// regexes from the shared budget (it compiles none of its own).
    pub fn matcher(&self, action: picket_rules::BundleAction, rules: Vec<Rule>) -> BundleMatcher {
        let provider: Arc<dyn RegexProvider> = self.budget.clone();
        BundleMatcher::new(action, rules)
            .with_public_suffix_list(crate::psl::rules_list())
            .with_regex_provider(provider)
    }

    pub fn config(&self, c: &Connection, edge: &str, short: &str) -> Result<Option<Arc<PublishedConfig>>> {
        let k = (edge.to_string(), short.to_string());
        if let Ok(mut m) = self.configs.lock()
            && let Some((at, v)) = m.get(&k)
            && at.elapsed() < META_TTL
        {
            return Ok(v);
        }
        let v = load_config(c, edge, short)?.map(Arc::new);
        if let Ok(mut m) = self.configs.lock() {
            m.insert(k, (Instant::now(), v.clone()), 1);
        }
        Ok(v)
    }

    pub fn version(
        &self,
        c: &Connection,
        bundle: &str,
        short: &str,
        model: &Model,
    ) -> Result<Arc<Result<VersionInfo, Unavailable>>> {
        let k = (bundle.to_string(), short.to_string());
        if let Ok(mut m) = self.versions.lock()
            && let Some((at, v)) = m.get(&k)
            && at.elapsed() < META_TTL
        {
            return Ok(v);
        }
        let v = Arc::new(load_version(c, bundle, short, model)?);
        if let Ok(mut m) = self.versions.lock() {
            m.insert(k, (Instant::now(), v.clone()), 1);
        }
        Ok(v)
    }

    /// One member feed's patterns at `run`, as `spec` takes it.
    fn feed_patterns(&self, c: &Connection, spec: &Spec, m: &Member, run: i64) -> Result<Arc<FeedPatterns>> {
        let types = spec.compiled_types(m);
        let bits = types.iter().fold(0u8, |a, t| {
            a | match t {
                RuleType::Dns => 1,
                RuleType::Ip => 2,
                RuleType::Browser => 4,
            }
        });
        let k = (m.feed.clone(), run, bits);
        if let Ok(mut l) = self.patterns.lock()
            && let Some(p) = l.get(&k)
        {
            return Ok(p);
        }
        // Read at position 0; the caller re-stamps the member's position.
        let one = Spec {
            id: spec.id.clone(),
            action: spec.action,
            members: vec![Member {
                position: 0,
                ..m.clone()
            }],
            max_shard_keys: 0,
            hot_max_mib: None,
            def_hash: String::new(),
        };
        let runs = Runs::from([(m.feed.clone(), run)]);
        let view = View::new(&one, &runs);
        let mut bad = 0u64;
        let (rows, over_cap) = match view.patterns(c, MAX_PATTERNS_PER_RUN, &mut bad)? {
            Ok(rows) => (rows, false),
            Err(_) => (Vec::new(), true),
        };
        if over_cap {
            tracing::warn!(feed = %m.feed, run, "too many patterns to replay; matched without them");
        }
        let rows: Vec<(Row, PatternSpec)> = rows
            .into_iter()
            .filter_map(|r| r.rule.pattern_spec().map(|p| (r, p)))
            .collect();
        let bytes = rows
            .iter()
            .map(|(r, p)| row_bytes(r).saturating_add(pattern_spec_bytes(p)))
            .sum::<usize>()
            .saturating_add(std::mem::size_of::<FeedPatterns>());
        // Rows that alone outweigh the cache's bound are never kept (README §2 Bounded): matched
        // without them, like a feed run past the pattern cap.
        let (rows, bytes, over_cap) = if bytes > PATTERN_ROW_BYTES {
            tracing::warn!(feed = %m.feed, run, bytes, "pattern rows too large to replay; matched without them");
            (Vec::new(), std::mem::size_of::<FeedPatterns>(), true)
        } else {
            (rows, bytes, over_cap)
        };
        let fp = Arc::new(FeedPatterns {
            rows,
            bytes,
            over_cap,
        });
        if let Ok(mut l) = self.patterns.lock() {
            l.insert(k, fp.clone(), fp.bytes);
        }
        Ok(fp)
    }
}

// The record's bundles -------------------------------------------------------------------------

/// The heads one bundle's parts came from, for one record (api.md §5 `versions`).
pub struct BundleAt {
    pub bundle: String,
    /// The head every part came from (plain), or the head being activated.
    pub head: Arc<Result<VersionInfo, Unavailable>>,
    /// Per active shard number, its head; per cold shard number, one or two heads; per IP shard,
    /// its head; per segment, its head. Empty for a plain version.
    shards: Vec<(u32, Arc<Result<VersionInfo, Unavailable>>)>,
    cold: Vec<(u32, Vec<Version>)>,
    ip_shards: HashMap<String, Arc<Result<VersionInfo, Unavailable>>>,
    patterns: Option<Arc<Result<VersionInfo, Unavailable>>>,
    /// The record listed more parts than replay reads ([`MAX_PARTS`]): a value in a part past the
    /// cap is read at the head, so its candidates are `partial`.
    pub truncated: bool,
}

/// Shards (hot or cold) and IP shards one record's `versions` entry is read for (README §2
/// Bounded; a head's shard directory has 256 entries and a bundle at most 257 IP shards,
/// bundles.md §4, so a real record stays below).
pub const MAX_PARTS: usize = 1024;

impl BundleAt {
    /// Resolves the record's `versions` entry for `bundle`.
    pub fn resolve(
        caches: &ReplayCaches,
        c: &Connection,
        model: &Model,
        bundle: &str,
        v: &BundleVersion,
    ) -> Result<BundleAt> {
        match v {
            BundleVersion::Plain(short) => Ok(BundleAt {
                bundle: bundle.to_string(),
                head: caches.version(c, bundle, short, model)?,
                shards: Vec::new(),
                cold: Vec::new(),
                ip_shards: HashMap::new(),
                patterns: None,
                truncated: false,
            }),
            BundleVersion::Parts(p) => {
                let head = caches.version(c, bundle, &p.head, model)?;
                let mut shards = Vec::new();
                let truncated = p.shards.len() > MAX_PARTS
                    || p.cold_shards.len() > MAX_PARTS
                    || p.ip_shards.len() > MAX_PARTS;
                for (n, h) in p.shards.iter().take(MAX_PARTS) {
                    if let Ok(n) = n.parse::<u32>() {
                        shards.push((n, caches.version(c, bundle, h, model)?));
                    }
                }
                let mut cold = Vec::new();
                for (n, h) in p.cold_shards.iter().take(MAX_PARTS) {
                    let Ok(n) = n.parse::<u32>() else { continue };
                    let heads = match h {
                        ColdShardVersion::One(h) => vec![caches.version(c, bundle, h, model)?],
                        ColdShardVersion::Moving([a, b]) => vec![
                            caches.version(c, bundle, a, model)?,
                            caches.version(c, bundle, b, model)?,
                        ],
                    };
                    cold.push((n, heads));
                }
                let mut ip_shards = HashMap::new();
                for (id, h) in p.ip_shards.iter().take(MAX_PARTS) {
                    ip_shards.insert(id.clone(), caches.version(c, bundle, h, model)?);
                }
                let patterns = match p.segments.get("patterns.bin") {
                    Some(h) => Some(caches.version(c, bundle, h, model)?),
                    None => None,
                };
                Ok(BundleAt {
                    bundle: bundle.to_string(),
                    head,
                    shards,
                    cold,
                    ip_shards,
                    patterns,
                    truncated,
                })
            }
        }
    }

    /// Every version this record's parts of the bundle came from; the first unavailable one, if
    /// any (core.md §6 step 1).
    pub fn unavailable(&self) -> Option<Unavailable> {
        let all = std::iter::once(&self.head)
            .chain(self.shards.iter().map(|(_, v)| v))
            .chain(self.cold.iter().flat_map(|(_, v)| v.iter()))
            .chain(self.ip_shards.values())
            .chain(self.patterns.iter());
        for v in all {
            if let Err(u) = v.as_ref() {
                return Some(u.clone());
            }
        }
        None
    }

    fn ok(v: &Arc<Result<VersionInfo, Unavailable>>) -> Option<&VersionInfo> {
        v.as_ref().as_ref().ok()
    }

    /// The versions a domain key is read at: its hot shard's head, and the head(s) of the cold
    /// shard holding its hash, if any (a key is in one part; the union covers both).
    fn key_versions(&self, key: &str) -> Vec<&VersionInfo> {
        let Some(head) = Self::ok(&self.head) else {
            return Vec::new();
        };
        if self.shards.is_empty() && self.cold.is_empty() {
            return vec![head];
        }
        let h = KeyHash::of(head.head.hash_seed, key.as_bytes());
        let idx = usize::from(h.dir_index());
        let mut out: Vec<&VersionInfo> = Vec::new();
        let covers = |v: &VersionInfo, n: u32, cold: bool| -> bool {
            let dir = if cold {
                &v.head.cold_shard_dir
            } else {
                &v.head.shard_dir
            };
            dir.iter()
                .find(|e| e.shard == n)
                .and_then(|e| e.index_range())
                .is_some_and(|(a, b)| a <= idx && idx < b)
        };
        for (n, v) in &self.shards {
            if let Some(v) = Self::ok(v)
                && covers(v, *n, false)
            {
                out.push(v);
                break;
            }
        }
        for (n, vs) in &self.cold {
            let hit = vs.iter().filter_map(Self::ok).any(|v| covers(v, *n, true));
            if hit {
                out.extend(vs.iter().filter_map(Self::ok));
                break;
            }
        }
        if out.is_empty() {
            out.push(head);
        }
        out
    }

    fn ip_version(&self, ip: IpAddr) -> Option<&VersionInfo> {
        let id = match picket_rules::ip::canonical_ip(ip) {
            IpAddr::V4(v4) => format!("v4/{}", v4.octets()[0]),
            IpAddr::V6(_) => "v6".to_string(),
        };
        self.ip_shards
            .get(&id)
            .and_then(Self::ok)
            .or_else(|| Self::ok(&self.head))
    }

    fn pattern_version(&self) -> Option<&VersionInfo> {
        self.patterns
            .as_ref()
            .and_then(Self::ok)
            .or_else(|| Self::ok(&self.head))
    }

    /// The bundle's action as its head took it.
    pub fn action(&self) -> Option<BundleAction> {
        Self::ok(&self.head).map(|v| v.spec.action)
    }

    /// The full head id of the head every part came from (or the one being activated).
    pub fn head_id(&self) -> Option<&str> {
        Self::ok(&self.head).map(|v| v.head_id.as_str())
    }

    /// The feed runs of the head (for display).
    pub fn feed_runs(&self) -> Option<&Runs> {
        Self::ok(&self.head).map(|v| &v.runs)
    }

    /// The member spec of the head.
    pub fn spec(&self) -> Option<&Spec> {
        Self::ok(&self.head).map(|v| &v.spec)
    }
}

/// A value replay checks: a name (wire labels) or an address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    Name(Vec<Vec<u8>>),
    Ip(IpAddr),
}

impl Value {
    /// A name from its log text (api.md §5 escapes); `None` when it doesn't decode.
    pub fn name_from_log(text: &str) -> Option<Value> {
        let t = text.trim_end_matches('.');
        if t.is_empty() {
            return None;
        }
        picket_api::names::decode_labels(t).map(Value::Name)
    }

    /// Its log text (names) or address text.
    pub fn text(&self) -> String {
        match self {
            Value::Name(l) => picket_api::names::encode_labels(l.iter().map(Vec::as_slice)),
            Value::Ip(ip) => picket_rules::ip::go_ip_string(*ip),
        }
    }
}

/// The candidate rules of one bundle for one value (see the module docs), whether they may be
/// partial, and the entry ids among them of patterns the version's compile left out
/// ([`ReplayCaches::admission_cut`]).
pub fn gather(
    c: &Connection,
    caches: &ReplayCaches,
    at: &BundleAt,
    value: &Value,
) -> Result<(Vec<Row>, bool, HashSet<i64>)> {
    let mut rows: Vec<Row> = Vec::new();
    let mut seen: HashSet<i64> = HashSet::new();
    let mut partial = false;
    let mut bad = 0u64;
    let mut capped = false;
    let mut push = |rows: &mut Vec<Row>, r: Row| {
        if seen.insert(r.entry_id) {
            if rows.len() < MAX_CANDIDATES {
                rows.push(r);
            } else {
                capped = true;
            }
        }
    };
    // Keys at each suffix of the name, or of the address's text labels.
    let labels: Vec<Vec<u8>> = match value {
        Value::Name(l) => l.clone(),
        Value::Ip(ip) => {
            let t = picket_rules::ip::go_ip_string(picket_rules::ip::canonical_ip(*ip));
            if ip.is_ipv4() || picket_rules::ip::canonical_ip(*ip).is_ipv4() {
                t.split('.').map(|s| s.as_bytes().to_vec()).collect()
            } else {
                vec![t.into_bytes()]
            }
        }
    };
    let first_ok = labels
        .iter()
        .rposition(|l| l.contains(&b'.'))
        .map_or(0, |j| j.saturating_add(1));
    for start in first_ok..labels.len() {
        let key: Vec<String> = labels[start..]
            .iter()
            .rev()
            .map(|l| String::from_utf8_lossy(&l.to_ascii_lowercase()).into_owned())
            .collect();
        let key = key.join(".");
        for v in at.key_versions(&key) {
            let view = View::new(&v.spec, &v.runs);
            for r in view.key_rules(c, &key, &mut bad)? {
                push(&mut rows, r);
            }
        }
    }
    // An address's IP rules: one index probe per prefix length (rules are CIDRs; ranges hold
    // their network address as `ip_first`).
    if let Value::Ip(ip) = value
        && let Some(v) = at.ip_version(*ip)
    {
        for r in ip_rules_covering(c, v, *ip, &mut bad)? {
            push(&mut rows, r);
        }
    }
    // Patterns whose shortcut and regex hit the text form.
    let text = match value {
        Value::Name(l) => picket_api::names::adguard_text(l.iter().map(Vec::as_slice)),
        Value::Ip(ip) => picket_rules::ip::go_ip_string(picket_rules::ip::canonical_ip(*ip)),
    };
    let mut dropped: HashSet<i64> = HashSet::new();
    if let Some(v) = at.pattern_version() {
        let view = View::new(&v.spec, &v.runs);
        let mut hit: Vec<Row> = Vec::new();
        for (feed, run) in view.feeds().collect::<Vec<_>>() {
            let Some(m) = v.spec.member(feed) else { continue };
            let fp = caches.feed_patterns(c, &v.spec, m, run)?;
            partial |= fp.over_cap;
            for mut r in fp.matching(&text, &caches.budget) {
                r.order.position = m.position;
                hit.push(r);
            }
        }
        // The patterns the version's compile left out match nothing (bundles.md §2 Determinism).
        if !hit.is_empty()
            && let Some(cut) = caches.admission_cut(c, v)?
        {
            let action = spec::rules_action(v.spec.action);
            for r in &hit {
                if r.order >= cut
                    && r.rule
                        .pattern_spec()
                        .is_some_and(|p| admission_costed(action, &r.rule, &p))
                {
                    dropped.insert(r.entry_id);
                }
            }
        }
        for r in hit {
            push(&mut rows, r);
        }
    }
    if bad > 0 {
        tracing::debug!(bad, bundle = %at.bundle, "replay skipped stored rows that don't make a rule");
    }
    if capped {
        tracing::debug!(bundle = %at.bundle, cap = MAX_CANDIDATES, "replay cut a value's candidates at the cap");
    }
    rows.sort_by(|a, b| a.order.cmp(&b.order));
    Ok((rows, partial || capped || at.truncated, dropped))
}

/// The IP rules of `v`'s member feeds (at their runs) whose range covers `ip`, plus the
/// `$badfilter` rules targeting one.
fn ip_rules_covering(c: &Connection, v: &VersionInfo, ip: IpAddr, bad: &mut u64) -> Result<Vec<Row>> {
    let canon = picket_rules::ip::canonical_ip(ip);
    let (bits, value): (u32, u128) = match canon {
        IpAddr::V4(a) => (32, u128::from(u32::from(a)) | 0xffff_0000_0000),
        IpAddr::V6(a) => (128, u128::from(a)),
    };
    let ip_bytes = value.to_be_bytes();
    let mut st = c.prepare_cached(
        "SELECT id, feed_id, rule_type, kind, key, flags, value_json, coalesce(line_no, 0), first_seen_at, first_run,
                removed_run, ip_last
         FROM feed_entries WHERE rule_type = 'ip' AND ip_first = ?1",
    )?;
    let members: HashMap<&str, &Member> = v.spec.members.iter().map(|m| (m.feed.as_str(), m)).collect();
    let mut out = Vec::new();
    for plen in 0..=bits {
        let host_bits = bits - plen;
        let mask: u128 = if host_bits >= 128 {
            0
        } else {
            !((1u128 << host_bits) - 1)
        };
        let net = if canon.is_ipv4() {
            (value & mask) | 0xffff_0000_0000
        } else {
            value & mask
        };
        let mut rows = st.query([&net.to_be_bytes()[..]])?;
        while let Some(r) = rows.next()? {
            let feed: String = r.get(1)?;
            let Some(m) = members.get(feed.as_str()) else {
                continue;
            };
            if !v.spec.compiled_types(m).contains(&RuleType::Ip) {
                continue;
            }
            let run = v.runs.get(&feed).copied().unwrap_or(0);
            let first_run: i64 = r.get(9)?;
            let removed: Option<i64> = r.get(10)?;
            if first_run > run || removed.is_some_and(|x| x <= run) {
                continue;
            }
            let last: Option<Vec<u8>> = r.get(11)?;
            if last.as_deref().is_some_and(|l| l < &ip_bytes[..]) {
                continue;
            }
            let rule_type: String = r.get(2)?;
            let kind: String = r.get(3)?;
            let key: String = r.get(4)?;
            let flags: i64 = r.get(5)?;
            let value_json: String = r.get(6)?;
            let Some((flags, rule)) =
                crate::compiler::source::stored_rule(&rule_type, &kind, &key, flags, &value_json)
            else {
                *bad += 1;
                continue;
            };
            out.push(Row {
                order: OrderKey {
                    position: m.position,
                    line_no: r.get(7)?,
                    rule_type: rule.rule_type.as_str(),
                    kind: rule.kind.as_str(),
                    key,
                    flags,
                    value_json,
                },
                feed,
                rule,
                first_seen_at: r.get(8)?,
                entry_id: r.get(0)?,
            });
        }
    }
    Ok(out)
}

/// The candidates of `at` for `value`, through the LRU.
pub fn candidates(
    c: &Connection,
    caches: &ReplayCaches,
    at: &BundleAt,
    key: CandKey,
    value: &Value,
) -> Result<Arc<Candidates>> {
    use std::sync::atomic::Ordering::Relaxed;
    if let Ok(mut l) = caches.candidates.lock()
        && let Some(v) = l.get(&key)
    {
        caches.hits.fetch_add(1, Relaxed);
        return Ok(v);
    }
    caches.misses.fetch_add(1, Relaxed);
    let (rows, partial, dropped) = gather(c, caches, at, value)?;
    let action = at.action().unwrap_or(BundleAction::Block);
    let left_out: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| dropped.contains(&r.entry_id))
        .map(|(i, _)| i)
        .collect();
    let matcher = caches
        .matcher(
            spec::rules_action(action),
            rows.iter().map(|r| r.rule.clone()).collect(),
        )
        .with_patterns_dropped(left_out);
    let cands = Arc::new(Candidates {
        rows,
        matcher,
        partial,
    });
    if let Ok(mut l) = caches.candidates.lock() {
        let w = cands.weight();
        l.insert(key, cands.clone(), w);
    }
    Ok(cands)
}

/// A record's client context for rule conditions (core.md §6 step 2: `$client` against the
/// record's `client` and `device`, `$ctag` against that device's tags).
pub struct ClientCtx {
    pub ip: Option<IpAddr>,
    pub names: Vec<String>,
    pub tags: Vec<String>,
}

impl ClientCtx {
    pub fn of(cfg: Option<&PublishedConfig>, client_ip: &str, device: Option<&str>) -> ClientCtx {
        let mut names: Vec<String> = Vec::new();
        if let Some(d) = device {
            names.push(d.to_string());
        }
        let tags = cfg
            .and_then(|c| c.client(device))
            .map(|c| c.tags.clone())
            .unwrap_or_default();
        ClientCtx {
            ip: client_ip.parse().ok(),
            names,
            tags,
        }
    }

    /// Matches `value` against `cands` for this client and record type.
    pub fn eval(&self, cands: &Candidates, value: &Value, qtype: u16) -> MatchResult {
        let names: Vec<&str> = self.names.iter().map(String::as_str).collect();
        let tags: Vec<&str> = self.tags.iter().map(String::as_str).collect();
        let ctx = QueryCtx {
            qtype,
            client_ip: self.ip,
            client_names: &names,
            client_tags: &tags,
        };
        match value {
            Value::Name(l) => {
                let labels: Vec<&[u8]> = l.iter().map(Vec::as_slice).collect();
                cands.matcher.match_name(&labels, &ctx)
            }
            Value::Ip(ip) => cands.matcher.match_ip(*ip, &ctx),
        }
    }
}

/// `raw` and `line_no` of a feed entry, for display.
pub fn raw_of(c: &Connection, entry_id: i64) -> Result<(String, Option<i64>)> {
    Ok(crate::compiler::source::raw_of(c, entry_id).unwrap_or_default())
}

/// The record's `versions` block, parsed.
pub fn parse_versions(json: &str) -> Option<Versions> {
    serde_json::from_str(json).ok()
}

/// A wire name's labels.
pub fn owned(labels: &[Vec<u8>]) -> OwnedName {
    OwnedName::from_labels(labels.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_evicts_least_recently_used_by_count_and_weight() {
        let mut l: Lru<u32, u32> = Lru::new(2, 100);
        l.insert(1, 10, 1);
        l.insert(2, 20, 1);
        assert_eq!(l.get(&1), Some(10));
        l.insert(3, 30, 1);
        assert_eq!(l.get(&2), None, "2 was least recently used");
        assert_eq!(l.get(&1), Some(10));
        let mut w: Lru<u32, u32> = Lru::new(10, 10);
        w.insert(1, 1, 6);
        w.insert(2, 2, 6);
        assert_eq!(w.len(), 1);
        assert_eq!(w.get(&2), Some(2));
    }

    fn rule(line: &str) -> Rule {
        match picket_rules::classify::classify_adblock_line(line, false) {
            picket_rules::classify::Line::Items(v) => v
                .into_iter()
                .find_map(|i| match i {
                    picket_rules::classify::Item::Rule(r) => Some(r),
                    _ => None,
                })
                .unwrap(),
            picket_rules::classify::Line::Skipped => panic!("{line} skipped"),
        }
    }

    #[test]
    fn one_pattern_budget_evicts_and_gives_back() {
        // Review fix-w5a N12 (core.md §6: one 32 MB cap for compiled patterns): every regex is
        // charged once, the least recently used go when a new one doesn't fit, and eviction and
        // clear give their bytes back, so the budget never fills with leaked charges.
        // Review round 2 (S3): each is charged what it holds (heap and a fresh cache, not a flat
        // growth allowance), cache growth sharing one pool.
        let spec = |i: usize| {
            rule(&format!("/^ad{i}[0-9]+x\\.example$/"))
                .pattern_spec()
                .unwrap()
        };
        let src = spec(0).regex.unwrap();
        let per = PatternRegex::build(&src).unwrap().resident_cost() + src.len() + REGEX_ENTRY_OVERHEAD;
        assert!(per < picket_rules::matcher::PATTERN_CACHE_GROWTH, "{per}");
        // Room for three regexes (three quarters of the budget): a fourth evicts the least
        // recently used.
        let b = PatternBudget::new((per * 3 + per / 2) * GROWTH_SHARE / (GROWTH_SHARE - 1) + GROWTH_SHARE);
        for i in 0..3 {
            assert!(b.pattern_hits(&spec(i), &format!("ad{i}7x.example")));
        }
        assert_eq!(b.len(), 3);
        assert!(
            b.pattern_hits(&spec(0), "ad07x.example"),
            "0 is now the most recent"
        );
        let builds = b.builds();
        assert!(!b.pattern_hits(&spec(3), "nothing.example"));
        assert!(b.pattern_hits(&spec(3), "ad37x.example"));
        assert_eq!(b.len(), 3, "one evicted");
        assert!(b.used() <= b.max(), "{} > {}", b.used(), b.max());
        assert_eq!(b.builds(), builds + 1, "a kept regex isn't built again");
        assert!(b.pattern_hits(&spec(0), "ad07x.example"));
        assert_eq!(b.builds(), builds + 1, "the most recent one stayed");
        assert!(b.pattern_hits(&spec(1), "ad17x.example"));
        assert_eq!(b.builds(), builds + 2, "the least recent one (1) went");
        // Every charge is the sum of what is kept: eviction gave the rest back.
        assert!(b.used() <= b.max(), "{}", b.used());
        assert!(
            b.cache.lock().unwrap().weight() <= per * 3 + 3 * 64,
            "{}",
            b.used()
        );
        b.clear();
        assert_eq!((b.used(), b.len()), (0, 0), "clear gives everything back");
        // A regex costing more than the whole budget is used once and not kept.
        let tiny = PatternBudget::new(16);
        assert!(tiny.pattern_hits(&spec(5), "ad55x.example"));
        assert_eq!((tiny.used(), tiny.len()), (0, 0));
        // A pattern whose shortcut is absent never reaches its regex.
        let before = tiny.builds();
        assert!(!tiny.pattern_hits(&rule("||track*er.example^").pattern_spec().unwrap(), "x.example"));
        assert_eq!(tiny.builds(), before);
    }

    #[test]
    fn search_caches_grow_within_one_pool() {
        // Review round 2 (S3): the caches' growth past their fresh size shares one pool (a
        // quarter of the budget); past it the least recently used grown caches are reset.
        let b = PatternBudget::new(512 * 1024);
        let specs: Vec<PatternSpec> = (0..8)
            .map(|i| {
                rule(&format!("/(?:a|b)*a(?:a|b){{{}}}x{i}/", 10 + i))
                    .pattern_spec()
                    .unwrap()
            })
            .collect();
        for round in 0..40 {
            for p in &specs {
                let hay: String = (0..96)
                    .map(|j| if (round * 7 + j) % 3 == 0 { 'a' } else { 'b' })
                    .collect();
                let _ = b.pattern_hits(p, &hay);
                assert!(b.used() <= b.max(), "{} > {}", b.used(), b.max());
            }
        }
        let grown: usize = b
            .cache
            .lock()
            .unwrap()
            .entries()
            .filter_map(|(_, v, _)| v.as_ref().map(|r| r.growth()))
            .sum();
        assert!(grown <= b.growth_pool(), "{grown}");
    }

    #[test]
    fn candidate_matchers_compile_nothing_of_their_own() {
        // N12: a candidate set's matcher takes its regexes from the shared budget.
        let caches = ReplayCaches::with_budget(PATTERN_BUDGET);
        let m = caches.matcher(
            picket_rules::BundleAction::Block,
            vec![rule("/^ad[0-9]+\\.example$/"), rule("||plain.example^")],
        );
        let r = m.match_dotted("ad1.example", &QueryCtx::default());
        assert_eq!(r.outcome, picket_rules::Outcome::Block);
        assert_eq!(m.regex_cache_stats(), (0, 0), "nothing compiled in the matcher");
        assert_eq!(caches.budget.len(), 1, "the regex is in the shared budget");
        assert!(caches.budget.used() > 0);
        assert!(caches.pattern_hits(
            &rule("/^ad[0-9]+\\.example$/").pattern_spec().unwrap(),
            "ad2.example"
        ));
        assert_eq!(caches.budget.builds(), 1, "one build for both users");
        caches.clear();
        assert_eq!(caches.budget.used(), 0);
    }

    #[test]
    fn values_round_trip_log_text() {
        let v = Value::name_from_log("a\\033b.example.com").unwrap();
        let Value::Name(l) = &v else { panic!() };
        assert_eq!(l.len(), 3);
        assert_eq!(l[0], b"a!b".to_vec());
        assert_eq!(v.text(), "a\\033b.example.com");
        assert!(Value::name_from_log("").is_none());
    }

    #[test]
    fn stored_definitions_round_trip() {
        let spec = Spec {
            id: "b".into(),
            action: BundleAction::Block,
            members: vec![Member {
                feed: "f".into(),
                position: 0,
                types: vec![RuleType::Dns],
                tier: Tier::Cold,
                downloaded: true,
                warn_on: vec![],
            }],
            max_shard_keys: 0,
            hot_max_mib: None,
            def_hash: "h".into(),
        };
        let j = definition_json(&spec);
        let back = version_spec("b", Some(&j), "h", &Runs::new(), &Model::default());
        assert_eq!(back.members.len(), 1);
        assert_eq!(back.members[0].types, vec![RuleType::Dns]);
        assert_eq!(back.members[0].tier, Tier::Cold);
        assert_eq!(back.action, BundleAction::Block);
    }
}
