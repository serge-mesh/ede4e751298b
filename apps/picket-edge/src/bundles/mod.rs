//! Bundle and verdict-set activation (edge.md §3, §10, §13, §17; bundles.md §6–§7; edge-unifi.md §1).
//!
//! [`BundleManager`] makes a config object live ([`EdgeActivator`] is the foundation's
//! [`Activator`]): it downloads what the heads the object names lack, verifies every blob, builds
//! each part off the hot path and swaps it in with a new `versions` block, then swaps the config
//! itself in, then unloads the bundles and verdict sets the object no longer names.
//!
//! - **One activation at a time** (a lock), **one part at a time** within a bundle head
//!   (a split or merge swaps all its shards at once), each swap waiting until the part it
//!   replaced is freed, so the peak extra RAM is one part (bundles.md §6). A query holds the
//!   active state it loaded for its whole life (its lookups wait up to `sync_lookup_budget_ms`, at most
//!   60 s, and resolution up to 3.5 s), so the wait has no short bound: past
//!   [`WAIT_FREED_MAX`] (2 min) a part still held is taken to be held by a stuck query, and the
//!   swap goes ahead with a warning naming the part (the bound is a policy choice).
//! - **Steps of a head:** first the head itself (every part it leaves unchanged moves to it at
//!   once, so even a head that changes none of them gets one), then cold upserts, hot swaps, IP
//!   shards, the patterns segment, and cold deletes, in the order bundles.md §2 "Moves" requires:
//!   while a head moves keys, the cold part it replaces stays behind the new one (the union, the
//!   new value winning), and is dropped only once every hot swap is done, so a key moving between
//!   the parts is never in neither. A head without a cold part keeps the previous one until then
//!   ([`picket_bundle::matcher::Bundle::drop_previous_cold`]). Each step logs `activated` with
//!   its part; the completion `activated` (no part) once every part the head needs is active.
//! - **A head that fails part-way** keeps the parts already swapped; the convergence loop retries
//!   the rest with backoff. Without a usable SSD, cold parts and verdict sets don't hold an
//!   activation up: `versions.not_loaded` names them until they load.
//! - **Budgets** (edge.md §17): before each swap, and after each part a whole head loads, the
//!   bundles the target config keeps (hot parts plus cold filters) must stay within
//!   `memory.bundle_budget_mib`, and their overlays plus the verdict sets' within
//!   `memory.overlay_budget_mib`: the steady state core checks (bundles.md §2 "Budget"). A part
//!   that doesn't fit isn't swapped in: the step fails at stage `budget` (an `activation_failed`
//!   event core sees) and the object waits for core to send another. Every object is capped by
//!   the budgets before it is fetched ([`store::Caps`]).
//! - **Activation peak** (bundles.md §6 "Activation": one part extra; "if memory is short"):
//!   everything resident meanwhile counts too, the bundles the target config drops and the
//!   version a whole head replaces included. When that passes `bundle_budget_mib`, memory is
//!   short: resident bundles nothing runs with (the target drops them and the running config
//!   doesn't name them) are unloaded ahead of the swap, each waited on until freed. A bundle the
//!   running config names (block, allow or scope alike) is never unloaded before the target is
//!   live (#70): the running policy stays whole whatever happens to the activation, so a failed
//!   one has nothing to restore. If the peak still passes the budget, the step fails at stage
//!   `budget` (not retried until core sends another object, so nothing is loaded and unloaded
//!   again and again), its reason naming the peak, the bundles held for the running config and
//!   what would make it fit: a budget of at least the peak, or the change made in two configs.
//! - **active.json** ([`record`]) is written next to the files at every step; a start from disk
//!   loads each bundle's recorded head whole (or its previous, complete head when the files of a
//!   head left part-way are gone).
//! - **Locations** ([`store`]): the SSD while it passes, memory only in the first 10 minutes after
//!   start, the eMMC copy after that while the SSD fails. A background task follows the SSD:
//!   loading cold parts and verdict sets once it passes, moving the hot files there (every file of
//!   each head a restart may load: the running config's, each bundle's active and previous head;
//!   each written and synced, then the record, each checked, and only then the eMMC copy
//!   deleted; any failure stops the move and keeps the copy), unloading them when it fails, and
//!   filling the eMMC copy after the start window. A move or fill that didn't complete stays
//!   pending and is retried at each follower round until it does; whether the fill completed is
//!   tracked, never inferred from the copy's `active.json` (activation steps write that too).
//!   Files placed are remembered, so a round with nothing new to move re-hashes nothing, and
//!   `active.json` is rewritten only when it changes.
//! - **Start from disk** (edge.md §3): while no config runs, each attempt reads `active.json`
//!   again, so a drive UniFi mounts after boot is used as soon as it passes.
//! - **Page files** ([`pages`]): read a page at a time; a page failing its checksum makes the file
//!   be deleted and fetched again, logged as `page_file_refetched`. A file fetched again (same
//!   BLAKE3, so the same bytes) that still has a bad page is a hard failure, however long after
//!   the refetch it fails again: logged once more with `still_bad`, and not fetched again while
//!   the file on disk still matches its BLAKE3 (fetching it again would bring the same bytes),
//!   checked after a backoff (doubling); reads fail open meanwhile.
//! - **Verdict sets** of a config load before it goes live and are swapped in with it, so a config
//!   that fails leaves the running one's sets as they were.
//! - **Garbage:** after an activation, files neither the active nor the previous head of a bundle
//!   or verdict set uses (nor a cold part still being read) are deleted.

pub mod load;
pub mod pages;
pub mod record;
pub mod store;
pub mod verdicts;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::sync::mpsc;

use picket_api::edge_config::EdgeConfig;
use picket_api::logs::{Versions, event_kind};
use picket_bundle::head::{Head, IpShardRef, PATTERNS, RICH, ShardRef};
use picket_bundle::matcher::{Bundle, Cold, ColdPart};
use picket_bundle::reader::{ColdShard, HotShard, IpShard};
use picket_bundle::rich::RichSegment;

use crate::dns::filter::ActiveBundles;
use crate::dns::runtime::DnsRuntime;
use crate::edge::{ActiveState, Edge};
use crate::hooks::{Activation, ActivationTarget, Activator, HaveProvider};
use crate::logs::fields;
use load::{HeadInfo, Loader};
use pages::{FilePages, Owner};
use record::{ConfigMaps, Record};
use store::StepError;

const MIB: usize = 1 << 20;
/// The longest a swap waits for the part it replaced to be freed (bundles.md §6): well past the
/// longest a query holds the active state (`sync_lookup_budget_ms` ≤ 60 s plus resolution).
pub const WAIT_FREED_MAX: Duration = Duration::from_secs(120);

/// Knobs tests shorten.
#[derive(Clone, Debug)]
pub struct BundleTuning {
    /// The longest wait for a replaced part to be freed before the next swap
    /// ([`WAIT_FREED_MAX`]).
    pub wait_freed: Duration,
    /// How often the SSD follower re-checks locations without a state change.
    pub follow_every: Duration,
    /// How often a start from disk is retried while nothing runs.
    pub start_retry: Duration,
    /// First and largest delay before a failed page-file refetch is tried again.
    pub refetch_backoff: (Duration, Duration),
    /// The compressed deltas fetched and applied together.
    pub chain_run: usize,
}

impl Default for BundleTuning {
    fn default() -> Self {
        Self {
            wait_freed: WAIT_FREED_MAX,
            follow_every: Duration::from_secs(60),
            start_retry: Duration::from_secs(5),
            refetch_backoff: (Duration::from_secs(5), Duration::from_secs(300)),
            chain_run: load::CHAIN_RUN,
        }
    }
}

/// What `have.in_progress` reports.
#[derive(Clone, Debug, Default)]
struct Progress {
    bundles: BTreeMap<String, Vec<String>>,
    verdict_sets: BTreeMap<String, Vec<String>>,
}

/// The cold part a head's cold phase started from: (the head, the part).
type ColdBase = (Arc<str>, Arc<ColdPart>);

/// Bundle and verdict-set state that survives activations.
pub struct BundleManager {
    pub pages: Arc<FilePages>,
    lock: tokio::sync::Mutex<()>,
    record: Mutex<Record>,
    heads: Mutex<HashMap<String, Arc<HeadInfo>>>,
    rich: Mutex<HashMap<String, Weak<RichSegment>>>,
    verified: Mutex<HashSet<String>>,
    progress: ArcSwap<Progress>,
    sets: ArcSwap<HashMap<String, Arc<verdicts::ActiveSet>>>,
    /// The verdict-set heads the running config names (`not_loaded` lists those not active).
    wanted_sets: ArcSwap<BTreeMap<String, String>>,
    /// The set each lookup client has attached, by provider.
    attached: Mutex<HashMap<String, Arc<str>>>,
    /// Per bundle: the cold part the current head's cold phase started from (the union's older
    /// half), so a retried step doesn't nest another one.
    cold_base: Mutex<HashMap<String, ColdBase>>,
    refetch_tx: mpsc::Sender<String>,
    refetch_rx: Mutex<Option<mpsc::Receiver<String>>>,
    /// A move of the hot files to the SSD, or the eMMC copy's fill, hasn't completed: retried at
    /// each follower round.
    placement_pending: AtomicBool,
    /// The eMMC copy's fill completed (edge-unifi.md §1): tracked, never inferred from the copy's
    /// `active.json`, which every activation step writes there during an SSD failure.
    emmc_filled: AtomicBool,
    /// Files placed for a move to the SSD this run.
    placed: Mutex<Placed>,
    pub tuning: BundleTuning,
}

/// What a move to the SSD placed there.
#[derive(Debug, Default)]
struct Placed {
    /// The bundles directory the files went to.
    root: Option<PathBuf>,
    /// Files written or verified there (each hashed once).
    files: HashSet<PathBuf>,
    /// Every file a restart may need, and the record, are there: a round with no eMMC copy to
    /// move has nothing to do.
    complete: bool,
}

/// Most files [`Placed`] remembers before starting over (README §2 Bounded).
const MAX_PLACED: usize = 1 << 16;

/// A verdict set loaded for a config, swapped in when the config goes live
/// ([`BundleManager::commit_set`]).
struct PreparedSet {
    provider: String,
    head: String,
    active: Arc<verdicts::ActiveSet>,
    change: verdicts::SetChange,
}

/// The foundation hook: makes config objects live through [`BundleManager`].
pub struct EdgeActivator;

#[async_trait]
impl Activator for EdgeActivator {
    async fn activate(&self, edge: &Edge, t: &ActivationTarget) -> Activation {
        let m = Arc::clone(&edge.bundles);
        m.activate(edge, t).await
    }
}

/// `have`'s bundle and verdict-set heads (api.md §3).
pub struct BundleHave(pub Arc<BundleManager>);

impl HaveProvider for BundleHave {
    fn bundles(&self) -> BTreeMap<String, Vec<String>> {
        let r = self.0.lock_record();
        r.heads
            .iter()
            .map(|(b, h)| {
                let mut v = vec![h.active.clone()];
                v.extend(h.previous.iter().filter(|p| **p != h.active).cloned());
                (b.clone(), v)
            })
            .collect()
    }
    fn verdict_sets(&self) -> BTreeMap<String, Vec<String>> {
        let r = self.0.lock_record();
        r.sets
            .iter()
            .map(|(p, s)| {
                let mut v = vec![s.active.clone()];
                v.extend(s.previous.iter().filter(|x| **x != s.active).cloned());
                (p.clone(), v)
            })
            .collect()
    }
    fn in_progress_bundles(&self) -> BTreeMap<String, Vec<String>> {
        self.0.progress.load().bundles.clone()
    }
    fn in_progress_verdict_sets(&self) -> BTreeMap<String, Vec<String>> {
        self.0.progress.load().verdict_sets.clone()
    }
}

/// The `budget` failure of a step whose activation peak passes `bundle_budget_mib` with only
/// what the running config names left to unload (#70): `peak` bytes, `held` the bundles kept for
/// the running config (name, bytes). Says what would make it fit.
fn peak_over_budget(cfg: &EdgeConfig, peak: usize, held: &[(Arc<str>, usize)]) -> StepError {
    let mut names: Vec<&str> = held.iter().map(|(k, _)| &**k).collect();
    names.sort_unstable();
    let bytes: usize = held.iter().map(|(_, m)| *m).sum();
    let mut reason = format!(
        "bundles would peak at {} MiB during this activation, over bundle_budget_mib {}",
        peak.div_ceil(MIB),
        cfg.memory.bundle_budget_mib
    );
    if names.is_empty() {
        reason.push_str(&format!(
            "; raise memory.bundle_budget_mib to at least {} MiB",
            peak.div_ceil(MIB)
        ));
    } else {
        reason.push_str(&format!(
            ": the running config keeps using {} ({} MiB) until this config is live, so they stay \
             loaded; raise memory.bundle_budget_mib to at least {} MiB, or make the change in two \
             configs (the first without {})",
            names.join(", "),
            bytes.div_ceil(MIB),
            peak.div_ceil(MIB),
            names.join(", ")
        ));
    }
    StepError::permanent("budget", reason)
}

fn short(id: &str) -> String {
    picket_api::ids::short_id(id).to_owned()
}

fn same_ref(
    base: &str,
    seq: u64,
    cs: picket_bundle::SetChecksum,
    r_base: &str,
    r_seq: u64,
    r_cs: picket_bundle::SetChecksum,
) -> bool {
    base == r_base && seq == r_seq && cs == r_cs
}

fn same_hot(s: &HotShard, r: &ShardRef) -> bool {
    s.number == r.shard && same_ref(s.base_id(), s.seq(), s.checksum(), &r.base, r.seq, r.checksum)
}

fn same_cold(s: &ColdShard, r: &ShardRef) -> bool {
    s.number == r.shard
        && s.moving_from.is_none()
        && same_ref(s.base_id(), s.seq(), s.checksum(), &r.base, r.seq, r.checksum)
}

fn same_ip(s: &IpShard, r: &IpShardRef) -> bool {
    s.id == r.ip_shard && same_ref(s.base_id(), s.seq(), s.checksum(), &r.base, r.seq, r.checksum)
}

/// True when every part `head` needs is active and is `head`'s (cold parts only when `cold_ok`).
pub fn is_complete(b: &Bundle, head: &Head, id: &str, cold_ok: bool) -> bool {
    if b.head() != id {
        return false;
    }
    let hot_ok = b.hot_shards().len() == head.shards.len()
        && b.hot_shards()
            .iter()
            .all(|s| *s.head == *id && head.shard(s.number).is_some_and(|r| same_hot(s, r)));
    let ips: Vec<&Arc<IpShard>> = b.ip_shards().collect();
    let ip_ok = ips.len() == head.ip_shards.len()
        && ips
            .iter()
            .all(|s| *s.head == *id && head.ip_shard(s.id).is_some_and(|r| same_ip(s, r)));
    let pat_ok = *b.patterns().head == *id;
    let cold_ok = match (head.has_cold(), b.cold()) {
        (false, Cold::None) => true,
        (false, _) => false,
        (true, Cold::Loaded(c)) => {
            c.previous().is_none()
                && c.shards().len() == head.cold_shards.len()
                && c.shards()
                    .iter()
                    .all(|s| *s.head == *id && head.cold_shard(s.number).is_some_and(|r| same_cold(s, r)))
        }
        (true, _) => !cold_ok,
    };
    hot_ok && ip_ok && pat_ok && cold_ok
}

/// Every page file the active cold parts read (the previous halves included).
fn cold_files(b: &Bundle, out: &mut HashSet<String>) {
    fn walk(c: &ColdPart, out: &mut HashSet<String>) {
        for s in c.shards() {
            out.insert(s.pages_file().to_owned());
        }
        if let Some(p) = c.previous() {
            walk(p, out);
        }
    }
    if let Cold::Loaded(c) = b.cold() {
        walk(c, out);
    }
}

/// Bundle ids an edge config refers to (profiles' allow and block lists, lookup scopes).
fn referenced_bundles(c: &EdgeConfig) -> bool {
    c.profiles.values().any(|p| {
        !p.allow.is_empty()
            || !p.block.is_empty()
            || p.lookup_providers
                .iter()
                .any(|l| !l.include_bundles.is_empty() || !l.exclude_bundles.is_empty())
    }) || !c.lookup_providers.is_empty()
}

impl BundleManager {
    pub fn new(metrics: Arc<crate::metrics::Metrics>, tuning: BundleTuning) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(64);
        Arc::new(Self {
            pages: FilePages::new(metrics),
            lock: tokio::sync::Mutex::new(()),
            record: Mutex::new(Record::default()),
            heads: Mutex::new(HashMap::new()),
            rich: Mutex::new(HashMap::new()),
            verified: Mutex::new(HashSet::new()),
            progress: ArcSwap::from_pointee(Progress::default()),
            sets: ArcSwap::from_pointee(HashMap::new()),
            wanted_sets: ArcSwap::from_pointee(BTreeMap::new()),
            attached: Mutex::new(HashMap::new()),
            cold_base: Mutex::new(HashMap::new()),
            refetch_tx: tx,
            refetch_rx: Mutex::new(Some(rx)),
            placement_pending: AtomicBool::new(false),
            emmc_filled: AtomicBool::new(false),
            placed: Mutex::new(Placed::default()),
            tuning,
        })
    }

    fn lock_record(&self) -> std::sync::MutexGuard<'_, Record> {
        self.record.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A snapshot of `active.json` as held.
    pub fn record(&self) -> Record {
        self.lock_record().clone()
    }

    /// Loads `active.json` at start (edge-unifi.md §1): the eMMC copy's is the authority when it
    /// exists; otherwise the SSD's (read only: every file is verified before use anyway), else
    /// `data_dir`'s on an edge without `ssd_dir`.
    pub fn load_record(&self, edge: &Edge) {
        *self.lock_record() = Self::disk_record(edge);
    }

    fn disk_record(edge: &Edge) -> Record {
        let emmc = Record::load(&edge.layout.bundles_dir());
        match (emmc, &edge.storage.ssd) {
            (Some(r), _) => r,
            (None, Some(s)) => Record::load(&s.bundles_dir()).unwrap_or_default(),
            (None, None) => Record::default(),
        }
    }

    /// Reads `active.json` again while no config runs (edge.md §3, edge-unifi.md §1): the SSD
    /// UniFi mounts after boot, or an eMMC copy, may hold what the start needs. With nothing
    /// running, the record in memory holds nothing newer than what is on disk but the progress of
    /// activations that never went live, which the next one redoes.
    fn reload_record(&self, edge: &Edge) {
        if edge.active().config.is_none() {
            let r = Self::disk_record(edge);
            if !r.configs.is_empty() || !r.heads.is_empty() {
                *self.lock_record() = r;
            }
        }
    }

    pub(crate) fn cached_rich(&self, id: &str) -> Option<Arc<RichSegment>> {
        self.rich
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .and_then(Weak::upgrade)
    }

    pub(crate) fn cache_rich(&self, id: &str, r: &Arc<RichSegment>) {
        let mut g = self.rich.lock().unwrap_or_else(|p| p.into_inner());
        g.retain(|_, w| w.strong_count() > 0);
        g.insert(id.to_owned(), Arc::downgrade(r));
    }

    pub(crate) fn page_verified(&self, id: &str) -> bool {
        self.verified
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(id)
    }

    pub(crate) fn mark_page_verified(&self, id: &str) {
        let mut g = self.verified.lock().unwrap_or_else(|p| p.into_inner());
        if g.len() > pages::MAX_FILES {
            g.clear();
        }
        g.insert(id.to_owned());
    }

    /// Asks for page file `id` to be deleted and fetched again (bundles.md §4 "Reading"). Never
    /// blocks: a full queue drops the request (the next failing read asks again).
    pub fn request_refetch(&self, id: &str) {
        let _ = self.refetch_tx.try_send(id.to_owned());
    }

    /// The `versions` block for `config_version` and `bundles` (api.md §5), with `not_loaded`.
    pub fn versions(&self, config_version: &str, bundles: &ActiveBundles) -> Versions {
        let mut v = crate::dns::activation::versions(config_version, bundles);
        let mut cold: Vec<String> = bundles
            .bundles
            .iter()
            .filter(|(_, b)| b.cold_not_loaded())
            .map(|(k, _)| k.to_string())
            .collect();
        cold.sort();
        v.not_loaded.cold = cold;
        let sets = self.sets.load();
        v.not_loaded.verdict_sets = self
            .wanted_sets
            .load()
            .iter()
            .filter(|(p, h)| sets.get(*p).is_none_or(|s| *s.head != ***h))
            .map(|(p, _)| p.clone())
            .collect();
        v
    }

    /// Swaps the active bundles with `f` applied, publishing a new `versions` block.
    fn swap(&self, edge: &Edge, f: impl FnOnce(&mut ActiveBundles)) {
        let prev = edge.active();
        let mut ab = ActiveBundles::clone(&prev.bundles);
        ab.pages = Some(self.pages.clone() as Arc<dyn picket_bundle::page::PageReader>);
        f(&mut ab);
        let v = self.versions(prev.config_version.as_deref().unwrap_or(""), &ab);
        let mut next = ActiveState::clone(&prev);
        next.bundles = Arc::new(ab);
        next.versions = Some(Arc::new(v));
        edge.active.store(Arc::new(next));
    }

    /// Republishes `versions` (verdict sets loaded or unloaded).
    fn refresh_versions(&self, edge: &Edge) {
        self.swap(edge, |_| {});
    }

    /// Waits until `w`'s last holder dropped it: the next swap waits for the part it replaced to
    /// be freed (bundles.md §6 "Activation"), however long the queries holding it take, up to
    /// `wait_freed` ([`WAIT_FREED_MAX`]); past that the part is taken to be held by a stuck query
    /// and the swap goes ahead, with a warning naming `what`.
    async fn wait_freed<T>(&self, w: Weak<T>, what: &str) {
        let start = tokio::time::Instant::now();
        let mut pause = Duration::from_millis(5);
        while w.strong_count() > 0 {
            if start.elapsed() >= self.tuning.wait_freed {
                tracing::warn!(
                    "{what} is still held {} s after it was replaced (a stuck query?): the next \
                     swap goes ahead",
                    start.elapsed().as_secs()
                );
                return;
            }
            tokio::time::sleep(pause).await;
            pause = (pause * 2).min(Duration::from_millis(100));
        }
    }

    fn persist(&self, edge: &Edge) {
        let Some(dir) = store::hot_write_root(edge) else {
            return; // memory only (edge-unifi.md §1): nothing is written
        };
        let r = self.lock_record().clone();
        if let Err(e) = r.save(&dir) {
            tracing::warn!("writing {}/active.json: {}", dir.display(), crate::diag::cap(e));
            edge.storage.recheck();
        }
    }

    fn set_progress(&self, f: impl FnOnce(&mut Progress)) {
        let mut p = Progress::clone(&self.progress.load());
        f(&mut p);
        self.progress.store(Arc::new(p));
    }

    fn bundle_event(
        edge: &Edge,
        kind: &str,
        bundle: &str,
        head: &str,
        part: Option<&str>,
        err: Option<&StepError>,
    ) {
        Self::object_event(edge, kind, ("bundle", bundle), head, part, err);
    }

    fn set_event(
        edge: &Edge,
        kind: &str,
        provider: &str,
        head: &str,
        part: Option<&str>,
        err: Option<&StepError>,
    ) {
        Self::object_event(edge, kind, ("verdict_set", provider), head, part, err);
    }

    /// An event about a bundle's or a verdict set's head: `object` is the field naming it and its
    /// id; a failed step adds its stage and reason.
    fn object_event(
        edge: &Edge,
        kind: &str,
        (field, id): (&str, &str),
        head: &str,
        part: Option<&str>,
        err: Option<&StepError>,
    ) {
        let mut f = fields(&[(field, id.into()), ("head", short(head).into())]);
        if let Some(p) = part {
            f.insert("part".into(), p.into());
        }
        if let Some(e) = err {
            f.insert("stage".into(), e.stage.into());
            f.insert("reason".into(), e.reason.clone().into());
        }
        edge.logs.event(kind, f);
    }

    /// The parsed head `id` of `bundle` (cached while it is referenced).
    async fn head_info(&self, edge: &Edge, bundle: &str, id: &str) -> Result<Arc<HeadInfo>, StepError> {
        if let Some(h) = self.heads.lock().unwrap_or_else(|p| p.into_inner()).get(id) {
            return Ok(Arc::clone(h));
        }
        let h = Arc::new(load::fetch_head(edge, bundle, id).await?);
        let mut g = self.heads.lock().unwrap_or_else(|p| p.into_inner());
        if g.len() > 4 * record::MAX_ENTRIES {
            g.clear();
        }
        g.insert(id.to_owned(), Arc::clone(&h));
        Ok(h)
    }

    fn cached_head(&self, id: &str) -> Option<Arc<HeadInfo>> {
        self.heads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .cloned()
    }

    /// Drops parsed heads no bundle references any more.
    fn prune_heads(&self, edge: &Edge) {
        let ab = edge.active().bundles.clone();
        let r = self.lock_record().clone();
        let mut keep: HashSet<String> = HashSet::new();
        for b in ab.bundles.values() {
            keep.insert(b.head().to_owned());
            keep.insert(b.patterns().head.to_string());
            for s in b.hot_shards() {
                keep.insert(s.head.to_string());
            }
            for s in b.ip_shards() {
                keep.insert(s.head.to_string());
            }
        }
        for h in r.heads.values() {
            keep.insert(h.active.clone());
            keep.extend(h.previous.clone());
        }
        self.heads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|k, _| keep.contains(k));
    }

    /// Keeps `bundle` becoming `candidate` within the budgets (edge.md §17): see [`Self::fit_bytes`].
    async fn fit(
        &self,
        edge: &Edge,
        cfg: &EdgeConfig,
        bundle: &str,
        candidate: &Bundle,
        shared: bool,
    ) -> Result<(), StepError> {
        self.fit_bytes(
            edge,
            cfg,
            bundle,
            candidate.memory_usage(),
            candidate.overlay_bytes(),
            shared,
        )
        .await
    }

    /// Keeps an activation within its budgets (edge.md §17; bundles.md §6 "Activation"). `bundle`
    /// is to hold `mem` bytes with `overlays` bytes of overlays (a whole head: what has loaded so
    /// far); `shared`: the candidate shares its unchanged parts with the active `bundle` (a step),
    /// so the active one isn't counted on top.
    ///
    /// - **Steady state:** the bundles the target config keeps plus the candidate within
    ///   `bundle_budget_mib`, and their overlays plus the target's verdict sets' within
    ///   `overlay_budget_mib` (what core checked, bundles.md §2 "Budget"); else the step fails at
    ///   stage `budget`.
    /// - **Peak:** every bundle resident meanwhile plus the candidate within `bundle_budget_mib`,
    ///   give or take the part being built. When it isn't, memory is short: resident bundles that
    ///   neither the target nor the running config names are unloaded ahead of the swap, then, for
    ///   a whole head of a bundle the running config doesn't name, the version it replaces; each
    ///   is waited on until freed (bounded). What the running config names stays (#70); a peak
    ///   still over the budget fails the step at stage `budget` with what would make it fit.
    async fn fit_bytes(
        &self,
        edge: &Edge,
        cfg: &EdgeConfig,
        bundle: &str,
        mem: usize,
        overlays: usize,
        shared: bool,
    ) -> Result<(), StepError> {
        let budget = (cfg.memory.bundle_budget_mib as usize).saturating_mul(MIB);
        let ob = (cfg.memory.overlay_budget_mib as usize).saturating_mul(MIB);
        // What the running config names is its policy until the target is live (#70).
        let running = edge.active().config.clone();
        let runs = |k: &str| running.as_ref().is_some_and(|c| c.bundles.contains_key(k));
        let (peak, evict) = {
            let ab = edge.active().bundles.clone();
            let mut total = mem;
            let mut ov = overlays;
            let mut peak = mem;
            let mut dropped: Vec<(Arc<str>, usize)> = Vec::new();
            // Bundles held for the running config that the target drops or replaces whole.
            let mut held: Vec<(Arc<str>, usize)> = Vec::new();
            let mut own = 0usize;
            for (k, b) in &ab.bundles {
                let m = b.memory_usage();
                if **k == *bundle {
                    if !shared {
                        own = m;
                    }
                } else if cfg.bundles.contains_key(&**k) {
                    total = total.saturating_add(m);
                    ov = ov.saturating_add(b.overlay_bytes());
                    peak = peak.saturating_add(m);
                } else {
                    if runs(k) {
                        held.push((Arc::clone(k), m));
                    } else {
                        dropped.push((Arc::clone(k), m));
                    }
                    peak = peak.saturating_add(m);
                }
            }
            for (p, s) in self.sets.load().iter() {
                if cfg.verdict_sets.contains_key(p) {
                    ov = ov.saturating_add(s.set.overlay_bytes());
                }
            }
            if total > budget {
                return Err(StepError::permanent(
                    "budget",
                    format!(
                        "bundles would take {} MiB, over bundle_budget_mib {}",
                        total.div_ceil(MIB),
                        cfg.memory.bundle_budget_mib
                    ),
                ));
            }
            if ov > ob {
                return Err(StepError::permanent(
                    "budget",
                    format!(
                        "overlays would take {} MiB, over overlay_budget_mib {}",
                        ov.div_ceil(MIB),
                        cfg.memory.overlay_budget_mib
                    ),
                ));
            }
            peak = peak.saturating_add(own);
            if own > 0 && runs(bundle) {
                held.push((bundle.into(), own));
            }
            // Memory is short: what nothing runs with goes first, then the replaced version when
            // the running config doesn't name it.
            let mut evict: Vec<Arc<str>> = Vec::new();
            let mut left = peak;
            for (k, m) in dropped {
                if left <= budget {
                    break;
                }
                left -= m;
                evict.push(k);
            }
            if left > budget && own > 0 && !runs(bundle) {
                left -= own;
                evict.push(bundle.into());
            }
            if left > budget {
                return Err(peak_over_budget(cfg, left, &held));
            }
            (peak, evict)
        };
        if evict.is_empty() {
            return Ok(());
        }
        tracing::warn!(
            "bundles would peak at {} MiB during this activation, over bundle_budget_mib {}: \
             unloading {} ahead of the swap",
            peak.div_ceil(MIB),
            cfg.memory.bundle_budget_mib,
            evict.iter().map(|k| &**k).collect::<Vec<_>>().join(", ")
        );
        let weak: Vec<(Arc<str>, Weak<Bundle>)> = {
            let ab = edge.active().bundles.clone();
            evict
                .iter()
                .filter_map(|k| ab.bundles.get(k).map(|b| (Arc::clone(k), Arc::downgrade(b))))
                .collect()
        };
        self.swap(edge, |ab| {
            for k in &evict {
                ab.bundles.remove(k);
            }
        });
        for (k, w) in weak {
            self.wait_freed(w, &format!("bundle {k}")).await;
        }
        Ok(())
    }

    /// The runtime maps of a stored config run from disk (edge.md §3 step 5): the stored file
    /// leaves `bundles` and `verdict_sets` out, `active.json` keeps them.
    fn disk_config(&self, t: &ActivationTarget) -> Result<Arc<EdgeConfig>, Activation> {
        let r = self.lock_record();
        match r.maps_for(&t.config_hash) {
            Some(m) => {
                let mut c = EdgeConfig::clone(&t.config);
                c.bundles = m.bundles.clone();
                c.verdict_sets = m.verdict_sets.clone();
                Ok(Arc::new(c))
            }
            None if !t.config.bundles.is_empty() || !referenced_bundles(&t.config) => {
                Ok(Arc::clone(&t.config))
            }
            None => Err(Activation::Retry {
                stage: "load".into(),
                reason: "the bundle heads this stored config runs with aren't recorded".into(),
            }),
        }
    }

    /// Makes `t` live (the [`Activator`]): bundles, verdict sets, then the config. One that fails
    /// leaves the running config's bundles as they were: none was unloaded for it
    /// ([`Self::fit_bytes`]). One refused for good ([`Activation::Failed`], not retried until core
    /// sends another object) also gives back what it loaded ([`Self::drop_refused`]).
    pub async fn activate(&self, edge: &Edge, t: &ActivationTarget) -> Activation {
        let _g = self.lock.lock().await;
        let a = self.activate_locked(edge, t).await;
        if matches!(a, Activation::Failed { .. }) {
            self.drop_refused(edge).await;
        }
        a
    }

    /// After a refused activation: unloads the bundles only it named (loaded unused, kept by
    /// nothing; a later config that names them reads their files from disk again) and clears
    /// what it reported in progress. With no config running, nothing is unloaded.
    async fn drop_refused(&self, edge: &Edge) {
        self.set_progress(|p| *p = Progress::default());
        let Some(running) = edge.active().config.clone() else {
            return;
        };
        let (unused, weak): (Vec<Arc<str>>, Vec<Weak<Bundle>>) = {
            let ab = edge.active().bundles.clone();
            ab.bundles
                .iter()
                .filter(|(k, _)| !running.bundles.contains_key(&***k))
                .map(|(k, b)| (Arc::clone(k), Arc::downgrade(b)))
                .unzip()
        };
        if unused.is_empty() {
            return;
        }
        self.swap(edge, |ab| {
            for k in &unused {
                ab.bundles.remove(k);
            }
        });
        for (k, w) in unused.iter().zip(weak) {
            self.wait_freed(w, &format!("bundle {k}")).await;
        }
    }

    async fn activate_locked(&self, edge: &Edge, t: &ActivationTarget) -> Activation {
        if t.from_disk && edge.active().config.is_some() {
            return Activation::Retry {
                stage: "start".into(),
                reason: "a config already runs".into(),
            };
        }
        if t.from_disk {
            self.reload_record(edge);
        }
        let cfg = if t.from_disk {
            match self.disk_config(t) {
                Ok(c) => c,
                Err(a) => return a,
            }
        } else {
            Arc::clone(&t.config)
        };
        // A config that can't be built leaves the active one running (edge.md §13).
        let c2 = Arc::clone(&cfg);
        let rt = match tokio::task::spawn_blocking(move || DnsRuntime::build(c2)).await {
            Ok(Ok(rt)) => rt,
            Ok(Err(reason)) => {
                return Activation::Failed {
                    stage: "build".into(),
                    reason,
                };
            }
            Err(e) => {
                return Activation::Failed {
                    stage: "build".into(),
                    reason: crate::diag::cap(e),
                };
            }
        };
        let cold_ok = store::cold_root(edge).is_some();
        self.set_progress(|p| {
            p.bundles = cfg
                .bundles
                .iter()
                .filter(|(b, h)| {
                    edge.active()
                        .bundles
                        .get(b)
                        .is_none_or(|x| x.head() != h.as_str())
                })
                .map(|(b, h)| (b.clone(), vec![h.clone()]))
                .collect();
            p.verdict_sets = cfg
                .verdict_sets
                .iter()
                .filter(|(p, h)| self.sets.load().get(*p).is_none_or(|s| *s.head != ***h))
                .map(|(p, h)| (p.clone(), vec![h.clone()]))
                .collect();
        });
        // Bundles it adds load first (unused); bundles it drops unload after the swap.
        for (b, h) in &cfg.bundles {
            // A start from disk falls back to a bundle's previous, complete head when the files of
            // a head left part-way are gone and core can't supply them (edge.md §3).
            let fallback = if t.from_disk {
                let r = self.lock_record();
                r.heads
                    .get(b)
                    .filter(|e| !e.complete && e.active == *h)
                    .and_then(|e| e.previous.clone())
            } else {
                None
            };
            if let Err((e, part)) = self
                .activate_bundle(edge, &cfg, b, h, cold_ok, fallback.as_deref())
                .await
            {
                tracing::warn!("bundle {b} head {}: {e}", short(h));
                Self::bundle_event(
                    edge,
                    event_kind::ACTIVATION_FAILED,
                    b,
                    h,
                    part.as_deref(),
                    Some(&e),
                );
                let a = if e.permanent {
                    Activation::Failed {
                        stage: e.stage.into(),
                        reason: e.reason,
                    }
                } else {
                    Activation::Retry {
                        stage: e.stage.into(),
                        reason: e.reason,
                    }
                };
                return a;
            }
            self.set_progress(|p| {
                p.bundles.remove(b);
            });
        }
        // Verdict sets load now and are swapped in with the config (edge.md §13): a config that
        // fails leaves the running one's sets as they were.
        let mut prepared: Vec<PreparedSet> = Vec::new();
        for (p, h) in &cfg.verdict_sets {
            match self.prepare_set(edge, &cfg, p, h, cold_ok, &prepared).await {
                Ok(x) => prepared.extend(x),
                Err(e) => {
                    tracing::warn!("verdict set {p} head {}: {e}", short(h));
                    Self::set_event(edge, event_kind::ACTIVATION_FAILED, p, h, Some("set"), Some(&e));
                    return if e.permanent {
                        Activation::Failed {
                            stage: e.stage.into(),
                            reason: e.reason,
                        }
                    } else {
                        Activation::Retry {
                            stage: e.stage.into(),
                            reason: e.reason,
                        }
                    };
                }
            }
            self.set_progress(|x| {
                x.verdict_sets.remove(p);
            });
        }

        // The firewall, once everything else the config needs is active (edge.md §3 step 2, §9):
        // a config that needs the helper has its shadow map seeded first; one that runs without
        // it replaces a helper config only once the helper acks an `apply` with no interfaces.
        // Nothing of the running config's firewall changes for a config that never goes live.
        if let Err(reason) = edge.fw.prepare(&cfg).await {
            return Activation::Retry {
                stage: "firewall".into(),
                reason,
            };
        }

        // The config itself.
        for w in &rt.warnings {
            tracing::warn!("config {}: {w}", short(&t.config_version));
        }
        for w in edge.dns.pool.configure(&cfg) {
            tracing::warn!("config {}: {w}", short(&t.config_version));
        }
        edge.dns.resolver.cache.configure(rt.cache);
        edge.dns.lookups.configure(&cfg);
        let mut changes = Vec::new();
        for x in prepared {
            changes.extend(self.commit_set(edge, x).await);
        }
        self.attach_sets(edge, changes).await;
        let prev = edge.active();
        let mut ab = ActiveBundles::clone(&prev.bundles);
        ab.pages = Some(self.pages.clone() as Arc<dyn picket_bundle::page::PageReader>);
        // The verdict sets this config names, now that it goes live (`not_loaded`; the follower
        // loads the ones waiting for the SSD).
        self.wanted_sets.store(Arc::new(cfg.verdict_sets.clone()));
        let v = self.versions(&t.config_version, &ab);
        edge.active.store(Arc::new(ActiveState {
            object_id: Some(t.object_id.clone()),
            config_version: Some(t.config_version.clone()),
            config_hash: Some(t.config_hash.clone()),
            config: Some(Arc::clone(&cfg)),
            versions: Some(Arc::new(v)),
            bundles: Arc::new(ab),
            dns: Some(Arc::new(rt)),
        }));
        edge.log_control.set_config(cfg.logging);
        edge.dns.listeners.wake.notify_one();

        // Unload what the object no longer names.
        let dropped: Vec<Arc<str>> = edge
            .active()
            .bundles
            .bundles
            .keys()
            .filter(|k| !cfg.bundles.contains_key(&***k))
            .cloned()
            .collect();
        if !dropped.is_empty() {
            self.swap(edge, |ab| {
                for k in &dropped {
                    ab.bundles.remove(k);
                }
            });
        }
        self.drop_unnamed_sets(edge, &cfg);
        {
            let mut r = self.lock_record();
            r.object = Some(t.object_id.clone());
            r.bundles = cfg.bundles.clone();
            r.verdict_sets = cfg.verdict_sets.clone();
            r.release = cfg.release.as_ref().and_then(|x| serde_json::to_value(x).ok());
            r.heads.retain(|b, _| cfg.bundles.contains_key(b));
            r.sets.retain(|p, _| cfg.verdict_sets.contains_key(p));
            r.push_config(ConfigMaps {
                hash: t.config_hash.clone(),
                object: t.object_id.clone(),
                bundles: cfg.bundles.clone(),
                verdict_sets: cfg.verdict_sets.clone(),
            });
        }
        self.persist(edge);
        self.set_progress(|p| *p = Progress::default());
        self.prune_heads(edge);
        self.gc(edge).await;
        // After the config is active: the firewall rules and the temporary allows it governs.
        edge.fw.config_active(&cfg);
        edge.bypass.recheck_all(edge).await;
        Activation::Active
    }

    /// Activates `head_id` of `bundle`, step by step. Errors carry the failing part. `fallback`:
    /// a complete head to load instead when a bundle that isn't loaded yet can't load `head_id`.
    async fn activate_bundle(
        &self,
        edge: &Edge,
        cfg: &EdgeConfig,
        bundle: &str,
        head_id: &str,
        cold_ok: bool,
        fallback: Option<&str>,
    ) -> Result<(), (StepError, Option<String>)> {
        let cur = edge.active().bundles.get(bundle).cloned();
        let head = self
            .head_info(edge, bundle, head_id)
            .await
            .map_err(|e| (e, None))?;
        if let Some(c) = &cur
            && is_complete(c, &head.head, head_id, cold_ok)
        {
            let mut r = self.lock_record();
            let e = r.heads.entry(bundle.to_owned()).or_default();
            if e.active != head_id {
                e.active = head_id.to_owned();
            }
            e.complete = true;
            return Ok(());
        }
        let id: Arc<str> = Arc::clone(&head.id);
        let caps = store::Caps::of(&cfg.memory);
        let loader = Loader {
            edge,
            mgr: self,
            bundle,
            head: &head,
            caps,
        };
        self.lock_record().start_head(bundle, head_id);
        let fresh = match &cur {
            None => true,
            Some(c) => c.hash_seed() != head.head.hash_seed || c.name() != bundle,
        };
        if fresh {
            // A new bundle (unused until the config that names it is swapped in), or a format
            // change: the whole head, swapped in at once.
            drop(cur);
            let b = match loader.whole(cold_ok, cfg).await {
                Ok(b) => b,
                Err(e) => {
                    let Some(prev) = fallback.filter(|p| *p != head_id) else {
                        return Err((e, None));
                    };
                    let ph = self
                        .head_info(edge, bundle, prev)
                        .await
                        .map_err(|_| (e.clone(), None))?;
                    let pl = Loader {
                        edge,
                        mgr: self,
                        bundle,
                        head: &ph,
                        caps,
                    };
                    let pb = pl.whole(cold_ok, cfg).await.map_err(|_| (e.clone(), None))?;
                    self.fit(edge, cfg, bundle, &pb, false)
                        .await
                        .map_err(|e| (e, Some("head".into())))?;
                    tracing::warn!(
                        "bundle {bundle}: head {} can't load ({e}); running its previous head {}",
                        short(head_id),
                        short(prev)
                    );
                    let pb = Arc::new(pb);
                    self.swap(edge, |ab| {
                        ab.bundles.insert(bundle.into(), pb);
                    });
                    return Ok(());
                }
            };
            self.fit(edge, cfg, bundle, &b, false)
                .await
                .map_err(|e| (e, Some("head".into())))?;
            let b = Arc::new(b);
            self.swap(edge, |ab| {
                ab.bundles.insert(bundle.into(), b);
            });
            Self::bundle_event(edge, event_kind::ACTIVATED, bundle, head_id, Some("head"), None);
            self.cold_base
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(bundle);
            return self.finish_head(edge, bundle, &head, cold_ok);
        }
        let Some(cur) = cur else { return Ok(()) };
        let mut b = Bundle::clone(&cur);
        drop(cur);
        let rich = loader.rich().await.map_err(|e| (e, Some("head".into())))?;

        // Step 1: the head itself; every part it leaves unchanged moves to it at once.
        if b.head() != head_id {
            b = b
                .with_head(&head.head, Arc::clone(&id))
                .map_err(|e| (StepError::retry("load", e.to_string()), Some("head".into())))?;
            let cur_dir = b.hot_dir().entries().to_vec();
            let moved: Vec<Arc<HotShard>> = b
                .hot_shards()
                .iter()
                .filter(|s| *s.head != *id && head.head.shard(s.number).is_some_and(|r| same_hot(s, r)))
                .filter(|s| {
                    head.head
                        .shard_dir
                        .iter()
                        .any(|e| Some(e) == cur_dir.iter().find(|c| c.shard == s.number))
                })
                .filter_map(|s| s.in_head(Arc::clone(&id), Arc::clone(&rich)).ok().map(Arc::new))
                .collect();
            if !moved.is_empty() {
                b = b
                    .with_hot(&cur_dir, moved)
                    .map_err(|e| (StepError::retry("load", e.to_string()), Some("head".into())))?;
            }
            let ips: Vec<Arc<IpShard>> = b.ip_shards().cloned().collect();
            for s in ips {
                if *s.head != *id
                    && head.head.ip_shard(s.id).is_some_and(|r| same_ip(&s, r))
                    && let Ok(m) = s.in_head(Arc::clone(&id), Arc::clone(&rich))
                {
                    b = b.with_ip_shard(Arc::new(m));
                }
            }
            if *b.patterns().head != *id
                && self.patterns_id(&b.patterns().head).as_deref() == head.head.segment(PATTERNS)
                && let Ok(p) = b.patterns().in_head(Arc::clone(&id), Arc::clone(&rich))
            {
                b = b.with_patterns(p);
            }
            if let Cold::Loaded(cp) = b.cold().clone()
                && cp.dir().entries() == head.head.cold_shard_dir.as_slice()
            {
                let shards: Vec<Arc<ColdShard>> = cp
                    .shards()
                    .iter()
                    .map(|s| match head.head.cold_shard(s.number) {
                        Some(r) if *s.head != *id && same_cold(s, r) => Arc::new(s.in_head(Arc::clone(&id))),
                        _ => Arc::clone(s),
                    })
                    .collect();
                if let Ok(p) = ColdPart::new(&head.head.cold_shard_dir, shards, cp.previous().cloned()) {
                    b = b.with_cold(Cold::Loaded(Arc::new(p)));
                }
            }
            self.fit(edge, cfg, bundle, &b, true)
                .await
                .map_err(|e| (e, Some("head".into())))?;
            self.publish(edge, bundle, &b);
            Self::bundle_event(edge, event_kind::ACTIVATED, bundle, head_id, Some("head"), None);
        }

        // Step 2: cold upserts (only with a usable SSD; edge.md §13 "Order").
        let mut cold_changed: Vec<u32> = Vec::new();
        if cold_ok && head.head.has_cold() {
            let new_dir = head.head.cold_shard_dir.clone();
            match b.cold().clone() {
                Cold::Loaded(cp) => {
                    let base = {
                        let mut g = self.cold_base.lock().unwrap_or_else(|p| p.into_inner());
                        match g.get(bundle) {
                            Some((h, p)) if **h == *head_id => Arc::clone(p),
                            _ => {
                                g.insert(bundle.to_owned(), (Arc::clone(&id), Arc::clone(&cp)));
                                Arc::clone(&cp)
                            }
                        }
                    };
                    if cp.dir().entries() == new_dir.as_slice() {
                        let mut shards: Vec<Arc<ColdShard>> = cp.shards().to_vec();
                        for r in &head.head.cold_shards {
                            let held = shards.iter().find(|s| s.number == r.shard).cloned();
                            if held.as_ref().is_some_and(|s| *s.head == *id && same_cold(s, r)) {
                                continue;
                            }
                            let part = format!("cold_shards/{}", r.shard);
                            let s = loader
                                .cold(r, held.as_ref())
                                .await
                                .map_err(|e| (e, Some(part.clone())))?;
                            for x in shards.iter_mut() {
                                if x.number == r.shard {
                                    *x = Arc::clone(&s);
                                }
                            }
                            let p = ColdPart::new(&new_dir, shards.clone(), Some(Arc::clone(&base)))
                                .map_err(|e| (StepError::retry("load", e.to_string()), Some(part.clone())))?;
                            b = b.with_cold(Cold::Loaded(Arc::new(p)));
                            self.fit(edge, cfg, bundle, &b, true)
                                .await
                                .map_err(|e| (e, Some(part.clone())))?;
                            self.publish(edge, bundle, &b);
                            cold_changed.push(r.shard);
                            Self::bundle_event(
                                edge,
                                event_kind::ACTIVATED,
                                bundle,
                                head_id,
                                Some(part.as_str()),
                                None,
                            );
                        }
                    } else {
                        // A split or merge: every new shard at once.
                        let mut shards = Vec::new();
                        for r in &head.head.cold_shards {
                            let held = cp.shards().iter().find(|s| s.number == r.shard).cloned();
                            let part = format!("cold_shards/{}", r.shard);
                            shards.push(loader.cold(r, held.as_ref()).await.map_err(|e| (e, Some(part)))?);
                        }
                        let p = ColdPart::new(&new_dir, shards, Some(Arc::clone(&base)))
                            .map_err(|e| (StepError::retry("load", e.to_string()), None))?;
                        b = b.with_cold(Cold::Loaded(Arc::new(p)));
                        self.fit(edge, cfg, bundle, &b, true)
                            .await
                            .map_err(|e| (e, None))?;
                        self.publish(edge, bundle, &b);
                        for r in &head.head.cold_shards {
                            cold_changed.push(r.shard);
                            Self::bundle_event(
                                edge,
                                event_kind::ACTIVATED,
                                bundle,
                                head_id,
                                Some(format!("cold_shards/{}", r.shard).as_str()),
                                None,
                            );
                        }
                    }
                }
                Cold::None | Cold::NotLoaded => {
                    // Nothing cold to move from: keys moving hot → cold are still hot.
                    let c = loader.cold_part().await.map_err(|e| (e, None))?;
                    b = b.with_cold(c);
                    self.fit(edge, cfg, bundle, &b, true)
                        .await
                        .map_err(|e| (e, None))?;
                    self.publish(edge, bundle, &b);
                    for r in &head.head.cold_shards {
                        Self::bundle_event(
                            edge,
                            event_kind::ACTIVATED,
                            bundle,
                            head_id,
                            Some(format!("cold_shards/{}", r.shard).as_str()),
                            None,
                        );
                    }
                }
            }
        }

        // Step 3: hot swaps, one shard at a time; a split or merge swaps its shards at once.
        let new_dir = head.head.shard_dir.clone();
        let cur_dir = b.hot_dir().entries().to_vec();
        for r in &head.head.shards {
            if !cur_dir.iter().any(|e| e.shard == r.shard) {
                continue;
            }
            let held = b.hot_shards().iter().find(|s| s.number == r.shard).cloned();
            if held.as_ref().is_some_and(|s| *s.head == *id && same_hot(s, r)) {
                continue;
            }
            let part = format!("shards/{}", r.shard);
            let s = loader
                .hot(r, held.as_ref(), &rich)
                .await
                .map_err(|e| (e, Some(part.clone())))?;
            let old = held.as_ref().map(Arc::downgrade);
            drop(held);
            b = b
                .with_hot(&cur_dir, vec![s])
                .map_err(|e| (StepError::retry("load", e.to_string()), Some(part.clone())))?;
            self.fit(edge, cfg, bundle, &b, true)
                .await
                .map_err(|e| (e, Some(part.clone())))?;
            self.publish(edge, bundle, &b);
            Self::bundle_event(
                edge,
                event_kind::ACTIVATED,
                bundle,
                head_id,
                Some(part.as_str()),
                None,
            );
            if let Some(w) = old {
                self.wait_freed(w, &format!("bundle {bundle} {part}")).await;
            }
        }
        if cur_dir != new_dir {
            let mut add = Vec::new();
            for r in head
                .head
                .shards
                .iter()
                .filter(|r| !cur_dir.iter().any(|e| e.shard == r.shard))
            {
                let part = format!("shards/{}", r.shard);
                add.push(loader.hot(r, None, &rich).await.map_err(|e| (e, Some(part)))?);
            }
            let nums: Vec<u32> = add.iter().map(|s| s.number).collect();
            b = b
                .with_hot(&new_dir, add)
                .map_err(|e| (StepError::retry("load", e.to_string()), None))?;
            self.fit(edge, cfg, bundle, &b, true)
                .await
                .map_err(|e| (e, None))?;
            self.publish(edge, bundle, &b);
            for n in nums {
                Self::bundle_event(
                    edge,
                    event_kind::ACTIVATED,
                    bundle,
                    head_id,
                    Some(format!("shards/{n}").as_str()),
                    None,
                );
            }
        }

        // Step 4: IP shards.
        for r in &head.head.ip_shards {
            let held = b.ip_shards().find(|s| s.id == r.ip_shard).cloned();
            if held.as_ref().is_some_and(|s| *s.head == *id && same_ip(s, r)) {
                continue;
            }
            let part = format!("ip_shards/{}", r.ip_shard);
            let s = loader
                .ip(r, held.as_ref(), &rich)
                .await
                .map_err(|e| (e, Some(part.clone())))?;
            b = b.with_ip_shard(s);
            self.fit(edge, cfg, bundle, &b, true)
                .await
                .map_err(|e| (e, Some(part.clone())))?;
            self.publish(edge, bundle, &b);
            Self::bundle_event(
                edge,
                event_kind::ACTIVATED,
                bundle,
                head_id,
                Some(part.as_str()),
                None,
            );
        }
        let gone: Vec<_> = b
            .ip_shards()
            .filter(|s| head.head.ip_shard(s.id).is_none())
            .map(|s| s.id)
            .collect();
        for sid in gone {
            b = b.without_ip_shard(sid);
            self.publish(edge, bundle, &b);
            Self::bundle_event(
                edge,
                event_kind::ACTIVATED,
                bundle,
                head_id,
                Some(format!("ip_shards/{sid}").as_str()),
                None,
            );
        }

        // Step 5: the patterns segment (with this head's rich rules).
        if *b.patterns().head != *id {
            let held_id = self.patterns_id(&b.patterns().head);
            let reuse = held_id.as_deref().map(|i| (b.patterns(), i));
            let p = loader
                .patterns(&rich, reuse)
                .await
                .map_err(|e| (e, Some("segments/patterns.bin".into())))?;
            b = b.with_patterns(p);
            self.fit(edge, cfg, bundle, &b, true)
                .await
                .map_err(|e| (e, Some("segments/patterns.bin".into())))?;
            self.publish(edge, bundle, &b);
            Self::bundle_event(
                edge,
                event_kind::ACTIVATED,
                bundle,
                head_id,
                Some("segments/patterns.bin"),
                None,
            );
        }

        // Step 6: cold deletes, now that every hot swap is done.
        if head.head.has_cold() {
            if let Cold::Loaded(cp) = b.cold().clone()
                && cp.previous().is_some()
                && cold_ok
            {
                b = b.with_cold(Cold::Loaded(Arc::new(cp.settled())));
                self.publish(edge, bundle, &b);
                for n in &cold_changed {
                    Self::bundle_event(
                        edge,
                        event_kind::ACTIVATED,
                        bundle,
                        head_id,
                        Some(format!("cold_shards/{n}").as_str()),
                        None,
                    );
                }
            }
        } else if !matches!(b.cold(), Cold::None) {
            b = b.drop_previous_cold();
            self.publish(edge, bundle, &b);
        }
        self.cold_base
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(bundle);
        drop(b);
        self.finish_head(edge, bundle, &head, cold_ok)
    }

    /// The completion step: logs `activated` (no part) once every part the head needs is active.
    fn finish_head(
        &self,
        edge: &Edge,
        bundle: &str,
        head: &HeadInfo,
        cold_ok: bool,
    ) -> Result<(), (StepError, Option<String>)> {
        let Some(b) = edge.active().bundles.get(bundle).cloned() else {
            return Ok(());
        };
        if is_complete(&b, &head.head, &head.id, cold_ok) {
            Self::bundle_event(edge, event_kind::ACTIVATED, bundle, &head.id, None, None);
            self.lock_record().complete_head(bundle);
            self.persist(edge);
            Ok(())
        } else {
            Err((
                StepError::retry("load", "not every part of the head is active yet"),
                None,
            ))
        }
    }

    /// Swaps `b` in for `bundle` and records the step in `active.json`.
    fn publish(&self, edge: &Edge, bundle: &str, b: &Bundle) {
        let arc = Arc::new(b.clone());
        self.swap(edge, |ab| {
            ab.bundles.insert(bundle.into(), arc);
        });
        {
            let mut r = self.lock_record();
            if let Some(e) = r.heads.get_mut(bundle) {
                e.parts = Some(b.versions());
            }
        }
        self.persist(edge);
    }

    /// The `patterns.bin` id of head `head` (known while its parsed head is held).
    fn patterns_id(&self, head: &str) -> Option<String> {
        self.cached_head(head)
            .and_then(|h| h.head.segment(PATTERNS).map(str::to_owned))
    }

    // ------------------------------------------------------------------------------------------
    // Verdict sets

    /// Loads `head` for `provider` without swapping it in. `Ok(None)` when nothing changes or no
    /// SSD can hold it (not loaded). `prepared`: the sets already loaded for the same config,
    /// counted in place of the active ones they replace.
    async fn prepare_set(
        &self,
        edge: &Edge,
        cfg: &EdgeConfig,
        provider: &str,
        head_id: &str,
        cold_ok: bool,
        prepared: &[PreparedSet],
    ) -> Result<Option<PreparedSet>, StepError> {
        let cur = self.sets.load().get(provider).cloned();
        if cur.as_ref().is_some_and(|c| *c.head == *head_id) {
            return Ok(None);
        }
        if !cold_ok {
            return Ok(None);
        }
        let Some(root) = store::verdicts_root(edge) else {
            return Ok(None);
        };
        let head = verdicts::fetch_head(edge, &root, provider, head_id).await?;
        let (set, change) = verdicts::load(
            edge,
            &self.pages,
            &root,
            provider,
            head_id,
            &head,
            cur.as_ref().map(|c| &c.set),
            store::Caps::of(&cfg.memory),
            self.tuning.chain_run,
        )
        .await?;
        let set = Arc::new(set);
        // Overlays count against overlay_budget_mib with the bundles' (edge.md §17): those the
        // target config keeps.
        let mut overlays: usize = edge
            .active()
            .bundles
            .bundles
            .iter()
            .filter(|(k, _)| cfg.bundles.contains_key(&***k))
            .map(|(_, b)| b.overlay_bytes())
            .sum();
        for (p, s) in self.sets.load().iter() {
            if p != provider && cfg.verdict_sets.contains_key(p) && !prepared.iter().any(|x| x.provider == *p)
            {
                overlays = overlays.saturating_add(s.set.overlay_bytes());
            }
        }
        for x in prepared.iter().filter(|x| x.provider != provider) {
            overlays = overlays.saturating_add(x.active.set.overlay_bytes());
        }
        overlays = overlays.saturating_add(set.overlay_bytes());
        if overlays > (cfg.memory.overlay_budget_mib as usize).saturating_mul(MIB) {
            return Err(StepError::permanent(
                "budget",
                format!(
                    "overlays would take {} MiB, over overlay_budget_mib {}",
                    overlays.div_ceil(MIB),
                    cfg.memory.overlay_budget_mib
                ),
            ));
        }
        let adapter = verdicts::SetAdapter::new(
            Arc::clone(&set),
            Arc::clone(&self.pages),
            Arc::clone(&edge.clock),
            self.refetch_tx.clone(),
        );
        Ok(Some(PreparedSet {
            provider: provider.to_owned(),
            head: head_id.to_owned(),
            active: Arc::new(verdicts::ActiveSet {
                head: head_id.into(),
                set,
                adapter,
            }),
            change,
        }))
    }

    /// Swaps a prepared set in: attached at once to its provider's client when one exists (no
    /// query sees the new set behind an older RAM entry), recorded, and logged `activated`.
    /// Returns the change for a provider without a client yet ([`Self::attach_sets`]).
    async fn commit_set(&self, edge: &Edge, x: PreparedSet) -> Option<(String, verdicts::SetChange)> {
        let mut change = Some(x.change);
        if let Some(client) = edge.dns.lookups.get(&x.provider)
            && let Some(c) = change.take()
        {
            verdicts::attach(client, &x.active, c, Arc::clone(&self.pages)).await;
            self.attached
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(x.provider.clone(), Arc::clone(&x.active.head));
        }
        self.sets.rcu(|m| {
            let mut m = HashMap::clone(m);
            m.insert(x.provider.clone(), Arc::clone(&x.active));
            m
        });
        {
            let mut r = self.lock_record();
            let e = r.sets.entry(x.provider.clone()).or_default();
            if e.active != x.head {
                if !e.active.is_empty() {
                    e.previous = Some(std::mem::take(&mut e.active));
                }
                e.active = x.head.clone();
            }
        }
        self.persist(edge);
        Self::set_event(
            edge,
            event_kind::ACTIVATED,
            &x.provider,
            &x.head,
            Some("set"),
            None,
        );
        Self::set_event(edge, event_kind::ACTIVATED, &x.provider, &x.head, None, None);
        change.map(|c| (x.provider, c))
    }

    /// Attaches active sets to the lookup clients that don't have them (new providers).
    async fn attach_sets(&self, edge: &Edge, changes: Vec<(String, verdicts::SetChange)>) {
        let sets = self.sets.load_full();
        let mut changes: HashMap<String, verdicts::SetChange> = changes.into_iter().collect();
        for id in edge.dns.lookups.ids() {
            let Some(active) = sets.get(&id) else { continue };
            let attached = self
                .attached
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&id)
                .cloned();
            if attached.as_deref() == Some(&*active.head) {
                continue;
            }
            let Some(client) = edge.dns.lookups.get(&id) else {
                continue;
            };
            let change = changes.remove(&id).unwrap_or(verdicts::SetChange::Base);
            verdicts::attach(client, active, change, Arc::clone(&self.pages)).await;
            self.attached
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(id.clone(), Arc::clone(&active.head));
        }
    }

    /// Drops the verdict sets of providers the config no longer names.
    fn drop_unnamed_sets(&self, edge: &Edge, cfg: &EdgeConfig) {
        let gone: Vec<String> = self
            .sets
            .load()
            .keys()
            .filter(|p| !cfg.verdict_sets.contains_key(*p))
            .cloned()
            .collect();
        if gone.is_empty() {
            return;
        }
        self.sets.rcu(|m| {
            let mut m = HashMap::clone(m);
            for p in &gone {
                m.remove(p);
            }
            m
        });
        let mut att = self.attached.lock().unwrap_or_else(|p| p.into_inner());
        for p in &gone {
            att.remove(p);
            if let Some(c) = edge.dns.lookups.get(p) {
                c.set_verdict_set(None);
            }
            self.pages.forget_owner(&Owner::Provider(p.as_str().into()));
        }
        drop(att);
        self.refresh_versions(edge);
    }

    /// Unloads every verdict set (no usable SSD): lookups skip them (edge.md §10).
    fn unload_sets(&self, edge: &Edge) {
        let had = !self.sets.load().is_empty();
        self.sets.store(Arc::new(HashMap::new()));
        let mut att = self.attached.lock().unwrap_or_else(|p| p.into_inner());
        for p in att.keys() {
            if let Some(c) = edge.dns.lookups.get(p) {
                c.set_verdict_set(None);
            }
        }
        att.clear();
        drop(att);
        if had {
            self.refresh_versions(edge);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Following the SSD (edge-unifi.md §1)

    /// Loads or unloads cold parts and verdict sets for where they can live now, moves the files
    /// between the SSD and the eMMC copy, and republishes `versions`.
    pub async fn follow_locations(&self, edge: &Edge) {
        let _g = self.lock.lock().await;
        let cold_ok = store::cold_root(edge).is_some();
        let Some(cfg) = edge.active().config.clone() else {
            return;
        };
        // Names only: each bundle is read fresh and let go before `fit`, which may wait for a
        // bundle it unloads to be freed (bundles.md §6); a held one would never be.
        let todo: Vec<Arc<str>> = {
            let ab = edge.active().bundles.clone();
            ab.bundles
                .iter()
                .filter(|(_, b)| {
                    matches!(
                        (cold_ok, b.cold()),
                        (true, Cold::NotLoaded) | (false, Cold::Loaded(_))
                    )
                })
                .map(|(k, _)| Arc::clone(k))
                .collect()
        };
        for k in &todo {
            let Some(b) = edge.active().bundles.get(k).cloned() else {
                continue;
            };
            let not_loaded = matches!(b.cold(), Cold::NotLoaded);
            match (cold_ok, not_loaded) {
                (true, true) => {
                    let head_id = b.head().to_owned();
                    let Ok(head) = self.head_info(edge, k, &head_id).await else {
                        continue;
                    };
                    if !head.head.has_cold() {
                        continue;
                    }
                    let loader = Loader {
                        edge,
                        mgr: self,
                        bundle: k,
                        head: &head,
                        caps: store::Caps::of(&cfg.memory),
                    };
                    match loader.cold_part().await {
                        Ok(c) => {
                            let nb = b.with_cold(c);
                            drop(b);
                            if let Err(e) = self.fit(edge, &cfg, k, &nb, true).await {
                                tracing::warn!("bundle {k}: cold part not loaded: {e}");
                                continue;
                            }
                            self.publish(edge, k, &nb);
                            for r in &head.head.cold_shards {
                                Self::bundle_event(
                                    edge,
                                    event_kind::ACTIVATED,
                                    k,
                                    &head_id,
                                    Some(format!("cold_shards/{}", r.shard).as_str()),
                                    None,
                                );
                            }
                            if is_complete(&nb, &head.head, &head.id, true) {
                                self.lock_record().complete_head(k);
                            }
                        }
                        Err(e) => tracing::info!("bundle {k}: cold part not loaded yet: {e}"),
                    }
                }
                (false, false) => {
                    let nb = b.with_cold(Cold::NotLoaded);
                    drop(b);
                    self.publish(edge, k, &nb);
                }
                _ => {}
            }
        }
        if cold_ok {
            let wanted = self.wanted_sets.load_full();
            let mut changes = Vec::new();
            // The running config's sets (never a newer head a failed config loaded: those are
            // swapped in only with their config).
            for (p, h) in wanted.iter() {
                match self.prepare_set(edge, &cfg, p, h, true, &[]).await {
                    Ok(Some(x)) => changes.extend(self.commit_set(edge, x).await),
                    Ok(None) => {}
                    Err(e) => tracing::info!("verdict set {p}: not loaded yet: {e}"),
                }
            }
            self.attach_sets(edge, changes).await;
            self.refresh_versions(edge);
        } else {
            self.unload_sets(edge);
        }
        self.move_files(edge).await;
    }

    /// When the SSD passes: writes there every hot file a restart may need that it lacks (from
    /// the eMMC copy or core), syncs each, then the record (merged with the record already there,
    /// so stored configs' maps survive), and only once all of that succeeded deletes the eMMC
    /// copy. When it fails past the start window and the copy isn't filled yet: fills the eMMC
    /// copy with those files and a record (edge-unifi.md §1 "Bundles"). Any failure stops there,
    /// keeps what exists, and leaves the move pending for the next follower round. Once a move
    /// completed, a round with no copy to move does nothing.
    async fn move_files(&self, edge: &Edge) {
        if edge.storage.ssd.is_none() {
            self.placement_pending.store(false, Relaxed);
            return;
        }
        let emmc = edge.layout.bundles_dir();
        let has_copy = emmc.join("active.json").exists();
        let done = match edge.storage.bundles_location() {
            // With no copy, the files fetched while they were in memory only, and the record in
            // memory, go there too.
            crate::storage::BundlesLocation::Ssd(dir) if dir != emmc => {
                // A later failure fills a new copy.
                self.emmc_filled.store(false, Relaxed);
                if !has_copy && self.placed_complete(&dir) {
                    true
                } else if self.place_hot_files(edge, &dir).await.is_ok() {
                    let r = {
                        let mut r = self.lock_record().clone();
                        if let Some(there) = Record::load(&dir) {
                            merge_configs(&mut r, there);
                        }
                        r
                    };
                    match save_if_changed(&r, &dir) {
                        Ok(()) => {
                            *self.lock_record() = r;
                            if has_copy {
                                let _ = std::fs::remove_dir_all(&emmc);
                                edge.storage.recount();
                            }
                            self.placed_lock().complete = true;
                            true
                        }
                        Err(e) => {
                            tracing::warn!("writing {}/active.json: {}", dir.display(), crate::diag::cap(e));
                            edge.storage.recheck();
                            false
                        }
                    }
                } else {
                    false
                }
            }
            crate::storage::BundlesLocation::DataDir(dir) => {
                self.forget_placed();
                if self.emmc_filled.load(Relaxed) {
                    true
                } else if self.place_hot_files(edge, &dir).await.is_ok() {
                    let r = self.lock_record().clone();
                    match save_if_changed(&r, &dir) {
                        Ok(()) => {
                            self.emmc_filled.store(true, Relaxed);
                            true
                        }
                        Err(e) => {
                            tracing::warn!("writing {}/active.json: {}", dir.display(), crate::diag::cap(e));
                            false
                        }
                    }
                } else {
                    false
                }
            }
            _ => {
                self.forget_placed();
                true
            }
        };
        self.placement_pending.store(!done, Relaxed);
    }

    fn placed_lock(&self) -> std::sync::MutexGuard<'_, Placed> {
        self.placed.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether a move to `dir` completed this run.
    fn placed_complete(&self, dir: &Path) -> bool {
        let p = self.placed_lock();
        p.complete && p.root.as_deref() == Some(dir)
    }

    /// The hot files left the SSD's care (it failed, or files went to memory only): the next
    /// move checks everything again.
    fn forget_placed(&self) {
        *self.placed_lock() = Placed::default();
    }

    /// The heads whose hot files go with a move, and whether a restart needs them (edge.md §3;
    /// edge-unifi.md §1). Needed: each head of the running config (what a start from disk loads,
    /// even while a newer config has moved a bundle on), plus a bundle's previous, complete head
    /// when the running head is recorded part-way (the start falls back to it). Also, when they
    /// can be had: every other recorded head (active and previous) and each bundle's head in
    /// memory.
    fn heads_to_keep(&self, edge: &Edge) -> Vec<(String, String, bool)> {
        let mut out: Vec<(String, String, bool)> = Vec::new();
        let mut add = |b: &str, h: &str, need: bool| {
            if h.is_empty() {
                return;
            }
            match out.iter_mut().find(|(x, y, _)| x == b && y == h) {
                Some(e) => e.2 |= need,
                None => out.push((b.to_owned(), h.to_owned(), need)),
            }
        };
        let running = edge.active().config.clone();
        let r = self.lock_record();
        if let Some(c) = &running {
            for (b, h) in &c.bundles {
                add(b, h, true);
                if let Some(e) = r.heads.get(b)
                    && e.active == *h
                    && !e.complete
                    && let Some(p) = &e.previous
                {
                    add(b, p, true);
                }
            }
        }
        for (b, e) in &r.heads {
            add(b, &e.active, false);
            if let Some(p) = &e.previous {
                add(b, p, false);
            }
        }
        drop(r);
        for (k, b) in &edge.active().bundles.bundles {
            add(k, b.head(), false);
        }
        out
    }

    /// Puts into `dir` every hot file of [`Self::heads_to_keep`] (from a local copy that
    /// verifies, or core), each written tmp → fsync → rename; stops at the first failure for a
    /// head a restart needs, and skips a head it doesn't need whose files can't be had. Files
    /// already placed this run aren't hashed again.
    async fn place_hot_files(&self, edge: &Edge, dir: &Path) -> Result<(), StepError> {
        {
            let mut p = self.placed_lock();
            if p.root.as_deref() != Some(dir) || p.files.len() > MAX_PLACED {
                *p = Placed {
                    root: Some(dir.to_path_buf()),
                    ..Placed::default()
                };
            }
            p.complete = false;
        }
        let read = store::hot_read_roots(edge);
        let caps = edge
            .active()
            .config
            .as_ref()
            .map(|c| store::Caps::of(&c.memory))
            .unwrap_or(store::Caps::of(&Default::default()));
        for (k, hid, need) in self.heads_to_keep(edge) {
            match self.place_head(edge, dir, &read, caps, &k, &hid).await {
                Ok(()) => {}
                Err(e) if need => return Err(e),
                Err(e) => tracing::debug!("bundle {k} head {}: not moved ({e})", short(&hid)),
            }
        }
        Ok(())
    }

    /// Places every hot file of head `hid` of bundle `k` into `dir`.
    async fn place_head(
        &self,
        edge: &Edge,
        dir: &Path,
        read: &[PathBuf],
        caps: store::Caps,
        k: &str,
        hid: &str,
    ) -> Result<(), StepError> {
        let head = self.head_info(edge, k, hid).await?;
        let blob = |id: &str| store::blob_path(dir, store::Tree::Hot, k, id);
        self.place_once(
            edge,
            read,
            &store::head_path(dir, k, hid),
            hid,
            &picket_api::edge_api::keys::bundle_head(k, hid),
            store::MAX_HEAD,
            true,
        )
        .await?;
        // Hot shard bases: the manifest, then the files it lists, then the deltas.
        for s in &head.head.shards {
            self.place_once(
                edge,
                read,
                &blob(&s.base),
                &s.base,
                &store::blob_key(&s.base),
                store::MAX_MANIFEST,
                false,
            )
            .await?;
            let m = crate::fsutil::read_nofollow_bounded(&blob(&s.base), store::MAX_MANIFEST)
                .ok()
                .and_then(|m| picket_bundle::head::Manifest::from_bytes(&m).ok())
                .ok_or_else(|| {
                    StepError::retry("verify", format!("{k}: shard manifest {}", short(&s.base)))
                })?;
            for f in m.files.values() {
                self.place_once(
                    edge,
                    read,
                    &blob(&f.blake3),
                    &f.blake3,
                    &store::blob_key(&f.blake3),
                    f.size.clamp(1, caps.file),
                    false,
                )
                .await?;
            }
            for d in &s.deltas {
                self.place_once(
                    edge,
                    read,
                    &blob(&d.blake3),
                    &d.blake3,
                    &store::blob_key(&d.blake3),
                    d.size.clamp(1, caps.delta),
                    false,
                )
                .await?;
            }
        }
        for s in &head.head.ip_shards {
            self.place_once(
                edge,
                read,
                &blob(&s.base),
                &s.base,
                &store::blob_key(&s.base),
                caps.file,
                false,
            )
            .await?;
            for d in &s.deltas {
                self.place_once(
                    edge,
                    read,
                    &blob(&d.blake3),
                    &d.blake3,
                    &store::blob_key(&d.blake3),
                    d.size.clamp(1, caps.delta),
                    false,
                )
                .await?;
            }
        }
        for name in [PATTERNS, RICH] {
            if let Some(id) = head.head.segment(name) {
                self.place_once(edge, read, &blob(id), id, &store::blob_key(id), caps.file, false)
                    .await?;
            }
        }
        Ok(())
    }

    /// [`store::place`], skipped for a file placed (and verified) earlier this run.
    #[expect(
        clippy::too_many_arguments,
        reason = "one placement: its sources, destination and size limit"
    )]
    async fn place_once(
        &self,
        edge: &Edge,
        read: &[PathBuf],
        dest: &Path,
        id: &str,
        key: &str,
        max: u64,
        is_head: bool,
    ) -> Result<(), StepError> {
        if self.placed_lock().files.contains(dest) {
            return Ok(());
        }
        store::place(edge, read, dest, id, key, max, is_head).await?;
        self.placed_lock().files.insert(dest.to_path_buf());
        Ok(())
    }

    // ------------------------------------------------------------------------------------------
    // Garbage

    /// Deletes files neither the active nor the previous head of a bundle or verdict set uses,
    /// keeping every page file an active cold part or verdict set still reads (edge.md §2).
    async fn gc(&self, edge: &Edge) {
        // It may delete a file a later head names again: placed files are checked again.
        self.placed_lock().files.clear();
        let r = self.lock_record().clone();
        let ab = edge.active().bundles.clone();
        let mut in_use: HashSet<String> = HashSet::new();
        for b in ab.bundles.values() {
            cold_files(b, &mut in_use);
        }
        for s in self.sets.load().values() {
            in_use.insert(s.set.base_id().to_owned());
        }
        let mut hot_roots: Vec<PathBuf> = store::hot_read_roots(edge);
        if let Some(w) = store::hot_write_root(edge)
            && !hot_roots.contains(&w)
        {
            hot_roots.push(w);
        }
        let cold_root = store::cold_root(edge);
        let vroot = store::verdicts_root(edge);
        let mut keep_hot: HashMap<String, HashSet<String>> = HashMap::new();
        let mut keep_cold: HashMap<String, HashSet<String>> = HashMap::new();
        let mut keep_heads: HashMap<String, HashSet<String>> = HashMap::new();
        for (bundle, h) in &r.heads {
            let heads: Vec<&String> = std::iter::once(&h.active).chain(h.previous.iter()).collect();
            for hid in heads {
                keep_heads.entry(bundle.clone()).or_default().insert(hid.clone());
                // A head's files: from the parsed head when held, else from its file on disk.
                let parsed = match self.cached_head(hid) {
                    Some(x) => Some(x.head.clone()),
                    None => hot_roots.iter().find_map(|root| {
                        crate::fsutil::read_nofollow_bounded(
                            &store::head_path(root, bundle, hid),
                            store::MAX_HEAD,
                        )
                        .ok()
                        .and_then(|b| Head::from_bytes(&b).ok())
                    }),
                };
                let Some(head) = parsed else {
                    // Can't tell what it uses: keep this bundle's files.
                    keep_hot.entry(bundle.clone()).or_default().insert("*".into());
                    keep_cold.entry(bundle.clone()).or_default().insert("*".into());
                    continue;
                };
                let mut ids = Vec::new();
                hot_files(&head, &mut ids, |base| {
                    hot_roots.iter().find_map(|root| {
                        crate::fsutil::read_nofollow_bounded(
                            &store::blob_path(root, store::Tree::Hot, bundle, base),
                            store::MAX_MANIFEST,
                        )
                        .ok()
                    })
                });
                keep_hot.entry(bundle.clone()).or_default().extend(ids);
                let mut cids = Vec::new();
                cold_files_of(&head, &mut cids, |base| {
                    cold_root.as_ref().and_then(|root| {
                        crate::fsutil::read_nofollow_bounded(
                            &store::blob_path(root, store::Tree::Cold, bundle, base),
                            store::MAX_MANIFEST,
                        )
                        .ok()
                    })
                });
                keep_cold.entry(bundle.clone()).or_default().extend(cids);
            }
        }
        let mut keep_vheads: HashMap<String, HashSet<String>> = HashMap::new();
        let mut keep_vblobs: HashMap<String, HashSet<String>> = HashMap::new();
        if let Some(vr) = &vroot {
            for (p, s) in &r.sets {
                for hid in std::iter::once(&s.active).chain(s.previous.iter()) {
                    keep_vheads.entry(p.clone()).or_default().insert(hid.clone());
                    let parsed =
                        crate::fsutil::read_nofollow_bounded(&store::head_path(vr, p, hid), store::MAX_HEAD)
                            .ok()
                            .and_then(|b| picket_bundle::verdict::VerdictHead::from_bytes(&b).ok());
                    match parsed {
                        Some(h) => {
                            let e = keep_vblobs.entry(p.clone()).or_default();
                            e.insert(h.base.clone());
                            e.extend(h.deltas.iter().map(|d| d.blake3.clone()));
                        }
                        None => {
                            keep_vblobs.entry(p.clone()).or_default().insert("*".into());
                        }
                    }
                }
            }
        }
        let in_use = Arc::new(in_use);
        let edge_disk = Arc::clone(&edge.storage);
        let ssd_root = edge.storage.ssd.as_ref().map(|s| s.root.clone());
        let _ = tokio::task::spawn_blocking(move || {
            let sweep = |root: &Path,
                         sub: &str,
                         keep: &HashMap<String, HashSet<String>>,
                         heads: bool,
                         drop_unknown: bool| {
                let Ok(rd) = std::fs::read_dir(root) else { return };
                for e in rd.flatten() {
                    let Some(scope) = e.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    if scope == "active.json" || !e.path().is_dir() {
                        continue;
                    }
                    let Some(k) = keep.get(&scope) else {
                        if drop_unknown {
                            let _ = std::fs::remove_dir_all(e.path().join(sub));
                            let _ = std::fs::remove_dir(e.path());
                        }
                        continue;
                    };
                    if k.contains("*") {
                        continue;
                    }
                    let Ok(files) = std::fs::read_dir(e.path().join(sub)) else {
                        continue;
                    };
                    for f in files.flatten() {
                        let Some(name) = f.file_name().to_str().map(str::to_owned) else {
                            continue;
                        };
                        let id = if heads {
                            name.strip_suffix(".json").unwrap_or(&name).to_owned()
                        } else {
                            name.clone()
                        };
                        if !k.contains(&id) && !in_use.contains(&id) {
                            let _ = std::fs::remove_file(f.path());
                        }
                    }
                }
            };
            for root in &hot_roots {
                sweep(root, "heads", &keep_heads, true, true);
                sweep(root, "blobs", &keep_hot, false, true);
            }
            if let Some(c) = &cold_root {
                sweep(c, "cold", &keep_cold, false, true);
            }
            if let Some(v) = &vroot {
                sweep(v, "heads", &keep_vheads, true, true);
                sweep(v, "blobs", &keep_vblobs, false, true);
            }
            let _ = ssd_root;
            edge_disk.recount();
        })
        .await;
        let keep = |id: &str| {
            // Registered page files stay while an active part reads them.
            ab.bundles.values().any(|b| {
                let mut s = HashSet::new();
                cold_files(b, &mut s);
                s.contains(id)
            }) || self.sets.load().values().any(|s| s.set.base_id() == id)
        };
        self.pages.retain(&keep);
    }

    // ------------------------------------------------------------------------------------------
    // Background tasks

    /// Refetches page files that failed their checksum, one at a time, logging each
    /// `page_file_refetched` (bundles.md §4).
    pub async fn run_refetch(self: Arc<Self>, edge: Arc<Edge>) -> anyhow::Result<()> {
        let Some(mut rx) = self.refetch_rx.lock().unwrap_or_else(|p| p.into_inner()).take() else {
            // Restarted by the supervisor after a panic: requests now go nowhere until restart;
            // reads keep failing open meanwhile.
            std::future::pending::<()>().await;
            return Ok(());
        };
        let mut backoff = self.tuning.refetch_backoff.0;
        // Files fetched again this run. A file is named by its BLAKE3, so a refetched file has the
        // same bytes as core's: one that fails its page checks again, however long after, is a
        // hard failure (bundles.md §4 "Reading"), logged with `still_bad`. It isn't fetched again
        // while the file on disk still matches its BLAKE3 (the same bytes would come back),
        // checked after a backoff (doubling); one changed on disk since is fetched again.
        let mut again: HashMap<String, Refetch> = HashMap::new();
        let (first, most) = self.tuning.refetch_backoff;
        while let Some(id) = rx.recv().await {
            let seen = match again.get(&id).copied() {
                Some(Refetch::Wait { until, .. }) if Instant::now() < until => continue,
                other => other,
            };
            if let Some(r) = seen {
                let Some(f) = self.pages.get(&id) else {
                    again.remove(&id);
                    continue;
                };
                let next = match r {
                    Refetch::Done { next } | Refetch::Wait { next, .. } => next,
                };
                let (path, want) = (f.path.clone(), id.clone());
                let intact =
                    tokio::task::spawn_blocking(move || store::hash_file(&path).is_some_and(|h| h == want))
                        .await
                        .unwrap_or(false);
                if intact {
                    if matches!(r, Refetch::Done { .. }) {
                        let (k, v) = match &f.owner {
                            Owner::Bundle(b) => ("bundle", b.to_string()),
                            Owner::Provider(p) => ("provider", p.to_string()),
                        };
                        tracing::warn!(
                            "page file {} still fails its checks after being fetched again (the same bytes \
                             as core's); not fetched again while it is unchanged",
                            short(&id)
                        );
                        let mut ff = fields(&[(k, v.into())]);
                        ff.insert("still_bad".into(), true.into());
                        edge.logs.event(event_kind::PAGE_FILE_REFETCHED, ff);
                    }
                    again.insert(
                        id,
                        Refetch::Wait {
                            until: Instant::now() + next,
                            next: (next * 2).min(most),
                        },
                    );
                    continue;
                }
                // Changed on disk since it was fetched: fetched again below.
            }
            let Some(f) = self.pages.begin_refetch(&id) else {
                continue;
            };
            let (k, v) = match &f.owner {
                Owner::Bundle(b) => ("bundle", b.to_string()),
                Owner::Provider(p) => ("provider", p.to_string()),
            };
            tracing::warn!(
                "page file {} failed its checks; deleting it and fetching it again",
                short(&id)
            );
            edge.logs
                .event(event_kind::PAGE_FILE_REFETCHED, fields(&[(k, v.into())]));
            store::remove(&edge, &f.path);
            self.verified
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            match store::ensure_page_file(&edge, &f.path, &id, &store::blob_key(&id), None, false).await {
                Ok(()) => {
                    self.mark_page_verified(&id);
                    self.pages.end_refetch(&id);
                    backoff = self.tuning.refetch_backoff.0;
                    // Another failing read of this file soon means it is bad as core serves it.
                    if again.len() >= pages::MAX_FILES {
                        again.clear();
                    }
                    let next = match again.get(&id) {
                        Some(Refetch::Wait { next, .. } | Refetch::Done { next }) => *next,
                        None => first,
                    };
                    again.insert(id.clone(), Refetch::Done { next });
                }
                Err(e) => {
                    tracing::warn!("refetching page file {}: {e}", short(&id));
                    self.pages.end_refetch(&id);
                    // The file is gone, so reads fail open until it is back; ask again later.
                    let tx = self.refetch_tx.clone();
                    let delay = backoff;
                    backoff = (backoff * 2).min(self.tuning.refetch_backoff.1);
                    let id2 = id.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = tx.send(id2).await;
                    });
                }
            }
        }
        Ok(())
    }

    /// Follows the SSD's state (and re-checks every minute), and retries a start from disk while
    /// no config runs (edge.md §3: with core down and no eMMC copy the edge waits for the SSD).
    pub async fn run_follow(self: Arc<Self>, edge: Arc<Edge>) -> anyhow::Result<()> {
        let mut rx = edge.storage.subscribe();
        let mut last_cold = store::cold_root(&edge).is_some();
        let mut last_loc = edge.storage.bundles_location();
        // A copy to move or fill at start (an eMMC copy left by an SSD failure, say).
        self.placement_pending.store(true, Relaxed);
        loop {
            let wait = if edge.active().config.is_none() {
                self.tuning.start_retry
            } else {
                self.tuning.follow_every
            };
            tokio::select! {
                r = rx.changed() => { if r.is_err() { return Ok(()); } }
                _ = tokio::time::sleep(wait) => {}
            }
            if edge.active().config.is_none() {
                crate::convergence::start_from_disk(&edge).await;
                continue;
            }
            let cold = store::cold_root(&edge).is_some();
            let loc = edge.storage.bundles_location();
            // A cold part or verdict set waiting for the SSD, or loaded without one. The snapshot
            // is let go before `follow_locations` waits for the activation lock: an activation
            // holding it waits for the parts it replaces to be freed (bundles.md §6).
            let pending = {
                let ab = edge.active().bundles.clone();
                ab.bundles.values().any(|b| match b.cold() {
                    Cold::NotLoaded => cold,
                    Cold::Loaded(_) => !cold,
                    Cold::None => false,
                }) || (cold && !self.versions("", &ab).not_loaded.verdict_sets.is_empty())
            } || (!cold && !self.sets.load().is_empty())
                // A move to the SSD or the eMMC copy's fill that didn't complete (edge-unifi.md §1).
                || self.placement_pending.load(Relaxed);
            if cold != last_cold || loc != last_loc || pending {
                self.follow_locations(&edge).await;
                last_cold = cold;
                last_loc = loc;
            }
        }
    }
}

/// Adds the stored configs' maps `there` keeps (the SSD's record) to `r`'s, by recency: `r`'s
/// first (the newer record: memory or the eMMC copy), then `there`'s, newest first, each config
/// once, the oldest dropped past [`record::KEEP_CONFIGS`].
fn merge_configs(r: &mut Record, there: Record) {
    for c in there.configs {
        if r.maps_for(&c.hash).is_none() {
            r.configs.push(c);
        }
    }
    r.configs.truncate(record::KEEP_CONFIGS);
}

/// Writes `r` as `dir`'s `active.json` unless it already holds exactly that.
fn save_if_changed(r: &Record, dir: &Path) -> std::io::Result<()> {
    if Record::load(dir).as_ref() == Some(r) {
        return Ok(());
    }
    r.save(dir)
}

/// A page file fetched again ([`BundleManager::run_refetch`]).
#[derive(Clone, Copy, Debug)]
enum Refetch {
    /// Fetched again (verified: core's bytes); failing again is a hard failure, then a wait of
    /// `next`.
    Done { next: Duration },
    /// Bad as core serves it: not checked again before `until`, then `next` after another miss.
    Wait { until: Instant, next: Duration },
}

/// The hot files a head uses (shard bases with their files, IP bases, deltas, segments).
/// `manifest` reads a hot shard manifest held locally (its listed files are kept too).
fn hot_files(head: &Head, out: &mut Vec<String>, manifest: impl Fn(&str) -> Option<Vec<u8>>) {
    for s in &head.shards {
        out.push(s.base.clone());
        if let Some(m) = manifest(&s.base).and_then(|b| picket_bundle::head::Manifest::from_bytes(&b).ok()) {
            out.extend(m.files.values().map(|f| f.blake3.clone()));
        }
        out.extend(s.deltas.iter().map(|d| d.blake3.clone()));
    }
    for s in &head.ip_shards {
        out.push(s.base.clone());
        out.extend(s.deltas.iter().map(|d| d.blake3.clone()));
    }
    for name in [PATTERNS, RICH] {
        if let Some(id) = head.segment(name) {
            out.push(id.to_owned());
        }
    }
}

/// The cold files a head uses.
fn cold_files_of(head: &Head, out: &mut Vec<String>, manifest: impl Fn(&str) -> Option<Vec<u8>>) {
    for s in &head.cold_shards {
        out.push(s.base.clone());
        if let Some(m) = manifest(&s.base).and_then(|b| picket_bundle::head::Manifest::from_bytes(&b).ok()) {
            out.extend(m.files.values().map(|f| f.blake3.clone()));
        }
        out.extend(s.deltas.iter().map(|d| d.blake3.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maps(h: &str) -> ConfigMaps {
        ConfigMaps {
            hash: h.into(),
            object: h.into(),
            ..ConfigMaps::default()
        }
    }

    #[test]
    fn merged_stored_configs_keep_the_newest() {
        // Memory holds the newest config; the SSD's record its three before it, newest first.
        let mut r = Record {
            configs: vec![maps("new")],
            ..Record::default()
        };
        let there = Record {
            configs: vec![maps("a"), maps("b"), maps("c"), maps("new")],
            ..Record::default()
        };
        merge_configs(&mut r, there);
        let got: Vec<&str> = r.configs.iter().map(|c| c.hash.as_str()).collect();
        let want = ["new", "a", "b", "c"];
        assert_eq!(got, want[..record::KEEP_CONFIGS.min(4)], "by recency");
    }
}
