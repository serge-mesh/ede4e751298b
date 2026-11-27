//! Building one part of a bundle head off the hot path (bundles.md §6 "Loading", "Overlay per
//! shard"; §7 "Distribution"): fetch what the edge lacks, verify it, and build the part in a
//! blocking thread.
//!
//! Per shard (hot, cold or IP): if the edge holds that base and the deltas it has applied start
//! the head's chain, only the rest of the chain is fetched and applied on top of the part it
//! holds; otherwise the head's base plus its whole chain. A part whose base and chain are the
//! head's is moved to the head as it is (`in_head`). The set checksum is checked after the chain
//! ([`picket_bundle::reader::LoadError::NeedBase`] on a mismatch: the base is fetched).
//!
//! **RAM** (edge.md §17): every object is capped by the edge's budgets before it is fetched
//! ([`store::Caps`]), and a chain is fetched and applied a bounded run at a time
//! ([`CHAIN_RUN`] bytes of deltas, one overlay rebuild per run), never held whole. A manifest
//! must be for the shard and part the head names it for.

use std::sync::Arc;

use picket_api::edge_api::keys;
use picket_api::edge_config::EdgeConfig;
use picket_bundle::head::{
    COLD_BF8, COLD_PAGES, DOMAINS_BF8, DOMAINS_FST, DeltaRef, Head, IpShardRef, Manifest, PATTERNS, RICH,
    ShardRef,
};
use picket_bundle::matcher::{Bundle, Cold, ColdPart, LoadedParts};
use picket_bundle::page::{PAGE_SIZE, PageReader};
use picket_bundle::reader::{
    ColdBaseBlobs, ColdShard, HotBaseBlobs, HotShard, IpShard, LoadError, PatternsPart, load_rich,
};
use picket_bundle::rich::RichSegment;

use super::BundleManager;
use super::pages::Owner;
use super::store::{self, Caps, MAX_MANIFEST, StepError, Tree};
use crate::edge::Edge;

/// The compressed deltas fetched and applied together (one overlay rebuild per run); a delta
/// bigger than this is a run of its own.
pub const CHAIN_RUN: usize = 4 << 20;

/// A parsed head and its id.
#[derive(Debug)]
pub struct HeadInfo {
    pub id: Arc<str>,
    pub head: Head,
}

fn load_err(stage: &'static str, what: &str, e: LoadError) -> StepError {
    match e {
        // Core sent a file that doesn't verify or parse: retried (core may serve a good copy).
        LoadError::Head(_) | LoadError::Fst(_) | LoadError::Filter(_) | LoadError::Ips(_) => {
            StepError::retry("verify", format!("{what}: {e}"))
        }
        other => StepError::retry(stage, format!("{what}: {other}")),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, StepError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| StepError::retry("load", crate::diag::cap(e)))
}

/// What a loader needs for one bundle head.
pub struct Loader<'a> {
    pub edge: &'a Edge,
    pub mgr: &'a BundleManager,
    pub bundle: &'a str,
    pub head: &'a HeadInfo,
    /// The largest objects this edge reads into memory.
    pub caps: Caps,
}

/// Checks a shard manifest is for the slot the head names it in.
fn check_manifest(
    m: &Manifest,
    part: picket_bundle::head::PartKind,
    shard: u32,
    what: &str,
) -> Result<(), StepError> {
    if m.part != part || m.shard != shard {
        return Err(StepError::retry(
            "verify",
            format!("{what}: the manifest is for {:?} shard {}", m.part, m.shard),
        ));
    }
    Ok(())
}

impl Loader<'_> {
    async fn hot_blob(&self, id: &str, max: u64) -> Result<Vec<u8>, StepError> {
        let read = store::hot_read_roots(self.edge);
        let write = store::hot_write_root(self.edge);
        store::fetch_bytes(
            self.edge,
            &read,
            write.as_deref(),
            Tree::Hot,
            self.bundle,
            id,
            &store::blob_key(id),
            max,
        )
        .await
    }

    async fn cold_blob(&self, id: &str, max: u64) -> Result<Vec<u8>, StepError> {
        let root = store::cold_root(self.edge)
            .ok_or_else(|| StepError::retry("fetch", "no usable SSD for cold parts"))?;
        store::fetch_bytes(
            self.edge,
            std::slice::from_ref(&root),
            Some(&root),
            Tree::Cold,
            self.bundle,
            id,
            &store::blob_key(id),
            max,
        )
        .await
    }

    /// Applies the deltas of `chain` after `after_seq` to `start`, fetching and applying a run of
    /// at most [`CHAIN_RUN`] bytes at a time (each delta capped by the overlay budget before it
    /// is fetched). `Ok(Err(_))`: the chain doesn't apply (the caller may fall back to the base).
    async fn apply_chain<S, F>(
        &self,
        chain: &[DeltaRef],
        after_seq: u64,
        cold: bool,
        start: S,
        apply: F,
    ) -> Result<Result<S, LoadError>, StepError>
    where
        S: Send + 'static,
        F: Fn(S, &[&[u8]]) -> Result<S, LoadError> + Send + Sync + Clone + 'static,
    {
        let run_bytes = self.mgr.tuning.chain_run.max(1);
        let mut cur = start;
        let mut run: Vec<Vec<u8>> = Vec::new();
        let mut held = 0usize;
        let todo: Vec<&DeltaRef> = chain.iter().filter(|d| d.seq > after_seq).collect();
        for (i, d) in todo.iter().enumerate() {
            if d.size > self.caps.delta {
                return Err(StepError::retry(
                    "verify",
                    format!(
                        "delta {} is {} bytes, more than this edge's overlays could hold",
                        d.seq, d.size
                    ),
                ));
            }
            let b = if cold {
                self.cold_blob(&d.blake3, d.size.max(1)).await?
            } else {
                self.hot_blob(&d.blake3, d.size.max(1)).await?
            };
            held += b.len();
            run.push(b);
            if held >= run_bytes || i + 1 == todo.len() {
                let f = apply.clone();
                let batch = std::mem::take(&mut run);
                held = 0;
                let r = blocking(move || {
                    let refs: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
                    f(cur, &refs)
                })
                .await?;
                match r {
                    Ok(s) => cur = s,
                    Err(e) => return Ok(Err(e)),
                }
            }
        }
        Ok(Ok(cur))
    }

    /// The head's `rich.json`, shared by every part of this head.
    pub async fn rich(&self) -> Result<Arc<RichSegment>, StepError> {
        let id = self
            .head
            .head
            .segment(RICH)
            .ok_or_else(|| StepError::retry("verify", "head names no rich.json"))?
            .to_owned();
        if let Some(r) = self.mgr.cached_rich(&id) {
            return Ok(r);
        }
        let bytes = self.hot_blob(&id, self.caps.file).await?;
        let id2 = id.clone();
        let r = blocking(move || load_rich(&id2, &bytes))
            .await?
            .map_err(|e| load_err("load", "rich.json", e))?;
        self.mgr.cache_rich(&id, &r);
        Ok(r)
    }

    /// The patterns segment as a part of this head, moving `reuse` when it holds the same
    /// `patterns.bin`.
    pub async fn patterns(
        &self,
        rich: &Arc<RichSegment>,
        reuse: Option<(&PatternsPart, &str)>,
    ) -> Result<PatternsPart, StepError> {
        let id = self
            .head
            .head
            .segment(PATTERNS)
            .ok_or_else(|| StepError::retry("verify", "head names no patterns.bin"))?
            .to_owned();
        if let Some((p, held_id)) = reuse
            && held_id == id
            && let Ok(moved) = p.in_head(Arc::clone(&self.head.id), Arc::clone(rich))
        {
            return Ok(moved);
        }
        let bytes = self.hot_blob(&id, self.caps.file).await?;
        let head = Arc::clone(&self.head.id);
        let rich = Arc::clone(rich);
        blocking(move || PatternsPart::load(head, &id, &bytes, picket_bundle::patterns::DEFAULT_BUDGET, rich))
            .await?
            .map_err(|e| load_err("load", "patterns.bin", e))
    }

    /// True when `seq` starts a part of `r`'s chain (the base, or one of its deltas).
    fn continues(r_base_seq: u64, chain: &[DeltaRef], seq: u64) -> bool {
        seq == r_base_seq || chain.iter().any(|d| d.seq == seq)
    }

    /// Hot shard `r` as a part of this head.
    pub async fn hot(
        &self,
        r: &ShardRef,
        reuse: Option<&Arc<HotShard>>,
        rich: &Arc<RichSegment>,
    ) -> Result<Arc<HotShard>, StepError> {
        let what = format!("shards/{}", r.shard);
        let (head, rich2, want) = (Arc::clone(&self.head.id), Arc::clone(rich), r.checksum);
        let step = move |s: HotShard, ds: &[&[u8]]| s.apply_deltas(ds, Arc::clone(&head), Arc::clone(&rich2));
        if let Some(p) = reuse.filter(|p| p.base_id() == r.base && p.number == r.shard) {
            if p.seq() == r.seq && p.checksum() == r.checksum {
                if let Ok(m) = p.in_head(Arc::clone(&self.head.id), Arc::clone(rich)) {
                    return Ok(Arc::new(m));
                }
            } else if p.seq() < r.seq && Self::continues(r.base_seq, &r.deltas, p.seq()) {
                let res = self
                    .apply_chain(&r.deltas, p.seq(), false, HotShard::clone(p), step.clone())
                    .await?
                    .and_then(|s| {
                        if s.checksum() == want {
                            Ok(s)
                        } else {
                            Err(LoadError::NeedBase("checksum after the chain".into()))
                        }
                    });
                match res {
                    Ok(s) => return Ok(Arc::new(s)),
                    Err(e) => tracing::info!(
                        "bundle {} {what}: applying the rest of the chain failed ({e}); loading its base",
                        self.bundle
                    ),
                }
            }
        }
        let manifest = self.hot_blob(&r.base, MAX_MANIFEST).await?;
        let m = Manifest::from_bytes(&manifest)
            .map_err(|e| StepError::retry("verify", format!("{what}: {e}")))?;
        check_manifest(&m, picket_bundle::head::PartKind::Hot, r.shard, &what)?;
        let fst_ref = m
            .file(DOMAINS_FST)
            .ok_or_else(|| StepError::retry("verify", format!("{what}: no domains.fst")))?
            .clone();
        let bf_ref = m
            .file(DOMAINS_BF8)
            .ok_or_else(|| StepError::retry("verify", format!("{what}: no domains.bf8")))?
            .clone();
        if fst_ref.size.saturating_add(bf_ref.size) > self.caps.file {
            return Err(StepError::retry(
                "verify",
                format!("{what}: its files are larger than the bundle budget"),
            ));
        }
        let fst = self.hot_blob(&fst_ref.blake3, fst_ref.size.max(1)).await?;
        let bf8 = self.hot_blob(&bf_ref.blake3, bf_ref.size.max(1)).await?;
        let (bundle, head, seed, base_seq, base, rich2) = (
            self.bundle.to_owned(),
            Arc::clone(&self.head.id),
            self.head.head.hash_seed,
            r.base_seq,
            r.base.clone(),
            Arc::clone(rich),
        );
        let s = blocking(move || {
            HotShard::load(
                &bundle,
                head,
                seed,
                base_seq,
                HotBaseBlobs {
                    base_id: &base,
                    manifest: &manifest,
                    fst,
                    bf8: &bf8,
                },
                rich2,
            )
        })
        .await?
        .map_err(|e| load_err("load", &what, e))?;
        let s = self
            .apply_chain(&r.deltas, r.base_seq, false, s, step)
            .await?
            .and_then(|s| {
                if s.checksum() == want {
                    Ok(s)
                } else {
                    Err(LoadError::NeedBase("checksum after the chain".into()))
                }
            })
            .map_err(|e| load_err("load", &what, e))?;
        Ok(Arc::new(s))
    }

    /// IP shard `r` as a part of this head.
    pub async fn ip(
        &self,
        r: &IpShardRef,
        reuse: Option<&Arc<IpShard>>,
        rich: &Arc<RichSegment>,
    ) -> Result<Arc<IpShard>, StepError> {
        let what = format!("ip_shards/{}", r.ip_shard);
        let (head, rich2, want) = (Arc::clone(&self.head.id), Arc::clone(rich), r.checksum);
        let step = move |s: IpShard, ds: &[&[u8]]| s.apply_deltas(ds, Arc::clone(&head), Arc::clone(&rich2));
        if let Some(p) = reuse.filter(|p| p.base_id() == r.base && p.id == r.ip_shard) {
            if p.seq() == r.seq && p.checksum() == r.checksum {
                if let Ok(m) = p.in_head(Arc::clone(&self.head.id), Arc::clone(rich)) {
                    return Ok(Arc::new(m));
                }
            } else if p.seq() < r.seq && Self::continues(r.base_seq, &r.deltas, p.seq()) {
                let res = self
                    .apply_chain(&r.deltas, p.seq(), false, IpShard::clone(p), step.clone())
                    .await?;
                if let Ok(s) = res
                    && s.checksum() == want
                {
                    return Ok(Arc::new(s));
                }
            }
        }
        let bytes = self.hot_blob(&r.base, self.caps.file).await?;
        let (bundle, head, base_seq, base, rich2, sid) = (
            self.bundle.to_owned(),
            Arc::clone(&self.head.id),
            r.base_seq,
            r.base.clone(),
            Arc::clone(rich),
            r.ip_shard,
        );
        let s = blocking(move || {
            let s = IpShard::load(&bundle, head, &base, base_seq, &bytes, rich2)?;
            if s.id != sid {
                return Err(LoadError::Mismatch("ips.bin is for another shard".into()));
            }
            Ok(s)
        })
        .await?
        .map_err(|e| load_err("load", &what, e))?;
        let s = self
            .apply_chain(&r.deltas, r.base_seq, false, s, step)
            .await?
            .and_then(|s| {
                if s.checksum() == want {
                    Ok(s)
                } else {
                    Err(LoadError::NeedBase("checksum after the chain".into()))
                }
            })
            .map_err(|e| load_err("load", &what, e))?;
        Ok(Arc::new(s))
    }

    /// Cold shard `r` as a part of this head: its filter and overlay in RAM, its page file on the
    /// SSD (fetched straight to disk and verified by streaming BLAKE3).
    pub async fn cold(
        &self,
        r: &ShardRef,
        reuse: Option<&Arc<ColdShard>>,
    ) -> Result<Arc<ColdShard>, StepError> {
        let what = format!("cold_shards/{}", r.shard);
        let reader: Arc<dyn PageReader> = self.mgr.pages.clone();
        let want = r.checksum;
        let rd = Arc::clone(&reader);
        let step = move |s: ColdShard, ds: &[&[u8]]| s.apply_deltas(ds, &*rd);
        if let Some(p) =
            reuse.filter(|p| p.base_id() == r.base && p.number == r.shard && p.moving_from.is_none())
        {
            if p.seq() == r.seq && p.checksum() == r.checksum {
                return Ok(Arc::new(p.in_head(Arc::clone(&self.head.id))));
            } else if p.seq() < r.seq && Self::continues(r.base_seq, &r.deltas, p.seq()) {
                let head = Arc::clone(&self.head.id);
                let res = self
                    .apply_chain(&r.deltas, p.seq(), true, ColdShard::clone(p), step.clone())
                    .await?
                    .map(|s| s.in_head(head))
                    .and_then(|s| {
                        if s.checksum() == want {
                            Ok(s)
                        } else {
                            Err(LoadError::NeedBase("checksum after the chain".into()))
                        }
                    });
                match res {
                    Ok(s) => return Ok(Arc::new(s)),
                    Err(LoadError::Page(e)) if e.needs_refetch() => {
                        self.mgr.request_refetch(p.pages_file());
                        return Err(StepError::retry("load", format!("{what}: {e}")));
                    }
                    Err(_) => {}
                }
            }
        }
        let root = store::cold_root(self.edge)
            .ok_or_else(|| StepError::retry("fetch", "no usable SSD for cold parts"))?;
        let manifest = self.cold_blob(&r.base, MAX_MANIFEST).await?;
        let m = Manifest::from_bytes(&manifest)
            .map_err(|e| StepError::retry("verify", format!("{what}: {e}")))?;
        check_manifest(&m, picket_bundle::head::PartKind::Cold, r.shard, &what)?;
        let bf_ref = m
            .file(COLD_BF8)
            .ok_or_else(|| StepError::retry("verify", format!("{what}: no cold.bf8")))?
            .clone();
        let pages_ref = m
            .file(COLD_PAGES)
            .ok_or_else(|| StepError::retry("verify", format!("{what}: no cold.pages")))?
            .clone();
        if bf_ref.size > self.caps.file {
            return Err(StepError::retry(
                "verify",
                format!("{what}: cold.bf8 is larger than the bundle budget"),
            ));
        }
        let bf8 = self.cold_blob(&bf_ref.blake3, bf_ref.size.max(1)).await?;
        let path = store::blob_path(&root, Tree::Cold, self.bundle, &pages_ref.blake3);
        let verified = self.mgr.page_verified(&pages_ref.blake3);
        store::ensure_page_file(
            self.edge,
            &path,
            &pages_ref.blake3,
            &store::blob_key(&pages_ref.blake3),
            Some(pages_ref.size),
            verified,
        )
        .await?;
        self.mgr.mark_page_verified(&pages_ref.blake3);
        self.mgr
            .pages
            .register(&pages_ref.blake3, path, Owner::Bundle(self.bundle.into()));
        let (bundle, head, seed, base_seq, base, pid, rd) = (
            self.bundle.to_owned(),
            Arc::clone(&self.head.id),
            self.head.head.hash_seed,
            r.base_seq,
            r.base.clone(),
            pages_ref.blake3.clone(),
            Arc::clone(&reader),
        );
        let base_shard = blocking(move || {
            let mut hdr = [0u8; PAGE_SIZE];
            rd.read_page(&pid, 0, &mut hdr)
                .map_err(|e| LoadError::Page(picket_bundle::page::PageError::Io(e.to_string())))?;
            ColdShard::load(
                &bundle,
                head,
                seed,
                base_seq,
                ColdBaseBlobs {
                    base_id: &base,
                    manifest: &manifest,
                    bf8: &bf8,
                },
                &hdr,
            )
        })
        .await?;
        let res = match base_shard {
            Ok(s) => self.apply_chain(&r.deltas, r.base_seq, true, s, step).await?,
            Err(e) => Err(e),
        }
        .and_then(|s| {
            if s.checksum() == want {
                Ok(s)
            } else {
                Err(LoadError::NeedBase("checksum after the chain".into()))
            }
        });
        match res {
            Ok(s) => Ok(Arc::new(s)),
            Err(LoadError::Page(e)) if e.needs_refetch() => {
                // A page failing its checksum while the chain reads it: delete and fetch the file
                // again (bundles.md §4 "Reading").
                self.mgr.request_refetch(&pages_ref.blake3);
                Err(StepError::retry("load", format!("{what}: {e}")))
            }
            Err(e) => Err(load_err("load", &what, e)),
        }
    }

    /// Every cold shard of this head, as a cold part (no previous half).
    pub async fn cold_part(&self) -> Result<Cold, StepError> {
        let h = &self.head.head;
        if !h.has_cold() {
            return Ok(Cold::None);
        }
        let mut shards = Vec::with_capacity(h.cold_shards.len());
        for r in &h.cold_shards {
            shards.push(self.cold(r, None).await?);
        }
        let part = ColdPart::new(&h.cold_shard_dir, shards, None)
            .map_err(|e| StepError::retry("verify", format!("cold part: {e}")))?;
        Ok(Cold::Loaded(Arc::new(part)))
    }

    /// The whole head, every part loaded (a new bundle, a start from disk, or a head whose
    /// format changed). The cold part only when `cold` (a usable SSD). The budgets are checked
    /// against `cfg` after each part loads, so a head too big for them fails at most one part
    /// past them, and room is made when memory is short ([`BundleManager::fit_bytes`]; edge.md
    /// §17, bundles.md §6 "Activation").
    pub async fn whole(&self, cold: bool, cfg: &EdgeConfig) -> Result<Bundle, StepError> {
        let mut mem = 0usize;
        let mut ov = 0usize;
        let rich = self.rich().await?;
        mem = mem.saturating_add(rich.memory_usage());
        let patterns = self.patterns(&rich, None).await?;
        mem = mem.saturating_add(patterns.patterns.memory_usage());
        self.fit(cfg, mem, ov).await?;
        let h = &self.head.head;
        let mut hot = Vec::with_capacity(h.shards.len());
        for r in &h.shards {
            let s = self.hot(r, None, &rich).await?;
            mem = mem.saturating_add(s.memory_usage());
            ov = ov.saturating_add(s.overlay_bytes());
            hot.push(s);
            self.fit(cfg, mem, ov).await?;
        }
        let mut ip = Vec::with_capacity(h.ip_shards.len());
        for r in &h.ip_shards {
            let s = self.ip(r, None, &rich).await?;
            mem = mem.saturating_add(s.memory_usage());
            ov = ov.saturating_add(s.overlay_bytes());
            ip.push(s);
            self.fit(cfg, mem, ov).await?;
        }
        let cold = if cold && h.has_cold() {
            let mut shards = Vec::with_capacity(h.cold_shards.len());
            for r in &h.cold_shards {
                let s = self.cold(r, None).await?;
                mem = mem.saturating_add(s.memory_usage());
                ov = ov.saturating_add(s.overlay_bytes());
                shards.push(s);
                self.fit(cfg, mem, ov).await?;
            }
            let part = ColdPart::new(&h.cold_shard_dir, shards, None)
                .map_err(|e| StepError::retry("verify", format!("cold part: {e}")))?;
            Cold::Loaded(Arc::new(part))
        } else {
            Cold::None
        };
        Bundle::assemble(
            h,
            Arc::clone(&self.head.id),
            LoadedParts {
                hot,
                cold,
                ip,
                patterns,
            },
        )
        .map_err(|e| StepError::retry("load", format!("assembling the bundle: {e}")))
    }

    /// The budgets with `mem` bytes (`ov` of overlays) of this head loaded so far.
    async fn fit(&self, cfg: &EdgeConfig, mem: usize, ov: usize) -> Result<(), StepError> {
        self.mgr
            .fit_bytes(self.edge, cfg, self.bundle, mem, ov, false)
            .await
            .map_err(|e| StepError {
                reason: format!(
                    "{} (after {} MiB of head {})",
                    e.reason,
                    mem.div_ceil(1 << 20),
                    picket_api::ids::short_id(&self.head.id)
                ),
                ..e
            })
    }
}

/// Fetches and parses a bundle head (`bundles/<bundle>/heads/<id>.json`), verifying its id.
pub async fn fetch_head(edge: &Edge, bundle: &str, id: &str) -> Result<HeadInfo, StepError> {
    let read = store::hot_read_roots(edge);
    let write = store::hot_write_root(edge);
    let bytes = store::fetch_bytes(
        edge,
        &read,
        write.as_deref(),
        Tree::Hot,
        bundle,
        id,
        &keys::bundle_head(bundle, id),
        store::MAX_HEAD,
    )
    .await?;
    let head = Head::from_bytes(&bytes).map_err(|e| StepError::retry("verify", format!("head: {e}")))?;
    if head.bundle != bundle {
        return Err(StepError::permanent(
            "verify",
            format!(
                "head {} is for bundle {:?}",
                picket_api::ids::short_id(id),
                crate::diag::truncate(&head.bundle, 64)
            ),
        ));
    }
    Ok(HeadInfo { id: id.into(), head })
}
