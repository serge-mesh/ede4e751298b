//! Verdict sets on the edge (edge.md §10, providers.md §4 "Verdict cache"): for each lookup provider
//! the edge's profiles attach `sync`, core's read-only verdict set for the provider's current
//! `cache_generation`, named in the config object and activated like a bundle head (§13).
//!
//! - Files live only where cold parts do (`<cold root>/verdicts/<provider>/`): without a usable
//!   SSD the set isn't loaded, lookups skip it, and `versions.not_loaded.verdict_sets` names it.
//! - A head that extends the active one's chain (same base) applies only the new deltas, and
//!   activates as a delta: the lookup client drops the RAM-tier entries those deltas supersede
//!   ([`picket_lookup::LookupClient::activate_set_delta`]). A new base activates with
//!   [`picket_lookup::LookupClient::activate_set_base`], every RAM entry checked against the new
//!   set off the hot path (in a blocking thread).
//! - A page that fails its checksum is a miss; the file is deleted and fetched again
//!   (`page_file_refetched {provider}`).
//! - **Clock** (README §2 Clocks): the client judges a record's expiry by the wall clock, which
//!   can't be trusted before it is synchronised; until then the verdict set answers nothing (a
//!   miss), so no record is used past its real expiry.

use std::sync::Arc;

use async_trait::async_trait;

use picket_api::edge_api::keys;
use picket_bundle::page::{PAGE_SIZE, PageReader};
use picket_bundle::verdict::{VerdictHead, VerdictKind, VerdictLoadError, VerdictRecord, VerdictSet};
use picket_lookup::{SetRecord, StoredVerdict};

use super::pages::{FilePages, Owner};
use super::store::{self, StepError, Tree};
use crate::clock::Clock;
use crate::edge::Edge;

/// One active verdict set.
pub struct ActiveSet {
    pub head: Arc<str>,
    pub set: Arc<VerdictSet>,
    pub adapter: Arc<SetAdapter>,
}

/// The lookup client's verdict-set tier over one set.
pub struct SetAdapter {
    pub set: Arc<VerdictSet>,
    pages: Arc<FilePages>,
    clock: Arc<Clock>,
    refetch: tokio::sync::mpsc::Sender<String>,
}

fn stored(r: &VerdictRecord) -> StoredVerdict {
    match r.verdict {
        VerdictKind::Block => StoredVerdict::Block {
            score: r.score,
            reason: r.reason.clone().unwrap_or_default().into(),
        },
        VerdictKind::Clean => StoredVerdict::Clean,
        VerdictKind::Unknown => StoredVerdict::Unknown,
    }
}

#[async_trait]
impl picket_lookup::VerdictSet for SetAdapter {
    async fn get(&self, name: &str) -> anyhow::Result<Option<SetRecord>> {
        if !self.clock.synced() {
            return Ok(None);
        }
        let set = Arc::clone(&self.set);
        let pages = Arc::clone(&self.pages);
        let name = name.to_owned();
        let r = tokio::task::spawn_blocking(move || set.lookup(&name, &*pages)).await?;
        match r {
            Ok(Some(rec)) => Ok(Some(SetRecord {
                verdict: stored(&rec),
                obtained_at: rec.obtained_at,
                generation: Arc::clone(&self.set.generation),
            })),
            Ok(None) => Ok(None),
            Err(e) => {
                if e.needs_refetch() {
                    let _ = self.refetch.try_send(self.set.base_id().to_owned());
                }
                Ok(None)
            }
        }
    }
}

/// Fetches and parses a verdict-set head, verifying its id and provider.
pub async fn fetch_head(
    edge: &Edge,
    root: &std::path::Path,
    provider: &str,
    id: &str,
) -> Result<VerdictHead, StepError> {
    let bytes = store::fetch_bytes(
        edge,
        std::slice::from_ref(&root.to_path_buf()),
        Some(root),
        Tree::Verdicts,
        provider,
        id,
        &keys::verdict_set_head(provider, id),
        store::MAX_HEAD,
    )
    .await?;
    let h = VerdictHead::from_bytes(&bytes)
        .map_err(|e| StepError::retry("verify", format!("verdict-set head: {e}")))?;
    if h.provider != provider {
        return Err(StepError::permanent(
            "verify",
            format!(
                "verdict-set head {} is for another provider",
                picket_api::ids::short_id(id)
            ),
        ));
    }
    Ok(h)
}

/// What activating a head did.
pub enum SetChange {
    /// The new deltas' records, by name hash with `obtained_at` (a delta activation).
    Delta(Vec<(u128, picket_api::time::Timestamp)>),
    /// A new base: every RAM entry is checked against the set.
    Base,
}

/// Loads `head` for `provider` on top of `current` (when its base and chain allow), fetching what
/// it lacks into `root`. Each delta is capped by `caps` before it is fetched, and a chain is
/// fetched and applied `run_bytes` at a time (edge.md §17).
#[expect(
    clippy::too_many_arguments,
    reason = "one verdict-set load: its head, the set it replaces and the store's limits"
)]
pub async fn load(
    edge: &Edge,
    pages: &Arc<FilePages>,
    root: &std::path::Path,
    provider: &str,
    id: &str,
    head: &VerdictHead,
    current: Option<&Arc<VerdictSet>>,
    caps: store::Caps,
    run_bytes: usize,
) -> Result<(VerdictSet, SetChange), StepError> {
    let reader: Arc<dyn PageReader> = pages.clone();
    let fetch_delta = |d: &picket_bundle::head::DeltaRef| {
        let d = d.clone();
        async move {
            if d.size > caps.delta {
                return Err(StepError::retry(
                    "verify",
                    format!(
                        "delta {} is {} bytes, more than this edge's overlays could hold",
                        d.seq, d.size
                    ),
                ));
            }
            store::fetch_bytes(
                edge,
                std::slice::from_ref(&root.to_path_buf()),
                Some(root),
                Tree::Verdicts,
                provider,
                &d.blake3,
                &store::blob_key(&d.blake3),
                d.size.max(1),
            )
            .await
        }
    };
    // Applies the deltas after `after` to `start`, a run at a time; collects what they change
    // when `changed` is given.
    let apply_chain = |start: VerdictSet,
                       after: Option<u64>,
                       mut changed: Option<Vec<(u128, picket_api::time::Timestamp)>>| {
        let reader = Arc::clone(&reader);
        let todo: Vec<picket_bundle::head::DeltaRef> = head
            .deltas
            .iter()
            .filter(|d| after.is_none_or(|a| d.seq > a))
            .cloned()
            .collect();
        async move {
            let mut cur = start;
            let mut run: Vec<Vec<u8>> = Vec::new();
            let mut held = 0usize;
            for (i, d) in todo.iter().enumerate() {
                let b = fetch_delta(d).await?;
                if let Some(c) = changed.as_mut()
                    && let Ok(d) = picket_bundle::verdict::read_delta(&b)
                {
                    for (h, rec) in d.ops {
                        if let Some(r) = rec {
                            c.push((h.0, r.obtained_at));
                        }
                    }
                }
                held += b.len();
                run.push(b);
                if held >= run_bytes.max(1) || i + 1 == todo.len() {
                    let batch = std::mem::take(&mut run);
                    held = 0;
                    let rd = Arc::clone(&reader);
                    let r = tokio::task::spawn_blocking(move || {
                        let refs: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
                        cur.apply_deltas(&refs, &*rd)
                    })
                    .await
                    .map_err(|e| StepError::retry("load", crate::diag::cap(e)))?;
                    match r {
                        Ok(s) => cur = s,
                        Err(e) => return Ok(Err(e)),
                    }
                }
            }
            Ok::<_, StepError>(Ok((cur, changed)))
        }
    };
    if let Some(cur) = current.filter(|c| c.base_id() == head.base && *c.generation == *head.generation)
        && cur.seq() < head.seq
        && (cur.seq() == 0 || head.deltas.iter().any(|d| d.seq == cur.seq()))
    {
        let res = apply_chain(VerdictSet::clone(cur), Some(cur.seq()), Some(Vec::new()))
            .await?
            .and_then(|(s, changed)| {
                let s = s.in_head(Arc::<str>::from(id));
                if s.checksum() == head.checksum {
                    Ok((s, changed.unwrap_or_default()))
                } else {
                    Err(VerdictLoadError::NeedBase("checksum after the chain".into()))
                }
            });
        match res {
            Ok((s, changed)) => return Ok((s, SetChange::Delta(changed))),
            Err(e) => tracing::info!(
                "verdict set {provider}: applying the new deltas failed ({e}); loading its base"
            ),
        }
    }
    // A new base: the page file to disk (verified by streaming BLAKE3), then the chain.
    let path = store::blob_path(root, Tree::Verdicts, provider, &head.base);
    store::ensure_page_file(edge, &path, &head.base, &store::blob_key(&head.base), None, false).await?;
    pages.register(&head.base, path, Owner::Provider(provider.into()));
    let (hid, h2, rd) = (Arc::<str>::from(id), head.clone(), Arc::clone(&reader));
    let base = tokio::task::spawn_blocking(move || {
        let mut hdr = [0u8; PAGE_SIZE];
        rd.read_page(&h2.base, 0, &mut hdr)
            .map_err(|e| VerdictLoadError::Mismatch(format!("base header: {e}")))?;
        VerdictSet::load(hid, &h2, &hdr)
    })
    .await
    .map_err(|e| StepError::retry("load", crate::diag::cap(e)))?;
    let res = match base {
        Ok(s) => apply_chain(s, None, None).await?.map(|(s, _)| s),
        Err(e) => Err(e),
    }
    .and_then(|s| {
        if s.checksum() == head.checksum {
            Ok(s)
        } else {
            Err(VerdictLoadError::NeedBase("checksum after the chain".into()))
        }
    });
    match res {
        Ok(s) => Ok((s, SetChange::Base)),
        Err(e) => Err(StepError::retry("load", format!("verdict set {provider}: {e}"))),
    }
}

impl SetAdapter {
    pub fn new(
        set: Arc<VerdictSet>,
        pages: Arc<FilePages>,
        clock: Arc<Clock>,
        refetch: tokio::sync::mpsc::Sender<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            set,
            pages,
            clock,
            refetch,
        })
    }
}

/// Attaches `active` to `client`: a delta drops the RAM entries it supersedes, a new base checks
/// every RAM entry against the set (page reads, in a blocking thread).
pub async fn attach(
    client: Arc<picket_lookup::LookupClient>,
    active: &ActiveSet,
    change: SetChange,
    pages: Arc<FilePages>,
) {
    let adapter: Arc<dyn picket_lookup::VerdictSet> = active.adapter.clone();
    match change {
        SetChange::Delta(changed) => {
            let seed_set = Arc::clone(&active.set);
            let _ = client.activate_set_delta(adapter, move |n| seed_set.hash(n).0, changed);
        }
        SetChange::Base => {
            let set = Arc::clone(&active.set);
            let _ = tokio::task::spawn_blocking(move || {
                client.activate_set_base(adapter, |name| {
                    set.lookup(name, &*pages).ok().flatten().map(|r| r.obtained_at)
                })
            })
            .await;
        }
    }
}
