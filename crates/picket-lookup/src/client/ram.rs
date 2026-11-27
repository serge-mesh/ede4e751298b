//! The edge's RAM tier (edge.md §10, providers.md §4 "Verdict cache"): S3-FIFO (`quick_cache`)
//! with a byte weigher, at most `cache.max_mib`. Each entry holds the result, `obtained_at`, the
//! `cache_generation` it was obtained under and the flush epoch; expiry is computed at each read
//! from the provider's current TTLs, so an edited TTL applies at once. Hits don't extend it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use picket_api::edge_config::VerdictCacheSettings;
use picket_api::time::Timestamp;
use quick_cache::sync::Cache;
use quick_cache::{DefaultHashBuilder, Lifecycle, Weighter};
use tokio::time::Instant;

use super::outcome::{ErrorKind, StoredVerdict};

/// The TTL cap (providers.md §4): 30 days.
pub const TTL_CAP: Duration = Duration::from_secs(30 * 86_400);
/// A hard cap on `cache.max_mib` (README §2 "Bounded", "Untrusted input": core is untrusted as
/// the edge sees it). 32 times the default of 2 MiB and 4 times an edge's default
/// `verdict_budget_mib` (core.md §4), so no config core means is refused, while a broken or
/// hostile one can't size one provider's tier past it.
pub const MAX_RAM_MIB: u32 = 64;
/// Bytes per entry beyond its key and value: the cache's slot, hash and queue bookkeeping.
const ENTRY_OVERHEAD: usize = 48;

/// What an entry holds.
#[derive(Clone, Debug, PartialEq)]
pub enum RamResult {
    Verdict(StoredVerdict),
    /// An error from a call, cached for `error_ttl_s` (edge only).
    Error(ErrorKind),
}

#[derive(Clone, Debug)]
pub(crate) struct RamEntry {
    pub result: RamResult,
    /// When the provider answered (wall clock, for logs and verdict-set activation).
    pub obtained_at: Timestamp,
    /// The same moment on the monotonic clock, for expiry.
    pub obtained_mono: Instant,
    pub gen_key: u64,
    pub epoch: u64,
}

/// The TTL of a result under the current settings, capped at 30 days.
pub fn ttl_for(c: &VerdictCacheSettings, result: &RamResult) -> Duration {
    let s = match result {
        RamResult::Verdict(StoredVerdict::Block { .. }) => c.block_ttl_s,
        RamResult::Verdict(StoredVerdict::Clean) => c.clean_ttl_s,
        RamResult::Verdict(StoredVerdict::Unknown) => c.unknown_ttl_s,
        RamResult::Error(_) => c.error_ttl_s,
    };
    Duration::from_secs(u64::from(s)).min(TTL_CAP)
}

#[derive(Clone, Copy, Debug, Default)]
struct ByteWeighter;

impl Weighter<Box<str>, RamEntry> for ByteWeighter {
    fn weight(&self, key: &Box<str>, val: &RamEntry) -> u64 {
        let reason = match &val.result {
            RamResult::Verdict(StoredVerdict::Block { reason, .. }) => reason.len(),
            _ => 0,
        };
        let bytes = key
            .len()
            .saturating_add(std::mem::size_of::<RamEntry>())
            .saturating_add(reason)
            .saturating_add(ENTRY_OVERHEAD);
        u64::try_from(bytes).unwrap_or(u64::MAX).max(1)
    }
}

#[derive(Clone, Debug, Default)]
struct EvictionCounter(Arc<AtomicU64>);

impl Lifecycle<Box<str>, RamEntry> for EvictionCounter {
    type RequestState = ();

    fn on_evict(&self, _: &mut (), _: Box<str>, _: RamEntry) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// What a read found.
pub(crate) enum RamLookup {
    Verdict {
        verdict: StoredVerdict,
        obtained_at: Timestamp,
    },
    Error(ErrorKind),
    Miss,
}

pub(crate) struct RamTier {
    cache: Cache<Box<str>, RamEntry, ByteWeighter, DefaultHashBuilder, EvictionCounter>,
    evictions: Arc<AtomicU64>,
    capacity: AtomicU64,
}

/// `max_mib` in bytes, at most [`MAX_RAM_MIB`].
fn capacity_bytes(c: &VerdictCacheSettings) -> u64 {
    u64::from(c.max_mib.min(MAX_RAM_MIB)) * 1024 * 1024
}

impl RamTier {
    pub fn new(c: &VerdictCacheSettings) -> Self {
        let bytes = capacity_bytes(c);
        let evictions = Arc::new(AtomicU64::new(0));
        // An estimate for sizing the shards: ~128 bytes an entry.
        let items = usize::try_from(bytes / 128).unwrap_or(usize::MAX).max(64);
        let cache = Cache::with(
            items,
            bytes.max(1),
            ByteWeighter,
            DefaultHashBuilder::default(),
            EvictionCounter(evictions.clone()),
        );
        Self {
            cache,
            evictions,
            capacity: AtomicU64::new(bytes),
        }
    }

    /// Applies a new `max_mib` in place (evicting down to it).
    pub fn set_capacity(&self, c: &VerdictCacheSettings) {
        let bytes = capacity_bytes(c);
        if self.capacity.swap(bytes, Ordering::Relaxed) != bytes {
            self.cache.set_capacity(bytes.max(1));
            if bytes == 0 {
                self.cache.clear();
            }
        }
    }

    /// Reads `name`. Entries of another generation or flush epoch, and expired ones, are misses
    /// and are dropped.
    pub fn get(
        &self,
        name: &str,
        c: &VerdictCacheSettings,
        gen_key: u64,
        epoch: u64,
        now: Instant,
    ) -> RamLookup {
        let Some(e) = self.cache.get(name) else {
            return RamLookup::Miss;
        };
        let live = e.gen_key == gen_key && e.epoch == epoch && now < e.obtained_mono + ttl_for(c, &e.result);
        if !live {
            let stamp = e.obtained_mono;
            self.cache.remove_if(name, |v| v.obtained_mono == stamp);
            return RamLookup::Miss;
        }
        match e.result {
            RamResult::Verdict(verdict) => RamLookup::Verdict {
                verdict,
                obtained_at: e.obtained_at,
            },
            RamResult::Error(kind) => RamLookup::Error(kind),
        }
    }

    /// Stores a result; a TTL of 0 stores nothing (providers.md §4 "Expiry").
    pub fn insert(&self, name: &str, entry: RamEntry, c: &VerdictCacheSettings) {
        if ttl_for(c, &entry.result).is_zero() || self.capacity.load(Ordering::Relaxed) == 0 {
            return;
        }
        self.cache.insert(name.into(), entry);
    }

    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Verdict-set activation (edge.md §10): drops each entry whose name `held_at` says the new
    /// head holds a record for, obtained at or after the entry. Entries are read one at a time,
    /// each under its shard's read lock only for the copy, so `held_at` runs with no lock held
    /// (it may read a page) and lookups go on meanwhile; an entry replaced since it was read
    /// stays. Returns how many were dropped.
    pub fn drop_superseded(&self, mut held_at: impl FnMut(&str) -> Option<Timestamp>) -> usize {
        let mut drop = Vec::new();
        for (name, e) in self.cache.iter() {
            if held_at(&name).is_some_and(|at| e.obtained_at <= at) {
                drop.push((name, e.obtained_mono, e.obtained_at));
            }
        }
        drop.into_iter()
            .filter(|(name, mono, at)| {
                self.cache
                    .remove_if(&**name, |v| v.obtained_mono == *mono && v.obtained_at == *at)
                    .is_some()
            })
            .count()
    }

    /// The byte capacity in force.
    #[cfg(test)]
    pub fn capacity(&self) -> u64 {
        self.capacity.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> u64 {
        u64::try_from(self.cache.len()).unwrap_or(u64::MAX)
    }

    pub fn bytes(&self) -> u64 {
        self.cache.weight()
    }

    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }
}
