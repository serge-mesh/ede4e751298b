//! The DNS cache (edge.md §8): a byte-bounded S3-FIFO (`quick_cache` with a byte weigher,
//! default 8 MiB) of validated wire answers.
//!
//! - **Key:** (qname lowercase, qtype, qclass, upstream DO, CD, upstream group). The client's DO
//!   isn't in it, so one signed answer serves clients with and without DO. The group is its id
//!   plus its generation, which changes whenever the group's upstreams or their settings change
//!   ([`super::upstream::Group::generation`]), so answers from servers a config removed are never served
//!   or joined again (edge.md §6, §8, §13); they age out of the cache.
//! - **Value:** picket-wire's [`CacheValue`] (both encoded copies, TTL offsets, facts) plus the
//!   answer's `answer` log record, shared with every buffered `q` record that references it.
//! - Profile-independent: filtering runs per query. Negative answers cache per RFC 2308; answers
//!   that may not be cached (TC, EDE 3, other rcodes, TTL 0) aren't inserted.
//! - Expired entries stay until evicted or [`CacheSettings::stale_max_s`] past expiry, for
//!   optimistic serving and for stale answers when every upstream fails (RFC 8767).
//! - **Prefetch:** an entry with `prefetch_min_hits` hits served during its last 10 % of TTL is
//!   refreshed in the background.
//! - **Background refreshes** (prefetch, the optimistic refresh) run one at a time per entry
//!   ([`Entry::try_refresh`]); the flag clears when the refresh ends however it ends, so a failed
//!   or uncacheable refresh doesn't pin the entry (AdGuard Home's `cache_optimistic` refreshes
//!   on each stale serve, single-flighted per key).

use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool, AtomicU32,
    Ordering::{AcqRel, Relaxed, Release},
};
use std::time::Instant;

use arc_swap::ArcSwap;
use quick_cache::{Equivalent, Weighter};
use smallvec::SmallVec;

use picket_api::edge_config::CacheSettings;
use picket_wire::{CacheValue, NameRef};

use crate::logs::{Answer, AnswerSlot};

/// The cache key (edge.md §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheKey {
    /// Lowercase wire name.
    pub name: SmallVec<[u8; 32]>,
    pub qtype: u16,
    pub qclass: u16,
    pub do_up: bool,
    pub cd: bool,
    pub group: Arc<str>,
    /// The group's generation.
    pub generation: u64,
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, h: &mut H) {
        KeyRef {
            name: &self.name,
            qtype: self.qtype,
            qclass: self.qclass,
            do_up: self.do_up,
            cd: self.cd,
            group: &self.group,
            generation: self.generation,
        }
        .hash(h)
    }
}

/// A borrowed key: looks entries up without building an owned key (no allocation).
#[derive(Clone, Copy, Debug)]
pub struct KeyRef<'a> {
    pub name: &'a [u8],
    pub qtype: u16,
    pub qclass: u16,
    pub do_up: bool,
    pub cd: bool,
    pub group: &'a str,
    pub generation: u64,
}

impl Hash for KeyRef<'_> {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.name.hash(h);
        self.qtype.hash(h);
        self.qclass.hash(h);
        self.do_up.hash(h);
        self.cd.hash(h);
        self.group.hash(h);
        self.generation.hash(h);
    }
}

impl Equivalent<CacheKey> for KeyRef<'_> {
    fn equivalent(&self, k: &CacheKey) -> bool {
        self.qtype == k.qtype
            && self.qclass == k.qclass
            && self.do_up == k.do_up
            && self.cd == k.cd
            && self.generation == k.generation
            && self.name == k.name.as_slice()
            && self.group == &*k.group
    }
}

impl<'a> KeyRef<'a> {
    pub fn new(
        name: NameRef<'a>,
        qtype: u16,
        qclass: u16,
        do_up: bool,
        cd: bool,
        group: &'a str,
        generation: u64,
    ) -> Self {
        Self {
            name: name.wire(),
            qtype,
            qclass,
            do_up,
            cd,
            group,
            generation,
        }
    }

    pub fn to_owned(&self) -> CacheKey {
        CacheKey {
            name: SmallVec::from_slice(self.name),
            qtype: self.qtype,
            qclass: self.qclass,
            do_up: self.do_up,
            cd: self.cd,
            group: self.group.into(),
            generation: self.generation,
        }
    }
}

/// One cached (or just fetched) upstream answer.
#[derive(Debug)]
pub struct Entry {
    pub value: CacheValue,
    /// The `answer` record, or `None` when it was over 4 KiB (never sent).
    pub answer: Option<Arc<Answer>>,
    pub upstream: Arc<str>,
    /// Hits served during the last 10 % of the TTL.
    late_hits: AtomicU32,
    /// A background refresh (prefetch or optimistic) of this entry is in flight.
    refreshing: AtomicBool,
    weight: u32,
}

impl Entry {
    pub fn new(value: CacheValue, upstream: Arc<str>) -> Self {
        let answer = Answer::new(bytes::Bytes::copy_from_slice(value.wire()));
        let weight = value
            .weight()
            .saturating_add(answer.as_ref().map_or(0, |a| a.wire.len() + 64))
            .saturating_add(std::mem::size_of::<Entry>());
        let weight = u32::try_from(weight).unwrap_or(u32::MAX);
        Self {
            value,
            answer,
            upstream,
            late_hits: AtomicU32::new(0),
            refreshing: AtomicBool::new(false),
            weight,
        }
    }

    /// What a `q` record carries for this answer.
    pub fn slot(&self) -> AnswerSlot {
        match &self.answer {
            Some(a) => AnswerSlot::Attached(Arc::clone(a)),
            None => AnswerSlot::Oversized,
        }
    }

    pub fn ttl(&self) -> u32 {
        self.value.ttl().unwrap_or(0)
    }

    /// Counts a hit served `elapsed` after the answer arrived; true when the entry is due for a
    /// prefetch: `min_hits` hits during the last 10 % of its TTL (edge.md §8). The caller then
    /// starts one with [`Self::try_refresh`].
    pub fn note_hit(&self, elapsed: std::time::Duration, min_hits: u32) -> bool {
        let ttl_ms = u128::from(self.ttl()) * 1000;
        if ttl_ms == 0 || elapsed.as_millis() * 10 < ttl_ms * 9 {
            return false;
        }
        let hits = self.late_hits.fetch_add(1, Relaxed).saturating_add(1);
        hits >= min_hits
    }

    /// Claims this entry's one background refresh slot; `None` while a refresh is in flight. The
    /// slot is given back when the guard drops, when the refresh ends.
    pub fn try_refresh(self: &Arc<Self>) -> Option<RefreshGuard> {
        (!self.refreshing.swap(true, AcqRel)).then(|| RefreshGuard(Arc::clone(self)))
    }
}

/// An entry's background refresh in flight ([`Entry::try_refresh`]).
#[derive(Debug)]
pub struct RefreshGuard(Arc<Entry>);

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.0.refreshing.store(false, Release);
    }
}

#[derive(Clone, Copy, Default)]
struct ByBytes;

impl Weighter<CacheKey, Arc<Entry>> for ByBytes {
    fn weight(&self, k: &CacheKey, v: &Arc<Entry>) -> u64 {
        u64::from(v.weight) + k.name.len() as u64 + k.group.len() as u64 + 64
    }
}

/// What a lookup found.
#[derive(Debug)]
pub enum Lookup {
    /// Within its TTL; `age` in whole seconds.
    Fresh {
        entry: Arc<Entry>,
        age: u32,
    },
    /// Past its TTL but within `stale_max`: servable optimistically or after failures.
    Expired {
        entry: Arc<Entry>,
        age: u32,
    },
    Miss,
}

/// The cache.
pub struct DnsCache {
    cache: quick_cache::sync::Cache<CacheKey, Arc<Entry>, ByBytes>,
    settings: ArcSwap<CacheSettings>,
}

const MIB: u64 = 1 << 20;

impl DnsCache {
    pub fn new(settings: CacheSettings) -> Self {
        let cap = u64::from(settings.size_mib.max(1)) * MIB;
        Self {
            cache: quick_cache::sync::Cache::with_weighter((cap / 1024) as usize, cap, ByBytes),
            settings: ArcSwap::from_pointee(settings),
        }
    }

    pub fn settings(&self) -> Arc<CacheSettings> {
        self.settings.load_full()
    }

    /// Applies new settings (the size is changed in place; entries stay).
    pub fn configure(&self, s: CacheSettings) {
        let old = self.settings.load();
        if old.size_mib != s.size_mib {
            self.cache.set_capacity(u64::from(s.size_mib.max(1)) * MIB);
        }
        self.settings.store(Arc::new(s));
    }

    pub fn get(&self, key: &KeyRef<'_>, now: Instant) -> Lookup {
        let Some(entry) = self.cache.get(key) else {
            return Lookup::Miss;
        };
        let age = entry.value.age_s(now);
        let ttl = entry.ttl();
        if age < ttl {
            return Lookup::Fresh { entry, age };
        }
        let stale_max = self.settings.load().stale_max_s;
        if u64::from(age) < u64::from(ttl) + u64::from(stale_max) {
            Lookup::Expired { entry, age }
        } else {
            self.cache.remove(key);
            Lookup::Miss
        }
    }

    /// Inserts an answer that may be cached (edge.md §8); others are ignored.
    pub fn insert(&self, key: CacheKey, entry: Arc<Entry>) {
        if entry.value.is_cacheable() {
            self.cache.insert(key, entry);
        }
    }

    /// `flush.dns`.
    pub fn flush(&self) {
        self.cache.clear();
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.len() == 0
    }

    pub fn weight(&self) -> u64 {
        self.cache.weight()
    }
}
