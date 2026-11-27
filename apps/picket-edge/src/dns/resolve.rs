//! Cache-or-upstream resolution (edge.md §6, §8): coalescing of identical in-flight queries
//! (qname, qtype, qclass, upstream DO, CD, group with its generation: the cache key), cache
//! inserts, prefetch and the optimistic refresh. A query never joins work started for an older
//! generation of its group (servers a config changed or removed).
//!
//! The coalesced work runs in a task of its own, so a client that goes away never cancels it for
//! the others; every waiter gets the same answer. Coalesced work never withholds an upstream's
//! stale (EDE 3) answer: each waiter that set DO retries on its own when it gets one (edge.md §7
//! step 3).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use tokio::sync::watch;

use picket_wire::{CacheValue, WireName};

use super::cache::{CacheKey, DnsCache, Entry, KeyRef, RefreshGuard};
use super::upstream::{Cause, Failure, ResolveRequest, UpstreamPool};

/// Most distinct coalesced resolutions at once; past it, queries resolve on their own.
pub const MAX_INFLIGHT: usize = 8192;

/// A fresh upstream answer.
#[derive(Debug)]
pub struct Fetched {
    pub entry: Arc<Entry>,
    pub rtt_ms: u32,
}

pub type FetchResult = Result<Arc<Fetched>, Failure>;

/// The resolver.
pub struct Resolver {
    pub cache: DnsCache,
    pub pool: Arc<UpstreamPool>,
    inflight: Mutex<HashMap<CacheKey, watch::Receiver<Option<FetchResult>>>>,
}

impl Resolver {
    pub fn new(cache: DnsCache, pool: Arc<UpstreamPool>) -> Arc<Self> {
        Arc::new(Self {
            cache,
            pool,
            inflight: Mutex::new(HashMap::new()),
        })
    }

    fn request(key: &CacheKey, exclude: Option<Arc<str>>, reject_stale: bool) -> ResolveRequest {
        ResolveRequest {
            group: Arc::clone(&key.group),
            qname: name_of(key).unwrap_or_else(WireName::root),
            qtype: key.qtype,
            qclass: key.qclass,
            do_up: key.do_up,
            cd: key.cd,
            exclude,
            reject_stale,
        }
    }

    async fn run(
        self: &Arc<Self>,
        key: &CacheKey,
        exclude: Option<Arc<str>>,
        reject_stale: bool,
    ) -> FetchResult {
        let req = Self::request(key, exclude, reject_stale);
        let r = self.pool.resolve(&req).await?;
        let value = CacheValue::new(r.answer, SystemTime::now(), Instant::now());
        let entry = Arc::new(Entry::new(value, r.upstream));
        self.cache.insert(key.clone(), Arc::clone(&entry));
        Ok(Arc::new(Fetched {
            entry,
            rtt_ms: u32::try_from(r.rtt.as_millis()).unwrap_or(u32::MAX),
        }))
    }

    /// Resolves `key` upstream, joining identical work in flight.
    pub async fn fetch(self: &Arc<Self>, key: &KeyRef<'_>) -> FetchResult {
        let owned = key.to_owned();
        enum Join {
            Wait(watch::Receiver<Option<FetchResult>>),
            Alone,
        }
        let join = {
            let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(rx) = map.get(&owned) {
                Join::Wait(rx.clone())
            } else if map.len() >= MAX_INFLIGHT {
                Join::Alone
            } else {
                let (tx, rx) = watch::channel(None);
                map.insert(owned.clone(), rx.clone());
                let me = Arc::clone(self);
                let k = owned.clone();
                tokio::spawn(async move {
                    // Removed however the task ends, a panic included, so a key never stays
                    // stuck in flight.
                    struct Done(Arc<Resolver>, CacheKey);
                    impl Drop for Done {
                        fn drop(&mut self) {
                            self.0
                                .inflight
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .remove(&self.1);
                        }
                    }
                    let _done = Done(Arc::clone(&me), k.clone());
                    let r = me.run(&k, None, false).await;
                    let _ = tx.send(Some(r));
                });
                Join::Wait(rx)
            }
        };
        let mut rx = match join {
            Join::Alone => return self.run(&owned, None, false).await,
            Join::Wait(rx) => rx,
        };
        let r = rx.wait_for(|v| v.is_some()).await.ok().and_then(|v| v.clone());
        r.unwrap_or(Err(Failure {
            cause: Cause::Timeout,
        }))
    }

    /// Resolves on its own (not coalesced): a DO client retrying after a stale answer, away from
    /// the upstream that gave it, with stale answers failing their upstream.
    pub async fn fetch_fresh_only(self: &Arc<Self>, key: &KeyRef<'_>, exclude: Arc<str>) -> FetchResult {
        self.run(&key.to_owned(), Some(exclude), true).await
    }

    /// Refreshes `key` in the background (prefetch, optimistic refresh), holding the entry's
    /// refresh slot until the refresh ends, whatever its outcome (edge.md §8).
    pub fn refresh(self: &Arc<Self>, key: CacheKey, slot: RefreshGuard) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let _slot = slot;
            let k = KeyRef {
                name: &key.name,
                qtype: key.qtype,
                qclass: key.qclass,
                do_up: key.do_up,
                cd: key.cd,
                group: &key.group,
                generation: key.generation,
            };
            let _ = me.fetch(&k).await;
        });
    }
}

fn name_of(key: &CacheKey) -> Option<WireName> {
    // The key holds a name this crate wrote from a checked query or answer.
    let mut labels: smallvec::SmallVec<[&[u8]; 16]> = smallvec::SmallVec::new();
    let mut at = 0usize;
    loop {
        let len = usize::from(*key.name.get(at)?);
        if len == 0 {
            break;
        }
        labels.push(key.name.get(at + 1..at + 1 + len)?);
        at += 1 + len;
    }
    WireName::from_labels(labels).ok()
}
