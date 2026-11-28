//! State shared between the engine thread, the fast worker and the socket tasks: the helper's
//! current findings, the reject counters, and event delivery.
//!
//! Events are coalesced per subscriber instead of queued (README "Bounded"): a subscriber that
//! reads slowly gets the latest `conditions`, one merged `rules_repaired` (every missing object
//! and recreated set since it last read, the largest gap) and the set of sets that went full. A
//! lagging reader therefore never loses a `rules_repaired`, and its pending events take a few
//! KiB whatever happens.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use picket_api::helper::{ApplyResponse, Conditions, InterfaceMode, RulesRepaired, SetStatus};
use tokio::sync::{Notify, oneshot};

use crate::rules::Desired;

/// Longest `missing` list kept in one merged `rules_repaired`.
const MAX_MISSING: usize = 256;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere must not poison the helper's shared state.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The helper's current findings, as `hello` and `status` report them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub rules_ok: bool,
    pub conditions: Conditions,
    pub last_repair: Option<String>,
    pub interfaces: Vec<InterfaceMode>,
    /// The four timed sets' fill, from the last check.
    pub sets: Vec<SetStatus>,
    /// Steps that failed and are retried at the next re-assert.
    pub pending: Vec<String>,
}

/// Pending events of one subscriber.
#[derive(Debug, Default)]
pub struct Pending {
    pub conditions: Option<Conditions>,
    pub repaired: Option<RulesRepaired>,
    pub set_full: BTreeSet<String>,
}

impl Pending {
    pub fn is_empty(&self) -> bool {
        self.conditions.is_none() && self.repaired.is_none() && self.set_full.is_empty()
    }
}

/// One subscriber's mailbox.
#[derive(Debug, Default)]
pub struct Mailbox {
    pending: Mutex<Pending>,
    pub notify: Notify,
}

impl Mailbox {
    pub fn take(&self) -> Pending {
        std::mem::take(&mut *lock(&self.pending))
    }

    fn push_conditions(&self, c: &Conditions) {
        lock(&self.pending).conditions = Some(c.clone());
        self.notify.notify_one();
    }

    fn push_repaired(&self, r: &RulesRepaired) {
        {
            let mut p = lock(&self.pending);
            match &mut p.repaired {
                None => p.repaired = Some(r.clone()),
                Some(m) => {
                    for x in &r.missing {
                        if !m.missing.contains(x) && m.missing.len() < MAX_MISSING {
                            m.missing.push(x.clone());
                        }
                    }
                    for s in &r.recreated_sets {
                        if !m.recreated_sets.contains(s) {
                            m.recreated_sets.push(s.clone());
                        }
                    }
                    m.gap_ms = m.gap_ms.max(r.gap_ms);
                }
            }
        }
        self.notify.notify_one();
    }

    fn push_set_full(&self, set: &str) {
        lock(&self.pending).set_full.insert(set.to_string());
        self.notify.notify_one();
    }
}

/// Reject counter totals since the helper started, and each client's baseline.
#[derive(Debug, Default)]
pub struct Counters {
    rejects: u64,
    mon_rejects: u64,
    baselines: HashMap<u32, (u64, u64)>,
}

/// Most clients whose baseline is kept (the edge's UID and root, in practice).
const MAX_BASELINES: usize = 16;

impl Counters {
    pub fn add(&mut self, rejects: u64, mon_rejects: u64) {
        self.rejects = self.rejects.saturating_add(rejects);
        self.mon_rejects = self.mon_rejects.saturating_add(mon_rejects);
    }

    /// Growth since this client's previous `status` (the first counts from the helper's start),
    /// keyed by the peer's UID so a reconnecting edge loses nothing in between.
    pub fn take_growth(&mut self, uid: u32) -> (u64, u64) {
        let now = (self.rejects, self.mon_rejects);
        if !self.baselines.contains_key(&uid) && self.baselines.len() >= MAX_BASELINES {
            self.baselines.clear();
        }
        let prev = self.baselines.insert(uid, now).unwrap_or((0, 0));
        (now.0.saturating_sub(prev.0), now.1.saturating_sub(prev.1))
    }
}

#[derive(Debug, Default)]
pub struct Shared {
    snapshot: Mutex<Snapshot>,
    subscribers: Mutex<Vec<Arc<Mailbox>>>,
    pub counters: Mutex<Counters>,
    /// Monotonic seconds (backend clock) at which the engine last finished a pass.
    pub engine_beat: AtomicU64,
    pending_apply: Mutex<Option<PendingApply>>,
}

/// A socket `apply` waiting for the engine. An `apply` replaces the whole desired state, so a
/// newer one supersedes a waiting one, and every waiting caller gets the answer of the apply
/// that ran. However many applies arrive while the engine is busy, at most one decoded
/// payload waits; a slow engine never answers `busy` to an edge re-applying after a timeout.
#[derive(Debug)]
pub struct PendingApply {
    pub desired: Box<Desired>,
    pub waiters: Vec<oneshot::Sender<ApplyResponse>>,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Leaves `desired` for the engine, replacing (and freeing) any apply still waiting. True
    /// when none was waiting, so the engine needs a wake.
    pub fn put_apply(&self, desired: Box<Desired>, tx: oneshot::Sender<ApplyResponse>) -> bool {
        let mut slot = lock(&self.pending_apply);
        match slot.as_mut() {
            Some(p) => {
                p.desired = desired;
                // Callers that timed out or disconnected no longer need an answer.
                p.waiters.retain(|w| !w.is_closed());
                p.waiters.push(tx);
                false
            }
            None => {
                *slot = Some(PendingApply {
                    desired,
                    waiters: vec![tx],
                });
                true
            }
        }
    }

    /// How many callers wait on the waiting apply.
    #[cfg(test)]
    pub fn apply_waiters(&self) -> usize {
        lock(&self.pending_apply).as_ref().map_or(0, |p| p.waiters.len())
    }

    /// The waiting apply, if any (the engine thread).
    pub fn take_apply(&self) -> Option<PendingApply> {
        lock(&self.pending_apply).take()
    }

    pub fn snapshot(&self) -> Snapshot {
        lock(&self.snapshot).clone()
    }

    pub fn update(&self, f: impl FnOnce(&mut Snapshot)) {
        f(&mut lock(&self.snapshot));
    }

    pub fn subscribe(&self) -> Arc<Mailbox> {
        let m = Arc::new(Mailbox::default());
        lock(&self.subscribers).push(m.clone());
        m
    }

    pub fn unsubscribe(&self, m: &Arc<Mailbox>) {
        lock(&self.subscribers).retain(|x| !Arc::ptr_eq(x, m));
    }

    pub fn subscriber_count(&self) -> usize {
        lock(&self.subscribers).len()
    }

    pub fn publish_conditions(&self, c: &Conditions) {
        for m in lock(&self.subscribers).iter() {
            m.push_conditions(c);
        }
    }

    pub fn publish_repaired(&self, r: &RulesRepaired) {
        for m in lock(&self.subscribers).iter() {
            m.push_repaired(r);
        }
    }

    pub fn publish_set_full(&self, set: &str) {
        for m in lock(&self.subscribers).iter() {
            m.push_set_full(set);
        }
    }

    pub fn beat(&self, mono_secs: u64) {
        self.engine_beat.store(mono_secs, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lagging_subscriber_gets_merged_repairs() {
        let s = Shared::new();
        let m = s.subscribe();
        for i in 0..1000 {
            s.publish_repaired(&RulesRepaired {
                missing: vec![format!("jump4:br{}", i % 3)],
                gap_ms: i,
                recreated_sets: if i == 10 { vec!["picket4".into()] } else { vec![] },
            });
            s.publish_conditions(&Conditions {
                helper_disabled: i % 2 == 0,
                ..Default::default()
            });
        }
        let p = m.take();
        let r = p.repaired.unwrap();
        assert_eq!(r.missing.len(), 3);
        assert_eq!(r.recreated_sets, vec!["picket4".to_string()]);
        assert_eq!(r.gap_ms, 999);
        assert!(!p.conditions.unwrap().helper_disabled); // the latest
        assert!(m.take().is_empty());
    }

    #[test]
    fn growth_is_per_client_since_previous_status() {
        let mut c = Counters::default();
        c.add(10, 1);
        assert_eq!(c.take_growth(1000), (10, 1));
        c.add(5, 0);
        assert_eq!(c.take_growth(1000), (5, 0));
        assert_eq!(c.take_growth(0), (15, 1)); // root's first status: since start
        assert_eq!(c.take_growth(1000), (0, 0));
    }
}
