//! The firewall shadow map (edge-firewall.md §3): `FwKey → {dns_exp, allow_exp}` mirroring the
//! kernel's four timed sets; an entry expires at the later of the two. Times are whole seconds on
//! the edge's monotonic clock. Query tasks read it directly; only misses and refreshes go to the
//! helper.
//!
//! Besides the entries it keeps what the firewall rules need: each client's share of each set
//! (edge-firewall.md §2 "Share per client"), and each device's DNS grants (set, answer IP and
//! expiry, by MAC), so a new address for a known MAC gets the live entries backfilled and an
//! address that moves to another MAC loses the old device's entries. Grants are capped per device
//! and in total (README §2 Bounded).
//!
//! An entry is **unconfirmed** while the kernel may lack it: its set was recreated and the edge's
//! re-send isn't acked yet (edge-firewall.md §3 "Set being refilled"), or an `ensure` for it
//! failed (the helper was unreachable, say). Answers treat an unconfirmed key as absent: they send
//! `ensure` and wait for the ack, which confirms it.
//!
//! One mutex guards it: every operation is a handful of hash lookups, never held across an
//! await, and a poisoned lock is recovered (the map stays usable).

use std::collections::HashMap;
use std::net::IpAddr;

use picket_api::helper::sets;

use crate::neighbours::Mac;

/// One of the four timed sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SetId {
    P4,
    P6,
    G4,
    G6,
}

impl SetId {
    pub const ALL: [SetId; 4] = [SetId::P4, SetId::P6, SetId::G4, SetId::G6];

    pub fn name(self) -> &'static str {
        match self {
            SetId::P4 => sets::PICKET4,
            SetId::P6 => sets::PICKET6,
            SetId::G4 => sets::PICKET_G4,
            SetId::G6 => sets::PICKET_G6,
        }
    }

    pub fn from_name(s: &str) -> Option<SetId> {
        Self::ALL.into_iter().find(|x| x.name() == s)
    }

    pub fn index(self) -> usize {
        self as usize
    }

    /// The per-client set for an address family.
    pub fn pair(v4: bool) -> SetId {
        if v4 { SetId::P4 } else { SetId::P6 }
    }

    /// The global set for an address family.
    pub fn global(v4: bool) -> SetId {
        if v4 { SetId::G4 } else { SetId::G6 }
    }

    pub fn is_pair(self) -> bool {
        matches!(self, SetId::P4 | SetId::P6)
    }
}

/// One kernel entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FwKey {
    pub set: SetId,
    pub src: Option<IpAddr>,
    pub dst: IpAddr,
}

impl FwKey {
    pub fn entry(&self, timeout_s: u32) -> picket_api::helper::SetEntry {
        picket_api::helper::SetEntry {
            set: self.set.name().to_owned(),
            src: self.src,
            dst: self.dst,
            timeout_s,
        }
    }
}

/// What the edge believes the kernel holds for a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Expiry from DNS answers (seconds, monotonic).
    pub dns_exp: u64,
    /// Expiry from a temporary IP allow (0: none).
    pub allow_exp: u64,
    /// The client whose share the key counts against.
    pub owner: u64,
    /// When the edge last changed it (the reconcile ignores keys changed after its dump began);
    /// 0 for an entry seeded from the kernel.
    pub changed: u32,
    /// The kernel may lack it: answers send `ensure` and wait until one is acked.
    pub unconfirmed: bool,
}

impl Entry {
    pub fn exp(&self) -> u64 {
        self.dns_exp.max(self.allow_exp)
    }
}

/// The map.
#[derive(Debug, Default)]
pub struct Shadow {
    pub map: HashMap<FwKey, Entry>,
    /// Live keys per (owner, set).
    share: HashMap<(u64, SetId), u32>,
    /// Keys per set.
    fill: [u32; 4],
    /// Per device (MAC): its DNS grants, (set, answer IP) → expiry.
    grants: HashMap<Mac, HashMap<(SetId, IpAddr), u64>>,
    /// Grants held, all devices together.
    grant_count: usize,
    /// Keys an answer's `ensure` is out for that the map doesn't hold yet, per (owner, set) and
    /// per set: they count against the client's share and the set's room until their ack (or
    /// failure) settles them, so answers arriving meanwhile can't overrun either (edge-firewall.md
    /// §2 "Share per client").
    pending: HashMap<(u64, SetId), u32>,
    pending_fill: [u32; 4],
}

/// Most devices whose grants are tracked (README §2 Bounded).
pub const MAX_GRANT_DEVICES: usize = 65_536;
/// Most grants one device holds: its share of both pair sets (a grant is at least one live key
/// in its share).
pub const MAX_GRANTS_PER_DEVICE: usize = 2 * (sets::MAXELEM as usize / 4);
/// Most grants held in total: what both pair sets can hold.
pub const MAX_GRANTS: usize = 2 * sets::MAXELEM as usize;

/// `now` as an entry's `changed` (seconds since the client started, which never reach u32::MAX
/// in practice; saturating).
fn stamp(now: u64) -> u32 {
    u32::try_from(now).unwrap_or(u32::MAX)
}

impl Shadow {
    pub fn get(&self, k: &FwKey) -> Option<&Entry> {
        self.map.get(k)
    }

    /// The live entry for `k` at `now` (an expired one is absent).
    pub fn live(&self, k: &FwKey, now: u64) -> Option<&Entry> {
        self.map.get(k).filter(|e| e.exp() > now)
    }

    pub fn fill(&self, s: SetId) -> u32 {
        self.fill[s.index()]
    }

    pub fn share_of(&self, owner: u64, s: SetId) -> u32 {
        self.share.get(&(owner, s)).copied().unwrap_or(0)
    }

    /// Whether `owner` may add `n` keys to `set`: within its share and the set's `maxelem`,
    /// counting the keys still waiting for their ack (edge-firewall.md §2).
    pub fn room(&self, owner: u64, set: SetId, n: u32) -> bool {
        let share = self
            .share_of(owner, set)
            .saturating_add(self.pending.get(&(owner, set)).copied().unwrap_or(0));
        let fill = self.fill(set).saturating_add(self.pending_fill[set.index()]);
        share.saturating_add(n) <= super::SHARE && fill.saturating_add(n) <= sets::MAXELEM
    }

    /// Counts a key whose `ensure` is going out against `owner`'s share and the set's room.
    pub fn reserve(&mut self, owner: u64, set: SetId) {
        *self.pending.entry((owner, set)).or_default() += 1;
        self.pending_fill[set.index()] += 1;
    }

    /// Ends a [`Shadow::reserve`]: the key's `ensure` was acked (the map counts it now) or failed.
    pub fn release(&mut self, owner: u64, set: SetId) {
        if let Some(n) = self.pending.get_mut(&(owner, set)) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.pending.remove(&(owner, set));
            }
        }
        self.pending_fill[set.index()] = self.pending_fill[set.index()].saturating_sub(1);
    }

    /// Keys reserved and not yet settled, for `owner` in `set` (tests).
    pub fn pending_of(&self, owner: u64, set: SetId) -> u32 {
        self.pending.get(&(owner, set)).copied().unwrap_or(0)
    }

    /// Inserts or updates `k`. Returns true when it was new (absent or expired). An expired
    /// entry taken up again is confirmed (the caller sends or has sent its `ensure`).
    pub fn upsert(&mut self, k: FwKey, dns_exp: u64, allow_exp: Option<u64>, owner: u64, now: u64) -> bool {
        match self.map.get_mut(&k) {
            Some(e) => {
                let was_live = e.exp() > now;
                if !was_live {
                    e.unconfirmed = false;
                }
                e.dns_exp = e.dns_exp.max(dns_exp);
                if let Some(a) = allow_exp {
                    e.allow_exp = a;
                }
                e.changed = stamp(now);
                let prev_owner = e.owner;
                if !was_live && prev_owner != owner {
                    e.owner = owner;
                    self.dec_share(prev_owner, k.set);
                    *self.share.entry((owner, k.set)).or_default() += 1;
                }
                !was_live
            }
            None => {
                self.map.insert(
                    k,
                    Entry {
                        dns_exp,
                        allow_exp: allow_exp.unwrap_or(0),
                        owner,
                        changed: stamp(now),
                        unconfirmed: false,
                    },
                );
                self.fill[k.set.index()] += 1;
                *self.share.entry((owner, k.set)).or_default() += 1;
                true
            }
        }
    }

    /// Sets a key's expiries outright (the reconcile and allow changes).
    pub fn set_exps(&mut self, k: &FwKey, dns_exp: u64, allow_exp: u64, now: u64) {
        if let Some(e) = self.map.get_mut(k) {
            e.dns_exp = dns_exp;
            e.allow_exp = allow_exp;
            e.changed = stamp(now);
        }
    }

    /// An `ensure` for `k` was acked: the kernel holds it.
    pub fn confirm(&mut self, k: &FwKey) {
        if let Some(e) = self.map.get_mut(k) {
            e.unconfirmed = false;
        }
    }

    /// The kernel may lack `k` (its set was recreated, or an `ensure` for it failed).
    pub fn unconfirm(&mut self, k: &FwKey) {
        if let Some(e) = self.map.get_mut(k) {
            e.unconfirmed = true;
        }
    }

    /// Marks an entry as seeded from the kernel (not changed by the edge: the reconcile right
    /// after seeding compares it).
    pub fn mark_seeded(&mut self, k: &FwKey) {
        if let Some(e) = self.map.get_mut(k) {
            e.changed = 0;
        }
    }

    fn dec_share(&mut self, owner: u64, s: SetId) {
        if let Some(n) = self.share.get_mut(&(owner, s)) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.share.remove(&(owner, s));
            }
        }
    }

    /// Removes `k`.
    pub fn remove(&mut self, k: &FwKey) -> Option<Entry> {
        let e = self.map.remove(k)?;
        self.fill[k.set.index()] = self.fill[k.set.index()].saturating_sub(1);
        self.dec_share(e.owner, k.set);
        Some(e)
    }

    /// Drops entries and grants that expired at or before `now` (userspace prunes only its own
    /// map; expiry is the kernel's job). The firewall client passes a time a few seconds back, so
    /// an entry the kernel may still hold for its whole-second rounding stays known to the
    /// reconcile (edge-firewall.md §3).
    pub fn prune(&mut self, now: u64) {
        let dead: Vec<FwKey> = self
            .map
            .iter()
            .filter(|(_, e)| e.exp() <= now)
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            self.remove(&k);
        }
        let mut count = 0usize;
        self.grants.retain(|_, g| {
            g.retain(|_, exp| *exp > now);
            count += g.len();
            !g.is_empty()
        });
        self.grant_count = count;
    }

    /// Records a DNS grant for device `mac`. False when it doesn't fit (the device's or the
    /// total cap): the device's new addresses then don't get that grant backfilled.
    pub fn grant(&mut self, mac: Mac, set: SetId, dst: IpAddr, exp: u64) -> bool {
        if self.grants.len() >= MAX_GRANT_DEVICES && !self.grants.contains_key(&mac) {
            return false;
        }
        let total = self.grant_count;
        let g = self.grants.entry(mac).or_default();
        let fresh = !g.contains_key(&(set, dst));
        if fresh && (g.len() >= MAX_GRANTS_PER_DEVICE || total >= MAX_GRANTS) {
            if g.is_empty() {
                self.grants.remove(&mac);
            }
            return false;
        }
        let e = g.entry((set, dst)).or_insert(0);
        *e = (*e).max(exp);
        if fresh {
            self.grant_count += 1;
        }
        true
    }

    /// Grants held, all devices together (tests).
    pub fn grant_count(&self) -> usize {
        self.grant_count
    }

    /// The live grants of device `mac`.
    pub fn grants_of(&self, mac: &Mac, now: u64) -> Vec<(SetId, IpAddr, u64)> {
        self.grants
            .get(mac)
            .map(|g| {
                g.iter()
                    .filter(|(_, exp)| **exp > now)
                    .map(|((s, d), exp)| (*s, *d, *exp))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Live keys of `set`.
    pub fn live_keys(&self, set: SetId, now: u64) -> Vec<(FwKey, u64)> {
        self.map
            .iter()
            .filter(|(k, e)| k.set == set && e.exp() > now)
            .map(|(k, e)| (*k, e.exp()))
            .collect()
    }
}

/// A stable 64-bit id for a client's share (the device key's text).
pub fn owner_of(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(dst: &str) -> FwKey {
        FwKey {
            set: SetId::P4,
            src: Some("192.168.1.10".parse().unwrap()),
            dst: dst.parse().unwrap(),
        }
    }

    #[test]
    fn upsert_counts_shares_and_fill_and_prune_releases_them() {
        let mut s = Shadow::default();
        assert!(s.upsert(k("1.1.1.1"), 100, None, 7, 0));
        assert!(!s.upsert(k("1.1.1.1"), 50, None, 7, 1), "a live key isn't new");
        assert_eq!(s.get(&k("1.1.1.1")).unwrap().dns_exp, 100, "only ever extend");
        assert!(s.upsert(k("2.2.2.2"), 10, None, 7, 1));
        assert_eq!(s.share_of(7, SetId::P4), 2);
        assert_eq!(s.fill(SetId::P4), 2);
        s.prune(20);
        assert_eq!(s.share_of(7, SetId::P4), 1);
        assert_eq!(s.fill(SetId::P4), 1);
        assert!(s.live(&k("2.2.2.2"), 20).is_none());
        // An allow keeps a key alive past its DNS expiry.
        s.upsert(k("3.3.3.3"), 10, Some(500), 8, 20);
        assert_eq!(s.live(&k("3.3.3.3"), 200).unwrap().exp(), 500);
    }

    #[test]
    fn grants_are_capped_per_device() {
        let mut s = Shadow::default();
        let m = [1, 2, 3, 4, 5, 6];
        let mut n = 0usize;
        for i in 0..(MAX_GRANTS_PER_DEVICE as u32 + 10) {
            let dst = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            n += usize::from(s.grant(m, SetId::P4, dst, 100));
        }
        assert_eq!(n, MAX_GRANTS_PER_DEVICE);
        assert_eq!(s.grants_of(&m, 0).len(), MAX_GRANTS_PER_DEVICE);
        assert_eq!(s.grant_count(), MAX_GRANTS_PER_DEVICE);
        // An existing grant is still extended at the cap.
        assert!(s.grant(m, SetId::P4, "10.0.0.0".parse().unwrap(), 200));
        // Another device still gets its own.
        assert!(s.grant([9; 6], SetId::P4, "1.1.1.1".parse().unwrap(), 100));
        s.prune(150);
        assert_eq!(s.grant_count(), 1, "only the extended grant is left");
    }

    #[test]
    fn grants_are_per_device_and_expire() {
        let mut s = Shadow::default();
        let m = [1, 2, 3, 4, 5, 6];
        s.grant(m, SetId::P4, "1.1.1.1".parse().unwrap(), 100);
        s.grant(m, SetId::P4, "1.1.1.1".parse().unwrap(), 50);
        assert_eq!(
            s.grants_of(&m, 0),
            vec![(SetId::P4, "1.1.1.1".parse().unwrap(), 100)]
        );
        s.prune(100);
        assert!(s.grants_of(&m, 0).is_empty());
    }
}
