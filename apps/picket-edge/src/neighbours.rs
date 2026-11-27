//! The neighbour watch (edge.md §1, §5 Devices): every IPv4 and IPv6 address the gateway's
//! neighbour table holds for one MAC (on-link only), from an unprivileged rtnetlink dump plus the
//! `RTNLGRP_NEIGH` multicast group (RTM_NEWNEIGH / RTM_DELNEIGH). The maps sit behind `ArcSwap`;
//! subscribers hear when a MAC gains an address (temporary allows, [`crate::bypass`], and the
//! firewall's backfill, [`crate::firewall`], use it). Without netlink (a sandbox, a container) the maps stay empty and devices fall back
//! to addresses; the watch retries every few minutes.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::Duration;

use arc_swap::ArcSwap;
use futures_util::StreamExt;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use rtnetlink::packet_core::NetlinkPayload;
use tokio::sync::broadcast;

/// A MAC address.
pub type Mac = [u8; 6];

/// Most addresses tracked.
pub const MAX_ADDRESSES: usize = 65_536;
/// Full re-dump period (resynchronises after a missed multicast message).
const RESYNC: Duration = Duration::from_secs(300);
/// How long a full dump may take.
const DUMP_TIMEOUT: Duration = Duration::from_secs(30);

/// `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(m: &Mac) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Parses `aa:bb:cc:dd:ee:ff` (any case).
pub fn parse_mac(s: &str) -> Option<Mac> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return None;
        }
        m[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(m)
}

/// The neighbour maps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NeighbourMap {
    pub by_mac: HashMap<Mac, BTreeSet<IpAddr>>,
    pub by_ip: HashMap<IpAddr, Mac>,
}

/// One change to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Upsert { ip: IpAddr, mac: Mac },
    Remove { ip: IpAddr },
}

/// What subscribers hear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighbourEvent {
    Gained { mac: Mac, ip: IpAddr },
    Lost { mac: Mac, ip: IpAddr },
}

pub struct Neighbours {
    map: ArcSwap<NeighbourMap>,
    events: broadcast::Sender<NeighbourEvent>,
    available: AtomicBool,
}

impl Neighbours {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            map: ArcSwap::from_pointee(NeighbourMap::default()),
            events: broadcast::channel(1024).0,
            available: AtomicBool::new(false),
        })
    }

    pub fn snapshot(&self) -> Arc<NeighbourMap> {
        self.map.load_full()
    }

    /// The MAC an address belongs to. An IPv4-mapped IPv6 address (how a dual-stack listener
    /// sees an IPv4 client) is looked up as IPv4.
    pub fn mac_of(&self, ip: &IpAddr) -> Option<Mac> {
        self.map.load().by_ip.get(&ip.to_canonical()).copied()
    }

    pub fn addresses_of(&self, mac: &Mac) -> Vec<IpAddr> {
        self.map
            .load()
            .by_mac
            .get(mac)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Whether the netlink watch is running.
    pub fn available(&self) -> bool {
        self.available.load(Relaxed)
    }

    /// Changes as they happen (a lagging subscriber misses some; it can re-read the map).
    pub fn subscribe(&self) -> broadcast::Receiver<NeighbourEvent> {
        self.events.subscribe()
    }

    /// Applies incremental changes.
    pub fn apply(&self, changes: &[Change]) {
        if changes.is_empty() {
            return;
        }
        let mut next = NeighbourMap::clone(&self.map.load());
        let mut events = vec![];
        for c in changes {
            apply_one(&mut next, *c, &mut events);
        }
        self.map.store(Arc::new(next));
        for e in events {
            let _ = self.events.send(e);
        }
    }

    /// Replaces the whole table with a dump, announcing the differences.
    pub fn replace(&self, entries: &[(IpAddr, Mac)]) {
        let cur = self.map.load_full();
        let mut next = NeighbourMap::default();
        let mut events = vec![];
        for (ip, mac) in entries.iter().take(MAX_ADDRESSES) {
            let ip = ip.to_canonical();
            next.by_ip.insert(ip, *mac);
            next.by_mac.entry(*mac).or_default().insert(ip);
        }
        for (ip, mac) in &next.by_ip {
            if cur.by_ip.get(ip) != Some(mac) {
                events.push(NeighbourEvent::Gained { mac: *mac, ip: *ip });
            }
        }
        for (ip, mac) in &cur.by_ip {
            if next.by_ip.get(ip) != Some(mac) {
                events.push(NeighbourEvent::Lost { mac: *mac, ip: *ip });
            }
        }
        self.map.store(Arc::new(next));
        for e in events {
            let _ = self.events.send(e);
        }
    }

    /// Dumps and follows the neighbour table; retries every 5 minutes where netlink isn't
    /// available. The warning repeats only after the watch had worked in between.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let mut warned = false;
        loop {
            match self.watch().await {
                Ok(()) => {}
                Err(e) => {
                    if self.available.swap(false, Relaxed) {
                        warned = false;
                    }
                    if !warned {
                        tracing::warn!(
                            "neighbour table unavailable ({}); devices fall back to addresses",
                            crate::diag::cap_chain(&e)
                        );
                        warned = true;
                    }
                }
            }
            tokio::time::sleep(RESYNC).await;
        }
    }

    async fn watch(&self) -> anyhow::Result<()> {
        use rtnetlink::MulticastGroup;
        let (conn, handle, mut messages) = rtnetlink::new_multicast_connection(&[MulticastGroup::Neigh])?;
        let conn_task = tokio::spawn(conn);
        let _guard = AbortOnDrop(conn_task);
        self.dump(&handle).await?;
        self.available.store(true, Relaxed);
        let mut resync = tokio::time::interval_at(tokio::time::Instant::now() + RESYNC, RESYNC);
        loop {
            tokio::select! {
                m = messages.next() => {
                    let Some((msg, _)) = m else { anyhow::bail!("netlink connection closed") };
                    let mut changes = vec![];
                    push_change(&mut changes, msg.payload);
                    // Batch whatever else is queued, then swap once.
                    while changes.len() < 4096 {
                        match tokio::time::timeout(Duration::ZERO, messages.next()).await {
                            Ok(Some((msg, _))) => push_change(&mut changes, msg.payload),
                            _ => break,
                        }
                    }
                    self.apply(&changes);
                }
                _ = resync.tick() => self.dump(&handle).await?,
            }
        }
    }

    async fn dump(&self, handle: &rtnetlink::Handle) -> anyhow::Result<()> {
        let mut stream = handle.neighbours().get().execute();
        let mut entries = vec![];
        let deadline = tokio::time::Instant::now() + DUMP_TIMEOUT;
        while let Some(m) = tokio::time::timeout_at(deadline, stream.next())
            .await
            .map_err(|_| anyhow::anyhow!("neighbour dump timed out"))?
        {
            let m = m?;
            if let Some(Change::Upsert { ip, mac }) = parse(&m, true) {
                entries.push((ip, mac));
            }
            if entries.len() >= MAX_ADDRESSES {
                break;
            }
        }
        self.replace(&entries);
        Ok(())
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn push_change(out: &mut Vec<Change>, payload: NetlinkPayload<RouteNetlinkMessage>) {
    match payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(m)) => out.extend(parse(&m, true)),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(m)) => out.extend(parse(&m, false)),
        _ => {}
    }
}

/// A neighbour message as a change: an on-link entry with a unicast MAC in a usable state is an
/// upsert; a deleted, failed, incomplete or unresolved (`NOARP`, `NONE`) one, or one without a
/// usable MAC, removes the address. Proxy entries (the gateway answering for another host) and
/// loopback, multicast or unspecified addresses are no device's. IPv4-mapped IPv6 addresses are
/// stored as IPv4.
pub fn parse(m: &NeighbourMessage, new: bool) -> Option<Change> {
    if m.header.flags.contains(NeighbourFlags::Proxy) {
        return None;
    }
    let ip = m
        .attributes
        .iter()
        .find_map(|a| match a {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(v4)) => Some(IpAddr::V4(*v4)),
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(v6)) => Some(IpAddr::V6(*v6)),
            _ => None,
        })?
        .to_canonical();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return None;
    }
    let gone = !new
        || matches!(
            m.header.state,
            NeighbourState::Failed
                | NeighbourState::Incomplete
                | NeighbourState::Noarp
                | NeighbourState::None
        );
    if gone {
        return Some(Change::Remove { ip });
    }
    let mac: Option<Mac> = m.attributes.iter().find_map(|a| match a {
        NeighbourAttribute::LinkLayerAddress(b) => b.as_slice().try_into().ok(),
        _ => None,
    });
    match mac {
        Some(mac) if mac != [0; 6] && mac[0] & 1 == 0 => Some(Change::Upsert { ip, mac }),
        _ => Some(Change::Remove { ip }),
    }
}

fn apply_one(map: &mut NeighbourMap, c: Change, events: &mut Vec<NeighbourEvent>) {
    match c {
        Change::Upsert { ip, mac } => {
            let ip = ip.to_canonical();
            if map.by_ip.get(&ip) == Some(&mac) {
                return;
            }
            if map.by_ip.len() >= MAX_ADDRESSES && !map.by_ip.contains_key(&ip) {
                return;
            }
            if let Some(old) = map.by_ip.insert(ip, mac) {
                remove_from_mac(map, &old, &ip);
                events.push(NeighbourEvent::Lost { mac: old, ip });
            }
            map.by_mac.entry(mac).or_default().insert(ip);
            events.push(NeighbourEvent::Gained { mac, ip });
        }
        Change::Remove { ip } => {
            let ip = ip.to_canonical();
            if let Some(old) = map.by_ip.remove(&ip) {
                remove_from_mac(map, &old, &ip);
                events.push(NeighbourEvent::Lost { mac: old, ip });
            }
        }
    }
}

fn remove_from_mac(map: &mut NeighbourMap, mac: &Mac, ip: &IpAddr) {
    if let Some(set) = map.by_mac.get_mut(mac) {
        set.remove(ip);
        if set.is_empty() {
            map.by_mac.remove(mac);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::neighbour::NeighbourHeader;

    fn msg(ip: IpAddr, mac: Option<Mac>, state: NeighbourState) -> NeighbourMessage {
        let mut m = NeighbourMessage::default();
        m.header = NeighbourHeader {
            state,
            ..Default::default()
        };
        m.attributes.push(NeighbourAttribute::Destination(match ip {
            IpAddr::V4(v) => NeighbourAddress::Inet(v),
            IpAddr::V6(v) => NeighbourAddress::Inet6(v),
        }));
        if let Some(mac) = mac {
            m.attributes
                .push(NeighbourAttribute::LinkLayerAddress(mac.to_vec()));
        }
        m
    }

    #[test]
    fn maps_and_events() {
        let n = Neighbours::new();
        let mut rx = n.subscribe();
        let mac = parse_mac("aa:bb:cc:dd:ee:02").unwrap();
        let v4: IpAddr = "192.168.1.140".parse().unwrap();
        let v6: IpAddr = "fd00::140".parse().unwrap();
        let changes: Vec<Change> = [
            parse(&msg(v4, Some(mac), NeighbourState::Reachable), true),
            parse(&msg(v6, Some(mac), NeighbourState::Stale), true),
        ]
        .into_iter()
        .flatten()
        .collect();
        n.apply(&changes);
        assert_eq!(n.mac_of(&v4), Some(mac));
        assert_eq!(n.addresses_of(&mac).len(), 2);
        assert_eq!(rx.try_recv().unwrap(), NeighbourEvent::Gained { mac, ip: v4 });
        assert_eq!(rx.try_recv().unwrap(), NeighbourEvent::Gained { mac, ip: v6 });
        // A failed entry or a delete removes the address.
        n.apply(&[parse(&msg(v4, None, NeighbourState::Failed), true).unwrap()]);
        assert_eq!(n.mac_of(&v4), None);
        assert_eq!(rx.try_recv().unwrap(), NeighbourEvent::Lost { mac, ip: v4 });
        n.apply(&[parse(&msg(v6, Some(mac), NeighbourState::Reachable), false).unwrap()]);
        assert!(n.addresses_of(&mac).is_empty());
        // A multicast or zero MAC is no device's: the address goes.
        assert_eq!(
            parse(
                &msg(v4, Some([1, 0, 0x5e, 0, 0, 1]), NeighbourState::Reachable),
                true
            ),
            Some(Change::Remove { ip: v4 })
        );
        assert_eq!(
            parse(&msg(v4, Some([0; 6]), NeighbourState::Reachable), true),
            Some(Change::Remove { ip: v4 })
        );
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:02");
    }

    #[test]
    fn mapped_addresses_proxies_and_unusable_entries() {
        let n = Neighbours::new();
        let mac = parse_mac("aa:bb:cc:dd:ee:02").unwrap();
        let v4: IpAddr = "192.168.1.140".parse().unwrap();
        n.apply(&[Change::Upsert { ip: v4, mac }]);
        // A dual-stack listener sees IPv4 clients as IPv4-mapped IPv6 addresses.
        let mapped: IpAddr = "::ffff:192.168.1.140".parse().unwrap();
        assert_eq!(n.mac_of(&mapped), Some(mac));
        assert_eq!(
            parse(&msg(mapped, Some(mac), NeighbourState::Reachable), true),
            Some(Change::Upsert { ip: v4, mac })
        );
        // A proxy entry answers for another host: not an on-link device.
        let mut proxy = msg(v4, Some(mac), NeighbourState::Reachable);
        proxy.header.flags = NeighbourFlags::Proxy;
        assert_eq!(parse(&proxy, true), None);
        // Loopback, multicast and unspecified addresses are nobody's.
        for ip in ["127.0.0.1", "ff02::1", "0.0.0.0", "::"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(
                parse(&msg(ip, Some(mac), NeighbourState::Reachable), true),
                None,
                "{ip}"
            );
        }
        // An entry that isn't (or is no longer) resolved on the link removes the address.
        for st in [NeighbourState::Noarp, NeighbourState::None] {
            assert_eq!(
                parse(&msg(v4, Some(mac), st), true),
                Some(Change::Remove { ip: v4 })
            );
        }
        assert_eq!(
            parse(&msg(v4, None, NeighbourState::Stale), true),
            Some(Change::Remove { ip: v4 }),
            "no usable MAC any more"
        );
    }

    #[test]
    fn replace_diffs_the_table() {
        let n = Neighbours::new();
        let a: Mac = [2, 0, 0, 0, 0, 1];
        let b: Mac = [2, 0, 0, 0, 0, 2];
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        n.replace(&[(ip1, a)]);
        let mut rx = n.subscribe();
        n.replace(&[(ip1, b), (ip2, b)]);
        let evs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(evs.contains(&NeighbourEvent::Gained { mac: b, ip: ip1 }));
        assert!(evs.contains(&NeighbourEvent::Gained { mac: b, ip: ip2 }));
        assert!(evs.contains(&NeighbourEvent::Lost { mac: a, ip: ip1 }));
        assert_eq!(n.addresses_of(&b).len(), 2);
    }
}
