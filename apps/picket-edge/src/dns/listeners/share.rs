//! Per-source shares of what the stream listeners hold (README §2 "Bounded": where clients share
//! a capped resource, each gets a capped share; edge.md §5, §16, §17).
//!
//! - **Connections:** a source holds at most [`PER_SOURCE_CONNECTIONS`] connections across every
//!   TCP, DoT and DoH listener, counted from `accept`, so TLS handshakes count too; each listener
//!   also keeps its own `max_connections`.
//! - **DoH request bodies:** a source's bodies being read hold at most [`PER_SOURCE_BODY_BYTES`],
//!   and all sources together [`TOTAL_BODY_BYTES`]; a body that doesn't fit is refused.
//!
//! A source is a device as the pipeline keys it (edge.md §5: the MAC, the client of a routed
//! address, else the address), so one device's IPv6 privacy addresses share one share. The table
//! holds only sources with something open, so it is bounded by the connections themselves.
//! The numbers are policy choices (flagged for the owner).

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use crate::dns::profiles::DeviceKey;
use crate::edge::Edge;

/// Connections one source may hold across the stream listeners.
pub const PER_SOURCE_CONNECTIONS: u32 = 32;
/// Bytes of DoH request bodies one source may have in reading (16 messages of the DNS maximum,
/// or thousands of ordinary queries).
pub const PER_SOURCE_BODY_BYTES: usize = 1 << 20;
/// Bytes of DoH request bodies all sources together may have in reading.
pub const TOTAL_BODY_BYTES: usize = 16 << 20;
const SHARDS: usize = 16;

#[derive(Default)]
struct Usage {
    conns: u32,
    body: usize,
}

pub struct SourceShares {
    shards: Vec<Mutex<HashMap<DeviceKey, Usage>>>,
    hasher: std::collections::hash_map::RandomState,
    total_body: AtomicUsize,
    max_conns: u32,
    max_body: usize,
    max_total_body: usize,
}

impl SourceShares {
    pub fn new() -> Arc<Self> {
        Self::with_limits(PER_SOURCE_CONNECTIONS, PER_SOURCE_BODY_BYTES, TOTAL_BODY_BYTES)
    }

    pub fn with_limits(conns: u32, body: usize, total_body: usize) -> Arc<Self> {
        Arc::new(Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            hasher: Default::default(),
            total_body: AtomicUsize::new(0),
            max_conns: conns,
            max_body: body,
            max_total_body: total_body,
        })
    }

    fn shard(&self, k: &DeviceKey) -> std::sync::MutexGuard<'_, HashMap<DeviceKey, Usage>> {
        self.shards[usize::try_from(self.hasher.hash_one(k) % SHARDS as u64).unwrap_or(0)]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Takes one connection of `key`'s share, or `None` when it is used up.
    pub fn connect(self: &Arc<Self>, key: DeviceKey) -> Option<ConnShare> {
        let mut g = self.shard(&key);
        let u = g.entry(key.clone()).or_default();
        if u.conns >= self.max_conns {
            if u.conns == 0 && u.body == 0 {
                g.remove(&key);
            }
            return None;
        }
        u.conns += 1;
        drop(g);
        Some(ConnShare {
            shares: Arc::clone(self),
            key,
        })
    }

    /// An empty body charge for `key`, grown with [`BodyCharge::add`].
    pub fn body(self: &Arc<Self>, key: DeviceKey) -> BodyCharge {
        BodyCharge {
            shares: Arc::clone(self),
            key,
            bytes: 0,
        }
    }

    /// The connections `key` holds now.
    pub fn connections(&self, key: &DeviceKey) -> u32 {
        self.shard(key).get(key).map_or(0, |u| u.conns)
    }

    /// The body bytes all sources hold now.
    pub fn body_bytes(&self) -> usize {
        self.total_body.load(Relaxed)
    }

    fn release(&self, key: &DeviceKey, conns: u32, body: usize) {
        let mut g = self.shard(key);
        if let Some(u) = g.get_mut(key) {
            u.conns = u.conns.saturating_sub(conns);
            u.body = u.body.saturating_sub(body);
            if u.conns == 0 && u.body == 0 {
                g.remove(key);
            }
        }
        drop(g);
        if body > 0 {
            self.total_body.fetch_sub(body, Relaxed);
        }
    }
}

/// One connection of a source's share, given back on drop.
pub struct ConnShare {
    shares: Arc<SourceShares>,
    key: DeviceKey,
}

impl Drop for ConnShare {
    fn drop(&mut self) {
        self.shares.release(&self.key, 1, 0);
    }
}

/// The bytes of one request body being read, charged to its source and the total; given back on
/// drop.
pub struct BodyCharge {
    shares: Arc<SourceShares>,
    key: DeviceKey,
    bytes: usize,
}

impl BodyCharge {
    /// Charges `n` more bytes; false (charging nothing) when the source's share or the total
    /// would be exceeded.
    pub fn add(&mut self, n: usize) -> bool {
        let s = &self.shares;
        if s.total_body
            .try_update(Relaxed, Relaxed, |t| {
                t.checked_add(n).filter(|t| *t <= s.max_total_body)
            })
            .is_err()
        {
            return false;
        }
        let mut g = s.shard(&self.key);
        let u = g.entry(self.key.clone()).or_default();
        if u.body.saturating_add(n) > s.max_body {
            if u.conns == 0 && u.body == 0 {
                g.remove(&self.key);
            }
            drop(g);
            s.total_body.fetch_sub(n, Relaxed);
            return false;
        }
        u.body += n;
        self.bytes += n;
        true
    }
}

impl Drop for BodyCharge {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.shares.release(&self.key, 0, self.bytes);
        }
    }
}

/// The source a peer address is: the device the pipeline would key it by under the active
/// config, else the address itself.
pub fn source_key(edge: &Edge, ip: IpAddr) -> DeviceKey {
    let ip = ip.to_canonical();
    match edge.active().dns.as_ref() {
        Some(rt) => rt.clients.key(&rt.device(ip, edge.neighbours.mac_of(&ip))),
        None => DeviceKey::Addr(ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> DeviceKey {
        DeviceKey::Addr(IpAddr::from([192, 168, 1, n]))
    }

    #[test]
    fn connections_are_capped_per_source_and_given_back() {
        let s = SourceShares::with_limits(2, 100, 1000);
        let a = s.connect(k(1)).unwrap();
        let _b = s.connect(k(1)).unwrap();
        assert!(s.connect(k(1)).is_none(), "the source's share is used up");
        assert!(s.connect(k(2)).is_some(), "other sources are unaffected");
        drop(a);
        assert_eq!(s.connections(&k(1)), 1);
        assert!(s.connect(k(1)).is_some());
    }

    #[test]
    fn body_bytes_are_capped_per_source_and_in_total() {
        let s = SourceShares::with_limits(2, 100, 150);
        let mut a = s.body(k(1));
        assert!(a.add(60));
        let mut b = s.body(k(1));
        assert!(!b.add(41), "over the source's 100 bytes");
        assert!(b.add(40));
        let mut c = s.body(k(2));
        assert!(!c.add(51), "over the 150 bytes in total");
        assert!(c.add(50));
        assert_eq!(s.body_bytes(), 150);
        drop((a, b, c));
        assert_eq!(s.body_bytes(), 0);
        assert!(
            s.shards.iter().all(|m| m.lock().unwrap().is_empty()),
            "nothing left"
        );
    }
}
