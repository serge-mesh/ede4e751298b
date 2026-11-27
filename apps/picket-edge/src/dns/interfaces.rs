//! The kernel's interface and address tables (edge.md §5 "Interfaces without SO_BINDTODEVICE"),
//! read unprivileged over rtnetlink: interface index → name (UDP's `IP_PKTINFO` gives the index
//! a datagram arrived on), and local address → interface (TCP, DoT and DoH match the local
//! address's interface). Refreshed every 30 s and on demand (rate-limited) when a lookup misses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use futures_util::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkAttribute;
use tokio::sync::Notify;

const REFRESH: Duration = Duration::from_secs(30);
const MIN_ON_DEMAND: Duration = Duration::from_secs(2);
const DUMP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Default)]
pub struct Table {
    pub names: HashMap<u32, Arc<str>>,
    pub addrs: HashMap<IpAddr, u32>,
    /// Each local address's network (address, prefix length) and interface, for the interface a
    /// client's traffic enters on (edge.md §12 "IP allow": the client's interface).
    pub nets: Vec<(ipnet::IpNet, u32)>,
}

pub struct Interfaces {
    table: ArcSwap<Table>,
    available: AtomicBool,
    base: Instant,
    last_refresh_ms: AtomicU64,
    refresh_now: Notify,
}

impl Interfaces {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            table: ArcSwap::from_pointee(Table::default()),
            available: AtomicBool::new(false),
            base: Instant::now(),
            last_refresh_ms: AtomicU64::new(0),
            refresh_now: Notify::new(),
        })
    }

    /// A table set directly (tests).
    pub fn set(&self, t: Table) {
        self.table.store(Arc::new(t));
        self.available.store(true, Relaxed);
    }

    pub fn available(&self) -> bool {
        self.available.load(Relaxed)
    }

    fn ask_refresh(&self) {
        let now = picket_api::duration::as_millis_u64(self.base.elapsed());
        let last = self.last_refresh_ms.load(Relaxed);
        if now.saturating_sub(last) >= picket_api::duration::as_millis_u64(MIN_ON_DEMAND) {
            self.refresh_now.notify_one();
        }
    }

    /// The name of interface `index`.
    pub fn name_of(&self, index: u32) -> Option<Arc<str>> {
        let r = self.table.load().names.get(&index).cloned();
        if r.is_none() {
            self.ask_refresh();
        }
        r
    }

    /// True when `ip` is one of the edge's own addresses.
    pub fn is_local(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_loopback() || self.table.load().addrs.contains_key(&ip)
    }

    /// The interface a client address is on: the most specific local network holding it. `None`
    /// for an address beyond another hop (or before the table is read).
    pub fn interface_for_client(&self, ip: IpAddr) -> Option<Arc<str>> {
        let t = self.table.load();
        let ip = ip.to_canonical();
        t.nets
            .iter()
            .filter(|(n, _)| n.contains(&ip) && n.prefix_len() > 0)
            .max_by_key(|(n, _)| n.prefix_len())
            .and_then(|(_, i)| t.names.get(i).cloned())
    }

    /// The interface a local address is configured on.
    pub fn interface_of(&self, ip: IpAddr) -> Option<Arc<str>> {
        let t = self.table.load();
        let ip = ip.to_canonical();
        let r = t.addrs.get(&ip).and_then(|i| t.names.get(i).cloned());
        if r.is_none() {
            self.ask_refresh();
        }
        r
    }

    async fn dump(&self) -> anyhow::Result<()> {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        let task = tokio::spawn(conn);
        struct Abort(tokio::task::JoinHandle<()>);
        impl Drop for Abort {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _g = Abort(task);
        let mut t = Table::default();
        let fut = async {
            let mut links = handle.link().get().execute();
            while let Some(l) = links.try_next().await? {
                if t.names.len() >= MAX_ENTRIES {
                    break;
                }
                if let Some(name) = l.attributes.iter().find_map(|a| match a {
                    LinkAttribute::IfName(n) => Some(n.clone()),
                    _ => None,
                }) {
                    t.names.insert(l.header.index, name.into());
                }
            }
            let mut addrs = handle.address().get().execute();
            while let Some(a) = addrs.try_next().await? {
                if t.addrs.len() >= MAX_ENTRIES {
                    break;
                }
                for attr in &a.attributes {
                    if let AddressAttribute::Address(ip) | AddressAttribute::Local(ip) = attr {
                        t.addrs.insert(ip.to_canonical(), a.header.index);
                        if let Ok(n) = ipnet::IpNet::new(ip.to_canonical(), a.header.prefix_len)
                            && t.nets.len() < MAX_ENTRIES
                        {
                            t.nets.push((n.trunc(), a.header.index));
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::time::timeout(DUMP_TIMEOUT, fut)
            .await
            .map_err(|_| anyhow::anyhow!("interface dump timed out"))??;
        self.table.store(Arc::new(t));
        self.available.store(true, Relaxed);
        self.last_refresh_ms
            .store(picket_api::duration::as_millis_u64(self.base.elapsed()), Relaxed);
        Ok(())
    }

    /// Keeps the table fresh.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let mut warned = false;
        loop {
            match self.dump().await {
                Ok(()) => warned = false,
                Err(e) => {
                    if !warned {
                        tracing::warn!(
                            "interface table unavailable ({}); listeners restricted by `interfaces` drop their queries",
                            crate::diag::cap_chain(&e)
                        );
                        warned = true;
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(REFRESH) => {}
                _ = self.refresh_now.notified() => {}
            }
        }
    }
}
