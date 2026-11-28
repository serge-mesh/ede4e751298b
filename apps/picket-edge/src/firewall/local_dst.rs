//! UniFi's local networks per protected interface (issue #47):
//! the helper reports, for each `enforce` interface and family, the members of the
//! `…local_zoned_subnets` set that guards every way into the interface's zone→External chain.
//! Traffic from that interface to them never meets Picket's jump, so [`super::FwClient::ip_blocked`]
//! must not call it blocked: the probe would show a firewall block page for a host that is simply
//! down, and an allow would install an entry that can't change anything.
//!
//! Fails closed: only a complete snapshot is used. An entry the helper marks unavailable, a
//! network that doesn't parse, a `/0`, more than [`MAX_LOCAL_DST_NETS`] networks or two entries
//! for the same interface and family leave that interface and family without exclusions, and
//! every destination stays blockable as before.

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use picket_api::helper::{LocalDst, MAX_LOCAL_DST_NETS};

/// Most interface/family entries kept.
const MAX_ENTRIES: usize = 256;

/// The usable entries, by (interface, IPv4?).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalNets {
    by_if: HashMap<(String, bool), Vec<IpNet>>,
}

impl LocalNets {
    pub fn of(entries: &[LocalDst]) -> Self {
        let mut by_if: HashMap<(String, bool), Option<Vec<IpNet>>> = HashMap::new();
        for e in entries.iter().take(MAX_ENTRIES) {
            let v4 = match e.family.as_str() {
                "ipv4" => true,
                "ipv6" => false,
                _ => continue,
            };
            let nets = parse(e, v4);
            by_if
                .entry((e.interface.clone(), v4))
                .and_modify(|n| *n = None) // a duplicate: neither is trusted
                .or_insert(nets);
        }
        Self {
            by_if: by_if.into_iter().filter_map(|(k, n)| Some((k, n?))).collect(),
        }
    }

    /// Is `ip` one of `iface`'s local destinations? Only a usable entry for `iface` and `ip`'s
    /// family can say yes.
    pub fn contains(&self, iface: &str, ip: IpAddr) -> bool {
        self.by_if
            .get(&(iface.to_string(), ip.is_ipv4()))
            .is_some_and(|nets| nets.iter().any(|n| n.contains(&ip)))
    }

    pub fn is_empty(&self) -> bool {
        self.by_if.is_empty()
    }
}

fn parse(e: &LocalDst, v4: bool) -> Option<Vec<IpNet>> {
    if e.unavailable.is_some() || e.nets.len() > MAX_LOCAL_DST_NETS {
        return None;
    }
    e.nets
        .iter()
        .map(|s| {
            let n: IpNet = s.parse().ok()?;
            (n.prefix_len() > 0 && n.addr().is_ipv4() == v4).then_some(n)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(iface: &str, family: &str, nets: &[&str]) -> LocalDst {
        LocalDst {
            interface: iface.into(),
            family: family.into(),
            set: "UBIOS_local_zoned_subnets".into(),
            nets: nets.iter().map(|s| (*s).to_string()).collect(),
            unavailable: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn scoped_by_interface_and_family() {
        let l = LocalNets::of(&[
            entry("br10", "ipv4", &["192.168.20.0/24", "10.99.0.0/16"]),
            entry("br10", "ipv6", &["fd00:20::/64"]),
            entry("br30", "ipv4", &["192.168.40.0/24"]),
        ]);
        assert!(l.contains("br10", ip("192.168.20.10")));
        assert!(l.contains("br10", ip("10.99.3.4")));
        assert!(l.contains("br10", ip("fd00:20::10")));
        assert!(!l.contains("br10", ip("192.168.40.1")), "another interface's set");
        assert!(!l.contains("br30", ip("192.168.20.10")));
        assert!(!l.contains("br30", ip("fd00:20::10")), "no IPv6 entry for br30");
        assert!(!l.contains("br10", ip("203.0.113.5")));
        assert!(!l.contains("eth9", ip("192.168.20.10")), "unknown interface");
    }

    #[test]
    fn anything_incomplete_is_dropped() {
        let mut unavailable = entry("br10", "ipv4", &[]);
        unavailable.unavailable = Some("nomatch".into());
        let too_many: Vec<String> = (0..=MAX_LOCAL_DST_NETS)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        let mut big = entry("br11", "ipv4", &[]);
        big.nets = too_many;
        let l = LocalNets::of(&[
            unavailable,
            big,
            entry("br12", "ipv4", &["192.168.20.0/24", "not a net"]),
            entry("br13", "ipv4", &["0.0.0.0/0"]),
            entry("br14", "ipv4", &["fd00::/64"]),
            entry("br15", "ipv4", &["192.168.20.0/24"]),
            entry("br15", "ipv4", &["192.168.20.0/24"]),
            entry("br16", "ipx", &["192.168.20.0/24"]),
        ]);
        assert!(l.is_empty(), "{l:?}");
    }
}
