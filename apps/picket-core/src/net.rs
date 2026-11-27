//! Addresses: core's own IPs, LAN ranges, CIDR lists (README §3, core.md §11–§12).

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// The LAN ranges the LAN CA may sign and the web certificate covers: RFC 1918 and ULA
/// (security.md §2).
pub fn lan_ranges() -> Vec<IpNet> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
        .iter()
        .filter_map(|s| IpNet::from_str(s).ok())
        .collect()
}

/// True when `ip` is in RFC 1918 or ULA space.
pub fn is_lan_ip(ip: &IpAddr) -> bool {
    let ip = canonical_ip(*ip);
    lan_ranges().iter().any(|n| n.contains(&ip))
}

/// True when every address of `net` is in RFC 1918 or ULA space.
pub fn is_lan_net(net: &IpNet) -> bool {
    lan_ranges()
        .iter()
        .any(|r| r.contains(&net.network()) && r.contains(&net.broadcast()))
}

/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) as IPv4, so allowlists match either form.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// The key of a client's capped share (README §2, Bounded): an IPv4 address, or an IPv6 /64.
/// One host picks SLAAC privacy addresses from its /64 at will (RFC 8981), so per-address
/// shares would give it one share per address. Used for the pending-key
/// list, the unknown-key rate, the UI login limiter and argon2 waiters, and (with a share per
/// address inside it) connection shares ([`PerIp`]).
pub fn share_key(ip: IpAddr) -> IpAddr {
    match canonical_ip(ip) {
        IpAddr::V6(v6) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
        v4 => v4,
    }
}

/// A share key as shown in alerts and logs: `192.0.2.1`, or `2001:db8:1:2::/64`.
pub fn share_label(ip: IpAddr) -> String {
    match share_key(ip) {
        IpAddr::V6(v6) => format!("{v6}/64"),
        v4 => v4.to_string(),
    }
}

/// A peer address with an IPv4-mapped IPv6 address turned into IPv4 (dual-stack sockets report
/// IPv4 peers as `::ffff:a.b.c.d`).
pub fn canonical_addr(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    std::net::SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

/// How many per-address shares an IPv6 /64 gets in all in a [`PerIp`]. A home LAN's IPv6
/// devices usually share one /64, so a share per /64 alone would squeeze them into one
/// device's share; a share per address alone gives a host with privacy addresses as many as it
/// likes. The spec leaves the value open.
pub const NET_SHARES: usize = 4;

/// Per-client shares of a capped resource (README §2, Bounded: where clients share a capped
/// resource, each gets a capped share). Used for connections on the web and edge ports, so one
/// LAN host re-opening idle connections can't take every slot: each address gets `cap` units,
/// and each IPv6 /64 ([`share_key`]) `cap` × [`NET_SHARES`] in all. The maps hold only keys
/// with a live guard, so they are bounded by the resource's own cap.
#[derive(Clone)]
pub struct PerIp {
    held: std::sync::Arc<std::sync::Mutex<Held>>,
    cap: usize,
    net_cap: usize,
}

#[derive(Default)]
struct Held {
    addrs: std::collections::HashMap<IpAddr, usize>,
    nets: std::collections::HashMap<IpAddr, usize>,
}

fn give_back(m: &mut std::collections::HashMap<IpAddr, usize>, k: &IpAddr) {
    if let Some(n) = m.get_mut(k) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            m.remove(k);
        }
    }
}

/// One unit of a [`PerIp`] share; dropping it gives the unit back.
pub struct PerIpGuard {
    held: std::sync::Arc<std::sync::Mutex<Held>>,
    ip: IpAddr,
    net: Option<IpAddr>,
}

impl PerIp {
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            held: Default::default(),
            cap,
            net_cap: cap.saturating_mul(NET_SHARES),
        }
    }

    /// Takes one unit for `ip`, or `None` when its address or its /64 holds its share.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<PerIpGuard> {
        let ip = canonical_ip(ip);
        let net = ip.is_ipv6().then(|| share_key(ip));
        let mut h = self.held.lock().ok()?;
        if h.addrs.get(&ip).copied().unwrap_or(0) >= self.cap
            || net.is_some_and(|n| h.nets.get(&n).copied().unwrap_or(0) >= self.net_cap)
        {
            return None;
        }
        *h.addrs.entry(ip).or_insert(0) += 1;
        if let Some(n) = net {
            *h.nets.entry(n).or_insert(0) += 1;
        }
        Some(PerIpGuard {
            held: self.held.clone(),
            ip,
            net,
        })
    }

    /// Units `ip` holds now.
    pub fn held(&self, ip: IpAddr) -> usize {
        self.held
            .lock()
            .ok()
            .and_then(|h| h.addrs.get(&canonical_ip(ip)).copied())
            .unwrap_or(0)
    }

    /// Units `ip`'s IPv6 /64 holds now (an IPv4 address's own units).
    pub fn held_net(&self, ip: IpAddr) -> usize {
        let ip = canonical_ip(ip);
        if ip.is_ipv4() {
            return self.held(ip);
        }
        self.held
            .lock()
            .ok()
            .and_then(|h| h.nets.get(&share_key(ip)).copied())
            .unwrap_or(0)
    }
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        if let Ok(mut h) = self.held.lock() {
            give_back(&mut h.addrs, &self.ip);
            if let Some(n) = &self.net {
                give_back(&mut h.nets, n);
            }
        }
    }
}

/// Parses a CIDR or a bare address (as a host route).
pub fn parse_net(s: &str) -> Option<IpNet> {
    let s = s.trim();
    if let Ok(n) = IpNet::from_str(s) {
        return Some(n.trunc());
    }
    IpAddr::from_str(s).ok().map(IpNet::from)
}

/// True when any net in `nets` contains `ip`.
pub fn nets_contain(nets: &[IpNet], ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    nets.iter().any(|n| n.contains(&ip))
}

/// Core's own addresses: the default for `dnssec.source_ips` and the IPs of the `Host` allowlist
/// and the web certificate (README §3, core.md §11). Read from `/proc/net/fib_trie` (local IPv4
/// routes) and `/proc/net/if_inet6`, without root, `unsafe` or another crate; when neither gives
/// an address, the one the kernel would use to reach the Internet. Loopback is included (it is
/// one of core's addresses and local tools reach the UI through it).
pub fn local_ips() -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    match std::fs::read_to_string("/proc/net/fib_trie") {
        Ok(t) => ips.extend(parse_fib_trie_locals(&t)),
        Err(e) => tracing::debug!(error = %e, "cannot read /proc/net/fib_trie"),
    }
    match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(t) => ips.extend(parse_if_inet6(&t)),
        Err(e) => tracing::debug!(error = %e, "cannot read /proc/net/if_inet6"),
    }
    if !ips.iter().any(|ip| !ip.is_loopback()) {
        for (bind, target) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
            if let Ok(sock) = std::net::UdpSocket::bind(bind)
                && sock.connect(target).is_ok()
                && let Ok(local) = sock.local_addr()
            {
                ips.push(local.ip());
            }
        }
    }
    ips.push(IpAddr::from([127, 0, 0, 1]));
    ips.push(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
    ips.retain(|ip| !ip.is_unspecified());
    ips.sort();
    ips.dedup();
    ips
}

/// The local (host) IPv4 addresses in `/proc/net/fib_trie`: an address line followed by
/// `/32 host LOCAL`.
fn parse_fib_trie_locals(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut last: Option<std::net::Ipv4Addr> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("|-- ").or_else(|| t.strip_prefix("+-- ")) {
            last = rest
                .split_whitespace()
                .next()
                .and_then(|a| a.split('/').next())
                .and_then(|a| a.parse().ok());
        } else if t.contains("/32 host LOCAL")
            && let Some(ip) = last
        {
            out.push(IpAddr::V4(ip));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The addresses in `/proc/net/if_inet6` (32 hex digits first on each line).
fn parse_if_inet6(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let hex = l.split_whitespace().next()?;
            if hex.len() != 32 {
                return None;
            }
            u128::from_str_radix(hex, 16)
                .ok()
                .map(|v| IpAddr::V6(std::net::Ipv6Addr::from(v)))
        })
        .collect()
}

/// Core's addresses that may go into the web certificate: those in the LAN ranges.
pub fn local_lan_ips(all: &[IpAddr]) -> Vec<IpAddr> {
    all.iter().copied().filter(is_lan_ip).collect()
}

/// A MAC in the canonical lowercase `aa:bb:cc:dd:ee:ff` form, if `s` is one (accepts `-` too).
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = String::with_capacity(17);
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if i > 0 {
            out.push(':');
        }
        out.push_str(&p.to_ascii_lowercase());
    }
    Some(out)
}

/// The `host` part of a `Host` header or URI authority, without port or IPv6 brackets,
/// lowercased, without a trailing dot.
pub fn host_without_port(authority: &str) -> Option<String> {
    let a = authority.trim();
    if a.is_empty() || a.len() > 300 {
        return None;
    }
    let host = if let Some(rest) = a.strip_prefix('[') {
        let end = rest.find(']')?;
        let (h, tail) = rest.split_at(end);
        let tail = &tail[1..];
        if !(tail.is_empty() || tail.starts_with(':')) {
            return None;
        }
        h.to_string()
    } else {
        match a.rsplit_once(':') {
            Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) && !h.contains(':') => h.to_string(),
            Some(_) if a.matches(':').count() > 1 => return None, // bare IPv6 without brackets
            Some(_) => return None,
            None => a.to_string(),
        }
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_hosts_share_by_slash_64() {
        // README §2 Bounded (CC10): one host with SLAAC privacy addresses gets at most its /64's
        // share, not one share per address; IPv4 shares stay per address.
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let p = PerIp::new(2);
        let mut guards = Vec::new();
        guards.push(p.try_acquire(ip("2001:db8:1:2::1")).unwrap());
        guards.push(p.try_acquire(ip("2001:db8:1:2::1")).unwrap());
        assert!(p.try_acquire(ip("2001:db8:1:2::1")).is_none(), "per address");
        for i in 0..(2 * NET_SHARES as u16 - 2) {
            guards.push(
                p.try_acquire(IpAddr::from([0x2001, 0xdb8, 1, 2, 9, i, 0, 1]))
                    .unwrap(),
            );
        }
        assert_eq!(p.held_net(ip("2001:db8:1:2::77")), 2 * NET_SHARES);
        assert!(p.try_acquire(ip("2001:db8:1:2:ffff::9")).is_none(), "per /64");
        assert!(p.try_acquire(ip("2001:db8:1:3::1")).is_some());
        let _c = p.try_acquire(ip("10.0.0.1")).unwrap();
        let _d = p.try_acquire(ip("10.0.0.1")).unwrap();
        assert!(p.try_acquire(ip("::ffff:10.0.0.1")).is_none());
        assert!(p.try_acquire(ip("10.0.0.2")).is_some());
        drop(guards);
        assert_eq!(p.held_net(ip("2001:db8:1:2::1")), 0);
        assert_eq!(p.held(ip("2001:db8:1:2::1")), 0);
        assert_eq!(share_key(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1:2::"));
        assert_eq!(share_label(ip("2001:db8:1:2:3:4:5:6")), "2001:db8:1:2::/64");
        assert_eq!(share_label(ip("::ffff:192.0.2.1")), "192.0.2.1");
    }

    #[test]
    fn lan() {
        assert!(is_lan_ip(&"192.168.1.20".parse().unwrap()));
        assert!(is_lan_ip(&"fd00::1".parse().unwrap()));
        assert!(is_lan_ip(&"::ffff:10.1.2.3".parse().unwrap()));
        assert!(!is_lan_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_lan_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_lan_net(&"192.168.1.0/24".parse().unwrap()));
        assert!(!is_lan_net(&"192.0.0.0/8".parse().unwrap()));
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host_without_port("Core.Home.Arpa:8443").unwrap(),
            "core.home.arpa"
        );
        assert_eq!(host_without_port("[::1]:8443").unwrap(), "::1");
        assert_eq!(host_without_port("10.0.0.1").unwrap(), "10.0.0.1");
        assert_eq!(host_without_port("core.home.arpa.").unwrap(), "core.home.arpa");
        assert!(host_without_port("").is_none());
        assert!(host_without_port("::1").is_none());
        assert!(host_without_port("[::1]x").is_none());
    }

    #[test]
    fn macs() {
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-01").unwrap(), "aa:bb:cc:dd:ee:01");
        assert!(normalize_mac("aa:bb:cc:dd:ee").is_none());
        assert!(normalize_mac("aa:bb:cc:dd:ee:zz").is_none());
    }

    #[test]
    fn proc_parsers() {
        let trie = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 192.168.1.20\n        /32 host LOCAL\n     |-- 192.168.1.255\n        /32 link BROADCAST\nLocal:\n  +-- 127.0.0.0/8 2 0 2\n     |-- 127.0.0.1\n        /32 host LOCAL\n     |-- 192.168.1.20\n        /32 host LOCAL\n";
        assert_eq!(
            parse_fib_trie_locals(trie),
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "192.168.1.20".parse().unwrap()
            ]
        );
        let v6 = "fe800000000000000000000000000001 02 40 20 80 eth0\nfd000000000000000000000000000002 03 40 00 80 eth0\nbad line\n";
        assert_eq!(
            parse_if_inet6(v6),
            vec!["fe80::1".parse::<IpAddr>().unwrap(), "fd00::2".parse().unwrap()]
        );
        let ips = local_ips();
        assert!(ips.contains(&IpAddr::from([127, 0, 0, 1])));
        assert!(!ips.iter().any(|ip| ip.is_unspecified()));
    }

    #[test]
    fn nets() {
        let n = parse_net("192.168.1.7/24").unwrap();
        assert_eq!(n.to_string(), "192.168.1.0/24");
        assert_eq!(parse_net("10.0.0.1").unwrap().prefix_len(), 32);
        assert!(nets_contain(&[n], "::ffff:192.168.1.9".parse().unwrap()));
    }
}
