//! Reverse names (`in-addr.arpa`, `ip6.arpa`) and private ranges, for the profile's
//! `private_reverse` (edge.md §4 "Special names", §6 "Forward zones"): private-range PTR names
//! that none of the profile's forward zones covers get NXDOMAIN locally.
//!
//! "Private" is the set of locally-served zones of RFC 6303 plus RFC 7793's shared address space,
//! as AdGuard Home's private reverse DNS uses: RFC 1918, 100.64.0.0/10, loopback, link-local,
//! "this network", the documentation ranges, the limited broadcast address, `::`, `::1`,
//! `fe80::/10`, ULA `fc00::/7` and `2001:db8::/32`.
//!
//! [`reverse_name`] goes the other way: the name a PTR query for an address asks (edge.md §12:
//! the extension's PTR probe).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use smallvec::SmallVec;

use crate::name::{NameRef, QName};

const V4_PRIVATE: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];

const V6_PRIVATE: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::UNSPECIFIED, 128),
    (Ipv6Addr::LOCALHOST, 128),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
];

fn v4_within(addr: Ipv4Addr, len: u8, net: Ipv4Addr, net_len: u8) -> bool {
    if len < net_len {
        return false;
    }
    let mask = u32::MAX
        .checked_shl(32u32.saturating_sub(u32::from(net_len)))
        .unwrap_or(0);
    u32::from(addr) & mask == u32::from(net) & mask
}

fn v6_within(addr: Ipv6Addr, len: u8, net: Ipv6Addr, net_len: u8) -> bool {
    if len < net_len {
        return false;
    }
    let mask = u128::MAX
        .checked_shl(128u32.saturating_sub(u32::from(net_len)))
        .unwrap_or(0);
    u128::from(addr) & mask == u128::from(net) & mask
}

/// True when `prefix/len` lies inside a private range.
fn prefix_is_private(addr: IpAddr, len: u8) -> bool {
    match addr {
        IpAddr::V4(a) => V4_PRIVATE.iter().any(|(n, l)| v4_within(a, len, *n, *l)),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped()
                && len >= 96
            {
                return prefix_is_private(IpAddr::V4(v4), len.saturating_sub(96));
            }
            V6_PRIVATE.iter().any(|(n, l)| v6_within(a, len, *n, *l))
        }
    }
}

/// True for a private address (an IPv4-mapped IPv6 address is judged as its IPv4 address).
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => prefix_is_private(ip, 32),
        IpAddr::V6(_) => prefix_is_private(ip, 128),
    }
}

fn parse_octet(label: &[u8]) -> Option<u8> {
    if label.is_empty() || label.len() > 3 || !label.iter().all(u8::is_ascii_digit) {
        return None;
    }
    // A leading zero would give one octet two names.
    if label.len() > 1 && label.first() == Some(&b'0') {
        return None;
    }
    std::str::from_utf8(label).ok()?.parse().ok()
}

fn parse_nibble(label: &[u8]) -> Option<u8> {
    match label {
        [c] => char::from(*c).to_digit(16).and_then(|d| u8::try_from(d).ok()),
        _ => None,
    }
}

/// The address prefix a reverse name stands for: `1.168.192.in-addr.arpa` → 192.168.1.0/24,
/// `b.d.0.1.0.0.2.ip6.arpa` → 2001:db0::/28. `None` for other names and for labels that aren't
/// octets or nibbles (such as RFC 2317 classless delegation names).
pub fn reverse_prefix(name: NameRef<'_>) -> Option<(IpAddr, u8)> {
    let labels: Vec<&[u8]> = name.labels().collect();
    match labels.as_slice() {
        [rest @ .., zone, arpa]
            if zone.eq_ignore_ascii_case(b"in-addr") && arpa.eq_ignore_ascii_case(b"arpa") =>
        {
            if rest.len() > 4 {
                return None;
            }
            let mut octets = [0u8; 4];
            for (slot, label) in octets.iter_mut().zip(rest.iter().rev()) {
                *slot = parse_octet(label)?;
            }
            let len = u8::try_from(rest.len().saturating_mul(8)).ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(octets)), len))
        }
        [rest @ .., zone, arpa]
            if zone.eq_ignore_ascii_case(b"ip6") && arpa.eq_ignore_ascii_case(b"arpa") =>
        {
            if rest.len() > 32 {
                return None;
            }
            let mut v: u128 = 0;
            for (i, label) in rest.iter().rev().enumerate() {
                let nib = u128::from(parse_nibble(label)?);
                let shift = 124u32.checked_sub(u32::try_from(i).ok()?.checked_mul(4)?)?;
                v |= nib.checked_shl(shift)?;
            }
            let len = u8::try_from(rest.len().saturating_mul(4)).ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(v)), len))
        }
        _ => None,
    }
}

/// The address of a full reverse name (4 octets or 32 nibbles), as a PTR query names it.
pub fn parse_reverse(name: NameRef<'_>) -> Option<IpAddr> {
    match reverse_prefix(name)? {
        (ip @ IpAddr::V4(_), 32) | (ip @ IpAddr::V6(_), 128) => Some(ip),
        _ => None,
    }
}

/// The reverse name of an address: `1.2.3.4` → `4.3.2.1.in-addr.arpa`, an IPv6 address as its 32
/// nibbles, least significant first, under `ip6.arpa`. An IPv4-mapped IPv6 address keeps its
/// `ip6.arpa` form.
pub fn reverse_name(ip: IpAddr) -> QName {
    let text = match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                for nibble in [byte & 0x0F, byte >> 4] {
                    s.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
                    s.push('.');
                }
            }
            s.push_str("ip6.arpa");
            s
        }
    };
    QName::from_text(&text).unwrap_or_else(|_| QName::root())
}

/// The longest address prefix whose reverse zone `name` is at or below: the octet or nibble
/// labels right above `in-addr.arpa` or `ip6.arpa`, read from the right while they parse (at
/// most 4 or 32). Labels further left (`_dns-sd._udp`, an RFC 2317 `0/25`, anything) are names
/// inside that zone. `None` for names outside both trees.
fn reverse_zone_prefix(name: NameRef<'_>) -> Option<(IpAddr, u8)> {
    // A full ip6.arpa name has 34 labels: no allocation for reverse names.
    let all: SmallVec<[&[u8]; 40]> = name.labels().collect();
    let mut labels = all.iter().rev().copied();
    let (arpa, zone) = (labels.next()?, labels.next()?);
    if !arpa.eq_ignore_ascii_case(b"arpa") {
        return None;
    }
    if zone.eq_ignore_ascii_case(b"in-addr") {
        let mut octets = [0u8; 4];
        let mut n = 0usize;
        for (slot, label) in octets.iter_mut().zip(labels) {
            let Some(o) = parse_octet(label) else { break };
            *slot = o;
            n = n.saturating_add(1);
        }
        let len = u8::try_from(n.saturating_mul(8)).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(octets)), len))
    } else if zone.eq_ignore_ascii_case(b"ip6") {
        let mut v: u128 = 0;
        let mut n = 0u32;
        for label in labels.take(32) {
            let Some(nib) = parse_nibble(label) else { break };
            v |= u128::from(nib).checked_shl(124u32.checked_sub(n.checked_mul(4)?)?)?;
            n = n.saturating_add(1);
        }
        let len = u8::try_from(n.saturating_mul(4)).ok()?;
        Some((IpAddr::V6(Ipv6Addr::from(v)), len))
    } else {
        None
    }
}

/// True when `name` is a private-range reverse name: at or below the reverse zone of a private
/// range (`168.192.in-addr.arpa`, `1.0.168.192.in-addr.arpa`, `d.f.ip6.arpa`, …). The zones of
/// RFC 6303 are answered whole, so this includes every name inside them: DNS-SD browsing names
/// such as `b._dns-sd._udp.0.1.168.192.in-addr.arpa` (RFC 6763 §11), RFC 2317 classless names
/// such as `0/25.1.168.192.in-addr.arpa`, and anything else under the address labels.
pub fn is_private_reverse(name: NameRef<'_>) -> bool {
    reverse_zone_prefix(name).is_some_and(|(a, l)| prefix_is_private(a, l))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::QName;

    fn n(s: &str) -> QName {
        QName::from_text(s).unwrap()
    }

    #[test]
    fn parse_v4() {
        assert_eq!(
            parse_reverse(n("4.3.2.1.in-addr.arpa").as_name()),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            reverse_prefix(n("168.192.IN-ADDR.ARPA").as_name()),
            Some(("192.168.0.0".parse().unwrap(), 16))
        );
        assert_eq!(parse_reverse(n("3.2.1.in-addr.arpa").as_name()), None);
        assert_eq!(parse_reverse(n("256.3.2.1.in-addr.arpa").as_name()), None);
        assert_eq!(parse_reverse(n("04.3.2.1.in-addr.arpa").as_name()), None);
        assert_eq!(parse_reverse(n("0/25.2.0.192.in-addr.arpa").as_name()), None);
        assert_eq!(parse_reverse(n("5.4.3.2.1.in-addr.arpa").as_name()), None);
        assert_eq!(parse_reverse(n("example.com").as_name()), None);
    }

    #[test]
    fn parse_v6() {
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        assert_eq!(
            parse_reverse(n(name).as_name()),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            reverse_prefix(n("D.F.ip6.arpa").as_name()),
            Some(("fd00::".parse().unwrap(), 8))
        );
        assert_eq!(reverse_prefix(n("g.ip6.arpa").as_name()), None);
        assert_eq!(reverse_prefix(n("10.ip6.arpa").as_name()), None);
    }

    #[test]
    fn private_ranges() {
        for ip in [
            "10.1.2.3",
            "172.31.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd12::1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::",
            "fc00::1",
            "2001:db8::5",
            "172.16.0.1",
            "172.31.255.255",
            "0.1.2.3",
            "255.255.255.255",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "fec0::1",
            "2001:db9::1",
            "255.255.255.254",
        ] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn reverse_names_round_trip() {
        for ip in [
            "1.2.3.4",
            "10.0.0.1",
            "2001:db8::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "::",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            let name = reverse_name(ip);
            assert_eq!(parse_reverse(name.as_name()), Some(ip), "{ip}");
        }
        assert_eq!(
            reverse_name("192.0.2.10".parse().unwrap()).log_text(),
            "10.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()).log_text(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        // Upper-case reverse names parse too.
        let upper = reverse_name("2001:db8::1".parse().unwrap())
            .log_text()
            .to_uppercase();
        assert_eq!(
            parse_reverse(n(&upper).as_name()),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn private_reverse_names() {
        assert!(is_private_reverse(n("1.1.168.192.in-addr.arpa").as_name()));
        assert!(is_private_reverse(n("168.192.in-addr.arpa").as_name()));
        assert!(is_private_reverse(n("16.172.in-addr.arpa").as_name()));
        assert!(!is_private_reverse(n("172.in-addr.arpa").as_name()));
        assert!(!is_private_reverse(n("8.8.8.8.in-addr.arpa").as_name()));
        assert!(is_private_reverse(n("d.f.ip6.arpa").as_name()));
        assert!(is_private_reverse(n("0.8.e.f.ip6.arpa").as_name()));
        assert!(!is_private_reverse(n("ip6.arpa").as_name()));
        assert!(!is_private_reverse(n("in-addr.arpa").as_name()));
        assert!(is_private_reverse(n("10.in-addr.arpa").as_name()));
        assert!(!is_private_reverse(n("192.in-addr.arpa").as_name()));
        assert!(!is_private_reverse(n("f.ip6.arpa").as_name()));
        assert!(!is_private_reverse(n("arpa").as_name()));
        assert!(!is_private_reverse(n("example.com").as_name()));
        for ip in ["fe80::1", "::ffff:10.0.0.1", "192.168.0.1"] {
            assert!(
                is_private_reverse(reverse_name(ip.parse().unwrap()).as_name()),
                "{ip}"
            );
        }
        for ip in ["2606:4700::1111", "::ffff:8.8.8.8", "8.8.4.4"] {
            assert!(
                !is_private_reverse(reverse_name(ip.parse().unwrap()).as_name()),
                "{ip}"
            );
        }
    }

    /// W8: every name at or below a private reverse zone is private (RFC 6303 zones are served
    /// whole): DNS-SD browsing names (RFC 6763 §11), RFC 2317 classless names and anything else
    /// under the address labels.
    #[test]
    fn names_below_private_reverse_zones() {
        let nibbles = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa";
        for name in [
            "b._dns-sd._udp.0.1.168.192.in-addr.arpa",
            "lb._dns-sd._udp.168.192.in-addr.arpa",
            "x.5.1.168.192.in-addr.arpa",
            "0/25.1.168.192.in-addr.arpa",
            "5.4.3.2.1.0.10.in-addr.arpa",
            "01.168.192.in-addr.arpa",
            "db._dns-sd._udp.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
            "x.d.f.ip6.arpa",
            &format!("extra.{nibbles}"),
            "b._dns-sd._udp.0.8.e.f.ip6.arpa",
        ] {
            assert!(is_private_reverse(n(name).as_name()), "{name}");
        }
        for name in [
            "b._dns-sd._udp.0.1.0.8.in-addr.arpa",
            "x.192.in-addr.arpa",
            "x.172.in-addr.arpa",
            "0/25.2.0.193.in-addr.arpa",
            "x.f.ip6.arpa",
            "x.in-addr.arpa",
            "x.ip6.arpa",
            "168.192.in-addr.arpa.example",
        ] {
            assert!(!is_private_reverse(n(name).as_name()), "{name}");
        }
        // The exact-prefix reading stays strict: these aren't address names.
        assert_eq!(reverse_prefix(n("0/25.1.168.192.in-addr.arpa").as_name()), None);
        assert_eq!(parse_reverse(n("x.5.1.168.192.in-addr.arpa").as_name()), None);
    }
}
