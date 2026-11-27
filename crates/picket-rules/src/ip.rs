//! IP addresses and ranges (rules.md §1, §6; storage.md §3; bundles.md §2 broad IP rules).

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// Formats an address exactly like Go's `net.IP.String()` (AdGuard Home's form, rules.md §1):
/// IPv4 dotted; IPv4-mapped IPv6 (`::ffff:a.b.c.d`) as dotted IPv4; other IPv6 in lowercase hex
/// with the longest run of two or more zero groups (the first, on a tie) written as `::`.
pub fn go_ip_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => go_ipv6_string(&v6),
        },
    }
}

fn go_ipv6_string(v6: &Ipv6Addr) -> String {
    let seg = v6.segments();
    // Longest run of zero groups, at least two long; the first one wins a tie.
    let (mut best_start, mut best_len) = (usize::MAX, 0usize);
    let mut i = 0usize;
    while i < 8 {
        if seg.get(i) == Some(&0) {
            let start = i;
            while seg.get(i) == Some(&0) {
                i = i.saturating_add(1);
            }
            let len = i.saturating_sub(start);
            if len >= 2 && len > best_len {
                best_start = start;
                best_len = len;
            }
        } else {
            i = i.saturating_add(1);
        }
    }
    let mut out = String::with_capacity(39);
    let mut i = 0usize;
    while i < 8 {
        if i == best_start {
            out.push_str("::");
            i = i.saturating_add(best_len);
            continue;
        }
        if i > 0 && !out.ends_with(':') {
            out.push(':');
        }
        let _ = write!(out, "{:x}", seg.get(i).copied().unwrap_or(0));
        i = i.saturating_add(1);
    }
    out
}

/// Formats an address like Go's `netip.Addr.String()`, which AdGuard uses when it prints
/// `$dnsrewrite` values: as [`go_ip_string`], except that an IPv4-mapped IPv6 address keeps its
/// `::ffff:a.b.c.d` form.
pub fn netip_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => format!("::ffff:{v4}"),
            None => go_ipv6_string(&v6),
        },
        IpAddr::V4(_) => go_ip_string(ip),
    }
}

/// Parses an address as Go's `netip.ParseAddr` does for AdGuard's purposes: IPv4 dotted quads
/// without leading zeros, or IPv6 with an optional `%zone`, which is accepted and dropped.
pub fn parse_go_ip(s: &str) -> Option<IpAddr> {
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    if s.contains(':') {
        let addr = match s.split_once('%') {
            Some((a, zone)) if !zone.is_empty() => a,
            Some(_) => return None,
            None => s,
        };
        return addr.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    s.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// True when `s` is an address string Go's `netip.ParseAddr` accepts (golibs
/// `netutil.IsValidIPString`), as `$denyallow` uses it to skip IP text (urlfilter).
pub fn is_go_ip_string(s: &str) -> bool {
    parse_go_ip(s).is_some()
}

/// An inclusive address range in one family. IPv4 ranges use the low 32 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IpRange {
    /// True for IPv4.
    pub v4: bool,
    /// First address (IPv4 in the low 32 bits).
    pub first: u128,
    /// Last address, inclusive.
    pub last: u128,
}

impl IpRange {
    /// One address. An IPv4-mapped IPv6 address becomes its IPv4 address (rules.md §6).
    pub fn single(ip: IpAddr) -> IpRange {
        let ip = canonical_ip(ip);
        let (v4, n) = ip_to_u128(ip);
        IpRange {
            v4,
            first: n,
            last: n,
        }
    }

    /// A CIDR prefix; host bits are cleared. An IPv4-mapped IPv6 prefix of /96 or longer becomes
    /// the IPv4 prefix. `None` for a prefix length out of range.
    pub fn cidr(ip: IpAddr, len: u8) -> Option<IpRange> {
        let (ip, len) = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if len >= 96 => (IpAddr::V4(v4), len.saturating_sub(96)),
                _ => (ip, len),
            },
            IpAddr::V4(_) => (ip, len),
        };
        let (v4, n) = ip_to_u128(ip);
        let bits: u32 = if v4 { 32 } else { 128 };
        if u32::from(len) > bits {
            return None;
        }
        let host_bits = bits.saturating_sub(u32::from(len));
        let host_mask: u128 = if host_bits == 0 {
            0
        } else if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits).wrapping_sub(1)
        };
        let first = n & !host_mask;
        let last = first | host_mask;
        Some(IpRange { v4, first, last })
    }

    /// Parses `a.b.c.d`, `a.b.c.d/n`, an IPv6 address or `x::/n`.
    pub fn parse(s: &str) -> Option<IpRange> {
        match s.split_once('/') {
            Some((addr, len)) => {
                if len.is_empty() || len.len() > 3 || !len.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let len: u8 = len.parse().ok()?;
                let ip = parse_go_ip(addr)?;
                if addr.contains('%') {
                    return None;
                }
                IpRange::cidr(ip, len)
            }
            None => parse_go_ip(s).map(IpRange::single),
        }
    }

    /// Parses everything [`IpRange::to_text`] writes: an address, a CIDR block, or `first-last` in
    /// one family (first ≤ last).
    pub fn from_text(s: &str) -> Option<IpRange> {
        let Some((a, b)) = s.split_once('-') else {
            return IpRange::parse(s);
        };
        let (first, last) = (IpRange::single(parse_go_ip(a)?), IpRange::single(parse_go_ip(b)?));
        if a.contains('%') || b.contains('%') || first.v4 != last.v4 || first.first > last.last {
            return None;
        }
        Some(IpRange {
            v4: first.v4,
            first: first.first,
            last: last.last,
        })
    }

    /// True when `ip` (IPv4-mapped IPv6 as IPv4) is inside.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (v4, n) = ip_to_u128(canonical_ip(ip));
        v4 == self.v4 && self.first <= n && n <= self.last
    }

    /// True when the ranges share an address.
    pub fn overlaps(&self, other: &IpRange) -> bool {
        self.v4 == other.v4 && self.first <= other.last && other.first <= self.last
    }

    /// Number of addresses, saturating at `u128::MAX`.
    pub fn size(&self) -> u128 {
        self.last.saturating_sub(self.first).saturating_add(1)
    }

    /// The first address as 16 bytes big-endian, IPv4 as IPv4-mapped (storage.md §3 `ip_first`).
    pub fn first_bytes(&self) -> [u8; 16] {
        to_storage_bytes(self.v4, self.first)
    }

    /// The last address as 16 bytes big-endian, IPv4 as IPv4-mapped (storage.md §3 `ip_last`).
    pub fn last_bytes(&self) -> [u8; 16] {
        to_storage_bytes(self.v4, self.last)
    }

    /// The first address.
    pub fn first_ip(&self) -> IpAddr {
        from_u128(self.v4, self.first)
    }

    /// The last address.
    pub fn last_ip(&self) -> IpAddr {
        from_u128(self.v4, self.last)
    }

    /// The prefix length when the range is exactly one CIDR block.
    pub fn prefix_len(&self) -> Option<u8> {
        let size = self.last.wrapping_sub(self.first).wrapping_add(1);
        let bits: u32 = if self.v4 { 32 } else { 128 };
        if self.first == 0 && self.last == u128::MAX && !self.v4 {
            return Some(0);
        }
        if size == 0 || !size.is_power_of_two() || self.first & size.wrapping_sub(1) != 0 {
            return None;
        }
        let host = size.trailing_zeros();
        u8::try_from(bits.checked_sub(host)?).ok()
    }

    /// Canonical text: an address for a single address, `addr/len` for a CIDR block, else
    /// `first-last` (Go text forms).
    pub fn to_text(&self) -> String {
        if self.first == self.last {
            return go_ip_string(self.first_ip());
        }
        match self.prefix_len() {
            Some(len) => format!("{}/{}", go_ip_string(self.first_ip()), len),
            None => format!(
                "{}-{}",
                go_ip_string(self.first_ip()),
                go_ip_string(self.last_ip())
            ),
        }
    }
}

/// IPv4-mapped IPv6 becomes IPv4 (rules.md §6).
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

fn ip_to_u128(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(v4) => (true, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (false, u128::from(v6)),
    }
}

fn from_u128(v4: bool, n: u128) -> IpAddr {
    if v4 {
        IpAddr::V4(Ipv4Addr::from(u32::try_from(n & 0xffff_ffff).unwrap_or(0)))
    } else {
        IpAddr::V6(Ipv6Addr::from(n))
    }
}

fn to_storage_bytes(v4: bool, n: u128) -> [u8; 16] {
    if v4 {
        let v4 = Ipv4Addr::from(u32::try_from(n & 0xffff_ffff).unwrap_or(0));
        v4.to_ipv6_mapped().octets()
    } else {
        n.to_be_bytes()
    }
}

/// IPv4 space that doesn't count towards a broad IP rule (bundles.md §2): private, loopback,
/// CGNAT, link-local, multicast and reserved (IANA special-purpose registry).
const V4_NOT_PUBLIC: &[(u32, u8)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8 "this network"
    (0x0a00_0000, 8),  // 10.0.0.0/8
    (0x6440_0000, 10), // 100.64.0.0/10 CGNAT
    (0x7f00_0000, 8),  // 127.0.0.0/8
    (0xa9fe_0000, 16), // 169.254.0.0/16
    (0xac10_0000, 12), // 172.16.0.0/12
    (0xc000_0000, 24), // 192.0.0.0/24
    (0xc000_0200, 24), // 192.0.2.0/24 TEST-NET-1
    (0xc058_6300, 24), // 192.88.99.0/24 6to4 relay (deprecated)
    (0xc0a8_0000, 16), // 192.168.0.0/16
    (0xc612_0000, 15), // 198.18.0.0/15 benchmarking
    (0xc633_6400, 24), // 198.51.100.0/24 TEST-NET-2
    (0xcb00_7100, 24), // 203.0.113.0/24 TEST-NET-3
    (0xe000_0000, 4),  // 224.0.0.0/4 multicast
    (0xf000_0000, 4),  // 240.0.0.0/4 reserved, incl. broadcast
];

/// Special-purpose blocks inside 2000::/3 that aren't global unicast for the broad test.
const V6_NOT_GLOBAL: &[(u128, u8)] = &[
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23), // 2001::/23 IETF protocol assignments
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // documentation
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 6to4
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20), // documentation (RFC 9637)
];

/// Public addresses of an IPv4 range, or global-unicast addresses of an IPv6 range: the count
/// the broad-rule test compares with a /8 or a /16 (bundles.md §2).
pub fn public_size(range: &IpRange) -> u128 {
    if range.v4 {
        let mut total = range.size();
        for &(net, len) in V4_NOT_PUBLIC {
            if let Some(block) = IpRange::cidr(IpAddr::V4(Ipv4Addr::from(net)), len) {
                total = total.saturating_sub(overlap_size(range, &block));
            }
        }
        total
    } else {
        let global = IpRange {
            v4: false,
            first: 0x2000u128 << 112,
            last: (0x4000u128 << 112).wrapping_sub(1),
        };
        let mut total = intersection(range, &global).map(|r| r.size()).unwrap_or(0);
        for &(net, len) in V6_NOT_GLOBAL {
            if let Some(block) = IpRange::cidr(IpAddr::V6(Ipv6Addr::from(net)), len) {
                total = total.saturating_sub(overlap_size(range, &block));
            }
        }
        total
    }
}

fn intersection(a: &IpRange, b: &IpRange) -> Option<IpRange> {
    if !a.overlaps(b) {
        return None;
    }
    Some(IpRange {
        v4: a.v4,
        first: a.first.max(b.first),
        last: a.last.min(b.last),
    })
}

fn overlap_size(a: &IpRange, b: &IpRange) -> u128 {
    intersection(a, b).map(|r| r.size()).unwrap_or(0)
}

/// True when an IP rule's range is broad (bundles.md §2): at least a /8 of public IPv4, or a
/// /16 of global unicast IPv6.
pub fn is_broad_range(range: &IpRange) -> bool {
    if range.v4 {
        public_size(range) >= 1u128 << 24
    } else {
        public_size(range) >= 1u128 << 112
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn go_text() {
        assert_eq!(go_ip_string(ip("1.2.3.4")), "1.2.3.4");
        assert_eq!(go_ip_string(ip("::ffff:1.2.3.4")), "1.2.3.4");
        assert_eq!(go_ip_string(ip("2001:db8::1")), "2001:db8::1");
        assert_eq!(go_ip_string(ip("2001:db8:0:0:1:0:0:1")), "2001:db8::1:0:0:1");
        assert_eq!(go_ip_string(ip("2001:0:0:1:0:0:0:1")), "2001:0:0:1::1");
        assert_eq!(go_ip_string(ip("2001:db8:1:1:1:1:0:1")), "2001:db8:1:1:1:1:0:1");
        assert_eq!(go_ip_string(ip("::")), "::");
        assert_eq!(go_ip_string(ip("::1")), "::1");
        assert_eq!(go_ip_string(ip("::1.2.3.4")), "::102:304");
        assert_eq!(go_ip_string(ip("fe80::")), "fe80::");
        assert_eq!(netip_string(ip("::ffff:1.2.3.4")), "::ffff:1.2.3.4");
        assert_eq!(go_ip_string(ip("1::")), "1::");
        assert_eq!(go_ip_string(ip("FE80::ABCD")), "fe80::abcd");
        assert_eq!(go_ip_string(ip("2001:db8:0:1:0:0:0:1")), "2001:db8:0:1::1");
    }

    #[test]
    fn parse_go() {
        assert_eq!(parse_go_ip("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse_go_ip("01.2.3.4"), None);
        assert_eq!(parse_go_ip("1.2.3"), None);
        assert_eq!(parse_go_ip("fe80::1%eth0"), Some(ip("fe80::1")));
        assert_eq!(parse_go_ip("fe80::1%"), None);
        assert!(is_go_ip_string("::ffff:1.2.3.4"));
        assert!(!is_go_ip_string("example.com"));
    }

    #[test]
    fn ranges() {
        let r = IpRange::parse("10.1.2.3/8").unwrap();
        assert_eq!(r.to_text(), "10.0.0.0/8");
        assert!(r.contains(ip("10.255.0.1")));
        assert!(r.contains(ip("::ffff:10.0.0.1")));
        assert!(!r.contains(ip("11.0.0.0")));
        assert_eq!(r.first_bytes()[10..12], [0xff, 0xff]);
        assert_eq!(r.first_bytes()[12], 10);
        let s = IpRange::parse("::ffff:1.2.3.4").unwrap();
        assert!(s.v4);
        assert_eq!(s.to_text(), "1.2.3.4");
        assert_eq!(
            IpRange::parse("2001:db8::/32").unwrap().to_text(),
            "2001:db8::/32"
        );
        assert!(IpRange::parse("1.2.3.4/33").is_none());
        assert!(IpRange::parse("1.2.3.4/").is_none());
        assert_eq!(IpRange::parse("::/0").unwrap().prefix_len(), Some(0));
        // An IPv4-mapped prefix of /96 or longer is the IPv4 prefix (rules.md §6).
        assert_eq!(
            IpRange::parse("::ffff:1.2.3.0/120").unwrap().to_text(),
            "1.2.3.0/24"
        );
        assert!(IpRange::parse("01.2.3.4").is_none());
        assert!(IpRange::parse("fe80::1%eth0/64").is_none());
        // `to_text` reads back, ranges included.
        let odd = IpRange {
            v4: true,
            first: 0x0102_0304,
            last: 0x0102_0306,
        };
        assert_eq!(odd.to_text(), "1.2.3.4-1.2.3.6");
        for r in [
            odd,
            IpRange::parse("10.0.0.0/8").unwrap(),
            IpRange::parse("2001:db8::1").unwrap(),
        ] {
            assert_eq!(IpRange::from_text(&r.to_text()), Some(r));
        }
        assert!(IpRange::from_text("1.2.3.6-1.2.3.4").is_none());
        assert!(IpRange::from_text("1.2.3.4-::1").is_none());
    }

    #[test]
    fn broad() {
        assert!(is_broad_range(&IpRange::parse("8.0.0.0/8").unwrap()));
        assert!(!is_broad_range(&IpRange::parse("8.0.0.0/9").unwrap()));
        assert!(!is_broad_range(&IpRange::parse("10.0.0.0/8").unwrap()));
        assert!(!is_broad_range(&IpRange::parse("224.0.0.0/3").unwrap()));
        assert!(!is_broad_range(&IpRange::parse("100.64.0.0/10").unwrap()));
        assert!(is_broad_range(&IpRange::parse("0.0.0.0/0").unwrap()));
        assert!(is_broad_range(&IpRange::parse("2a00::/16").unwrap()));
        assert!(!is_broad_range(&IpRange::parse("2a00::/17").unwrap()));
        assert!(!is_broad_range(&IpRange::parse("fc00::/7").unwrap()));
        assert!(!is_broad_range(&IpRange::parse("2002::/16").unwrap()));
    }
}
