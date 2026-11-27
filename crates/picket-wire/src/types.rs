//! Record type, class and rcode numbers, and their mnemonics for logs and config (api.md §5:
//! `"qtype":"A"`, `"rcode":"NOERROR"`). Unknown types read and print as `TYPEnnn` and unknown
//! classes as `CLASSnnn` (RFC 3597 §5), unknown rcodes as `RCODEnnn` (12 bits, RFC 6891 §6.1.3).

use std::fmt;

/// Record types used by this crate (IANA "Resource Record (RR) TYPEs").
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const MD: u16 = 3;
    pub const MF: u16 = 4;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const MB: u16 = 7;
    pub const MG: u16 = 8;
    pub const MR: u16 = 9;
    pub const NULL: u16 = 10;
    pub const PTR: u16 = 12;
    pub const HINFO: u16 = 13;
    pub const MINFO: u16 = 14;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const RP: u16 = 17;
    pub const AFSDB: u16 = 18;
    pub const RT: u16 = 21;
    pub const SIG: u16 = 24;
    pub const KEY: u16 = 25;
    pub const PX: u16 = 26;
    pub const AAAA: u16 = 28;
    pub const NXT: u16 = 30;
    pub const SRV: u16 = 33;
    pub const NAPTR: u16 = 35;
    pub const DNAME: u16 = 39;
    pub const OPT: u16 = 41;
    pub const DS: u16 = 43;
    pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47;
    pub const DNSKEY: u16 = 48;
    pub const NSEC3: u16 = 50;
    pub const NSEC3PARAM: u16 = 51;
    pub const SVCB: u16 = 64;
    pub const HTTPS: u16 = 65;
    pub const TKEY: u16 = 249;
    pub const TSIG: u16 = 250;
    pub const IXFR: u16 = 251;
    pub const AXFR: u16 = 252;
    pub const MAILB: u16 = 253;
    pub const MAILA: u16 = 254;
    pub const ANY: u16 = 255;
}

/// Classes.
pub mod class {
    pub const IN: u16 = 1;
    pub const CH: u16 = 3;
    pub const HS: u16 = 4;
    pub const NONE: u16 = 254;
    pub const ANY: u16 = 255;
}

/// Response codes, including the extended ones carried in OPT (RFC 6891 §6.1.3).
pub mod rcode {
    pub const NOERROR: u16 = 0;
    pub const FORMERR: u16 = 1;
    pub const SERVFAIL: u16 = 2;
    pub const NXDOMAIN: u16 = 3;
    pub const NOTIMP: u16 = 4;
    pub const REFUSED: u16 = 5;
    pub const YXDOMAIN: u16 = 6;
    pub const BADVERS: u16 = 16;
}

/// EDNS option codes used by this crate.
pub mod edns_code {
    /// Client Subnet (RFC 7871).
    pub const CLIENT_SUBNET: u16 = 8;
    /// DNS Cookies (RFC 7873).
    pub const COOKIE: u16 = 10;
    /// edns-tcp-keepalive (RFC 7828).
    pub const TCP_KEEPALIVE: u16 = 11;
    /// Padding (RFC 7830).
    pub const PADDING: u16 = 12;
    /// Extended DNS Error (RFC 8914).
    pub const EDE: u16 = 15;
}

/// Extended DNS Error INFO-CODEs the edge sends and the `dns` lookup presets test (RFC 8914 §4;
/// edge.md §4 EDE, providers.md §5 `dns`).
pub mod ede_code {
    pub const OTHER: u16 = 0;
    pub const STALE_ANSWER: u16 = 3;
    pub const FORGED_ANSWER: u16 = 4;
    pub const BLOCKED: u16 = 15;
    pub const CENSORED: u16 = 16;
    pub const FILTERED: u16 = 17;
    pub const PROHIBITED: u16 = 18;
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
    pub const NETWORK_ERROR: u16 = 23;
    /// Quad9 marks locally synthesised NXDOMAINs with it (providers.md §5 `dns`).
    pub const SYNTHESIZED: u16 = 29;
}

const TYPES: &[(u16, &str)] = &[
    (1, "A"),
    (2, "NS"),
    (3, "MD"),
    (4, "MF"),
    (5, "CNAME"),
    (6, "SOA"),
    (7, "MB"),
    (8, "MG"),
    (9, "MR"),
    (10, "NULL"),
    (11, "WKS"),
    (12, "PTR"),
    (13, "HINFO"),
    (14, "MINFO"),
    (15, "MX"),
    (16, "TXT"),
    (17, "RP"),
    (18, "AFSDB"),
    (19, "X25"),
    (20, "ISDN"),
    (21, "RT"),
    (22, "NSAP"),
    (23, "NSAP-PTR"),
    (24, "SIG"),
    (25, "KEY"),
    (26, "PX"),
    (27, "GPOS"),
    (28, "AAAA"),
    (29, "LOC"),
    (30, "NXT"),
    (31, "EID"),
    (32, "NIMLOC"),
    (33, "SRV"),
    (34, "ATMA"),
    (35, "NAPTR"),
    (36, "KX"),
    (37, "CERT"),
    (38, "A6"),
    (39, "DNAME"),
    (40, "SINK"),
    (41, "OPT"),
    (42, "APL"),
    (43, "DS"),
    (44, "SSHFP"),
    (45, "IPSECKEY"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (49, "DHCID"),
    (50, "NSEC3"),
    (51, "NSEC3PARAM"),
    (52, "TLSA"),
    (53, "SMIMEA"),
    (55, "HIP"),
    (56, "NINFO"),
    (57, "RKEY"),
    (58, "TALINK"),
    (59, "CDS"),
    (60, "CDNSKEY"),
    (61, "OPENPGPKEY"),
    (62, "CSYNC"),
    (63, "ZONEMD"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (66, "DSYNC"),
    (99, "SPF"),
    (104, "NID"),
    (105, "L32"),
    (106, "L64"),
    (107, "LP"),
    (108, "EUI48"),
    (109, "EUI64"),
    (249, "TKEY"),
    (250, "TSIG"),
    (251, "IXFR"),
    (252, "AXFR"),
    (253, "MAILB"),
    (254, "MAILA"),
    (255, "ANY"),
    (256, "URI"),
    (257, "CAA"),
    (258, "AVC"),
    (259, "DOA"),
    (260, "AMTRELAY"),
    (261, "RESINFO"),
    (262, "WALLET"),
    (32768, "TA"),
    (32769, "DLV"),
];

const CLASSES: &[(u16, &str)] = &[(1, "IN"), (3, "CH"), (4, "HS"), (254, "NONE"), (255, "ANY")];

/// The largest rcode: 4 header bits and 8 OPT bits (RFC 6891 §6.1.3).
pub const MAX_RCODE: u16 = 0x0FFF;

const RCODES: &[(u16, &str)] = &[
    (0, "NOERROR"),
    (1, "FORMERR"),
    (2, "SERVFAIL"),
    (3, "NXDOMAIN"),
    (4, "NOTIMP"),
    (5, "REFUSED"),
    (6, "YXDOMAIN"),
    (7, "YXRRSET"),
    (8, "NXRRSET"),
    (9, "NOTAUTH"),
    (10, "NOTZONE"),
    (11, "DSOTYPENI"),
    (16, "BADVERS"),
    (17, "BADKEY"),
    (18, "BADTIME"),
    (19, "BADMODE"),
    (20, "BADNAME"),
    (21, "BADALG"),
    (22, "BADTRUNC"),
    (23, "BADCOOKIE"),
];

/// The mnemonic of a record type, if it has one.
pub fn rtype_mnemonic(t: u16) -> Option<&'static str> {
    TYPES.iter().find(|(n, _)| *n == t).map(|(_, s)| *s)
}

/// A record type from its mnemonic (ASCII case-insensitive) or `TYPEnnn`.
pub fn rtype_from_text(s: &str) -> Option<u16> {
    if let Some((n, _)) = TYPES.iter().find(|(_, m)| m.eq_ignore_ascii_case(s)) {
        return Some(*n);
    }
    parse_numbered(s, "TYPE")
}

/// The mnemonic of an rcode, if it has one.
pub fn rcode_mnemonic(r: u16) -> Option<&'static str> {
    RCODES.iter().find(|(n, _)| *n == r).map(|(_, s)| *s)
}

/// An rcode from its mnemonic (ASCII case-insensitive) or `RCODEnnn`, at most [`MAX_RCODE`].
pub fn rcode_from_text(s: &str) -> Option<u16> {
    if let Some((n, _)) = RCODES.iter().find(|(_, m)| m.eq_ignore_ascii_case(s)) {
        return Some(*n);
    }
    parse_numbered(s, "RCODE").filter(|&r| r <= MAX_RCODE)
}

/// The mnemonic of a class, if it has one.
pub fn class_mnemonic(c: u16) -> Option<&'static str> {
    CLASSES.iter().find(|(n, _)| *n == c).map(|(_, s)| *s)
}

/// A class from its mnemonic (ASCII case-insensitive) or `CLASSnnn`.
pub fn class_from_text(s: &str) -> Option<u16> {
    if let Some((n, _)) = CLASSES.iter().find(|(_, m)| m.eq_ignore_ascii_case(s)) {
        return Some(*n);
    }
    parse_numbered(s, "CLASS")
}

fn parse_numbered(s: &str, prefix: &str) -> Option<u16> {
    let head = s.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let digits = s.get(prefix.len()..)?;
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Displays a record type as its mnemonic or `TYPEnnn`, without allocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeText(pub u16);

impl fmt::Display for TypeText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match rtype_mnemonic(self.0) {
            Some(m) => f.write_str(m),
            None => write!(f, "TYPE{}", self.0),
        }
    }
}

/// Displays an rcode as its mnemonic or `RCODEnnn`, without allocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RcodeText(pub u16);

impl fmt::Display for RcodeText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match rcode_mnemonic(self.0) {
            Some(m) => f.write_str(m),
            None => write!(f, "RCODE{}", self.0),
        }
    }
}

/// Displays a class as its mnemonic or `CLASSnnn`, without allocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassText(pub u16);

impl fmt::Display for ClassText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match class_mnemonic(self.0) {
            Some(m) => f.write_str(m),
            None => write!(f, "CLASS{}", self.0),
        }
    }
}

/// True for types whose RDATA may hold compressed names that hickory 0.26 doesn't decode
/// itself: such a record kept as opaque bytes would copy pointers into the upstream's message
/// (edge.md §7 step 1; RFC 3597 §4 lists NS … MX as compressible and RP … SRV as ones receivers
/// must decompress).
pub(crate) fn may_hold_compressed_names(t: u16) -> bool {
    matches!(
        t,
        rtype::NS
            | rtype::MD
            | rtype::MF
            | rtype::CNAME
            | rtype::SOA
            | rtype::MB
            | rtype::MG
            | rtype::MR
            | rtype::PTR
            | rtype::MINFO
            | rtype::MX
            | rtype::RP
            | rtype::AFSDB
            | rtype::RT
            | rtype::SIG
            | rtype::PX
            | rtype::NXT
            | rtype::NAPTR
            | rtype::SRV
    )
}

/// QTYPE-only types that never appear as records (RFC 6895 §3.1: meta-types and OPT).
pub(crate) fn is_meta_type(t: u16) -> bool {
    matches!(
        t,
        rtype::OPT | rtype::IXFR | rtype::AXFR | rtype::MAILB | rtype::MAILA | rtype::ANY
    ) || (128..=255).contains(&t) && t != rtype::TSIG && t != rtype::TKEY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_tables() {
        assert_eq!(rtype_mnemonic(1), Some("A"));
        assert_eq!(rtype_from_text("aaaa"), Some(28));
        assert_eq!(rtype_from_text("HTTPS"), Some(65));
        assert_eq!(rtype_from_text("TYPE65"), Some(65));
        assert_eq!(rtype_from_text("type1234"), Some(1234));
        assert_eq!(rtype_from_text("TYPE65536"), None);
        assert_eq!(rtype_from_text("TYPE"), None);
        assert_eq!(rtype_from_text("TYPE+1"), None);
        assert_eq!(rtype_from_text("BOGUS"), None);
        assert_eq!(TypeText(1234).to_string(), "TYPE1234");
        assert_eq!(TypeText(64).to_string(), "SVCB");
        assert_eq!(TypeText(rtype::NSEC3).to_string(), "NSEC3");
    }

    #[test]
    fn rcode_tables() {
        assert_eq!(RcodeText(3).to_string(), "NXDOMAIN");
        assert_eq!(RcodeText(16).to_string(), "BADVERS");
        assert_eq!(RcodeText(4000).to_string(), "RCODE4000");
        assert_eq!(rcode_from_text("servfail"), Some(2));
        assert_eq!(rcode_from_text("RCODE12"), Some(12));
        assert_eq!(rcode_from_text("nope"), None);
        // Rcodes are 12 bits (RFC 6891 §6.1.3).
        assert_eq!(rcode_from_text("RCODE4095"), Some(4095));
        assert_eq!(rcode_from_text("RCODE4096"), None);
        assert_eq!(rcode_from_text("RCODE65535"), None);
    }

    #[test]
    fn tables_sorted_and_round_trip() {
        for t in [TYPES, CLASSES, RCODES] {
            assert!(t.windows(2).all(|w| w[0].0 < w[1].0));
        }
        for &(n, m) in TYPES {
            assert_eq!(rtype_from_text(m), Some(n), "{m}");
            assert_eq!(TypeText(n).to_string(), m);
        }
        for &(n, m) in RCODES {
            assert_eq!(rcode_from_text(m), Some(n), "{m}");
        }
        for &(n, m) in CLASSES {
            assert_eq!(class_from_text(m), Some(n), "{m}");
        }
    }

    #[test]
    fn class_tables() {
        assert_eq!(ClassText(1).to_string(), "IN");
        assert_eq!(ClassText(42).to_string(), "CLASS42");
        assert_eq!(class_from_text("ch"), Some(3));
        assert_eq!(class_from_text("CLASS42"), Some(42));
        assert_eq!(class_from_text("CLASS"), None);
        assert_eq!(class_from_text("XX"), None);
    }

    #[test]
    fn compressible_and_meta() {
        assert!(may_hold_compressed_names(rtype::RP));
        assert!(!may_hold_compressed_names(rtype::A));
        assert!(!may_hold_compressed_names(rtype::DNAME));
        assert!(is_meta_type(rtype::ANY));
        assert!(is_meta_type(rtype::OPT));
        assert!(!is_meta_type(rtype::TSIG));
        assert!(!is_meta_type(rtype::A));
    }
}
