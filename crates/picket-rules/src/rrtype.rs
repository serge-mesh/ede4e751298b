//! DNS RR type and rcode mnemonics as AdGuard reads them (miekg/dns `StringToType` and
//! `StringToRcode`, which urlfilter uses for `$dnstype` and `$dnsrewrite`).

/// RR type mnemonics → numbers (miekg/dns v1.1.x `TypeToString`, reversed). `None` and
/// `Reserved` are present in miekg's table but urlfilter refuses them.
const TYPES: &[(&str, u16)] = &[
    ("A", 1),
    ("NS", 2),
    ("MD", 3),
    ("MF", 4),
    ("CNAME", 5),
    ("SOA", 6),
    ("MB", 7),
    ("MG", 8),
    ("MR", 9),
    ("NULL", 10),
    ("PTR", 12),
    ("HINFO", 13),
    ("MINFO", 14),
    ("MX", 15),
    ("TXT", 16),
    ("RP", 17),
    ("AFSDB", 18),
    ("X25", 19),
    ("ISDN", 20),
    ("RT", 21),
    ("NSAP-PTR", 23),
    ("SIG", 24),
    ("KEY", 25),
    ("PX", 26),
    ("GPOS", 27),
    ("AAAA", 28),
    ("LOC", 29),
    ("NXT", 30),
    ("EID", 31),
    ("NIMLOC", 32),
    ("SRV", 33),
    ("ATMA", 34),
    ("NAPTR", 35),
    ("KX", 36),
    ("CERT", 37),
    ("DNAME", 39),
    ("OPT", 41),
    ("APL", 42),
    ("DS", 43),
    ("SSHFP", 44),
    ("IPSECKEY", 45),
    ("RRSIG", 46),
    ("NSEC", 47),
    ("DNSKEY", 48),
    ("DHCID", 49),
    ("NSEC3", 50),
    ("NSEC3PARAM", 51),
    ("TLSA", 52),
    ("SMIMEA", 53),
    ("HIP", 55),
    ("NINFO", 56),
    ("RKEY", 57),
    ("TALINK", 58),
    ("CDS", 59),
    ("CDNSKEY", 60),
    ("OPENPGPKEY", 61),
    ("CSYNC", 62),
    ("ZONEMD", 63),
    ("SVCB", 64),
    ("HTTPS", 65),
    ("SPF", 99),
    ("UINFO", 100),
    ("UID", 101),
    ("GID", 102),
    ("UNSPEC", 103),
    ("NID", 104),
    ("L32", 105),
    ("L64", 106),
    ("LP", 107),
    ("EUI48", 108),
    ("EUI64", 109),
    ("NXNAME", 128),
    ("TKEY", 249),
    ("TSIG", 250),
    ("IXFR", 251),
    ("AXFR", 252),
    ("MAILB", 253),
    ("MAILA", 254),
    ("ANY", 255),
    ("URI", 256),
    ("CAA", 257),
    ("AVC", 258),
    ("AMTRELAY", 260),
    ("RESINFO", 261),
    ("TA", 32768),
    ("DLV", 32769),
];

/// Common RR type numbers.
pub mod types {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const SVCB: u16 = 64;
    pub const HTTPS: u16 = 65;
    pub const ANY: u16 = 255;
}

/// Parses an RR type mnemonic in any letter case, as urlfilter's `strToRRType` does: `NONE` and
/// `RESERVED` are refused, as are unknown names (no `TYPEnnn` form).
pub fn parse_rr_type(s: &str) -> Option<u16> {
    if s.eq_ignore_ascii_case("none") || s.eq_ignore_ascii_case("reserved") {
        return None;
    }
    TYPES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(s))
        .map(|&(_, v)| v)
}

/// The mnemonic of an RR type, or `TYPEnnn`.
pub fn rr_type_name(t: u16) -> String {
    match TYPES.iter().find(|&&(_, v)| v == t) {
        Some((n, _)) => (*n).to_string(),
        None => format!("TYPE{t}"),
    }
}

/// Rcode mnemonics → numbers (miekg/dns `StringToRcode`; `BADVERS` shares 16 with `BADSIG`).
const RCODES: &[(&str, u16)] = &[
    ("NOERROR", 0),
    ("FORMERR", 1),
    ("SERVFAIL", 2),
    ("NXDOMAIN", 3),
    ("NOTIMP", 4),
    ("REFUSED", 5),
    ("YXDOMAIN", 6),
    ("YXRRSET", 7),
    ("NXRRSET", 8),
    ("NOTAUTH", 9),
    ("NOTZONE", 10),
    ("DSOTYPENI", 11),
    ("BADSIG", 16),
    ("BADVERS", 16),
    ("BADKEY", 17),
    ("BADTIME", 18),
    ("BADMODE", 19),
    ("BADNAME", 20),
    ("BADALG", 21),
    ("BADTRUNC", 22),
    ("BADCOOKIE", 23),
];

/// Common rcodes.
pub mod rcodes {
    pub const NOERROR: u16 = 0;
    pub const SERVFAIL: u16 = 2;
    pub const NXDOMAIN: u16 = 3;
    pub const REFUSED: u16 = 5;
}

/// Parses an rcode mnemonic in any letter case.
pub fn parse_rcode(s: &str) -> Option<u16> {
    RCODES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(s))
        .map(|&(_, v)| v)
}

/// The mnemonic of an rcode, or its number.
pub fn rcode_name(r: u16) -> String {
    match RCODES.iter().find(|&&(_, v)| v == r) {
        Some((n, _)) => (*n).to_string(),
        None => r.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(parse_rr_type("aaaa"), Some(28));
        assert_eq!(parse_rr_type("HTTPS"), Some(65));
        assert_eq!(parse_rr_type("nsap-ptr"), Some(23));
        assert_eq!(parse_rr_type("None"), None);
        assert_eq!(parse_rr_type("TYPE65"), None);
        assert_eq!(rr_type_name(65), "HTTPS");
        assert_eq!(rr_type_name(999), "TYPE999");
        assert_eq!(parse_rcode("nxdomain"), Some(3));
        assert_eq!(rcode_name(5), "REFUSED");
    }
}
