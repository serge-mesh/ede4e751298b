//! A small builder for hand-made DNS messages in tests, including malformed ones (compression
//! pointers anywhere, wrong counts, trailing bytes), plus fixture loading.

#![allow(dead_code, reason = "test helpers: each test module uses only part of them")]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::answer::SentQuery;
use crate::name::QName;
use crate::types::{class, rtype};

/// Wire form of a presentation name (no escapes; tests only).
pub(crate) fn n(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for l in name.trim_end_matches('.').split('.') {
        if l.is_empty() {
            continue;
        }
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    out
}

/// A compression pointer to `offset`.
pub(crate) fn ptr(offset: u16) -> Vec<u8> {
    (0xC000u16 | offset).to_be_bytes().to_vec()
}

/// A message under construction. Records must be added in section order.
#[derive(Clone)]
pub(crate) struct Msg {
    pub buf: Vec<u8>,
    pub counts: [u16; 4],
    pub fix_counts: bool,
}

impl Msg {
    /// A header with these flag bytes and no records.
    pub fn with_flags(id: u16, b2: u8, b3: u8) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.push(b2);
        buf.push(b3);
        buf.extend_from_slice(&[0; 8]);
        Self {
            buf,
            counts: [0; 4],
            fix_counts: true,
        }
    }

    /// A recursive query for `name`/`qtype`/IN.
    pub fn query(id: u16, name: &str, qtype: u16) -> Self {
        let mut m = Self::with_flags(id, 0x01, 0x00);
        m.question(&n(name), qtype, class::IN);
        m
    }

    /// A response (QR, RD, RA) with `rcode` for `name`/`qtype`/IN.
    pub fn response(id: u16, name: &str, qtype: u16, rcode: u8) -> Self {
        let mut m = Self::with_flags(id, 0x81, 0x80 | (rcode & 0x0F));
        m.question(&n(name), qtype, class::IN);
        m
    }

    pub fn question(&mut self, name: &[u8], qtype: u16, qclass: u16) -> &mut Self {
        self.buf.extend_from_slice(name);
        self.buf.extend_from_slice(&qtype.to_be_bytes());
        self.buf.extend_from_slice(&qclass.to_be_bytes());
        self.counts[0] += 1;
        self
    }

    /// Current length: the offset the next byte lands at (for pointers).
    pub fn here(&self) -> u16 {
        self.buf.len() as u16
    }

    /// Adds a record to section 1 (answer), 2 (authority) or 3 (additional).
    pub fn rr(&mut self, section: usize, owner: &[u8], rt: u16, ttl: u32, rdata: &[u8]) -> &mut Self {
        self.rr_class(section, owner, rt, class::IN, ttl, rdata)
    }

    pub fn rr_class(
        &mut self,
        section: usize,
        owner: &[u8],
        rt: u16,
        cls: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> &mut Self {
        self.buf.extend_from_slice(owner);
        self.buf.extend_from_slice(&rt.to_be_bytes());
        self.buf.extend_from_slice(&cls.to_be_bytes());
        self.buf.extend_from_slice(&ttl.to_be_bytes());
        self.buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(rdata);
        self.counts[section] += 1;
        self
    }

    /// Adds an OPT to the additional section.
    pub fn opt(
        &mut self,
        udp: u16,
        ext_rcode: u8,
        version: u8,
        do_bit: bool,
        options: &[(u16, &[u8])],
    ) -> &mut Self {
        let mut data = Vec::new();
        for (code, p) in options {
            data.extend_from_slice(&code.to_be_bytes());
            data.extend_from_slice(&(p.len() as u16).to_be_bytes());
            data.extend_from_slice(p);
        }
        let ttl = u32::from_be_bytes([ext_rcode, version, if do_bit { 0x80 } else { 0 }, 0]);
        self.rr_class(3, &[0], rtype::OPT, udp, ttl, &data)
    }

    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Overrides the header counts instead of using the counted ones.
    pub fn set_counts(&mut self, qd: u16, an: u16, ns: u16, ar: u16) -> &mut Self {
        self.counts = [qd, an, ns, ar];
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut b = self.buf.clone();
        for (i, c) in self.counts.iter().enumerate() {
            b[4 + 2 * i..6 + 2 * i].copy_from_slice(&c.to_be_bytes());
        }
        b
    }
}

pub(crate) fn a(ip: &str) -> Vec<u8> {
    ip.parse::<Ipv4Addr>().unwrap().octets().to_vec()
}

pub(crate) fn aaaa(ip: &str) -> Vec<u8> {
    ip.parse::<Ipv6Addr>().unwrap().octets().to_vec()
}

pub(crate) fn soa(mname: &[u8], rname: &[u8], serial: u32, minimum: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(mname);
    v.extend_from_slice(rname);
    for x in [serial, 7200, 3600, 1_209_600, minimum] {
        v.extend_from_slice(&x.to_be_bytes());
    }
    v
}

/// RRSIG data: covering `covered`, signed by `signer` (uncompressed), with a dummy signature.
pub(crate) fn rrsig(covered: u16, labels: u8, orig_ttl: u32, signer: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&covered.to_be_bytes());
    v.push(13); // ECDSAP256SHA256
    v.push(labels);
    v.extend_from_slice(&orig_ttl.to_be_bytes());
    v.extend_from_slice(&0x6b00_0000u32.to_be_bytes());
    v.extend_from_slice(&0x6a00_0000u32.to_be_bytes());
    v.extend_from_slice(&12345u16.to_be_bytes());
    v.extend_from_slice(&n(signer));
    v.extend_from_slice(&[0xAB; 64]);
    v
}

/// The type bitmap of NSEC/NSEC3 data (RFC 4034 §4.1.2).
pub(crate) fn type_bitmap(types: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut windows: std::collections::BTreeMap<u8, [u8; 32]> = Default::default();
    for &t in types {
        let w = windows.entry((t >> 8) as u8).or_insert([0; 32]);
        let low = (t & 0xFF) as usize;
        w[low / 8] |= 0x80 >> (low % 8);
    }
    for (win, bits) in windows {
        let len = bits.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        out.push(win);
        out.push(len as u8);
        out.extend_from_slice(&bits[..len]);
    }
    out
}

pub(crate) fn nsec(next: &str, types: &[u16]) -> Vec<u8> {
    let mut v = n(next);
    v.extend_from_slice(&type_bitmap(types));
    v
}

pub(crate) fn nsec3(types: &[u16]) -> Vec<u8> {
    let mut v = vec![1, 0, 0, 0, 0]; // SHA-1, flags 0, 0 iterations, no salt
    v.push(20);
    v.extend_from_slice(&[0x5A; 20]);
    v.extend_from_slice(&type_bitmap(types));
    v
}

/// SVCB/HTTPS data: priority, target (uncompressed), and params as given (key, value).
pub(crate) fn svcb(priority: u16, target: &str, params: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut v = priority.to_be_bytes().to_vec();
    v.extend_from_slice(&n(target));
    for (k, val) in params {
        v.extend_from_slice(&k.to_be_bytes());
        v.extend_from_slice(&(val.len() as u16).to_be_bytes());
        v.extend_from_slice(val);
    }
    v
}

pub(crate) fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A recorded upstream exchange from `fixtures/wire/<name>.txt`.
pub(crate) struct Fixture {
    pub name: &'static str,
    pub query: Vec<u8>,
    pub answer: Vec<u8>,
}

pub(crate) const RECORDED: &[&str] = &[
    "plain-a",
    "cname-chain",
    "signed-nsec3-nxdomain",
    "nxdomain-soa",
    "https-hints",
    "dname",
    "dot-padded-a",
    "nodata-signed",
    "wildcard-nsec3",
];

pub(crate) fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/wire")
}

pub(crate) fn fixture(name: &'static str) -> Fixture {
    let text = std::fs::read_to_string(fixtures_dir().join(format!("{name}.txt"))).unwrap();
    let mut query = None;
    let mut answer = None;
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("query ") {
            query = Some(hex(h));
        } else if let Some(h) = line.strip_prefix("answer ") {
            answer = Some(hex(h));
        }
    }
    Fixture {
        name,
        query: query.unwrap(),
        answer: answer.unwrap(),
    }
}

/// The client queries of `fixtures/wire/queries.txt`.
pub(crate) fn queries() -> Vec<(String, Vec<u8>)> {
    let text = std::fs::read_to_string(fixtures_dir().join("queries.txt")).unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let (name, h) = l.split_once(' ').unwrap();
            (name.to_string(), hex(h))
        })
        .collect()
}

/// What a recorded query sent: its ID and question.
pub(crate) struct Sent {
    pub id: u16,
    pub qname: QName,
    pub qtype: u16,
    pub qclass: u16,
}

impl Sent {
    pub fn of(query: &[u8]) -> Self {
        let q = crate::query::check_query(query).unwrap();
        Self {
            id: q.id,
            qname: q.qname().clone(),
            qtype: q.qtype,
            qclass: q.qclass,
        }
    }

    pub fn sent(&self) -> SentQuery<'_> {
        SentQuery {
            id: self.id,
            qname: self.qname.as_name(),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }
}

/// A `SentQuery` for a test response built with [`Msg::response`].
pub(crate) fn sent_for(id: u16, name: &str, qtype: u16) -> Sent {
    Sent {
        id,
        qname: QName::from_text(name).unwrap(),
        qtype,
        qclass: class::IN,
    }
}
