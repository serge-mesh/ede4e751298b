//! The `domain` side of the differential oracle (build-and-test.md §4): NLnet Labs' `domain`
//! 0.12 decodes a message on its own, and the facts response checks use are recomputed from that
//! decode. Shared, by `#[path]`, between picket-wire's unit tests and the `fuzz/wire` targets, so
//! it depends on `domain` only.
//!
//! An AliasMode SVCB/HTTPS record's SvcParams aren't decoded: recipients MUST ignore them (RFC
//! 9460 §2.4.2), so the edge neither checks them nor takes hints from them.

#![allow(
    dead_code,
    reason = "shared by `#[path]` with the fuzz/wire targets, which use other parts of it"
)]

use std::net::IpAddr;

use domain::base::Message;
use domain::base::name::{ParsedName, ToLabelIter};
use domain::rdata::AllRecordData;
use domain::rdata::svcb::value::AllValues;

type Data<'a> = AllRecordData<&'a [u8], ParsedName<&'a [u8]>>;

fn lower_wire(name: &ParsedName<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for l in name.iter_labels() {
        let b: &[u8] = l.as_ref();
        out.push(b.len() as u8);
        out.extend(b.iter().map(u8::to_ascii_lowercase));
    }
    out
}

/// A record as `domain` decoded it.
pub struct DRec {
    pub section: usize,
    pub owner: Vec<u8>,
    pub rtype: u16,
    pub class: u16,
    pub addr: Option<IpAddr>,
    /// CNAME or DNAME target.
    pub target: Option<Vec<u8>>,
    pub svcb_target: Option<Vec<u8>>,
    pub hints: Vec<(IpAddr, bool)>,
    /// What decides that two records of one owner, type and class are the same, as the scrub's
    /// duplicate rule compares hickory's decoded data (names case-insensitively, never their
    /// compression): set for the types whose data the facts use; `None` for the others, whose
    /// duplicates change no fact.
    pub data_key: Option<Vec<u8>>,
}

/// `domain`'s decode of a whole message: header, question and every record of every section;
/// `Err` with the reason when it rejects the message.
pub fn domain_decode(msg: &[u8]) -> Result<(Vec<u8>, u16, Vec<DRec>), String> {
    let m = Message::from_octets(msg).map_err(|e| format!("header: {e}"))?;
    let mut qs = m.question();
    let q = qs
        .next()
        .ok_or("no question")?
        .map_err(|e| format!("question: {e}"))?;
    let qname = lower_wire(q.qname());
    let qtype = q.qtype().to_int();
    let mut out = Vec::new();
    let sections = [m.answer(), m.authority(), m.additional()];
    for (i, sec) in sections.into_iter().enumerate() {
        let sec = sec.map_err(|e| format!("section {i}: {e}"))?;
        for rec in sec {
            let rec = rec.map_err(|e| format!("record header: {e}"))?;
            let parsed = match rec.to_record::<Data<'_>>() {
                Ok(p) => p,
                // Record data hickory leaves opaque isn't checked by edge.md §7 (RFC 3597 §4):
                // `domain` refusing it isn't a mismatch. Types hickory decodes must agree.
                Err(_) if !hickory_decodes(rec.rtype().to_int()) => continue,
                Err(e) => return Err(format!("record data ({}): {e}", rec.rtype())),
            };
            let Some(r) = parsed else { continue };
            let mut d = DRec {
                section: i + 1,
                owner: lower_wire(r.owner()),
                rtype: r.rtype().to_int(),
                class: r.class().to_int(),
                addr: None,
                target: None,
                svcb_target: None,
                hints: Vec::new(),
                data_key: None,
            };
            let svcb_key = |priority: u16, target: &[u8], params: &[u8]| {
                [&priority.to_be_bytes()[..], target, params].concat()
            };
            match r.data() {
                AllRecordData::A(x) => {
                    d.addr = Some(IpAddr::V4(x.addr()));
                    d.data_key = Some(x.addr().octets().to_vec());
                }
                AllRecordData::Aaaa(x) => {
                    d.addr = Some(IpAddr::V6(x.addr()));
                    d.data_key = Some(x.addr().octets().to_vec());
                }
                AllRecordData::Cname(x) => {
                    d.target = Some(lower_wire(x.cname()));
                    d.data_key = d.target.clone();
                }
                AllRecordData::Dname(x) => {
                    d.target = Some(lower_wire(x.dname()));
                    d.data_key = d.target.clone();
                }
                AllRecordData::Svcb(x) => {
                    let t = lower_wire(x.target());
                    d.data_key = Some(svcb_key(x.priority(), &t, x.params().as_slice()));
                    d.svcb_target = Some(t);
                    if x.priority() != 0 {
                        d.hints = svcb_hints(x.params().iter_all())?;
                    }
                }
                AllRecordData::Https(x) => {
                    let t = lower_wire(x.target());
                    d.data_key = Some(svcb_key(x.priority(), &t, x.params().as_slice()));
                    d.svcb_target = Some(t);
                    if x.priority() != 0 {
                        d.hints = svcb_hints(x.params().iter_all())?;
                    }
                }
                _ => {}
            }
            out.push(d);
        }
    }
    Ok((qname, qtype, out))
}

/// Types whose data hickory 0.26 (with its DNSSEC types) decodes; others it keeps opaque.
pub fn hickory_decodes(t: u16) -> bool {
    matches!(
        t,
        1 | 2
            | 5
            | 6
            | 10
            | 12
            | 13
            | 15
            | 16
            | 24
            | 25
            | 28
            | 33
            | 35
            | 41
            | 43
            | 44
            | 46
            | 47
            | 48
            | 50
            | 51
            | 52
            | 53
            | 59
            | 60
            | 61
            | 62
            | 64
            | 65
            | 250
            | 257
            | 37
            | 65305
    )
}

fn svcb_hints<'a, I>(iter: I) -> Result<Vec<(IpAddr, bool)>, String>
where
    I: Iterator<Item = Result<AllValues<&'a [u8]>, domain::base::wire::ParseError>>,
{
    let mut out = Vec::new();
    for v in iter {
        match v.map_err(|e| format!("svcb params: {e}"))? {
            AllValues::Ipv4Hint(h) => out.extend(h.iter().map(|a| (IpAddr::V4(a), true))),
            AllValues::Ipv6Hint(h) => out.extend(h.iter().map(|a| (IpAddr::V6(a), false))),
            _ => {}
        }
    }
    Ok(out)
}

/// The facts response checks use, recomputed from `domain`'s decode of `msg` (raw or scrubbed):
/// the chain from the question name, then A/AAAA and SVCB/HTTPS data of the qtype at chain names.
pub struct DomainFacts {
    pub chain: Vec<Vec<u8>>,
    pub addrs: Vec<IpAddr>,
    pub hints: Vec<(IpAddr, bool)>,
    pub targets: Vec<Vec<u8>>,
}

pub fn domain_facts(msg: &[u8]) -> Result<DomainFacts, String> {
    let (qname, qtype, recs) = domain_decode(msg)?;
    let qclass = Message::from_octets(msg)
        .map_err(|e| format!("header: {e}"))?
        .first_question()
        .ok_or("no question")?
        .qclass()
        .to_int();
    // The answer records of the question's class (any class for QCLASS *, RFC 1035 §3.2.5), less
    // exact duplicates of an earlier record, as the scrub drops them (edge.md §7 step 3).
    let mut answer: Vec<&DRec> = Vec::new();
    for r in recs.iter().filter(|r| r.section == 1) {
        if !(qclass == 255 || r.class == qclass) {
            continue;
        }
        let dup = r.data_key.is_some()
            && answer.iter().any(|p| {
                p.owner == r.owner && p.rtype == r.rtype && p.class == r.class && p.data_key == r.data_key
            });
        if !dup {
            answer.push(r);
        }
    }
    let mut chain = vec![qname.clone()];
    for _ in 0..9 {
        let cur = chain.last().unwrap().clone();
        let cname = answer
            .iter()
            .find(|r| r.rtype == 5 && r.owner == cur)
            .and_then(|r| r.target.clone());
        let dname = answer.iter().find_map(|r| {
            let t = r.target.as_ref()?;
            (r.rtype == 39
                && cur.len() > r.owner.len()
                && cur.ends_with(&r.owner)
                && is_label_boundary(&cur, cur.len() - r.owner.len()))
            .then(|| [&cur[..cur.len() - r.owner.len()], &t[..]].concat())
        });
        match cname.or(dname) {
            Some(next) if !chain.contains(&next) => chain.push(next),
            _ => break,
        }
    }
    let mut f = DomainFacts {
        chain: chain[1..].to_vec(),
        addrs: vec![],
        hints: vec![],
        targets: vec![],
    };
    for r in &answer {
        if !chain.contains(&r.owner) || !(r.rtype == qtype || qtype == 255) {
            continue;
        }
        if let Some(ip) = r.addr {
            f.addrs.push(ip);
        }
        if let Some(t) = &r.svcb_target {
            if t.len() > 1 && !f.targets.contains(t) {
                f.targets.push(t.clone());
            }
            f.hints.extend(r.hints.iter().copied());
        }
    }
    Ok(f)
}

fn is_label_boundary(wire: &[u8], at: usize) -> bool {
    let mut i = 0;
    while i < at {
        i += 1 + wire[i] as usize;
    }
    i == at
}
