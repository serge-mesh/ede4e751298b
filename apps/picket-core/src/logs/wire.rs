//! The wire check (core.md §6; build-and-test.md §5 "Wire check"): the edge's reading of each
//! logged answer against an independent decode of its `wire` by NLnet Labs' `domain` crate (the
//! edge decodes with hickory-proto, so the check uses a different library).
//!
//! - [`decode`]: `domain`'s decode of a whole message, and the facts response checks use,
//!   recomputed from it: the CNAME chain from the question name (DNAME-synthesised CNAMEs
//!   included), the A/AAAA addresses and HTTPS/SVCB hints and target names of the question type
//!   at chain names, after the scrub's duplicate rule (edge.md §7). A message `domain` rejects
//!   for a reason edge.md §7 checks (header, question, a record header, the data of a type
//!   hickory-proto decodes) is an error; record data `domain` leaves opaque never is. An
//!   AliasMode SVCB/HTTPS record's SvcParams aren't decoded and give no hints: recipients MUST
//!   ignore them (RFC 9460 §2.4.2), and so does the edge.
//! - [`check`]: the comparison rules: the logged `cname` chain must be the decoded one (for a
//!   CNAME rewrite, the part after the edge's own CNAME); every logged `answers` IP and `targets`
//!   name must be in the decode; on a response-phase block, the deciding value must be in the
//!   part `reason.stage` names. Each failed rule is a mismatch kind: `rejected`, `cname`,
//!   `answers`, `targets`, `deciding`.
//!
//! Untrusted input (the wire comes from an edge): every decode is bounded by the message (≤ 4 KiB
//! as logged), never panics, and is fuzzed (`fuzz/core/fuzz_targets/wire_check.rs`).

use std::net::IpAddr;

use domain::base::Message;
use domain::base::name::{ParsedName, ToLabelIter};
use domain::rdata::AllRecordData;
use domain::rdata::svcb::value::AllValues;
use serde::Serialize;

type Data<'a> = AllRecordData<&'a [u8], ParsedName<&'a [u8]>>;

/// The longest message decoded (api.md §5: a logged answer is at most 4 KiB; a reply 2 KiB).
pub const MAX_WIRE: usize = 4096;
/// Chain links followed (edge.md §7 bounds the chain the same way).
const MAX_CHAIN: usize = 16;
/// Records decoded per message (a 4 KiB message holds fewer).
const MAX_RECORDS: usize = 1024;

/// A mismatch kind (core.md §6, `wire_mismatch{edge, kind}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Rejected,
    Cname,
    Answers,
    Targets,
    Deciding,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Rejected => "rejected",
            Kind::Cname => "cname",
            Kind::Answers => "answers",
            Kind::Targets => "targets",
            Kind::Deciding => "deciding",
        }
    }
}

fn lower_wire(name: &ParsedName<&[u8]>) -> Vec<Vec<u8>> {
    name.iter_labels()
        .filter(|l| !l.is_root())
        .map(|l| {
            let b: &[u8] = l.as_ref();
            b.iter().map(u8::to_ascii_lowercase).collect()
        })
        .collect()
}

/// A record as `domain` decoded it.
#[derive(Clone, Debug)]
struct DRec {
    section: usize,
    owner: Vec<Vec<u8>>,
    rtype: u16,
    class: u16,
    addr: Option<IpAddr>,
    target: Option<Vec<Vec<u8>>>,
    svcb_target: Option<Vec<Vec<u8>>>,
    hints: Vec<IpAddr>,
    data_key: Option<Vec<u8>>,
}

/// Types whose data hickory-proto 0.26 (with its DNSSEC types) decodes; others it keeps opaque,
/// so `domain` refusing them isn't a mismatch (RFC 3597 §4).
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
            | 37
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
            | 65305
    )
}

fn flat(labels: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    for l in labels {
        v.push(u8::try_from(l.len()).unwrap_or(u8::MAX));
        v.extend_from_slice(l);
    }
    v
}

fn svcb_hints<'a, I>(iter: I) -> Result<Vec<IpAddr>, String>
where
    I: Iterator<Item = Result<AllValues<&'a [u8]>, domain::base::wire::ParseError>>,
{
    let mut out = Vec::new();
    for v in iter.take(64) {
        match v.map_err(|e| format!("svcb params: {e}"))? {
            AllValues::Ipv4Hint(h) => out.extend(h.iter().map(IpAddr::V4)),
            AllValues::Ipv6Hint(h) => out.extend(h.iter().map(IpAddr::V6)),
            _ => {}
        }
    }
    Ok(out)
}

/// The question name (labels), type and class, and every record.
type Records = (Vec<Vec<u8>>, u16, u16, Vec<DRec>);

fn decode_records(msg: &[u8]) -> Result<Records, String> {
    if msg.len() > MAX_WIRE {
        return Err(format!("{} bytes, more than {MAX_WIRE}", msg.len()));
    }
    let m = Message::from_octets(msg).map_err(|e| format!("header: {e}"))?;
    let mut qs = m.question();
    let q = qs
        .next()
        .ok_or("no question")?
        .map_err(|e| format!("question: {e}"))?;
    let qname = lower_wire(q.qname());
    let qtype = q.qtype().to_int();
    let qclass = q.qclass().to_int();
    let mut out = Vec::new();
    let sections = [m.answer(), m.authority(), m.additional()];
    for (i, sec) in sections.into_iter().enumerate() {
        let sec = sec.map_err(|e| format!("section {}: {e}", i + 1))?;
        for rec in sec {
            if out.len() >= MAX_RECORDS {
                return Err("too many records".into());
            }
            let rec = rec.map_err(|e| format!("record header: {e}"))?;
            let parsed = match rec.to_record::<Data<'_>>() {
                Ok(p) => p,
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
            let svcb_key = |priority: u16, target: &[Vec<u8>], params: &[u8]| {
                [&priority.to_be_bytes()[..], &flat(target), params].concat()
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
                    let t = lower_wire(x.cname());
                    d.data_key = Some(flat(&t));
                    d.target = Some(t);
                }
                AllRecordData::Dname(x) => {
                    let t = lower_wire(x.dname());
                    d.data_key = Some(flat(&t));
                    d.target = Some(t);
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
    Ok((qname, qtype, qclass, out))
}

/// `domain`'s reading of an answer: the facts response checks use (names as wire labels).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Decoded {
    /// The question name and type.
    pub qname: String,
    pub qtype: u16,
    /// The CNAME chain after the question name, as log text (api.md §5).
    pub chain: Vec<String>,
    /// A and AAAA addresses of chain names, in answer order.
    pub addrs: Vec<IpAddr>,
    /// HTTPS/SVCB address hints.
    pub hints: Vec<IpAddr>,
    /// HTTPS/SVCB target names other than the root, as log text.
    pub targets: Vec<String>,
    /// Records decoded per section (answer, authority, additional).
    pub records: [usize; 3],
}

fn text(labels: &[Vec<u8>]) -> String {
    picket_api::names::encode_labels(labels.iter().map(Vec::as_slice))
}

fn is_suffix(name: &[Vec<u8>], suffix: &[Vec<u8>]) -> bool {
    name.len() > suffix.len() && name[name.len() - suffix.len()..] == *suffix
}

/// Decodes `msg` with `domain`; `Err` with the reason when it rejects it.
pub fn decode(msg: &[u8]) -> Result<Decoded, String> {
    let (qname, qtype, qclass, recs) = decode_records(msg)?;
    // The answer records of the question's class (any class for QCLASS *), less exact
    // duplicates of an earlier record, as the scrub drops them (edge.md §7).
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
    let mut chain: Vec<Vec<Vec<u8>>> = vec![qname.clone()];
    for _ in 0..MAX_CHAIN {
        let Some(cur) = chain.last().cloned() else { break };
        let cname = answer
            .iter()
            .find(|r| r.rtype == 5 && r.owner == cur)
            .and_then(|r| r.target.clone());
        let dname = answer.iter().find_map(|r| {
            let t = r.target.as_ref()?;
            (r.rtype == 39 && is_suffix(&cur, &r.owner)).then(|| {
                let mut n: Vec<Vec<u8>> = cur[..cur.len() - r.owner.len()].to_vec();
                n.extend(t.iter().cloned());
                n
            })
        });
        match cname.or(dname) {
            Some(next) if !chain.contains(&next) => chain.push(next),
            _ => break,
        }
    }
    let mut d = Decoded {
        qname: text(&qname),
        qtype,
        chain: chain.iter().skip(1).map(|c| text(c)).collect(),
        records: [
            recs.iter().filter(|r| r.section == 1).count(),
            recs.iter().filter(|r| r.section == 2).count(),
            recs.iter().filter(|r| r.section == 3).count(),
        ],
        ..Default::default()
    };
    for r in &answer {
        if !chain.contains(&r.owner) || !(r.rtype == qtype || qtype == 255) {
            continue;
        }
        if let Some(ip) = r.addr {
            d.addrs.push(ip);
        }
        if let Some(t) = &r.svcb_target {
            let tt = text(t);
            if !t.is_empty() && !d.targets.contains(&tt) {
                d.targets.push(tt);
            }
            d.hints.extend(r.hints.iter().copied());
        }
    }
    Ok(d)
}

/// What a logged record says about its answer (api.md §5), for [`check`].
#[derive(Clone, Debug, Default)]
pub struct Logged<'a> {
    pub cname: &'a [String],
    pub answers: &'a [String],
    pub targets: &'a [String],
    /// A CNAME rewrite: the logged chain starts with the edge's own CNAME.
    pub cname_rewrite: bool,
    /// On a response-phase block: the stage and the deciding value.
    pub deciding: Option<(picket_api::logs::Stage, String)>,
}

/// The outcome of one record's check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Outcome {
    /// Every failed rule, in kind order; empty when the record agrees.
    pub kinds: Vec<Kind>,
    /// `domain`'s decode, or its error.
    pub decoded: Result<Decoded, String>,
}

fn norm_name(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

fn norm_ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().map(picket_rules::ip::canonical_ip)
}

/// Compares a record's logged reading with `decoded` (the result of [`decode`]).
pub fn compare(logged: &Logged<'_>, decoded: &Result<Decoded, String>) -> Vec<Kind> {
    let d = match decoded {
        Ok(d) => d,
        Err(_) => return vec![Kind::Rejected],
    };
    let mut kinds = Vec::new();
    let chain: Vec<String> = d.chain.iter().map(|n| norm_name(n)).collect();
    let logged_chain: Vec<String> = logged
        .cname
        .iter()
        .skip(usize::from(logged.cname_rewrite))
        .map(|n| norm_name(n))
        .collect();
    if logged_chain != chain {
        kinds.push(Kind::Cname);
    }
    let addrs: Vec<IpAddr> = d
        .addrs
        .iter()
        .chain(d.hints.iter())
        .map(|a| picket_rules::ip::canonical_ip(*a))
        .collect();
    if logged
        .answers
        .iter()
        .any(|a| norm_ip(a).is_none_or(|ip| !addrs.contains(&ip)))
    {
        kinds.push(Kind::Answers);
    }
    let targets: Vec<String> = d.targets.iter().map(|n| norm_name(n)).collect();
    if logged.targets.iter().any(|t| !targets.contains(&norm_name(t))) {
        kinds.push(Kind::Targets);
    }
    if let Some((stage, value)) = &logged.deciding {
        use picket_api::logs::Stage;
        let ok = match stage {
            Stage::Cname => chain.contains(&norm_name(value)),
            Stage::AnswerIp => norm_ip(value).is_some_and(|ip| {
                d.addrs
                    .iter()
                    .map(|a| picket_rules::ip::canonical_ip(*a))
                    .any(|a| a == ip)
            }),
            Stage::Svcb => {
                targets.contains(&norm_name(value))
                    || norm_ip(value).is_some_and(|ip| {
                        d.hints
                            .iter()
                            .map(|a| picket_rules::ip::canonical_ip(*a))
                            .any(|a| a == ip)
                    })
            }
            Stage::Query => true,
        };
        if !ok {
            kinds.push(Kind::Deciding);
        }
    }
    kinds
}

/// Decodes `wire` and compares it with what the record logged.
pub fn check(wire: &[u8], logged: &Logged<'_>) -> Outcome {
    let decoded = decode(wire);
    let kinds = compare(logged, &decoded);
    Outcome { kinds, decoded }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use picket_api::logs::Stage;

    /// An answer message: `qname` A with the given CNAME chain and final addresses.
    pub fn answer(qname: &str, chain: &[&str], addrs: &[[u8; 4]]) -> Vec<u8> {
        fn name(n: &str) -> Vec<u8> {
            let mut v = Vec::new();
            for l in n.split('.').filter(|l| !l.is_empty()) {
                v.push(l.len() as u8);
                v.extend_from_slice(l.as_bytes());
            }
            v.push(0);
            v
        }
        let count = chain.len() + addrs.len();
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, count as u8, 0, 0, 0, 0];
        m.extend(name(qname));
        m.extend_from_slice(&[0, 1, 0, 1]);
        let mut owner = qname.to_string();
        for c in chain {
            m.extend(name(&owner));
            m.extend_from_slice(&[0, 5, 0, 1, 0, 0, 1, 0]);
            let t = name(c);
            m.extend_from_slice(&(t.len() as u16).to_be_bytes());
            m.extend(t);
            owner = c.to_string();
        }
        for a in addrs {
            m.extend(name(&owner));
            m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 1, 0, 0, 4]);
            m.extend_from_slice(a);
        }
        m
    }

    #[test]
    fn agreeing_records_have_no_mismatch() {
        let w = answer("www.example.com", &["cdn.example.net"], &[[192, 0, 2, 1]]);
        let cname = vec!["cdn.example.net".to_string()];
        let answers = vec!["192.0.2.1".to_string()];
        let o = check(
            &w,
            &Logged {
                cname: &cname,
                answers: &answers,
                ..Default::default()
            },
        );
        assert!(o.kinds.is_empty(), "{o:?}");
        let d = o.decoded.unwrap();
        assert_eq!(d.qname, "www.example.com");
        assert_eq!(d.chain, cname);
    }

    #[test]
    fn each_rule_has_its_kind() {
        let w = answer("www.example.com", &["cdn.example.net"], &[[192, 0, 2, 1]]);
        let wrong_chain = vec!["other.example".to_string()];
        let wrong_ip = vec!["192.0.2.9".to_string()];
        let targets = vec!["svc.example".to_string()];
        let o = check(
            &w,
            &Logged {
                cname: &wrong_chain,
                answers: &wrong_ip,
                targets: &targets,
                deciding: Some((Stage::AnswerIp, "198.51.100.1".into())),
                ..Default::default()
            },
        );
        assert_eq!(
            o.kinds,
            vec![Kind::Cname, Kind::Answers, Kind::Targets, Kind::Deciding]
        );
        // A CNAME rewrite's own CNAME comes first in its logged chain.
        let rewrite = vec!["mine.example".to_string(), "cdn.example.net".to_string()];
        let ok = vec!["192.0.2.1".to_string()];
        let o = check(
            &w,
            &Logged {
                cname: &rewrite,
                answers: &ok,
                cname_rewrite: true,
                ..Default::default()
            },
        );
        assert!(o.kinds.is_empty(), "{o:?}");
    }

    #[test]
    fn rejections_count_but_opaque_data_never_does() {
        let mut w = answer("www.example.com", &[], &[[192, 0, 2, 1]]);
        // An A record whose data is 3 bytes: hickory decodes A, so `domain` refusing it counts.
        let n = w.len();
        w[n - 6] = 0;
        w[n - 5] = 3;
        w.truncate(n - 1);
        assert_eq!(compare(&Logged::default(), &decode(&w)), vec![Kind::Rejected]);
        // A record of a type hickory keeps opaque, with data `domain` can't read: no mismatch.
        let mut ok = answer("www.example.com", &[], &[]);
        ok[7] = 1;
        ok.extend_from_slice(&[3, b'w', b'w', b'w', 7]);
        ok.extend_from_slice(b"example");
        ok.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0xff, 0x00, 0, 1, 0, 0, 1, 0, 0, 1, 0x99]);
        assert!(decode(&ok).is_ok(), "{:?}", decode(&ok));
        assert!(decode(&[1, 2, 3]).is_err());
        assert!(decode(&vec![0u8; MAX_WIRE + 1]).is_err());
    }

    /// RFC 9460 §2.4.2: an AliasMode record's SvcParams are ignored, as the edge ignores them: a
    /// 3-byte `port` there is no rejection and its `ipv4hint` no hint; in ServiceMode it is both.
    #[test]
    fn alias_mode_params_are_ignored() {
        let https = |priority: u8| {
            // svc.example HTTPS, one answer: target pool.example, port of 3 bytes, ipv4hint.
            let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            m.extend_from_slice(b"\x03svc\x07example\x00\x00\x41\x00\x01");
            m.extend_from_slice(&[0xc0, 12, 0, 0x41, 0, 1, 0, 0, 1, 0]);
            let mut rdata = vec![0, priority];
            rdata.extend_from_slice(b"\x04pool\x07example\x00");
            rdata.extend_from_slice(&[0, 3, 0, 3, 0, 80, 0]);
            rdata.extend_from_slice(&[0, 4, 0, 4, 192, 0, 2, 1]);
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend(rdata);
            m
        };
        let d = decode(&https(0)).unwrap();
        assert!(d.hints.is_empty(), "{d:?}");
        assert_eq!(d.targets, vec!["pool.example".to_string()]);
        assert!(decode(&https(1)).is_err());
    }

    /// A `www.example.com` TXT answer with one record of type `rtype` holding `data`.
    fn txt_answer(rtype: u8, data: &[u8]) -> Vec<u8> {
        let mut w = answer("www.example.com", &[], &[]);
        w[7] = 1;
        let n = w.len();
        w[n - 3] = 16;
        w.extend_from_slice(&[0xc0, 12, 0, rtype, 0, 1, 0, 0, 1, 0]);
        w.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        w.extend_from_slice(data);
        w
    }

    /// The `wire` an edge logs for an upstream answer: its scrub (edge.md §7), or why it refused
    /// the answer.
    fn served(upstream: &[u8]) -> Result<Vec<u8>, picket_wire::answer::Invalid> {
        let q = picket_wire::QName::from_text("www.example.com").unwrap();
        let sent = picket_wire::answer::SentQuery {
            id: 0x1234,
            qname: q.as_name(),
            qtype: 16,
            qclass: 1,
        };
        picket_wire::answer::check_answer(upstream, &sent, &Default::default()).map(|a| a.wire().to_vec())
    }

    /// `domain` 0.13's stricter parsing: it refuses a TXT record with no data, as the edge does
    /// (RFC 1035 §3.3.14: one or more character strings), so a logged one is `rejected`; it also
    /// refuses a ZONEMD digest under 12 octets, which stays opaque (hickory-proto keeps ZONEMD
    /// opaque, so the edge passes it on).
    #[test]
    fn domain_refuses_empty_txt_as_the_edge_does() {
        let empty = txt_answer(16, &[]);
        assert_eq!(served(&empty), Err(picket_wire::answer::Invalid::Undecodable));
        assert_eq!(compare(&Logged::default(), &decode(&empty)), vec![Kind::Rejected]);

        let text = served(&txt_answer(16, b"\x02hi")).unwrap();
        assert_eq!(decode(&text).unwrap().records, [1, 0, 0]);
        let short = txt_answer(16, b"\x05hi");
        assert!(served(&short).is_err());
        assert_eq!(compare(&Logged::default(), &decode(&short)), vec![Kind::Rejected]);

        // ZONEMD: serial, scheme, hash algorithm and a 5-octet digest.
        let zonemd = txt_answer(63, &[0, 0, 0, 1, 1, 1, 1, 2, 3, 4, 5]);
        assert!(!hickory_decodes(63));
        assert!(served(&zonemd).is_ok());
        let d = decode(&zonemd).unwrap();
        assert_eq!(d.records, [0, 0, 0]);
        assert_eq!(compare(&Logged::default(), &Ok(d)), vec![]);
    }
}
