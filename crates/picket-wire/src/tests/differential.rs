//! The differential oracle (build-and-test.md §4; core.md §6 "Wire check"): NLnet Labs' `domain`
//! decodes what the pipeline accepted. A message the pipeline accepts that `domain` rejects for
//! a reason edge.md §7 checks (header, question, names, RDLENGTH, record formats), or whose
//! A/AAAA values or names decode differently, is a bug; record data `domain` leaves opaque is
//! not.
//!
//! The oracle runs on the raw upstream answer (an independent decode of the input the pipeline
//! judged) and on every message this crate writes (scrubbed wires, DO=0 copies, served hits).
//! A served hit also reads back as the answer it was served from (same names and addresses),
//! and one for a client without DO carries no record the DO=0 predicate strips.

use std::net::IpAddr;
use std::time::{Instant, SystemTime};

use domain::base::Rtype;
use picket_api::edge_config::TtlClamp;

use super::oracle::{domain_decode, domain_facts};

use crate::answer::{AddrSource, AnswerFacts, AnswerLimits, SentQuery, check_answer};
use crate::cache::{CacheValue, ServeParams, serve_hit};
use crate::dnssec::strip_for_do0;
use crate::reply::{ReplyTo, Transport};
use crate::testutil::{Msg, RECORDED, Sent, a, aaaa, fixture, n, ptr, rrsig, sent_for, soa, svcb};
use crate::types::rtype;

/// `domain` decodes every record of a message this crate accepted or wrote.
pub(crate) fn assert_domain_accepts(msg: &[u8]) {
    if let Err(e) = domain_decode(msg) {
        panic!("domain rejects a message picket-wire accepted or wrote: {e}\n{msg:02x?}");
    }
}

/// What the pipeline extracted equals `domain`'s decode of `msg`.
pub(crate) fn assert_facts_match_domain(msg: &[u8], facts: &AnswerFacts) {
    let d = domain_facts(msg).unwrap_or_else(|e| panic!("domain rejects: {e}"));
    let chain: Vec<Vec<u8>> = facts.chain.iter().map(|w| w.wire().to_vec()).collect();
    assert_eq!(chain, d.chain, "chain");
    let addrs: Vec<IpAddr> = facts
        .addrs
        .iter()
        .filter(|a| matches!(a.source, AddrSource::A | AddrSource::Aaaa))
        .map(|a| a.ip)
        .collect();
    assert_eq!(addrs, d.addrs, "A/AAAA");
    let hints: Vec<(IpAddr, bool)> = facts
        .addrs
        .iter()
        .filter(|a| matches!(a.source, AddrSource::Ipv4Hint | AddrSource::Ipv6Hint))
        .map(|a| (a.ip, a.source == AddrSource::Ipv4Hint))
        .collect();
    assert_eq!(hints, d.hints, "hints");
    let targets: Vec<Vec<u8>> = facts.targets.iter().map(|w| w.wire().to_vec()).collect();
    assert_eq!(targets, d.targets, "targets");
}

/// Runs the pipeline and, when it accepts, the oracle on the raw input and on its outputs.
fn judge(msg: &[u8], sent: &Sent) -> bool {
    let Ok(s) = check_answer(msg, &sent.sent(), &AnswerLimits::default()) else {
        return false;
    };
    if let Err(e) = domain_decode(msg) {
        panic!("accepted a message domain rejects: {e}\n{msg:02x?}");
    }
    assert_facts_match_domain(msg, &s.facts);
    assert_domain_accepts(s.wire());
    assert_facts_match_domain(s.wire(), &s.facts);
    assert_served_hits_read_back(&CacheValue::new(s, SystemTime::now(), Instant::now()), sent);
    true
}

/// Serves `value` to clients without an OPT, with DO clear and with DO set: each hit decodes
/// with `domain`, re-checks as an answer with the same chain, addresses and targets, and a hit
/// for a client without DO carries no record the DO=0 predicate strips (edge.md §7 step 4, §8).
fn assert_served_hits_read_back(value: &CacheValue, sent: &Sent) {
    let mut question = sent.qname.wire().to_vec();
    question.extend_from_slice(&sent.qtype.to_be_bytes());
    question.extend_from_slice(&sent.qclass.to_be_bytes());
    let mut out = vec![0u8; crate::MAX_MESSAGE];
    for client_opt in [None, Some(false), Some(true)] {
        let to = ReplyTo {
            id: 1,
            rd: true,
            cd: false,
            question: &question,
            client_opt,
            limit: crate::MAX_MESSAGE,
            payload: crate::EDGE_UDP_PAYLOAD,
            pad: false,
        };
        let p = ServeParams {
            age_s: 3,
            clamp: TtlClamp::default(),
            stale: None,
        };
        let r = serve_hit(&mut out, &to, value, &p).unwrap();
        let served = &out[..r.len];
        let (_, _, recs) = domain_decode(served)
            .unwrap_or_else(|e| panic!("domain rejects a served hit: {e}\n{served:02x?}"));
        if client_opt != Some(true) {
            for rec in &recs {
                assert!(
                    !strip_for_do0(rec.rtype, sent.qtype),
                    "a DO=0 hit carries type {}",
                    rec.rtype
                );
            }
        }
        if r.tc {
            // An upstream answer with TC set is served in the TC form (RFC 1035 §4.1.1).
            assert!(value.facts().tc);
            assert!(recs.iter().all(|r| r.section == 3), "only an OPT");
            continue;
        }
        let back = SentQuery { id: 1, ..sent.sent() };
        let again = check_answer(served, &back, &AnswerLimits::default())
            .unwrap_or_else(|e| panic!("a served hit doesn't re-check: {e:?}\n{served:02x?}"));
        assert_eq!(again.facts.chain, value.facts().chain, "served chain");
        assert_eq!(again.facts.addrs, value.facts().addrs, "served addresses");
        assert_eq!(again.facts.targets, value.facts().targets, "served targets");
    }
}

#[test]
fn recorded_answers() {
    for name in RECORDED {
        let f = fixture(name);
        assert!(judge(&f.answer, &Sent::of(&f.query)), "{name}");
    }
}

#[test]
fn hand_built_answers() {
    let s = sent_for(9, "www.example.com", rtype::A);
    let mut m = Msg::response(9, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::CNAME, 60, &n("cdn.example.net"));
    m.rr(1, &n("cdn.example.net"), rtype::A, 60, &a("192.0.2.1"));
    m.rr(1, &n("off.example"), rtype::A, 60, &a("192.0.2.66"));
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        60,
        &rrsig(rtype::CNAME, 3, 60, "example.com"),
    );
    m.rr(
        2,
        &n("example.net"),
        rtype::SOA,
        60,
        &soa(&n("ns.example.net"), &n("h.example.net"), 1, 60),
    );
    assert!(judge(&m.build(), &s));

    let s = sent_for(9, "svc.example", rtype::HTTPS);
    let mut m = Msg::response(9, "svc.example", rtype::HTTPS, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::HTTPS,
        60,
        &svcb(1, "t.example", &[(4, a("192.0.2.1")), (6, aaaa("2001:db8::1"))]),
    );
    assert!(judge(&m.build(), &s));

    let s = sent_for(9, "x.d.example", rtype::AAAA);
    let mut m = Msg::response(9, "x.d.example", rtype::AAAA, 0);
    m.rr(1, &n("d.example"), rtype::DNAME, 60, &n("t.example.org"));
    m.rr(
        1,
        &n("x.t.example.org"),
        rtype::AAAA,
        60,
        &aaaa("::ffff:192.0.2.9"),
    );
    assert!(judge(&m.build(), &s));
}

/// W6: the scrub drops exact duplicates (same section, owner, type, class and data, edge.md §7
/// step 3: "Scrub removals are counted"). The oracle applies the same rule, so valid duplicates
/// aren't reported; duplicates that differ in case or compression still count as one, and
/// records that differ in data are both kept on both sides.
#[test]
fn duplicate_records_are_not_oracle_mismatches() {
    let s = sent_for(9, "www.example.com", rtype::A);
    let mut m = Msg::response(9, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::CNAME, 60, &n("cdn.example.net"));
    let cdn = m.here();
    m.rr(1, &n("cdn.example.net"), rtype::A, 60, &a("192.0.2.1"));
    m.rr(1, &n("CDN.Example.NET"), rtype::A, 30, &a("192.0.2.1"));
    m.rr(1, &ptr(cdn), rtype::A, 60, &a("192.0.2.1"));
    m.rr(1, &ptr(cdn), rtype::A, 60, &a("192.0.2.2"));
    m.rr(1, &ptr(12), rtype::CNAME, 60, &ptr(cdn));
    assert!(judge(&m.build(), &s));
    let ans = check_answer(&m.build(), &s.sent(), &AnswerLimits::default()).unwrap();
    assert_eq!(ans.removed.duplicate, 3);
    assert_eq!(ans.facts.addrs.len(), 2);

    let s = sent_for(9, "svc.example", rtype::HTTPS);
    let mut m = Msg::response(9, "svc.example", rtype::HTTPS, 0);
    let rdata = svcb(1, "t.example", &[(4, a("192.0.2.1"))]);
    m.rr(1, &ptr(12), rtype::HTTPS, 60, &rdata);
    m.rr(1, &ptr(12), rtype::HTTPS, 60, &rdata);
    m.rr(
        1,
        &ptr(12),
        rtype::HTTPS,
        60,
        &svcb(1, "T.Example", &[(4, a("192.0.2.1"))]),
    );
    // Same target and hints, another alpn: a different record.
    m.rr(
        1,
        &ptr(12),
        rtype::HTTPS,
        60,
        &svcb(1, "t.example", &[(1, b"\x02h2".to_vec()), (4, a("192.0.2.1"))]),
    );
    assert!(judge(&m.build(), &s));
}

/// Messages `domain` rejects for reasons edge.md §7 checks are rejected by the pipeline too.
#[test]
fn oracle_rejections_are_ours_too() {
    let s = sent_for(9, "x.example", rtype::A);
    let cases: Vec<Vec<u8>> = vec![
        {
            let mut m = Msg::response(9, "x.example", rtype::A, 0);
            m.rr(1, &ptr(12), rtype::A, 60, &[1, 2, 3]);
            m.build()
        },
        {
            let mut m = Msg::response(9, "x.example", rtype::A, 0);
            m.rr(1, &ptr(100), rtype::A, 60, &a("192.0.2.1"));
            m.build()
        },
        {
            let mut m = Msg::response(9, "x.example", rtype::A, 0);
            m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
            let b = m.build();
            b[..b.len() - 2].to_vec()
        },
        {
            let mut m = Msg::response(9, "x.example", rtype::A, 0);
            m.rr(1, &ptr(12), rtype::CNAME, 60, &[3, b'a', b'b']);
            m.build()
        },
        {
            let mut m = Msg::response(9, "x.example", rtype::A, 0);
            m.rr(1, &ptr(12), rtype::AAAA, 60, &[0; 15]);
            m.build()
        },
    ];
    for c in cases {
        assert!(domain_decode(&c).is_err(), "domain accepts {c:02x?}");
        assert!(
            check_answer(&c, &s.sent(), &AnswerLimits::default()).is_err(),
            "pipeline accepts {c:02x?}"
        );
    }
}

/// fuzz/wire `upstream_answer` found this (corpus `upstream_answer/offchain-https-long-port.bin`):
/// an HTTPS answer whose answer section holds an HTTPS record off the chain (owner
/// `cloudfl\152re.com`) with a 6-byte `port`. hickory reads the first two bytes and ignores the
/// rest, and the scrub would drop the record, but RFC 9460 §2.2 makes it malformed and `domain`
/// refuses it: the pipeline refuses the answer too, for any SVCB/HTTPS record in any section
/// (edge.md §7 step 1), so the edge retries another upstream (step 3).
#[test]
fn malformed_svcb_off_the_chain() {
    let msg = crate::testutil::hex(
        "84b5 8180 0001 0001 0000 0001 0a63 6c6f 7564 666c 6172 6503 636f 6d00 0041 0001
         0a63 6c6f 7564 666c 9872 6503 636f 6d00 0041 0001 0000 0384 0019 0001 0000 0300
         0602 6833 0268 3200 0400 0868 1084 e568 1085 e500 0029 04d0 0000 0000 0000",
    );
    assert_eq!(msg.len(), 94);
    let s = sent_for(0x84b5, "cloudflare.com", rtype::HTTPS);
    assert!(domain_decode(&msg).is_err());
    assert_eq!(
        check_answer(&msg, &s.sent(), &AnswerLimits::default()).unwrap_err(),
        crate::answer::Invalid::BadSvcb
    );
    // With a 2-byte `port`, both read it, and the scrub drops the record.
    let owner = [&b"\x0acloudfl\x98re"[..], &n("com")].concat();
    let mut m = Msg::response(0x84b5, "cloudflare.com", rtype::HTTPS, 0);
    m.rr(
        1,
        &owner,
        rtype::HTTPS,
        900,
        &svcb(1, ".", &[(3, vec![0, 0x68]), (4, a("104.16.132.229"))]),
    );
    let msg = m.build();
    assert!(judge(&msg, &s));
    let ans = check_answer(&msg, &s.sent(), &AnswerLimits::default()).unwrap();
    assert_eq!(ans.removed.out_of_bailiwick, 1);
}

/// RFC 9460 §2.4.2: both sides ignore an AliasMode record's SvcParams, so one carrying a 3-byte
/// `port`, an empty `alpn` id and an `ipv4hint` is accepted with its target and no hints, kept or
/// in the additional section; in ServiceMode the same parameters are refused.
#[test]
fn alias_mode_params_are_ignored_on_both_sides() {
    let s = sent_for(9, "svc.example", rtype::HTTPS);
    let params = [(1, vec![0]), (3, vec![0, 80, 0]), (4, a("192.0.2.1"))];
    for section in [1, 3] {
        let mut m = Msg::response(9, "svc.example", rtype::HTTPS, 0);
        m.rr(
            section,
            &ptr(12),
            rtype::HTTPS,
            60,
            &svcb(0, "pool.example", &params),
        );
        assert!(judge(&m.build(), &s), "section {section}");
        let ans = check_answer(&m.build(), &s.sent(), &AnswerLimits::default()).unwrap();
        assert!(ans.facts.addrs.is_empty());
        let mut m = Msg::response(9, "svc.example", rtype::HTTPS, 0);
        m.rr(
            section,
            &ptr(12),
            rtype::HTTPS,
            60,
            &svcb(1, "pool.example", &params),
        );
        assert_eq!(
            check_answer(&m.build(), &s.sent(), &AnswerLimits::default()).unwrap_err(),
            crate::answer::Invalid::BadSvcb
        );
    }
}

/// Generated messages: byte mutations, truncations and splices of the recordings. Whatever the
/// pipeline accepts, the oracle must too, with the same names and addresses.
#[test]
fn mutated_recordings() {
    let mut seed = std::env::var("PICKET_WIRE_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x9E37_79B9_7F4A_7C15u64)
        | 1;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut accepted = 0usize;
    let mut seeds: Vec<(Vec<u8>, Sent)> = RECORDED
        .iter()
        .map(|name| {
            let f = fixture(name);
            (f.answer, Sent::of(&f.query))
        })
        .collect();
    seeds.extend(hand_built_seeds());
    for (answer, sent) in &seeds {
        for _ in 0..mutations() {
            let mut m = answer.clone();
            match next() % 4 {
                0 => {
                    let i = (next() as usize) % m.len();
                    m[i] ^= 1 << (next() % 8);
                }
                1 => {
                    let i = 12 + (next() as usize) % (m.len() - 12);
                    m[i] = next() as u8;
                }
                2 => {
                    let i = 12 + (next() as usize) % (m.len() - 12);
                    m.truncate(i);
                }
                _ => {
                    // Point a random byte pair at a random earlier offset.
                    let i = 12 + (next() as usize) % (m.len() - 13);
                    let p = (0xC000 | ((next() as usize) % i.max(1)) as u16).to_be_bytes();
                    m[i] = p[0];
                    m[i + 1] = p[1];
                }
            }
            if judge(&m, sent) {
                accepted += 1;
            }
        }
    }
    assert!(accepted > 100, "mutations accepted: {accepted}");
}

/// Hand-built seeds for the shapes recordings lack: SVCB hints and targets, a DNAME without
/// its CNAME, IPv4-mapped AAAA, signed NODATA with NSEC.
fn hand_built_seeds() -> Vec<(Vec<u8>, Sent)> {
    let mut out = Vec::new();
    let mut m = Msg::response(9, "svc.example", rtype::HTTPS, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::HTTPS,
        60,
        &svcb(
            1,
            "t.example",
            &[
                (1, b"\x02h2".to_vec()),
                (4, a("192.0.2.1")),
                (6, aaaa("2001:db8::1")),
            ],
        ),
    );
    out.push((m.build(), sent_for(9, "svc.example", rtype::HTTPS)));
    let mut m = Msg::response(9, "x.d.example", rtype::AAAA, 0);
    m.rr(1, &n("d.example"), rtype::DNAME, 60, &n("t.example.org"));
    m.rr(
        1,
        &n("x.t.example.org"),
        rtype::AAAA,
        60,
        &aaaa("::ffff:192.0.2.9"),
    );
    out.push((m.build(), sent_for(9, "x.d.example", rtype::AAAA)));
    let mut m = Msg::response(9, "nope.example.com", rtype::TXT, 0);
    m.rr(
        2,
        &n("example.com"),
        rtype::SOA,
        60,
        &soa(&n("ns.example.com"), &n("h.example.com"), 1, 60),
    );
    m.rr(
        2,
        &n("nope.example.com"),
        rtype::NSEC,
        60,
        &crate::testutil::nsec("z.example.com", &[rtype::A, rtype::NSEC]),
    );
    m.rr(
        2,
        &n("nope.example.com"),
        rtype::RRSIG,
        60,
        &rrsig(rtype::NSEC, 3, 60, "example.com"),
    );
    m.opt(1232, 0, 0, true, &[(12, &[0; 20])]);
    out.push((m.build(), sent_for(9, "nope.example.com", rtype::TXT)));
    // Review round 1: duplicates the scrub drops (W6), an upstream TC answer (W2), an NSEC3 with
    // an unknown hash algorithm (W10), QCLASS * (W11) and more than 8 EDE options (W9).
    let mut m = Msg::response(9, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    m.rr(1, &ptr(12), rtype::A, 30, &a("192.0.2.2"));
    let edes: Vec<(u16, &[u8])> = (0..10)
        .map(|i| {
            (
                15,
                if i == 9 {
                    &b"\x00\x03"[..]
                } else {
                    &b"\x00\x0f"[..]
                },
            )
        })
        .collect();
    m.opt(1232, 0, 0, false, &edes);
    out.push((m.build(), sent_for(9, "www.example.com", rtype::A)));
    let mut m = Msg::with_flags(9, 0x83, 0x80);
    m.question(&n("big.example"), rtype::TXT, 1);
    m.rr(1, &ptr(12), rtype::TXT, 60, b"\x05part1");
    out.push((m.build(), sent_for(9, "big.example", rtype::TXT)));
    let mut data = crate::testutil::nsec3(&[rtype::A]);
    data[0] = 2;
    let mut m = Msg::response(9, "nope.example.com", rtype::A, 3);
    m.rr(
        2,
        &n("example.com"),
        rtype::SOA,
        3600,
        &soa(&n("ns.example.com"), &n("h.example.com"), 1, 300),
    );
    m.rr(2, &n("h4sh.example.com"), rtype::NSEC3, 300, &data);
    out.push((m.build(), sent_for(9, "nope.example.com", rtype::A)));
    let mut m = Msg::with_flags(9, 0x81, 0x80);
    m.question(&n("www.example.com"), rtype::A, 255);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    let mut s = sent_for(9, "www.example.com", rtype::A);
    s.qclass = 255;
    out.push((m.build(), s));
    out
}

/// Mutations per recording: `PICKET_WIRE_MUTATIONS` raises it for a longer local run.
fn mutations() -> usize {
    std::env::var("PICKET_WIRE_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500)
}

/// Mutated client queries never panic the query check; an accepted one has a question `domain`
/// reads the same way.
#[test]
fn mutated_queries() {
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for (_, q) in crate::testutil::queries() {
        for _ in 0..mutations() {
            let mut m = q.clone();
            let i = (next() as usize) % m.len();
            m[i] = next() as u8;
            if next() % 4 == 0 {
                m.truncate(12 + (next() as usize) % (m.len() - 11));
            }
            match crate::query::check_query(&m) {
                Ok(parsed) => {
                    let (qname, qtype, _) = domain_decode(&m)
                        .unwrap_or_else(|e| panic!("domain rejects an accepted query: {e} {m:02x?}"));
                    assert_eq!(qname, parsed.qname().wire());
                    assert_eq!(qtype, parsed.qtype);
                }
                Err(e) => {
                    let mut out = [0u8; 600];
                    let _ = crate::query::write_query_error(
                        &mut out,
                        &m,
                        &e,
                        Transport::Udp,
                        crate::EDGE_UDP_PAYLOAD,
                    )
                    .unwrap();
                }
            }
        }
    }
}

#[test]
fn rtype_numbers_agree() {
    for t in [
        rtype::A,
        rtype::CNAME,
        rtype::DNAME,
        rtype::HTTPS,
        rtype::SVCB,
        rtype::NSEC3,
    ] {
        assert_eq!(Rtype::from_int(t).to_int(), t);
    }
}
