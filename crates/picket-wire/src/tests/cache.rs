//! Cache values and hit serving (edge.md §8), the DO=0 copy (§7 step 4) and core's rebuild
//! (core.md §6).

use std::net::Ipv4Addr;
use std::time::{Instant, SystemTime};

use hickory_proto::rr::{RData, RecordType};
use picket_api::edge_config::TtlClamp;

use super::decode;
use crate::answer::{AnswerLimits, check_answer};
use crate::cache::{CacheValue, ServeParams, StaleServe, rebuild_reply, serve_hit, write_cname_rewrite};
use crate::name::QName;
use crate::query::{Query, check_query};
use crate::reply::{ReplyTo, Transport};
use crate::testutil::{Msg, Sent, a, fixture, n, nsec, ptr, rrsig, sent_for};
use crate::types::{edns_code, rtype};
use crate::wire::WriteError;
use picket_api::logs::Proto;

const ID: u16 = 0x7777;
const WIDE: TtlClamp = TtlClamp {
    min: 0,
    max: u32::MAX,
};

/// The whole encoded message of the copy a client with or without DO gets.
pub(crate) fn copy_message(v: &CacheValue, do_bit: bool) -> Vec<u8> {
    v.copy_message(do_bit).to_vec()
}

fn value(m: &Msg, name: &str, qtype: u16) -> CacheValue {
    let s = sent_for(ID, name, qtype);
    let a = check_answer(&m.build(), &s.sent(), &AnswerLimits::default()).unwrap();
    CacheValue::new(a, SystemTime::now(), Instant::now())
}

fn client(name: &str, qtype: u16, opt: Option<bool>) -> Query {
    let mut m = Msg::query(0x0B0B, name, qtype);
    if let Some(do_bit) = opt {
        m.opt(1232, 0, 0, do_bit, &[]);
    }
    check_query(&m.build()).unwrap()
}

fn params(age_s: u32, clamp: TtlClamp) -> ServeParams<'static> {
    ServeParams {
        age_s,
        clamp,
        stale: None,
    }
}

#[test]
fn serve_ages_and_clamps_ttls() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::CNAME, 600, &n("cdn.example.net"));
    m.rr(1, &n("cdn.example.net"), rtype::A, 100, &a("192.0.2.1"));
    let v = value(&m, "www.example.com", rtype::A);
    let q = client("WWW.example.com", rtype::A, Some(false));
    let mut buf = [0u8; 1232];

    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &params(30, WIDE),
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.metadata.id, 0x0B0B);
    assert_eq!(d.answers.iter().map(|r| r.ttl).collect::<Vec<_>>(), vec![570, 70]);
    // The client's question bytes, case and all; owners point at them.
    assert_eq!(&buf[12..12 + q.question().len()], q.question());
    assert_eq!(d.answers[0].name.to_ascii(), "WWW.example.com.");
    assert!(d.edns.is_some());
    assert!(!d.authentic_data);

    // Age past a TTL: 0, then the profile clamp.
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &params(150, WIDE),
    )
    .unwrap();
    assert_eq!(
        decode(&buf[..r.len])
            .answers
            .iter()
            .map(|r| r.ttl)
            .collect::<Vec<_>>(),
        vec![450, 0]
    );
    let clamp = TtlClamp { min: 5, max: 300 };
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &params(150, clamp),
    )
    .unwrap();
    assert_eq!(
        decode(&buf[..r.len])
            .answers
            .iter()
            .map(|r| r.ttl)
            .collect::<Vec<_>>(),
        vec![300, 5]
    );

    // No OPT in the query: none in the reply.
    let q = client("www.example.com", rtype::A, None);
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &params(0, WIDE),
    )
    .unwrap();
    assert!(decode(&buf[..r.len]).edns.is_none());
}

#[test]
fn stale_variant() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 100, &a("192.0.2.1"));
    let v = value(&m, "www.example.com", rtype::A);
    let q = client("www.example.com", rtype::A, Some(false));
    let mut buf = [0u8; 1232];
    let p = ServeParams {
        age_s: 5000,
        clamp: WIDE,
        stale: Some(StaleServe {
            ttl: 30,
            cause: "optimistic",
        }),
    };
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &p,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers[0].ttl, 30);
    let opts = &d.edns.as_ref().unwrap().options().options;
    let (code, opt) = &opts[0];
    assert_eq!(u16::from(*code), edns_code::EDE);
    let bytes: Vec<u8> = opt.try_into().unwrap();
    assert_eq!(&bytes, b"\x00\x03cause=optimistic");
}

/// build-and-test.md §5 "Edge pipeline": DO=1 to upstream groups, with DNSSEC records stripped
/// for DO=0 clients and kept for DO=1 clients.
#[test]
fn signed_answer_by_client_do() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::A, 3, 300, "example.com"),
    );
    m.opt(1232, 0, 0, true, &[]);
    let v = value(&m, "www.example.com", rtype::A);
    assert!(v.has_stripped_copy());
    let mut buf = [0u8; 1232];
    for (do_bit, expect) in [(Some(true), 2usize), (Some(false), 1), (None, 1)] {
        let q = client("www.example.com", rtype::A, do_bit);
        let r = serve_hit(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &v,
            &params(0, WIDE),
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        assert_eq!(d.answers.len(), expect, "client DO {do_bit:?}");
        if let Some(e) = &d.edns {
            assert_eq!(e.flags().dnssec_ok, do_bit == Some(true));
        }
        super::differential::assert_domain_accepts(&buf[..r.len]);
    }
}

/// build-and-test.md §5 "Edge pipeline": a DO=0 query for type RRSIG or NSEC.
#[test]
fn do0_query_for_rrsig_or_nsec() {
    let mut m = Msg::response(ID, "example.com", rtype::NSEC, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::NSEC,
        300,
        &nsec("a.example.com", &[rtype::A, rtype::NSEC]),
    );
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::NSEC, 2, 300, "example.com"),
    );
    let v = value(&m, "example.com", rtype::NSEC);
    let q = client("example.com", rtype::NSEC, Some(false));
    let mut buf = [0u8; 1232];
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &params(0, WIDE),
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers.len(), 1);
    assert_eq!(d.answers[0].record_type(), RecordType::NSEC);

    let mut m = Msg::response(ID, "example.com", rtype::RRSIG, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::SOA, 2, 300, "example.com"),
    );
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::NS, 2, 300, "example.com"),
    );
    let v = value(&m, "example.com", rtype::RRSIG);
    assert!(!v.has_stripped_copy());
    let q = client("example.com", rtype::RRSIG, None);
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &params(0, WIDE),
    )
    .unwrap();
    assert_eq!(decode(&buf[..r.len]).answers.len(), 2);
}

/// build-and-test.md §5 "Edge pipeline": a DO=0 variant where stripping removes a record ahead
/// of a kept compression target. The full copy's CNAME target compresses into the RRSIG's
/// signer name; the DO=0 copy is encoded on its own, so it never points into a removed record.
#[test]
fn do0_copy_encoded_separately() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::CNAME, 3, 300, "sig.example.net"),
    );
    m.rr(1, &ptr(12), rtype::CNAME, 300, &n("sig.example.net"));
    m.rr(1, &n("sig.example.net"), rtype::A, 300, &a("192.0.2.1"));
    m.opt(1232, 0, 0, true, &[]);
    let v = value(&m, "www.example.com", rtype::A);
    let full = copy_message(&v, true);
    let stripped = copy_message(&v, false);
    // In the full copy the CNAME data is a 2-byte pointer into the RRSIG's signer name.
    let fd = decode(&full);
    assert_eq!(fd.answers.len(), 3);
    let signer_at = full
        .windows(17)
        .position(|w| w == &n("sig.example.net")[..])
        .unwrap();
    let pointer = (0xC000u16 | signer_at as u16).to_be_bytes();
    assert!(
        full.windows(2).any(|w| w == pointer),
        "the CNAME compresses into the RRSIG"
    );
    // The DO=0 copy: no RRSIG, and every name decodes.
    let sd = decode(&stripped);
    assert_eq!(sd.answers.len(), 2);
    let RData::CNAME(c) = &sd.answers[0].data else {
        panic!()
    };
    assert_eq!(c.0.to_ascii(), "sig.example.net.");
    assert_eq!(sd.answers[1].name.to_ascii(), "sig.example.net.");
    super::differential::assert_domain_accepts(&stripped);
    // Served to a DO=0 client.
    let q = client("www.example.com", rtype::A, Some(false));
    let mut buf = [0u8; 1232];
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &params(10, WIDE),
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers.len(), 2);
    super::differential::assert_domain_accepts(&buf[..r.len]);
}

/// build-and-test.md §5 "Edge pipeline": an upstream answer whose pointer aims at a TTL, served
/// from cache after the TTL changes. The upstream's CNAME target and the A record's owner point
/// at the CNAME record's own TTL bytes, which spell "b" + a pointer to "example".
#[test]
fn upstream_pointer_into_ttl() {
    let mut m = Msg::response(ID, "a.example", rtype::A, 0);
    // Question at 12: \x01a (12..14) \x07example\x00 (14..23), type/class to 27.
    let rr1 = m.here();
    let ttl_at = rr1 + 2 + 4; // owner pointer (2), type (2), class (2)
    let ttl = u32::from_be_bytes([0x01, b'b', 0xC0, 14]); // "b" + pointer to "example"
    m.rr(1, &ptr(12), rtype::CNAME, ttl, &ptr(ttl_at));
    m.rr(1, &ptr(ttl_at), rtype::A, 300, &a("192.0.2.77"));
    let msg = m.build();
    let s = sent_for(ID, "a.example", rtype::A);
    let up = check_answer(&msg, &s.sent(), &AnswerLimits::default()).unwrap();
    assert_eq!(up.facts.chain[0].log_text(), "b.example");
    let v = CacheValue::new(up, SystemTime::now(), Instant::now());
    // hickory's encoding points only at names it wrote: TTLs change, names don't.
    let q = client("a.example", rtype::A, Some(false));
    let mut buf = [0u8; 1232];
    for age in [0u32, 1, 255, 70_000] {
        let r = serve_hit(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &v,
            &params(age, WIDE),
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        let RData::CNAME(c) = &d.answers[0].data else {
            panic!()
        };
        assert_eq!(c.0.to_ascii(), "b.example.");
        assert_eq!(d.answers[1].name.to_ascii(), "b.example.");
        assert_eq!(d.answers[0].ttl, ttl - age);
        assert_eq!(d.answers[1].ttl, 300u32.saturating_sub(age));
        super::differential::assert_domain_accepts(&buf[..r.len]);
    }
}

#[test]
fn tc_when_over_limit_and_core_rebuild_agrees() {
    let mut m = Msg::response(ID, "many.example", rtype::A, 0);
    for i in 0..40u8 {
        m.rr(1, &ptr(12), rtype::A, 300, &a(&format!("192.0.2.{i}")));
    }
    let v = value(&m, "many.example", rtype::A);
    let mut edge = vec![0u8; 65_535];
    let mut core = vec![0u8; 65_535];
    for opt in [None, Some(false), Some(true)] {
        let q = client("many.example", rtype::A, opt);
        for limit in [512usize, 600, 700, 1232, 65_535] {
            let to = ReplyTo {
                limit,
                ..q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD)
            };
            let e = serve_hit(&mut edge, &to, &v, &params(7, WIDE)).unwrap();
            // Core rebuilds with the edge's limit and checks the logged `tc`.
            let c = rebuild_reply(&mut core, &to, &v, &params(7, WIDE), e.tc).unwrap();
            assert_eq!(e, c, "opt {opt:?} limit {limit}");
            assert_eq!(&edge[..e.len], &core[..c.len]);
            assert_eq!(
                rebuild_reply(&mut core, &to, &v, &params(7, WIDE), !e.tc),
                Err(WriteError::TcMismatch)
            );
            let d = decode(&edge[..e.len]);
            if e.tc {
                assert!(d.truncation);
                assert!(d.answers.is_empty());
                assert_eq!(
                    e.len,
                    12 + q.question().len() + if opt.is_some() { 11 } else { 0 }
                );
            } else {
                assert!(e.len <= limit);
                assert_eq!(d.answers.len(), 40);
            }
        }
    }
    // 40 A records (16 bytes each with a pointer) don't fit 512 but fit 700.
    let q = client("many.example", rtype::A, Some(false));
    let to = ReplyTo {
        limit: 512,
        ..q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD)
    };
    assert!(serve_hit(&mut edge, &to, &v, &params(0, WIDE)).unwrap().tc);
    let to = ReplyTo {
        limit: 700,
        ..q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD)
    };
    assert!(!serve_hit(&mut edge, &to, &v, &params(0, WIDE)).unwrap().tc);
}

#[test]
fn question_length_must_match() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 100, &a("192.0.2.1"));
    let v = value(&m, "www.example.com", rtype::A);
    let q = client("www.example.org.x", rtype::A, None);
    let mut buf = [0u8; 512];
    assert_eq!(
        serve_hit(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &v,
            &params(0, WIDE)
        ),
        Err(WriteError::QuestionLength)
    );
}

#[test]
fn value_accessors() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 100, &a("192.0.2.1"));
    let now = Instant::now();
    let s = sent_for(ID, "www.example.com", rtype::A);
    let up = check_answer(&m.build(), &s.sent(), &AnswerLimits::default()).unwrap();
    let wire = up.wire().to_vec();
    let v = CacheValue::new(up, SystemTime::UNIX_EPOCH, now);
    assert_eq!(v.ttl(), Some(100));
    assert!(v.is_cacheable());
    assert!(!v.is_negative());
    assert_eq!(v.wire(), &wire[..]);
    assert_eq!(v.answer_id, None);
    assert_eq!(v.age_s(now + std::time::Duration::from_millis(2500)), 2);
    assert!(!v.is_expired(now + std::time::Duration::from_secs(99)));
    assert!(v.is_expired(now + std::time::Duration::from_secs(100)));
    assert!(v.weight() > wire.len());
    assert_eq!(v.received_at(), SystemTime::UNIX_EPOCH);
    assert_eq!(v.qtype(), rtype::A);
}

/// Core rebuilds from the logged wire: the scrub is idempotent, so the value equals the edge's.
#[test]
fn from_logged_wire_matches_edge() {
    for name in crate::testutil::RECORDED {
        let f = fixture(name);
        let sent = Sent::of(&f.query);
        let up = check_answer(&f.answer, &sent.sent(), &AnswerLimits::default()).unwrap();
        let edge = CacheValue::new(up, SystemTime::now(), Instant::now());
        let core = CacheValue::from_logged_wire(edge.wire(), SystemTime::now(), Instant::now()).unwrap();
        assert_eq!(core.wire(), edge.wire(), "{name}");
        for do_bit in [false, true] {
            assert_eq!(core.blob(do_bit), edge.blob(do_bit), "{name} DO={do_bit}");
            assert_eq!(copy_message(&core, do_bit), copy_message(&edge, do_bit), "{name}");
        }
        assert_eq!(core.facts(), edge.facts(), "{name}");
        assert_eq!(core.has_stripped_copy(), edge.has_stripped_copy(), "{name}");
        // Serving both gives the same bytes.
        let q = check_query(&f.query).unwrap();
        let mut a1 = vec![0u8; 65_535];
        let mut a2 = vec![0u8; 65_535];
        for do_bit in [Some(false), Some(true), None] {
            let to = ReplyTo {
                client_opt: do_bit,
                ..q.reply_to(Transport::Stream, crate::EDGE_UDP_PAYLOAD)
            };
            let e = serve_hit(&mut a1, &to, &edge, &params(3, WIDE)).unwrap();
            let c = rebuild_reply(&mut a2, &to, &core, &params(3, WIDE), false).unwrap();
            assert_eq!(&a1[..e.len], &a2[..c.len], "{name}");
        }
    }
}

#[test]
fn cname_rewrite_with_target_answer() {
    // The target's cached answer (DO=1 upstream answer, signed).
    let mut m = Msg::response(ID, "target.example.net", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("198.51.100.1"));
    m.rr(1, &ptr(12), rtype::A, 300, &a("198.51.100.2"));
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::A, 3, 300, "example.net"),
    );
    m.opt(1232, 0, 0, true, &[]);
    let target_value = value(&m, "target.example.net", rtype::A);
    let target = QName::from_text("target.example.net").unwrap();
    let q = client("Rewritten.Example.com", rtype::A, Some(false));
    let mut buf = [0u8; 1232];
    let p = params(100, TtlClamp { min: 0, max: 150 });
    let r = write_cname_rewrite(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        10,
        target.as_name(),
        &target_value,
        &p,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(&buf[12..12 + q.question().len()], q.question());
    assert_eq!(d.answers.len(), 3, "CNAME + two A, no RRSIG for a DO=0 client");
    assert_eq!(d.answers[0].name.to_ascii(), "Rewritten.Example.com.");
    let RData::CNAME(c) = &d.answers[0].data else {
        panic!()
    };
    assert_eq!(c.0.to_ascii(), "target.example.net.");
    assert_eq!(d.answers[0].ttl, 10);
    assert_eq!(d.answers[1].ttl, 150, "aged 300 - 100, clamped to 150");
    assert_eq!(d.answers[1].data, RData::A(Ipv4Addr::new(198, 51, 100, 1).into()));
    super::differential::assert_domain_accepts(&buf[..r.len]);
}

/// ER10 (edge.md §4 EDE table): a CNAME rewrite onto a stale target answer carries EDE 3 with its
/// cause and the target's records at `stale_ttl`, as a hit on the target would; a fresh one has no
/// EDE (rewrites carry none), nor does a client without an OPT.
#[test]
fn cname_rewrite_of_a_stale_target_carries_ede_3() {
    let mut m = Msg::response(ID, "target.example.net", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("198.51.100.1"));
    let target_value = value(&m, "target.example.net", rtype::A);
    let target = QName::from_text("target.example.net").unwrap();
    let stale = ServeParams {
        age_s: 400,
        clamp: WIDE,
        stale: Some(StaleServe {
            ttl: 30,
            cause: "optimistic",
        }),
    };
    let mut buf = [0u8; 1232];
    for (opt, p, want) in [
        (Some(false), stale, vec![(3u16, b"cause=optimistic".to_vec())]),
        (Some(false), params(0, WIDE), vec![]),
        (None, stale, vec![]),
    ] {
        let q = client("alias.example", rtype::A, opt);
        let r = write_cname_rewrite(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            10,
            target.as_name(),
            &target_value,
            &p,
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        assert_eq!(d.answers.len(), 2);
        assert_eq!(d.answers[0].ttl, 10, "the CNAME keeps its TTL");
        let ede: Vec<(u16, Vec<u8>)> = d
            .edns
            .as_ref()
            .map(|e| {
                e.options()
                    .options
                    .iter()
                    .map(|(_, v)| {
                        let b: Vec<u8> = v.try_into().unwrap();
                        (u16::from_be_bytes([b[0], b[1]]), b[2..].to_vec())
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(ede, want, "{opt:?} {:?}", p.stale);
        assert_eq!(r.ede, ede.len());
        if p.stale.is_some() {
            assert_eq!(d.answers[1].ttl, 30, "the target's records at stale_ttl");
        }
        super::differential::assert_domain_accepts(&buf[..r.len]);
    }
}

/// A stale hit over the client's limit drops EDE 3's text, then the option, before TC; a client
/// without an OPT gets no EDE (edge.md §4 EDE, §8).
#[test]
fn stale_hit_drops_ede_before_tc() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 100, &a("192.0.2.1"));
    let v = value(&m, "www.example.com", rtype::A);
    let q = client("www.example.com", rtype::A, Some(false));
    let p = ServeParams {
        age_s: 200,
        clamp: WIDE,
        stale: Some(StaleServe {
            ttl: 30,
            cause: "timeout",
        }),
    };
    let wide = q.reply_to(Transport::Stream, crate::EDGE_UDP_PAYLOAD);
    let mut buf = [0u8; 1232];
    let full = serve_hit(&mut buf, &wide, &v, &p).unwrap().len;
    let to = ReplyTo {
        limit: full - 1,
        ..wide
    };
    let r = serve_hit(&mut buf, &to, &v, &p).unwrap();
    assert!(!r.tc);
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers[0].ttl, 30);
    let opts = &d.edns.as_ref().unwrap().options().options;
    let bytes: Vec<u8> = (&opts[0].1).try_into().unwrap();
    assert_eq!(bytes, b"\x00\x03", "EDE 3 without its text");
    let bare = full - 6 - "cause=timeout".len();
    let r = serve_hit(&mut buf, &ReplyTo { limit: bare, ..wide }, &v, &p).unwrap();
    assert_eq!((r.tc, r.ede, r.len), (false, 0, bare));
    let r = serve_hit(
        &mut buf,
        &ReplyTo {
            limit: bare - 1,
            ..wide
        },
        &v,
        &p,
    )
    .unwrap();
    assert!(r.tc);
    let q = client("www.example.com", rtype::A, None);
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v,
        &p,
    )
    .unwrap();
    assert!(decode(&buf[..r.len]).edns.is_none());
}

/// Edge and core compute one `answer` id from the logged wire (api.md §5).
#[test]
fn answer_id_matches_on_edge_and_core() {
    let f = fixture("signed-nsec3-nxdomain");
    let sent = Sent::of(&f.query);
    let a = check_answer(&f.answer, &sent.sent(), &AnswerLimits::default()).unwrap();
    let edge = CacheValue::new(a, SystemTime::now(), Instant::now());
    let core = CacheValue::from_logged_wire(edge.wire(), SystemTime::now(), Instant::now()).unwrap();
    let id = crate::log::answer_id(edge.wire());
    assert_eq!(crate::log::answer_id(core.wire()), id);
    assert_eq!(crate::log::answer_id_text(id).len(), 16);
}

/// W1: RFC 2308 §5: a negative answer's lifetime is min(SOA TTL, SOA MINIMUM), carried in the
/// SOA's header TTL, which decrements while cached. A hit must advertise what is left of that,
/// not the SOA's own TTL less its age: SOA TTL 3600 and MINIMUM 300 at age 299 is 1 s, not 300.
#[test]
fn negative_ttl_ages_from_min_of_soa_ttl_and_minimum() {
    let mut m = Msg::response(ID, "gone.example.com", rtype::A, 3);
    m.rr(
        2,
        &n("example.com"),
        rtype::SOA,
        3600,
        &crate::testutil::soa(&n("ns.example.com"), &n("h.example.com"), 1, 300),
    );
    let v = value(&m, "gone.example.com", rtype::A);
    assert_eq!(v.ttl(), Some(300));
    let q = client("gone.example.com", rtype::A, Some(false));
    let mut buf = [0u8; 1232];
    for (age, expect) in [(0u32, 300u32), (299, 1), (300, 0)] {
        let r = serve_hit(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &v,
            &params(age, WIDE),
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        let soa = &d.authorities[0];
        let RData::SOA(data) = &soa.data else { panic!() };
        assert_eq!(data.minimum, 300, "MINIMUM is RDATA: never touched");
        assert_eq!(soa.ttl, expect, "age {age}");
    }
    // The logged wire keeps the upstream's original TTLs (api.md §5), and core's value from it
    // serves the same bytes.
    let logged = decode(v.wire());
    assert_eq!(logged.authorities[0].ttl, 3600);
    let core = CacheValue::from_logged_wire(v.wire(), SystemTime::now(), Instant::now()).unwrap();
    let mut a1 = [0u8; 1232];
    let mut a2 = [0u8; 1232];
    let to = q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD);
    let e = serve_hit(&mut a1, &to, &v, &params(299, WIDE)).unwrap();
    let c = serve_hit(&mut a2, &to, &core, &params(299, WIDE)).unwrap();
    assert_eq!(&a1[..e.len], &a2[..c.len]);
}

/// W2: an upstream answer with TC set (RFC 1035 §4.1.1) is partial. It is served in the TC form
/// (header, question, any OPT, TC set) on every transport, so the client never takes it for a
/// complete answer, and the reply is logged as `tc` (api.md §5).
#[test]
fn upstream_tc_answer_served_with_tc() {
    let mut m = Msg::with_flags(ID, 0x83, 0x80); // QR, TC, RD; RA
    m.question(&n("big.example"), rtype::TXT, 1);
    m.rr(1, &ptr(12), rtype::TXT, 300, b"\x05part1");
    let v = value(&m, "big.example", rtype::TXT);
    assert!(v.facts().tc);
    assert!(!v.is_cacheable());
    let mut buf = vec![0u8; 65_535];
    for opt in [None, Some(false), Some(true)] {
        let q = client("big.example", rtype::TXT, opt);
        for transport in [Transport::Udp, Transport::Stream] {
            let to = q.reply_to(transport, crate::EDGE_UDP_PAYLOAD);
            let r = serve_hit(&mut buf, &to, &v, &params(0, WIDE)).unwrap();
            assert!(r.tc, "{opt:?} {transport:?}");
            let d = decode(&buf[..r.len]);
            assert!(d.truncation);
            assert!(d.answers.is_empty());
            assert_eq!(d.edns.is_some(), opt.is_some());
            // Logged as `tc`; core rebuilds the same TC form.
            let proto = if transport == Transport::Udp {
                Proto::Udp
            } else {
                Proto::Tcp
            };
            let logged = ReplyTo::logged(
                v.question(),
                v.cd(),
                proto,
                q.do_bit(),
                q.edns_log().as_ref(),
                crate::EDGE_UDP_PAYLOAD,
            );
            let mut core = vec![0u8; 65_535];
            let c = rebuild_reply(&mut core, &logged, &v, &params(0, WIDE), true).unwrap();
            assert_eq!(&buf[2..r.len], &core[2..c.len]);
        }
    }
    // A CNAME rewrite onto a truncated target answer is truncated too.
    let target = QName::from_text("big.example").unwrap();
    let q = client("alias.example", rtype::TXT, Some(false));
    let r = write_cname_rewrite(
        &mut buf,
        &q.reply_to(Transport::Stream, crate::EDGE_UDP_PAYLOAD),
        10,
        target.as_name(),
        &v,
        &params(0, WIDE),
    )
    .unwrap();
    assert!(r.tc);
    let d = decode(&buf[..r.len]);
    assert!(d.truncation);
    assert!(d.answers.is_empty());
}

/// W4: a stale hit near the client's UDP size drops EDE 3's text, or the whole option, to fit.
/// Core rebuilds the reply from what the `q` record logs (`proto`, `do`, `edns`, `age_s`,
/// `upstream.cause`, `tc`) with the edge's limit, so it drops exactly what the edge dropped
/// (core.md §6: "the referenced answer as the edge served it").
#[test]
fn rebuild_reproduces_ede_dropped_near_the_udp_size() {
    // 29 A records: 12 + question + 29 × 16 + OPT 11 bytes. "many.example" leaves room for a
    // bare EDE 3 within 512 but not its text; "many12.example" leaves room for neither.
    for (name, kept_ede) in [("many.example", 1usize), ("many12.example", 0)] {
        let mut m = Msg::response(ID, name, rtype::A, 0);
        for i in 0..29u8 {
            m.rr(1, &ptr(12), rtype::A, 300, &a(&format!("192.0.2.{i}")));
        }
        let v = value(&m, name, rtype::A);
        let mut m = Msg::query(0x0B0B, name, rtype::A);
        m.opt(512, 0, 0, false, &[]);
        let q = check_query(&m.build()).unwrap();
        let p = ServeParams {
            age_s: 400,
            clamp: WIDE,
            stale: Some(StaleServe {
                ttl: 30,
                cause: "timeout",
            }),
        };
        let mut edge = vec![0u8; 65_535];
        let mut core = vec![0u8; 65_535];
        let e = serve_hit(
            &mut edge,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &v,
            &p,
        )
        .unwrap();
        assert!(!e.tc, "{name}");
        assert_eq!(e.ede, kept_ede, "{name}");
        assert!(e.len <= 512);
        let to = ReplyTo::logged(
            v.question(),
            v.cd(),
            Proto::Udp,
            q.do_bit(),
            q.edns_log().as_ref(),
            crate::EDGE_UDP_PAYLOAD,
        );
        let c = rebuild_reply(&mut core, &to, &v, &p, e.tc).unwrap();
        assert_eq!(e.len, c.len, "{name}");
        assert_eq!(&edge[2..e.len], &core[2..c.len], "{name}: all but the ID");
    }
}

/// W4, W7: across transports, OPT shapes (none, small, large, padded), DO, stale and answer
/// sizes, core's rebuild from the logged fields equals the edge's reply but for the ID and the
/// question's letter case, and agrees with the logged `tc`.
#[test]
fn rebuild_from_the_log_matches_the_edge() {
    let mut answers = Vec::new();
    for (name, n) in [("small.example", 1u8), ("mid.example", 29), ("big.example", 60)] {
        let mut m = Msg::response(ID, name, rtype::A, 0);
        for i in 0..n {
            m.rr(1, &ptr(12), rtype::A, 300, &a(&format!("192.0.2.{i}")));
        }
        m.rr(
            1,
            &ptr(12),
            rtype::RRSIG,
            300,
            &rrsig(rtype::A, 2, 300, "example"),
        );
        answers.push((name, value(&m, name, rtype::A)));
    }
    let mut edge = vec![0u8; 65_535];
    let mut core = vec![0u8; 65_535];
    let pad = [(edns_code::PADDING, &[0u8; 20][..])];
    for (name, v) in &answers {
        for opt in [
            None,
            Some((512u16, false)),
            Some((1232, true)),
            Some((4096, false)),
        ] {
            for padded in [false, true] {
                if padded && opt.is_none() {
                    continue;
                }
                let mut m = Msg::query(0x0B0B, &name.to_uppercase(), rtype::A);
                if let Some((udp, do_bit)) = opt {
                    m.opt(udp, 0, 0, do_bit, if padded { &pad } else { &[] });
                }
                let q = check_query(&m.build()).unwrap();
                for (transport, proto) in [
                    (Transport::Udp, Proto::Udp),
                    (Transport::Stream, Proto::Tcp),
                    (Transport::Encrypted, Proto::Dot),
                    (Transport::Encrypted, Proto::Doh),
                ] {
                    for stale in [None, Some("optimistic")] {
                        let p = ServeParams {
                            age_s: 12,
                            clamp: WIDE,
                            stale: stale.map(|cause| StaleServe { ttl: 30, cause }),
                        };
                        let e = serve_hit(&mut edge, &q.reply_to(transport, 1400), v, &p).unwrap();
                        let to = ReplyTo::logged(
                            v.question(),
                            v.cd(),
                            proto,
                            q.do_bit(),
                            q.edns_log().as_ref(),
                            1400,
                        );
                        let c = rebuild_reply(&mut core, &to, v, &p, e.tc).unwrap_or_else(|err| {
                            panic!("{name} {opt:?} pad {padded} {proto:?} {stale:?}: {err}")
                        });
                        let what = format!("{name} {opt:?} pad {padded} {proto:?} {stale:?}");
                        assert_eq!((e.len, e.tc, e.ede), (c.len, c.tc, c.ede), "{what}");
                        let qlen = 12 + q.question().len();
                        assert_eq!(&edge[2..12], &core[2..12], "{what}: header");
                        assert!(
                            edge[12..qlen].eq_ignore_ascii_case(&core[12..qlen]),
                            "{what}: question"
                        );
                        assert_eq!(&edge[qlen..e.len], &core[qlen..c.len], "{what}");
                        if transport == Transport::Encrypted && padded {
                            assert_eq!(e.len % crate::reply::REPLY_PAD_BLOCK, 0, "{what}");
                        }
                    }
                }
            }
        }
    }
}
