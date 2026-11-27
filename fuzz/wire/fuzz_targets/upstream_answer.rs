//! The upstream answer pipeline (edge.md §7) with `domain` as the differential oracle
//! (build-and-test.md §4): a message the pipeline accepts that `domain` rejects for a reason §7
//! checks, or whose A/AAAA values or names decode differently, is a bug; record data `domain`
//! leaves opaque is not. Also: the scrub is idempotent (core rebuilds from the logged wire); every
//! served hit, fresh or stale, over UDP, TCP or DoH, decodes, re-checks with the same facts, and
//! carries no record the DO=0 predicate strips when the client didn't set DO; core's rebuild from
//! the logged fields gives the same bytes; and an answer accepted for a fixed query carries
//! exactly that query's ID and question.

#![no_main]

use std::time::{Instant, SystemTime};

use libfuzzer_sys::fuzz_target;
use picket_api::edge_config::TtlClamp;
use picket_api::logs::Proto;
use picket_wire::answer::{AddrSource, AnswerLimits, SentQuery, check_answer};
use picket_wire::cache::{CacheValue, ServeParams, StaleServe, rebuild_reply, serve_hit};
use picket_wire::dnssec::strip_for_do0;
use picket_wire::name::QName;
use picket_wire::query::check_query;
use picket_wire::reply::{ReplyTo, Transport};
use picket_wire_fuzz::oracle::{domain_decode, domain_facts};
use picket_wire_fuzz::sent_of;

fuzz_target!(|data: &[u8]| {
    // A fixed query: anything accepted for it carries its ID and question, whatever the case.
    if let [i0, i1, hint, ..] = data {
        let id = u16::from_be_bytes([*i0, *i1]);
        let fixed = QName::from_text("www.example.com").expect("name");
        let qtype = [1u16, 28, 65, 5][usize::from(hint & 3)];
        let sent = SentQuery {
            id,
            qname: fixed.as_name(),
            qtype,
            qclass: 1,
        };
        if check_answer(data, &sent, &AnswerLimits::default()).is_ok() {
            let (own_id, own, own_type, own_class) = sent_of(data).expect("accepted without a question");
            assert_eq!((own_id, own_type, own_class), (id, qtype, 1));
            assert_eq!(own, fixed);
        }
    }

    let Some((id, qname, qtype, qclass)) = sent_of(data) else {
        return;
    };
    let sent = SentQuery {
        id,
        qname: qname.as_name(),
        qtype,
        qclass,
    };
    let Ok(answer) = check_answer(data, &sent, &AnswerLimits::default()) else {
        return;
    };
    // The oracle on the input.
    if let Err(e) = domain_decode(data) {
        panic!("accepted a message domain rejects: {e}");
    }
    let d = domain_facts(data).expect("domain facts");
    let f = &answer.facts;
    let chain: Vec<Vec<u8>> = f.chain.iter().map(|w| w.wire().to_vec()).collect();
    assert_eq!(chain, d.chain, "chain");
    let addrs: Vec<_> = f
        .addrs
        .iter()
        .filter(|a| matches!(a.source, AddrSource::A | AddrSource::Aaaa))
        .map(|a| a.ip)
        .collect();
    assert_eq!(addrs, d.addrs, "A/AAAA");
    let hints: Vec<_> = f
        .addrs
        .iter()
        .filter(|a| matches!(a.source, AddrSource::Ipv4Hint | AddrSource::Ipv6Hint))
        .map(|a| (a.ip, a.source == AddrSource::Ipv4Hint))
        .collect();
    assert_eq!(hints, d.hints, "hints");
    let targets: Vec<Vec<u8>> = f.targets.iter().map(|w| w.wire().to_vec()).collect();
    assert_eq!(targets, d.targets, "targets");
    // The oracle on what we wrote.
    domain_decode(answer.wire()).expect("domain rejects the scrubbed wire");

    let value = CacheValue::new(answer, SystemTime::now(), Instant::now());
    // Idempotent: core's value from the logged wire is the edge's.
    let core = CacheValue::from_logged_wire(value.wire(), SystemTime::now(), Instant::now())
        .expect("logged wire re-checks");
    assert_eq!(core.wire(), value.wire());
    assert_eq!(core.blob(false), value.blob(false));
    assert_eq!(core.facts(), value.facts());

    // Serve to clients with and without an OPT, DO and Padding, over each transport, fresh and
    // stale; core rebuilds the same bytes from what the `q` record logs (core.md §6).
    let mut edge = vec![0u8; 65_535];
    let mut rebuilt = vec![0u8; 65_535];
    let opts = [
        None,
        Some((512u16, false, false)),
        Some((1232, true, false)),
        Some((4096, false, true)),
    ];
    for opt in opts {
        // The client's query: ID 0 (the log has no ID), the answer's question and CD.
        let msg = client_query(value.question(), value.cd(), opt);
        let Ok(q) = check_query(&msg) else {
            return;
        };
        for (transport, proto) in [
            (Transport::Udp, Proto::Udp),
            (Transport::Stream, Proto::Tcp),
            (Transport::Encrypted, Proto::Doh),
        ] {
            for stale in [None, Some("timeout")] {
                let to = q.reply_to(transport, picket_wire::EDGE_UDP_PAYLOAD);
                let p = ServeParams {
                    age_s: 17,
                    clamp: TtlClamp::default(),
                    stale: stale.map(|cause| StaleServe { ttl: 30, cause }),
                };
                let r = serve_hit(&mut edge, &to, &value, &p).unwrap();
                assert!(r.len <= to.limit);
                let (_, _, recs) = domain_decode(&edge[..r.len]).expect("domain rejects a served hit");
                if !q.do_bit() {
                    for rec in &recs {
                        assert!(
                            !strip_for_do0(rec.rtype, qtype),
                            "a DO=0 hit carries type {}",
                            rec.rtype
                        );
                    }
                }
                if r.tc {
                    assert!(recs.iter().all(|rec| rec.section == 3), "records in a TC reply");
                } else {
                    // What the client got reads back as the answer it was served from.
                    let back = SentQuery {
                        id: 0,
                        qname: qname.as_name(),
                        qtype,
                        qclass,
                    };
                    let again = check_answer(&edge[..r.len], &back, &AnswerLimits::default())
                        .expect("a served hit re-checks");
                    assert_eq!(again.facts.addrs, value.facts().addrs, "served addresses");
                    assert_eq!(again.facts.chain, value.facts().chain, "served chain");
                    assert_eq!(again.facts.targets, value.facts().targets, "served targets");
                }
                let logged = ReplyTo::logged(
                    core.question(),
                    core.cd(),
                    proto,
                    q.do_bit(),
                    q.edns_log().as_ref(),
                    picket_wire::EDGE_UDP_PAYLOAD,
                );
                let c = rebuild_reply(&mut rebuilt, &logged, &core, &p, r.tc).unwrap();
                assert_eq!(&edge[..r.len], &rebuilt[..c.len]);
            }
        }
    }
});

/// A client query with ID 0, RD, `cd`, `question` and, with `opt`, an OPT advertising its UDP
/// size and DO, with a Padding option when asked.
fn client_query(question: &[u8], cd: bool, opt: Option<(u16, bool, bool)>) -> Vec<u8> {
    let mut m = vec![
        0,
        0,
        0x01,
        if cd { 0x10 } else { 0 },
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        u8::from(opt.is_some()),
    ];
    m.extend_from_slice(question);
    if let Some((udp, do_bit, pad)) = opt {
        m.push(0);
        m.extend_from_slice(&41u16.to_be_bytes());
        m.extend_from_slice(&udp.to_be_bytes());
        m.extend_from_slice(&[0, 0, if do_bit { 0x80 } else { 0 }, 0]);
        if pad {
            m.extend_from_slice(&[0, 8, 0, 12, 0, 4, 0, 0, 0, 0]);
        } else {
            m.extend_from_slice(&[0, 0]);
        }
    }
    m
}
