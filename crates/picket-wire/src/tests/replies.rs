//! Reply writers (edge.md §4: blocked answers, rewrites, host-IP mappings, ANY, local names, the
//! EDE table and the EXTRA-TEXT token rules).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};
use picket_api::edge_config::{BlockResponse, BlockResponseType};

use super::decode;
use crate::ede::EdeOption;
use crate::name::QName;
use crate::query::{Query, check_query};
use crate::reply::{
    MappingAnswer, NegativeKind, RecordData, RecordSpec, ReplyTo, Transport, write_any_minimal, write_block,
    write_host_mapping, write_local_answer, write_negative, write_rcode, write_records,
};
use crate::testutil::{Msg, n};
use crate::types::{ede_code, edns_code, rcode, rtype};

fn query(name: &str, qtype: u16, opt: Option<(u16, bool)>) -> (Vec<u8>, Query) {
    let mut m = Msg::query(0x4242, name, qtype);
    if let Some((udp, do_bit)) = opt {
        m.opt(udp, 0, 0, do_bit, &[]);
    }
    let msg = m.build();
    let q = check_query(&msg).unwrap();
    (msg, q)
}

/// The EDE options of a reply, as (code, text).
fn edes(reply: &[u8]) -> Vec<(u16, String)> {
    let m = decode(reply);
    let Some(edns) = m.edns.as_ref() else {
        return vec![];
    };
    edns.options()
        .options
        .iter()
        .filter(|(c, _)| u16::from(*c) == edns_code::EDE)
        .map(|(_, o)| {
            let bytes: Vec<u8> = o.try_into().unwrap();
            (
                u16::from_be_bytes([bytes[0], bytes[1]]),
                String::from_utf8(bytes[2..].to_vec()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn header_flags() {
    let mut m = Msg::with_flags(0x0102, 0x01, 0x10 | 0x20); // RD, CD, AD
    m.question(&n("Example.com"), rtype::A, 1);
    m.opt(1232, 0, 0, true, &[]);
    let q = check_query(&m.build()).unwrap();
    let mut buf = [0u8; 512];
    let r = write_rcode(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        rcode::REFUSED,
        &[],
    )
    .unwrap();
    let out = &buf[..r.len];
    assert_eq!(&out[..2], &[0x01, 0x02]);
    assert_eq!(out[2], 0x81, "QR, opcode 0, RD");
    assert_eq!(out[3], 0x80 | 0x10 | 5, "RA, CD, no AD, REFUSED");
    // The client's question bytes, case included.
    assert_eq!(&out[12..12 + q.question().len()], q.question());
    let d = decode(out);
    assert!(d.edns.as_ref().unwrap().flags().dnssec_ok);
    assert_eq!(d.edns.as_ref().unwrap().max_payload(), crate::EDGE_UDP_PAYLOAD);
}

#[test]
fn refused_ede18_only_with_opt() {
    let (_, q) = query("example.com", rtype::A, Some((1232, false)));
    let mut buf = [0u8; 512];
    let r = write_rcode(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        rcode::REFUSED,
        &[EdeOption::not_permitted()],
    )
    .unwrap();
    assert_eq!(r.ede, 1);
    assert_eq!(
        edes(&buf[..r.len]),
        vec![(18, "not permitted from this address".into())]
    );

    // No OPT in the query: no OPT, so no EDE (RFC 6891 §7).
    let (_, q) = query("example.com", rtype::A, None);
    let r = write_rcode(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        rcode::REFUSED,
        &[EdeOption::not_permitted()],
    )
    .unwrap();
    assert_eq!(r.ede, 0);
    let d = decode(&buf[..r.len]);
    assert!(d.edns.is_none());
    assert_eq!(d.response_code, ResponseCode::Refused);
    assert_eq!(&buf[10..12], &[0, 0]);
}

#[test]
fn servfail_ede23() {
    let (_, q) = query("example.com", rtype::A, Some((1232, true)));
    let mut buf = [0u8; 512];
    let r = write_rcode(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        rcode::SERVFAIL,
        &[EdeOption::no_upstream("timeout")],
    )
    .unwrap();
    assert_eq!(
        edes(&buf[..r.len]),
        vec![(ede_code::NETWORK_ERROR, "cause=timeout".into())]
    );
}

#[test]
fn negative_with_synthesised_soa() {
    let (_, q) = query("ads.example.com", rtype::A, Some((1232, false)));
    let mut buf = [0u8; 512];
    for (kind, rc) in [
        (NegativeKind::Nxdomain, ResponseCode::NXDomain),
        (NegativeKind::Nodata, ResponseCode::NoError),
    ] {
        let r = write_negative(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            kind,
            42,
            &[],
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        assert_eq!(d.response_code, rc);
        assert!(d.answers.is_empty());
        assert_eq!(d.authorities.len(), 1);
        let soa = &d.authorities[0];
        assert_eq!(soa.ttl, 42);
        assert_eq!(soa.name.to_ascii(), "ads.example.com.");
        let RData::SOA(s) = &soa.data else { panic!() };
        assert_eq!(s.minimum, 42);
    }
}

fn block_resp(kind: BlockResponseType) -> BlockResponse {
    BlockResponse {
        kind,
        ipv4: Some(Ipv4Addr::new(192, 0, 2, 7)),
        ipv6: Some("2001:db8::7".parse().unwrap()),
        ttl: 10,
    }
}

#[test]
fn block_responses() {
    let ede = EdeOption::blocked_by_bundle("block-common", "c02f7a9e1b4d6e83", "k3j9q2");
    let text = "bundle=block-common@c02f7a9e1b4d6e83 block=k3j9q2".to_string();
    let mut buf = [0u8; 1232];

    // null_ip: 0.0.0.0 for A, :: for AAAA, NODATA for others; EDE 4 only with records.
    let (_, q) = query("ads.example.com", rtype::A, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &block_resp(BlockResponseType::NullIp),
        ede,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers.len(), 1);
    assert_eq!(d.answers[0].ttl, 10);
    assert_eq!(d.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED.into()));
    assert_eq!(edes(&buf[..r.len]), vec![(15, text.clone()), (4, String::new())]);

    let (_, q) = query("ads.example.com", rtype::AAAA, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &block_resp(BlockResponseType::NullIp),
        ede,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers[0].data, RData::AAAA(Ipv6Addr::UNSPECIFIED.into()));

    let (_, q) = query("ads.example.com", rtype::TXT, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &block_resp(BlockResponseType::NullIp),
        ede,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert!(d.answers.is_empty());
    assert_eq!(d.authorities[0].record_type(), RecordType::SOA);
    assert_eq!(edes(&buf[..r.len]), vec![(15, text.clone())]);

    // custom_ip.
    let (_, q) = query("ads.example.com", rtype::A, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &block_resp(BlockResponseType::CustomIp),
        ede,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 7).into()));

    // nxdomain, nodata, refused: EDE 15 only.
    for (kind, rc) in [
        (BlockResponseType::Nxdomain, ResponseCode::NXDomain),
        (BlockResponseType::Nodata, ResponseCode::NoError),
        (BlockResponseType::Refused, ResponseCode::Refused),
    ] {
        let r = write_block(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &block_resp(kind),
            ede,
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        assert_eq!(d.response_code, rc);
        assert!(d.answers.is_empty());
        assert_eq!(edes(&buf[..r.len]), vec![(15, text.clone())]);
        if kind != BlockResponseType::Refused {
            let RData::SOA(s) = &d.authorities[0].data else {
                panic!()
            };
            assert_eq!((d.authorities[0].ttl, s.minimum), (10, 10));
        }
    }
}

#[test]
fn lookup_block_ede_text() {
    let (_, q) = query("bad.example.org", rtype::A, Some((1232, false)));
    let mut buf = [0u8; 512];
    let ede = EdeOption::blocked_by_lookup("q9", "timeout", "k3j9q2");
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &block_resp(BlockResponseType::Nxdomain),
        ede,
    )
    .unwrap();
    assert_eq!(
        edes(&buf[..r.len]),
        vec![(15, "lookup=q9 verdict=timeout block=k3j9q2".into())]
    );
}

/// build-and-test.md §5 "Edge EDE": EXTRA-TEXT past the 128-byte cap.
#[test]
fn extra_text_cap() {
    let (_, q) = query("ads.example.com", rtype::A, Some((1232, false)));
    let long_bundle = "b".repeat(110);
    let ede = EdeOption::blocked_by_bundle(&long_bundle, "c02f7a9e1b4d6e83", "k3j9q2");
    let mut buf = [0u8; 1232];
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &block_resp(BlockResponseType::NullIp),
        ede,
    )
    .unwrap();
    assert_eq!(
        edes(&buf[..r.len]),
        vec![(15, "block=k3j9q2".into()), (4, String::new())]
    );
}

/// Over the client's UDP size: tokens go from the left, then EDE options, before records are
/// dropped or TC set.
#[test]
fn udp_size_drops_ede_before_tc() {
    // 30 local addresses: 12 + 17 + 30*16 + 11 = 520 bytes > 512.
    let addrs: Vec<IpAddr> = (1..=30u8)
        .map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)))
        .collect();
    let (_, q) = query("dns.home.arpa", rtype::A, Some((512, false)));
    let mut buf = [0u8; 2048];
    let r = write_local_answer(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &addrs,
        60,
    )
    .unwrap();
    assert!(r.tc);
    assert_eq!(r.len, 12 + q.question().len() + 11);
    let d = decode(&buf[..r.len]);
    assert!(d.truncation);
    assert!(d.answers.is_empty());
    assert!(d.edns.is_some());

    // 27 addresses fit (12 + 19 + 27*16 = 463, + OPT 11 = 474), leaving 38 bytes for EDE.
    let addrs: Vec<IpAddr> = (1..=27u8)
        .map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)))
        .collect();
    let (_, q) = query("ads.example.org", rtype::A, Some((512, false)));
    let to = q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD);
    let specs: Vec<RecordSpec<'_>> = addrs
        .iter()
        .map(|a| RecordSpec {
            owner: None,
            ttl: 10,
            data: match a {
                IpAddr::V4(v) => RecordData::A(*v),
                IpAddr::V6(v) => RecordData::Aaaa(*v),
            },
        })
        .collect();
    let ede = [
        EdeOption::blocked_by_lookup("provider", "block", "abc"),
        EdeOption::forged(),
    ];
    let r = write_records(&mut buf, &to, rcode::NOERROR, &specs, &[], &ede).unwrap();
    assert!(!r.tc);
    assert!(r.len <= 512);
    // 38 bytes: EDE 15 keeps "verdict=block block=abc" (6 + 23 = 29) and EDE 4 (6) = 35.
    assert_eq!(
        edes(&buf[..r.len]),
        vec![(15, "verdict=block block=abc".into()), (4, String::new())]
    );
    assert_eq!(decode(&buf[..r.len]).answers.len(), 27);

    // Tighter: only room for EDE options without text, then none.
    let (_, q) = query("ads.example.org.x", rtype::A, Some((512, false)));
    let r = write_records(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        rcode::NOERROR,
        &specs,
        &[],
        &ede,
    )
    .unwrap();
    assert!(!r.tc);
    let e = edes(&buf[..r.len]);
    assert!(e.len() <= 2 && e.iter().all(|(_, t)| t.len() < 23), "{e:?}");
}

#[test]
fn tc_over_tcp_never() {
    let addrs: Vec<IpAddr> = (1..=100u8)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
        .collect();
    let (_, q) = query("dns.home.arpa", rtype::A, None);
    let mut buf = vec![0u8; 65_535];
    let r = write_local_answer(
        &mut buf,
        &q.reply_to(Transport::Stream, crate::EDGE_UDP_PAYLOAD),
        &addrs,
        60,
    )
    .unwrap();
    assert!(!r.tc);
    assert_eq!(decode(&buf[..r.len]).answers.len(), 100);
    // The same over UDP without an OPT: 512 bytes, TC.
    let r = write_local_answer(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &addrs,
        60,
    )
    .unwrap();
    assert!(r.tc);
}

#[test]
fn rewrite_records() {
    let (_, q) = query("svc.example.com", rtype::A, Some((1232, false)));
    let target = QName::from_text("target.example.net").unwrap();
    let mx = QName::from_text("mail.example.net").unwrap();
    let https = crate::testutil::svcb(1, ".", &[(1, b"\x02h2".to_vec()), (4, vec![192, 0, 2, 1])]);
    let txt: [&[u8]; 2] = [b"v=spf1 -all", b""];
    let specs = [
        RecordSpec {
            owner: None,
            ttl: 30,
            data: RecordData::Cname(target.as_name()),
        },
        RecordSpec {
            owner: Some(target.as_name()),
            ttl: 30,
            data: RecordData::A(Ipv4Addr::new(198, 51, 100, 1)),
        },
        RecordSpec {
            owner: Some(target.as_name()),
            ttl: 30,
            data: RecordData::Mx {
                preference: 10,
                exchange: mx.as_name(),
            },
        },
        RecordSpec {
            owner: Some(target.as_name()),
            ttl: 30,
            data: RecordData::Txt(&txt),
        },
        RecordSpec {
            owner: Some(target.as_name()),
            ttl: 30,
            data: RecordData::Srv {
                priority: 1,
                weight: 2,
                port: 443,
                target: mx.as_name(),
            },
        },
        RecordSpec {
            owner: Some(target.as_name()),
            ttl: 30,
            data: RecordData::Raw {
                rtype: rtype::HTTPS,
                rdata: &https,
            },
        },
        RecordSpec {
            owner: Some(target.as_name()),
            ttl: 30,
            data: RecordData::Ptr(mx.as_name()),
        },
    ];
    let mut buf = [0u8; 1232];
    let r = write_records(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        rcode::NOERROR,
        &specs,
        &[],
        &[],
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers.len(), 7);
    assert_eq!(d.answers[0].name.to_ascii(), "svc.example.com.");
    let RData::CNAME(c) = &d.answers[0].data else {
        panic!()
    };
    assert_eq!(c.0.to_ascii(), "target.example.net.");
    let RData::HTTPS(h) = &d.answers[5].data else {
        panic!()
    };
    assert_eq!(h.svc_priority, 1);
    assert_eq!(r.ede, 0);
    super::differential::assert_domain_accepts(&buf[..r.len]);
}

#[test]
fn txt_string_over_255_refused() {
    let (_, q) = query("x.example", rtype::TXT, None);
    let long = vec![b'a'; 256];
    let txt: [&[u8]; 1] = [&long];
    let specs = [RecordSpec {
        owner: None,
        ttl: 1,
        data: RecordData::Txt(&txt),
    }];
    let mut buf = [0u8; 1232];
    assert_eq!(
        write_records(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            0,
            &specs,
            &[],
            &[]
        ),
        Err(crate::wire::WriteError::TooLong)
    );
}

#[test]
fn any_minimal() {
    let (_, q) = query("example.com", rtype::ANY, Some((1232, false)));
    let mut buf = [0u8; 512];
    let r = write_any_minimal(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        3789,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers.len(), 1);
    let RData::HINFO(h) = &d.answers[0].data else {
        panic!()
    };
    assert_eq!(&h.cpu[..], &b"RFC8482"[..]);
    assert!(h.os.is_empty());
    assert_eq!(d.answers[0].ttl, 3789);
}

#[test]
fn local_answers() {
    let addrs: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap(), "fd00::1".parse().unwrap()];
    let mut buf = [0u8; 512];
    for (qtype, expect) in [(rtype::A, 1usize), (rtype::AAAA, 1), (rtype::HTTPS, 0)] {
        let (_, q) = query("dns.home.arpa", qtype, None);
        let r = write_local_answer(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &addrs,
            60,
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        assert_eq!(d.answers.len(), expect);
        if expect == 0 {
            assert_eq!(d.authorities[0].record_type(), RecordType::SOA);
        }
    }
    let only_v4: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
    let (_, q) = query("dns.home.arpa", rtype::AAAA, None);
    let r = write_local_answer(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &only_v4,
        60,
    )
    .unwrap();
    assert!(decode(&buf[..r.len]).answers.is_empty());
}

#[test]
fn host_mappings() {
    let v4 = [Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 11)];
    let ede = EdeOption::blocked_by_bundle("b", "h", "id");
    let mut buf = [0u8; 512];
    let (_, q) = query("mapped.example", rtype::A, Some((1232, false)));
    let (r, kind) = write_host_mapping(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v4,
        &[],
        10,
        ede,
    )
    .unwrap();
    assert_eq!(kind, MappingAnswer::Rewrite);
    assert_eq!(decode(&buf[..r.len]).answers.len(), 2);
    assert!(edes(&buf[..r.len]).is_empty());
    // No IPv6 mapping: :: as a block, with EDE 15 and 4.
    let (_, q) = query("mapped.example", rtype::AAAA, Some((1232, false)));
    let (r, kind) = write_host_mapping(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v4,
        &[],
        10,
        ede,
    )
    .unwrap();
    assert_eq!(kind, MappingAnswer::Block);
    assert_eq!(
        decode(&buf[..r.len]).answers[0].data,
        RData::AAAA(Ipv6Addr::UNSPECIFIED.into())
    );
    assert_eq!(edes(&buf[..r.len]).len(), 2);
    // Other types: NODATA block.
    let (_, q) = query("mapped.example", rtype::MX, Some((1232, false)));
    let (r, kind) = write_host_mapping(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &v4,
        &[],
        10,
        ede,
    )
    .unwrap();
    assert_eq!(kind, MappingAnswer::Block);
    assert!(decode(&buf[..r.len]).answers.is_empty());
}

#[test]
fn buffer_too_small_is_an_error_not_a_panic() {
    let (_, q) = query("example.com", rtype::A, Some((1232, false)));
    let mut buf = [0u8; 20];
    assert_eq!(
        write_rcode(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            rcode::REFUSED,
            &[]
        ),
        Err(crate::wire::WriteError::BufferTooSmall)
    );
}

#[test]
fn core_built_reply_to() {
    // Core builds a ReplyTo from a log record: the question from the logged name.
    let qname = QName::from_text("ads.example.com").unwrap();
    let mut question = qname.wire().to_vec();
    question.extend_from_slice(&[0, 1, 0, 1]);
    let to = ReplyTo {
        id: 0,
        rd: true,
        cd: false,
        question: &question,
        client_opt: None,
        limit: 512,
        payload: crate::EDGE_UDP_PAYLOAD,
        pad: false,
    };
    let mut buf = [0u8; 512];
    let r = write_negative(&mut buf, &to, NegativeKind::Nxdomain, 10, &[]).unwrap();
    assert_eq!(
        decode(&buf[..r.len]).queries[0].name().to_ascii(),
        "ads.example.com."
    );
}

/// edge.md §4 "Blocked answers": `custom_ip` answers with `block_response.ipv4` and `.ipv6`; a
/// family the profile gives no address gets NODATA (with the synthesised SOA and EDE 15 only),
/// never an address the admin didn't configure.
#[test]
fn custom_ip_without_a_family_is_nodata() {
    let ede = EdeOption::blocked_by_bundle("b", "h", "id");
    let only_v4 = BlockResponse {
        kind: BlockResponseType::CustomIp,
        ipv4: Some(Ipv4Addr::new(192, 0, 2, 7)),
        ipv6: None,
        ttl: 10,
    };
    let mut buf = [0u8; 512];
    let (_, q) = query("ads.example.com", rtype::A, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &only_v4,
        ede,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 7).into()));
    assert!(crate::reply::block_has_records(&only_v4, rtype::A));

    let (_, q) = query("ads.example.com", rtype::AAAA, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &only_v4,
        ede,
    )
    .unwrap();
    let d = decode(&buf[..r.len]);
    assert!(d.answers.is_empty(), "{:?}", d.answers);
    assert_eq!(d.response_code, ResponseCode::NoError);
    assert_eq!(d.authorities[0].record_type(), RecordType::SOA);
    assert_eq!(edes(&buf[..r.len]).len(), 1, "EDE 15 only: no records");
    assert!(!crate::reply::block_has_records(&only_v4, rtype::AAAA));

    let only_v6 = BlockResponse {
        ipv4: None,
        ipv6: Some("2001:db8::7".parse().unwrap()),
        ..only_v4
    };
    let (_, q) = query("ads.example.com", rtype::A, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &only_v6,
        ede,
    )
    .unwrap();
    assert!(decode(&buf[..r.len]).answers.is_empty());
    let (_, q) = query("ads.example.com", rtype::AAAA, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &only_v6,
        ede,
    )
    .unwrap();
    assert_eq!(
        decode(&buf[..r.len]).answers[0].data,
        RData::AAAA("2001:db8::7".parse::<Ipv6Addr>().unwrap().into())
    );
}

/// Records the edge synthesises carry the question's class (a CH query gets CH records), and IN
/// for the QCLASS-only values ANY and NONE.
#[test]
fn synthesised_records_carry_the_question_class() {
    let mut buf = [0u8; 512];
    for (qclass, expect) in [(crate::types::class::CH, 3u16), (crate::types::class::ANY, 1)] {
        let mut m = Msg::with_flags(7, 0x01, 0);
        m.question(&n("version.example"), rtype::TXT, qclass);
        let q = check_query(&m.build()).unwrap();
        let r = write_negative(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            NegativeKind::Nodata,
            10,
            &[],
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        assert_eq!(u16::from(d.authorities[0].dns_class), expect, "qclass {qclass}");

        let mut m = Msg::with_flags(7, 0x01, 0);
        m.question(&n("version.example"), rtype::A, qclass);
        let q = check_query(&m.build()).unwrap();
        let resp = BlockResponse::default();
        let r = write_block(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &resp,
            EdeOption::blocked_by_bundle("b", "h", "id"),
        )
        .unwrap();
        let d = decode(&buf[..r.len]);
        assert_eq!(u16::from(d.answers[0].dns_class), expect, "qclass {qclass}");
    }
}

/// The edge is the authority for its managed listener names (edge.md §4 "Special names"): their
/// answers set AA, NODATA included. Blocks and rewrites don't.
#[test]
fn local_answers_are_authoritative() {
    let addrs: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
    let mut buf = [0u8; 512];
    for qtype in [rtype::A, rtype::AAAA] {
        let (_, q) = query("dns.home.arpa", qtype, Some((1232, false)));
        let r = write_local_answer(
            &mut buf,
            &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
            &addrs,
            60,
        )
        .unwrap();
        assert!(decode(&buf[..r.len]).authoritative, "{qtype}");
    }
    let (_, q) = query("ads.example.com", rtype::A, Some((1232, false)));
    let r = write_block(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        &BlockResponse::default(),
        EdeOption::blocked_by_bundle("b", "h", "id"),
    )
    .unwrap();
    assert!(!decode(&buf[..r.len]).authoritative);
}

/// edge.md §5: the listener's `limits.udp_payload` (default 1232) caps its UDP replies, with the
/// client's UDP size (at least 512), and is what the reply's OPT advertises (README §2:
/// settings reach their user).
#[test]
fn listener_udp_payload_caps_and_is_advertised() {
    let (_, q) = query("example.com", rtype::A, Some((4096, false)));
    assert_eq!(q.udp_limit(1232), 1232);
    assert_eq!(q.udp_limit(1400), 1400);
    assert_eq!(q.udp_limit(4096), 4096);
    assert_eq!(q.udp_limit(100), 512, "a listener size below 512 counts as 512");
    let (_, small) = query("example.com", rtype::A, Some((700, false)));
    assert_eq!(small.udp_limit(1400), 700);
    let (_, none) = query("example.com", rtype::A, None);
    assert_eq!(none.udp_limit(1400), 512);

    let to = q.reply_to(Transport::Udp, 1400);
    assert_eq!((to.limit, to.payload), (1400, 1400));
    assert_eq!(q.reply_to(Transport::Stream, 1400).limit, crate::MAX_MESSAGE);
    let mut buf = [0u8; 512];
    let r = write_rcode(&mut buf, &to, rcode::REFUSED, &[]).unwrap();
    assert_eq!(decode(&buf[..r.len]).edns.unwrap().max_payload(), 1400);

    // A FORMERR reply's OPT advertises it too.
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.opt(1232, 0, 0, false, &[]);
    m.raw(&[0]);
    let msg = m.build();
    let e = check_query(&msg).unwrap_err();
    let len = crate::query::write_query_error(&mut buf, &msg, &e, Transport::Udp, 1400)
        .unwrap()
        .unwrap();
    assert_eq!(decode(&buf[..len]).edns.unwrap().max_payload(), 1400);
}

/// A `$dnsrewrite` TXT value is one text: written as 255-byte character strings, the last one
/// shorter; an empty text is one empty string.
#[test]
fn txt_split_into_character_strings() {
    let (_, q) = query("txt.example", rtype::TXT, Some((1232, false)));
    let long = vec![b'x'; 300];
    let mut buf = [0u8; 1232];
    for (text, strings) in [
        (&long[..], vec![255usize, 45]),
        (&b""[..], vec![0]),
        (&[b'y'; 255][..], vec![255]),
    ] {
        let specs = [RecordSpec {
            owner: None,
            ttl: 10,
            data: RecordData::TxtSplit(text),
        }];
        let to = q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD);
        let r = write_records(&mut buf, &to, rcode::NOERROR, &specs, &[], &[]).unwrap();
        let d = decode(&buf[..r.len]);
        let RData::TXT(t) = &d.answers[0].data else {
            panic!("{:?}", d.answers[0])
        };
        assert_eq!(t.txt_data.iter().map(|s| s.len()).collect::<Vec<_>>(), strings);
        super::differential::assert_domain_accepts(&buf[..r.len]);
    }
}

/// build-and-test.md §5 "Edge EDE": every row of edge.md §4's table, with its rcode, code and
/// text; names in EXTRA-TEXT are percent-encoded.
#[test]
fn every_ede_table_row() {
    let (_, q) = query("4.3.2.1.in-addr.arpa", rtype::PTR, Some((1232, false)));
    let to = q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD);
    let mut buf = [0u8; 1232];
    let rows = [
        (rcode::NXDOMAIN, EdeOption::firewall(), 15, "cause=firewall"),
        (
            rcode::REFUSED,
            EdeOption::not_permitted(),
            18,
            "not permitted from this address",
        ),
        (
            rcode::REFUSED,
            EdeOption::profile_not_permitted(),
            18,
            "profile not permitted from this address",
        ),
        (
            rcode::NOERROR,
            EdeOption::stale("optimistic"),
            3,
            "cause=optimistic",
        ),
        (rcode::SERVFAIL, EdeOption::no_upstream("down"), 23, "cause=down"),
        (
            rcode::SERVFAIL,
            EdeOption::no_upstream("stale"),
            23,
            "cause=stale",
        ),
        (
            rcode::NXDOMAIN,
            EdeOption::blocked_by_lookup("my provider", "rejected", "x/y"),
            15,
            "lookup=my%20provider verdict=rejected block=x%2Fy",
        ),
    ];
    for (rc, ede, code, text) in rows {
        let r = write_rcode(&mut buf, &to, rc, &[ede]).unwrap();
        assert_eq!(
            decode(&buf[..r.len]).response_code,
            ResponseCode::from_low(rc as u8)
        );
        assert_eq!(edes(&buf[..r.len]), vec![(code, text.to_string())], "{text}");
    }
}

/// Over the limit, EDE text goes first, then the EDE options one by one from the last, and only
/// then are the records cut with TC set: checked at each exact boundary.
#[test]
fn ede_drops_at_exact_boundaries() {
    let (_, q) = query("x.example", rtype::A, Some((4096, false)));
    let specs: Vec<RecordSpec<'_>> = (1..=3u8)
        .map(|i| RecordSpec {
            owner: None,
            ttl: 1,
            data: RecordData::A(Ipv4Addr::new(192, 0, 2, i)),
        })
        .collect();
    let ede = [
        EdeOption::blocked_by_bundle("block-common", "c02f7a9e1b4d6e83", "k3j9q2"),
        EdeOption::forged(),
    ];
    let mut buf = [0u8; 2048];
    let wide = q.reply_to(Transport::Stream, crate::EDGE_UDP_PAYLOAD);
    let full = write_records(&mut buf, &wide, rcode::NOERROR, &specs, &[], &ede)
        .unwrap()
        .len;
    let text = "bundle=block-common@c02f7a9e1b4d6e83 block=k3j9q2".len();
    // The reply without any EDE option: header, question, records, an empty OPT.
    let bare = full - (6 + text) - 6;
    let at = |limit: usize, buf: &mut [u8]| {
        let to = ReplyTo { limit, ..wide };
        let r = write_records(buf, &to, rcode::NOERROR, &specs, &[], &ede).unwrap();
        assert!(r.len <= limit);
        r
    };
    let r = at(full, &mut buf);
    assert_eq!((r.tc, r.ede), (false, 2));
    let r = at(full - 1, &mut buf);
    assert_eq!(
        edes(&buf[..r.len]),
        vec![(15, "block=k3j9q2".into()), (4, String::new())]
    );
    let r = at(bare + 12, &mut buf);
    assert_eq!(edes(&buf[..r.len]), vec![(15, String::new()), (4, String::new())]);
    let r = at(bare + 11, &mut buf);
    assert_eq!(edes(&buf[..r.len]), vec![(15, String::new())]);
    let r = at(bare + 6, &mut buf);
    assert_eq!((r.tc, r.ede), (false, 1));
    let r = at(bare + 5, &mut buf);
    assert_eq!((r.tc, r.ede, r.len), (false, 0, bare));
    let r = at(bare - 1, &mut buf);
    assert!(r.tc);
    assert_eq!(r.len, 12 + q.question().len() + 11);
}

/// Without an OPT in the query, an rcode-only reply is exactly the header and the question.
#[test]
fn no_opt_reply_is_header_and_question() {
    let (msg, q) = query("a.example", rtype::A, None);
    let mut buf = [0u8; 512];
    let r = write_rcode(
        &mut buf,
        &q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
        rcode::SERVFAIL,
        &[EdeOption::no_upstream("timeout")],
    )
    .unwrap();
    assert_eq!((r.len, r.ede), (msg.len(), 0));
    assert_eq!(&buf[12..r.len], &msg[12..]);
}

/// The options of a reply's OPT, in order, as (code, length).
fn opt_options(reply: &[u8]) -> Vec<(u16, usize)> {
    let m = decode(reply);
    let Some(edns) = m.edns.as_ref() else {
        return vec![];
    };
    edns.options()
        .options
        .iter()
        .map(|(c, o)| {
            let bytes: Vec<u8> = o.try_into().unwrap();
            (u16::from(*c), bytes.len())
        })
        .collect()
}

/// A query with a Padding option, as a browser sends over DoH.
fn padded_query(name: &str, qtype: u16, do_bit: bool) -> Query {
    let mut m = Msg::query(0x5150, name, qtype);
    m.opt(4096, 0, 0, do_bit, &[(edns_code::PADDING, &[0; 40])]);
    check_query(&m.build()).unwrap()
}

/// W7: RFC 7830 §4: a responder MUST pad its reply when the query carried a Padding option;
/// RFC 8467 §4.1: to a multiple of 468 bytes. Only over DoT and DoH (padding hides nothing on a
/// plain transport, RFC 7830 §6); the Padding option comes after the EDE options.
#[test]
fn replies_to_padded_encrypted_queries_are_padded() {
    let q = padded_query("ads.example.com", rtype::A, false);
    assert!(q.edns.unwrap().padding);
    let ede = EdeOption::blocked_by_bundle("block-common", "c02f7a9e1b4d6e83", "k3j9q2");
    let mut buf = vec![0u8; 65_535];
    let to = q.reply_to(Transport::Encrypted, crate::EDGE_UDP_PAYLOAD);
    assert!(to.pad);
    let r = write_block(&mut buf, &to, &block_resp(BlockResponseType::NullIp), ede).unwrap();
    assert_eq!(r.len % crate::reply::REPLY_PAD_BLOCK, 0);
    assert_eq!(r.len, 468);
    let opts = opt_options(&buf[..r.len]);
    assert_eq!(
        opts.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
        vec![edns_code::EDE, edns_code::EDE, edns_code::PADDING]
    );
    let d = decode(&buf[..r.len]);
    assert_eq!(d.answers.len(), 1);
    super::differential::assert_domain_accepts(&buf[..r.len]);
    // Every writer pads.
    let r = write_rcode(
        &mut buf,
        &to,
        rcode::SERVFAIL,
        &[EdeOption::no_upstream("timeout")],
    )
    .unwrap();
    assert_eq!(r.len, 468);
    let r = write_negative(&mut buf, &to, NegativeKind::Nxdomain, 10, &[]).unwrap();
    assert_eq!(r.len, 468);
    let addrs: Vec<IpAddr> = (1..=40u8)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
        .collect();
    let r = write_local_answer(&mut buf, &to, &addrs, 60).unwrap();
    assert_eq!(r.len, 936, "two blocks");
    assert_eq!(decode(&buf[..r.len]).answers.len(), 40);

    // Plain TCP and UDP replies aren't padded; nor are replies to unpadded queries over DoT.
    for to in [
        q.reply_to(Transport::Stream, crate::EDGE_UDP_PAYLOAD),
        q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD),
    ] {
        assert!(!to.pad);
        let r = write_rcode(&mut buf, &to, rcode::REFUSED, &[]).unwrap();
        assert!(
            !opt_options(&buf[..r.len])
                .iter()
                .any(|(c, _)| *c == edns_code::PADDING)
        );
    }
    let (_, plain) = query("ads.example.com", rtype::A, Some((1232, false)));
    let to = plain.reply_to(Transport::Encrypted, crate::EDGE_UDP_PAYLOAD);
    assert!(!to.pad);
    let r = write_rcode(&mut buf, &to, rcode::REFUSED, &[]).unwrap();
    assert!(opt_options(&buf[..r.len]).is_empty());
}

/// W7: padding comes after the EDE and TC choices and never takes the reply past the client's
/// limit (RFC 7830 §4): the next block, or as far as the limit allows, or none when not even
/// the option's 4 bytes fit.
#[test]
fn padding_stays_within_the_limit() {
    let q = padded_query("ads.example.com", rtype::A, false);
    let wide = q.reply_to(Transport::Encrypted, crate::EDGE_UDP_PAYLOAD);
    let ede = EdeOption::blocked_by_bundle("block-common", "c02f7a9e1b4d6e83", "k3j9q2");
    let mut buf = vec![0u8; 65_535];
    let unpadded = write_block(
        &mut buf,
        &ReplyTo { pad: false, ..wide },
        &block_resp(BlockResponseType::NullIp),
        ede,
    )
    .unwrap();
    for (limit, expect) in [
        (600usize, 468usize),
        (400, 400),
        (unpadded.len + 4, unpadded.len + 4),
        (unpadded.len + 3, unpadded.len),
    ] {
        let to = ReplyTo { limit, ..wide };
        let r = write_block(&mut buf, &to, &block_resp(BlockResponseType::NullIp), ede).unwrap();
        assert_eq!(r.len, expect, "limit {limit}");
        assert_eq!(r.ede, 2, "EDE kept before padding is added");
        let pads = opt_options(&buf[..r.len])
            .iter()
            .filter(|(c, _)| *c == edns_code::PADDING)
            .count();
        assert_eq!(pads, usize::from(expect != unpadded.len), "limit {limit}");
    }
    // The TC form is padded too.
    let to = ReplyTo { limit: 60, ..wide };
    let addrs: Vec<IpAddr> = (1..=40u8)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
        .collect();
    let r = write_local_answer(&mut buf, &to, &addrs, 60).unwrap();
    assert!(r.tc);
    assert_eq!(r.len, 60);
}

/// W7: a cache hit and an error reply to a padded DoT/DoH query are padded too.
#[test]
fn padded_hits_and_error_replies() {
    use std::time::{Instant, SystemTime};

    use crate::answer::{AnswerLimits, check_answer};
    use crate::cache::{CacheValue, ServeParams, serve_hit};
    use crate::testutil::{a, ptr, sent_for};

    let mut m = Msg::response(7, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    let s = sent_for(7, "www.example.com", rtype::A);
    let v = CacheValue::new(
        check_answer(&m.build(), &s.sent(), &AnswerLimits::default()).unwrap(),
        SystemTime::now(),
        Instant::now(),
    );
    let q = padded_query("www.example.com", rtype::A, true);
    let mut buf = vec![0u8; 65_535];
    let p = ServeParams {
        age_s: 0,
        clamp: Default::default(),
        stale: None,
    };
    let r = serve_hit(
        &mut buf,
        &q.reply_to(Transport::Encrypted, crate::EDGE_UDP_PAYLOAD),
        &v,
        &p,
    )
    .unwrap();
    assert_eq!(r.len, 468);
    assert_eq!(decode(&buf[..r.len]).answers.len(), 1);

    // FORMERR (trailing byte) for a padded query over DoT: padded; over UDP: not.
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.opt(1232, 0, 0, false, &[(edns_code::PADDING, &[0; 8])]);
    m.raw(&[0]);
    let msg = m.build();
    let e = check_query(&msg).unwrap_err();
    let n = crate::query::write_query_error(&mut buf, &msg, &e, Transport::Encrypted, 1232)
        .unwrap()
        .unwrap();
    assert_eq!(n, 468);
    assert_eq!(decode(&buf[..n]).response_code, ResponseCode::FormErr);
    let n = crate::query::write_query_error(&mut buf, &msg, &e, Transport::Udp, 1232)
        .unwrap()
        .unwrap();
    assert!(n < 100);
}
