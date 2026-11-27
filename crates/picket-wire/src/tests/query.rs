//! The query check (edge.md §4 "Parsing", §16) and error replies.

use crate::query::{FormErr, NoReply, QueryError, check_query, write_query_error};
use crate::reply::Transport;
use crate::testutil::{Msg, n, ptr, queries};
use crate::types::{edns_code, rcode, rtype};

#[test]
fn baseline_fixtures_pass() {
    for (name, msg) in queries() {
        let q = check_query(&msg).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(q.question(), &msg[12..12 + q.question().len()], "{name}");
        match name.as_str() {
            "a-no-opt" => {
                assert!(q.edns.is_none());
                assert_eq!(q.udp_limit(crate::EDGE_UDP_PAYLOAD), 512);
                assert_eq!(q.qname().log_text(), "www.example.com");
                assert_eq!(q.qtype, rtype::A);
                assert!(q.rd);
            }
            "a-opt" => {
                assert_eq!(q.edns.unwrap().udp_size, 1232);
                assert_eq!(q.udp_limit(crate::EDGE_UDP_PAYLOAD), 1232);
                assert!(!q.do_bit());
            }
            "aaaa-opt-do" => assert!(q.do_bit()),
            "https-opt-padded" => {
                let e = q.edns.unwrap();
                assert_eq!(e.option_count, 1);
                assert_eq!(e.udp_size, 4096);
                // The edge's own UDP limit applies (RFC 6891 §6.2.5).
                assert_eq!(q.udp_limit(crate::EDGE_UDP_PAYLOAD), 1232);
                let opts: Vec<_> = q.client_options(&msg).collect();
                assert_eq!(opts.len(), 1);
                assert_eq!(opts[0].0, edns_code::PADDING);
                assert_eq!(msg.len() % 128, 0);
            }
            "a-opt-cookie" => {
                let opts: Vec<_> = q.client_options(&msg).collect();
                assert_eq!(
                    opts,
                    vec![(
                        edns_code::COOKIE,
                        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef][..]
                    )]
                );
            }
            "a-long-name" => assert_eq!(q.qname().num_labels(), 4),
            "ptr-private" => assert_eq!(q.qtype, rtype::PTR),
            other => panic!("unexpected fixture {other}"),
        }
    }
}

#[test]
fn qname_lowercased_question_kept_raw() {
    let msg = Msg::query(7, "WwW.ExAmPlE.CoM", rtype::A).build();
    let q = check_query(&msg).unwrap();
    assert_eq!(q.qname().wire(), &n("www.example.com")[..]);
    assert_eq!(&q.question()[..4], b"\x03WwW");
    let to = q.reply_to(Transport::Udp, crate::EDGE_UDP_PAYLOAD);
    assert_eq!(to.question, q.question());
    assert_eq!(to.limit, 512);
    assert_eq!(
        q.reply_to(Transport::Stream, crate::EDGE_UDP_PAYLOAD).limit,
        65_535
    );
}

#[test]
fn dotted_label_is_one_label() {
    let mut m = Msg::with_flags(1, 0x01, 0);
    m.question(b"\x03a.b\x07example\x00", rtype::A, 1);
    let q = check_query(&m.build()).unwrap();
    assert_eq!(q.qname().num_labels(), 2);
    assert_eq!(q.qname().label(0), Some(&b"a.b"[..]));
    assert_eq!(q.qname().log_text(), "a\\046b.example");
    assert_eq!(q.qname().adguard_text(), "a\\.b.example");
    let r = q.qname().reversed();
    assert_eq!(r.suffix(1), Some(&b"example"[..]));
    assert_eq!(r.suffix(2), None);
}

#[test]
fn header_rules() {
    assert_eq!(
        check_query(&[0u8; 11]).unwrap_err(),
        QueryError::NoReply(NoReply::ShortHeader)
    );
    let resp = Msg::response(1, "example.com", rtype::A, 0).build();
    assert_eq!(
        check_query(&resp).unwrap_err(),
        QueryError::NoReply(NoReply::Response)
    );
    let mut buf = [0u8; 512];
    assert_eq!(
        write_query_error(
            &mut buf,
            &resp,
            &check_query(&resp).unwrap_err(),
            Transport::Udp,
            crate::EDGE_UDP_PAYLOAD
        )
        .unwrap(),
        None
    );

    // Opcode STATUS (2) → NOTIMP from the header alone: no question echoed.
    let mut m = Msg::with_flags(0x1234, 0x10 | 0x01, 0);
    m.question(&n("example.com"), rtype::A, 1);
    let msg = m.build();
    let e = check_query(&msg).unwrap_err();
    assert!(matches!(e, QueryError::NotImp(_)));
    assert_eq!(e.rcode(), Some(rcode::NOTIMP));
    let len = write_query_error(&mut buf, &msg, &e, Transport::Udp, crate::EDGE_UDP_PAYLOAD)
        .unwrap()
        .unwrap();
    assert_eq!(len, 12);
    assert_eq!(&buf[..4], &[0x12, 0x34, 0x80 | 0x10 | 0x01, 0x80 | 4]);
    assert_eq!(&buf[4..12], &[0; 8]);
}

#[test]
fn question_count_and_record_limits() {
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.set_counts(0, 0, 0, 0);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::QuestionCount))
    ));
    m.set_counts(2, 0, 0, 0);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::QuestionCount))
    ));
    // 9 records besides the question: refused from the header.
    m.set_counts(1, 3, 3, 3);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::TooManyRecords))
    ));
    // 8 is fine when they decode.
    let mut m = Msg::query(1, "example.com", rtype::A);
    for _ in 0..7 {
        m.rr(3, &n("x.example"), rtype::TXT, 0, b"\x01a");
    }
    m.opt(1232, 0, 0, false, &[]);
    assert!(check_query(&m.build()).is_ok());
}

/// build-and-test.md §5 "Edge pipeline": a header claiming 65,535 questions is rejected before
/// its body is decoded (the body here isn't even a question).
#[test]
fn many_questions_rejected_before_body() {
    let mut msg = vec![0xAB, 0xCD, 0x01, 0x00, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0];
    msg.extend_from_slice(&[0xC0; 64]);
    let e = check_query(&msg).unwrap_err();
    assert!(matches!(e, QueryError::FormErr(c, FormErr::QuestionCount) if c.question_len.is_none()));
    let mut buf = [0u8; 64];
    let len = write_query_error(&mut buf, &msg, &e, Transport::Udp, crate::EDGE_UDP_PAYLOAD)
        .unwrap()
        .unwrap();
    assert_eq!(len, 12);
    assert_eq!(buf[3] & 0x0F, rcode::FORMERR as u8);
    assert_eq!(&buf[4..6], &[0, 0]);
}

#[test]
fn compressed_question_name() {
    // "www" then a pointer to offset 11 (ARCOUNT's low byte, 0: the root).
    let mut m = Msg::with_flags(1, 0x01, 0);
    let mut name = b"\x03www".to_vec();
    name.extend_from_slice(&ptr(11));
    m.question(&name, rtype::A, 1);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::CompressedQuestion))
    ));
}

#[test]
fn opt_placement() {
    // OPT in the answer section.
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.rr_class(1, &[0], rtype::OPT, 1232, 0, &[]);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::OptNotAdditional))
    ));
    // Two OPTs: FORMERR, echoing the question and an OPT (the first one was read).
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.opt(1232, 0, 0, true, &[]);
    m.opt(1232, 0, 0, true, &[]);
    let msg = m.build();
    let e = check_query(&msg).unwrap_err();
    assert!(matches!(e, QueryError::FormErr(_, FormErr::DuplicateOpt)));
    let mut buf = [0u8; 512];
    let len = write_query_error(&mut buf, &msg, &e, Transport::Udp, crate::EDGE_UDP_PAYLOAD)
        .unwrap()
        .unwrap();
    let reply = super::decode(&buf[..len]);
    assert_eq!(reply.response_code, hickory_proto::op::ResponseCode::FormErr);
    assert_eq!(reply.queries.len(), 1);
    assert!(reply.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok));
    // An OPT owned by a name other than the root.
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.rr_class(3, &n("x"), rtype::OPT, 1232, 0, &[]);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::MalformedOpt))
    ));
    // Option TLVs that overrun the OPT data.
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.rr_class(3, &[0], rtype::OPT, 1232, 0, &[0, 10, 0, 9, 1, 2]);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::MalformedOpt))
    ));
}

#[test]
fn trailing_and_undecodable() {
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.raw(&[0]);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::TrailingBytes))
    ));
    let msg = Msg::query(1, "example.com", rtype::A).build();
    assert!(matches!(
        check_query(&msg[..msg.len() - 1]),
        Err(QueryError::FormErr(_, FormErr::Undecodable))
    ));
    // A claimed additional record that isn't there.
    let mut m = Msg::query(1, "example.com", rtype::A);
    m.set_counts(1, 0, 0, 1);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::Undecodable))
    ));
    // A label over 63 bytes.
    let mut m = Msg::with_flags(1, 0x01, 0);
    let mut name = vec![64u8];
    name.extend_from_slice(&[b'a'; 64]);
    name.push(0);
    m.question(&name, rtype::A, 1);
    assert!(matches!(
        check_query(&m.build()),
        Err(QueryError::FormErr(_, FormErr::Undecodable))
    ));
}

/// An SVCB/HTTPS record whose parameters RFC 9460 forbids is a body the edge can't decode, in
/// any section of a query (edge.md §4 "Parsing"), as in an upstream answer (§7 step 1); one in
/// its valid form is accepted.
#[test]
fn malformed_svcb_record_in_a_query() {
    let svcb = |port: &[u8]| crate::testutil::svcb(1, ".", &[(3, port.to_vec())]);
    for section in 1..=3 {
        let mut m = Msg::query(1, "example.com", rtype::HTTPS);
        m.rr(section, &ptr(12), rtype::HTTPS, 60, &svcb(&[0, 80, 0, 0]));
        assert!(
            matches!(
                check_query(&m.build()),
                Err(QueryError::FormErr(_, FormErr::Undecodable))
            ),
            "section {section}"
        );
        let mut m = Msg::query(1, "example.com", rtype::HTTPS);
        m.rr(section, &ptr(12), rtype::HTTPS, 60, &svcb(&[0, 80]));
        assert!(check_query(&m.build()).is_ok(), "section {section}");
    }
}

#[test]
fn edns_version_and_udp_size() {
    let mut m = Msg::query(0x0102, "example.com", rtype::A);
    m.opt(4096, 0, 1, true, &[]);
    let msg = m.build();
    let e = check_query(&msg).unwrap_err();
    assert!(matches!(e, QueryError::BadVers(_)));
    let mut buf = [0u8; 512];
    let len = write_query_error(&mut buf, &msg, &e, Transport::Udp, crate::EDGE_UDP_PAYLOAD)
        .unwrap()
        .unwrap();
    let reply = super::decode(&buf[..len]);
    // BADVERS (16): upper bits in the OPT, low bits 0 in the header.
    assert_eq!(buf[3] & 0x0F, 0);
    assert_eq!(u16::from(reply.response_code), rcode::BADVERS);
    assert_eq!(reply.queries.len(), 1);

    let mut m = Msg::query(1, "example.com", rtype::A);
    m.opt(100, 0, 0, false, &[]);
    let q = check_query(&m.build()).unwrap();
    assert_eq!(q.edns.unwrap().udp_size, 512);
    assert_eq!(q.udp_limit(crate::EDGE_UDP_PAYLOAD), 512);
}

#[test]
fn cd_and_rd_flags() {
    let mut m = Msg::with_flags(9, 0x00, 0x10);
    m.question(&n("example.com"), rtype::A, 1);
    let q = check_query(&m.build()).unwrap();
    assert!(!q.rd);
    assert!(q.cd);
}

#[test]
fn counter_names_cover_every_error() {
    let ctx = crate::query::ErrorContext {
        id: 0,
        opcode: 0,
        rd: false,
        cd: false,
        question_len: None,
        edns: None,
    };
    let all = [
        QueryError::NoReply(crate::query::NoReply::ShortHeader),
        QueryError::NoReply(crate::query::NoReply::Response),
        QueryError::NotImp(ctx),
        QueryError::FormErr(ctx, FormErr::TrailingBytes),
        QueryError::BadVers(ctx),
    ];
    assert_eq!(all.map(|e| e.counter()), QueryError::COUNTERS);
}
