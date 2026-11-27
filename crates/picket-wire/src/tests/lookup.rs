//! Answer facts for the `dns` lookup module (providers.md §5): checked like an upstream answer,
//! with rcode, EDE codes and texts, A/AAAA, the CNAME chain and the authority SOA.

use std::net::IpAddr;

use crate::answer::Invalid;
use crate::facts::lookup_answer_facts;
use crate::testutil::{Msg, a, n, ptr, sent_for, soa};
use crate::types::{edns_code, rcode, rtype};
use crate::upstream::{QueryParams, write_query};

const ID: u16 = 0x0909;

#[test]
fn quad9_style_block_and_real_nxdomain() {
    // A blocked name: NXDOMAIN, EDE 15, empty authority.
    let mut m = Msg::response(ID, "isitblocked.org", rtype::A, 3);
    m.opt(1232, 0, 0, false, &[(edns_code::EDE, b"\x00\x0f")]);
    let s = sent_for(ID, "isitblocked.org", rtype::A);
    let f = lookup_answer_facts(&m.build(), &s.sent()).unwrap();
    assert_eq!(f.rcode, rcode::NXDOMAIN);
    assert_eq!(f.ede.len(), 1);
    assert_eq!(f.ede[0].code, 15);
    assert!(!f.soa);
    // A real NXDOMAIN carries the zone's SOA.
    let mut m = Msg::response(ID, "nope.example.org", rtype::A, 3);
    m.rr(
        2,
        &n("example.org"),
        rtype::SOA,
        3600,
        &soa(&n("ns.example.org"), &n("h.example.org"), 1, 300),
    );
    let s = sent_for(ID, "nope.example.org", rtype::A);
    let f = lookup_answer_facts(&m.build(), &s.sent()).unwrap();
    assert!(f.soa);
    assert!(f.ede.is_empty());
}

#[test]
fn nextdns_style_sinkhole() {
    let mut m = Msg::response(ID, "ads.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("0.0.0.0"));
    m.opt(
        1232,
        0,
        0,
        false,
        &[(edns_code::EDE, b"\x00\x11Blocked by NextDNS")],
    );
    let s = sent_for(ID, "ads.example", rtype::A);
    let f = lookup_answer_facts(&m.build(), &s.sent()).unwrap();
    assert_eq!(f.addrs, vec!["0.0.0.0".parse::<IpAddr>().unwrap()]);
    assert_eq!(f.ede[0].code, 17);
    assert_eq!(f.ede[0].text, "Blocked by NextDNS");
}

/// build-and-test.md §5 "DNS lookups": a 200-byte EXTRA-TEXT with `<` and control bytes comes
/// through whole (the module cuts and escapes it for `detail`).
#[test]
fn long_extra_text_with_control_bytes() {
    let mut text = b"<script>".to_vec();
    text.extend_from_slice(&[0x01, 0x1b, b'\n']);
    text.resize(200, b'x');
    let payload = [&[0u8, 15][..], &text].concat();
    let mut m = Msg::response(ID, "x.example", rtype::A, 3);
    m.opt(1232, 0, 0, false, &[(edns_code::EDE, &payload)]);
    let s = sent_for(ID, "x.example", rtype::A);
    let f = lookup_answer_facts(&m.build(), &s.sent()).unwrap();
    assert_eq!(f.ede[0].text.len(), 200);
    assert!(f.ede[0].text.starts_with("<script>\u{1}\u{1b}\n"));
}

#[test]
fn chain_and_checks() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::CNAME, 60, &n("blocked.filter.example"));
    m.rr(1, &n("blocked.filter.example"), rtype::A, 60, &a("192.0.2.1"));
    let s = sent_for(ID, "www.example.com", rtype::A);
    let f = lookup_answer_facts(&m.build(), &s.sent()).unwrap();
    assert_eq!(f.chain.len(), 1);
    assert_eq!(f.chain[0].log_text(), "blocked.filter.example");
    // Another ID or question is invalid.
    let other = sent_for(ID + 1, "www.example.com", rtype::A);
    assert_eq!(
        lookup_answer_facts(&m.build(), &other.sent()).unwrap_err(),
        Invalid::IdMismatch
    );
    let other = sent_for(ID, "www.example.com", rtype::AAAA);
    assert_eq!(
        lookup_answer_facts(&m.build(), &other.sent()).unwrap_err(),
        Invalid::QuestionMismatch
    );
}

/// providers.md §5 `dns`: RD, a random ID, an OPT with DO and CD clear, no ECS, padding to a
/// multiple of 128 on dot and doh.
#[test]
fn lookup_query_shape() {
    let q = crate::name::QName::from_text("isitblocked.org").unwrap();
    let mut buf = [0u8; 512];
    for pad in [false, true] {
        let p = QueryParams {
            id: crate::upstream::random_query_id(),
            cd: false,
            do_bit: false,
            pad,
        };
        let len = write_query(&mut buf, q.as_name(), rtype::A, 1, &p).unwrap();
        let parsed = crate::query::check_query(&buf[..len]).unwrap();
        assert!(parsed.rd);
        assert!(!parsed.cd);
        assert!(!parsed.do_bit());
        let opts: Vec<_> = parsed.client_options(&buf[..len]).collect();
        assert!(opts.iter().all(|(c, _)| *c != edns_code::CLIENT_SUBNET));
        assert_eq!(opts.len(), usize::from(pad));
        assert_eq!(len.is_multiple_of(128), pad);
        super::differential::assert_domain_accepts(&buf[..len]);
    }
}

/// providers.md §5 `dns` "Detail": EXTRA-TEXT cut to 64 bytes, with control characters, `\` and
/// bytes that aren't UTF-8 escaped as `\DDD`; a cut never splits a character.
#[test]
fn detail_text_escaping() {
    use crate::facts::{DETAIL_TEXT_MAX, detail_text};
    let mut text = b"<script>".to_vec();
    text.extend_from_slice(&[0x01, 0x1b]);
    text.resize(200, b'x');
    let d = detail_text(&text, DETAIL_TEXT_MAX);
    assert!(d.starts_with("<script>\\001\\027"));
    assert_eq!(d.len(), 64 + 2 * 3);
    assert_eq!(detail_text(b"a\x01b\\c\xffd", 64), "a\\001b\\092c\\255d");
    assert_eq!(detail_text("aé".as_bytes(), 2), "a");
    assert_eq!(detail_text("aé".as_bytes(), 3), "aé");
    assert_eq!(detail_text("\u{85}".as_bytes(), 8), "\\194\\133");

    // From an answer: the facts keep the whole text; the detail is cut.
    let payload = [&[0u8, 17][..], &text].concat();
    let mut m = Msg::response(ID, "x.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("0.0.0.0"));
    m.opt(1232, 0, 0, false, &[(edns_code::EDE, &payload)]);
    let s = sent_for(ID, "x.example", rtype::A);
    let f = lookup_answer_facts(&m.build(), &s.sent()).unwrap();
    assert_eq!(f.ede[0].text.len(), 200);
    assert_eq!(f.ede[0].detail_text(), d);
}

/// `answers_in` tests A and AAAA records only: HTTPS hints aren't answers.
#[test]
fn lookup_addresses_leave_hints_out() {
    let mut m = Msg::response(ID, "h.example", rtype::HTTPS, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::HTTPS,
        60,
        &crate::testutil::svcb(1, ".", &[(4, a("0.0.0.0"))]),
    );
    let s = sent_for(ID, "h.example", rtype::HTTPS);
    let f = lookup_answer_facts(&m.build(), &s.sent()).unwrap();
    assert!(f.addrs.is_empty());
}
