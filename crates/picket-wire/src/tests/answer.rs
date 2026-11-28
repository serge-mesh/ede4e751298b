//! The upstream answer pipeline (edge.md §7): structure checks, the scrub, facts, encoding.

use std::net::{IpAddr, Ipv4Addr};

use hickory_proto::rr::{RData, RecordType};

use super::decode;
use crate::answer::{AddrSource, AnswerLimits, Invalid, Negative, check_answer};
use crate::testutil::{Msg, a, aaaa, n, nsec, nsec3, ptr, rrsig, sent_for, soa, svcb};
use crate::types::{edns_code, rtype};

const ID: u16 = 0x5151;

fn check(m: &Msg, name: &str, qtype: u16) -> Result<crate::answer::ScrubbedAnswer, Invalid> {
    let s = sent_for(ID, name, qtype);
    check_answer(&m.build(), &s.sent(), &AnswerLimits::default())
}

fn names(v: &[crate::name::WireName]) -> Vec<String> {
    v.iter().map(|n| n.log_text()).collect()
}

#[test]
fn plain_answer() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    m.rr(1, &ptr(12), rtype::A, 200, &a("192.0.2.2"));
    m.opt(1232, 0, 0, true, &[]);
    let s = check(&m, "www.example.com", rtype::A).unwrap();
    let f = &s.facts;
    assert_eq!(f.rcode, 0);
    assert_eq!(f.addrs.len(), 2);
    assert_eq!(f.addrs[0].ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(f.addrs[0].source, AddrSource::A);
    assert!(f.chain.is_empty());
    assert_eq!(f.min_ttl, Some(200));
    assert_eq!(f.cache_ttl, Some(200));
    assert!(f.negative.is_none());
    assert!(!s.has_stripped_copy());
    assert_eq!(s.removed.total(), 0);
    super::differential::assert_domain_accepts(s.wire());
}

#[test]
fn structure_from_header() {
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    // Wrong ID.
    let s = sent_for(ID + 1, "example.com", rtype::A);
    assert_eq!(
        check_answer(&m.build(), &s.sent(), &AnswerLimits::default()).unwrap_err(),
        Invalid::IdMismatch
    );
    // Wrong question (name, type).
    assert_eq!(
        check(&m, "example.net", rtype::A).unwrap_err(),
        Invalid::QuestionMismatch
    );
    assert_eq!(
        check(&m, "example.com", rtype::AAAA).unwrap_err(),
        Invalid::QuestionMismatch
    );
    // Case doesn't matter.
    assert!(check(&m, "EXAMPLE.com", rtype::A).is_ok());
    // Size cap.
    let s = sent_for(ID, "example.com", rtype::A);
    assert_eq!(
        check_answer(
            &m.build(),
            &s.sent(),
            &AnswerLimits {
                max_len: 20,
                ..AnswerLimits::default()
            }
        )
        .unwrap_err(),
        Invalid::TooLarge
    );
    // Not a response, not QUERY.
    let mut q = Msg::query(ID, "example.com", rtype::A);
    q.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    assert_eq!(
        check(&q, "example.com", rtype::A).unwrap_err(),
        Invalid::NotResponse
    );
    let mut op = Msg::with_flags(ID, 0x80 | (5 << 3), 0x80);
    op.question(&n("example.com"), rtype::A, 1);
    assert_eq!(check(&op, "example.com", rtype::A).unwrap_err(), Invalid::Opcode);
    // Trailing bytes.
    let mut t = m.clone();
    t.raw(&[0, 0]);
    assert_eq!(
        check(&t, "example.com", rtype::A).unwrap_err(),
        Invalid::TrailingBytes
    );
    // Short.
    assert_eq!(
        check_answer(&[0; 5], &s.sent(), &AnswerLimits::default()).unwrap_err(),
        Invalid::ShortHeader
    );
}

#[test]
fn record_counts_checked_before_body() {
    // 1,025 answers claimed; the body is garbage: refused on the counts alone.
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.raw(&[0xC0; 32]);
    m.set_counts(1, 1025, 0, 0);
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::TooManyRecords
    );
    m.set_counts(1, 0, 1025, 0);
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::TooManyRecords
    );
    m.set_counts(1, 0, 0, 1025);
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::TooManyRecords
    );
    m.set_counts(2, 0, 0, 0);
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::QuestionCount
    );
    // The size refusal comes only once the header matches the query (the edge doesn't count it
    // against the upstream): not a response, or another ID, is refused as such first.
    let mut q = Msg::query(ID, "example.com", rtype::A);
    q.raw(&[0xC0; 32]);
    q.set_counts(1, 1025, 0, 0);
    assert_eq!(
        check(&q, "example.com", rtype::A).unwrap_err(),
        Invalid::NotResponse
    );
    let mut other = Msg::response(ID + 1, "example.com", rtype::A, 0);
    other.raw(&[0xC0; 32]);
    other.set_counts(1, 1025, 0, 0);
    assert_eq!(
        check(&other, "example.com", rtype::A).unwrap_err(),
        Invalid::IdMismatch
    );
}

#[test]
fn hickory_decode_failures() {
    // A record of 5 bytes.
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &[1, 2, 3, 4, 5]);
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::Undecodable
    );
    // A forward pointer.
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(200), rtype::A, 300, &a("192.0.2.1"));
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::Undecodable
    );
    // RDLENGTH past the end.
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.raw(&ptr(12)).raw(&[0, 1, 0, 1, 0, 0, 0, 1, 0, 9, 1, 2, 3, 4]);
    m.set_counts(1, 1, 0, 0);
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::Undecodable
    );
}

#[test]
fn opt_rules_and_padding() {
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    m.opt(1232, 0, 0, true, &[]);
    m.opt(1232, 0, 0, true, &[]);
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::DuplicateOpt
    );

    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr_class(2, &[0], rtype::OPT, 1232, 0, &[]);
    assert_eq!(
        check(&m, "example.com", rtype::A).unwrap_err(),
        Invalid::OptNotAdditional
    );

    // Padding is dropped from the scrubbed OPT; other options stay.
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    m.opt(1232, 0, 0, true, &[(edns_code::PADDING, &[0; 40]), (3, b"nsid")]);
    let s = check(&m, "example.com", rtype::A).unwrap();
    assert_eq!(s.removed.padding, 1);
    let d = decode(s.wire());
    let opts = &d.edns.as_ref().unwrap().options().options;
    assert_eq!(opts.len(), 1);
    assert_eq!(u16::from(opts[0].0), 3);
    assert!(s.wire().len() < m.build().len());
}

#[test]
fn ede_extracted_and_bounded() {
    let mut m = Msg::response(ID, "blocked.example", rtype::A, 3);
    m.opt(
        1232,
        0,
        0,
        false,
        &[
            (edns_code::EDE, b"\x00\x0fBlocked by policy"),
            (edns_code::EDE, b"\x00\x11"),
        ],
    );
    let s = check(&m, "blocked.example", rtype::A).unwrap();
    assert_eq!(s.facts.ede.len(), 2);
    assert_eq!(s.facts.ede[0].code, 15);
    assert_eq!(s.facts.ede[0].text, "Blocked by policy");
    assert_eq!(s.facts.ede[1].code, 17);
    assert_eq!(s.facts.ede[1].text, "");
    assert!(!s.facts.stale);
    // An NXDOMAIN without an SOA isn't cached (RFC 2308 §5).
    assert_eq!(s.facts.negative, Some(Negative::Nxdomain));
    assert!(!s.facts.soa);
    assert_eq!(s.facts.cache_ttl, None);

    // Nine EDE options: the first eight kept, the ninth counted (see also
    // many_ede_options_kept_bounded_and_scanned).
    let opts: Vec<(u16, &[u8])> = (0..9).map(|_| (edns_code::EDE, &b"\x00\x0f"[..])).collect();
    let mut m = Msg::response(ID, "blocked.example", rtype::A, 3);
    m.opt(1232, 0, 0, false, &opts);
    let s = check(&m, "blocked.example", rtype::A).unwrap();
    assert_eq!((s.facts.ede.len(), s.facts.ede_dropped), (8, 1));
    // Eight: none dropped.
    let mut m = Msg::response(ID, "blocked.example", rtype::A, 3);
    m.opt(1232, 0, 0, false, &opts[..8]);
    let s = check(&m, "blocked.example", rtype::A).unwrap();
    assert_eq!((s.facts.ede.len(), s.facts.ede_dropped), (8, 0));
    // An EDE option shorter than its INFO-CODE.
    let mut m = Msg::response(ID, "blocked.example", rtype::A, 3);
    m.opt(1232, 0, 0, false, &[(edns_code::EDE, b"\x00")]);
    assert_eq!(
        check(&m, "blocked.example", rtype::A).unwrap_err(),
        Invalid::MalformedOpt
    );
}

/// TC answers and EDE 3 (stale) answers are not cacheable.
#[test]
fn tc_and_stale_not_cacheable() {
    let mut m = Msg::with_flags(ID, 0x83, 0x80); // QR, TC, RD
    m.question(&n("example.com"), rtype::A, 1);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    let s = check(&m, "example.com", rtype::A).unwrap();
    assert!(s.facts.tc);
    assert_eq!(s.facts.cache_ttl, None);

    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    m.opt(1232, 0, 0, false, &[(edns_code::EDE, b"\x00\x03")]);
    let s = check(&m, "example.com", rtype::A).unwrap();
    assert!(s.facts.stale);
    assert_eq!(s.facts.cache_ttl, None);

    // SERVFAIL isn't cached; a TTL of 0 isn't either.
    let m = Msg::response(ID, "example.com", rtype::A, 2);
    assert_eq!(check(&m, "example.com", rtype::A).unwrap().facts.cache_ttl, None);
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 0, &a("192.0.2.1"));
    assert_eq!(check(&m, "example.com", rtype::A).unwrap().facts.cache_ttl, None);
    // A TTL with the top bit set counts as 0 (RFC 2181 §8).
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 0x8000_0000, &a("192.0.2.1"));
    assert_eq!(check(&m, "example.com", rtype::A).unwrap().facts.min_ttl, Some(0));
}

#[test]
fn cname_chain_and_bailiwick() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::CNAME, 300, &n("cdn.example.net"));
    m.rr(
        1,
        &n("cdn.example.net"),
        rtype::CNAME,
        120,
        &n("edge.cdn.example.org"),
    );
    m.rr(1, &n("edge.cdn.example.org"), rtype::A, 60, &a("198.51.100.7"));
    // Out of bailiwick: an A for a name off the chain, and NSEC/RRSIG for one too.
    m.rr(1, &n("evil.example"), rtype::A, 60, &a("203.0.113.66"));
    m.rr(
        1,
        &n("evil.example"),
        rtype::NSEC,
        60,
        &nsec("z.evil.example", &[rtype::A]),
    );
    m.rr(
        1,
        &n("evil.example"),
        rtype::RRSIG,
        60,
        &rrsig(rtype::A, 2, 60, "evil.example"),
    );
    // Unexpected type at a chain name.
    m.rr(1, &n("cdn.example.net"), rtype::TXT, 60, b"\x03txt");
    // Authority NS and additional glue.
    m.rr(2, &n("example.org"), rtype::NS, 60, &n("ns1.evil.example"));
    m.rr(3, &n("ns1.evil.example"), rtype::A, 60, &a("203.0.113.1"));
    let s = check(&m, "www.example.com", rtype::A).unwrap();
    let f = &s.facts;
    assert_eq!(names(&f.chain), vec!["cdn.example.net", "edge.cdn.example.org"]);
    assert_eq!(f.addrs.len(), 1);
    assert_eq!(f.addrs[0].ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    assert_eq!(s.removed.out_of_bailiwick, 3);
    assert_eq!(s.removed.unexpected_type, 1);
    assert_eq!(s.removed.authority, 1);
    assert_eq!(s.removed.additional, 1);
    assert_eq!(f.cache_ttl, Some(60));
    let d = decode(s.wire());
    assert_eq!(d.answers.len(), 3);
    assert!(d.authorities.is_empty());
    assert!(d.additionals.is_empty());
    super::differential::assert_domain_accepts(s.wire());
}

#[test]
fn cname_hops_and_loops() {
    let build = |hops: usize| {
        let mut m = Msg::response(ID, "h0.example", rtype::A, 0);
        for i in 0..hops {
            m.rr(
                1,
                &n(&format!("h{i}.example")),
                rtype::CNAME,
                60,
                &n(&format!("h{}.example", i + 1)),
            );
        }
        m.rr(1, &n(&format!("h{hops}.example")), rtype::A, 60, &a("192.0.2.1"));
        m
    };
    let s = check(&build(8), "h0.example", rtype::A).unwrap();
    assert_eq!(s.facts.chain.len(), 8);
    assert_eq!(
        check(&build(9), "h0.example", rtype::A).unwrap_err(),
        Invalid::CnameHops
    );

    let mut m = Msg::response(ID, "a.example", rtype::A, 0);
    m.rr(1, &n("a.example"), rtype::CNAME, 60, &n("b.example"));
    m.rr(1, &n("b.example"), rtype::CNAME, 60, &n("a.example"));
    assert_eq!(check(&m, "a.example", rtype::A).unwrap_err(), Invalid::CnameLoop);
}

/// Two different CNAMEs at one owner, or a DNAME whose synthesised CNAME conflicts with the
/// CNAME present, don't survive the scrub.
#[test]
fn ambiguous_chains() {
    let mut m = Msg::response(ID, "a.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::CNAME, 60, &n("b.example"));
    m.rr(1, &ptr(12), rtype::CNAME, 60, &n("c.example"));
    assert_eq!(
        check(&m, "a.example", rtype::A).unwrap_err(),
        Invalid::AmbiguousChain
    );

    // The same CNAME twice is a duplicate, removed.
    let mut m = Msg::response(ID, "a.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::CNAME, 60, &n("b.example"));
    m.rr(1, &ptr(12), rtype::CNAME, 60, &n("B.example"));
    m.rr(1, &n("b.example"), rtype::A, 60, &a("192.0.2.1"));
    let s = check(&m, "a.example", rtype::A).unwrap();
    assert_eq!(s.removed.duplicate, 1);

    // DNAME example → example.net synthesises x.example.net; the CNAME says otherwise.
    let mut m = Msg::response(ID, "x.example", rtype::A, 0);
    m.rr(1, &n("example"), rtype::DNAME, 60, &n("example.net"));
    m.rr(1, &ptr(12), rtype::CNAME, 60, &n("elsewhere.example.org"));
    m.rr(1, &n("elsewhere.example.org"), rtype::A, 60, &a("192.0.2.1"));
    assert_eq!(
        check(&m, "x.example", rtype::A).unwrap_err(),
        Invalid::AmbiguousChain
    );

    // Two DNAMEs that both apply.
    let mut m = Msg::response(ID, "x.a.example", rtype::A, 0);
    m.rr(1, &n("example"), rtype::DNAME, 60, &n("one.net"));
    m.rr(1, &n("a.example"), rtype::DNAME, 60, &n("two.net"));
    assert_eq!(
        check(&m, "x.a.example", rtype::A).unwrap_err(),
        Invalid::AmbiguousChain
    );
}

/// build-and-test.md §5 "Edge pipeline": a DNAME with a compressed target (invalid) and one
/// without.
#[test]
fn dname_targets() {
    // Uncompressed target with its synthesised CNAME.
    let mut m = Msg::response(ID, "foo.dname.example", rtype::A, 0);
    m.rr(
        1,
        &n("dname.example"),
        rtype::DNAME,
        3600,
        &n("target.example.net"),
    );
    m.rr(1, &ptr(12), rtype::CNAME, 3600, &n("foo.target.example.net"));
    m.rr(1, &n("foo.target.example.net"), rtype::A, 300, &a("192.0.2.9"));
    m.opt(1232, 0, 0, true, &[]);
    let s = check(&m, "foo.dname.example", rtype::A).unwrap();
    assert_eq!(names(&s.facts.chain), vec!["foo.target.example.net"]);
    assert!(s.has_stripped_copy(), "the DNAME is stripped for DO=0 clients");
    super::differential::assert_domain_accepts(s.wire());

    // The same DNAME with a target compressed to the question's "example".
    let mut m = Msg::response(ID, "foo.dname.example", rtype::A, 0);
    let mut target = b"\x06target".to_vec();
    target.extend_from_slice(&ptr(12 + 4 + 6)); // "example." inside the question
    m.rr(1, &n("dname.example"), rtype::DNAME, 3600, &target);
    m.rr(1, &ptr(12), rtype::CNAME, 3600, &n("foo.target.example"));
    m.rr(1, &n("foo.target.example"), rtype::A, 300, &a("192.0.2.9"));
    assert_eq!(
        check(&m, "foo.dname.example", rtype::A).unwrap_err(),
        Invalid::DnameTarget
    );

    // A target that doesn't fill the data.
    let mut m = Msg::response(ID, "foo.dname.example", rtype::A, 0);
    let mut target = n("target.example.net");
    target.push(0);
    m.rr(1, &n("dname.example"), rtype::DNAME, 3600, &target);
    assert_eq!(
        check(&m, "foo.dname.example", rtype::A).unwrap_err(),
        Invalid::DnameTarget
    );

    // An out-of-bailiwick DNAME isn't interpreted: dropped, not invalid.
    let mut m = Msg::response(ID, "www.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    m.rr(1, &n("other.example"), rtype::DNAME, 60, &[0xC0, 0x0C]);
    let s = check(&m, "www.example", rtype::A).unwrap();
    assert_eq!(s.removed.out_of_bailiwick, 1);
}

#[test]
fn dname_without_cname_is_synthesised() {
    let mut m = Msg::response(ID, "foo.dname.example", rtype::A, 0);
    m.rr(
        1,
        &n("dname.example"),
        rtype::DNAME,
        3600,
        &n("target.example.net"),
    );
    m.rr(1, &n("foo.target.example.net"), rtype::A, 300, &a("192.0.2.9"));
    let s = check(&m, "foo.dname.example", rtype::A).unwrap();
    assert_eq!(names(&s.facts.chain), vec!["foo.target.example.net"]);
    assert_eq!(s.facts.addrs.len(), 1);
    // The DO=0 copy leaves the DNAME out and carries its synthesised CNAME.
    let v = crate::cache::CacheValue::new(s, std::time::SystemTime::now(), std::time::Instant::now());
    let stripped = super::cache::copy_message(&v, false);
    let d = decode(&stripped);
    assert_eq!(d.answers.len(), 2);
    assert_eq!(d.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(d.answers[0].ttl, 3600);
    let RData::CNAME(c) = &d.answers[0].data else {
        panic!()
    };
    assert_eq!(c.0.to_ascii(), "foo.target.example.net.");
    assert_eq!(d.answers[0].name.to_ascii(), "foo.dname.example.");
}

/// The negative-caching SOA is judged against the chain's terminal name, and the negative TTL
/// is min(SOA TTL, SOA MINIMUM).
#[test]
fn negative_soa_and_ttl() {
    // NXDOMAIN at the end of a CNAME into another zone: the first zone's SOA is out of
    // bailiwick for the terminal name.
    let mut m = Msg::response(ID, "a.example.com", rtype::A, 3);
    m.rr(1, &ptr(12), rtype::CNAME, 300, &n("gone.other.net"));
    m.rr(
        2,
        &n("example.com"),
        rtype::SOA,
        900,
        &soa(&n("ns.example.com"), &n("h.example.com"), 1, 60),
    );
    let s = check(&m, "a.example.com", rtype::A).unwrap();
    assert_eq!(s.facts.negative, Some(Negative::Nxdomain));
    assert!(!s.facts.soa);
    assert_eq!(s.facts.cache_ttl, None);
    assert_eq!(s.removed.authority, 1);

    let mut m = Msg::response(ID, "a.example.com", rtype::A, 3);
    m.rr(1, &ptr(12), rtype::CNAME, 300, &n("gone.other.net"));
    m.rr(
        2,
        &n("other.net"),
        rtype::SOA,
        900,
        &soa(&n("ns.other.net"), &n("h.other.net"), 1, 60),
    );
    let s = check(&m, "a.example.com", rtype::A).unwrap();
    assert!(s.facts.soa);
    assert_eq!(s.facts.negative_ttl, Some(60), "min(900, 60)");
    assert_eq!(s.facts.cache_ttl, Some(60));

    // SOA TTL smaller than MINIMUM.
    let mut m = Msg::response(ID, "x.other.net", rtype::AAAA, 0);
    m.rr(
        2,
        &n("other.net"),
        rtype::SOA,
        30,
        &soa(&n("ns.other.net"), &n("h.other.net"), 1, 3600),
    );
    let s = check(&m, "x.other.net", rtype::AAAA).unwrap();
    assert_eq!(s.facts.negative, Some(Negative::Nodata));
    assert_eq!(s.facts.negative_ttl, Some(30));
    assert_eq!(s.facts.cache_ttl, Some(30));

    // The chain's CNAME TTL bounds a negative entry too.
    let mut m = Msg::response(ID, "a.example.com", rtype::A, 3);
    m.rr(1, &ptr(12), rtype::CNAME, 20, &n("gone.other.net"));
    m.rr(
        2,
        &n("other.net"),
        rtype::SOA,
        900,
        &soa(&n("ns.other.net"), &n("h.other.net"), 1, 600),
    );
    assert_eq!(
        check(&m, "a.example.com", rtype::A).unwrap().facts.cache_ttl,
        Some(20)
    );

    // Only one SOA is kept; the root zone's SOA covers every name.
    let mut m = Msg::response(ID, "nope.invalid", rtype::A, 3);
    m.rr(
        2,
        &[0],
        rtype::SOA,
        86400,
        &soa(&n("a.root-servers.net"), &n("nstld.verisign-grs.com"), 1, 86400),
    );
    m.rr(
        2,
        &[0],
        rtype::SOA,
        86400,
        &soa(&n("b.root-servers.net"), &n("nstld.verisign-grs.com"), 2, 86400),
    );
    let s = check(&m, "nope.invalid", rtype::A).unwrap();
    assert!(s.facts.soa);
    assert_eq!(decode(s.wire()).authorities.len(), 1);

    // A positive answer drops the SOA.
    let mut m = Msg::response(ID, "x.other.net", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    m.rr(
        2,
        &n("other.net"),
        rtype::SOA,
        30,
        &soa(&n("ns.other.net"), &n("h.other.net"), 1, 3600),
    );
    let s = check(&m, "x.other.net", rtype::A).unwrap();
    assert!(!s.facts.soa);
    assert_eq!(s.removed.authority, 1);
}

#[test]
fn rrsig_retention() {
    let mut m = Msg::response(ID, "www.example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::A, 3, 300, "example.com"),
    );
    // An RRSIG covering a type the scrub doesn't keep at that owner.
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::TXT, 3, 300, "example.com"),
    );
    // Authority NS with its RRSIG: both dropped.
    m.rr(2, &n("example.com"), rtype::NS, 300, &n("ns.example.com"));
    m.rr(
        2,
        &n("example.com"),
        rtype::RRSIG,
        300,
        &rrsig(rtype::NS, 2, 300, "example.com"),
    );
    m.opt(1232, 0, 0, true, &[]);
    let s = check(&m, "www.example.com", rtype::A).unwrap();
    assert_eq!(s.removed.rrsig, 1);
    assert_eq!(s.removed.authority, 2);
    let d = decode(s.wire());
    assert_eq!(d.answers.len(), 2);
    assert!(s.has_stripped_copy());

    // A question for RRSIG keeps the answer's RRSIGs without the RRsets they cover.
    let mut m = Msg::response(ID, "www.example.com", rtype::RRSIG, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::A, 3, 300, "example.com"),
    );
    m.rr(
        1,
        &ptr(12),
        rtype::RRSIG,
        300,
        &rrsig(rtype::AAAA, 3, 300, "example.com"),
    );
    m.rr(
        1,
        &n("other.example"),
        rtype::RRSIG,
        300,
        &rrsig(rtype::A, 2, 300, "example"),
    );
    let s = check(&m, "www.example.com", rtype::RRSIG).unwrap();
    assert_eq!(decode(s.wire()).answers.len(), 2);
    assert_eq!(s.removed.out_of_bailiwick, 1);
    assert!(s.facts.negative.is_none());
    // Asked for: the DO=0 copy keeps them, so there is nothing to strip.
    assert!(!s.has_stripped_copy());
}

#[test]
fn negative_proofs_kept() {
    let mut m = Msg::response(ID, "nope.example.com", rtype::A, 3);
    m.rr(
        2,
        &n("example.com"),
        rtype::SOA,
        3600,
        &soa(&n("ns.example.com"), &n("h.example.com"), 1, 300),
    );
    m.rr(
        2,
        &n("example.com"),
        rtype::RRSIG,
        3600,
        &rrsig(rtype::SOA, 2, 3600, "example.com"),
    );
    m.rr(
        2,
        &n("example.com"),
        rtype::NSEC,
        300,
        &nsec("www.example.com", &[rtype::SOA, rtype::NS]),
    );
    m.rr(
        2,
        &n("example.com"),
        rtype::RRSIG,
        300,
        &rrsig(rtype::NSEC, 2, 300, "example.com"),
    );
    m.rr(
        2,
        &n("abcdef.example.com"),
        rtype::NSEC3,
        300,
        &nsec3(&[rtype::A]),
    );
    // A proof from another zone: dropped.
    m.rr(
        2,
        &n("unrelated.net"),
        rtype::NSEC,
        300,
        &nsec("z.unrelated.net", &[rtype::A]),
    );
    m.opt(1232, 0, 0, true, &[]);
    let s = check(&m, "nope.example.com", rtype::A).unwrap();
    assert_eq!(s.removed.authority, 1);
    assert_eq!(decode(s.wire()).authorities.len(), 5);
    assert_eq!(s.facts.cache_ttl, Some(300));
}

#[test]
fn ipv4_mapped_answers() {
    let mut m = Msg::response(ID, "mapped.example", rtype::AAAA, 0);
    m.rr(1, &ptr(12), rtype::AAAA, 60, &aaaa("::ffff:203.0.113.5"));
    m.rr(1, &ptr(12), rtype::AAAA, 60, &aaaa("2001:db8::5"));
    let s = check(&m, "mapped.example", rtype::AAAA).unwrap();
    let f = &s.facts;
    assert_eq!(f.addrs[0].mapped_v4(), Some(Ipv4Addr::new(203, 0, 113, 5)));
    assert_eq!(f.addrs[0].match_ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    assert_eq!(f.addrs[1].mapped_v4(), None);
    assert_eq!(f.addrs[1].match_ip(), "2001:db8::5".parse::<IpAddr>().unwrap());
}

#[test]
fn svcb_https_hints_and_targets() {
    let params = vec![
        (1u16, b"\x02h3\x02h2".to_vec()),
        (3, 8443u16.to_be_bytes().to_vec()),
        (4, [a("192.0.2.1"), a("192.0.2.2")].concat()),
        (6, [aaaa("::ffff:198.51.100.3"), aaaa("2001:db8::1")].concat()),
    ];
    let mut m = Msg::response(ID, "svc.example", rtype::HTTPS, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::HTTPS,
        300,
        &svcb(1, "pool.cdn.example", &params),
    );
    m.rr(1, &ptr(12), rtype::HTTPS, 300, &svcb(2, ".", &params[..1]));
    let s = check(&m, "svc.example", rtype::HTTPS).unwrap();
    let f = &s.facts;
    assert_eq!(names(&f.targets), vec!["pool.cdn.example"]);
    let hints: Vec<_> = f.addrs.iter().map(|x| (x.ip, x.source)).collect();
    assert_eq!(hints.len(), 4);
    assert_eq!(hints[0], ("192.0.2.1".parse().unwrap(), AddrSource::Ipv4Hint));
    assert_eq!(hints[2].1, AddrSource::Ipv6Hint);
    assert_eq!(f.addrs[2].mapped_v4(), Some(Ipv4Addr::new(198, 51, 100, 3)));
    super::differential::assert_domain_accepts(s.wire());

    // SVCB (type 64) too.
    let mut m = Msg::response(ID, "_dns.resolver.example", rtype::SVCB, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::SVCB,
        300,
        &svcb(1, "dot.resolver.example", &[(4, a("192.0.2.53"))]),
    );
    let s = check(&m, "_dns.resolver.example", rtype::SVCB).unwrap();
    assert_eq!(names(&s.facts.targets), vec!["dot.resolver.example"]);
    assert_eq!(s.facts.addrs.len(), 1);
}

/// SVCB/HTTPS parameters RFC 9460 forbids are never accepted as hints. Such a record is
/// malformed (RFC 9460 §2.2) wherever it is: kept, off the chain, of a type the question didn't
/// ask for, or in the authority or additional section, the answer is invalid for the same reason
/// (edge.md §7 step 1), as it is when hickory itself refuses the parameters.
#[test]
fn svcb_forbidden_params() {
    type Case = (&'static str, Vec<(u16, Vec<u8>)>, Invalid);
    let bad: Vec<Case> = vec![
        (
            "duplicate key",
            vec![(4, a("192.0.2.1")), (4, a("192.0.2.2"))],
            Invalid::Undecodable,
        ),
        (
            "unordered keys",
            vec![(4, a("192.0.2.1")), (1, b"\x02h2".to_vec())],
            Invalid::Undecodable,
        ),
        (
            "ipv4hint of 5 bytes",
            vec![(4, vec![192, 0, 2, 1, 9])],
            Invalid::Undecodable,
        ),
        (
            "ipv6hint of 15 bytes",
            vec![(6, vec![0; 15])],
            Invalid::Undecodable,
        ),
        ("alpn with an empty id", vec![(1, vec![0])], Invalid::BadSvcb),
        (
            "alpn with an empty id after h2",
            vec![(1, b"\x02h2\x00".to_vec())],
            Invalid::BadSvcb,
        ),
        ("empty ipv4hint", vec![(4, vec![])], Invalid::BadSvcb),
        ("empty ipv6hint", vec![(6, vec![])], Invalid::BadSvcb),
        ("3-byte port", vec![(3, vec![0, 80, 0])], Invalid::BadSvcb),
        (
            "no-default-alpn with a value",
            vec![(2, vec![1])],
            Invalid::Undecodable,
        ),
        (
            "mandatory lists a missing key",
            vec![(0, 4u16.to_be_bytes().to_vec()), (1, b"\x02h2".to_vec())],
            Invalid::BadSvcb,
        ),
        (
            "mandatory lists itself",
            vec![(0, 0u16.to_be_bytes().to_vec()), (1, b"\x02h2".to_vec())],
            Invalid::BadSvcb,
        ),
        ("ohttp with a value", vec![(8, vec![1])], Invalid::BadSvcb),
        ("dohpath not UTF-8", vec![(7, vec![0xff, 0xfe])], Invalid::BadSvcb),
        (
            "tls-supported-groups of 3 bytes",
            vec![(9, vec![0, 29, 0])],
            Invalid::BadSvcb,
        ),
        ("empty tls-supported-groups", vec![(9, vec![])], Invalid::BadSvcb),
        (
            "mandatory unordered",
            vec![
                (0, [3u16.to_be_bytes(), 1u16.to_be_bytes()].concat()),
                (1, b"\x02h2".to_vec()),
                (3, vec![0, 80]),
            ],
            Invalid::BadSvcb,
        ),
    ];
    // Where the record goes: (section, owner, qtype). The first is kept; the scrub drops the
    // others (out of bailiwick, unexpected type, authority, additional).
    let places: [(usize, Option<&str>, u16); 6] = [
        (1, None, rtype::HTTPS),
        (1, Some("off.example"), rtype::HTTPS),
        (1, None, rtype::A),
        (2, None, rtype::HTTPS),
        (3, None, rtype::HTTPS),
        (3, Some("pool.example"), rtype::A),
    ];
    let placed = |(section, owner, qtype): (usize, Option<&str>, u16), rdata: &[u8]| {
        let mut m = Msg::response(ID, "svc.example", qtype, 0);
        if qtype == rtype::A {
            m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
        }
        let owner = owner.map_or_else(|| ptr(12), n);
        m.rr(section, &owner, rtype::HTTPS, 300, rdata);
        check(&m, "svc.example", qtype)
    };
    for (what, params, expect) in &bad {
        for place in places {
            assert_eq!(
                placed(place, &svcb(1, ".", params)).unwrap_err(),
                *expect,
                "{what} at {place:?}"
            );
            // In AliasMode the SvcParams are ignored (RFC 9460 §2.4.2): only their framing is
            // checked (keys strictly increasing), never a value, even one hickory's decoder
            // would refuse.
            let alias = placed(place, &svcb(0, "pool.example", params));
            if params.windows(2).all(|w| w[0].0 < w[1].0) {
                assert!(alias.is_ok(), "AliasMode {what} at {place:?}: {alias:?}");
            } else {
                assert_eq!(
                    alias.unwrap_err(),
                    Invalid::Undecodable,
                    "AliasMode {what} at {place:?}"
                );
            }
        }
    }
    // A compressed target name (RFC 9460 §2.2 forbids it), in ServiceMode and AliasMode.
    for priority in [1u16, 0] {
        let mut data = priority.to_be_bytes().to_vec();
        data.extend_from_slice(b"\x04pool");
        data.extend_from_slice(&ptr(12 + 4));
        for place in places {
            assert_eq!(
                placed(place, &data).unwrap_err(),
                Invalid::BadSvcb,
                "priority {priority} at {place:?}"
            );
        }
    }
    // Legitimate records pass, kept or dropped: ServiceMode with alpn and port, an unknown key,
    // no-default-alpn beside alpn, and AliasMode with and without parameters.
    let legit = [
        svcb(1, ".", &[(1, b"\x02h2".to_vec()), (3, vec![1, 187])]),
        svcb(1, "pool.example", &[(65_000, b"opaque value".to_vec())]),
        svcb(1, ".", &[(1, b"\x02h3".to_vec()), (2, vec![])]),
        svcb(0, "pool.example", &[]),
        svcb(0, "pool.example", &[(4, a("192.0.2.9"))]),
    ];
    for rdata in &legit {
        for place in places {
            let s = placed(place, rdata).unwrap_or_else(|e| panic!("{place:?} {rdata:02x?}: {e:?}"));
            assert_eq!(s.removed.total() == 0, place == places[0], "{place:?}");
        }
    }
    // A kept AliasMode record gives its target, never its hints.
    let s = placed(places[0], &legit[4]).unwrap();
    assert_eq!(names(&s.facts.targets), ["pool.example"]);
    assert!(s.facts.addrs.is_empty(), "{:?}", s.facts.addrs);
    // The later keys in their valid forms.
    let mut m = Msg::response(ID, "svc.example", rtype::HTTPS, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::HTTPS,
        300,
        &svcb(
            1,
            ".",
            &[
                (7, b"/dns-query{?dns}".to_vec()),
                (8, vec![]),
                (9, vec![0, 29, 0, 23]),
            ],
        ),
    );
    assert!(check(&m, "svc.example", rtype::HTTPS).is_ok());
    // Mandatory lists checked in one pass over the record's keys: each listed key present,
    // before, between and after keys the list skips.
    let k = |v: &[u16]| v.iter().flat_map(|k| k.to_be_bytes()).collect::<Vec<u8>>();
    let params = |list: &[u16]| {
        vec![
            (0, k(list)),
            (1, b"\x02h2".to_vec()),
            (3, vec![1, 187]),
            (4, a("192.0.2.1")),
            (65_000, vec![]),
        ]
    };
    for (list, ok) in [
        (&[1][..], true),
        (&[3, 4], true),
        (&[1, 65_000], true),
        (&[1, 3, 4, 65_000], true),
        (&[2], false),
        (&[1, 5], false),
        (&[4, 65_001], false),
        (&[3, 3], false),
    ] {
        let mut m = Msg::response(ID, "svc.example", rtype::HTTPS, 0);
        m.rr(1, &ptr(12), rtype::HTTPS, 300, &svcb(1, ".", &params(list)));
        let r = check(&m, "svc.example", rtype::HTTPS);
        assert_eq!(r.is_ok(), ok, "mandatory {list:?}: {:?}", r.err());
    }
}

#[test]
fn kept_records_that_cannot_be_kept() {
    // RP may hold compressed names and hickory doesn't decode it.
    let mut m = Msg::response(ID, "x.example", rtype::RP, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::RP,
        60,
        &[n("h.example"), n("txt.example")].concat(),
    );
    assert_eq!(
        check(&m, "x.example", rtype::RP).unwrap_err(),
        Invalid::OpaqueCompressible
    );
    // ... but dropped, it does no harm.
    let mut m = Msg::response(ID, "x.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    m.rr(
        2,
        &n("example"),
        rtype::RP,
        60,
        &[n("h.example"), n("txt.example")].concat(),
    );
    assert!(check(&m, "x.example", rtype::A).is_ok());
    // An unknown type stays opaque.
    let mut m = Msg::response(ID, "x.example", 65280, 0);
    m.rr(1, &ptr(12), 65280, 60, &[0xC0, 0x0C, 1, 2]);
    let s = check(&m, "x.example", 65280).unwrap();
    assert_eq!(decode(s.wire()).answers.len(), 1);
    // Empty data for A: hickory's A decoder refuses it, in any section.
    let mut m = Msg::response(ID, "x.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &[]);
    assert_eq!(
        check(&m, "x.example", rtype::A).unwrap_err(),
        Invalid::Undecodable
    );
    let mut m = Msg::response(ID, "x.example", rtype::A, 0);
    m.rr(3, &n("glue.example"), rtype::DS, 60, &[]);
    assert_eq!(
        check(&m, "x.example", rtype::A).unwrap_err(),
        Invalid::Undecodable
    );
    // Empty TXT (RFC 1035: one or more strings).
    let mut m = Msg::response(ID, "x.example", rtype::TXT, 0);
    m.rr(1, &ptr(12), rtype::TXT, 60, &[]);
    assert_eq!(
        check(&m, "x.example", rtype::TXT).unwrap_err(),
        Invalid::Undecodable
    );
    // An empty DNAME kept for a DNAME question.
    let mut m = Msg::response(ID, "x.example", rtype::DNAME, 0);
    m.rr(1, &ptr(12), rtype::DNAME, 60, &[]);
    assert_eq!(
        check(&m, "x.example", rtype::DNAME).unwrap_err(),
        Invalid::DnameTarget
    );
    // A record of a meta type.
    let mut m = Msg::response(ID, "x.example", rtype::ANY, 0);
    m.rr(1, &ptr(12), rtype::MAILA, 60, &[]);
    assert_eq!(
        check(&m, "x.example", rtype::ANY).unwrap_err(),
        Invalid::EmptyRdata
    );
    // Empty data for an unknown type is fine.
    let mut m = Msg::response(ID, "x.example", 65280, 0);
    m.rr(1, &ptr(12), 65280, 60, &[]);
    assert!(check(&m, "x.example", 65280).is_ok());
}

/// RFC 4034 §4.1.2: NSEC/NSEC3 type bitmaps are refused unless their window blocks are in
/// order, 1 to 32 bytes long and fill the data (hickory keeps them unchecked).
#[test]
fn nsec_bitmaps_checked() {
    let good = nsec("z.example.com", &[rtype::A, rtype::NSEC, rtype::RRSIG]);
    let name_len = n("z.example.com").len();
    let cases: Vec<(Vec<u8>, bool)> = vec![
        (good.clone(), true),
        ([&good[..name_len], &[0, 0][..]].concat(), false), // empty block
        ([&good[..name_len], &[0, 33][..], &[0u8; 33][..]].concat(), false), // over 32
        ([&good[..name_len], &[0, 4, 0x40][..]].concat(), false), // short block
        ([&good[..name_len], &[1, 1, 0x40, 0, 1, 0x40][..]].concat(), false), // unordered
        (good[..name_len].to_vec(), true),                  // no bitmap at all
    ];
    for (data, ok) in cases {
        let mut m = Msg::response(ID, "nope.example.com", rtype::A, 3);
        m.rr(
            2,
            &n("example.com"),
            rtype::SOA,
            60,
            &soa(&n("ns.example.com"), &n("h.example.com"), 1, 60),
        );
        m.rr(2, &n("example.com"), rtype::NSEC, 60, &data);
        assert_eq!(check(&m, "nope.example.com", rtype::A).is_ok(), ok, "{data:02x?}");
    }
    let mut bad3 = nsec3(&[rtype::A]);
    let at = bad3.len() - 2;
    bad3[at] = 40; // the block length
    let mut m = Msg::response(ID, "nope.example.com", rtype::A, 3);
    m.rr(2, &n("x.example.com"), rtype::NSEC3, 60, &bad3);
    assert_eq!(
        check(&m, "nope.example.com", rtype::A).unwrap_err(),
        Invalid::Undecodable
    );
}

#[test]
fn class_mismatch_dropped() {
    let mut m = Msg::response(ID, "x.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    m.rr_class(1, &ptr(12), rtype::A, 3, 60, &a("192.0.2.2"));
    m.rr_class(
        1,
        &ptr(12),
        rtype::RRSIG,
        3,
        60,
        &rrsig(rtype::A, 2, 60, "example"),
    );
    let s = check(&m, "x.example", rtype::A).unwrap();
    assert_eq!(s.facts.addrs.len(), 1);
    assert_eq!(s.removed.wrong_class, 2);
    assert_eq!(s.removed.unexpected_type, 0);
    assert_eq!(s.removed.total(), 2);
}

#[test]
fn ad_cleared_and_owners_lowercased() {
    let mut m = Msg::with_flags(ID, 0x81, 0x80 | 0x20 | 0x10); // AD and CD set
    m.question(&n("WWW.Example.COM"), rtype::A, 1);
    m.rr(1, &n("www.EXAMPLE.com"), rtype::A, 60, &a("192.0.2.1"));
    let s = check(&m, "www.example.com", rtype::A).unwrap();
    let w = s.wire();
    assert_eq!(w[3] & 0x20, 0, "AD cleared");
    assert_eq!(w[3] & 0x10, 0x10, "CD kept");
    // The question is written as sent (lowercase); the owner compresses to it.
    assert_eq!(&w[12..12 + 17], &n("www.example.com")[..]);
    assert_eq!(&w[12 + 21..12 + 23], &[0xC0, 0x0C]);
}

#[test]
fn ttl_offsets_are_header_ttls() {
    // The SOA's MINIMUM is never an offset; only header TTLs are.
    let mut m = Msg::response(ID, "x.other.net", rtype::A, 3);
    m.rr(
        2,
        &n("other.net"),
        rtype::SOA,
        77,
        &soa(&n("ns.other.net"), &n("h.other.net"), 1, 99),
    );
    let s = check(&m, "x.other.net", rtype::A).unwrap();
    let ttls = &s.full.ttls;
    assert_eq!(ttls.len(), 1);
    assert_eq!(ttls[0].ttl, 77);
    let at = s.full.records.start + usize::from(ttls[0].offset);
    assert_eq!(&s.wire()[at..at + 4], &77u32.to_be_bytes());
}

/// Every invalid reason is in `Invalid::ALL` once, with its own counter name, and every scrub
/// reason in `ScrubCounts::REASONS`, so counters can be registered up front.
#[test]
fn counter_names_cover_every_reason() {
    // The match is exhaustive: a new variant fails to compile until it has an index here.
    fn index(i: Invalid) -> usize {
        match i {
            Invalid::TooLarge => 0,
            Invalid::ShortHeader => 1,
            Invalid::NotResponse => 2,
            Invalid::Opcode => 3,
            Invalid::TooManyRecords => 4,
            Invalid::QuestionCount => 5,
            Invalid::IdMismatch => 6,
            Invalid::Undecodable => 7,
            Invalid::QuestionMismatch => 8,
            Invalid::TrailingBytes => 9,
            Invalid::OptNotAdditional => 10,
            Invalid::DuplicateOpt => 11,
            Invalid::MalformedOpt => 12,
            Invalid::CnameHops => 13,
            Invalid::CnameLoop => 14,
            Invalid::AmbiguousChain => 15,
            Invalid::DnameTarget => 16,
            Invalid::EmptyRdata => 17,
            Invalid::OpaqueCompressible => 18,
            Invalid::BadSvcb => 19,
            Invalid::Encode => 20,
            Invalid::RrsetTooLarge => 21,
        }
    }
    for (i, r) in Invalid::ALL.iter().enumerate() {
        assert_eq!(index(*r), i, "{r:?}");
    }
    let mut labels: Vec<&str> = Invalid::ALL.iter().map(|r| r.reason()).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), Invalid::ALL.len());

    let counts = crate::answer::ScrubCounts {
        out_of_bailiwick: 1,
        unexpected_type: 2,
        wrong_class: 3,
        rrsig: 4,
        authority: 5,
        additional: 6,
        duplicate: 7,
        padding: 8,
    };
    let l = counts.labelled();
    assert_eq!(l.map(|(name, _)| name), crate::answer::ScrubCounts::REASONS);
    assert_eq!(l.map(|(_, n)| n), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(counts.total(), 36);
}

/// The rcode's upper 8 bits come from the OPT (RFC 6891 §6.1.3) and the scrubbed wire keeps them.
#[test]
fn extended_rcode_from_opt() {
    // BADCOOKIE (23): header low bits 7, OPT extended rcode 1.
    let mut m = Msg::response(ID, "example.com", rtype::A, 7);
    m.opt(1232, 1, 0, false, &[]);
    let s = check(&m, "example.com", rtype::A).unwrap();
    assert_eq!(s.facts.rcode, 23);
    assert_eq!(s.facts.cache_ttl, None);
    assert_eq!(u16::from(decode(s.wire()).response_code), 23);
    // BADVERS (16).
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.opt(1232, 1, 0, false, &[]);
    assert_eq!(check(&m, "example.com", rtype::A).unwrap().facts.rcode, 16);
}

/// An OPT whose owner is a pointer to a root byte is still the root (RFC 6891 §6.1.2); the
/// scrubbed copy writes a plain root owner, so nothing points at scrubbed bytes.
#[test]
fn opt_owner_pointer_to_root() {
    let root_at = 12 + n("a.example").len() as u16 - 1;
    let mut m = Msg::response(ID, "a.example", rtype::A, 0);
    m.rr(1, &n("evil.example"), rtype::A, 60, &a("192.0.2.66"));
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    m.rr_class(
        3,
        &ptr(root_at),
        rtype::OPT,
        1232,
        0,
        b"\x00\x0f\x00\x04\x00\x0fxy",
    );
    let s = check(&m, "a.example", rtype::A).unwrap();
    assert_eq!(s.removed.out_of_bailiwick, 1);
    assert_eq!(s.facts.ede.len(), 1);
    assert_eq!((s.facts.ede[0].code, s.facts.ede[0].text.as_str()), (15, "xy"));
    let w = s.wire();
    // The OPT is the last record: a root owner, then TYPE 41.
    let opt_at = w.len() - 11 - 8;
    assert_eq!(&w[opt_at..opt_at + 3], &[0, 0, 41]);
    assert!(decode(w).edns.is_some());
    super::differential::assert_domain_accepts(w);
}

/// Resolvers may echo the question in another case (DNS 0x20); class and type must match.
#[test]
fn question_echo_case_and_class() {
    let mut m = Msg::response(ID, "WwW.ExAmPlE.CoM", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    let s = check(&m, "www.example.com", rtype::A).unwrap();
    // The scrubbed copy carries the question as sent, so every client's question lines up.
    assert_eq!(&s.wire()[12..12 + 17], &n("www.example.com")[..]);
    let mut ch = Msg::with_flags(ID, 0x81, 0x80);
    ch.question(&n("www.example.com"), rtype::A, crate::types::class::CH);
    assert_eq!(
        check(&ch, "www.example.com", rtype::A).unwrap_err(),
        Invalid::QuestionMismatch
    );
}

/// 64 records in a section is the cap, not over it (edge.md §7 step 1).
/// An address for record `i` of a large test RRset.
fn nth_a(i: u16) -> Vec<u8> {
    let [hi, lo] = i.to_be_bytes();
    vec![10, 0, hi, lo]
}

fn check_limited(
    m: &Msg,
    name: &str,
    qtype: u16,
    max_rrset: u16,
) -> Result<crate::answer::ScrubbedAnswer, Invalid> {
    let s = sent_for(ID, name, qtype);
    let limits = AnswerLimits {
        max_rrset: Some(max_rrset),
        ..AnswerLimits::default()
    };
    check_answer(&m.build(), &s.sent(), &limits)
}

/// Issue #16: real answers pass 64 records in a section (large TXT sets, address pools over TCP);
/// the section bound is 1,024.
#[test]
fn section_bound_is_1024_records() {
    let mut m = Msg::response(ID, "many.example", rtype::A, 0);
    for i in 0..1024u16 {
        m.rr(1, &ptr(12), rtype::A, 60, &nth_a(i));
    }
    let s = check(&m, "many.example", rtype::A).unwrap();
    assert_eq!(s.facts.addrs.len(), 1024);
    assert_eq!(s.removed.total(), 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("10.9.0.0"));
    assert_eq!(
        check(&m, "many.example", rtype::A).unwrap_err(),
        Invalid::TooManyRecords
    );
}

/// The per-RRset limit counts kept answer records after duplicates are removed; unset (the
/// default) means no limit beyond the section bound, and 0 means unset.
#[test]
fn rrset_limit() {
    let mut m = Msg::response(ID, "pool.example", rtype::A, 0);
    for i in 0..300u16 {
        m.rr(1, &ptr(12), rtype::A, 60, &nth_a(i));
    }
    assert_eq!(
        check(&m, "pool.example", rtype::A).unwrap().facts.addrs.len(),
        300
    );
    assert_eq!(
        check_limited(&m, "pool.example", rtype::A, 256).unwrap_err(),
        Invalid::RrsetTooLarge
    );
    assert_eq!(
        check_limited(&m, "pool.example", rtype::A, 299).unwrap_err(),
        Invalid::RrsetTooLarge
    );
    assert_eq!(
        check_limited(&m, "pool.example", rtype::A, 300)
            .unwrap()
            .facts
            .addrs
            .len(),
        300
    );
    assert_eq!(
        check_limited(&m, "pool.example", rtype::A, 0)
            .unwrap()
            .facts
            .addrs
            .len(),
        300
    );
    assert!(!Invalid::RrsetTooLarge.reason().is_empty());
    assert!(Invalid::RrsetTooLarge.is_size_limit() && Invalid::TooManyRecords.is_size_limit());
    assert!(!Invalid::Undecodable.is_size_limit());

    // Duplicates don't count: 200 records, each twice, fit a limit of 200.
    let mut d = Msg::response(ID, "pool.example", rtype::A, 0);
    for i in 0..400u16 {
        d.rr(1, &ptr(12), rtype::A, 60, &nth_a(i % 200));
    }
    let s = check_limited(&d, "pool.example", rtype::A, 200).unwrap();
    assert_eq!(s.facts.addrs.len(), 200);
    assert_eq!(s.removed.duplicate, 200);
}

/// Records the scrub drops never count toward the RRset limit: an out-of-bailiwick set in the
/// answer section, a large authority or additional section.
#[test]
fn rrset_limit_counts_only_kept_records() {
    let mut m = Msg::response(ID, "www.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    let other = n("other.example");
    for i in 0..300u16 {
        m.rr(1, &other, rtype::A, 60, &nth_a(i));
    }
    let s = check_limited(&m, "www.example", rtype::A, 256).unwrap();
    assert_eq!(s.facts.addrs.len(), 1);
    assert_eq!(s.removed.out_of_bailiwick, 300);

    // Big authority and additional sections (e.g. many NS and glue): scrubbed, not refused.
    let mut m = Msg::response(ID, "www.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    for i in 0..200u16 {
        m.rr(2, &n("example"), rtype::NS, 60, &n(&format!("ns{i}.example")));
    }
    for i in 0..200u16 {
        m.rr(3, &n(&format!("ns{i}.example")), rtype::A, 60, &nth_a(i));
    }
    m.opt(1232, 0, 0, false, &[]);
    let s = check_limited(&m, "www.example", rtype::A, 64).unwrap();
    assert_eq!(s.facts.addrs.len(), 1);
    assert_eq!(s.removed.authority, 200);
    assert_eq!(s.removed.additional, 200);
}

/// Duplicate detection switches from a scan to a hash index past 32 records: the result is the
/// same either side of the switch, whatever the order and section.
#[test]
fn duplicates_found_past_the_scan() {
    for unique in [1u16, 31, 32, 33, 100, 500] {
        let mut m = Msg::response(ID, "dup.example", rtype::A, 0);
        for i in 0..unique {
            m.rr(1, &ptr(12), rtype::A, 60, &nth_a(i));
        }
        // Every record again, in reverse, plus the same data in the additional section (not a
        // duplicate: another section).
        for i in (0..unique).rev() {
            m.rr(1, &ptr(12), rtype::A, 60, &nth_a(i));
        }
        for i in 0..unique.min(10) {
            m.rr(3, &ptr(12), rtype::A, 60, &nth_a(i));
        }
        let s = check(&m, "dup.example", rtype::A).unwrap();
        assert_eq!(s.facts.addrs.len(), usize::from(unique), "{unique}");
        assert_eq!(s.removed.duplicate, unique, "{unique}");
        assert_eq!(s.removed.additional, unique.min(10), "{unique}");
    }
}

/// A UDP transport retries a truncated answer over TCP before checking it (RFC 7766 §5,
/// providers.md §5 `dns`); the header alone tells.
#[test]
fn truncated_response_from_the_header() {
    use crate::answer::is_truncated_response;
    let mut m = Msg::with_flags(ID, 0x83, 0x80); // QR, TC, RD
    m.question(&n("a.example"), rtype::A, 1);
    // Cut mid-record, as some servers do: the header still says TC.
    m.raw(&[0xC0, 0x0C, 0, 1]);
    let msg = m.build();
    assert!(is_truncated_response(&msg, ID));
    assert!(!is_truncated_response(&msg, ID + 1));
    assert!(!is_truncated_response(&msg[..11], ID));
    let full = Msg::response(ID, "a.example", rtype::A, 0).build();
    assert!(!is_truncated_response(&full, ID));
    let mut q = Msg::with_flags(ID, 0x03, 0); // TC without QR: a query
    q.question(&n("a.example"), rtype::A, 1);
    assert!(!is_truncated_response(&q.build(), ID));
}

/// EDE 3 (stale) is found among other options, Padding included, and only EDE options count
/// toward the EDE cap.
#[test]
fn stale_ede_among_other_options() {
    let mut m = Msg::response(ID, "example.com", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 60, &a("192.0.2.1"));
    m.opt(
        1232,
        0,
        0,
        false,
        &[
            (edns_code::EDE, b"\x00\x0fBlocked"),
            (edns_code::PADDING, &[0; 8]),
            (edns_code::EDE, b"\x00\x03"),
        ],
    );
    let s = check(&m, "example.com", rtype::A).unwrap();
    assert!(s.facts.stale);
    assert_eq!(s.facts.ede.len(), 2);
    assert_eq!(s.removed.padding, 1);
    assert_eq!(s.facts.cache_ttl, None);
}

/// A wildcard-expanded signed answer (RRSIG labels below the owner's) keeps its NSEC3 proof and
/// that proof's RRSIG from the authority section; the DO=0 copy strips them.
#[test]
fn wildcard_answer_keeps_nsec3_proof() {
    let f = crate::testutil::fixture("wildcard-nsec3");
    let sent = crate::testutil::Sent::of(&f.query);
    let s = check_answer(&f.answer, &sent.sent(), &AnswerLimits::default()).unwrap();
    assert!(s.facts.negative.is_none());
    assert_eq!(s.facts.addrs.len(), 1);
    assert_eq!(s.removed.total(), 0, "{:?}", s.removed);
    let d = decode(s.wire());
    let auth: Vec<RecordType> = d.authorities.iter().map(|r| r.record_type()).collect();
    assert_eq!(auth.len(), 2);
    assert!(auth.contains(&RecordType::NSEC3));
    let v = crate::cache::CacheValue::new(s, std::time::SystemTime::now(), std::time::Instant::now());
    let sd = decode(&super::cache::copy_message(&v, false));
    assert_eq!(sd.answers.len(), 1);
    assert_eq!(sd.answers[0].record_type(), RecordType::A);
    assert!(sd.authorities.is_empty());
}

/// W5: an SOA in the answer section is an ordinary record of the qtype: it bounds a positive
/// entry's lifetime like any other (edge.md §8); only the negative-caching SOA in the authority
/// section is judged by min(TTL, MINIMUM) instead (RFC 2308 §5).
#[test]
fn positive_soa_answers_bound_the_cache_ttl() {
    let mut m = Msg::response(ID, "example.com", rtype::SOA, 0);
    m.rr(
        1,
        &ptr(12),
        rtype::SOA,
        3600,
        &soa(&n("ns.example.com"), &n("h.example.com"), 1, 300),
    );
    let s = check(&m, "example.com", rtype::SOA).unwrap();
    assert!(s.facts.negative.is_none());
    assert_eq!(s.facts.cache_ttl, Some(3600));

    let mut m = Msg::response(ID, "www.example.com", rtype::SOA, 0);
    m.rr(1, &ptr(12), rtype::CNAME, 300, &n("zone.example.net"));
    m.rr(
        1,
        &n("zone.example.net"),
        rtype::SOA,
        60,
        &soa(&n("ns.example.net"), &n("h.example.net"), 1, 3600),
    );
    let s = check(&m, "www.example.com", rtype::SOA).unwrap();
    assert!(s.facts.negative.is_none());
    assert_eq!(s.facts.cache_ttl, Some(60), "the SOA's 60 s, not the CNAME's 300");
}

/// W3: RFC 9460 §2.2 forbids a compressed TargetName and §7.2 a `port` that isn't 2 bytes. Each
/// alone was refused, but a pointer that expands by 11 bytes plus a `port` carrying 11 extra
/// bytes kept the re-encoded length equal to RDLENGTH, so the pair was accepted.
#[test]
fn svcb_malformations_cannot_cancel_out() {
    let mut m = Msg::response(ID, "svc.example", rtype::HTTPS, 0);
    let mut data = 1u16.to_be_bytes().to_vec();
    data.extend_from_slice(&ptr(12)); // svc.example: 13 bytes uncompressed, 2 here
    data.extend_from_slice(&3u16.to_be_bytes());
    data.extend_from_slice(&13u16.to_be_bytes());
    data.extend_from_slice(&[0x01, 0xBB]);
    data.extend_from_slice(&[0; 11]);
    m.rr(1, &ptr(12), rtype::HTTPS, 300, &data);
    assert_eq!(
        check(&m, "svc.example", rtype::HTTPS).unwrap_err(),
        Invalid::BadSvcb
    );
}

/// W9: more than 8 EDE options is well-formed (README "Health": only malformed answers count
/// against an upstream). The first 8 are kept in the facts and the rest counted ("Bounded"); an
/// EDE 3 among the rest still marks the answer stale.
#[test]
fn many_ede_options_kept_bounded_and_scanned() {
    let mut opts: Vec<(u16, &[u8])> = (0..9).map(|_| (edns_code::EDE, &b"\x00\x0f"[..])).collect();
    opts.push((edns_code::EDE, b"\x00\x03"));
    let mut m = Msg::response(ID, "blocked.example", rtype::A, 0);
    m.rr(1, &ptr(12), rtype::A, 300, &a("192.0.2.1"));
    m.opt(1232, 0, 0, false, &opts);
    let s = check(&m, "blocked.example", rtype::A).unwrap();
    assert_eq!(s.facts.ede.len(), crate::answer::MAX_EDE);
    assert_eq!(s.facts.ede_dropped, 2);
    assert!(s.facts.stale, "EDE 3 past the first 8 still counts");
    assert_eq!(s.facts.cache_ttl, None);
    // A malformed option anywhere is still malformed.
    let mut bad = opts.clone();
    bad.push((edns_code::EDE, b"\x00"));
    let mut m = Msg::response(ID, "blocked.example", rtype::A, 0);
    m.opt(1232, 0, 0, false, &bad);
    assert_eq!(
        check(&m, "blocked.example", rtype::A).unwrap_err(),
        Invalid::MalformedOpt
    );
}

/// W10: RFC 5155 §8.1/§8.2: a validator ignores NSEC3 records with an unknown hash algorithm or
/// unknown flags, so a forwarder passes them through. hickory refuses both values; the record is
/// kept as opaque bytes once a copy with the known values decodes, so its format is still
/// checked.
#[test]
fn nsec3_with_unknown_hash_algorithm_or_flags_passes_through() {
    for (alg, flags) in [(2u8, 0u8), (1, 0x02), (200, 0x81)] {
        let mut data = nsec3(&[rtype::A, rtype::RRSIG]);
        data[0] = alg;
        data[1] = flags;
        let mut m = Msg::response(ID, "nope.example.com", rtype::A, 3);
        m.rr(
            2,
            &n("example.com"),
            rtype::SOA,
            300,
            &soa(&n("ns.example.com"), &n("h.example.com"), 1, 300),
        );
        m.rr(
            2,
            &n("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.com"),
            rtype::NSEC3,
            300,
            &data,
        );
        m.opt(1232, 0, 0, true, &[]);
        let s = check(&m, "nope.example.com", rtype::A)
            .unwrap_or_else(|e| panic!("alg {alg} flags {flags}: {e:?}"));
        assert_eq!(s.removed.authority, 0);
        let wire = s.wire();
        assert!(
            wire.windows(data.len()).any(|w| w == &data[..]),
            "NSEC3 data copied as received"
        );
        super::differential::assert_domain_accepts(wire);
        // A DO=0 client doesn't get it.
        assert!(s.has_stripped_copy());
    }
    // NSEC3PARAM (RFC 5155 §4.1.2) likewise, answering a question for it.
    let mut m = Msg::response(ID, "example.com", rtype::NSEC3PARAM, 0);
    m.rr(1, &ptr(12), rtype::NSEC3PARAM, 300, &[2, 0, 0, 10, 2, 0xAB, 0xCD]);
    let s = check(&m, "example.com", rtype::NSEC3PARAM).unwrap();
    assert!(s.wire().ends_with(&[0, 7, 2, 0, 0, 10, 2, 0xAB, 0xCD]));
    m = Msg::response(ID, "example.com", rtype::NSEC3PARAM, 0);
    m.rr(1, &ptr(12), rtype::NSEC3PARAM, 300, &[2, 0, 0, 10, 9, 0xAB, 0xCD]);
    assert_eq!(
        check(&m, "example.com", rtype::NSEC3PARAM).unwrap_err(),
        Invalid::Undecodable,
        "salt length past the data"
    );
    // An NSEC3 whose format is wrong stays undecodable, whatever its algorithm.
    let mut data = nsec3(&[rtype::A]);
    data[0] = 2;
    data[4] = 200; // salt length past the data
    let mut m = Msg::response(ID, "nope.example.com", rtype::A, 3);
    m.rr(2, &n("x.example.com"), rtype::NSEC3, 300, &data);
    assert_eq!(
        check(&m, "nope.example.com", rtype::A).unwrap_err(),
        Invalid::Undecodable
    );
}

/// W11: QCLASS * (255) matches every class (RFC 1035 §3.2.5): the answer's records of any class
/// are the answer, not "wrong class".
#[test]
fn qclass_any_keeps_records_of_every_class() {
    let mut m = Msg::with_flags(ID, 0x81, 0x80);
    m.question(&n("www.example.com"), rtype::A, 255);
    m.rr(1, &ptr(12), rtype::CNAME, 300, &n("cdn.example.net"));
    m.rr(1, &n("cdn.example.net"), rtype::A, 300, &a("192.0.2.1"));
    let mut s = sent_for(ID, "www.example.com", rtype::A);
    s.qclass = 255;
    let ans = check_answer(&m.build(), &s.sent(), &AnswerLimits::default()).unwrap();
    assert_eq!(ans.removed.wrong_class, 0);
    assert_eq!(names(&ans.facts.chain), vec!["cdn.example.net"]);
    assert_eq!(ans.facts.addrs.len(), 1);
    assert!(ans.facts.negative.is_none());
    super::differential::assert_facts_match_domain(ans.wire(), &ans.facts);
}
