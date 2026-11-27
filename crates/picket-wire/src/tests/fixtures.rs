//! Recorded upstream answers (fixtures/wire/): each goes through the pipeline, and what it says
//! matches what the recording holds.

use std::time::{Instant, SystemTime};

use hickory_proto::rr::RecordType;

use super::decode;
use crate::answer::{AddrSource, AnswerLimits, Negative, check_answer};
use crate::cache::CacheValue;
use crate::dnssec::strip_for_do0;
use crate::testutil::{RECORDED, Sent, fixture};
use crate::types::edns_code;

fn run(name: &'static str) -> (crate::answer::ScrubbedAnswer, CacheValue) {
    let f = fixture(name);
    let sent = Sent::of(&f.query);
    let s = check_answer(&f.answer, &sent.sent(), &AnswerLimits::default())
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let v = CacheValue::new(s.clone(), SystemTime::now(), Instant::now());
    (s, v)
}

#[test]
fn every_recording_passes_and_round_trips() {
    for name in RECORDED {
        let (s, v) = run(name);
        // The scrubbed wire decodes with hickory and with domain.
        let d = decode(s.wire());
        assert!(!d.authentic_data, "{name}");
        super::differential::assert_domain_accepts(s.wire());
        super::differential::assert_facts_match_domain(s.wire(), &s.facts);
        // The DO=0 copy has no record the predicate strips.
        let stripped = super::cache::copy_message(&v, false);
        let sd = decode(&stripped);
        let qtype = u16::from(sd.queries[0].query_type());
        for r in sd.answers.iter().chain(sd.authorities.iter()) {
            assert!(!strip_for_do0(u16::from(r.record_type()), qtype), "{name}: {r:?}");
        }
        super::differential::assert_domain_accepts(&stripped);
    }
}

#[test]
fn plain_a() {
    let (s, _) = run("plain-a");
    assert_eq!(s.facts.addrs.len(), 2);
    assert!(s.facts.addrs.iter().all(|a| a.source == AddrSource::A));
    assert!(s.facts.cache_ttl.is_some());
    assert!(!s.has_stripped_copy());
}

#[test]
fn cname_chain() {
    let (s, _) = run("cname-chain");
    assert!(s.facts.chain.len() >= 2, "{:?}", s.facts.chain);
    assert_eq!(s.facts.chain[0].log_text(), "www.microsoft.com-c-3.edgekey.net");
    assert!(!s.facts.addrs.is_empty());
    assert!(s.facts.negative.is_none());
}

#[test]
fn signed_nsec3_nxdomain() {
    let (s, v) = run("signed-nsec3-nxdomain");
    assert_eq!(s.facts.negative, Some(Negative::Nxdomain));
    assert!(s.facts.soa);
    assert!(s.facts.cache_ttl.is_some());
    let d = decode(s.wire());
    let types: Vec<RecordType> = d.authorities.iter().map(|r| r.record_type()).collect();
    assert!(types.contains(&RecordType::SOA));
    assert!(types.contains(&RecordType::NSEC3));
    assert!(types.contains(&RecordType::RRSIG));
    assert_eq!(s.removed.total(), 0, "{:?}", s.removed);
    assert!(s.has_stripped_copy());
    let sd = decode(&super::cache::copy_message(&v, false));
    assert_eq!(sd.authorities.len(), 1);
    assert_eq!(sd.authorities[0].record_type(), RecordType::SOA);
}

#[test]
fn nxdomain_with_soa() {
    let (s, _) = run("nxdomain-soa");
    assert_eq!(s.facts.negative, Some(Negative::Nxdomain));
    assert!(s.facts.soa);
    let soa_ttl = s.facts.negative_ttl.unwrap();
    assert_eq!(s.facts.cache_ttl, Some(soa_ttl));
}

#[test]
fn https_with_hints() {
    let (s, _) = run("https-hints");
    // Recorded: alpn h3,h2 and two ipv4hint addresses.
    let v4: Vec<_> = s
        .facts
        .addrs
        .iter()
        .filter(|a| a.source == AddrSource::Ipv4Hint)
        .collect();
    assert_eq!(v4.len(), 2);
    assert!(s.facts.addrs.iter().all(|a| a.source == AddrSource::Ipv4Hint));
    assert!(s.facts.targets.is_empty(), "target is the owner (\".\")");
}

#[test]
fn dname_recording() {
    let (s, v) = run("dname");
    assert_eq!(
        s.facts.chain.iter().map(|n| n.log_text()).collect::<Vec<_>>(),
        vec!["foo.dns.netmeister.org"]
    );
    assert_eq!(s.facts.addrs.len(), 1);
    let d = decode(s.wire());
    assert!(
        d.answers
            .iter()
            .any(|r| r.record_type() == RecordType::Unknown(39) || u16::from(r.record_type()) == 39)
    );
    // The wildcard proof stays, signed by the zone the answer's RRSIGs name.
    assert!(d.authorities.iter().any(|r| r.record_type() == RecordType::NSEC));
    // DO=0: no DNAME, no RRSIG, no NSEC; the synthesised CNAME stays.
    let sd = decode(&super::cache::copy_message(&v, false));
    assert!(sd.answers.iter().all(|r| u16::from(r.record_type()) != 39));
    assert!(sd.answers.iter().any(|r| r.record_type() == RecordType::CNAME));
    assert!(sd.authorities.is_empty());
}

#[test]
fn padded_dot_answer() {
    let f = fixture("dot-padded-a");
    assert_eq!(f.query.len() % 128, 0, "the recorded query was padded");
    assert_eq!(f.answer.len(), 468, "the resolver padded its answer");
    let (s, _) = run("dot-padded-a");
    assert_eq!(s.removed.padding, 1);
    let d = decode(s.wire());
    let opts = &d.edns.as_ref().unwrap().options().options;
    assert!(opts.iter().all(|(c, _)| u16::from(*c) != edns_code::PADDING));
    assert!(s.wire().len() < 468);
}

#[test]
fn nodata_signed() {
    let (s, _) = run("nodata-signed");
    assert_eq!(s.facts.negative, Some(Negative::Nodata));
    assert!(s.facts.soa);
    assert!(s.facts.cache_ttl.is_some());
}

/// The recorded queries match what [`crate::upstream::write_query`] writes.
#[test]
fn upstream_writer_matches_recorded_queries() {
    use crate::upstream::{QueryParams, write_query};
    for name in RECORDED {
        let f = fixture(name);
        let q = crate::query::check_query(&f.query).unwrap();
        let p = QueryParams {
            id: q.id,
            cd: q.cd,
            do_bit: q.do_bit(),
            pad: *name == "dot-padded-a",
        };
        let mut buf = [0u8; 512];
        let len = write_query(&mut buf, q.qname().as_name(), q.qtype, q.qclass, &p).unwrap();
        assert_eq!(&buf[..len], &f.query[..], "{name}");
    }
}
