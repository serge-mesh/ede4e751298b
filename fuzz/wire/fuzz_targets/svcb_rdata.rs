//! `svcb::rdata_facts` on arbitrary RDATA (build-and-test.md §4 "Fuzzing"): the facts of HTTPS or
//! SVCB data the edge answers with, such as a `$dnsrewrite` value (edge.md §4). It never panics;
//! data it accepts is well-formed per RFC 9460 (hickory re-encodes it byte for byte, so the target
//! isn't compressed and no value carries extra bytes), and `domain` reads it with the same target
//! and hints. The first byte picks the type: even SVCB, odd HTTPS.

#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_wire::answer::AddrSource;
use picket_wire::svcb::rdata_facts;
use picket_wire_fuzz::oracle::domain_decode;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rdata)) = data.split_first() else {
        return;
    };
    let rtype: u16 = if pick & 1 == 0 { 64 } else { 65 };
    let Some(facts) = rdata_facts(rtype, rdata) else {
        return;
    };
    let Ok(rdlen) = u16::try_from(rdata.len()) else {
        panic!("accepted over 65,535 bytes");
    };
    // The data as the one answer record of a response, for the oracle.
    let mut msg = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    msg.extend_from_slice(b"\x03svc\x07example\x00");
    msg.extend_from_slice(&rtype.to_be_bytes());
    msg.extend_from_slice(&[0, 1, 0xC0, 0x0C]);
    msg.extend_from_slice(&rtype.to_be_bytes());
    msg.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    msg.extend_from_slice(&rdlen.to_be_bytes());
    msg.extend_from_slice(rdata);
    let (_, _, recs) =
        domain_decode(&msg).unwrap_or_else(|e| panic!("domain rejects accepted SVCB data: {e}"));
    let rec = recs.first().expect("domain keeps the record");
    let target = rec.svcb_target.as_ref().expect("an SVCB target");
    match &facts.target {
        Some(t) => assert_eq!(t.wire(), &target[..], "target"),
        None => assert_eq!(&target[..], &[0], "root target"),
    }
    let hints: Vec<_> = facts
        .hints
        .iter()
        .map(|a| (a.ip, a.source == AddrSource::Ipv4Hint))
        .collect();
    assert_eq!(hints, rec.hints, "hints");
});
