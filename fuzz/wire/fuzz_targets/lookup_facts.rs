//! Lookup answer facts (providers.md §5 `dns`) on arbitrary bytes: never panics, and agrees with
//! the full pipeline's facts.

#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_wire::answer::{AnswerLimits, SentQuery, check_answer};
use picket_wire::facts::lookup_answer_facts;
use picket_wire_fuzz::sent_of;

fuzz_target!(|data: &[u8]| {
    let Some((id, qname, qtype, qclass)) = sent_of(data) else {
        return;
    };
    let sent = SentQuery {
        id,
        qname: qname.as_name(),
        qtype,
        qclass,
    };
    let facts = lookup_answer_facts(data, &sent);
    let full = check_answer(data, &sent, &AnswerLimits::default());
    match (facts, full) {
        (Ok(f), Ok(a)) => {
            assert_eq!(f.rcode, a.facts.rcode);
            assert_eq!(f.chain, a.facts.chain);
            assert_eq!(f.soa, a.facts.soa);
            assert_eq!(f.ede, a.facts.ede);
        }
        (Err(e1), Err(e2)) => assert_eq!(e1, e2),
        // Only encoding can fail after the checks lookups share.
        (Ok(_), Err(e)) => assert_eq!(e, picket_wire::answer::Invalid::Encode),
        (Err(e), Ok(_)) => panic!("lookup refused what the pipeline accepted: {e:?}"),
    }
});
