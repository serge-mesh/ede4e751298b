//! The wire check's independent decode of a logged answer (core.md §6): `domain`'s decode, the
//! comparison with what a record logged, the presentation of a message's records and the answer
//! values replay reads (from the wire an edge sent), and the query-log API's record ids. Never
//! panics on any input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_api::logs::Stage;
use picket_core::logs::{query, record, wire};

fuzz_target!(|data: &[u8]| {
    let names = vec!["cdn.example.net".to_string(), "a\\033b.example".to_string()];
    let addrs = vec![
        "192.0.2.1".to_string(),
        "2001:db8::1".to_string(),
        "x".to_string(),
    ];
    for (i, stage) in [Stage::Query, Stage::Cname, Stage::AnswerIp, Stage::Svcb]
        .into_iter()
        .enumerate()
    {
        let logged = wire::Logged {
            cname: &names,
            answers: &addrs,
            targets: &names,
            cname_rewrite: i % 2 == 1,
            deciding: Some((stage, if i < 2 { names[0].clone() } else { addrs[0].clone() })),
        };
        let o = wire::check(data, &logged);
        if o.decoded.is_err() {
            assert_eq!(o.kinds, vec![wire::Kind::Rejected]);
        }
    }
    let _ = query::records_text(data);
    // A record whose answer is this wire: the values replay and retro-match read from it.
    let r = record::Rec {
        answer_wire: Some(data.to_vec()),
        response: Some(data.to_vec()),
        qname: "www.example.com".into(),
        decision: "allow".into(),
        ..Default::default()
    };
    let _ = r.answer_values();
    let _ = query::reply_of(&r, None);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = record::parse_record_id(s);
    }
});
