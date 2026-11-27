//! DNSSEC validation and the cross-check on untrusted answers (core.md §8): a logged answer's
//! wire (from an edge) and every chain or fallback answer (from an edge's DoH listener) are the
//! fuzz input, validated by hickory over core's adapter; the candidate and cross-check readers
//! (sinkhole addresses, NODATA, "data for the question") read the same bytes. Never panics on any
//! input.
#![no_main]

use std::sync::Arc;

use hickory_proto::dnssec::TrustAnchors;
use hickory_proto::rr::{Name, RecordType};
use libfuzzer_sys::fuzz_target;
use picket_core::dnssec::validator::{
    self, ChainCache, ChainResolver, Limiter, ResolveError, Shared, Subject,
};
use picket_core::dnssec::{candidate, crosscheck};

/// Answers every query with the fuzz input.
struct Echo(Vec<u8>);

#[async_trait::async_trait]
impl ChainResolver for Echo {
    async fn query(&self, _: &Name, _: RecordType) -> Result<Vec<u8>, ResolveError> {
        Ok(self.0.clone())
    }
}

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let shared = Shared {
        resolver: Arc::new(Echo(data.to_vec())),
        cache: Arc::new(ChainCache::default()),
        limiter: Arc::new(Limiter::new(100_000)),
        anchors: Arc::new(TrustAnchors::empty()),
        generation: 0,
    };
    let qname = validator::parse_name("www.example.com").unwrap();
    for qtype in [RecordType::A, RecordType::DS] {
        let q = validator::question(&qname, qtype);
        let v = rt.block_on(validator::validate(
            &shared,
            Subject::Logged {
                query: q.clone(),
                wire: data,
            },
            1_700_000_000,
        ));
        let _ = v.retry();
        let _ = rt.block_on(validator::validate(
            &shared,
            Subject::Fallback { query: q },
            1_700_000_000,
        ));
    }
    // The readers of the same bytes.
    let r = picket_core::logs::record::Rec {
        answer_wire: Some(data.to_vec()),
        qname: "www.example.com".into(),
        qtype: "A".into(),
        decision: "allow".into(),
        upstream_json: Some(r#"{"group":"g"}"#.into()),
        ..Default::default()
    };
    let _ = candidate::answer_addrs(&r);
    let _ = candidate::sinkhole_flag(&r, &[]);
    let _ = candidate::nodata(&r);
    if let Ok(m) = hickory_proto::op::Message::from_vec(data) {
        let _ = crosscheck::has_data(&m, &qname, RecordType::MX);
    }
    // Names and types as records write them.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = validator::parse_name(text);
        let _ = validator::parse_qtype(text);
    }
});
