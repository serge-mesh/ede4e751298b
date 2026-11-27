//! What clients send the listeners, below the DNS message: length-prefixed stream framing (TCP,
//! DoT, and the upstream connections' answers), DoH paths and `?dns=` parameters, the DoT SNI
//! profile prefix, the question bounds the transports match answers on, and address ranges.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use picket_edge::dns::listeners::{doh, stream};
use picket_edge::dns::upstream::transport::{question_len, question_matches};

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);
    let mut total = 0usize;
    while let Some(m) = stream::take_frame(&mut buf) {
        assert!(m.len() <= 65_535);
        total += m.len() + 2;
        let ql = question_len(&m);
        assert!(ql == 0 || 12 + ql <= m.len());
        let _ = question_matches(&m, &m[12.min(m.len())..(12 + ql).min(m.len())]);
    }
    assert!(total <= data.len());
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = doh::path_profile(s);
        let _ = doh::get_param(Some(s));
        let names = vec!["dns.home.arpa".to_owned()];
        if let Some(p) = stream::profile_prefix(s, &names) {
            assert!(!p.contains('.') && !p.is_empty());
        }
        let _ = picket_edge::dns::profiles::parse_range(s);
    }
});
