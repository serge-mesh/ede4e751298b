//! What an edge sends the edge port besides logs and sessions (api.md §2): `POST /v1/csr`
//! bodies, `Range`, `If-Match`/`If-None-Match` values. Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<picket_api::edge_api::CsrRequest>(data);
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(h) = http::HeaderValue::from_str(s) {
        for len in [0u64, 1, 10, 4096, u64::MAX] {
            if let Ok(Some((a, b))) = picket_core::edge_api::objects::parse_range(Some(&h), len) {
                assert!(a <= b && b < len);
            }
        }
    }
    let _ = picket_core::edge_api::objects::tag_matches(s, "abc");
    let _ = picket_core::edges::status::parse_firmware(s);
    let _ = picket_core::metrics::query::parse_series(s);
});
