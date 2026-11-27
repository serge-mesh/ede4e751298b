//! `bin/update-result.json` as the edge imports it (edge.md §14).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = picket_edge::update::parse_result(&v, None);
    }
});
