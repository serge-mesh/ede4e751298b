//! `bundles/active.json` as the edge reads it at start (edge.md §2): it sits on a drive UniFi
//! owns, so it is untrusted (README §2).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = picket_edge::bundles::record::Record::parse(data) {
        let _ = serde_json::to_vec(&r);
    }
});
