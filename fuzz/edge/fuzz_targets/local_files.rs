//! Local files the edge reads at start: edge.json, state.json, allows.json, mount tables.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = picket_edge::local_config::parse(data);
    let _ = serde_json::from_slice::<picket_edge::state::State>(data);
    let _ = serde_json::from_slice::<picket_edge::allows::AllowsFile>(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = picket_edge::storage::parse_mountinfo(s);
        let _ = picket_edge::local_config::CoreUrl::parse(s);
        let _ = picket_edge::neighbours::parse_mac(s);
    }
});
