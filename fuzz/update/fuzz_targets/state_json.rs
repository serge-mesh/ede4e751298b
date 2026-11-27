//! The edge's `state.json`, read for `ready_version` (edge.md §14 step 4).
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge_update::update::parse_ready_version;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ready_version(data);
});
