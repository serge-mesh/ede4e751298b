//! `bin/update-result.json`: read back for the duplicate check and the snapshot rule.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge_update::result::parse;

fuzz_target!(|data: &[u8]| {
    if let Some(r) = parse(data) {
        // What parses re-serialises and parses to the same value.
        let again = serde_json::to_vec(&r).expect("serialise");
        assert_eq!(parse(&again), Some(r));
    }
});
