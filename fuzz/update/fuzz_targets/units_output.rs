//! The new release's `units` output (edge.md §14 step 3).
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge_update::units::{MAX_UNITS, is_release_unit_name, parse_units_output};

fuzz_target!(|data: &[u8]| {
    if let Ok(units) = parse_units_output(data) {
        assert!(units.len() <= MAX_UNITS);
        assert!(units.contains_key("picket-edge-update.path"));
        assert!(units.contains_key("picket-edge-update.service"));
        for (name, text) in &units {
            assert!(is_release_unit_name(name));
            assert!(!name.contains('/'));
            assert!(!text.contains('\0'));
        }
    }
});
