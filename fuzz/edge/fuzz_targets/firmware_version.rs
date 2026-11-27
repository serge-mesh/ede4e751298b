//! `/usr/lib/version` (untrusted UniFi state, README §2; edge-unifi.md §1): the firmware string
//! the edge sends in `hello` is one clean line of at most 128 bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge::firmware::{MAX_FIRMWARE, parse};

fuzz_target!(|data: &[u8]| {
    if let Some(s) = parse(data) {
        assert!(!s.is_empty());
        assert!(s.len() <= MAX_FIRMWARE);
        assert!(!s.chars().any(char::is_control));
    }
});
