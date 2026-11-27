//! domains.bf8 / cold.bf8: refuse a length that doesn't match the fields; lookups never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_bundle::filter::KeyFilter;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = KeyFilter::from_bytes(data) {
        for k in [0u64, 1, u64::MAX, 0x9E37_79B9_7F4A_7C15, data.len() as u64] {
            let _ = f.contains(k);
        }
    }
});
