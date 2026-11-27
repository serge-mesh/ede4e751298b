//! Verdict records (the page-file values of a verdict set): decode, and re-encode canonically.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_bundle::verdict::VerdictRecord;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = VerdictRecord::decode(data) {
        let back = r.encode().expect("a decoded record encodes");
        assert_eq!(back, data, "the encoding is canonical");
    }
});
