//! The Go → Rust regex translator: never panics; a translation either builds within the NFA limit
//! or fails cleanly, and the can-match proof terminates.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_rules::analysis::{ORDINARY_ALPHABET, build_regex, can_match};
use picket_rules::goregex::translate;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if text.len() > 512 {
        return;
    }
    if let Ok(re) = translate(text) {
        if let Ok(r) = build_regex(&re) {
            let _ = r.is_match("ads.example.com");
        }
        let _ = can_match(&re, ORDINARY_ALPHABET);
    }
});
