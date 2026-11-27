//! Stored feed_entries columns are untrusted on read-back (a restored or edited database):
//! rebuilding a rule from arbitrary columns never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_rules::Rule;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = text.splitn(5, '\n');
    let (Some(t), Some(k), Some(key), Some(flags), Some(json)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return;
    };
    let flags = flags.parse::<u16>().unwrap_or(0);
    if let Ok(rule) = Rule::from_stored(t, k, key, flags, json) {
        let _ = rule.fold();
        let _ = rule.pattern_spec();
        let _ = rule.ip_spec();
        let _ = rule.name();
    }
});
