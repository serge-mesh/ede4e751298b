//! `block_if` / `clean_if` comparison parsing and matching: never panics, a parsed comparison
//! reads back from its own display, and a value of another type never matches.

#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_lookup::modules::http_json::Comparison;
use serde_json::{Value, json};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(c) = Comparison::parse(text) else {
        return;
    };
    for v in [
        json!(0),
        json!(-7.5),
        json!(1e300),
        json!("malicious"),
        json!(true),
        json!(null),
        json!([1]),
        json!({"a": 1}),
    ] {
        let _ = c.matches(&v);
    }
    assert!(!c.matches(&Value::Null));
    assert!(!c.matches(&json!([1])));
    let shown = c.to_string();
    if shown.len() <= 64 {
        assert_eq!(Comparison::parse(&shown).as_ref(), Ok(&c), "{shown}");
    }
});
