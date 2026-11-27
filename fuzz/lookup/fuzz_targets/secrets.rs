//! `${secret:name}` resolution and redaction on arbitrary configs and text: never panics, and a
//! secret value a config used never survives redaction, as written or JSON-escaped (one value
//! holds `"` and `\`), nor, for a value shorter than `MIN_SUBSTRING_SECRET`, as a whole token.

#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use picket_lookup::secrets::{MIN_SUBSTRING_SECRET, referenced_names, resolve, with_placeholders};
use picket_lookup_fuzz::split;

const VALUES: [(&str, &str); 5] = [
    ("k1", "s3cr3tValue1"),
    ("api_key", "AnotherKey/22=="),
    ("x", "tok_9f8e7d6c"),
    ("q", "quo\"te\\Val"),
    ("short", "ab1"),
];

/// Whether `v` stands in `text` as a whole token (not next to a letter, digit, `-` or `_`).
fn has_token(text: &str, v: &str) -> bool {
    let token = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    let bytes = text.as_bytes();
    text.match_indices(v).any(|(i, _)| {
        let before = i.checked_sub(1).and_then(|j| bytes.get(j)).copied();
        let after = bytes.get(i + v.len()).copied();
        !before.is_some_and(token) && !after.is_some_and(token)
    })
}

fuzz_target!(|data: &[u8]| {
    let (cfg, text) = split(data);
    let Ok(cfg) = serde_json::from_slice::<serde_json::Value>(cfg) else {
        return;
    };
    let secrets: BTreeMap<String, String> = VALUES
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let _ = referenced_names(&cfg);
    let _ = with_placeholders(&cfg);
    let Ok(resolved) = resolve(&cfg, &secrets) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(text) else {
        return;
    };
    let names = referenced_names(&cfg).unwrap();
    let out = resolved.redactor.redact(text);
    for (k, v) in VALUES {
        if !names.iter().any(|n| n == k) {
            continue;
        }
        if v.len() < MIN_SUBSTRING_SECRET {
            assert!(!has_token(&out, v), "{k} survived redaction");
            continue;
        }
        let json = serde_json::to_string(v).unwrap();
        for form in [v, json.trim_matches('"')] {
            assert!(!out.contains(form), "{k} survived redaction");
        }
    }
});
