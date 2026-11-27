//! JSON Pointer (RFC 6901) parsing and evaluation: never panics, and agrees with serde_json's
//! own pointer wherever the pointer is well formed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_lookup::modules::http_json::JsonPointer;
use picket_lookup_fuzz::split;

fuzz_target!(|data: &[u8]| {
    let (ptr, doc) = split(data);
    let Ok(text) = std::str::from_utf8(ptr) else {
        return;
    };
    let Ok(p) = JsonPointer::parse(text) else {
        return;
    };
    assert_eq!(p.as_str(), text);
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(doc) else {
        return;
    };
    assert_eq!(p.resolve(&doc), doc.pointer(text), "{text:?}");
});
