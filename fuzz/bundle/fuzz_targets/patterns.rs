//! patterns.bin: load (DFAs validated by the safe constructor, budget admission), then match.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_bundle::patterns::PatternSegment;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    let Ok(seg) = PatternSegment::from_bytes(data, 8 * 1024 * 1024) else {
        return;
    };
    for text in [
        "ads.example.com",
        "a\\!b.example",
        "1.2.3.4",
        "",
        "banner12.example",
    ] {
        let url = format!("http://{text}");
        seg.for_each_match(text.as_bytes(), url.as_bytes(), |_, p| {
            let _ = p.source();
        });
    }
});
