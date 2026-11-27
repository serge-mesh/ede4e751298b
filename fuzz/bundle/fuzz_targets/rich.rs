//! rich.json: parse, bound, link entities (counting unlinked rules); seed an incremental builder.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_bundle::rich::{RichBuilder, RichSegment};
use picket_rules::QueryCtx;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    let Ok(seg) = RichSegment::from_bytes(data) else {
        return;
    };
    let labels: [&[u8]; 3] = [b"a", b"tracker", b"com"];
    for s in 0..seg.set_count().min(64) as u32 {
        for &r in seg.set(s) {
            if let Some(rule) = seg.rule(r) {
                let _ = rule.conditions_match(&labels, "a.tracker.com", &QueryCtx::default(), picket_rules::modifiers::NameSemantics::Labels);
            }
        }
    }
    let _ = RichBuilder::from_previous(data).map(|b| b.to_bytes());
});
