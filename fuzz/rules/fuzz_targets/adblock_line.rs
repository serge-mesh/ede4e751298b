//! One adblock line: classification, the storage round trip of every rule it yields, and every
//! view the compiler takes of it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_rules::classify::{Item, Line, classify_adblock_line};
use picket_rules::{Rule, compile, policy};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if text.len() > 4096 {
        return;
    }
    for cond in [false, true] {
        let Line::Items(items) = classify_adblock_line(text, cond) else {
            continue;
        };
        for item in items {
            let Item::Rule(rule) = item else { continue };
            let json = rule.value_json();
            let back = Rule::from_stored(
                rule.rule_type.as_str(),
                rule.kind.as_str(),
                &rule.key,
                rule.flags.bits(),
                &json,
            )
            .expect("a parsed rule rebuilds from its columns");
            assert_eq!(back, rule);
            let _ = rule.fold();
            let _ = rule.pattern_spec();
            let _ = rule.ip_spec();
            let _ = policy::covering(&rule);
            let _ = compile::can_match_ip_text(&rule);
        }
    }
});
