//! `rich.json` parts are untrusted on the edge (core as seen by the edge; README §2): the
//! `$denyallow` entity table and rich rules, linked as the edge links them (review round 2, CC4),
//! never panic, stay within the table's bounds, and a rule left unlinked never applies as a block.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_rules::entity::{EntityTable, MAX_ENTITIES_PER_BUNDLE, MAX_EXPANSION_RULES};
use picket_rules::modifiers::{NameSemantics, QueryCtx};
use picket_rules::rule::RichRule;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (table, rules) = text.split_once('\n').unwrap_or((text, "[]"));
    let table: EntityTable = serde_json::from_str(table).unwrap_or_default();
    assert!(table.len() <= MAX_ENTITIES_PER_BUNDLE);
    let Ok(mut rules) = serde_json::from_str::<Vec<RichRule>>(rules) else {
        return;
    };
    let ctx = QueryCtx {
        qtype: 1,
        ..QueryCtx::default()
    };
    let names: [&[&[u8]]; 3] = [
        &[b"tracker", b"co", b"uk"],
        &[b"a", b"example", b"com"],
        &[b"x!y", b"de"],
    ];
    for r in rules.iter_mut() {
        let linked = table.link(r);
        for e in &r.denyallow_entities {
            assert!(e.len() <= MAX_EXPANSION_RULES);
        }
        for labels in names {
            let text: Vec<String> = labels
                .iter()
                .map(|l| String::from_utf8_lossy(l).into_owned())
                .collect();
            let text = text.join(".");
            let hit = r.conditions_match(labels, &text, &ctx, NameSemantics::Labels);
            let _ = r.conditions_match_any_query(labels, &text, NameSemantics::Text);
            if !linked && r.has_unexpanded_entity() && hit {
                // Only an exception, or a rule whose unexpanded entities are its suppressors'.
                assert!(
                    r.flags.intersects(picket_rules::Flags::ALL_ALLOW)
                        || r.denyallow_entities.iter().all(|e| e.is_expanded())
                );
            }
        }
    }
});
