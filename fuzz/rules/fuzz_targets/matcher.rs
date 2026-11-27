//! The reference matcher: rules from the first lines, then a name of arbitrary labels and an
//! address; nothing panics and outcomes are consistent with roles (entities and urlfilter's rule
//! order included).
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_rules::QueryCtx;
use picket_rules::classify::{Item, Line, classify_adblock_line};
use picket_rules::matcher::{BundleAction, BundleMatcher, Outcome, Role};

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let (rules_part, name_part) = data.split_at(split);
    let Ok(text) = std::str::from_utf8(rules_part) else {
        return;
    };
    let rules: Vec<_> = text
        .lines()
        .take(16)
        .flat_map(|l| match classify_adblock_line(l, false) {
            Line::Items(v) => v
                .into_iter()
                .filter_map(|i| if let Item::Rule(r) = i { Some(r) } else { None })
                .collect(),
            Line::Skipped => Vec::new(),
        })
        .collect();
    let labels: Vec<&[u8]> = name_part
        .get(1..)
        .unwrap_or(&[])
        .split(|&b| b == 0xff)
        .filter(|l| !l.is_empty() && l.len() <= 63)
        .take(16)
        .collect();
    let ctx = QueryCtx {
        qtype: 1,
        ..QueryCtx::default()
    };
    // A small public suffix list, so `$denyallow` entities (`x.*`) are expanded and matched too.
    let psl = picket_rules::psl::PublicSuffixList::parse(
        "// ===BEGIN ICANN DOMAINS===\ncom\nco.uk\nuk\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n// ===END PRIVATE DOMAINS===\n",
    );
    for action in [BundleAction::Block, BundleAction::Allow, BundleAction::Scope] {
        let m = BundleMatcher::new(action, rules.clone()).with_public_suffix_list(&psl);
        let r = m.match_name(&labels, &ctx);
        if !matches!(r.outcome, Outcome::None | Outcome::Exception) {
            assert!(r.matches.iter().any(|x| x.role == Role::Decisive));
        }
        // Every cancelled match names the rule that cancelled it.
        assert!(
            r.matches
                .iter()
                .all(|x| !matches!(x.role, Role::Overridden(_)) || x.by.is_some())
        );
        let dotted: Vec<String> = labels
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect();
        if let Ok(key) = picket_rules::RuleName::parse(&dotted.join(".")) {
            let _ = m.match_key_any(&key);
        }
        let ip = std::net::IpAddr::from([1, 2, 3, *name_part.first().unwrap_or(&4)]);
        let _ = m.match_ip(ip, &ctx);
    }
});
