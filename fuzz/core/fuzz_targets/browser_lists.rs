//! Browser lists (bundles.md §8) over untrusted feed rule text: bundle lists (block and allow,
//! with the conversion table and exact cancellation), profile lists with a DNS oracle that blocks
//! names the input picks, the list text, and the `/lists/*` path parser. Never panic; no written
//! line holds a line break; the pruned list never holds more rules than the full one; the indexed
//! exact cancellation finds what the plain scan finds; a list built a step at a time is the list
//! built at once. Up to 4,096 rules, so selector groups grow large enough to exercise the index.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::lists::render::{
    BrowserRule, BundleListBuild, DnsOracle, ProfileListBuild, Source, bundle_list, cancellations,
    cancellations_naive, parse_browser, profile_lists, text,
};

struct Oracle(Vec<String>);

impl DnsOracle for Oracle {
    fn scope_blocked(&mut self, name: &str) -> Option<String> {
        self.0.iter().any(|n| n == name).then(|| "b".to_string())
    }
    fn name_blocked(&mut self, name: &str) -> Option<String> {
        self.0
            .iter()
            .any(|n| name.ends_with(n.as_str()))
            .then(|| "b".to_string())
    }
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let lines: Vec<&str> = s.lines().take(4096).collect();
    let src = |i: usize, l: &str| Source {
        bundle: if i % 3 == 0 { "a".into() } else { "b".into() },
        feed: format!("f{}", i % 2),
        text: l.to_string(),
    };
    let sources: Vec<Source> = lines.iter().enumerate().map(|(i, l)| src(i, l)).collect();
    // The index finds exactly what the plain scan of each group finds.
    let rules: Vec<BrowserRule> = lines.iter().map(|l| parse_browser(l)).collect();
    let scope = |i: usize, j: usize| i % 2 != j % 2;
    assert_eq!(cancellations(&rules, scope), cancellations_naive(&rules, scope));
    assert_eq!(
        cancellations(&rules, |_, _| true),
        cancellations_naive(&rules, |_, _| true)
    );
    for allow in [false, true] {
        let out = bundle_list(allow, &sources);
        let mut b = BundleListBuild::new(allow, sources.clone());
        while !b.step(7) {}
        assert_eq!(b.finish(), out);
        for l in &out.lines {
            assert!(!l.contains('\n'));
        }
        let t = text("Picket x", jiff::Timestamp::now(), &out.lines);
        assert!(t.starts_with("! Title: Picket x\n"));
    }
    let (allow, block): (Vec<Source>, Vec<Source>) = sources.into_iter().partition(|s| s.bundle == "a");
    let blocked: Vec<String> = lines
        .iter()
        .filter_map(|l| {
            l.split(['|', '^', '/', '#', '$'])
                .find(|p| p.contains('.'))
                .map(str::to_string)
        })
        .take(8)
        .collect();
    let out = profile_lists(&allow, &block, &mut Oracle(blocked.clone()));
    assert!(out.pruned.len() <= out.full.len());
    let mut b = ProfileListBuild::new(allow.clone(), block.clone());
    while !b.step(&mut Oracle(blocked.clone()), 13) {}
    assert_eq!(b.finish(), out);
    for l in out.full.iter().chain(out.pruned.iter()) {
        assert!(!l.contains('\n'));
    }
    for l in &lines {
        let _ = picket_core::lists::serve::list_path(l);
    }
});
