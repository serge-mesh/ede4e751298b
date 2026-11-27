//! Parity (build-and-test.md §5 "AdGuard parity", "Bundles"; bundles.md §6): rules compiled with
//! the writer, loaded with the reader and matched by [`picket_bundle::Bundle`] decide exactly as
//! picket-rules' reference [`picket_rules::matcher::BundleMatcher`], for every group of
//! `fixtures/rules/parity-corpus.txt`, for randomized rule sets, and for urlfilter's recorded
//! decisions in `fixtures/rules/urlfilter-expectations.tsv`. Each case runs all hot in one shard,
//! and again with plain blocks spread over hot and cold parts in many small shards, so the cold
//! stage, sharding and pruning across parts are exercised too.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::collections::HashMap;
use std::net::IpAddr;

use common::*;
use picket_rules::matcher::BundleAction;

fn corpus_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn corpus_query(target: &str, is_ip: bool, opts: &[String]) -> Query {
    let mut q = if is_ip {
        Query::ip(target.parse().unwrap())
    } else {
        Query::name(target)
    };
    for o in opts {
        let (k, v) = o.split_once('=').unwrap();
        match k {
            "qtype" => q.qtype = picket_rules::rrtype::parse_rr_type(v).unwrap(),
            "ip" => q.client_ip = Some(v.parse().unwrap()),
            "client" => q.client_name = Some(v.to_string()),
            "tags" => q.tags = v.split(',').map(String::from).collect(),
            _ => {}
        }
    }
    q
}

struct Group {
    title: String,
    rules: Vec<String>,
    queries: Vec<Query>,
}

fn corpus() -> Vec<Group> {
    let text = std::fs::read_to_string(format!("{FIXTURES}/rules/parity-corpus.txt")).unwrap();
    let mut out: Vec<Group> = Vec::new();
    for raw in text.lines() {
        if raw.trim().is_empty() || raw.starts_with('#') {
            continue;
        }
        if let Some(t) = raw.strip_prefix("= ") {
            out.push(Group {
                title: t.to_string(),
                rules: vec![],
                queries: vec![],
            });
            continue;
        }
        if let Some(m) = raw.strip_prefix("m ") {
            let parts: Vec<&str> = m.split(" ~~").collect();
            let mut g = Group {
                title: format!("matrix {}", parts[0].trim()),
                rules: vec![parts[0].trim().to_string()],
                queries: vec![],
            };
            for names in &parts[1..] {
                for t in names.split_whitespace() {
                    let is_ip = t.parse::<IpAddr>().is_ok();
                    g.queries.push(corpus_query(t, is_ip, &[]));
                }
            }
            out.push(g);
            continue;
        }
        let g = out.last_mut().unwrap();
        if let Some(r) = raw.strip_prefix("r ") {
            g.rules.push(r.to_string());
            continue;
        }
        let (is_ip, rest) = match (raw.strip_prefix("e "), raw.strip_prefix("i ")) {
            (Some(r), _) => (false, r),
            (_, Some(r)) => (true, r),
            _ => panic!("unknown corpus line {raw:?}"),
        };
        let toks = corpus_tokens(rest);
        g.queries.push(corpus_query(&toks[0], is_ip, &toks[2..]));
    }
    out
}

/// More names around each query name: its parent, a child, and the name under another type.
fn widen(queries: &[Query]) -> Vec<Query> {
    let mut out = queries.to_vec();
    for q in queries {
        if let Target::Name(l) = &q.target {
            if l.len() > 1 {
                let mut p = q.clone();
                p.target = Target::Name(l[1..].to_vec());
                out.push(p);
            }
            let mut c = q.clone();
            let mut ll = vec![b"zz".to_vec()];
            ll.extend(l.iter().cloned());
            c.target = Target::Name(ll);
            out.push(c);
            let mut t = q.clone();
            t.qtype = if q.qtype == 28 { 1 } else { 28 };
            out.push(t);
        }
    }
    out
}

/// What the cases exercised, so a test that silently matches nothing fails.
#[derive(Default, Debug)]
struct Coverage {
    decisions: std::collections::BTreeMap<String, usize>,
    cold_matches: usize,
    multi_shard: usize,
    cold_parts: usize,
    ip_shards: usize,
    patterns: usize,
}

impl Coverage {
    fn kind(&self, word: &str) -> usize {
        self.decisions
            .iter()
            .filter(|(k, _)| k.as_str() == word)
            .map(|(_, v)| v)
            .sum()
    }
}

thread_local! {
    static COVERAGE: std::cell::RefCell<Coverage> = std::cell::RefCell::new(Coverage::default());
}

fn take_coverage() -> Coverage {
    COVERAGE.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

fn check_case(
    title: &str,
    action: BundleAction,
    rules: &[String],
    queries: &[Query],
    failures: &mut Vec<String>,
) {
    let parsed = parse_rules(rules);
    let reference = reference(action, parsed.clone());
    for (tiering, cap) in [
        (Tiering::AllHot, 0u64),
        (Tiering::Mixed, 1),
        (Tiering::AllCold, 3),
    ] {
        let loaded = compile_and_load(action, &parsed, cap, tiering);
        COVERAGE.with(|c| {
            let mut c = c.borrow_mut();
            c.multi_shard += usize::from(loaded.built.head.shards.len() > 1);
            c.cold_parts += usize::from(!loaded.built.head.cold_shards.is_empty());
            c.ip_shards += loaded.built.head.ip_shards.len();
            c.patterns += loaded.bundle.patterns().patterns.len();
        });
        for q in queries {
            let want = decision(&reference_outcome(&reference, q));
            let d = compiled_decision(&loaded, q);
            let got = decision(&d.outcome);
            COVERAGE.with(|c| {
                let mut c = c.borrow_mut();
                *c.decisions
                    .entry(got.split(' ').next().unwrap_or("").to_string())
                    .or_default() += 1;
                c.cold_matches += usize::from(d.cold == picket_bundle::ColdCheck::Matched);
            });
            if want != got {
                failures.push(format!(
                    "[{title}] {action:?} {tiering:?} rules={rules:?} query={:?} qtype={} client={:?}/{:?} tags={:?}: compiled={got} reference={want}",
                    q.target, q.qtype, q.client_ip, q.client_name, q.tags
                ));
            }
        }
    }
}

#[test]
fn parity_corpus() {
    let groups = corpus();
    assert!(groups.len() > 50, "corpus too small: {}", groups.len());
    let mut failures = Vec::new();
    let mut n = 0usize;
    for g in &groups {
        let qs = widen(&g.queries);
        n += qs.len();
        check_case(&g.title, BundleAction::Block, &g.rules, &qs, &mut failures);
    }
    assert!(n > 1000, "too few queries: {n}");
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
    let c = take_coverage();
    eprintln!("corpus coverage: {c:?}");
    for k in ["block", "allow", "none", "rewrite", "hosts"] {
        assert!(c.kind(k) > 10, "too few {k} decisions: {c:?}");
    }
    assert!(
        c.cold_matches > 50 && c.multi_shard > 10 && c.cold_parts > 30 && c.ip_shards > 10 && c.patterns > 50,
        "{c:?}"
    );
}

#[test]
fn parity_corpus_allow_and_scope() {
    let mut failures = Vec::new();
    for g in corpus() {
        for action in [BundleAction::Allow, BundleAction::Scope] {
            check_case(&g.title, action, &g.rules, &g.queries, &mut failures);
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
    // Both sides of each comparison: matches and misses, so a lookup answering `none` for a match
    // (or a match for a miss) fails above.
    let c = take_coverage();
    for k in ["allowed", "in-scope", "none"] {
        assert!(c.kind(k) > 100, "too few {k} decisions: {c:?}");
    }
}

const DOMAINS: &[&str] = &[
    "example.com",
    "ads.example.com",
    "a.ads.example.com",
    "example.net",
    "tracker.co.uk",
    "x.tracker.net",
    "evil.example",
];

const FORMS: &[&str] = &[
    "||D^",
    "|D^",
    "@@||D^",
    "@@|D^",
    "||D^$important",
    "@@||D^$important",
    "|D^$important",
    "*.D^",
    ".D^",
    "@@*.D^",
    "D",
    "0.0.0.0 D",
    "192.0.2.1 D",
    "2001:db8::7 D",
    "||D^$dnstype=AAAA",
    "||D^$dnstype=~A",
    "@@||D^$dnstype=AAAA",
    "||D^$client=192.168.1.0/24",
    "||D^$client=kid",
    "@@||D^$client=~kid",
    "||D^$ctag=device_phone",
    "||D^$denyallow=E",
    "||D^$denyallow=tracker.*",
    "||D^$dnsrewrite=1.2.3.4",
    "||D^$dnsrewrite=1.2.3.5",
    "||D^$dnsrewrite=NXDOMAIN;;",
    "||D^$dnsrewrite=cname.example",
    "||D^$dnsrewrite=D",
    "@@||D^$dnsrewrite",
    "@@||D^$dnsrewrite=1.2.3.4",
    "||D^$important,dnsrewrite=::1",
    "||D^$badfilter",
    "@@||D^$badfilter",
    "||D^$important,badfilter",
    "||D^$dnstype=AAAA,badfilter",
    "https://D",
    "||D:8443^",
];

const PATTERNS: &[&str] = &[
    "||ads*^",
    "/^ad[0-9a-z]*\\./",
    "*tracker*",
    "||ex*le.com^",
    "/example\\.(com|net)$/",
    "@@/^a\\./",
    "||*^$dnstype=AAAA",
    "*$denyallow=example.net|tracker.co.uk",
    "/[!]/",
    "-ad-",
    "||ads*^$dnsrewrite=9.9.9.9",
    "@@||ads*^$important",
    "/^10\\./",
    "||*.example^",
];

const IP_RULES: &[&str] = &[
    "||1.2.3.4^",
    "|1.2.3.5^",
    "@@||1.2.3.4^",
    "||1.2.3.4^$important",
    "||10.0.0^",
    "||1.2.3.4^$dnsrewrite=5.6.7.8",
    "||1.2.3.4^$dnstype=AAAA",
    "0.0.0.0 1.2.3.6",
    "||2001:db8::1^",
    "@@||10.0.0.1^",
];

const NAMES: &[&str] = &[
    "example.com",
    "www.example.com",
    "ads.example.com",
    "a.ads.example.com",
    "b.a.ads.example.com",
    "example.net",
    "ads1.example.net",
    "ad7.example.org",
    "tracker.co.uk",
    "x.tracker.co.uk",
    "x.tracker.net",
    "mytracker.org",
    "evil.example",
    "a.evil.example",
    "exammple.com",
    "1.2.3.4",
    "a.1.2.3.4",
    "my-ad-server.com",
];

const IPS: &[&str] = &[
    "1.2.3.4",
    "1.2.3.5",
    "1.2.3.6",
    "10.0.0.1",
    "10.0.0.2",
    "1.10.0.0",
    "::ffff:1.2.3.4",
    "2001:db8::1",
    "2001:db8::2",
];

fn random_rules(rng: &mut Rng) -> Vec<String> {
    let n = 1 + rng.below(10);
    (0..n)
        .map(|_| match rng.below(10) {
            0..=5 => {
                let d = rng.pick(DOMAINS);
                let e = rng.pick(DOMAINS);
                rng.pick(FORMS).replace('D', d).replace('E', e)
            }
            6..=7 => rng.pick(PATTERNS).to_string(),
            _ => rng.pick(IP_RULES).to_string(),
        })
        .collect()
}

fn random_queries(rng: &mut Rng) -> Vec<Query> {
    let mut out = Vec::new();
    for n in NAMES {
        let mut q = Query::name(n);
        match rng.below(4) {
            0 => {}
            1 => q.qtype = 28,
            2 => {
                q.client_ip = Some("192.168.1.7".parse().unwrap());
                q.client_name = Some("kid".into());
            }
            _ => {
                q.qtype = 65;
                q.tags = vec!["device_phone".into()];
            }
        }
        out.push(q);
    }
    // Names with unusual bytes (rules.md §3).
    let mut q = Query::name("x");
    q.target = Target::Name(vec![b"a.b".to_vec(), b"evil".to_vec(), b"example".to_vec()]);
    out.push(q.clone());
    q.target = Target::Name(vec![
        b"a!b".to_vec(),
        b"ads".to_vec(),
        b"example".to_vec(),
        b"com".to_vec(),
    ]);
    out.push(q.clone());
    q.target = Target::Name(vec![b"x".to_vec(), b"example.com".to_vec()]);
    out.push(q);
    for ip in IPS {
        let mut q = Query::ip(ip.parse().unwrap());
        if rng.below(2) == 1 {
            q.qtype = 28;
        }
        out.push(q);
    }
    out
}

#[test]
fn parity_randomized() {
    let mut rng = Rng(0x5eed_2026_1121);
    let mut failures = Vec::new();
    for i in 0..300 {
        let rules = random_rules(&mut rng);
        let queries = random_queries(&mut rng);
        let action = match i % 10 {
            8 => BundleAction::Allow,
            9 => BundleAction::Scope,
            _ => BundleAction::Block,
        };
        check_case(&format!("random {i}"), action, &rules, &queries, &mut failures);
        if failures.len() > 40 {
            break;
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
    let c = take_coverage();
    eprintln!("random coverage: {c:?}");
    for k in [
        "block", "allow", "none", "rewrite", "hosts", "allowed", "in-scope",
    ] {
        assert!(c.kind(k) > 50, "too few {k} decisions: {c:?}");
    }
    assert!(
        c.cold_matches > 100 && c.multi_shard > 100 && c.ip_shards > 100 && c.patterns > 100,
        "{c:?}"
    );
}

#[test]
fn urlfilter_expectations_replay() {
    let text = std::fs::read_to_string(format!("{FIXTURES}/rules/urlfilter-expectations.tsv")).unwrap();
    let mut cache: HashMap<String, Loaded> = HashMap::new();
    let mut rows = 0usize;
    let mut failures = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        let [rules, host, qtype, ip, name, tags, expected] = f.as_slice() else {
            panic!("bad row {line}")
        };
        let loaded = cache.entry(rules.to_string()).or_insert_with(|| {
            let lines: Vec<String> = rules.split(" ⏎ ").map(String::from).collect();
            compile_and_load(BundleAction::Block, &parse_rules(&lines), 0, Tiering::Mixed)
        });
        let target = if let Some(n) = host.strip_prefix("name:") {
            Target::Name(picket_api::names::decode_labels(n).unwrap())
        } else {
            Target::Ip(host.strip_prefix("ip:").unwrap().parse().unwrap())
        };
        let q = Query {
            target,
            qtype: qtype.parse().unwrap(),
            client_ip: (*ip != "-").then(|| ip.parse().unwrap()),
            client_name: (*name != "-").then(|| name.to_string()),
            tags: if *tags == "-" {
                vec![]
            } else {
                tags.split(',').map(String::from).collect()
            },
        };
        let got = decision(&compiled_outcome(loaded, &q));
        rows += 1;
        if got != *expected {
            failures.push(format!(
                "{rules} | {host} qtype={qtype}: compiled={got} urlfilter={expected}"
            ));
        }
    }
    assert!(rows > 1000, "table too small: {rows}");
    assert!(
        failures.is_empty(),
        "{} of {rows} rows differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn build_and_test_examples() {
    // build-and-test.md §5 "AdGuard parity" and "Bundles" rows.
    let cases: &[(&[&str], &str, &str)] = &[
        (
            &["||d.example^", "|d.example^$important", "@@||d.example^"],
            "d.example",
            "block",
        ),
        (
            &["||d.example^", "|d.example^$important", "@@||d.example^"],
            "sub.d.example",
            "allow",
        ),
        (
            &["||d.example^$important", "|d.example^", "@@||d.example^"],
            "d.example",
            "block",
        ),
        (
            &["||d.example^$important", "|d.example^", "@@||d.example^"],
            "sub.d.example",
            "block",
        ),
        (&["192.0.2.10 d.example", "@@||d.example^"], "d.example", "allow"),
        (&["||d.example^", "||sub.d.example^"], "sub.d.example", "block"),
        (&["||sub.d.example^"], "sub.d.example", "block"),
        (
            &[
                "||d.example^",
                "@@|d.example^",
                "||sub.d.example^",
                "@@|sub.d.example^",
            ],
            "sub.d.example",
            "allow",
        ),
    ];
    for (rules, name, want) in cases {
        let rules: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        for tiering in [Tiering::AllHot, Tiering::Mixed, Tiering::AllCold] {
            let l = compile_and_load(BundleAction::Block, &parse_rules(&rules), 0, tiering);
            let got = decision(&compiled_outcome(&l, &Query::name(name)));
            assert_eq!(&got, want, "{rules:?} {name} {tiering:?}");
        }
    }
}
