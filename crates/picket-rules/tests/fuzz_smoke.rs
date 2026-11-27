//! A deterministic, in-process smoke run of the fuzz targets' properties (fuzz/rules), so CI
//! without nightly still feeds mutated untrusted input through every parser: no panic, stored
//! rules round-trip, counts stay consistent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

use jiff::Timestamp;
use picket_rules::classify::{Item, Line, classify_adblock_line};
use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};
use picket_rules::goregex::translate;
use picket_rules::matcher::{BundleAction, BundleMatcher};
use picket_rules::misp::parse_misp;
use picket_rules::{QueryCtx, Rule};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const ALPHABET: &[u8] = b"|^*$@#!~,=/.:-_[](){}\\?+%'\" \tabcxyz0129AZ\xc3\xa9";

fn mutate(rng: &mut Rng, seed: &str) -> Vec<u8> {
    let mut b = seed.as_bytes().to_vec();
    for _ in 0..rng.below(6) + 1 {
        match rng.below(4) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            1 => {
                let i = rng.below(b.len() + 1);
                b.insert(i, ALPHABET[rng.below(ALPHABET.len())]);
            }
            2 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = ALPHABET[rng.below(ALPHABET.len())];
            }
            _ => {
                let i = rng.below(b.len() + 1);
                let j = rng.below(b.len() + 1);
                let (lo, hi) = (i.min(j), i.max(j));
                let piece: Vec<u8> = b[lo..hi].to_vec();
                b.extend_from_slice(&piece);
            }
        }
    }
    b
}

fn seeds() -> Vec<String> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/rules/");
    let mut out = Vec::new();
    for f in [
        "easylist-sample.txt",
        "adguard-dns-sample.txt",
        "protocol-port.txt",
        "hagezi-hosts-sample.txt",
        "plain-mixed.txt",
    ] {
        let text = std::fs::read_to_string(format!("{dir}{f}")).unwrap();
        out.extend(text.lines().map(String::from));
    }
    out.extend(
        [
            "||a.example^$dnsrewrite=NOERROR;HTTPS;1 . alpn=h2",
            "||a.example^$client='x\\'y'|~1.2.3.0/24,ctag=a|~b",
            "/^(?i)a\\Qb.c\\E[[:alpha:]]{2,3}$/",
            "||1.2.3.4^$badfilter,dnstype=A",
            "@@||a.example^$dnsrewrite,important",
        ]
        .map(String::from),
    );
    out
}

#[test]
fn mutated_lines() {
    let seeds = seeds();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut all_rules: Vec<Rule> = Vec::new();
    for round in 0..4000 {
        let seed = &seeds[round % seeds.len()];
        let bytes = mutate(&mut rng, seed);
        let text = String::from_utf8_lossy(&bytes);
        for cond in [false, true] {
            let Line::Items(items) = classify_adblock_line(&text, cond) else {
                continue;
            };
            for item in items {
                let Item::Rule(rule) = item else { continue };
                let back = Rule::from_stored(
                    rule.rule_type.as_str(),
                    rule.kind.as_str(),
                    &rule.key,
                    rule.flags.bits(),
                    &rule.value_json(),
                )
                .unwrap_or_else(|e| panic!("{text:?}: {e}"));
                assert_eq!(back, rule, "{text:?}");
                let _ = (rule.fold(), rule.pattern_spec(), rule.ip_spec());
                if all_rules.len() < 400 {
                    all_rules.push(rule);
                }
            }
        }
        let _ = translate(&text);
    }
    let ctx = QueryCtx {
        qtype: 1,
        ..QueryCtx::default()
    };
    for action in [BundleAction::Block, BundleAction::Allow, BundleAction::Scope] {
        let m = BundleMatcher::new(action, all_rules.clone());
        for _ in 0..300 {
            let name: Vec<Vec<u8>> = (0..rng.below(5) + 1)
                .map(|_| {
                    (0..rng.below(8) + 1)
                        .map(|_| ALPHABET[rng.below(ALPHABET.len())])
                        .collect()
                })
                .collect();
            let labels: Vec<&[u8]> = name.iter().map(Vec::as_slice).collect();
            let _ = m.match_name(&labels, &ctx);
        }
        for key in [
            "example.com",
            "a.b.example.org",
            "1.2.3.4",
            "xn--e1afmkfd.xn--p1ai",
        ] {
            let _ = m.match_key_any(&picket_rules::RuleName::parse(key).unwrap());
        }
        for ip in ["1.2.3.4", "10.1.1.1", "::1", "::ffff:1.2.3.4", "2001:db8::1"] {
            let _ = m.match_ip(ip.parse().unwrap(), &ctx);
        }
    }
    let feeds: Vec<usize> = (0..all_rules.len()).map(|i| i % 3).collect();
    let _ = picket_rules::badfilter::cross_feed_cancellations(&all_rules, &feeds);
}

/// Every entry a parser emits reads back from its stored identity (storage.md §3).
fn assert_round_trips(e: &picket_rules::Entry) {
    let r = &e.rule;
    let back = Rule::from_stored(
        r.rule_type.as_str(),
        r.kind.as_str(),
        &r.key,
        r.flags.bits(),
        &r.value_json(),
    )
    .unwrap_or_else(|err| panic!("{:?}: {err}", e.raw));
    assert_eq!(&back, r, "{:?}", e.raw);
}

#[test]
fn mutated_feeds_and_misp() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let base = seeds().join("\n");
    for _ in 0..200 {
        let bytes = mutate(&mut rng, &base);
        for format in [Format::Adblock, Format::Hosts, Format::Plain] {
            let cfg = ParseConfig {
                max_line_len: 256,
                ..ParseConfig::new(format, DomainsAs::Exact, Timestamp::now())
            };
            let mut n = 0u64;
            let s = parse_lines(bytes.as_slice(), &cfg, |e| {
                assert_round_trips(&e);
                n += 1;
            })
            .unwrap();
            assert_eq!(s.entries.total(), n);
        }
    }
    let json = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/misp-list.json"
    ))
    .unwrap();
    for _ in 0..2000 {
        let bytes = mutate(&mut rng, &json);
        let cfg = ParseConfig {
            max_line_len: 64,
            ..ParseConfig::new(Format::MispWarninglist, DomainsAs::Exact, Timestamp::now())
        };
        let _ = parse_misp(
            || Ok(bytes.as_slice()),
            &cfg,
            |e| {
                assert!(e.raw.len() <= 64);
                assert_round_trips(&e);
            },
        );
    }
}
