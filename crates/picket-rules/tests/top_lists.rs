//! AdGuard parity on the top lists (build-and-test.md §5 "AdGuard parity": ≥ 99.99 % agreement
//! with urlfilter "on the top lists"; rules.md §3; review round 1, R16): the real AdGuard DNS
//! filter, EasyList, HaGeZi Pro and TIF and FireHOL level 1, fetched by
//! `tools/urlfilter-oracle/fetch-top-lists.sh` into a cache directory (`PICKET_TOP_LISTS_DIR`,
//! default `~/.cache/picket/top-lists`), never committed. Each list is one bundle, read as an
//! `adblock` feed (FireHOL too: this measures AdGuard parity of that reading; Picket's preset reads
//! it as `plain`, whose indicators aren't AdGuard rules), checked on names sampled from its own
//! rules (each key, a subdomain of it, a pattern's literal in a name), the corpus names, and
//! answer addresses. Exclusions are urlfilter_parity.rs's.
//!
//! Runs when `PICKET_URLFILTER_ORACLE` is set and a list is present; skipped otherwise.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;

use common::{
    Case, Explained, Group, Query, Target, block_matcher, decision, evaluate, normalise_oracle, parse_rules,
    run_oracle,
};
use picket_rules::Kind;

const LISTS: &[&str] = &[
    "adguard-dns.txt",
    "easylist.txt",
    "hagezi-pro.txt",
    "hagezi-tif.txt",
    "firehol-level1.netset",
];

/// Names sampled per list, at most.
const SAMPLE: usize = 6_000;

fn dir() -> PathBuf {
    if let Some(d) = std::env::var_os("PICKET_TOP_LISTS_DIR") {
        return PathBuf::from(d);
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("."));
    cache.join("picket").join("top-lists")
}

fn dotted(n: &str) -> Vec<Vec<u8>> {
    n.split('.').map(|l| l.as_bytes().to_vec()).collect()
}

/// Names a list's own rules reach: each sampled key, a name below it, and a name around a
/// pattern's literal; plus the corpus names.
fn names_for(lines: &[String]) -> Vec<Vec<Vec<u8>>> {
    let rules = parse_rules(lines);
    let mut set: BTreeSet<String> = BTreeSet::new();
    let keyed: Vec<_> = rules.iter().filter_map(|r| r.name()).collect();
    let step = (keyed.len() / (SAMPLE / 2)).max(1);
    for n in keyed.iter().step_by(step) {
        set.insert(n.as_str().to_string());
        set.insert(format!("x.{}", n.as_str()));
    }
    let patterns: Vec<_> = rules
        .iter()
        .filter(|r| matches!(r.kind, Kind::Pattern | Kind::Regex))
        .filter_map(|r| r.pattern_spec()?.shortcut)
        .collect();
    let step = (patterns.len() / 1_000).max(1);
    for s in patterns.iter().step_by(step) {
        let lit: String = s
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect();
        let lit = lit.trim_matches('.');
        if !lit.is_empty() && !lit.contains("..") && lit.len() < 200 {
            set.insert(format!("{lit}.example.com"));
            set.insert(format!("a.{lit}"));
        }
    }
    set.extend(common::ORDINARY_NAMES.iter().map(|n| n.to_string()));
    let mut out: Vec<Vec<Vec<u8>>> = set.iter().map(|n| dotted(n)).collect();
    out.extend(common::unusual_names());
    out
}

/// Addresses: the corpus's, plus each sampled IP or range start of the list.
fn ips_for(lines: &[String]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = common::IP_CHECKS.iter().map(|s| s.parse().unwrap()).collect();
    let found: Vec<IpAddr> = lines
        .iter()
        .filter_map(|l| {
            let t = l.trim().trim_start_matches("||").trim_end_matches('^');
            let t = t.split('/').next()?;
            t.parse::<IpAddr>().ok()
        })
        .collect();
    let step = (found.len() / 2_000).max(1);
    out.extend(found.iter().step_by(step).copied());
    out
}

fn queries(names: &[Vec<Vec<u8>>], ips: &[IpAddr]) -> Vec<Query> {
    let mut out = Vec::new();
    for n in names {
        out.push(Query {
            target: Target::Name(n.clone()),
            qtype: 1,
            client_ip: None,
            client_name: None,
            tags: vec![],
        });
        out.push(Query {
            target: Target::Name(n.clone()),
            qtype: 28,
            client_ip: Some("192.168.1.5".parse().unwrap()),
            client_name: Some("kid".into()),
            tags: vec!["device_phone".into()],
        });
    }
    for ip in ips {
        out.push(Query {
            target: Target::Ip(*ip),
            qtype: if ip.is_ipv4() { 1 } else { 28 },
            client_ip: None,
            client_name: None,
            tags: vec![],
        });
    }
    out
}

#[test]
fn top_lists_differential() {
    let Ok(bin) = std::env::var("PICKET_URLFILTER_ORACLE") else {
        eprintln!("skipped: set PICKET_URLFILTER_ORACLE (see PARITY.md)");
        return;
    };
    let d = dir();
    let mut report = String::new();
    let mut failures = Vec::new();
    let mut ran = 0usize;
    for list in LISTS {
        let Ok(text) = std::fs::read_to_string(d.join(list)) else {
            let _ = writeln!(report, "[{list}] not present in {} (skipped)", d.display());
            continue;
        };
        ran += 1;
        let lines: Vec<String> = text.lines().map(String::from).collect();
        let names = names_for(&lines);
        let ips = ips_for(&lines);
        let case = Case {
            id: format!("top-{list}"),
            group: Group::Main,
            rules: lines.clone(),
            queries: queries(&names, &ips),
        };
        let cases = vec![case];
        let oracle = run_oracle(&bin, &cases);
        let case = &cases[0];
        let m = block_matcher(parse_rules(&case.rules));
        let alt = common::Alternatives::new(&case.rules);
        let mut tally: BTreeMap<&str, u64> = BTreeMap::new();
        let mut examples: Vec<String> = Vec::new();
        for (qi, q) in case.queries.iter().enumerate() {
            let ours = decision(&evaluate(&m, q).outcome);
            let theirs = normalise_oracle(&oracle[0][qi]);
            let class = if ours == theirs {
                if theirs == "none" {
                    "agree (none)"
                } else {
                    "agree (decided)"
                }
            } else {
                match alt.explain(q, &theirs) {
                    Explained::Extension => "excluded: protocol/port extension",
                    Explained::UnusualBytes => "excluded: unusual bytes",
                    Explained::PathNames => "owner decision: path rules × `/` names (R10)",
                    Explained::No => {
                        examples.push(format!(
                            "{} qtype={}: picket={ours} adguard={theirs}",
                            q.host_text(),
                            q.qtype
                        ));
                        "disagree"
                    }
                }
            };
            *tally.entry(class).or_default() += 1;
        }
        let agree = tally.get("agree (none)").copied().unwrap_or(0)
            + tally.get("agree (decided)").copied().unwrap_or(0);
        let total = agree + tally.get("disagree").copied().unwrap_or(0);
        let pct = agree as f64 * 100.0 / total.max(1) as f64;
        let _ = writeln!(
            report,
            "[{list}] {} rules, {} queries: {agree}/{total} agree ({pct:.4} %); {tally:?}",
            lines.len(),
            case.queries.len()
        );
        for e in examples.iter().take(20) {
            let _ = writeln!(report, "    {e}");
        }
        if pct < 99.99 {
            failures.push(format!("{list}: {pct:.4} %"));
        }
    }
    eprintln!("{report}");
    let _ = std::fs::write(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("top-lists-report.txt"),
        &report,
    );
    if ran == 0 {
        eprintln!(
            "skipped: no top lists in {} (run tools/urlfilter-oracle/fetch-top-lists.sh)",
            d.display()
        );
    }
    assert!(failures.is_empty(), "below 99.99 %: {failures:?}\n{report}");
}
