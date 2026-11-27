//! Response-phase AdGuard parity (build-and-test.md §5 "AdGuard parity": response-phase decisions
//! replayed on recorded upstream answers, compared with AdGuard Home v0.107.80's response filtering;
//! rules.md §3, §5 step 5, §6; review round 1, R16).
//!
//! Each case's bundle decides each recorded answer (`fixtures/rules/recorded-answers.txt`) as
//! Picket's response checks do: when the query itself has no result, every CNAME target, answer
//! IP, HTTPS/SVCB hint and HTTPS/SVCB target name is matched (with the record's type as `$dnstype`
//! sees it); a BLOCK (or a host-IP mapping, a block in AdGuard Home's response phase) blocks the
//! response, a REWRITE there is ignored, an exception passes the item. The oracle (tools/
//! urlfilter-oracle, response mode) does what AdGuard Home's `filterDNSResponse` does.
//!
//! rules.md §6's differences leave the metric, per decision: Picket also checks SVCB hints and
//! HTTPS/SVCB target names, so a disagreement that disappears without those checks is excluded; so
//! is one on a target name with unusual bytes that disappears with keyed rules read as AdGuard's
//! text patterns (rules.md §3). Runs with `PICKET_URLFILTER_ORACLE`; skipped otherwise.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use common::{Group, Query, Target, block_matcher, build, decision, evaluate, parse_rules};
use picket_rules::QueryCtx;
use picket_rules::classify::path_rule_as_pattern;
use picket_rules::matcher::{BundleMatcher, Outcome};

const ANSWERS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/rules/recorded-answers.txt"
);

#[derive(Clone, Debug)]
enum Rr {
    Cname(Vec<Vec<u8>>),
    Ip(u16, IpAddr),
    Svcb {
        rrtype: u16,
        target: Option<Vec<Vec<u8>>>,
        hints: Vec<IpAddr>,
    },
    Other,
}

#[derive(Clone, Debug)]
struct Answer {
    qname: Vec<Vec<u8>>,
    qtype: u16,
    rrs: Vec<Rr>,
    /// The records as written (for the oracle).
    text: String,
}

/// A name in presentation form (`\.`, `\ `, `\DDD` escapes; one trailing dot) as wire labels.
fn name(presentation: &str) -> Vec<Vec<u8>> {
    let b = presentation.as_bytes();
    let mut labels = vec![Vec::new()];
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if i + 3 < b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) => {
                let v =
                    (b[i + 1] - b'0') as u16 * 100 + (b[i + 2] - b'0') as u16 * 10 + (b[i + 3] - b'0') as u16;
                labels.last_mut().unwrap().push(v as u8);
                i += 4;
            }
            b'\\' => {
                labels.last_mut().unwrap().push(b[i + 1]);
                i += 2;
            }
            b'.' => {
                labels.push(Vec::new());
                i += 1;
            }
            c => {
                labels.last_mut().unwrap().push(c);
                i += 1;
            }
        }
    }
    if labels.last().is_some_and(Vec::is_empty) {
        labels.pop();
    }
    labels
}

fn answers() -> Vec<Answer> {
    let text = std::fs::read_to_string(ANSWERS).unwrap();
    let mut out = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let (head, rrs) = line.split_once('\t').unwrap();
        let (qname, qtype) = head.split_once(' ').unwrap();
        let mut parsed = Vec::new();
        for rr in rrs.split(';').map(str::trim).filter(|r| !r.is_empty()) {
            let f: Vec<&str> = rr.split(' ').collect();
            parsed.push(match f[0] {
                // The rest of the record: a name may hold an escaped space.
                "CNAME" => Rr::Cname(name(rr["CNAME ".len()..].trim())),
                "A" => Rr::Ip(1, f[1].parse().unwrap()),
                "AAAA" => Rr::Ip(28, f[1].parse().unwrap()),
                "HTTPS" | "SVCB" => {
                    let mut hints = Vec::new();
                    for kv in &f[3..] {
                        if let Some(v) = kv
                            .strip_prefix("ipv4hint=")
                            .or_else(|| kv.strip_prefix("ipv6hint="))
                        {
                            hints.extend(v.split(',').map(|ip| ip.parse::<IpAddr>().unwrap()));
                        }
                    }
                    Rr::Svcb {
                        rrtype: if f[0] == "HTTPS" { 65 } else { 64 },
                        target: (f[2] != ".").then(|| name(f[2])),
                        hints,
                    }
                }
                _ => Rr::Other,
            });
        }
        out.push(Answer {
            qname: name(qname),
            qtype: qtype.parse().unwrap(),
            rrs: parsed,
            text: rrs.to_string(),
        });
    }
    out
}

/// The two client contexts each answer is checked in.
fn contexts() -> Vec<(Option<IpAddr>, Option<String>, Vec<String>)> {
    vec![
        (None, None, vec![]),
        (
            Some("192.168.1.5".parse().unwrap()),
            Some("kid".into()),
            vec!["device_phone".into()],
        ),
    ]
}

fn blocked(o: &Outcome) -> bool {
    matches!(o, Outcome::Block | Outcome::HostMapping(_))
}

/// Picket's decision on a query and its answer (rules.md §5 step 5, §6), in the oracle's syntax.
/// With `extra` off, only what AdGuard Home checks.
fn picket(m: &BundleMatcher, q: &Query, a: &Answer, extra: bool) -> String {
    let d = decision(&evaluate(m, q).outcome);
    if d != "none" {
        return format!("request {d}");
    }
    let names: Vec<&str> = q.client_name.iter().map(String::as_str).collect();
    let tags: Vec<&str> = q.tags.iter().map(String::as_str).collect();
    let ctx = |qtype: u16| QueryCtx {
        qtype,
        client_ip: q.client_ip,
        client_names: &names,
        client_tags: &tags,
    };
    let by_name = |n: &Vec<Vec<u8>>, qtype: u16| {
        let labels: Vec<&[u8]> = n.iter().map(Vec::as_slice).collect();
        blocked(&m.match_name(&labels, &ctx(qtype)).outcome)
    };
    for (i, rr) in a.rrs.iter().enumerate() {
        let hit = match rr {
            Rr::Cname(t) => by_name(t, 5),
            Rr::Ip(t, ip) => blocked(&m.match_ip(*ip, &ctx(*t)).outcome),
            Rr::Svcb {
                rrtype,
                target,
                hints,
            } => {
                let checked = *rrtype == 65 || extra;
                (checked
                    && hints
                        .iter()
                        .any(|ip| blocked(&m.match_ip(*ip, &ctx(*rrtype)).outcome)))
                    || (extra && target.as_ref().is_some_and(|t| by_name(t, *rrtype)))
            }
            Rr::Other => false,
        };
        if hit {
            return format!("response block {i}");
        }
    }
    "response pass".into()
}

fn unusual(a: &Answer) -> bool {
    let odd = |n: &Vec<Vec<u8>>| !n.iter().all(|l| picket_api::names::is_ordinary_label(l));
    odd(&a.qname)
        || a.rrs.iter().any(|rr| match rr {
            Rr::Cname(t) => odd(t),
            Rr::Svcb { target: Some(t), .. } => odd(t),
            _ => false,
        })
}

const TABLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/rules/response-expectations.tsv"
);

/// Without Go: the response-phase decisions recorded from the oracle
/// (`PICKET_WRITE_RESPONSE_TABLE=1` with the oracle writes them).
fn recorded() {
    let text = std::fs::read_to_string(TABLE).expect("fixtures/rules/response-expectations.tsv");
    let answers = answers();
    let mut rows = 0usize;
    let mut failures = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        let [rules, ai, ctx, want] = f.as_slice() else {
            panic!("bad row {line}")
        };
        let lines: Vec<String> = rules.split(" ⏎ ").map(String::from).collect();
        let m = block_matcher(parse_rules(&lines));
        let a = &answers[ai.parse::<usize>().unwrap()];
        let (ip, cname, tags) = contexts().swap_remove(ctx.parse::<usize>().unwrap());
        let q = Query {
            target: Target::Name(a.qname.clone()),
            qtype: a.qtype,
            client_ip: ip,
            client_name: cname,
            tags,
        };
        rows += 1;
        let got = picket(&m, &q, a, true);
        if got != *want {
            failures.push(format!("{rules} | {}: picket={got} adguard={want}", a.text));
        }
    }
    assert!(rows > 1_000, "table too small: {rows}");
    assert!(
        failures.is_empty(),
        "{} rows differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn response_differential() {
    let Ok(bin) = std::env::var("PICKET_URLFILTER_ORACLE") else {
        recorded();
        return;
    };
    let write_table = std::env::var_os("PICKET_WRITE_RESPONSE_TABLE").is_some();
    let mut table = String::from(
        "# rules (joined by ' ⏎ ')\tanswer (index in recorded-answers.txt)\tclient context\tAdGuard Home v0.107.80 response-phase decision\n# Generated by crates/picket-rules/tests/response_parity.rs from tools/urlfilter-oracle; see PARITY.md.\n",
    );
    let cases: Vec<common::Case> = build().into_iter().filter(|c| c.group == Group::Main).collect();
    let answers = answers();
    // Oracle input: each case with every answer in every context.
    let mut input = String::new();
    for c in &cases {
        let _ = writeln!(input, "case {}", c.id);
        for r in &c.rules {
            let _ = writeln!(input, "rule {r}");
        }
        for a in &answers {
            for (ip, cname, tags) in contexts() {
                let q = Query {
                    target: Target::Name(a.qname.clone()),
                    qtype: a.qtype,
                    client_ip: ip,
                    client_name: cname.clone(),
                    tags: tags.clone(),
                };
                let ipt = ip.map_or("-".to_string(), picket_rules::ip::go_ip_string);
                let nm = cname.unwrap_or_else(|| "-".into());
                let tg = if tags.is_empty() {
                    "-".to_string()
                } else {
                    tags.join(",")
                };
                let _ = writeln!(
                    input,
                    "resp {} {ipt} {nm} {tg} {}\t{}",
                    a.qtype,
                    q.host_text(),
                    a.text
                );
            }
        }
        input.push_str("end\n");
    }
    let out = run(&bin, &input);
    let mut tally: BTreeMap<&str, u64> = BTreeMap::new();
    let mut examples: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for c in &cases {
        let rules = parse_rules(&c.rules);
        let m = block_matcher(rules.clone());
        let text_m = block_matcher(rules.iter().map(common::keyed_as_pattern).collect());
        let has_extension = rules.iter().any(|r| r.spec.extension);
        let no_ext_m = block_matcher(rules.iter().filter(|r| !r.spec.extension).cloned().collect());
        let mut with_paths = rules.clone();
        with_paths.extend(c.rules.iter().filter_map(|l| path_rule_as_pattern(l.trim())));
        let paths_m = block_matcher(with_paths);
        let mut k = 0usize;
        for (ai, a) in answers.iter().enumerate() {
            for (ci, (ip, cname, tags)) in contexts().into_iter().enumerate() {
                let q = Query {
                    target: Target::Name(a.qname.clone()),
                    qtype: a.qtype,
                    client_ip: ip,
                    client_name: cname,
                    tags,
                };
                let theirs = out.get(&(c.id.clone(), k)).cloned().unwrap_or_default();
                // Hosts lines with a block address are blocks (feeds.md §4), as in the name test.
                let theirs = match theirs.strip_prefix("request ") {
                    Some(d) => format!("request {}", common::normalise_oracle(d)),
                    None => theirs,
                };
                k += 1;
                let ours = picket(&m, &q, a, true);
                let class = if ours == theirs {
                    "agree"
                } else if has_extension && picket(&no_ext_m, &q, a, true) == theirs {
                    "excluded: protocol/port extension (rules.md §2)"
                } else if a.text.contains('/') && picket(&paths_m, &q, a, true) == theirs {
                    "owner decision: browser path rules × names with `/` bytes (R10)"
                } else if picket(&m, &q, a, false) == theirs {
                    "excluded: rules.md §6 (SVCB hints, HTTPS/SVCB target names)"
                } else if unusual(a) && picket(&text_m, &q, a, true) == theirs {
                    "excluded: unusual bytes (keyed rules match whole labels)"
                } else {
                    "disagree"
                };
                *tally.entry(class).or_default() += 1;
                if class != "agree" {
                    examples.entry(class).or_default().push(format!(
                        "{} {:?} {} [{}]: picket={ours} adguard={theirs}",
                        c.id,
                        c.rules.iter().take(3).collect::<Vec<_>>(),
                        q.host_text(),
                        a.text
                    ));
                }
                if class == "agree" && theirs.starts_with("response block") {
                    *tally.entry("agree (response blocks)").or_default() += 1;
                }
                // The table: single rules and the parity examples, every response block and a
                // sample of the rest.
                if write_table
                    && class == "agree"
                    && c.id.starts_with(['s', 'x', 'o', 'e'])
                    && (theirs.starts_with("response block") || k.is_multiple_of(23))
                {
                    let _ = writeln!(table, "{}\t{ai}\t{ci}\t{theirs}", c.rules.join(" ⏎ "));
                }
            }
        }
    }
    if write_table {
        std::fs::write(TABLE, &table).unwrap();
    }
    let mut report = format!("response phase: {tally:?}\n");
    for (class, ex) in &examples {
        let _ = writeln!(report, "  {class}: {}", ex.len());
        for e in ex.iter().take(12) {
            let _ = writeln!(report, "    {e}");
        }
    }
    eprintln!("{report}");
    let agree = tally.get("agree").copied().unwrap_or(0);
    let disagree = tally.get("disagree").copied().unwrap_or(0);
    let total = agree + disagree;
    assert!(total > 50_000, "too few decisions: {total}");
    assert!(
        tally.get("agree (response blocks)").copied().unwrap_or(0) > 500,
        "too few response blocks\n{report}"
    );
    let pct = agree as f64 * 100.0 / total as f64;
    assert!(pct >= 99.99, "response-phase agreement {pct:.4} %\n{report}");
}

fn run(bin: &str, input: &str) -> std::collections::HashMap<(String, usize), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run the oracle");
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_string();
    let writer = std::thread::spawn(move || stdin.write_all(data.as_bytes()));
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    assert!(out.status.success());
    let mut res = std::collections::HashMap::new();
    for line in String::from_utf8(out.stdout).unwrap().lines() {
        let mut f = line.splitn(3, '\t');
        let (Some(id), Some(k), Some(d)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if let Some(k) = k.strip_prefix('r') {
            res.insert((id.to_string(), k.parse().unwrap()), d.to_string());
        }
    }
    res
}
