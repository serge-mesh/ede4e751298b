//! Go `regexp` parity of the Go → Rust translation (rules.md §3 "patterns keep AdGuard's regex";
//! review round 1, R2): a deterministic set of random Go regexes, built from the syntax urlfilter
//! rules use and Go's corner cases, must be accepted exactly when Go accepts them and must match
//! exactly the subjects Go matches.
//!
//! With `PICKET_URLFILTER_ORACLE` set, every regex is checked against Go's `regexp` (the oracle's
//! regex mode). Without it, the verdicts recorded from Go in `fixtures/rules/go-regex-expectations.tsv`
//! are checked. Regenerate with `PICKET_URLFILTER_ORACLE=<oracle> PICKET_WRITE_GOREGEX_TABLE=1 cargo
//! test -p picket-rules --test goregex_parity`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

use std::fmt::Write as _;

use picket_rules::analysis::build_regex;
use picket_rules::goregex::translate;

const TABLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/rules/go-regex-expectations.tsv"
);

/// Regexes in the random set (the oracle run); the first `RECORDED` go into the table.
const RANDOM: usize = 40_000;
const RECORDED: usize = 4_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        v[(self.next() % v.len() as u64) as usize]
    }
}

/// Syntax Go accepts.
const ATOMS: &[&str] = &[
    "a",
    "b",
    "k",
    "s",
    "K",
    "S",
    "x",
    "ad",
    "ads",
    "tracker",
    ".",
    "-",
    "_",
    "\\.",
    "\\-",
    "\\d",
    "\\D",
    "\\w",
    "\\W",
    "\\s",
    "\\S",
    "\\b",
    "\\B",
    "\\pL",
    "\\PL",
    "\\pl",
    "\\p{Greek}",
    "\\p{greek}",
    "\\p{^Greek}",
    "\\p{Letter}",
    "\\p{Lu}",
    "\\p{Any}",
    "\\p{ASCII}",
    "\\p{Assigned}",
    "\\p{Cs}",
    "\\p{Sidetic}",
    "\\Qa.b\\E",
    "\\Q*\\E",
    "\\x41",
    "\\x{6b}",
    "\\101",
    "\\0",
    "\\_",
    "\\<",
    "\\>",
    "[a-c]",
    "[^a]",
    "[k]",
    "[^k]",
    "[Kk]",
    "[Aa]",
    "[a]",
    "[[:alpha:]]",
    "[[:^digit:]]",
    "[[:word:]]",
    "[\\d-]",
    "[]a]",
    "[^]a]",
    "[a&&b]",
    "[--/]",
    "[\\pL\\d]",
    "[^\\PL]",
    "[\\x{212A}]",
    "[\\x{17F}]",
    "\u{212A}",
    "\u{17F}",
    "σ",
    "Σ",
    "ß",
    "^",
    "$",
    "\\A",
    "\\z",
    "(?:)",
    "()",
    "(|)",
    "x{",
    "{",
    "}",
    "]",
    "#",
    " ",
    "<",
    "é",
    "|",
    "a|b",
    "ab|ac",
    "[ab]|a",
];

/// Syntax Go refuses (or reads in a way Rust wouldn't), used sparingly.
const BAD_ATOMS: &[&str] = &[
    "\\p{Bogus}",
    "\\p{sc=Greek}",
    "\\p",
    "\\p{",
    "\\Q",
    "\\C",
    "\\x{}",
    "\\x4",
    "\\8",
    "\\1",
    "\\y",
    "[[:foo:]]",
    "[a-\\d]",
    "[b-a]",
    "[",
    "[a",
    "\\",
];

const OPEN: &[&str] = &[
    "(", "(?:", "(?i)", "(?-i)", "(?i:", "(?-i:", "(?s)", "(?m)", "(?U)", "(?i-s:", "(?P<n>", "(?P<1>",
    "(?<x>", "(?i-i)",
];

const BAD_OPEN: &[&str] = &["(?P=n)", "(?x)", "(?", "(?-)", "(?i-)", "(?="];

const REPEATS: &[&str] = &[
    "*",
    "+",
    "?",
    "*?",
    "+?",
    "??",
    "{2}",
    "{2,}",
    "{0,3}",
    "{1,1}",
    "{0}",
    "{0,}",
    "{1000}",
    "{500}",
    "{01}",
    "{,2}",
    "{999,1000}",
    "{3}",
];

const BAD_REPEATS: &[&str] = &["{1001}", "{3,2}", "{2}{3}", "**", "{100000000}"];

fn random_regex(rng: &mut Rng) -> String {
    let bad = |rng: &mut Rng| rng.next().is_multiple_of(25);
    let mut s = String::new();
    if !rng.next().is_multiple_of(3) {
        s.push_str("(?i)");
    }
    let mut depth = 0u32;
    let n = 1 + rng.next() % 12;
    for _ in 0..n {
        match rng.next() % 10 {
            0 | 1 => {
                s.push_str(if bad(rng) {
                    rng.pick(BAD_OPEN)
                } else {
                    rng.pick(OPEN)
                });
                depth += 1;
            }
            2 | 3 if depth > 0 => {
                s.push(')');
                depth -= 1;
            }
            4 => s.push('|'),
            _ => s.push_str(if bad(rng) {
                rng.pick(BAD_ATOMS)
            } else {
                rng.pick(ATOMS)
            }),
        }
        if rng.next().is_multiple_of(3) {
            s.push_str(if bad(rng) {
                rng.pick(BAD_REPEATS)
            } else {
                rng.pick(REPEATS)
            });
        }
    }
    while depth > 0 && !rng.next().is_multiple_of(12) {
        s.push(')');
        depth -= 1;
    }
    s
}

/// Deterministic regexes that stress Go's tree: factoring, nesting and size limits.
fn structural() -> Vec<String> {
    let mut v: Vec<String> = vec![
        "(?i)ads|adserver|adsrvr|tracker|track".into(),
        "(?i)abc|abd|aef|bcx|bcy".into(),
        "(?i)a|b|c|[d-f]|.".into(),
        "(?i)(?:a{2}x|a{2}y)".into(),
        "(?i:a)x|Ay".into(),
        "(?i:a)x|A".into(),
        "(?i)x(?-i:A)|xa".into(),
        "(?i)(a{1000}){2}|example".into(),
        "(?i)(a{500}){2}|example".into(),
        "(?i)((a{10}){10}){10}".into(),
        "(?i)((a{10}){10}){11}".into(),
        "(?i)((a{600}){0}){2}".into(),
        "(?i)((a{600}){1}){2}".into(),
        "(?i)(?:\\w|-){900}N".into(),
        format!("(?i){}a{}", "(".repeat(999), ")".repeat(999)),
        format!("(?i){}a{}", "(".repeat(1000), ")".repeat(1000)),
        format!("(?i){}a{}", "(?:".repeat(2000), ")".repeat(2000)),
        format!("(?i)(?:{}){{1000}}", "[a-z]x".repeat(1700)),
        format!("(?i)(?:{}){{100}}", "abcdefgh".repeat(4200)),
    ];
    let mut tall = String::from("a");
    for _ in 0..470 {
        tall = format!("(?:{tall})*b");
    }
    v.push(tall);
    let mut tall = String::from("a");
    for _ in 0..520 {
        tall = format!("(?:{tall})*b");
    }
    v.push(tall);
    let alts: Vec<String> = (1..400).map(|i| "x".repeat(i)).collect();
    v.push(alts.join("|"));
    v
}

fn subjects() -> Vec<String> {
    let mut v: Vec<String> = [
        "",
        "a",
        "A",
        "ab",
        "aa",
        "aaa",
        "ads.example.com",
        "x.tracker.net",
        "k",
        "K",
        "s",
        "S",
        "\u{212A}",
        "\u{17F}",
        "αβγ",
        "Σσς",
        "ß",
        "x\ny",
        "\n",
        "5",
        "a.b",
        "a-b",
        "_x_",
        "<>",
        "-",
        "]",
        "[",
        "{",
        "}",
        "x{01}",
        "a{,2}",
        "a.b*",
        "http://ads.example/",
        "e",
        "é",
        "N",
        "aN",
        "#",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    v.push("a".repeat(2000) + "b" + &"a".repeat(1100));
    v.push(format!("{}N", "w".repeat(900)));
    v
}

/// Picket's verdict in the oracle's syntax: `ERR`, or `OK\t<bits>`.
fn ours(pattern: &str, subjects: &[String]) -> String {
    let Ok(rust) = translate(pattern) else {
        return "ERR".into();
    };
    let re = match build_regex(&rust) {
        Ok(re) => re,
        // Accepted by Go but over the shared NFA limit: dropped as too large (rules.md §3).
        Err(_) => return "TOO-LARGE".into(),
    };
    let bits: String = subjects
        .iter()
        .map(|s| if re.is_match(s.as_str()) { '1' } else { '0' })
        .collect();
    format!("OK\t{bits}")
}

fn theirs(bin: &str, patterns: &[String], subjects: &[String]) -> Vec<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut input = String::new();
    for (i, p) in patterns.iter().enumerate() {
        assert!(!p.contains('\n') && !p.contains('\t'));
        let _ = writeln!(input, "re {i}\t{p}");
        for s in subjects {
            // The protocol is line-based: subjects with a newline are encoded as `\n`.
            let _ = writeln!(input, "sj {s}");
        }
        input.push_str("re-end\n");
    }
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run the oracle");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let mut res = vec![String::new(); patterns.len()];
    for line in text.lines() {
        let (id, rest) = line.split_once('\t').unwrap();
        res[id.parse::<usize>().unwrap()] = rest.to_string();
    }
    res
}

fn all_patterns() -> Vec<String> {
    let mut rng = Rng(0x005e_ed0f_9c0e_ab1e);
    let mut v = structural();
    while v.len() < RANDOM {
        v.push(random_regex(&mut rng));
    }
    v
}

/// Subjects without newlines (the oracle protocol is line-based).
fn line_subjects() -> Vec<String> {
    subjects().into_iter().filter(|s| !s.contains('\n')).collect()
}

#[test]
fn go_regex_parity() {
    let subjects = line_subjects();
    let Ok(bin) = std::env::var("PICKET_URLFILTER_ORACLE") else {
        recorded(&subjects);
        return;
    };
    let patterns = all_patterns();
    let go = theirs(&bin, &patterns, &subjects);
    let mut mismatches = Vec::new();
    let (mut accepted, mut refused, mut too_large) = (0usize, 0usize, 0usize);
    for (p, g) in patterns.iter().zip(&go) {
        let o = ours(p, &subjects);
        match (o.as_str(), g.as_str()) {
            ("TOO-LARGE", g) if g.starts_with("OK") => {
                too_large += 1;
                continue;
            }
            _ => {}
        }
        if o.starts_with("OK") {
            accepted += 1;
        } else {
            refused += 1;
        }
        if &o != g {
            mismatches.push(format!("{p:?}: picket {o} go {g}"));
        }
    }
    eprintln!(
        "{} regexes: {accepted} accepted, {refused} refused, {too_large} over the NFA limit; {} mismatches",
        patterns.len(),
        mismatches.len()
    );
    if std::env::var_os("PICKET_WRITE_GOREGEX_TABLE").is_some() {
        let mut out = String::from(
            "# Go regexp verdicts (tools/urlfilter-oracle regex mode) for crates/picket-rules/tests/goregex_parity.rs.\n# regex (escaped: \\t \\n \\\\)\tverdict (ERR, or OK and one bit per subject)\n",
        );
        // Long structural regexes are covered by goregex.rs's unit tests; keep the table small.
        for (p, g) in patterns
            .iter()
            .zip(&go)
            .filter(|(p, _)| p.len() <= 512)
            .take(RECORDED)
        {
            let _ = writeln!(out, "{}\t{g}", escape(p));
        }
        std::fs::write(TABLE, out).unwrap();
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} regexes differ from Go:\n{}",
        mismatches.len(),
        patterns.len(),
        mismatches.iter().take(60).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(
        accepted > 10_000 && refused > 5_000,
        "{accepted} accepted, {refused} refused"
    );
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n")
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some(o) => out.push(o),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn recorded(subjects: &[String]) {
    let text = std::fs::read_to_string(TABLE).expect("fixtures/rules/go-regex-expectations.tsv");
    let mut rows = 0usize;
    let mut failures = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let (p, want) = line.split_once('\t').unwrap();
        let p = unescape(p);
        let got = ours(&p, subjects);
        rows += 1;
        if got == "TOO-LARGE" && want.starts_with("OK") {
            continue;
        }
        if got != want {
            failures.push(format!("{p:?}: picket {got} go {want}"));
        }
    }
    assert!(rows >= 1_000, "table too small: {rows}");
    assert!(
        failures.is_empty(),
        "{} of {rows} recorded regexes differ:\n{}",
        failures.len(),
        failures.iter().take(60).cloned().collect::<Vec<_>>().join("\n")
    );
}
