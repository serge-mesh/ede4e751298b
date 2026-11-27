//! Allocation budgets (build-and-test.md §4): on the baseline query fixtures, a cache hit and a
//! block reply, query decoding included, make at most 2 heap allocations, and serving after
//! decoding makes none. Other query shapes and the upstream-answer pipeline have the committed
//! per-fixture budgets in the tables below; a change that needs more changes the table in the
//! same commit, reviewed like code.
//!
//! Counted with a counting global allocator; everything runs in one test so no other test thread
//! allocates during a measurement. Allocations and reallocations both count.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

use std::hint::black_box;
use std::time::{Instant, SystemTime};

use picket_api::edge_config::{BlockResponse, TtlClamp};
use picket_wire::answer::{AnswerLimits, SentQuery, check_answer};
use picket_wire::cache::{CacheValue, ServeParams, serve_hit};
use picket_wire::ede::EdeOption;
use picket_wire::query::check_query;
use picket_wire::reply::{Transport, write_block};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

/// The baseline query fixtures: at most 2 allocations for decode + serve or decode + block.
const BASELINE: &[&str] = &["a-no-opt", "a-opt", "aaaa-opt-do", "https-opt-padded"];
const BASELINE_MAX: usize = 2;

/// Committed budgets for decoding the other query shapes.
const QUERY_BUDGETS: &[(&str, usize)] = &[
    ("a-opt-cookie", 0),
    // A 40-byte name is over hickory's 32 inline label bytes: its label buffer spills, then grows.
    ("a-long-name", 2),
    ("ptr-private", 0),
];

/// Committed budgets for checking, scrubbing and encoding each recorded upstream answer and
/// building its cache value (both copies, TTL offsets, facts).
const ANSWER_BUDGETS: &[(&str, usize)] = &[
    ("plain-a", 18),
    ("cname-chain", 37),
    ("signed-nsec3-nxdomain", 147),
    ("nxdomain-soa", 28),
    ("https-hints", 36),
    ("dname", 92),
    ("dot-padded-a", 35),
    ("nodata-signed", 74),
];

fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/wire")
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn queries() -> Vec<(String, Vec<u8>)> {
    std::fs::read_to_string(fixtures_dir().join("queries.txt"))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let (n, h) = l.split_once(' ').unwrap();
            (n.to_string(), hex(h.trim()))
        })
        .collect()
}

fn recorded(name: &str) -> (Vec<u8>, Vec<u8>) {
    let text = std::fs::read_to_string(fixtures_dir().join(format!("{name}.txt"))).unwrap();
    let get = |p: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(p))
            .map(|h| hex(h.trim()))
            .unwrap()
    };
    (get("query "), get("answer "))
}

/// An upstream answer to `query` with one record of its type (A, AAAA or a ServiceMode HTTPS).
fn answer_for(query: &[u8], id: u16) -> Vec<u8> {
    let q = check_query(query).unwrap();
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 1]);
    m.extend_from_slice(q.qname().wire());
    m.extend_from_slice(&q.qtype.to_be_bytes());
    m.extend_from_slice(&q.qclass.to_be_bytes());
    m.extend_from_slice(&[0xC0, 0x0C]);
    m.extend_from_slice(&q.qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 1, 0x2C]);
    let rdata: Vec<u8> = match q.qtype {
        1 => vec![192, 0, 2, 1],
        28 => vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        _ => vec![0, 1, 0, 0, 1, 0, 3, 2, b'h', b'2'],
    };
    m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    m.extend_from_slice(&rdata);
    m.extend_from_slice(&[0, 0, 0x29, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]);
    m
}

fn value_for(query: &[u8]) -> CacheValue {
    let q = check_query(query).unwrap();
    let answer = answer_for(query, 0x4444);
    let sent = SentQuery {
        id: 0x4444,
        qname: q.qname().as_name(),
        qtype: q.qtype,
        qclass: q.qclass,
    };
    let a = check_answer(&answer, &sent, &AnswerLimits::default()).unwrap();
    CacheValue::new(a, SystemTime::now(), Instant::now())
}

fn count<R>(f: impl FnOnce() -> R) -> usize {
    let region = Region::new(GLOBAL);
    black_box(f());
    let s = region.change();
    s.allocations + s.reallocations
}

#[test]
fn allocation_budgets() {
    let queries = queries();
    let mut out = vec![0u8; 65_535];
    let block = BlockResponse::default();
    let clamp = TtlClamp::default();
    let mut report = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for (name, msg) in &queries {
        if BASELINE.contains(&name.as_str()) {
            let value = value_for(msg);
            let p = ServeParams {
                age_s: 5,
                clamp,
                stale: None,
            };
            // Serving after decoding: none.
            let q = check_query(msg).unwrap();
            let serve = count(|| {
                serve_hit(
                    &mut out,
                    &q.reply_to(Transport::Udp, picket_wire::EDGE_UDP_PAYLOAD),
                    &value,
                    &p,
                )
                .unwrap()
            });
            assert_eq!(serve, 0, "{name}: serving a hit allocated");
            // Over DoT/DoH, where a padded query's reply is padded (RFC 7830 §4): none either.
            let padded = count(|| {
                serve_hit(
                    &mut out,
                    &q.reply_to(Transport::Encrypted, picket_wire::EDGE_UDP_PAYLOAD),
                    &value,
                    &p,
                )
                .unwrap()
            });
            assert_eq!(padded, 0, "{name}: serving a hit over DoT/DoH allocated");
            let blk = count(|| {
                let ede = EdeOption::blocked_by_bundle("block-common", "c02f7a9e1b4d6e83", "k3j9q2");
                write_block(
                    &mut out,
                    &q.reply_to(Transport::Udp, picket_wire::EDGE_UDP_PAYLOAD),
                    &block,
                    ede,
                )
                .unwrap()
            });
            assert_eq!(blk, 0, "{name}: writing a block reply allocated");
            let blk = count(|| {
                let ede = EdeOption::blocked_by_bundle("block-common", "c02f7a9e1b4d6e83", "k3j9q2");
                write_block(
                    &mut out,
                    &q.reply_to(Transport::Encrypted, picket_wire::EDGE_UDP_PAYLOAD),
                    &block,
                    ede,
                )
                .unwrap()
            });
            assert_eq!(blk, 0, "{name}: writing a block reply over DoT/DoH allocated");
            // Decode + serve, decode + block.
            let hit = count(|| {
                let q = check_query(black_box(msg)).unwrap();
                serve_hit(
                    &mut out,
                    &q.reply_to(Transport::Udp, picket_wire::EDGE_UDP_PAYLOAD),
                    &value,
                    &p,
                )
                .unwrap()
            });
            let blocked = count(|| {
                let q = check_query(black_box(msg)).unwrap();
                let ede = EdeOption::blocked_by_bundle("block-common", "c02f7a9e1b4d6e83", "k3j9q2");
                write_block(
                    &mut out,
                    &q.reply_to(Transport::Udp, picket_wire::EDGE_UDP_PAYLOAD),
                    &block,
                    ede,
                )
                .unwrap()
            });
            report.push(format!("{name}: hit {hit}, block {blocked}"));
            assert!(hit <= BASELINE_MAX, "{name}: cache hit made {hit} allocations");
            assert!(
                blocked <= BASELINE_MAX,
                "{name}: block reply made {blocked} allocations"
            );
        } else {
            let budget = QUERY_BUDGETS
                .iter()
                .find(|(n, _)| n == name)
                .unwrap_or_else(|| panic!("no committed budget for query fixture {name}"))
                .1;
            let n = count(|| check_query(black_box(msg)).unwrap());
            report.push(format!("{name}: decode {n} (budget {budget})"));
            failures.extend(
                (n > budget).then(|| format!("{name}: decode made {n} allocations, budget {budget}")),
            );
        }
    }

    // A header claiming 65,535 questions, or an answer claiming 65 records in a section, is
    // refused from the header alone: nothing is decoded, nothing allocated.
    let mut many = vec![0xAB, 0xCD, 0x01, 0x00, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0];
    many.extend_from_slice(&[0xC0; 64]);
    let n = count(|| check_query(black_box(&many)).unwrap_err());
    assert_eq!(n, 0, "65,535-question header");
    let mut answer = vec![0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 65, 0, 0, 0, 0];
    answer.extend_from_slice(&[0xC0; 64]);
    let name = picket_wire::name::QName::from_text("example.com").unwrap();
    let sent = SentQuery {
        id: 0xABCD,
        qname: name.as_name(),
        qtype: 1,
        qclass: 1,
    };
    let n = count(|| check_answer(black_box(&answer), &sent, &AnswerLimits::default()).unwrap_err());
    assert_eq!(n, 0, "65-record answer header");

    for (name, budget) in ANSWER_BUDGETS {
        let (query, answer) = recorded(name);
        let q = check_query(&query).unwrap();
        let sent = SentQuery {
            id: q.id,
            qname: q.qname().as_name(),
            qtype: q.qtype,
            qclass: q.qclass,
        };
        let n = count(|| {
            let a = check_answer(black_box(&answer), &sent, &AnswerLimits::default()).unwrap();
            CacheValue::new(a, SystemTime::UNIX_EPOCH, Instant::now())
        });
        report.push(format!("{name}: answer pipeline {n} (budget {budget})"));
        failures.extend(
            (n > *budget).then(|| format!("{name}: answer pipeline made {n} allocations, budget {budget}")),
        );
    }
    println!("{}", report.join("\n"));
    assert!(failures.is_empty(), "over budget:\n{}", failures.join("\n"));
}
