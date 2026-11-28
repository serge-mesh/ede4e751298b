//! `dns` module tests (providers.md §5 `dns`; build-and-test.md §5 "DNS lookups"): recorded and
//! synthesised resolver answers per transport, the rules, the detail, query construction, server
//! order and skipping, UDP truncation, the config checks, the schema warning and the presets.

mod msg;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use picket_api::edge_config::UpstreamProtocol;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use self::msg::{Msg, a, aaaa, ede, n, ptr, soa};
use super::config::{Config, PLAIN_DNS_WARNING};
use super::presets::{Encrypted, NextDnsParams, nextdns_config, quad9_config};
use super::{Module, SERVER_TIMEOUT};
use crate::ctx::{DnsClientError, DnsServer, LookupCtx, SystemClock};
use crate::module::{Category, Expect, LookupError, LookupModule, Verdict};
use crate::testkit::{MockDns, MockHttp, connections};

fn ctx(dns: Arc<MockDns>) -> LookupCtx {
    let http = MockHttp::new(|_| Err(crate::ctx::HttpError::Refused("no".into())));
    LookupCtx::new(
        "q9",
        connections(http, dns),
        Arc::new(SystemClock),
        CancellationToken::new(),
    )
}

/// The query's ID, written into a canned answer so it matches (the module picks a random ID).
fn with_id(answer: &[u8], query: &[u8]) -> Vec<u8> {
    let mut out = answer.to_vec();
    out[0] = query[0];
    out[1] = query[1];
    out
}

/// A server client that answers every query with `answer` (its ID patched).
fn answering(answer: Vec<u8>) -> Arc<MockDns> {
    MockDns::new(move |_, q| Ok(with_id(&answer, q)))
}

async fn lookup(cfg: &Value, dns: Arc<MockDns>, name: &str) -> Result<crate::module::Answer, LookupError> {
    Module.lookup(&ctx(dns), cfg, name).await
}

fn verdict_and_rule(a: &crate::module::Answer) -> (String, Option<String>) {
    let v = match &a.verdict {
        Verdict::Block { .. } => "block",
        Verdict::Clean => "clean",
        Verdict::Unknown => "unknown",
    };
    let rule = a
        .detail
        .as_ref()
        .and_then(|d| d["rule"].as_str())
        .map(str::to_owned);
    (v.to_owned(), rule)
}

// ---------------------------------------------------------------------------------------------
// Recorded and synthesised fixtures

struct Case {
    case: String,
    qname: String,
    answer: Vec<u8>,
    verdict: String,
    rule: Option<String>,
}

fn load(text: &str) -> Vec<Case> {
    let mut out = Vec::new();
    let mut cur: Option<Case> = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once(' ').unwrap();
        match k {
            "case" => {
                out.extend(cur.take());
                cur = Some(Case {
                    case: v.into(),
                    qname: String::new(),
                    answer: vec![],
                    verdict: String::new(),
                    rule: None,
                });
            }
            "qname" => cur.as_mut().unwrap().qname = v.into(),
            "qtype" => assert_eq!(v, "A"),
            "answer" => {
                let c = cur.as_mut().unwrap();
                c.answer = (0..v.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                    .collect();
            }
            "expect" => {
                let (verdict, rule) = v.split_once(' ').unwrap();
                let c = cur.as_mut().unwrap();
                c.verdict = verdict.into();
                c.rule = (rule != "-").then(|| rule.to_owned());
            }
            other => panic!("unknown fixture key {other}"),
        }
    }
    out.extend(cur);
    out
}

async fn run_fixtures(file: &str, text: &str, cfg: Value) -> usize {
    let cases = load(text);
    assert!(!cases.is_empty(), "{file}");
    for c in &cases {
        let a = lookup(&cfg, answering(c.answer.clone()), &c.qname)
            .await
            .unwrap_or_else(|e| panic!("{file} {}: {e}", c.case));
        let (v, rule) = verdict_and_rule(&a);
        assert_eq!(v, c.verdict, "{file} {}", c.case);
        assert_eq!(rule, c.rule, "{file} {}", c.case);
        let d = a.detail.unwrap();
        assert!(serde_json::to_string(&d).unwrap().len() < crate::DETAIL_MAX);
        // A Clean verdict alone doesn't establish that a recording exercises NXDOMAIN or
        // EDE 29: a NOERROR/NODATA answer also falls through to Clean.
        match c.case.as_str() {
            "nonexistent" => {
                assert_eq!(d["rcode"], "NXDOMAIN", "{file} {}", c.case);
                assert_eq!(d["soa"], true, "{file} {}", c.case);
            }
            "synthesized" => {
                assert_eq!(d["rcode"], "NXDOMAIN", "{file} {}", c.case);
                assert!(
                    d["ede"].as_array().unwrap().iter().any(|e| e["code"] == 29),
                    "{file} {}: missing EDE 29: {d}",
                    c.case
                );
            }
            "servfail" => assert_eq!(d["rcode"], "SERVFAIL", "{file} {}", c.case),
            "blocked" if file.starts_with("nextdns-") => {
                assert_eq!(d["rcode"], "NOERROR", "{file} {}", c.case);
                assert_eq!(d["answers"], json!(["0.0.0.0"]), "{file} {}", c.case);
                assert_eq!(
                    d["ede"],
                    json!([{"code": 17, "text": "Blocked by NextDNS: blacklist"}]),
                    "{file} {}",
                    c.case
                );
            }
            _ => {}
        }
        if let Verdict::Block { reason, .. } = &a.verdict {
            assert_eq!(Some(reason), c.rule.as_ref(), "a Block's reason is the rule id");
        }
    }
    cases.len()
}

/// build-and-test.md §5 "DNS lookups": Quad9 for `isitblocked.org`, a nonexistent name and EDE
/// 29, per transport.
#[tokio::test]
async fn quad9_answers_per_transport() {
    for (file, text, t) in [
        ("quad9-dot.txt", include_str!("quad9-dot.txt"), Encrypted::Dot),
        ("quad9-doh.txt", include_str!("quad9-doh.txt"), Encrypted::Doh),
    ] {
        assert_eq!(run_fixtures(file, text, quad9_config(t)).await, 8);
    }
    // Live Quad9 replies over plain UDP: the same rules over `udp`.
    let mut cfg = quad9_config(Encrypted::Dot);
    cfg["transport"] = json!("udp");
    assert_eq!(
        run_fixtures("quad9-udp.txt", include_str!("quad9-udp.txt"), cfg).await,
        8
    );
}

/// Live NextDNS replies for a denylisted name, a normal name and NXDOMAIN, plus a synthetic
/// `0.0.0.0` answer without EDE, per transport.
#[tokio::test]
async fn nextdns_answers_per_transport() {
    for (file, text, t) in [
        ("nextdns-dot.txt", include_str!("nextdns-dot.txt"), Encrypted::Dot),
        ("nextdns-doh.txt", include_str!("nextdns-doh.txt"), Encrypted::Doh),
    ] {
        let p = NextDnsParams {
            profile: "abc123".into(),
            transport: t,
            self_test: None,
        };
        assert_eq!(run_fixtures(file, text, nextdns_config(&p).unwrap()).await, 4);
    }
}

#[tokio::test]
async fn quad9_block_detail() {
    let m = Msg::response(0, "isitblocked.org", 1, 3).opt(&[ede(15, b"")]);
    let a = lookup(
        &quad9_config(Encrypted::Dot),
        answering(m.build()),
        "isitblocked.org",
    )
    .await
    .unwrap();
    assert_eq!(
        a.verdict,
        Verdict::Block {
            score: None,
            reason: "blocked".into()
        }
    );
    assert_eq!(
        a.detail.unwrap(),
        json!({"server": "9.9.9.9", "transport": "dot", "rcode": "NXDOMAIN", "ede": [{"code": 15}],
               "answers": [], "cname": [], "soa": false, "rule": "blocked"})
    );
}

// ---------------------------------------------------------------------------------------------
// Detail

/// build-and-test.md §5 "DNS lookups": `detail` from a 200-byte EXTRA-TEXT with `<` and control
/// bytes.
#[tokio::test]
async fn detail_from_long_extra_text_with_control_bytes() {
    let mut text = b"<script>".to_vec();
    text.extend_from_slice(&[0x01, 0x1b, b'\n', b'\\']);
    text.resize(200, b'x');
    let m = Msg::response(0, "x.example", 1, 3).opt(&[ede(15, &text)]);
    let a = lookup(&quad9_config(Encrypted::Dot), answering(m.build()), "x.example")
        .await
        .unwrap();
    let d = a.detail.unwrap();
    let t = d["ede"][0]["text"].as_str().unwrap();
    // 64 bytes of EXTRA-TEXT, control characters and `\` written as \DDD.
    assert!(t.starts_with("<script>\\001\\027\\010\\092xxx"), "{t}");
    assert_eq!(t.matches('x').count(), 64 - 12);
    assert!(!t.chars().any(char::is_control));
    assert!(serde_json::to_string(&d).unwrap().len() < crate::DETAIL_MAX);
}

#[tokio::test]
async fn detail_caps_answers_cname_and_size() {
    // A 4-hop CNAME chain of long names with 6 addresses, and 8 long EDEs.
    let long = |i: usize| format!("{}{i}.{}.example", "c".repeat(60), "d".repeat(60));
    let mut m = Msg::response(0, "www.example.com", 1, 0);
    let mut owner = ptr(12);
    for i in 0..5 {
        let target = n(&long(i));
        m = m.rr(1, &owner, 5, 60, &target);
        owner = target;
    }
    for i in 0..6 {
        m = m.rr(1, &owner, 1, 60, &a(&format!("192.0.2.{i}")));
    }
    let edes: Vec<(u16, Vec<u8>)> = (0..8).map(|i| ede(i + 1, &[b'\x07'; 100])).collect();
    let m = m.opt(&edes);
    let cfg = json!({"transport": "tcp", "servers": [{"ip": "192.0.2.53"}]});
    let a = lookup(&cfg, answering(m.build()), "www.example.com")
        .await
        .unwrap();
    assert_eq!(a.verdict, Verdict::Clean);
    let d = a.detail.unwrap();
    assert!(
        serde_json::to_string(&d).unwrap().len() < crate::DETAIL_MAX,
        "{d}"
    );
    assert!(d["answers"].as_array().unwrap().len() <= 4);
    assert!(d["cname"].as_array().unwrap().len() <= 4);
    assert_eq!(d["server"], "192.0.2.53");
    assert_eq!(d["transport"], "tcp");
    assert_eq!(d["rule"], Value::Null);
}

#[tokio::test]
async fn detail_names_in_log_text_and_port() {
    let m = Msg::response(0, "www.example.com", 1, 0)
        .rr(1, &ptr(12), 5, 60, &n("Edge.Example.NET"))
        .rr(1, &n("edge.example.net"), 1, 60, &a("192.0.2.1"));
    let cfg = json!({"transport": "udp", "servers": [{"ip": "192.0.2.53", "port": 5353}]});
    let a = lookup(&cfg, answering(m.build()), "www.example.com")
        .await
        .unwrap();
    let d = a.detail.unwrap();
    assert_eq!(d["cname"], json!(["edge.example.net"]));
    assert_eq!(d["answers"], json!(["192.0.2.1"]));
    assert_eq!(d["server"], "192.0.2.53:5353");
}

// ---------------------------------------------------------------------------------------------
// Rules

fn cfg_with_rules(rules: Value) -> Value {
    json!({"transport": "dot", "servers": [{"ip": "192.0.2.53", "tls_host": "r.example"}], "rules": rules})
}

async fn decide(rules: Value, m: Msg, name: &str) -> (String, Option<String>) {
    let a = lookup(&cfg_with_rules(rules), answering(m.build()), name)
        .await
        .unwrap();
    verdict_and_rule(&a)
}

#[tokio::test]
async fn each_condition() {
    let block = |id: &str| ("block".to_owned(), Some(id.to_owned()));
    let none = |v: &str| (v.to_owned(), None);
    // rcode
    let r = json!([{"id": "r", "when": {"rcode": ["SERVFAIL", "REFUSED"]}, "verdict": "block"}]);
    assert_eq!(
        decide(
            r.clone(),
            Msg::response(0, "x.example", 1, 5).opt(&[]),
            "x.example"
        )
        .await,
        block("r")
    );
    assert_eq!(
        decide(r, Msg::response(0, "x.example", 1, 0).opt(&[]), "x.example").await,
        none("clean")
    );
    // ede codes and "none"
    let r = json!([{"id": "e", "when": {"ede": [15, 17]}, "verdict": "block"},
                   {"id": "n", "when": {"ede": "none"}, "verdict": "unknown"}]);
    let with = Msg::response(0, "x.example", 1, 0).opt(&[ede(3, b""), ede(17, b"")]);
    assert_eq!(decide(r.clone(), with, "x.example").await, block("e"));
    let other = Msg::response(0, "x.example", 1, 0).opt(&[ede(3, b"")]);
    assert_eq!(decide(r.clone(), other, "x.example").await, none("clean"));
    let without = Msg::response(0, "x.example", 1, 0).opt(&[]);
    assert_eq!(
        decide(r, without, "x.example").await,
        ("unknown".into(), Some("n".into()))
    );
    // ede_text, ASCII case-insensitive
    let r = json!([{"id": "t", "when": {"ede_text": "BLOCKED BY"}, "verdict": "block"}]);
    let m = Msg::response(0, "x.example", 1, 0).opt(&[ede(17, b"Blocked by NextDNS")]);
    assert_eq!(decide(r.clone(), m, "x.example").await, block("t"));
    let m = Msg::response(0, "x.example", 1, 0).opt(&[ede(17, b"Filtered")]);
    assert_eq!(decide(r, m, "x.example").await, none("clean"));
    // answers_in: every A/AAAA inside, and at least one
    let r =
        json!([{"id": "s", "when": {"answers_in": ["0.0.0.0", "::", "192.0.2.0/24"]}, "verdict": "block"}]);
    let all_in = Msg::response(0, "x.example", 1, 0)
        .rr(1, &ptr(12), 1, 60, &a("0.0.0.0"))
        .rr(1, &ptr(12), 1, 60, &a("192.0.2.77"));
    assert_eq!(decide(r.clone(), all_in, "x.example").await, block("s"));
    let one_out = Msg::response(0, "x.example", 1, 0)
        .rr(1, &ptr(12), 1, 60, &a("0.0.0.0"))
        .rr(1, &ptr(12), 1, 60, &a("198.51.100.1"));
    assert_eq!(decide(r.clone(), one_out, "x.example").await, none("clean"));
    let empty = Msg::response(0, "x.example", 1, 0);
    assert_eq!(decide(r.clone(), empty, "x.example").await, none("clean"));
    let v6 = Msg::response(0, "x.example", 28, 0).rr(1, &ptr(12), 28, 60, &aaaa("::"));
    let mut cfg = cfg_with_rules(r);
    cfg["qtype"] = json!("AAAA");
    let ans = lookup(&cfg, answering(v6.build()), "x.example").await.unwrap();
    assert_eq!(verdict_and_rule(&ans), block("s"));
    // cname_suffix: the chain's last name under a suffix
    let r = json!([{"id": "c", "when": {"cname_suffix": ["blockpage.example"]}, "verdict": "block"}]);
    let chain = Msg::response(0, "www.x.example", 1, 0)
        .rr(1, &ptr(12), 5, 60, &n("a.cdn.example"))
        .rr(1, &n("a.cdn.example"), 5, 60, &n("lb.BlockPage.example"))
        .rr(1, &n("lb.blockpage.example"), 1, 60, &a("192.0.2.1"));
    assert_eq!(decide(r.clone(), chain, "www.x.example").await, block("c"));
    let partial = Msg::response(0, "www.x.example", 1, 0).rr(1, &ptr(12), 5, 60, &n("notblockpage.example"));
    assert_eq!(decide(r.clone(), partial, "www.x.example").await, none("clean"));
    let no_chain = Msg::response(0, "www.x.example", 1, 0).rr(1, &ptr(12), 1, 60, &a("192.0.2.1"));
    assert_eq!(decide(r, no_chain, "www.x.example").await, none("clean"));
    // soa true / false
    let r = json!([{"id": "with", "when": {"soa": true}, "verdict": "clean"},
                   {"id": "without", "when": {"soa": false, "rcode": ["NXDOMAIN"]}, "verdict": "unknown"}]);
    let with_soa = Msg::response(0, "nx.example.org", 1, 3).rr(2, &n("example.org"), 6, 60, &soa());
    assert_eq!(
        decide(r.clone(), with_soa, "nx.example.org").await,
        ("clean".into(), Some("with".into()))
    );
    let no_soa = Msg::response(0, "nx.example.org", 1, 3);
    assert_eq!(
        decide(r, no_soa, "nx.example.org").await,
        ("unknown".into(), Some("without".into()))
    );
}

#[tokio::test]
async fn first_match_decides_and_defaults() {
    let r = json!([{"id": "first", "when": {"rcode": ["NXDOMAIN"]}, "verdict": "clean"},
                   {"id": "second", "when": {"rcode": ["NXDOMAIN"]}, "verdict": "block", "score": 9.5}]);
    let m = Msg::response(0, "x.example", 1, 3);
    assert_eq!(
        decide(r, m, "x.example").await,
        ("clean".into(), Some("first".into()))
    );
    let r = json!([{"id": "b", "when": {"rcode": ["NXDOMAIN"]}, "verdict": "block", "score": 9.5}]);
    let a = lookup(
        &cfg_with_rules(r),
        answering(Msg::response(0, "x.example", 1, 3).build()),
        "x.example",
    )
    .await
    .unwrap();
    assert_eq!(
        a.verdict,
        Verdict::Block {
            score: Some(9.5),
            reason: "b".into()
        }
    );
    // No rule matched: NOERROR and NXDOMAIN are Clean, SERVFAIL and REFUSED Unknown.
    for (rc, v) in [(0, "clean"), (3, "clean"), (2, "unknown"), (5, "unknown")] {
        let m = Msg::response(0, "x.example", 1, rc);
        assert_eq!(
            decide(json!([]), m, "x.example").await,
            (v.to_owned(), None),
            "rcode {rc}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Query construction, servers, transports

/// What the module sent: (id, flags, qname wire, qtype, OPT flags, OPT options).
type SentParts = (u16, u16, Vec<u8>, u16, u16, Vec<(u16, Vec<u8>)>);

fn parse_query(q: &[u8]) -> SentParts {
    let id = u16::from_be_bytes([q[0], q[1]]);
    let flags = u16::from_be_bytes([q[2], q[3]]);
    assert_eq!(&q[4..12], &[0, 1, 0, 0, 0, 0, 0, 1], "one question, one OPT");
    let mut i = 12;
    while q[i] != 0 {
        i += 1 + q[i] as usize;
    }
    let qname = q[12..=i].to_vec();
    i += 1;
    let qtype = u16::from_be_bytes([q[i], q[i + 1]]);
    assert_eq!(&q[i + 2..i + 4], &[0, 1], "class IN");
    i += 4;
    assert_eq!(q[i], 0, "OPT owner is the root");
    assert_eq!(&q[i + 1..i + 3], &[0, 41]);
    let opt_flags = u16::from_be_bytes([q[i + 7], q[i + 8]]);
    let rdlen = u16::from_be_bytes([q[i + 9], q[i + 10]]) as usize;
    let mut j = i + 11;
    assert_eq!(j + rdlen, q.len(), "nothing after the OPT");
    let mut opts = vec![];
    while j < q.len() {
        let code = u16::from_be_bytes([q[j], q[j + 1]]);
        let len = u16::from_be_bytes([q[j + 2], q[j + 3]]) as usize;
        opts.push((code, q[j + 4..j + 4 + len].to_vec()));
        j += 4 + len;
    }
    (id, flags, qname, qtype, opt_flags, opts)
}

#[tokio::test]
async fn query_construction_per_transport() {
    for (t, padded) in [("dot", true), ("doh", true), ("udp", false), ("tcp", false)] {
        let dns = answering(Msg::response(0, "Ads.Example.com", 28, 0).build());
        let cfg = json!({"transport": t, "qtype": "AAAA",
                         "servers": [{"ip": "192.0.2.53", "tls_host": "r.example"}]});
        lookup(&cfg, dns.clone(), "ads.example.com").await.unwrap();
        let sent = dns.sent();
        assert_eq!(sent.len(), 1);
        let (server, q) = &sent[0];
        assert_eq!(server.transport, cfg_transport(t));
        let (_id, flags, qname, qtype, opt_flags, opts) = parse_query(q);
        assert_eq!(flags, 0x0100, "{t}: QUERY, RD set, CD clear");
        assert_eq!(qname, b"\x03ads\x07example\x03com\x00");
        assert_eq!(qtype, 28, "AAAA, whatever the client asked");
        assert_eq!(opt_flags & 0x8000, 0, "DO clear");
        assert!(opts.iter().all(|(c, _)| *c != 8), "no Client Subnet");
        if padded {
            assert_eq!(q.len() % 128, 0, "{t}: padded to 128");
            assert_eq!(opts.last().unwrap().0, 12);
        } else {
            assert!(opts.is_empty(), "{t}: no padding");
        }
        match t {
            "dot" => assert_eq!(server.port, 853),
            "doh" => {
                assert_eq!(server.port, 443);
                assert_eq!(server.path.as_deref(), Some("/dns-query"));
            }
            _ => assert_eq!(server.port, 53),
        }
    }
    // The ID is random.
    let dns = answering(Msg::response(0, "x.example", 1, 0).build());
    let cfg = json!({"transport": "udp", "servers": [{"ip": "192.0.2.53"}]});
    for _ in 0..8 {
        lookup(&cfg, dns.clone(), "x.example").await.unwrap();
    }
    let ids: std::collections::BTreeSet<_> = dns.sent().iter().map(|(_, q)| [q[0], q[1]]).collect();
    assert!(ids.len() > 1);
}

fn cfg_transport(t: &str) -> UpstreamProtocol {
    serde_json::from_value(json!(t)).unwrap()
}

#[tokio::test]
async fn answer_with_other_id_or_question_is_invalid() {
    let good = Msg::response(0, "x.example", 1, 0).build();
    // Wrong ID on the first server, a different question on the second, a good answer on the third.
    let dns = MockDns::new(move |s, q| {
        let mut m = with_id(&good, q);
        match s.ip.to_string().as_str() {
            "192.0.2.1" => m[1] ^= 0xff,
            "192.0.2.2" => return Ok(with_id(&Msg::response(0, "y.example", 1, 0).build(), q)),
            _ => {}
        }
        Ok(m)
    });
    let cfg = json!({"transport": "tcp", "servers": [{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}, {"ip": "192.0.2.3"}]});
    let a = lookup(&cfg, dns.clone(), "x.example").await.unwrap();
    assert_eq!(a.detail.unwrap()["server"], "192.0.2.3");
    let tried: Vec<IpAddr> = dns.sent().iter().map(|(s, _)| s.ip).collect();
    assert_eq!(tried.len(), 3);
}

#[tokio::test(start_paused = true)]
async fn servers_in_order_and_failed_ones_skipped_for_30s() {
    let good = Msg::response(0, "x.example", 1, 0).build();
    let fail_first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let ff = fail_first.clone();
    let dns = MockDns::new(move |s: &DnsServer, q| {
        if s.ip.to_string() == "192.0.2.1" && ff.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(DnsClientError::Connect("refused".into()));
        }
        Ok(with_id(&good, q))
    });
    let c = ctx(dns.clone());
    let cfg = json!({"transport": "tcp", "servers": [{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}]});
    let ips = |dns: &MockDns| {
        dns.sent()
            .iter()
            .map(|(s, _)| s.ip.to_string())
            .collect::<Vec<_>>()
    };
    Module.lookup(&c, &cfg, "x.example").await.unwrap();
    assert_eq!(ips(&dns), ["192.0.2.1", "192.0.2.2"]);
    // Within 30 s the failed server is skipped while another works.
    tokio::time::advance(Duration::from_secs(29)).await;
    fail_first.store(false, std::sync::atomic::Ordering::SeqCst);
    Module.lookup(&c, &cfg, "x.example").await.unwrap();
    assert_eq!(ips(&dns)[2..], ["192.0.2.2"]);
    // After 30 s it is first again.
    tokio::time::advance(Duration::from_secs(2)).await;
    Module.lookup(&c, &cfg, "x.example").await.unwrap();
    assert_eq!(ips(&dns)[3..], ["192.0.2.1"]);
}

#[tokio::test(start_paused = true)]
async fn per_server_timeout_moves_on_and_all_failing_is_failed() {
    let good = Msg::response(0, "x.example", 1, 0).build();
    let dns = MockDns::new(move |_, q| Ok(with_id(&good, q)));
    dns.delay("192.0.2.1".parse().unwrap(), Duration::from_secs(5));
    let cfg = json!({"transport": "dot", "servers": [{"ip": "192.0.2.1", "tls_host": "r.example"},
                                                     {"ip": "192.0.2.2", "tls_host": "r.example"}]});
    let started = tokio::time::Instant::now();
    let a = lookup(&cfg, dns.clone(), "x.example").await.unwrap();
    assert_eq!(a.detail.unwrap()["server"], "192.0.2.2");
    assert!(started.elapsed() >= SERVER_TIMEOUT && started.elapsed() < SERVER_TIMEOUT * 2);

    // All failing: Failed.
    let dns = MockDns::new(|_, _| Err(DnsClientError::Connect("down".into())));
    match lookup(&cfg, dns.clone(), "x.example").await {
        Err(LookupError::Failed(e)) => assert!(e.to_string().contains("no valid answer")),
        other => panic!("{other:?}"),
    }
    assert_eq!(dns.sent().len(), 2);
}

/// A skipped server is still tried, last, when every other one fails.
#[tokio::test(start_paused = true)]
async fn skipped_server_tried_last_when_the_others_fail() {
    let good = Msg::response(0, "x.example", 1, 0).build();
    // Which server is down: .1 first, then .2.
    let down = Arc::new(std::sync::Mutex::new("192.0.2.1"));
    let d = down.clone();
    let dns = MockDns::new(move |s: &DnsServer, q| {
        if s.ip.to_string() == *d.lock().unwrap() {
            return Err(DnsClientError::Connect("down".into()));
        }
        Ok(with_id(&good, q))
    });
    // One context across lookups, so the skip carries over.
    let c = ctx(dns.clone());
    let cfg = json!({"transport": "tcp", "servers": [{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}]});
    Module.lookup(&c, &cfg, "x.example").await.unwrap();
    // .1 is skipped for 30 s; now .2 fails too, and .1 is tried after it.
    *down.lock().unwrap() = "192.0.2.2";
    tokio::time::advance(Duration::from_secs(5)).await;
    let a = Module.lookup(&c, &cfg, "x.example").await.unwrap();
    assert_eq!(a.detail.unwrap()["server"], "192.0.2.1");
    let ips: Vec<String> = dns.sent().iter().map(|(s, _)| s.ip.to_string()).collect();
    assert_eq!(ips, ["192.0.2.1", "192.0.2.2", "192.0.2.2", "192.0.2.1"]);
}

/// providers.md §5 Transport: a truncated answer over a stream (TCP, DoT, DoH, or the TCP retry
/// of a truncated UDP answer) is not a valid answer: the next server is tried.
#[tokio::test]
async fn truncated_answer_over_a_stream_is_invalid() {
    let tc = Msg::response(0, "x.example", 1, 0).tc().build();
    let sinkhole = Msg::response(0, "x.example", 1, 0)
        .rr(1, &ptr(12), 1, 60, &a("0.0.0.0"))
        .build();
    let rules = json!([{"id": "sinkhole", "when": {"answers_in": ["0.0.0.0"]}, "verdict": "block"}]);
    for t in ["tcp", "dot", "doh", "udp"] {
        let (tc2, good) = (tc.clone(), sinkhole.clone());
        // The first server always truncates; the second answers in full.
        let dns = MockDns::new(move |s: &DnsServer, q| {
            Ok(if s.ip.to_string() == "192.0.2.1" {
                with_id(&tc2, q)
            } else {
                with_id(&good, q)
            })
        });
        let cfg = json!({"transport": t, "rules": rules,
                         "servers": [{"ip": "192.0.2.1", "tls_host": "r.example"},
                                     {"ip": "192.0.2.2", "tls_host": "r.example"}]});
        let a = lookup(&cfg, dns.clone(), "x.example").await.unwrap();
        assert_eq!(a.detail.as_ref().unwrap()["server"], "192.0.2.2", "{t}");
        assert_eq!(
            verdict_and_rule(&a),
            ("block".into(), Some("sinkhole".into())),
            "{t}"
        );
        let sent: Vec<(String, UpstreamProtocol)> = dns
            .sent()
            .iter()
            .map(|(s, _)| (s.ip.to_string(), s.transport))
            .collect();
        let expect = if t == "udp" { 3 } else { 2 };
        assert_eq!(sent.len(), expect, "{t}: {sent:?}");
        // Only one server, still truncated: no valid answer.
        let dns = answering(tc.clone());
        let cfg = json!({"transport": t, "servers": [{"ip": "192.0.2.1", "tls_host": "r.example"}]});
        match lookup(&cfg, dns, "x.example").await {
            Err(LookupError::Failed(e)) => assert!(e.to_string().contains("truncated"), "{t}: {e}"),
            other => panic!("{t}: {other:?}"),
        }
    }
}

/// A server client whose first server (192.0.2.1) truncates over UDP and never answers over a
/// stream (it waits out the timeout it is given); every other server answers.
struct FirstSilentOverStreams {
    good: Vec<u8>,
    tc: Vec<u8>,
    sent: std::sync::Mutex<Vec<(String, UpstreamProtocol)>>,
}

#[async_trait::async_trait]
impl crate::ctx::DnsServerClient for FirstSilentOverStreams {
    async fn query(&self, s: &DnsServer, q: &[u8], timeout: Duration) -> Result<Vec<u8>, DnsClientError> {
        self.sent.lock().unwrap().push((s.ip.to_string(), s.transport));
        match (s.ip.to_string() == "192.0.2.1", s.transport) {
            (true, UpstreamProtocol::Udp) => Ok(with_id(&self.tc, q)),
            (true, _) => {
                tokio::time::sleep(timeout).await;
                Err(DnsClientError::Timeout)
            }
            (false, _) => Ok(with_id(&self.good, q)),
        }
    }
}

/// providers.md §5 Transport: the per-server timeout fits the time the call has, so a silent
/// first server gives way to the next even when `async_timeout_ms` is shorter than
/// [`SERVER_TIMEOUT`] (over UDP, the TCP retry of a truncated answer included); the silent
/// server is then skipped.
#[tokio::test(start_paused = true)]
async fn per_server_timeout_fits_a_short_async_timeout() {
    use crate::client::{AsyncOptions, AsyncResult, ClientOptions, LookupClient, ProviderSpec, Role};
    use picket_api::edge_config::LookupSettings;
    for t in ["tcp", "udp", "dot"] {
        let dns = Arc::new(FirstSilentOverStreams {
            good: Msg::response(0, "x.example", 1, 0).build(),
            tc: Msg::response(0, "x.example", 1, 0).tc().build(),
            sent: Default::default(),
        });
        let d2 = dns.clone();
        let factory: crate::ctx::ConnectionFactory = Arc::new(move |_: &str| {
            connections(
                MockHttp::new(|_| Err(crate::ctx::HttpError::Refused("no".into()))),
                d2.clone(),
            )
        });
        let settings = LookupSettings {
            async_timeout_ms: 1000,
            ..LookupSettings::default()
        };
        let client = LookupClient::new(
            ProviderSpec {
                id: "q9".into(),
                module: "dns".into(),
                config: json!({"transport": t, "servers": [{"ip": "192.0.2.1", "tls_host": "r.example"},
                                                           {"ip": "192.0.2.2", "tls_host": "r.example"}]}),
                generation: "3f9a0c17d2e84b65".into(),
                settings,
            },
            &Default::default(),
            ClientOptions::new(Role::Core, Arc::new(crate::Registry::builtin()), factory),
        );
        // Core has no RAM tier: each lookup calls.
        for i in 0..3 {
            let o = client.lookup_async("x.example", AsyncOptions::default()).await;
            match &o.result {
                AsyncResult::Answer { detail, .. } => {
                    assert_eq!(detail.as_ref().unwrap()["server"], "192.0.2.2", "{t}")
                }
                other => panic!("{t} lookup {i}: {other:?}"),
            }
            assert!(o.elapsed < Duration::from_millis(1000), "{t}: {:?}", o.elapsed);
        }
        let first: Vec<UpstreamProtocol> = dns
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(ip, _)| ip == "192.0.2.1")
            .map(|(_, t)| *t)
            .collect();
        let expect = if t == "udp" { 2 } else { 1 };
        assert_eq!(
            first.len(),
            expect,
            "{t}: the silent server is tried once, then skipped: {first:?}"
        );
    }
}

#[test]
fn server_budget_fits_the_time_left() {
    use super::{MIN_SERVER_TIMEOUT, server_budget};
    let now = tokio::time::Instant::now();
    let ms = Duration::from_millis;
    // No deadline (a module called directly), or plenty of time: SERVER_TIMEOUT.
    assert_eq!(server_budget(now, None, false), SERVER_TIMEOUT);
    assert_eq!(server_budget(now, Some(now + ms(10_000)), false), SERVER_TIMEOUT);
    assert_eq!(server_budget(now, Some(now + ms(10_000)), true), SERVER_TIMEOUT);
    // Less: half of it while servers remain, all of it for the last one.
    assert_eq!(server_budget(now, Some(now + ms(1000)), false), ms(500));
    assert_eq!(server_budget(now, Some(now + ms(1000)), true), ms(1000));
    // At least MIN_SERVER_TIMEOUT while that much is left, never more than is left.
    assert_eq!(server_budget(now, Some(now + ms(150)), false), MIN_SERVER_TIMEOUT);
    assert_eq!(server_budget(now, Some(now + ms(60)), false), ms(60));
    assert_eq!(server_budget(now, Some(now), false), Duration::ZERO);
    assert_eq!(server_budget(now + ms(5), Some(now), true), Duration::ZERO);
}

/// A call dropped while a server is being asked marks that server failed.
#[tokio::test(start_paused = true)]
async fn dropped_call_marks_the_server_it_was_asking_failed() {
    let good = Msg::response(0, "x.example", 1, 0).build();
    let dns = MockDns::new(move |_, q| Ok(with_id(&good, q)));
    dns.delay("192.0.2.1".parse().unwrap(), Duration::from_secs(60));
    let c = ctx(dns.clone());
    let cfg = json!({"transport": "tcp", "servers": [{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}]});
    let dropped =
        tokio::time::timeout(Duration::from_millis(100), Module.lookup(&c, &cfg, "x.example")).await;
    assert!(dropped.is_err());
    let a = Module.lookup(&c, &cfg, "x.example").await.unwrap();
    assert_eq!(a.detail.unwrap()["server"], "192.0.2.2");
    assert_eq!(dns.sent().len(), 2, "192.0.2.1 skipped");
}

#[tokio::test]
async fn truncated_udp_answer_retried_over_tcp() {
    let tc = Msg::response(0, "x.example", 1, 0).tc().build();
    let full = Msg::response(0, "x.example", 1, 0)
        .rr(1, &ptr(12), 1, 60, &a("0.0.0.0"))
        .build();
    let dns = MockDns::new(move |s, q| {
        Ok(match s.transport {
            UpstreamProtocol::Udp => with_id(&tc, q),
            _ => with_id(&full, q),
        })
    });
    let cfg = json!({"transport": "udp", "servers": [{"ip": "192.168.1.1"}],
                     "rules": [{"id": "sinkhole", "when": {"answers_in": ["0.0.0.0"]}, "verdict": "block"}]});
    let a = lookup(&cfg, dns.clone(), "x.example").await.unwrap();
    assert_eq!(verdict_and_rule(&a), ("block".into(), Some("sinkhole".into())));
    let sent = dns.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].0.transport, UpstreamProtocol::Udp);
    assert_eq!(sent[1].0.transport, UpstreamProtocol::Tcp);
    assert_eq!(sent[1].0.port, 53);
    assert_eq!(sent[0].1, sent[1].1, "the same query over TCP");
}

// ---------------------------------------------------------------------------------------------
// Config, schema, presets, self-test

fn check(cfg: Value) -> Result<Config, String> {
    serde_json::from_value::<Config>(cfg).map_err(|e| e.to_string())
}

#[test]
fn config_checks() {
    let srv = json!({"ip": "192.0.2.1", "tls_host": "r.example"});
    let base = |extra: Value| {
        let mut c = json!({"servers": [srv.clone()]});
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    };
    assert!(check(base(json!({}))).is_ok());
    let c = check(base(json!({}))).unwrap();
    assert_eq!(c.transport, UpstreamProtocol::Dot, "dot by default");
    assert_eq!(c.qtype, 1, "A by default");
    for (bad, why) in [
        (json!({"servers": []}), "servers"),
        (json!({"servers": vec![srv.clone(); 9]}), "servers"),
        (json!({"servers": [{"ip": "192.0.2.1"}]}), "tls_host"),
        (
            json!({"servers": [{"ip": "0.0.0.0", "tls_host": "r.example"}]}),
            "ip",
        ),
        (
            json!({"servers": [{"ip": "192.0.2.1", "tls_host": "bad host"}]}),
            "tls_host",
        ),
        (
            json!({"transport": "doh", "servers": [{"ip": "192.0.2.1", "tls_host": "r.example", "path": "x"}]}),
            "path",
        ),
        // Core's `url` and the edge's `http` would read these differently (providers.md §5).
        (
            json!({"transport": "doh", "servers": [{"ip": "192.0.2.1", "tls_host": "r.example", "path": "/a/../dns-query"}]}),
            "path",
        ),
        (
            json!({"transport": "doh", "servers": [{"ip": "192.0.2.1", "tls_host": "r.example", "path": "/a\\b"}]}),
            "path",
        ),
        (
            json!({"servers": [{"ip": "192.0.2.1", "tls_host": "r.example", "port": 0}]}),
            "port",
        ),
        (
            json!({"servers": [{"ip": "192.0.2.1", "tls_host": "r.example", "trust_store": "nope"}]}),
            "trust_store",
        ),
        (json!({"qtype": "MX"}), "MX"),
        (
            json!({"rules": [{"id": "Bad-Id", "when": {"soa": true}, "verdict": "block"}]}),
            "id",
        ),
        (
            json!({"rules": [{"id": "x", "when": {}, "verdict": "block"}]}),
            "at least one",
        ),
        (
            json!({"rules": [{"id": "x", "when": {"rcode": []}, "verdict": "block"}]}),
            "rcode",
        ),
        (
            json!({"rules": [{"id": "x", "when": {"rcode": ["NOTIMP"]}, "verdict": "block"}]}),
            "NOTIMP",
        ),
        (
            json!({"rules": [{"id": "x", "when": {"ede": "some"}, "verdict": "block"}]}),
            "ede",
        ),
        (
            json!({"rules": [{"id": "x", "when": {"answers_in": ["not-an-ip"]}, "verdict": "block"}]}),
            "answers_in",
        ),
        (
            json!({"rules": [{"id": "x", "when": {"cname_suffix": ["a..b"]}, "verdict": "block"}]}),
            "cname_suffix",
        ),
        (
            json!({"rules": [{"id": "x", "when": {"ede_text": ""}, "verdict": "block"}]}),
            "ede_text",
        ),
        (
            json!({"rules": [{"id": "x", "when": {"soa": true}, "verdict": "clean", "score": 1.0}]}),
            "score",
        ),
        (
            json!({"rules": [{"id": "x", "when": {"soa": true}, "verdict": "block"},
                          {"id": "x", "when": {"soa": false}, "verdict": "block"}]}),
            "duplicate",
        ),
        (
            json!({"rules": vec![json!({"id": "x", "when": {"soa": true}, "verdict": "block"}); 33]}),
            "rules",
        ),
        (
            json!({"self_test": {"name": "bad name", "expect": "block", "cron": "0 * * * *"}}),
            "self_test.name",
        ),
        (
            json!({"self_test": {"name": "isitblocked.org", "expect": "block", "cron": "every hour"}}),
            "self_test.cron",
        ),
    ] {
        let e = check(base(bad.clone())).expect_err(&bad.to_string());
        assert!(e.contains(why), "{bad}: {e}");
    }
    // Plain transports ignore TLS fields and need no tls_host.
    let c =
        check(json!({"transport": "udp", "servers": [{"ip": "192.168.1.1", "tls_host": "x", "path": "/p"}]}))
            .unwrap();
    assert_eq!(c.servers[0].dns.tls_host, None);
    assert_eq!(c.servers[0].dns.path, None);
    // 32 rules are fine.
    let rules: Vec<Value> = (0..32)
        .map(|i| json!({"id": format!("r{i}"), "when": {"soa": true}, "verdict": "block"}))
        .collect();
    assert!(check(base(json!({"rules": rules}))).is_ok());
}

#[test]
fn schema_warns_about_plain_dns() {
    let schema = serde_json::to_value(Module.config_schema()).unwrap();
    let w = &schema["properties"]["transport"]["x-picket-warning"];
    assert_eq!(w["when"], json!(["udp", "tcp"]));
    assert_eq!(w["text"], PLAIN_DNS_WARNING);
    assert_eq!(
        PLAIN_DNS_WARNING,
        "Plain DNS is unencrypted. Every name this provider looks up is sent in clear text, and anyone on the network path can read it or change the answer, letting a blocked name through or blocking any name. Use DoT or DoH unless the resolver offers neither."
    );
    assert_eq!(schema["properties"]["servers"]["maxItems"], 8);
    assert_eq!(schema["properties"]["rules"]["maxItems"], 32);
}

/// providers.md §5 `dns`: the `quad9` preset builds exactly the config the spec gives.
#[test]
fn quad9_preset_exactly() {
    let spec = json!({"transport": "dot",
     "servers": [{"ip": "9.9.9.9", "tls_host": "dns.quad9.net"}, {"ip": "149.112.112.112", "tls_host": "dns.quad9.net"},
                 {"ip": "2620:fe::fe", "tls_host": "dns.quad9.net"}, {"ip": "2620:fe::9", "tls_host": "dns.quad9.net"}],
     "qtype": "A",
     "rules": [{"id": "blocked",  "when": {"ede": [15]}, "verdict": "block"},
               {"id": "censored", "when": {"ede": [16]}, "verdict": "block"},
               {"id": "filtered", "when": {"ede": [17]}, "verdict": "block"},
               {"id": "nxdomain_without_soa", "when": {"rcode": ["NXDOMAIN"], "soa": false, "ede": "none"}, "verdict": "unknown"}],
     "self_test": {"name": "isitblocked.org", "expect": "block", "cron": "0 * * * *"}});
    let presets = Module.presets();
    let q9 = presets.iter().find(|p| p.id == "quad9").unwrap();
    let (cfg, cat) = (q9.build)(&json!({})).unwrap();
    assert_eq!(cfg, spec);
    assert_eq!(cat, Some(Category::Security));
    assert_eq!((q9.build)(&Value::Null).unwrap().0, spec);
    let (doh, _) = (q9.build)(&json!({"transport": "doh"})).unwrap();
    assert_eq!(doh["transport"], "doh");
    for s in doh["servers"].as_array().unwrap() {
        assert_eq!(s["tls_host"], "dns.quad9.net");
        assert_eq!(s["path"], "/dns-query");
    }
    assert_eq!(doh["rules"], spec["rules"]);
    assert!(
        (q9.build)(&json!({"transport": "udp"})).is_err(),
        "presets don't offer plain DNS"
    );
    check(cfg).unwrap();
    check(doh).unwrap();
}

#[test]
fn nextdns_preset_exactly() {
    let presets = Module.presets();
    let nd = presets.iter().find(|p| p.id == "nextdns").unwrap();
    let (cfg, cat) = (nd.build)(&json!({"profile": "abc123", "self_test": "denied.example"})).unwrap();
    assert_eq!(cat, Some(Category::Mixed));
    assert_eq!(
        cfg,
        json!({"transport": "dot",
               "servers": [{"ip": "45.90.28.0", "tls_host": "abc123.dns.nextdns.io"},
                           {"ip": "45.90.30.0", "tls_host": "abc123.dns.nextdns.io"},
                           {"ip": "2a07:a8c0::", "tls_host": "abc123.dns.nextdns.io"},
                           {"ip": "2a07:a8c1::", "tls_host": "abc123.dns.nextdns.io"}],
               "qtype": "A",
               "rules": [{"id": "blocked", "when": {"ede": [15, 16, 17]}, "verdict": "block"},
                         {"id": "sinkhole", "when": {"answers_in": ["0.0.0.0", "::"]}, "verdict": "block"}],
               "self_test": {"name": "denied.example", "expect": "block", "cron": "0 * * * *"}})
    );
    let (doh, _) = (nd.build)(&json!({"profile": "abc123", "transport": "doh"})).unwrap();
    for s in doh["servers"].as_array().unwrap() {
        assert_eq!(s["tls_host"], "dns.nextdns.io");
        assert_eq!(s["path"], "/abc123");
    }
    assert!(doh.get("self_test").is_none());
    assert!((nd.build)(&json!({"profile": "../x"})).is_err());
    assert!((nd.build)(&json!({})).is_err());
    check(cfg).unwrap();
    check(doh).unwrap();
}

#[test]
fn self_test_from_config() {
    let t = Module.self_test(&quad9_config(Encrypted::Dot)).unwrap();
    assert_eq!(t.name, "isitblocked.org");
    assert_eq!(t.expect, Expect::Block);
    assert_eq!(t.cron, "0 * * * *");
    assert!(Module.self_test(&cfg_with_rules(json!([]))).is_none());
}

/// README §2 Secrets: a config error never shows part of a secret: a value isn't cut before
/// redaction, and quoted values are redacted in their escaped form.
#[tokio::test]
async fn config_errors_never_show_part_of_a_secret() {
    use crate::client::{AsyncOptions, AsyncResult, ClientOptions, LookupClient, ProviderSpec, Role};
    let long = "L".repeat(40) + &"z".repeat(60);
    for (value, prefix) in [
        (long.as_str(), "LLLLLLLLLLLLLLLLLLLL"),
        ("ab\"cd\\ef..x", "ab\\\"cd"),
    ] {
        for field in ["answers_in", "cname_suffix"] {
            let secrets = std::collections::BTreeMap::from([("s".to_owned(), value.to_owned())]);
            let client = LookupClient::new(
                ProviderSpec {
                    id: "q9".into(),
                    module: "dns".into(),
                    config: json!({"transport": "tcp", "servers": [{"ip": "192.0.2.1"}],
                                   "rules": [{"id": "r", "when": {field: ["${secret:s}"]}, "verdict": "block"}]}),
                    generation: "3f9a0c17d2e84b65".into(),
                    settings: Default::default(),
                },
                &secrets,
                ClientOptions::new(
                    Role::Core,
                    Arc::new(crate::Registry::builtin()),
                    Arc::new(|_: &str| crate::ctx::Connections::none()),
                ),
            );
            match client
                .lookup_async("x.example", AsyncOptions::default())
                .await
                .result
            {
                AsyncResult::Error { message, .. } => {
                    assert!(message.contains(field), "{message}");
                    assert!(!message.contains(prefix), "{field}: {message}");
                    assert!(
                        !message.contains("LLLL") && !message.contains("cd"),
                        "{field}: {message}"
                    );
                }
                other => panic!("{other:?}"),
            }
        }
    }
}

/// Review round 2, CR7: errors quote a value as resolved, never transformed. A secret with its own
/// surrounding spaces is quoted whole (and redacted), not trimmed into a form the redactor doesn't
/// know; a cron expression's error doesn't quote croner's upper-cased field of it.
#[tokio::test]
async fn config_errors_quote_values_untransformed() {
    use crate::client::{AsyncOptions, AsyncResult, ClientOptions, LookupClient, ProviderSpec, Role};
    let cases = [
        (
            "  verySecretValue123  ",
            json!({"transport": "tcp", "servers": [{"ip": "192.0.2.1"}],
                   "rules": [{"id": "r", "when": {"answers_in": ["${secret:s}"]}, "verdict": "block"}]}),
            "answers_in",
            "verysecretvalue",
        ),
        (
            "* * * * qwertyuiop",
            json!({"transport": "tcp", "servers": [{"ip": "192.0.2.1"}],
                   "self_test": {"name": "test.example", "expect": "block", "cron": "${secret:s}"}}),
            "self_test.cron",
            "qwerty",
        ),
    ];
    for (value, config, field, part) in cases {
        let secrets = std::collections::BTreeMap::from([("s".to_owned(), value.to_owned())]);
        let client = LookupClient::new(
            ProviderSpec {
                id: "q9".into(),
                module: "dns".into(),
                config,
                generation: "3f9a0c17d2e84b65".into(),
                settings: Default::default(),
            },
            &secrets,
            ClientOptions::new(
                Role::Core,
                Arc::new(crate::Registry::builtin()),
                Arc::new(|_: &str| crate::ctx::Connections::none()),
            ),
        );
        match client
            .lookup_async("x.example", AsyncOptions::default())
            .await
            .result
        {
            AsyncResult::Error { message, .. } => {
                assert!(message.contains(field), "{message}");
                assert!(!message.to_ascii_lowercase().contains(part), "{field}: {message}");
            }
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn invalid_config_is_other() {
    let dns = answering(Msg::response(0, "x.example", 1, 0).build());
    match lookup(&json!({"servers": []}), dns, "x.example").await {
        Err(LookupError::Other(e)) => assert!(e.to_string().contains("servers")),
        other => panic!("{other:?}"),
    }
}
