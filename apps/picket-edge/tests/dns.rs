//! The DNS data path end to end, in process (build-and-test.md §5 rows "Edge pipeline", "Edge
//! EDE", "Failure semantics", "Clients and profile choice", the edge side of "Lookup sharing",
//! and edge.md §4–§10, §16): an edge started against the mock core with a config, fake upstream
//! servers over UDP/TCP/DoT/DoH answering with crafted messages, bundles compiled in memory, and
//! scripted lookup modules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod dnsh;
mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use serde_json::{Value, json};

use dnsh::*;
use picket_api::time::Timestamp;
use picket_edge::service::{self, Options, Running, Tuning};
use picket_rules::matcher::BundleAction;
use support::{MockCore, wait_until, write_edge_json};

struct Dirs {
    _tmp: tempfile::TempDir,
    config: PathBuf,
    data: PathBuf,
    run: PathBuf,
    result: PathBuf,
}

fn dirs() -> Dirs {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Dirs {
        config: root.join("dev/edge.json"),
        data: root.join("dev/edge"),
        run: root.join("dev/run"),
        result: root.join("bin/update-result.json"),
        _tmp: tmp,
    }
}

fn tuning(d: &Dirs) -> Tuning {
    let mut t = Tuning {
        platform: Some(picket_edge::paths::HostPlatform::Debian),
        clock: Some(picket_edge::clock::Clock::fixed(true)),
        neighbours: Some(picket_edge::neighbours::Neighbours::new()),
        update_result: Some(d.result.clone()),
        service: Some(false),
        firmware_file: d.data.join("no-such-version-file"),
        import_every: Duration::from_millis(200),
        ..Default::default()
    };
    t.session.heartbeat = Duration::from_millis(200);
    t.session.backoff_min = Duration::from_millis(50);
    t.session.backoff_max = Duration::from_millis(200);
    t.convergence.retry_min = Duration::from_millis(50);
    t.convergence.retry_max = Duration::from_millis(200);
    t.convergence.every = Duration::from_millis(300);
    t.shipper.tick = Duration::from_millis(50);
    t.shipper.retry_min = Duration::from_millis(20);
    t.shipper.retry_max = Duration::from_millis(100);
    t.supervisor.min = Duration::from_millis(20);
    t.dns.watchdog_every = Duration::from_millis(100);
    t.dns.rebind_every = Duration::from_millis(200);
    t.dns.certs_every = Duration::from_millis(200);
    t.dns.attempt_timeout = Duration::from_millis(600);
    t.dns.resolve_budget = Duration::from_millis(1500);
    t.dns.csr_backoff = (Duration::from_millis(50), Duration::from_millis(200));
    t.dns.down_after = Duration::from_millis(300);
    t
}

struct Env {
    core: MockCore,
    _d: Dirs,
    r: Running,
}

impl Env {
    fn edge(&self) -> &Arc<picket_edge::edge::Edge> {
        &self.r.edge
    }

    fn addr(&self, listener: &str) -> std::net::SocketAddr {
        self.edge().dns.listeners.local_addrs(listener)[0]
    }

    fn dns(&self) -> std::net::SocketAddr {
        self.addr("lan-dns")
    }

    fn q_records(&self) -> Vec<Value> {
        self.core
            .with(|s| s.logs.iter().filter(|l| l["t"] == "q").cloned().collect())
    }

    async fn q_record(&self, qname: &str) -> Value {
        let mut found = None;
        wait_until(T, || {
            found = self.q_records().into_iter().rev().find(|r| r["qname"] == qname);
            found.is_some()
        })
        .await;
        found.unwrap_or_else(|| panic!("no q record for {qname}: {:?}", self.q_records()))
    }

    async fn q_record_where(&self, qname: &str, pred: impl Fn(&Value) -> bool) -> Value {
        let mut found = None;
        wait_until(T, || {
            found = self
                .q_records()
                .into_iter()
                .rev()
                .find(|r| r["qname"] == qname && pred(r));
            found.is_some()
        })
        .await;
        found.unwrap_or_else(|| panic!("no matching q record for {qname}: {:?}", self.q_records()))
    }

    async fn set_config(&self, cfg: &Value) {
        let edge = Arc::clone(self.edge());
        // Bundles these tests set by hand (`set_bundles`) aren't named in the config object, so
        // the activator unloads them after the swap (edge.md §13): put them back once it is done.
        let held: Vec<(String, Arc<picket_bundle::matcher::Bundle>)> = edge
            .active()
            .bundles
            .bundles
            .iter()
            .map(|(k, b)| (k.to_string(), Arc::clone(b)))
            .collect();
        let id = self.core.set_config(cfg);
        self.core.changed(&id);
        assert!(
            wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())
                && edge.bundles.record().object.as_deref() == Some(id.as_str()))
            .await,
            "config goes live"
        );
        if !held.is_empty() {
            set_bundles(
                &edge,
                held.iter().map(|(k, b)| (k.as_str(), Arc::clone(b))).collect(),
            );
        }
        edge.dns.listeners.wake.notify_one();
    }

    async fn shutdown(self) {
        self.r.shutdown().await;
    }
}

fn base_config(groups: Value, upstreams: Value) -> Value {
    json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
        "listeners": [{"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"}],
        "default_profile": "default",
        "profiles": {"default": {"upstream": "g"}},
        "upstreams": upstreams,
        "upstream_groups": groups,
        "logging": {"spool_after_s": 1},
    })
}

fn one_upstream(u: &FakeUpstream, proto: &str) -> Value {
    let up = if proto == "udp" || proto == "tcp" {
        plain_upstream(u, proto)
    } else {
        tls_upstream(u, proto)
    };
    base_config(
        json!({"g": {"upstreams": ["up1"], "strategy": "failover", "optimistic": true}}),
        json!({"up1": up}),
    )
}

async fn start(cfg: Value, tweak: impl FnOnce(&mut Tuning)) -> Env {
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&cfg);
    let mut t = tuning(&d);
    tweak(&mut t);
    let r = service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        t,
        |_| {},
    )
    .await
    .unwrap();
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await,
        "config live"
    );
    let has_dns = cfg["listeners"]
        .as_array()
        .is_some_and(|l| l.iter().any(|x| x["id"] == "lan-dns"));
    assert!(
        wait_until(T, || !has_dns
            || !edge.dns.listeners.local_addrs("lan-dns").is_empty())
        .await,
        "listener bound: {:?}",
        edge.dns.listeners.status()
    );
    Env { core, _d: d, r }
}

fn ok_upstream() -> impl Fn(&Msg, &[u8]) -> Act + Send + Sync + 'static {
    |m: &Msg, _q: &[u8]| match m.qtype {
        1 => Act::Answer(Ans::records(vec![a(&m.qname, "93.184.216.34", 300)])),
        28 => Act::Answer(Ans::records(vec![aaaa(&m.qname, "2606:2800:220:1::1", 300)])),
        _ => Act::Answer(Ans {
            authority: vec![soa(&m.qname, 300, 60)],
            opt: true,
            ..Default::default()
        }),
    }
}

// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resolves_over_udp_and_tcp_caches_and_logs_with_answers() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    let addr = env.dns();
    let q = Q::new("www.example.com", 1);
    let m = udp_q(addr, &q).await;
    assert_eq!(m.rcode, 0);
    assert_eq!(
        m.ips(),
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(!m.ad, "AD is always cleared (hard rule 6)");
    assert_eq!(up.count(), 1);
    // A cache hit: no new upstream query; the TTL counts down from the original.
    let m2 = udp_q(addr, &Q::new("WWW.Example.com", 1)).await;
    assert_eq!(m2.ips(), m.ips());
    assert_eq!(up.count(), 1, "served from the cache");
    assert!(m2.ttls()[0] <= 300);
    // TCP, pipelined: two queries on one connection.
    let r = tcp(
        addr,
        &[
            Q::new("a.example.com", 1).bytes(),
            Q::new("b.example.com", 28).bytes(),
        ],
    )
    .await;
    assert_eq!(r.len(), 2);
    // The upstream query was built by the edge: RD, a new ID, its own OPT, no client options.
    let s = &up.seen()[0];
    assert!(s.msg.rd);
    assert!(s.msg.opt.is_some());
    // The log: a q record referencing the answer, which travels with it.
    let rec = env.q_record("www.example.com").await;
    assert_eq!(rec["decision"], "allow");
    assert_eq!(rec["proto"], "udp");
    assert_eq!(rec["listener"], "lan-dns");
    assert_eq!(rec["profile"], "default");
    assert_eq!(rec["answers"], json!(["93.184.216.34"]));
    assert_eq!(rec["upstream"]["group"], "g");
    assert_eq!(rec["upstream"]["upstream"], "up1");
    assert!(rec["answer_id"].is_string());
    assert!(rec["edns"]["udp"].as_u64().is_some());
    let answer_id = rec["answer_id"].as_str().unwrap().to_owned();
    assert!(
        env.core.with(|s| s
            .logs
            .iter()
            .any(|l| l["t"] == "answer" && l["id"] == answer_id.as_str())),
        "the answer record ships with the q record"
    );
    // Metrics: decisions, cache hits and misses, per-upstream queries.
    let m = env.edge().metrics.snapshot();
    assert!(m.cache_hits >= 1 && m.cache_misses >= 1);
    assert!(m.upstream["up1"].queries >= 1);
    assert_eq!(
        m.queries,
        m.by_decision.allow
            + m.by_decision.block
            + m.by_decision.rewrite
            + m.by_decision.refused
            + m.by_decision.servfail
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_queries_and_owner_decisions() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    let addr = env.dns();
    // A header claiming 65,535 questions: FORMERR, before the body is decoded.
    let mut h = vec![0x12, 0x34, 0x01, 0x00, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
    h.extend_from_slice(&[0xC0, 0x0C]);
    let r = parse(&udp(addr, &h).await.unwrap());
    assert_eq!((r.id, r.rcode), (0x1234, 1));
    // QR set: no reply at all.
    let mut resp = Q::new("x.example", 1).bytes();
    resp[2] |= 0x80;
    assert!(udp(addr, &resp).await.is_none());
    // An opcode other than QUERY: NOTIMP.
    let mut notify = Q::new("x.example", 1).bytes();
    notify[2] |= 4 << 3;
    assert_eq!(parse(&udp(addr, &notify).await.unwrap()).rcode, 4);
    // EDNS version above 0: BADVERS (extended rcode 16).
    let mut v1 = Q::new("x.example", 1).bytes();
    let n = v1.len();
    v1[n - 5] = 1; // the OPT's VERSION byte
    assert_eq!(parse(&udp(addr, &v1).await.unwrap()).rcode, 16);
    // Owner decision S7: QCLASS * gets NOTIMP, never forwarded; so do meta qtypes.
    let mut any_class = Q::new("x.example", 1);
    any_class.qclass = 255;
    assert_eq!(udp_q(addr, &any_class).await.rcode, 4);
    assert_eq!(udp_q(addr, &Q::new("x.example", 252)).await.rcode, 4, "AXFR");
    // Not recursion-desired: REFUSED (edge.md §16).
    let mut nord = Q::new("x.example", 1);
    nord.rd = false;
    assert_eq!(udp_q(addr, &nord).await.rcode, 5);
    assert_eq!(up.count(), 0, "none of these reached an upstream");
    assert!(env.edge().metrics.snapshot().rejected >= 5);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocks_under_each_block_response_with_ede_and_canaries() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    merge(
        &mut cfg,
        json!({"profiles": {
            "default": {"upstream": "g", "block": ["block-common", "canaries"]},
            "nx": {"upstream": "g", "block": ["block-common", "canaries"], "block_response": {"type": "nxdomain", "ttl": 20}},
            "nd": {"upstream": "g", "block": ["block-common", "canaries"], "block_response": {"type": "nodata"}},
            "rf": {"upstream": "g", "block": ["block-common", "canaries"], "block_response": {"type": "refused"}},
            "cu": {"upstream": "g", "block": ["block-common", "canaries"], "block_response": {"type": "custom_ip", "ipv4": "192.0.2.99", "ttl": 30}},
        }}),
    );
    merge(
        &mut cfg,
        json!({"listeners": [
            {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        ]}),
    );
    let env = start(cfg.clone(), |_| {}).await;
    set_bundles(
        env.edge(),
        vec![
            (
                "block-common",
                bundle("block-common", BundleAction::Block, &["||ads.example.com^"]),
            ),
            (
                "canaries",
                bundle(
                    "canaries",
                    BundleAction::Block,
                    &["||canary.picket.test^$dnsrewrite=NXDOMAIN;;"],
                ),
            ),
        ],
    );
    let addr = env.dns();
    // null_ip (default): 0.0.0.0 for A, :: for AAAA, NODATA (with SOA) for others; EDE 15 + 4.
    let m = udp_q(addr, &Q::new("x.ads.example.com", 1)).await;
    assert_eq!(m.rcode, 0);
    assert_eq!(m.ips(), vec!["0.0.0.0".parse::<std::net::IpAddr>().unwrap()]);
    assert_eq!(m.ttls(), vec![10]);
    assert_eq!(m.ede_codes(), vec![15, 4]);
    let text = &m.ede()[0].1;
    assert!(text.starts_with("bundle=block-common@"), "{text}");
    assert!(text.contains(" block="), "{text}");
    let m = udp_q(addr, &Q::new("x.ads.example.com", 28)).await;
    assert_eq!(m.ips(), vec!["::".parse::<std::net::IpAddr>().unwrap()]);
    let m = udp_q(addr, &Q::new("x.ads.example.com", 16)).await;
    assert_eq!(
        (m.rcode, m.answers.len(), m.authority.len()),
        (0, 0, 1),
        "NODATA with SOA"
    );
    assert_eq!(m.authority[0].1, 6);
    assert_eq!(m.ede_codes(), vec![15], "no EDE 4 without records");
    // The canary rewrite answers NXDOMAIN whatever block_response says (rules.md §4).
    let m = udp_q(addr, &Q::new("canary.picket.test", 1)).await;
    assert_eq!(m.rcode, 3);
    assert!(m.ede().is_empty(), "rewrites carry no EDE");
    assert_eq!(up.count(), 0, "blocks and rewrites never touch upstreams");
    // A query without OPT gets no EDE.
    let m = udp_q(addr, &Q::new("x.ads.example.com", 1).no_opt()).await;
    assert!(m.opt.is_none());
    let rec = env.q_record("x.ads.example.com").await;
    assert_eq!(rec["decision"], "block");
    assert_eq!(rec["reason"]["step"], 3);
    assert_eq!(rec["reason"]["bundle"], "block-common");
    assert_eq!(rec["reason"]["kind"], "subs");
    assert!(rec["reason"]["block_id"].is_string());
    // The other block types, through profiles chosen by client ranges.
    for (profile, check) in [("nx", 0), ("nd", 1), ("rf", 2), ("cu", 3)] {
        let mut c = cfg.clone();
        c["default_profile"] = profile.into();
        env.set_config(&c).await;
        let a = udp_q(env.dns(), &Q::new("x.ads.example.com", 1)).await;
        let canary = udp_q(env.dns(), &Q::new("canary.picket.test", 1)).await;
        assert_eq!(canary.rcode, 3, "{profile}: canaries under every block_response");
        match check {
            0 => {
                assert_eq!(a.rcode, 3);
                assert_eq!(a.authority[0].1, 6);
                assert_eq!(a.authority[0].2, 20, "SOA TTL = block_response.ttl");
                let min =
                    u32::from_be_bytes(a.authority[0].3[a.authority[0].3.len() - 4..].try_into().unwrap());
                assert_eq!(min, 20, "SOA MINIMUM = block_response.ttl");
                assert_eq!(a.ede_codes(), vec![15]);
            }
            1 => assert_eq!((a.rcode, a.answers.len(), a.authority.len()), (0, 0, 1)),
            2 => {
                assert_eq!(a.rcode, 5);
                assert_eq!(a.ede_codes(), vec![15]);
            }
            _ => {
                assert_eq!(a.ips(), vec!["192.0.2.99".parse::<std::net::IpAddr>().unwrap()]);
                assert_eq!(a.ttls(), vec![30]);
                let aaaa = udp_q(env.dns(), &Q::new("x.ads.example.com", 28)).await;
                assert_eq!(
                    (aaaa.answers.len(), aaaa.ede_codes()),
                    (0, vec![15]),
                    "no ipv6: NODATA"
                );
            }
        }
    }
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ede_extra_text_is_capped_from_the_left() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let long = "b".repeat(100);
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!([long.clone()]);
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![(&long, bundle(&long, BundleAction::Block, &["||ads.example^"]))],
    );
    let m = udp_q(env.dns(), &Q::new("ads.example", 1)).await;
    let (code, text) = &m.ede()[0];
    assert_eq!(*code, 15);
    assert!(text.len() <= 128, "{}", text.len());
    assert!(text.starts_with("block="), "the bundle token went first: {text}");
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn response_checks_cname_ipv4_mapped_and_svcb_hints() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| match (m.qname.as_str(), m.qtype) {
        ("www.shop.example", 1) => Act::Answer(Ans::records(vec![
            cname("www.shop.example", "edge.tracker.example", 60),
            a("edge.tracker.example", "198.51.100.7", 60),
        ])),
        ("v6.example", 28) => Act::Answer(Ans::records(vec![aaaa("v6.example", "::ffff:203.0.113.5", 60)])),
        ("svc.example", 65) => Act::Answer(Ans::records(vec![https(
            "svc.example",
            1,
            ".",
            &["203.0.113.5"],
            60,
        )])),
        ("ok.example", 65) => Act::Answer(Ans::records(vec![https(
            "ok.example",
            1,
            ".",
            &["192.0.2.1"],
            60,
        )])),
        ("allowed.example", 1) => Act::Answer(Ans::records(vec![
            cname("allowed.example", "edge.tracker.example", 60),
            a("edge.tracker.example", "198.51.100.7", 60),
        ])),
        _ => Act::Answer(Ans::records(vec![])),
    })
    .await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!(["block-common"]);
    cfg["profiles"]["default"]["allow"] = json!(["allow-common"]);
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![
            (
                "block-common",
                bundle(
                    "block-common",
                    BundleAction::Block,
                    &[
                        "||tracker.example^",
                        "||203.0.113.5^",
                        "||svc-rw.example^$dnsrewrite=NOERROR;HTTPS;1 . ipv4hint=203.0.113.5",
                    ],
                ),
            ),
            (
                "allow-common",
                bundle("allow-common", BundleAction::Allow, &["||allowed.example^"]),
            ),
        ],
    );
    let addr = env.dns();
    // A CNAME target blocked: the whole response is replaced.
    let m = udp_q(addr, &Q::new("www.shop.example", 1)).await;
    assert_eq!(m.ips(), vec!["0.0.0.0".parse::<std::net::IpAddr>().unwrap()]);
    let rec = env.q_record("www.shop.example").await;
    assert_eq!(rec["reason"]["step"], 5);
    assert_eq!(rec["reason"]["stage"], "cname");
    assert!(rec["answer_id"].is_string(), "the checked answer is referenced");
    // An IPv4-mapped IPv6 answer matches as its IPv4 address (rules.md §6).
    let m = udp_q(addr, &Q::new("v6.example", 28)).await;
    assert_eq!(m.ede_codes(), vec![15, 4]);
    let rec = env.q_record("v6.example").await;
    assert_eq!(rec["reason"]["stage"], "answer_ip");
    // HTTPS hints are checked (stage svcb), and a clean one passes.
    let m = udp_q(addr, &Q::new("svc.example", 65)).await;
    assert_eq!(m.ede_codes(), vec![15]);
    assert_eq!(env.q_record("svc.example").await["reason"]["stage"], "svcb");
    let m = udp_q(addr, &Q::new("ok.example", 65)).await;
    assert_eq!((m.rcode, m.types()), (0, vec![65]));
    // A rewritten HTTPS answer isn't checked (rules.md §6).
    let m = udp_q(addr, &Q::new("svc-rw.example", 65)).await;
    assert_eq!(m.types(), vec![65]);
    assert!(m.ede().is_empty());
    assert_eq!(env.q_record("svc-rw.example").await["decision"], "rewrite");
    // Allowed at step 2: no response checks under skip_after_allow.
    let m = udp_q(addr, &Q::new("allowed.example", 1)).await;
    assert_eq!(m.ips(), vec!["198.51.100.7".parse::<std::net::IpAddr>().unwrap()]);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rewrites_host_mappings_and_cname_rewrites() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!(["rw", "hosts"]);
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![
            (
                "rw",
                bundle(
                    "rw",
                    BundleAction::Block,
                    &[
                        "||a.example^$dnsrewrite=NOERROR;A;192.0.2.1",
                        "||txt.example^$dnsrewrite=NOERROR;TXT;hello",
                        "||c.example^$dnsrewrite=NOERROR;CNAME;target.example",
                    ],
                ),
            ),
            (
                "hosts",
                bundle_fmt(
                    "hosts",
                    BundleAction::Block,
                    &["192.0.2.10 mapped.example"],
                    picket_rules::formats::Format::Hosts,
                ),
            ),
        ],
    );
    let addr = env.dns();
    let m = udp_q(addr, &Q::new("a.example", 1)).await;
    assert_eq!(m.ips(), vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]);
    assert_eq!(m.ttls(), vec![10], "rewrites use block_response.ttl");
    let rec = env.q_record("a.example").await;
    assert_eq!(rec["decision"], "rewrite");
    assert!(rec["response"].is_string(), "a reply the edge made is logged");
    // A rewrite of another type answers NOERROR with no records.
    let m = udp_q(addr, &Q::new("a.example", 28)).await;
    assert_eq!((m.rcode, m.answers.len()), (0, 0));
    let m = udp_q(addr, &Q::new("txt.example", 16)).await;
    assert_eq!(m.types(), vec![16]);
    // A CNAME rewrite: the CNAME plus the target's records under the original question.
    let m = udp_q(addr, &Q::new("c.example", 1)).await;
    assert_eq!(m.types(), vec![5, 1]);
    assert_eq!(m.qname, "c.example");
    assert_eq!(up.seen()[0].msg.qname, "target.example");
    let rec = env.q_record("c.example").await;
    assert_eq!(rec["decision"], "rewrite");
    assert!(rec["answer_id"].is_string(), "the target's answer is referenced");
    assert!(rec["response"].is_string());
    // A host-IP mapping under null_ip: A with its address (a rewrite), AAAA gets ::.
    let m = udp_q(addr, &Q::new("mapped.example", 1)).await;
    assert_eq!(m.ips(), vec!["192.0.2.10".parse::<std::net::IpAddr>().unwrap()]);
    assert!(m.ede().is_empty());
    assert_eq!(env.q_record("mapped.example").await["decision"], "rewrite");
    let m = udp_q(addr, &Q::new("mapped.example", 28)).await;
    assert_eq!(m.ips(), vec!["::".parse::<std::net::IpAddr>().unwrap()]);
    assert_eq!(m.ede_codes(), vec![15, 4]);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn special_names_forward_zones_and_any() {
    let local = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.168.1.50", 60)]))
    })
    .await;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = base_config(
        json!({
            "g": {"upstreams": ["up1"], "strategy": "failover", "optimistic": true},
            "local": {"upstreams": ["dnsmasq"], "strategy": "failover", "optimistic": false},
        }),
        json!({"up1": plain_upstream(&up, "udp"), "dnsmasq": plain_upstream(&local, "udp")}),
    );
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-doh", "proto": "doh", "bind": "127.0.0.1:0", "ips": ["192.168.1.1"], "tls": {"managed": "dns.home.arpa"}},
    ]);
    cfg["profiles"]["default"]["forward_zones"] = json!(["localdomain", "lan-reverse"]);
    cfg["forward_zones"] = json!({
        "localdomain": {"zone": "localdomain", "group": "local"},
        "lan-reverse": {"zone": "1.168.192.in-addr.arpa", "group": "local"},
    });
    let cfg2 = cfg.clone();
    let env = start(cfg, |_| {}).await;
    let addr = env.dns();
    // A managed listener name and *.name answer with the listener's IPs.
    for n in ["dns.home.arpa", "strict.dns.home.arpa"] {
        let m = udp_q(addr, &Q::new(n, 1)).await;
        assert_eq!(
            m.ips(),
            vec!["192.168.1.1".parse::<std::net::IpAddr>().unwrap()],
            "{n}"
        );
        assert!(m.aa);
    }
    // home.arpa and local names: NXDOMAIN.
    assert_eq!(udp_q(addr, &Q::new("nas.home.arpa", 1)).await.rcode, 3);
    assert_eq!(udp_q(addr, &Q::new("printer.local", 1)).await.rcode, 3);
    // Private-range PTR: NXDOMAIN unless a zone covers it.
    assert_eq!(udp_q(addr, &Q::new("5.0.0.10.in-addr.arpa", 12)).await.rcode, 3);
    let m = udp_q(addr, &Q::new("5.1.168.192.in-addr.arpa", 12)).await;
    assert_eq!(m.rcode, 0);
    // A forward zone goes to its group; the client's DO is kept.
    let m = udp_q(addr, &Q::new("nas.localdomain", 1).dnssec()).await;
    assert_eq!(m.ips(), vec!["192.168.1.50".parse::<std::net::IpAddr>().unwrap()]);
    assert!(
        local
            .seen()
            .iter()
            .any(|s| s.msg.qname == "nas.localdomain" && s.msg.opt.as_ref().unwrap().do_bit)
    );
    assert_eq!(env.q_record("nas.localdomain").await["reason"]["kind"], "forward");
    // A zone whose group is down: `fallback: none` answers SERVFAIL; `default` uses the profile's
    // group.
    local.set(|_m: &Msg, _q: &[u8]| Act::Drop);
    assert_eq!(udp_q(addr, &Q::new("x.localdomain", 1)).await.rcode, 2);
    let mut c2 = cfg2.clone();
    c2["forward_zones"]["localdomain"]["fallback"] = "default".into();
    env.set_config(&c2).await;
    let m = udp_q(env.dns(), &Q::new("y.localdomain", 1)).await;
    assert_eq!(
        m.ips(),
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
    );
    let addr = env.dns();
    // ANY: the RFC 8482 answer, no upstream query.
    let before = up.count();
    let m = udp_q(addr, &Q::new("example.org", 255)).await;
    assert_eq!(m.types(), vec![13]);
    assert_eq!(up.count(), before);
    // A public name goes to the default group.
    assert_eq!(udp_q(addr, &Q::new("example.net", 1)).await.rcode, 0);
    assert_eq!(up.seen().last().unwrap().msg.qname, "example.net");
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dnssec_do_handling_per_group_kind() {
    // A signed answer: the A RRset with its RRSIG.
    let signed = |m: &Msg, _q: &[u8]| match m.qtype {
        1 => Act::Answer(Ans::records(vec![
            a(&m.qname, "192.0.2.80", 300),
            rrsig(&m.qname, 1, 300),
        ])),
        46 => Act::Answer(Ans::records(vec![rrsig(&m.qname, 1, 300)])),
        _ => Act::Answer(Ans::records(vec![])),
    };
    let dot = FakeUpstream::dot(signed).await;
    let plain = FakeUpstream::plain(signed).await;
    let mut cfg = base_config(
        json!({
            "g": {"upstreams": ["enc"], "strategy": "failover", "optimistic": true},
            "p": {"upstreams": ["pl"], "strategy": "failover", "optimistic": true},
        }),
        json!({"enc": tls_upstream(&dot, "dot"), "pl": plain_upstream(&plain, "udp")}),
    );
    cfg["profiles"]["plain"] = json!({"upstream": "p"});
    let env = start(cfg.clone(), |_| {}).await;
    let addr = env.dns();
    // Encrypted group: DO=1 upstream whatever the client set; DO=0 clients get no RRSIG,
    // DO=1 clients keep it; one upstream answer serves both.
    let m0 = udp_q(addr, &Q::new("signed.example", 1)).await;
    assert_eq!(
        m0.types(),
        vec![1],
        "unsolicited DNSSEC records stripped for DO=0"
    );
    let m1 = udp_q(addr, &Q::new("signed.example", 1).dnssec()).await;
    assert_eq!(m1.types(), vec![1, 46], "kept for DO=1");
    assert!(
        m1.opt.as_ref().unwrap().do_bit,
        "the reply's OPT carries the client's DO"
    );
    assert_eq!(dot.count(), 1, "one cached answer for both");
    let s = &dot.seen()[0];
    assert!(s.msg.opt.as_ref().unwrap().do_bit, "DO=1 to encrypted groups");
    assert_eq!(s.raw.len() % 128, 0, "DoT queries padded to 128 bytes");
    // A DO=0 query for type RRSIG keeps the records of the type asked for.
    let m = udp_q(addr, &Q::new("sigs.example", 46)).await;
    assert_eq!(m.types(), vec![46]);
    // A plain group keeps the client's DO.
    let mut c = cfg.clone();
    c["default_profile"] = "plain".into();
    env.set_config(&c).await;
    udp_q(env.dns(), &Q::new("p0.example", 1)).await;
    udp_q(env.dns(), &Q::new("p1.example", 1).dnssec()).await;
    let seen = plain.seen();
    let do_of = |n: &str| {
        seen.iter()
            .find(|s| s.msg.qname == n)
            .unwrap()
            .msg
            .opt
            .as_ref()
            .unwrap()
            .do_bit
    };
    assert!(!do_of("p0.example"));
    assert!(do_of("p1.example"));
    assert!(
        seen.iter().all(|s| s.raw.len() % 128 != 0 || s.raw.len() < 128),
        "plain queries aren't padded"
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_edns_options_are_never_forwarded() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    let mut q = Q::new("ecs.example", 1);
    // A Client Subnet option (code 8) and a cookie (code 10).
    q.options = vec![
        (8, vec![0, 1, 24, 0, 192, 0, 2]),
        (10, vec![1, 2, 3, 4, 5, 6, 7, 8]),
    ];
    udp_q(env.dns(), &q).await;
    let s = &up.seen()[0];
    assert!(s.msg.opt.as_ref().unwrap().options.is_empty(), "{:?}", s.msg.opt);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_choice_and_refusals_over_dns_dot_and_doh() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    let signer = support::CsrSigner::new(&["dns.home.arpa", "*.dns.home.arpa"], &[], (2026, 1, 1));
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0", "tls": {"managed": "dns.home.arpa"}},
        {"id": "lan-doh", "proto": "doh", "bind": "127.0.0.1:0", "tls": {"managed": "dns.home.arpa"}},
    ]);
    cfg["profiles"] = json!({
        "default": {"upstream": "g"},
        "strict": {"upstream": "g", "block": ["b"]},
        "adults": {"upstream": "g", "allowed_sources": ["10.0.0.0/8"]},
    });
    let core = MockCore::start().await;
    core.with(|s| s.csr_signer = Some(signer.clone()));
    let env = start_with_core(core, cfg.clone()).await;
    set_bundles(
        env.edge(),
        vec![("b", bundle("b", BundleAction::Block, &["||blocked.example^"]))],
    );
    let edge = Arc::clone(env.edge());
    assert!(
        wait_until(T, || ["lan-dot", "lan-doh"].iter().all(|l| edge
            .dns
            .certs
            .slot(l)
            .is_some_and(|s| s.has_cert())))
        .await,
        "managed certificates from core"
    );
    let csr = env.core.with(|s| s.csrs[0].clone());
    assert_eq!(
        csr["listener"].as_str().map(|l| l == "lan-dot" || l == "lan-doh"),
        Some(true)
    );
    assert!(csr["csr_pem"].as_str().unwrap().contains("CERTIFICATE REQUEST"));
    let ca = signer.ca_cert_pem.clone();
    let blocked = Q::new("blocked.example", 1).bytes();
    // DoT: the SNI prefix names the profile.
    let r = dot(
        env.addr("lan-dot"),
        "strict.dns.home.arpa",
        &ca,
        std::slice::from_ref(&blocked),
    )
    .await
    .unwrap();
    assert_eq!(parse(&r[0]).ede_codes(), vec![15, 4], "strict blocks it");
    let r = dot(
        env.addr("lan-dot"),
        "dns.home.arpa",
        &ca,
        std::slice::from_ref(&blocked),
    )
    .await
    .unwrap();
    assert_eq!(parse(&r[0]).rcode, 0);
    assert!(
        parse(&r[0]).ede().is_empty(),
        "the default profile doesn't block it"
    );
    // A named profile that doesn't admit the client: DoT REFUSED with EDE 18 and its text.
    let r = dot(
        env.addr("lan-dot"),
        "adults.dns.home.arpa",
        &ca,
        std::slice::from_ref(&blocked),
    )
    .await
    .unwrap();
    let m = parse(&r[0]);
    assert_eq!(m.rcode, 5);
    assert_eq!(
        m.ede(),
        vec![(18, "profile not permitted from this address".to_owned())]
    );
    // DoH: path names the profile; a refused one is HTTP 403 with the text as body.
    let (st, _, body) = doh(
        env.addr("lan-doh"),
        "dns.home.arpa",
        &ca,
        "/dns-query/adults",
        &blocked,
        false,
        &[],
    )
    .await;
    assert_eq!(st, 403);
    assert_eq!(
        String::from_utf8_lossy(&body),
        "profile not permitted from this address"
    );
    let (st, _, _) = doh(
        env.addr("lan-doh"),
        "dns.home.arpa",
        &ca,
        "/dns-query/nope",
        &blocked,
        true,
        &[],
    )
    .await;
    assert_eq!(st, 403, "an unknown profile id too");
    let (st, h, body) = doh(
        env.addr("lan-doh"),
        "dns.home.arpa",
        &ca,
        "/dns-query/strict",
        &blocked,
        true,
        &[],
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(h["content-type"], "application/dns-message");
    assert_eq!(
        h["cache-control"], "private, max-age=10",
        "the minimum TTL (block_response.ttl)"
    );
    assert_eq!(parse(&body).ede_codes(), vec![15, 4]);
    // The extension's queries are never cached by the browser.
    let (_, h, _) = doh(
        env.addr("lan-doh"),
        "dns.home.arpa",
        &ca,
        "/dns-query",
        &Q::new("www.example.com", 1).bytes(),
        false,
        &[("x-picket-client", "extension")],
    )
    .await;
    assert_eq!(h["cache-control"], "no-store");
    let (_, h, _) = doh(
        env.addr("lan-doh"),
        "dns.home.arpa",
        &ca,
        "/dns-query",
        &Q::new("www.example.com", 1).bytes(),
        true,
        &[],
    )
    .await;
    let cc = h["cache-control"].to_str().unwrap().to_owned();
    assert!(cc.starts_with("private, max-age="), "{cc}");
    let age: u32 = cc.trim_start_matches("private, max-age=").parse().unwrap();
    assert!(age <= 300 && age > 200, "{age}");
    // No profile admits the client: REFUSED with EDE 18 (not permitted from this address).
    let mut c = cfg.clone();
    c["default_profile"] = "adults".into();
    env.set_config(&c).await;
    let m = udp_q(env.dns(), &Q::new("x.example", 1)).await;
    assert_eq!(m.rcode, 5);
    assert_eq!(m.ede(), vec![(18, "not permitted from this address".to_owned())]);
    assert_eq!(env.q_record("x.example").await["decision"], "refused");
    let s = env.edge().metrics.snapshot();
    assert!(s.refused >= 1 && s.by_decision.refused >= s.refused);
    env.shutdown().await;
}

/// A TLS 1.2 ClientHello as OpenSSL or Go send one with TLS 1.3 off: legacy version 0x0303 and no
/// `supported_versions` extension, with an SNI (a rustls client always sends the extension).
fn tls12_client_hello(sni: &str) -> Vec<u8> {
    client_hello(0x0303, sni, true)
}

/// A ClientHello with legacy version `version`, an SNI, no `supported_versions` extension and, if
/// `sig_algs`, a `signature_algorithms` extension (RFC 5246 §7.4.1.4.1: a TLS 1.0 or 1.1 client
/// never sends one, and a TLS 1.2 client may leave it out).
fn client_hello(version: u16, sni: &str, sig_algs: bool) -> Vec<u8> {
    let be16 = |n: usize| (n as u16).to_be_bytes();
    let mut name = vec![0u8];
    name.extend(be16(sni.len()));
    name.extend(sni.as_bytes());
    let mut list = be16(name.len()).to_vec();
    list.extend(name);
    let mut ext = vec![0, 0];
    ext.extend(be16(list.len()));
    ext.extend(list);
    // supported_groups (x25519, secp256r1), ec_point_formats (uncompressed), signature_algorithms
    // (ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256).
    ext.extend([0, 0x0a, 0, 6, 0, 4, 0, 0x1d, 0, 0x17]);
    ext.extend([0, 0x0b, 0, 2, 1, 0]);
    if sig_algs {
        ext.extend([0, 0x0d, 0, 6, 0, 4, 4, 3, 8, 4]);
    }
    let mut body = version.to_be_bytes().to_vec();
    body.extend([7u8; 32]);
    body.push(0);
    // ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-SHA; null
    // compression.
    body.extend([0, 6, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x13, 1, 0]);
    body.extend(be16(ext.len()));
    body.extend(ext);
    let mut hs = vec![1];
    hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend(be16(hs.len()));
    rec.extend(hs);
    rec
}

/// Sends `hello` to `to` from `from` and returns the fatal alert's description the edge answers
/// with.
async fn refused_hello(from: &str, to: std::net::SocketAddr, hello: &[u8]) -> u8 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let s = tokio::net::TcpSocket::new_v4().unwrap();
    s.bind(format!("{from}:0").parse().unwrap()).unwrap();
    let mut c = s.connect(to).await.unwrap();
    c.write_all(hello).await.unwrap();
    let mut alert = [0u8; 7];
    c.read_exact(&mut alert).await.unwrap();
    assert_eq!(alert[..3], [0x15, 3, 3], "an alert record: {alert:?}");
    assert_eq!(alert[5], 2, "fatal: {alert:?}");
    alert[6]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_listeners_speak_only_tls_1_3_and_log_one_refusal_per_client_an_hour() {
    // edge.md §5 (DoT, DoH and the bypass API: TLS 1.3 only); api.md §5 `tls_version_refused`.
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    let signer = support::CsrSigner::new(&["dns.home.arpa", "*.dns.home.arpa"], &[], (2026, 1, 1));
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0", "tls": {"managed": "dns.home.arpa"}},
        {"id": "lan-doh", "proto": "doh", "bind": "127.0.0.1:0", "api": true, "tls": {"managed": "dns.home.arpa"}},
    ]);
    cfg["clients"] = json!([{"name": "old-printer", "source_ips": ["127.0.0.1"]}]);
    let core = MockCore::start().await;
    core.with(|s| s.csr_signer = Some(signer.clone()));
    let env = start_with_core(core, cfg).await;
    let edge = Arc::clone(env.edge());
    assert!(
        wait_until(T, || ["lan-dot", "lan-doh"].iter().all(|l| edge
            .dns
            .certs
            .slot(l)
            .is_some_and(|s| s.has_cert())))
        .await,
        "managed certificates from core"
    );
    let ca = signer.ca_cert_pem.clone();
    let tls12: &[&'static rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
    // A TLS 1.2-only client is refused, every time, on DoT and on DoH (the bypass API's listener).
    for _ in 0..3 {
        let e = tls_handshake(env.addr("lan-dot"), "strict.dns.home.arpa", &ca, &[], tls12)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("ProtocolVersion"), "{e}");
    }
    for _ in 0..2 {
        let e = tls_handshake(env.addr("lan-doh"), "dns.home.arpa", &ca, &[b"h2"], tls12)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("ProtocolVersion"), "{e}");
    }
    // A TLS 1.2 client without the supported_versions extension, from another address (no
    // device: no client names it and loopback has no MAC): refused with a protocol_version alert.
    for _ in 0..2 {
        let hello = tls12_client_hello("dns.home.arpa");
        assert_eq!(
            refused_hello("127.0.0.2", env.addr("lan-dot"), &hello).await,
            70,
            "protocol_version"
        );
    }
    // A TLS 1.3 client is unaffected, over both.
    let tls = tls_handshake(
        env.addr("lan-dot"),
        "dns.home.arpa",
        &ca,
        &[],
        &[&rustls::version::TLS13],
    )
    .await
    .unwrap();
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    drop(tls);
    let r = dot(
        env.addr("lan-dot"),
        "dns.home.arpa",
        &ca,
        &[Q::new("after-refusals.example", 1).bytes()],
    )
    .await
    .unwrap();
    assert_eq!(parse(&r[0]).rcode, 0);
    let (st, _, _) = doh(
        env.addr("lan-doh"),
        "dns.home.arpa",
        &ca,
        "/dns-query",
        &Q::new("after-refusals-doh.example", 1).bytes(),
        false,
        &[],
    )
    .await;
    assert_eq!(st, 200);
    // Records ship in order: once the later query's record is in, every refusal's record is.
    env.q_record("after-refusals-doh.example").await;
    let refusals: Vec<Value> = env.core.with(|s| {
        s.logs
            .iter()
            .filter(|l| l["t"] == "event" && l["kind"] == "tls_version_refused")
            .cloned()
            .collect()
    });
    assert_eq!(
        refusals.len(),
        3,
        "one per listener and client within the hour: {refusals:?}"
    );
    let find = |listener: &str, client: &str| {
        refusals
            .iter()
            .find(|e| e["listener"] == listener && e["client"] == client)
            .unwrap_or_else(|| panic!("{listener} {client}: {refusals:?}"))
            .clone()
    };
    let dot_ev = find("lan-dot", "127.0.0.1");
    assert_eq!(dot_ev["transport"], "dot");
    assert_eq!(dot_ev["device"], "old-printer");
    assert_eq!(dot_ev["sni"], "strict.dns.home.arpa");
    // rustls's client lists only TLS 1.2 in supported_versions (rustls's refusal says only that
    // the list has no TLS 1.3; the hello's bytes say which).
    assert_eq!(dot_ev["offered"], "tls12");
    assert_eq!(dot_ev["refused"], 1);
    assert!(dot_ev.get("unlogged").is_none(), "{dot_ev}");
    let doh_ev = find("lan-doh", "127.0.0.1");
    assert_eq!(doh_ev["transport"], "doh");
    assert_eq!(doh_ev["sni"], "dns.home.arpa");
    let legacy = find("lan-dot", "127.0.0.2");
    assert_eq!(legacy["offered"], "tls12");
    assert_eq!(legacy["device"], Value::Null);
    assert_eq!(legacy["sni"], "dns.home.arpa");
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn old_hellos_are_reported_and_refusals_key_on_the_device() {
    // Review r10 T1/U1, T2/U3, U5: rustls refuses a hello without signature_algorithms before it
    // looks at versions, which every TLS 1.0 and 1.1 client is; one device on several addresses
    // is one device (edge.md §5), and the event names its MAC.
    use picket_edge::neighbours::Change;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    let signer = support::CsrSigner::new(&["dns.home.arpa", "*.dns.home.arpa"], &[], (2026, 1, 1));
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0", "tls": {"managed": "dns.home.arpa"}},
    ]);
    let core = MockCore::start().await;
    core.with(|s| s.csr_signer = Some(signer.clone()));
    let env = start_with_core(core, cfg).await;
    let edge = Arc::clone(env.edge());
    assert!(
        wait_until(T, || edge.dns.certs.slot("lan-dot").is_some_and(|s| s.has_cert())).await,
        "a managed certificate from core"
    );
    let dot_addr = env.addr("lan-dot");
    // TLS 1.0, 1.1 and 1.2 hellos without signature_algorithms: handshake_failure, and reported.
    for (from, version) in [
        ("127.0.0.10", 0x0301),
        ("127.0.0.11", 0x0302),
        ("127.0.0.12", 0x0303),
    ] {
        let hello = client_hello(version, "old.dns.home.arpa", false);
        assert_eq!(refused_hello(from, dot_addr, &hello).await, 40, "{from}");
    }
    // One device (one MAC) on two addresses, refused from both: one event, naming its MAC.
    let mac = [0x02, 0, 0, 0, 0, 0x2a];
    edge.neighbours.apply(&[
        Change::Upsert {
            ip: "127.0.0.20".parse().unwrap(),
            mac,
        },
        Change::Upsert {
            ip: "127.0.0.21".parse().unwrap(),
            mac,
        },
    ]);
    for from in ["127.0.0.20", "127.0.0.21", "127.0.0.20"] {
        let hello = tls12_client_hello("dns.home.arpa");
        assert_eq!(refused_hello(from, dot_addr, &hello).await, 70, "{from}");
    }
    // Records ship in order: once a later query's record is in, every refusal's record is.
    let ca = signer.ca_cert_pem.clone();
    let r = dot(
        dot_addr,
        "dns.home.arpa",
        &ca,
        &[Q::new("after-old.example", 1).bytes()],
    )
    .await
    .unwrap();
    assert_eq!(parse(&r[0]).rcode, 0);
    env.q_record("after-old.example").await;
    let refusals: Vec<Value> = env.core.with(|s| {
        s.logs
            .iter()
            .filter(|l| l["t"] == "event" && l["kind"] == "tls_version_refused")
            .cloned()
            .collect()
    });
    let by_client = |c: &str| {
        refusals
            .iter()
            .filter(|e| e["client"] == c)
            .cloned()
            .collect::<Vec<_>>()
    };
    for (client, offered) in [
        ("127.0.0.10", "tls11_or_older"),
        ("127.0.0.11", "tls11_or_older"),
        ("127.0.0.12", "tls12"),
    ] {
        let e = by_client(client);
        assert_eq!(e.len(), 1, "{client}: {refusals:?}");
        assert_eq!(e[0]["offered"], offered, "{client}");
        assert_eq!(e[0]["sni"], "old.dns.home.arpa", "{client}");
        assert_eq!(e[0]["listener"], "lan-dot");
        assert!(
            e[0].get("mac").is_none_or(Value::is_null),
            "no MAC known: {}",
            e[0]
        );
    }
    let device: Vec<&Value> = refusals
        .iter()
        .filter(|e| e["mac"] == "02:00:00:00:00:2a")
        .collect();
    assert_eq!(device.len(), 1, "one device, one event: {refusals:?}");
    assert_eq!(device[0]["client"], "127.0.0.20");
    assert_eq!(
        device[0]["device"], "02:00:00:00:00:2a",
        "named by its MAC (no client names it)"
    );
    assert_eq!(refusals.len(), 4, "{refusals:?}");
    env.shutdown().await;
}

async fn start_with_core(core: MockCore, cfg: Value) -> Env {
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&cfg);
    let r = service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        tuning(&d),
        |_| {},
    )
    .await
    .unwrap();
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    assert!(wait_until(T, || !edge.dns.listeners.local_addrs("lan-dns").is_empty()).await);
    Env { core, _d: d, r }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_certificates_renew_and_survive_restarts() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0", "ips": ["192.168.1.1"], "tls": {"managed": "dns.home.arpa"}},
    ]);
    // An old leaf (issued in 2020): past its 265 days, so the edge asks again at once.
    let core = MockCore::start().await;
    core.with(|s| {
        s.csr_signer = Some(support::CsrSigner::new(
            &["dns.home.arpa", "*.dns.home.arpa"],
            &["192.168.1.1"],
            (2020, 1, 1),
        ));
        s.csr_fail = 1;
    });
    let env = start_with_core(core, cfg).await;
    let edge = Arc::clone(env.edge());
    // The first request fails (503) and is retried with backoff.
    assert!(
        wait_until(T, || env.core.with(|s| s.csrs.len()) >= 3).await,
        "renewed repeatedly while old"
    );
    assert!(
        edge.dns.certs.slot("lan-dot").unwrap().has_cert(),
        "an expired certificate is still served"
    );
    // A current leaf ends the renewals.
    env.core.with(|s| {
        s.csr_signer = Some(support::CsrSigner::new(
            &["dns.home.arpa", "*.dns.home.arpa"],
            &["192.168.1.1"],
            (2026, 11, 1),
        ))
    });
    assert!(
        wait_until(T, || {
            let i = edge.dns.certs.slot("lan-dot").unwrap().info();
            i.not_before
                .as_deref()
                .is_some_and(|t| t.starts_with("2026-11-01"))
        })
        .await
    );
    let n = env.core.with(|s| s.csrs.len());
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        env.core.with(|s| s.csrs.len()),
        n,
        "no request while the leaf is current"
    );
    // On disk, key and chain in one file, 0600.
    let key = env._d.data.join("tls/lan-dot.pem");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The listener's IPs change: the SANs no longer match, so a new leaf is requested.
    let mut cfg2 = one_upstream(&up, "udp");
    cfg2["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0", "ips": ["192.168.1.2"], "tls": {"managed": "dns.home.arpa"}},
    ]);
    env.set_config(&cfg2).await;
    assert!(wait_until(T, || env.core.with(|s| s.csrs.len()) > n).await);
    env.shutdown().await;
}

/// The fingerprint `EdgeConfig.lanca_root` carries for a signer's root.
fn root_fp(signer: &support::CsrSigner) -> String {
    use rustls_pki_types::pem::PemObject;
    let der = rustls_pki_types::CertificateDer::from_pem_slice(signer.ca_cert_pem.as_bytes()).unwrap();
    picket_api::ids::cert_fingerprint(der.as_ref())
}

/// core.md §11, edge.md §5: a `lanca.zones` change makes a new LAN CA root, and the config names
/// it (`lanca_root`): the edge replaces its managed certificate at once (clock or not), and asks
/// once only when core keeps issuing from another root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_certificates_follow_the_lanca_root() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let listeners = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0", "ips": ["192.168.1.1"], "tls": {"managed": "dns.home.arpa"}},
    ]);
    let signer = |d| support::CsrSigner::new(&["dns.home.arpa", "*.dns.home.arpa"], &["192.168.1.1"], d);
    let (a, b, c) = (
        signer((2026, 11, 1)),
        signer((2026, 11, 1)),
        signer((2026, 11, 1)),
    );
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = listeners.clone();
    cfg["lanca_root"] = json!(root_fp(&a));
    let core = MockCore::start().await;
    core.with(|s| s.csr_signer = Some(a.clone()));
    let env = start_with_core(core, cfg).await;
    let edge = Arc::clone(env.edge());
    let root = || edge.dns.certs.slot("lan-dot").unwrap().info().root.clone();
    assert!(wait_until(T, || root() == Some(root_fp(&a))).await);
    let n = env.core.with(|s| s.csrs.len());
    // The rotation: core signs from root B, and the config names it.
    env.core.with(|s| s.csr_signer = Some(b.clone()));
    let mut cfg2 = one_upstream(&up, "udp");
    cfg2["listeners"] = listeners.clone();
    cfg2["lanca_root"] = json!(root_fp(&b));
    env.set_config(&cfg2).await;
    assert!(
        wait_until(T, || root() == Some(root_fp(&b))).await,
        "the certificate from the old root is replaced"
    );
    assert!(env.core.with(|s| s.csrs.len()) > n);
    let n = env.core.with(|s| s.csrs.len());
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(env.core.with(|s| s.csrs.len()), n, "no request once it matches");
    // A config naming a root core doesn't sign with: one request, then no loop.
    let mut cfg3 = one_upstream(&up, "udp");
    cfg3["listeners"] = listeners;
    cfg3["lanca_root"] = json!(root_fp(&c));
    env.set_config(&cfg3).await;
    assert!(wait_until(T, || env.core.with(|s| s.csrs.len()) > n).await);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(env.core.with(|s| s.csrs.len()), n + 1, "asked once");
    assert_eq!(root(), Some(root_fp(&b)));
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coalescing_hedging_and_failover() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&calls);
    let slow = FakeUpstream::plain(move |m: &Msg, _q: &[u8]| {
        c.fetch_add(1, Ordering::SeqCst);
        Act::Delay(
            Duration::from_millis(400),
            Box::new(Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.1", 300)]))),
        )
    })
    .await;
    let fast = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.2", 300)]))
    })
    .await;
    // Nothing listens on this TCP port: connections are refused at once.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let cfg = base_config(
        json!({
            "g": {"upstreams": ["slow"], "strategy": "failover", "optimistic": true},
            "h": {"upstreams": ["slow", "fast"], "strategy": "failover", "optimistic": true},
            "f": {"upstreams": ["dead", "fast2"], "strategy": "failover", "optimistic": true},
        }),
        json!({
            "slow": plain_upstream(&slow, "udp"),
            "fast": plain_upstream(&fast, "udp"),
            "fast2": plain_upstream(&fast, "tcp"),
            "dead": {"protocol": "tcp", "ip": "127.0.0.1", "port": closed_port},
        }),
    );
    let env = start(cfg.clone(), |_| {}).await;
    let addr = env.dns();
    // Coalescing: identical queries in flight share one upstream query.
    let qs: Vec<_> = (0..5)
        .map(|_| {
            let q = Q::new("same.example", 1);
            tokio::spawn(async move { udp_q(addr, &q).await })
        })
        .collect();
    for q in qs {
        assert_eq!(q.await.unwrap().rcode, 0);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "coalesced");
    // Hedging: no answer by the slow upstream's p90 (bounded to 50–250 ms) → the next one too.
    let mut c = cfg.clone();
    c["profiles"]["default"]["upstream"] = "h".into();
    env.set_config(&c).await;
    let m = udp_q(env.dns(), &Q::new("hedge.example", 1)).await;
    assert_eq!(
        m.ips(),
        vec!["192.0.2.2".parse::<std::net::IpAddr>().unwrap()],
        "first valid answer wins"
    );
    assert!(env.edge().metrics.snapshot().upstream["fast"].hedges >= 1);
    // Failover: a dead first upstream times out and the query moves on.
    let mut c = cfg.clone();
    c["profiles"]["default"]["upstream"] = "f".into();
    env.set_config(&c).await;
    let m = udp_q(env.dns(), &Q::new("failover.example", 1)).await;
    assert_eq!(m.ips(), vec!["192.0.2.2".parse::<std::net::IpAddr>().unwrap()]);
    let s = env.edge().metrics.snapshot();
    assert!(s.upstream["dead"].errors >= 1);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_optimistic_and_do_clients_never_get_stale_data() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.5", 1)]))
    })
    .await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    let addr = env.dns();
    udp_q(addr, &Q::new("opt.example", 1)).await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // Expired, optimistic group, DO=0: answered at once from the cache with stale_ttl and EDE 3.
    let m = udp_q(addr, &Q::new("opt.example", 1)).await;
    assert_eq!(m.ttls(), vec![30]);
    assert_eq!(m.ede(), vec![(3, "cause=optimistic".to_owned())]);
    // ...and refreshed once in the background.
    assert!(wait_until(T, || up.count() >= 2).await);
    let rec = env
        .q_record_where("opt.example", |r| r["upstream"]["stale"] == true)
        .await;
    assert_eq!(rec["upstream"]["cause"], "optimistic");
    assert!(env.edge().metrics.snapshot().stale_served >= 1);
    // A DO client never gets stale data: an expired entry is a miss.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let n = up.count();
    let m = udp_q(addr, &Q::new("opt.example", 1).dnssec()).await;
    assert!(m.ede().is_empty());
    assert_eq!(up.count(), n + 1);
    // Every upstream fails: DO=0 gets the stale answer with the failure's cause; DO=1 SERVFAIL.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    up.set(|_m: &Msg, _q: &[u8]| Act::Drop);
    let mut c = one_upstream(&up, "udp");
    c["upstream_groups"]["g"]["optimistic"] = false.into();
    env.set_config(&c).await;
    let m = udp_q(env.dns(), &Q::new("opt.example", 1)).await;
    assert_eq!(m.ede(), vec![(3, "cause=timeout".to_owned())]);
    let m = udp_q(env.dns(), &Q::new("opt.example", 1).dnssec()).await;
    assert_eq!(m.rcode, 2);
    assert_eq!(m.ede(), vec![(23, "cause=timeout".to_owned())]);
    // Nothing cached at all: SERVFAIL with EDE 23.
    let m = udp_q(env.dns(), &Q::new("never.example", 1)).await;
    assert_eq!((m.rcode, m.ede_codes()), (2, vec![23]));
    assert_eq!(env.q_record("never.example").await["decision"], "servfail");
    env.shutdown().await;
}

/// edge.md §7 step 3, §6: coalesced work returns an upstream's stale (EDE 3) answer to every
/// waiter; a waiter that set DO retries on its own. The group is encrypted, so DO=0 and DO=1
/// clients share the upstream DO (1) and so one upstream query (D14: a plain group keeps the
/// client's DO, and the two never coalesced).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_stale_answers_are_withheld_from_do_clients_even_when_coalesced() {
    let stale = FakeUpstream::dot(|m: &Msg, _q: &[u8]| {
        Act::Delay(
            Duration::from_millis(150),
            Box::new(Act::Answer(Ans {
                answers: vec![a(&m.qname, "192.0.2.9", 60)],
                ede: vec![(3, String::new())],
                opt: true,
                ..Default::default()
            })),
        )
    })
    .await;
    let env = start(one_upstream(&stale, "dot"), |_| {}).await;
    let addr = env.dns();
    let a0 = tokio::spawn(async move { udp_q(addr, &Q::new("st.example", 1)).await });
    let a1 = tokio::spawn(async move { udp_q(addr, &Q::new("st.example", 1).dnssec()).await });
    let (m0, m1) = (a0.await.unwrap(), a1.await.unwrap());
    assert_eq!(
        m0.ips(),
        vec!["192.0.2.9".parse::<std::net::IpAddr>().unwrap()],
        "DO=0 gets it"
    );
    assert_eq!(m1.rcode, 2, "DO=1: no other upstream, SERVFAIL");
    assert_eq!(m1.ede(), vec![(23, "cause=stale".to_owned())]);
    assert_eq!(stale.count(), 1, "one upstream query served both (coalesced)");
    // Not cached: the next query goes upstream again.
    udp_q(addr, &Q::new("st.example", 1)).await;
    assert_eq!(stale.count(), 2);
    env.shutdown().await;
}

/// edge.md §6, §8 (D14): coalescing never merges queries whose CD or upstream DO differ (a plain
/// group keeps the client's DO), and merges those that differ only in the client's DO when the
/// upstream DO is the same (an encrypted group).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coalescing_keys_on_cd_and_upstream_do() {
    let slow = |m: &Msg, _q: &[u8]| {
        Act::Delay(
            Duration::from_millis(300),
            Box::new(Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.10", 300)]))),
        )
    };
    let plain = FakeUpstream::plain(slow).await;
    let dot_up = FakeUpstream::dot(slow).await;
    let mut cfg = base_config(
        json!({
            "g": {"upstreams": ["plain"], "strategy": "failover", "optimistic": true},
            "e": {"upstreams": ["enc"], "strategy": "failover", "optimistic": true},
        }),
        json!({"plain": plain_upstream(&plain, "udp"), "enc": tls_upstream(&dot_up, "dot")}),
    );
    cfg["profiles"]["enc"] = json!({"upstream": "e"});
    let env = start(cfg.clone(), |_| {}).await;
    let addr = env.dns();
    let both = |a: Q, b: Q| async move {
        let x = tokio::spawn(async move { udp_q(addr, &a).await });
        let y = tokio::spawn(async move { udp_q(addr, &b).await });
        (x.await.unwrap(), y.await.unwrap())
    };
    // Plain group: the upstream DO is the client's.
    both(Q::new("do.example", 1), Q::new("do.example", 1).dnssec()).await;
    let dos: Vec<bool> = plain
        .seen()
        .iter()
        .map(|s| s.msg.opt.as_ref().unwrap().do_bit)
        .collect();
    assert_eq!(dos.len(), 2, "different upstream DO: not coalesced");
    assert!(dos.contains(&true) && dos.contains(&false));
    // CD differs.
    let mut cd = Q::new("cd.example", 1);
    cd.cd = true;
    both(Q::new("cd.example", 1), cd).await;
    let cds: Vec<bool> = plain
        .seen()
        .iter()
        .filter(|s| s.msg.qname == "cd.example")
        .map(|s| s.msg.cd)
        .collect();
    assert_eq!(cds.len(), 2, "different CD: not coalesced");
    assert!(cds.contains(&true) && cds.contains(&false));
    // Encrypted group: both clients' queries are DO=1 upstream, so they share one.
    let mut c = cfg.clone();
    c["default_profile"] = "enc".into();
    env.set_config(&c).await;
    let (m0, m1) = both(Q::new("same.example", 1), Q::new("same.example", 1).dnssec()).await;
    assert_eq!((m0.rcode, m1.rcode), (0, 0));
    assert_eq!(dot_up.count(), 1, "same upstream DO and CD: coalesced");
    env.shutdown().await;
}

/// D11 (edge.md §4, edge-firewall.md §3): a rewritten answer (records, a host-IP mapping, a
/// CNAME rewrite's CNAME) carries `block_response.ttl` clamped to the profile's `ttl`, the same
/// `client_ttl` the firewall gets; a block keeps `block_response.ttl` as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rewritten_answers_carry_the_clamped_ttl_the_firewall_gets() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!(["rw", "hosts"]);
    cfg["profiles"]["default"]["ttl"] = json!({"min": 60, "max": 120});
    cfg["profiles"]["default"]["block_response"] = json!({"type": "null_ip", "ttl": 10});
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![
            (
                "rw",
                bundle(
                    "rw",
                    BundleAction::Block,
                    &[
                        "||r.example^$dnsrewrite=NOERROR;A;192.0.2.77",
                        "||c.example^$dnsrewrite=NOERROR;CNAME;target.example",
                        "||ads.example^",
                    ],
                ),
            ),
            (
                "hosts",
                bundle_fmt(
                    "hosts",
                    BundleAction::Block,
                    &["192.0.2.88 mapped.example"],
                    picket_rules::formats::Format::Hosts,
                ),
            ),
        ],
    );
    let rec = Arc::new(std::sync::Mutex::new(vec![]));
    env.edge()
        .dns
        .hooks
        .firewall
        .store(Arc::new(Box::new(RecFw(Arc::clone(&rec)))));
    let addr = env.dns();
    let m = udp_q(addr, &Q::new("r.example", 1)).await;
    assert_eq!(m.ttls(), vec![60]);
    assert_eq!(rec.lock().unwrap().pop().unwrap().1, 60);
    let m = udp_q(addr, &Q::new("mapped.example", 1)).await;
    assert_eq!(m.ttls(), vec![60]);
    assert_eq!(rec.lock().unwrap().pop().unwrap().1, 60);
    // The CNAME at the clamped block TTL; the target's records at their own clamped TTL (300 →
    // 120), which the firewall gets for the addresses.
    let m = udp_q(addr, &Q::new("c.example", 1)).await;
    assert_eq!(m.types(), vec![5, 1]);
    assert_eq!(m.ttls(), vec![60, 120]);
    assert_eq!(rec.lock().unwrap().pop().unwrap().1, 120);
    // A block isn't clamped and never reaches the firewall.
    let m = udp_q(addr, &Q::new("ads.example", 1)).await;
    assert_eq!(m.ttls(), vec![10]);
    assert!(rec.lock().unwrap().is_empty());
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_tc_fails_the_upstream_and_udp_tc_retries_over_tcp() {
    // Over UDP the answer is truncated; over TCP it is whole.
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.3", 60)]))
    })
    .await;
    let seen_tcp = Arc::clone(&up.seen);
    up.set(move |m: &Msg, _q: &[u8]| {
        let last = seen_tcp
            .lock()
            .unwrap()
            .last()
            .map(|s| s.transport)
            .unwrap_or("udp");
        if last == "udp" {
            Act::Answer(Ans {
                tc: true,
                opt: true,
                ..Default::default()
            })
        } else {
            Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.3", 60)]))
        }
    });
    // A DoT upstream that always sets TC (S6), then a good one.
    let bad_dot = FakeUpstream::dot(|_m: &Msg, _q: &[u8]| {
        Act::Answer(Ans {
            tc: true,
            opt: true,
            ..Default::default()
        })
    })
    .await;
    let good_dot =
        FakeUpstream::dot(|m: &Msg, _q: &[u8]| Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.4", 60)])))
            .await;
    let mut cfg = base_config(
        json!({
            "g": {"upstreams": ["up1"], "strategy": "failover", "optimistic": true},
            "d": {"upstreams": ["bad", "good"], "strategy": "failover", "optimistic": true},
        }),
        json!({"up1": plain_upstream(&up, "udp"), "bad": tls_upstream(&bad_dot, "dot"), "good": tls_upstream(&good_dot, "dot")}),
    );
    cfg["profiles"]["dot"] = json!({"upstream": "d"});
    let env = start(cfg.clone(), |_| {}).await;
    let m = udp_q(env.dns(), &Q::new("tc.example", 1)).await;
    assert_eq!(m.ips(), vec!["192.0.2.3".parse::<std::net::IpAddr>().unwrap()]);
    let transports: Vec<&str> = up.seen().iter().map(|s| s.transport).collect();
    assert_eq!(transports, vec!["udp", "tcp"], "UDP TC retried over TCP");
    let mut c = cfg.clone();
    c["default_profile"] = "dot".into();
    env.set_config(&c).await;
    let m = udp_q(env.dns(), &Q::new("tc2.example", 1)).await;
    assert_eq!(m.ips(), vec!["192.0.2.4".parse::<std::net::IpAddr>().unwrap()]);
    assert!(
        env.edge().metrics.snapshot().upstream["bad"]
            .invalid
            .get("tc_stream")
            .copied()
            .unwrap_or(0)
            >= 1
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_upstream_and_invalid_answers_are_counted_per_reason() {
    let doh_up = FakeUpstream::doh(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.44", 60)]))
    })
    .await;
    // Our ID but another question: invalid (edge.md §6: matched on ID plus question).
    let bad = FakeUpstream::dot(|_m: &Msg, q: &[u8]| {
        let mut r = answer(q, &Ans::records(vec![]));
        r[13] = b'z';
        Act::Raw(r)
    })
    .await;
    // A plain upstream whose answer has trailing bytes.
    let trailing = FakeUpstream::plain(|m: &Msg, q: &[u8]| {
        let mut r = answer(q, &Ans::records(vec![a(&m.qname, "192.0.2.1", 60)]));
        r.extend_from_slice(&[0, 0]);
        Act::Raw(r)
    })
    .await;
    let mut cfg = base_config(
        json!({
            "g": {"upstreams": ["bad", "doh"], "strategy": "failover", "optimistic": true},
            "p": {"upstreams": ["trailing"], "strategy": "failover", "optimistic": true},
        }),
        json!({"bad": tls_upstream(&bad, "dot"), "doh": tls_upstream(&doh_up, "doh"), "trailing": plain_upstream(&trailing, "udp")}),
    );
    cfg["profiles"]["p"] = json!({"upstream": "p"});
    let env = start(cfg.clone(), |_| {}).await;
    let m = udp_q(env.dns(), &Q::new("x.example", 1)).await;
    assert_eq!(m.ips(), vec!["192.0.2.44".parse::<std::net::IpAddr>().unwrap()]);
    let s = &doh_up.seen()[0];
    assert_eq!(s.raw[..2], [0, 0], "DoH queries use ID 0 (RFC 8484)");
    assert_eq!(s.raw.len() % 128, 0, "padded");
    let s = env.edge().metrics.snapshot();
    assert_eq!(
        s.upstream["bad"].invalid.get("question_mismatch").copied(),
        Some(1)
    );
    // A malformed answer is counted per reason and upstream; no other upstream → SERVFAIL.
    let mut c = cfg.clone();
    c["default_profile"] = "p".into();
    env.set_config(&c).await;
    let m = udp_q(env.dns(), &Q::new("y.example", 1)).await;
    assert_eq!(m.ede(), vec![(23, "cause=invalid".to_owned())]);
    let s = env.edge().metrics.snapshot();
    assert!(
        s.upstream["trailing"]
            .invalid
            .get("trailing_bytes")
            .copied()
            .unwrap_or(0)
            >= 1,
        "{:?}",
        s.upstream["trailing"].invalid
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prefetch_refreshes_hot_entries_near_expiry() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.6", 3)]))
    })
    .await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    let addr = env.dns();
    udp_q(addr, &Q::new("hot.example", 1)).await;
    // The last 10 % of a 3 s TTL starts at 2.7 s.
    tokio::time::sleep(Duration::from_millis(2750)).await;
    for _ in 0..3 {
        udp_q(addr, &Q::new("hot.example", 1)).await;
    }
    assert!(
        wait_until(T, || up.count() >= 2).await,
        "prefetched in the background"
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limits_refuse_without_logging() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["limits"] = json!({"client_qps": 1, "client_inflight": 64});
    let env = start(cfg, |_| {}).await;
    let addr = env.dns();
    // Burst = max(5 × qps, 300) = 300; then REFUSED.
    let mut refused = 0;
    for i in 0..320 {
        let m = udp_q(addr, &Q::new(&format!("n{}.ads.example", i % 3), 16)).await;
        if m.rcode == 5 {
            refused += 1;
        }
    }
    assert!(refused >= 15, "{refused}");
    let rejected = env.edge().metrics.snapshot().rejected;
    assert!(rejected >= refused as u64);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let logged = env.q_records().len();
    assert!(logged <= 320 - refused, "refused queries aren't logged: {logged}");
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panics_in_a_query_task_answer_servfail() {
    struct Boom;
    #[async_trait::async_trait]
    impl picket_edge::dns::FirewallEnsure for Boom {
        async fn ensure(&self, _r: &picket_edge::dns::FwRequest<'_>) -> picket_edge::dns::FwOutcome {
            panic!("injected");
        }
    }
    let up = FakeUpstream::plain(ok_upstream()).await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    env.edge().dns.hooks.firewall.store(Arc::new(
        Box::new(Boom) as Box<dyn picket_edge::dns::FirewallEnsure>
    ));
    let m = udp_q(env.dns(), &Q::new("panic.example", 1)).await;
    assert_eq!(m.rcode, 2);
    assert_eq!(env.edge().metrics.snapshot().panics, 1);
    assert!(
        wait_until(T, || env.core.with(|s| s
            .logs
            .iter()
            .any(|l| l["t"] == "event" && l["kind"] == "panic")))
        .await
    );
    // The edge keeps serving.
    env.edge().dns.hooks.firewall.store(Arc::new(
        Box::new(picket_edge::dns::NoFirewall) as Box<dyn picket_edge::dns::FirewallEnsure>
    ));
    assert_eq!(udp_q(env.dns(), &Q::new("after.example", 1)).await.rcode, 0);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_down_condition_and_mixed_groups_refused() {
    let dead = FakeUpstream::plain(|_m: &Msg, _q: &[u8]| Act::Drop).await;
    let dot = FakeUpstream::dot(ok_upstream()).await;
    let mut cfg = base_config(
        json!({
            "g": {"upstreams": ["dead"], "strategy": "failover", "optimistic": true},
            "mixed": {"upstreams": ["dead", "dot"], "strategy": "failover"},
        }),
        json!({"dead": plain_upstream(&dead, "udp"), "dot": tls_upstream(&dot, "dot")}),
    );
    cfg["profiles"]["mixed"] = json!({"upstream": "mixed"});
    let env = start(cfg, |_| {}).await;
    assert!(
        env.edge().dns.pool.group("mixed").is_none(),
        "a mixed group is refused"
    );
    // Failures open the breaker; the group is unhealthy, and a query fails fast with `down`.
    for i in 0..4 {
        let _ = udp_q(env.dns(), &Q::new(&format!("d{i}.example"), 1)).await;
    }
    assert!(env.edge().dns.pool.group_down("g"));
    let m = udp_q(env.dns(), &Q::new("down.example", 1)).await;
    assert_eq!(m.ede(), vec![(23, "cause=down".to_owned())]);
    // All unhealthy for `down_after` (30 s in production): `upstream_down` for the group, in the
    // heartbeat, and as a condition record.
    let edge = Arc::clone(env.edge());
    let kind = picket_api::session::condition_kind::UPSTREAM_DOWN;
    assert!(wait_until(T, || edge.conditions.is_set(kind, Some("g"))).await);
    assert!(
        wait_until(T, || env
            .core
            .with(|s| s.logs.iter().any(|l| l["t"] == "condition"
                && l["kind"] == kind
                && l["key"] == "g")))
        .await
    );
    // The upstream answers again: after the breaker's open time a probe succeeds and it clears.
    dead.set(ok_upstream());
    assert!(
        wait_until(Duration::from_secs(20), || {
            let _ = std::net::UdpSocket::bind("127.0.0.1:0")
                .and_then(|s| s.send_to(&Q::new("probe.example", 1).bytes(), env.dns()));
            !edge.conditions.is_set(kind, Some("g"))
        })
        .await,
        "cleared once healthy"
    );
    env.shutdown().await;
}

/// rules.md §5, edge.md §4 and §10: a sync lookup is asked only about a query name the local lists
/// (ladder steps 1–3, on the query) left undecided. A name a block bundle blocks or an allow bundle
/// allows never reaches the provider. A block bundle's exception decides nothing, so its name
/// is still looked up. The call starts with the upstream query, not after its answer: response
/// checks (step 5) don't hold it back, and the provider sees only the query name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_lookups_ask_only_about_names_the_local_lists_left_undecided() {
    use picket_lookup::testkit::ScriptedModule;
    use picket_lookup::{Answer, Verdict};
    use std::sync::Mutex;
    use std::time::Instant;
    // When the upstream got the slow name's query, and when the provider was asked about it.
    let upstream_at: Arc<Mutex<Option<Instant>>> = Arc::default();
    let provider_at: Arc<Mutex<Option<Instant>>> = Arc::default();
    let pa = Arc::clone(&provider_at);
    let module = ScriptedModule::new("scripted", move |_cfg, name, _n| {
        if name == "slow-upstream.example" {
            pa.lock().unwrap().get_or_insert_with(Instant::now);
        }
        Box::pin(async move {
            Ok(Answer {
                verdict: if name.starts_with("bad.") || name.starts_with("except.") {
                    Verdict::Block {
                        score: None,
                        reason: "remote".into(),
                    }
                } else {
                    Verdict::Clean
                },
                detail: None,
            })
        })
    });
    let mut reg = picket_lookup::Registry::empty();
    reg.insert(module.clone());
    let ua = Arc::clone(&upstream_at);
    let ok = ok_upstream();
    let up = FakeUpstream::plain(move |m: &Msg, q: &[u8]| {
        if m.qname.trim_end_matches('.') == "slow-upstream.example" {
            ua.lock().unwrap().get_or_insert_with(Instant::now);
            return Act::Delay(Duration::from_millis(800), Box::new(ok(m, q)));
        }
        ok(m, q)
    })
    .await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["allow"] = json!(["allow-common"]);
    cfg["profiles"]["default"]["block"] = json!(["block-common"]);
    cfg["profiles"]["default"]["lookups"] = json!([{"provider": "am", "mode": "sync"}]);
    cfg["profiles"]["default"]["lookup_budget_ms"] = 3000.into();
    cfg["lookup_providers"] = json!({"am": {"module": "scripted", "config": {}, "cache_generation": "0123456789abcdef",
        "sync_timeout_ms": 3000, "async_timeout_ms": 5000, "fail_mode": "open",
        "scope": {"exclude_bundles": [], "qtypes": ["A", "AAAA"]}}});
    let reg = Arc::new(reg);
    let env = start(cfg, |t| t.lookup_registry = Some(Arc::clone(&reg))).await;
    set_bundles(
        env.edge(),
        vec![
            (
                "allow-common",
                bundle("allow-common", BundleAction::Allow, &["||good.example^"]),
            ),
            (
                "block-common",
                bundle(
                    "block-common",
                    BundleAction::Block,
                    &["||ads.example^", "@@||except.ads.example^"],
                ),
            ),
        ],
    );
    let addr = env.dns();
    // Step 3, a block bundle: blocked locally; the provider isn't asked.
    let m = udp_q(addr, &Q::new("x.ads.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4]);
    assert_eq!(env.q_record("x.ads.example").await["reason"]["step"], 3);
    // Step 2, an allow bundle: allowed locally; the name never leaves the box.
    let m = udp_q(addr, &Q::new("www.good.example", 1)).await;
    assert!(m.ede().is_empty(), "{:?}", m.ede());
    assert_eq!(env.q_record("www.good.example").await["reason"]["step"], 2);
    // Undecided: the provider decides (step 4).
    let m = udp_q(addr, &Q::new("bad.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4]);
    assert_eq!(env.q_record("bad.example").await["reason"]["step"], 4);
    // A block bundle's exception lets the name pass step 3 without deciding it: still asked.
    let m = udp_q(addr, &Q::new("except.ads.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4]);
    assert_eq!(env.q_record("except.ads.example").await["reason"]["step"], 4);
    // Asked at the same time as the upstream, not after its (0.8 s late) answer; the reply
    // itself doesn't matter here (the edge may give up on that upstream first).
    let _ = udp_q(addr, &Q::new("slow-upstream.example", 1)).await;
    let (u, p) = (
        upstream_at.lock().unwrap().unwrap(),
        provider_at.lock().unwrap().unwrap(),
    );
    let gap = p.saturating_duration_since(u).max(u.saturating_duration_since(p));
    assert!(
        gap < Duration::from_millis(500),
        "provider asked {gap:?} from the upstream query"
    );
    let asked: Vec<String> = module.names.lock().unwrap().clone();
    assert_eq!(
        asked,
        ["bad.example", "except.ads.example", "slow-upstream.example"],
        "only names the local lists left undecided"
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_lookups_block_fail_modes_and_late_answers() {
    use picket_lookup::testkit::ScriptedModule;
    use picket_lookup::{Answer, Verdict};
    let module = ScriptedModule::new("scripted", |_cfg, name, _n| {
        Box::pin(async move {
            match name.as_str() {
                "bad.example" => Ok(Answer {
                    verdict: Verdict::Block {
                        score: Some(9.0),
                        reason: "malware".into(),
                    },
                    detail: None,
                }),
                "slow.example" => {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    Ok(Answer {
                        verdict: Verdict::Block {
                            score: None,
                            reason: "late".into(),
                        },
                        detail: None,
                    })
                }
                _ => Ok(Answer {
                    verdict: Verdict::Clean,
                    detail: None,
                }),
            }
        })
    });
    let mut reg = picket_lookup::Registry::empty();
    reg.insert(module.clone());
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["lookups"] = json!([{"provider": "am", "mode": "sync"}]);
    cfg["profiles"]["default"]["lookup_budget_ms"] = 150.into();
    cfg["lookup_providers"] = json!({"am": {"module": "scripted", "config": {}, "cache_generation": "0123456789abcdef",
        "sync_timeout_ms": 150, "async_timeout_ms": 2000, "fail_mode": "open",
        "scope": {"exclude_bundles": [], "qtypes": ["A", "AAAA"]}}});
    let reg = Arc::new(reg);
    let env = start(cfg.clone(), |t| t.lookup_registry = Some(Arc::clone(&reg))).await;
    let addr = env.dns();
    // A Block blocks (step 4): EDE `lookup=<provider> verdict=block block=<id>`.
    let m = udp_q(addr, &Q::new("bad.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4]);
    assert!(
        m.ede()[0].1.starts_with("lookup=am verdict=block block="),
        "{:?}",
        m.ede()
    );
    let rec = env.q_record("bad.example").await;
    assert_eq!(rec["reason"]["step"], 4);
    assert_eq!(rec["reason"]["provider"], "am");
    assert_eq!(rec["lookups"][0]["verdict"], "block");
    assert_eq!(rec["lookups"][0]["reason"], "malware");
    // Clean: resolved.
    assert_eq!(udp_q(addr, &Q::new("good.example", 1)).await.ede(), vec![]);
    // A slow provider under fail_mode open: the reply doesn't wait past the budget; the late
    // answer is logged as a `lookup` record and lands in the RAM tier.
    let t0 = std::time::Instant::now();
    let m = udp_q(addr, &Q::new("slow.example", 1)).await;
    assert!(t0.elapsed() < Duration::from_millis(390), "{:?}", t0.elapsed());
    assert!(m.ede().is_empty(), "fail open");
    let rec = env.q_record("slow.example").await;
    assert_eq!(rec["lookups"][0]["timed_out"], true);
    assert_eq!(rec["lookups"][0]["retry"], true);
    assert!(
        wait_until(T, || env.core.with(|s| s
            .logs
            .iter()
            .any(|l| l["t"] == "lookup" && l["qname"] == "slow.example")))
        .await,
        "late answer logged"
    );
    // Next time the RAM tier has the late Block.
    let m = udp_q(addr, &Q::new("slow.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4]);
    // fail_mode closed: a timeout blocks, with verdict=timeout.
    let mut c = cfg.clone();
    c["lookup_providers"]["am"]["fail_mode"] = "closed".into();
    c["lookup_providers"]["am"]["cache_generation"] = "fedcba9876543210".into();
    env.set_config(&c).await;
    let m = udp_q(env.dns(), &Q::new("slow.example", 1)).await;
    assert!(m.ede()[0].1.contains("verdict=timeout"), "{:?}", m.ede());
    // Lookup metrics reach the heartbeat.
    assert!(
        wait_until(T, || env.core.with(|s| s.heartbeats.last().is_some_and(|h| h
            .metrics
            .lookups
            .get("am")
            .is_some_and(|l| l.calls >= 2))))
        .await
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listeners_rebind_keep_unchanged_sockets_and_report_rejects() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "other", "proto": "dns", "bind": "127.0.0.1:0"},
    ]);
    let env = start(cfg.clone(), |_| {}).await;
    let edge = Arc::clone(env.edge());
    let first = env.addr("lan-dns");
    let other = env.addr("other");
    // ready_version is set once listeners are bound; the watchdog uses the test query.
    assert!(wait_until(T, || edge.state.get().ready_version.is_some()).await);
    assert!(edge.watchdog.in_pipeline_mode());
    let passes = edge.watchdog.pings.load(Ordering::Relaxed);
    let _ = passes;
    assert!(picket_edge::dns::pipeline::self_test(&edge).await);
    // A config change that drops "other" and keeps "lan-dns": lan-dns keeps its socket.
    let mut c = cfg.clone();
    c["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0", "limits": {"udp_payload": 1400}},
    ]);
    env.set_config(&c).await;
    assert!(wait_until(T, || edge.dns.listeners.status().len() == 1).await);
    assert_eq!(env.addr("lan-dns"), first, "unchanged sockets are kept");
    assert!(
        udp(other, &Q::new("x.example", 1).bytes()).await.is_none(),
        "dropped listener closed"
    );
    assert_eq!(udp_q(first, &Q::new("x.example", 1)).await.rcode, 0);
    // The status lists listeners; the admin `explain` works offline.
    let sock = env._d.run.join("edge.sock");
    let v = picket_edge::admin::call(&sock, "status", json!({}))
        .await
        .unwrap();
    assert_eq!(v["listeners"][0]["id"], "lan-dns");
    assert_eq!(v["listeners"][0]["state"], "bound");
    let v = picket_edge::admin::call(&sock, "explain", json!({"name": "x.example", "type": "AAAA"}))
        .await
        .unwrap();
    assert_eq!(v["decision"], "resolve");
    assert_eq!(v["profile"], "default");
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allowed_binds_reject_and_bind_failures_hold_listener_failed() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    // A DNS listener binds UDP and TCP on its port, so the busy port is held in both: holding
    // only UDP let the retry fail on TCP whenever another test's socket used that TCP port
    // (seen under parallel load), and the condition never cleared within T.
    let (busy, busy_port) = loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if let Ok(udp) = std::net::UdpSocket::bind(("127.0.0.1", port)) {
            break ((udp, tcp), port);
        }
    };
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "nope", "proto": "dns", "bind": "127.0.0.1:1"},
        {"id": "busy", "proto": "dns", "bind": format!("127.0.0.1:{busy_port}")},
    ]);
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(
        &d.config,
        Some(&core),
        json!({"allowed_binds": ["127.0.0.1:0", format!("127.0.0.1:{busy_port}")]}),
    );
    let id = core.set_config(&cfg);
    let r = service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        tuning(&d),
        |_| {},
    )
    .await
    .unwrap();
    let edge = Arc::clone(&r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    let kind = picket_api::session::condition_kind::LISTENER_FAILED;
    assert!(wait_until(T, || edge.conditions.is_set(kind, Some("busy"))).await);
    assert!(
        wait_until(T, || core.with(|s| s
            .logs
            .iter()
            .any(|l| l["kind"] == "listener_rejected" && l["listener"] == "nope")))
        .await
    );
    // The port frees up: the retry binds it and the condition clears.
    drop(busy);
    assert!(wait_until(T, || !edge.conditions.is_set(kind, Some("busy"))).await);
    assert!(wait_until(T, || edge.dns.listeners.all_bound()).await);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interfaces_drop_udp_from_other_interfaces() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0", "interfaces": ["no-such-if0"]},
    ]);
    let env = start(cfg, |_| {}).await;
    assert!(udp(env.dns(), &Q::new("x.example", 1).bytes()).await.is_none());
    assert!(env.edge().metrics.snapshot().rejected >= 1);
    assert_eq!(up.count(), 0);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flush_requests_empty_the_cache() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    udp_q(env.dns(), &Q::new("f.example", 1)).await;
    udp_q(env.dns(), &Q::new("f.example", 1)).await;
    assert_eq!(up.count(), 1);
    let mut c = one_upstream(&up, "udp");
    c["flush"] = json!({"dns": "1111222233334444"});
    env.set_config(&c).await;
    assert!(
        wait_until(T, || env.edge().state.get().applied.flush_dns.as_deref()
            == Some("1111222233334444"))
        .await
    );
    udp_q(env.dns(), &Q::new("f.example", 1)).await;
    assert_eq!(up.count(), 2, "flushed");
    env.shutdown().await;
}

/// A self-signed certificate and key PEM for `name`.
fn self_signed(name: &str) -> (String, String) {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    (cert.pem(), kp.serialize_pem())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_certificates_reload_on_change() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let tmp = tempfile::tempdir().unwrap();
    let (c1, k1) = self_signed("dot.example.lan");
    let cert = tmp.path().join("cert.pem");
    let key = tmp.path().join("key.pem");
    std::fs::write(&cert, &c1).unwrap();
    std::fs::write(&key, &k1).unwrap();
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0",
         "tls": {"cert_file": cert.to_str().unwrap(), "key_file": key.to_str().unwrap()}},
    ]);
    cfg["profiles"]["strict"] = json!({"upstream": "g", "block": ["b"]});
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![("b", bundle("b", BundleAction::Block, &["||blocked.example^"]))],
    );
    let edge = Arc::clone(env.edge());
    assert!(wait_until(T, || edge.dns.certs.slot("lan-dot").is_some_and(|s| s.has_cert())).await);
    let q = Q::new("blocked.example", 1).bytes();
    let r = dot(
        env.addr("lan-dot"),
        "dot.example.lan",
        &c1,
        std::slice::from_ref(&q),
    )
    .await
    .unwrap();
    assert_eq!(parse(&r[0]).rcode, 0);
    // The SNI prefix works for a file certificate's names too.
    let r = dot(
        env.addr("lan-dot"),
        "strict.dot.example.lan",
        &c1,
        std::slice::from_ref(&q),
    )
    .await;
    // (the certificate doesn't cover strict.dot.example.lan, so a strict client refuses it)
    assert!(r.is_err() || parse(&r.unwrap()[0]).ede_codes() == vec![15, 4]);
    // New files: served without a rebind.
    let (c2, k2) = self_signed("dot.example.lan");
    tokio::time::sleep(Duration::from_millis(20)).await;
    std::fs::write(&key, &k2).unwrap();
    std::fs::write(&cert, &c2).unwrap();
    let port = env.addr("lan-dot");
    assert!(
        wait_until(T, || {
            let s = edge.dns.certs.slot("lan-dot").unwrap();
            s.info().last_error.is_none() && s.has_cert()
        })
        .await
    );
    let mut ok = false;
    for _ in 0..100 {
        if let Ok(r) = dot(port, "dot.example.lan", &c2, std::slice::from_ref(&q)).await
            && !r.is_empty()
        {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok, "the new certificate is served");
    assert_eq!(env.addr("lan-dot"), port, "no rebind");
    // A broken pair keeps the last good one.
    std::fs::write(&cert, b"not a certificate").unwrap();
    assert!(
        wait_until(T, || edge
            .dns
            .certs
            .slot("lan-dot")
            .unwrap()
            .info()
            .last_error
            .is_some())
        .await
    );
    assert!(
        dot(port, "dot.example.lan", &c2, std::slice::from_ref(&q))
            .await
            .is_ok()
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_json_lookups_use_the_edges_http_client_and_resolver() {
    use http_body_util::Full;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    // An HTTPS API at api.test, which the edge resolves through its own upstreams.
    let (cert, key) = self_signed("api.test");
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_slice_iter(cert.as_bytes())
        .map(|c| c.unwrap())
        .collect();
    let mut sc =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));
    let api = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_port = api.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU32::new(0));
    let h2 = Arc::clone(&hits);
    let server = tokio::spawn(async move {
        loop {
            let Ok((c, _)) = api.accept().await else { return };
            let acc = acceptor.clone();
            let hits = Arc::clone(&h2);
            tokio::spawn(async move {
                let Ok(tls) = acc.accept(c).await else { return };
                let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let body = match req.uri().path() {
                        "/v1/domain/bad.example" => r#"{"risk": 9}"#,
                        _ => r#"{"risk": 1}"#,
                    };
                    async move {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                            bytes::Bytes::from(body),
                        )))
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| match (m.qname.as_str(), m.qtype) {
        ("api.test", 1) => Act::Answer(Ans::records(vec![a("api.test", "127.0.0.1", 300)])),
        ("api.test", _) => Act::Answer(Ans::records(vec![])),
        _ => Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.1", 300)])),
    })
    .await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["lookups"] = json!([{"provider": "api", "mode": "sync"}]);
    cfg["profiles"]["default"]["lookup_budget_ms"] = 3000.into();
    cfg["lookup_providers"] = json!({"api": {"module": "http_json", "cache_generation": "0123456789abcdef",
        "config": {"url": format!("https://api.test:{api_port}/v1/domain/{{domain}}"),
                   "verdict": {"pointer": "/risk", "block_if": ">= 7", "clean_if": "< 4"}},
        "sync_timeout_ms": 3000, "async_timeout_ms": 5000, "scope": {"exclude_bundles": []}}});
    let env = start(cfg, |t| t.dns.http_roots = Some(cert.clone())).await;
    let m = udp_q(env.dns(), &Q::new("bad.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4], "{m:?}");
    let m = udp_q(env.dns(), &Q::new("good.example", 1)).await;
    assert!(m.ede().is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert!(
        up.seen().iter().any(|s| s.msg.qname == "api.test"),
        "resolved through the edge's upstreams"
    );
    server.abort();
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_lookups_ask_their_servers_over_the_upstream_transports() {
    // A filtering resolver over DoT: EDE 15 for blocked names.
    let filt = FakeUpstream::dot(|m: &Msg, _q: &[u8]| {
        if m.qname == "bad.example" {
            Act::Answer(Ans {
                rcode: 3,
                ede: vec![(15, "blocked".into())],
                opt: true,
                ..Default::default()
            })
        } else {
            Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.1", 60)]))
        }
    })
    .await;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["lookups"] = json!([{"provider": "q9", "mode": "sync"}]);
    cfg["profiles"]["default"]["lookup_budget_ms"] = 2000.into();
    cfg["lookup_providers"] = json!({"q9": {"module": "dns", "cache_generation": "0123456789abcdef",
        "config": {"transport": "dot",
                   "servers": [{"ip": "127.0.0.1", "port": filt.addr.port(), "tls_host": UPSTREAM_TLS_NAME, "trust_store": filt.cert_pem}],
                   "rules": [{"id": "blocked", "when": {"ede": [15]}, "verdict": "block"}]},
        "sync_timeout_ms": 2000, "async_timeout_ms": 5000, "scope": {"exclude_bundles": []}}});
    let env = start(cfg, |_| {}).await;
    let m = udp_q(env.dns(), &Q::new("bad.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4]);
    assert!(
        m.ede()[0].1.starts_with("lookup=q9 verdict=block"),
        "{:?}",
        m.ede()
    );
    let rec = env.q_record("bad.example").await;
    assert_eq!(rec["lookups"][0]["detail"]["transport"], "dot");
    let s = &filt.seen()[0];
    assert_eq!(s.raw.len() % 128, 0, "lookup queries to DoT servers are padded");
    // The upstream query ran in parallel with the lookup (latency = max, edge.md §4); the lookup
    // server's answer never enters the DNS cache: a good name still goes upstream.
    assert_eq!(
        up.seen().iter().filter(|s| s.msg.qname == "bad.example").count(),
        1
    );
    let m = udp_q(env.dns(), &Q::new("good.example", 1)).await;
    assert_eq!(
        m.ips(),
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
    );
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_and_tcp_listener_edges() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    let (c, k) = self_signed("dns.example.lan");
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("c.pem"), &c).unwrap();
    std::fs::write(tmp.path().join("k.pem"), &k).unwrap();
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0", "limits": {"idle_timeout_ms": 1000, "max_connections": 2}},
        {"id": "lan-doh", "proto": "doh", "bind": "127.0.0.1:0",
         "tls": {"cert_file": tmp.path().join("c.pem").to_str().unwrap(), "key_file": tmp.path().join("k.pem").to_str().unwrap()}},
    ]);
    let env = start(cfg, |_| {}).await;
    let edge = Arc::clone(env.edge());
    assert!(wait_until(T, || edge.dns.certs.slot("lan-doh").is_some_and(|s| s.has_cert())).await);
    let doh_addr = env.addr("lan-doh");
    let q = Q::new("www.example.com", 1).bytes();
    // GET and POST.
    let (st, _, body) = doh(doh_addr, "dns.example.lan", &c, "/dns-query", &q, true, &[]).await;
    assert_eq!(st, 200);
    assert_eq!(parse(&body).rcode, 0);
    let (st, _, _) = doh(doh_addr, "dns.example.lan", &c, "/dns-query", &q, false, &[]).await;
    assert_eq!(st, 200);
    // Other paths 404; a query with QR set gets no reply (400).
    let (st, _, _) = doh(doh_addr, "dns.example.lan", &c, "/other", &q, true, &[]).await;
    assert_eq!(st, 404);
    let mut qr = q.clone();
    qr[2] |= 0x80;
    let (st, _, _) = doh(doh_addr, "dns.example.lan", &c, "/dns-query", &qr, false, &[]).await;
    assert_eq!(st, 400);
    // TCP: at most max_connections; an idle connection is closed.
    let addr = env.dns();
    let c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c3 = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut b = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(2), c3.read(&mut b)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "the third connection is closed at once: {r:?}"
    );
    let mut c1 = c1;
    let r = tokio::time::timeout(Duration::from_secs(5), c1.read(&mut b)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "idle connections are closed: {r:?}"
    );
    drop(c2);
    // Listener self-check passes with every listener bound.
    assert!(edge.dns.listeners.all_bound());
    env.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Review round 1 (edge DNS data path): regressions for the validated findings.

fn stored_dns_allow(id: &str, target: &str) -> picket_edge::allows::StoredAllow {
    serde_json::from_value(json!({
        "allow_id": id, "kind": "dns", "device": "127.0.0.1", "client": "127.0.0.1",
        "target": target, "created_at": "2026-01-01T00:00:00.000000Z",
        "expires_at": "2099-01-01T00:00:00.000000Z",
    }))
    .unwrap()
}

/// D1 (edge.md §12, rules.md §5 step 1): ladder step 1 follows every change to `allows.json`. The
/// index was cached by the snapshot's address without keeping the snapshot alive, so a later
/// snapshot at a reused address kept a revoked allow working and hid a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn temp_allow_index_follows_every_allows_change() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!(["b"]);
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![("b", bundle("b", BundleAction::Block, &["||ads.example^"]))],
    );
    let addr = env.dns();
    let blocked = |m: &Msg| m.ede_codes().contains(&15);
    assert!(blocked(&udp_q(addr, &Q::new("ads.example", 1)).await));
    let allows = &env.edge().allows;
    let (mut revoked_still_allowed, mut new_allow_ignored) = (0, 0);
    let rounds = 100;
    for i in 0..rounds {
        allows.upsert(stored_dns_allow("x", "ads.example")).unwrap();
        if blocked(&udp_q(addr, &Q::new("ads.example", 1)).await) {
            new_allow_ignored += 1;
        }
        allows
            .end(&["x".into()], picket_api::logs::AllowAction::Revoked, "test")
            .unwrap();
        allows
            .upsert(stored_dns_allow(&format!("z{i}"), "other.example"))
            .unwrap();
        if !blocked(&udp_q(addr, &Q::new("ads.example", 1)).await) {
            revoked_still_allowed += 1;
        }
        allows
            .end(&[format!("z{i}")], picket_api::logs::AllowAction::Revoked, "test")
            .unwrap();
    }
    assert_eq!(
        (revoked_still_allowed, new_allow_ignored),
        (0, 0),
        "revoked allows still applied / new allows ignored over {rounds} rounds"
    );
    env.shutdown().await;
}

/// D2 (edge.md §8): one optimistic refresh in flight at a time, and a failed one doesn't stop
/// later ones, so a stale answer isn't pinned until `stale_max` after one failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_optimistic_refresh_doesnt_pin_the_stale_answer() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.5", 1)]))
    })
    .await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    let addr = env.dns();
    udp_q(addr, &Q::new("latch.example", 1)).await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // The upstream is unreachable when the first optimistic serve triggers its refresh.
    up.set(|_m: &Msg, _q: &[u8]| Act::Drop);
    let m = udp_q(addr, &Q::new("latch.example", 1)).await;
    assert_eq!(m.ede(), vec![(3, "cause=optimistic".to_owned())]);
    // While that refresh is in flight, more stale serves start no other one.
    let n = up.count();
    for _ in 0..5 {
        udp_q(addr, &Q::new("latch.example", 1)).await;
    }
    assert!(
        up.count() <= n + 1,
        "single-flighted: {} refreshes",
        up.count() - n
    );
    // The refresh fails (the attempt timeout); the upstream comes back with a new address.
    tokio::time::sleep(Duration::from_millis(1800)).await;
    up.set(|m: &Msg, _q: &[u8]| Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.6", 300)])));
    let n = up.count();
    let new_ip: std::net::IpAddr = "192.0.2.6".parse().unwrap();
    let mut got_new = false;
    for _ in 0..20 {
        let m = udp_q(addr, &Q::new("latch.example", 1)).await;
        if m.ips() == vec![new_ip] && m.ede().is_empty() {
            got_new = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up.count() > n, "a later stale serve refreshes again");
    assert!(got_new, "the refreshed answer replaces the stale one");
    env.shutdown().await;
}

/// Records every firewall ensure call (edge.md §9's seam): each call's addresses and their
/// `client_ttl` (the same for every address in these answers).
type FwCalls = Arc<std::sync::Mutex<Vec<(Vec<std::net::IpAddr>, u32)>>>;

struct RecFw(FwCalls);

#[async_trait::async_trait]
impl picket_edge::dns::FirewallEnsure for RecFw {
    async fn ensure(&self, req: &picket_edge::dns::FwRequest<'_>) -> picket_edge::dns::FwOutcome {
        let ttl = req.addrs.first().map_or(0, |a| a.client_ttl);
        assert!(req.addrs.iter().all(|a| a.client_ttl == ttl), "{req:?}");
        self.0
            .lock()
            .unwrap()
            .push((req.addrs.iter().map(|a| a.ip).collect(), ttl));
        Default::default()
    }
}

/// D3 (edge.md §4, §9; edge-firewall.md §1): every allowed or rewritten answer with addresses
/// goes through the firewall ensure point before it leaves: plain, allow-bundle and temporarily
/// allowed answers, rewrites (records, host-IP mappings, CNAME rewrites) and forward-zone
/// answers; never a block or a name the edge answers itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn firewall_ensure_covers_every_answer_with_addresses() {
    let corp = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "10.20.30.40", 60)]))
    })
    .await;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = base_config(
        json!({
            "g": {"upstreams": ["up1"], "strategy": "failover", "optimistic": true},
            "corp": {"upstreams": ["corpdns"], "strategy": "failover", "optimistic": false},
        }),
        json!({"up1": plain_upstream(&up, "udp"), "corpdns": plain_upstream(&corp, "udp")}),
    );
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0", "ips": ["192.168.1.2"], "tls": {"managed": "dns.home.arpa"}},
    ]);
    cfg["profiles"]["default"]["forward_zones"] = json!(["corp"]);
    cfg["profiles"]["default"]["allow"] = json!(["ok"]);
    cfg["profiles"]["default"]["block"] = json!(["rw", "hosts"]);
    cfg["forward_zones"] = json!({"corp": {"zone": "corp.example", "group": "corp"}});
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![
            ("ok", bundle("ok", BundleAction::Allow, &["||good.example^"])),
            (
                "rw",
                bundle(
                    "rw",
                    BundleAction::Block,
                    &[
                        "||c.example^$dnsrewrite=NOERROR;CNAME;target.example",
                        "||r.example^$dnsrewrite=NOERROR;A;192.0.2.77",
                        "||ads.example^",
                        "||temp.example^",
                    ],
                ),
            ),
            (
                "hosts",
                bundle_fmt(
                    "hosts",
                    BundleAction::Block,
                    &["192.0.2.88 mapped.example"],
                    picket_rules::formats::Format::Hosts,
                ),
            ),
        ],
    );
    env.edge()
        .allows
        .upsert(stored_dns_allow("t", "temp.example"))
        .unwrap();
    let rec = Arc::new(std::sync::Mutex::new(vec![]));
    env.edge()
        .dns
        .hooks
        .firewall
        .store(Arc::new(Box::new(RecFw(Arc::clone(&rec)))));
    let addr = env.dns();
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    let check = async |name: &str, want: Option<&str>| {
        rec.lock().unwrap().clear();
        let m = udp_q(addr, &Q::new(name, 1)).await;
        let calls = rec.lock().unwrap().clone();
        match want {
            Some(w) => {
                assert_eq!(m.ips(), vec![ip(w)], "{name}");
                assert_eq!(calls.len(), 1, "{name}: one ensure call: {calls:?}");
                assert_eq!(calls[0].0, vec![ip(w)], "{name}");
                let a_ttl = m
                    .types()
                    .iter()
                    .zip(m.ttls())
                    .find(|(t, _)| **t == 1)
                    .map(|x| x.1);
                assert_eq!(
                    a_ttl,
                    Some(calls[0].1),
                    "{name}: the firewall gets the TTL the client got for the addresses"
                );
            }
            None => assert!(calls.is_empty(), "{name}: no ensure call: {calls:?}"),
        }
    };
    check("plain.example", Some("93.184.216.34")).await;
    check("good.example", Some("93.184.216.34")).await;
    check("temp.example", Some("93.184.216.34")).await;
    check("c.example", Some("93.184.216.34")).await;
    check("r.example", Some("192.0.2.77")).await;
    check("mapped.example", Some("192.0.2.88")).await;
    check("host.corp.example", Some("10.20.30.40")).await;
    check("ads.example", None).await;
    check("dns.home.arpa", None).await;
    env.shutdown().await;
}

/// D7 (owner decision S6, edge.md §6): a UDP upstream's TCP retry that also comes back with TC
/// fails that upstream like any stream TC, and the query moves to another upstream instead of
/// serving the truncated answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tc_on_a_udp_upstreams_tcp_retry_fails_that_upstream() {
    let bad = FakeUpstream::plain(|_m: &Msg, _q: &[u8]| {
        Act::Answer(Ans {
            tc: true,
            opt: true,
            ..Default::default()
        })
    })
    .await;
    let good = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.31", 60)]))
    })
    .await;
    let cfg = base_config(
        json!({"g": {"upstreams": ["bad", "good"], "strategy": "failover", "optimistic": true}}),
        json!({"bad": plain_upstream(&bad, "udp"), "good": plain_upstream(&good, "udp")}),
    );
    let env = start(cfg, |_| {}).await;
    let m = udp_q(env.dns(), &Q::new("tc3.example", 1)).await;
    assert_eq!(m.ips(), vec!["192.0.2.31".parse::<std::net::IpAddr>().unwrap()]);
    assert!(!m.tc);
    let legs: Vec<&str> = bad.seen().iter().map(|s| s.transport).collect();
    assert_eq!(legs, vec!["udp", "tcp"], "UDP TC retried over TCP first");
    assert_eq!(good.count(), 1, "then the next upstream");
    let s = env.edge().metrics.snapshot();
    assert_eq!(s.upstream["bad"].invalid.get("tc_stream").copied(), Some(1));
    env.shutdown().await;
}

/// D6 (edge.md §16 "Not an open resolver"): a listener binds to a LAN address or to a wildcard
/// restricted by `interfaces`. A wildcard bind without `interfaces` isn't opened, for any
/// protocol, and holds `listener_failed` with the reason; with `interfaces` it serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wildcard_listeners_need_interfaces() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "open4", "proto": "dns", "bind": "0.0.0.0:0"},
        {"id": "open6", "proto": "dot", "bind": "[::]:0", "tls": {"managed": "dns.home.arpa"}},
        {"id": "lo-only", "proto": "dns", "bind": "0.0.0.0:0", "interfaces": ["lo"]},
    ]);
    let env = start(cfg.clone(), |_| {}).await;
    let edge = Arc::clone(env.edge());
    assert!(wait_until(T, || !edge.dns.listeners.local_addrs("lo-only").is_empty()).await);
    let st = edge.dns.listeners.status();
    for id in ["open4", "open6"] {
        let s = st.iter().find(|s| s.id == id).unwrap();
        assert_eq!(
            s.state,
            picket_edge::dns::listeners::ListenerState::Failed,
            "{id}"
        );
        assert_eq!(
            s.error.as_deref(),
            Some(picket_edge::dns::listeners::OPEN_WILDCARD)
        );
        assert!(s.local.is_none(), "{id} isn't bound");
        assert!(
            edge.conditions
                .snapshot()
                .iter()
                .any(|c| c.kind == "listener_failed" && c.key.as_deref() == Some(id)),
            "{id} holds listener_failed"
        );
    }
    // The wildcard restricted to `lo` answers on the loopback interface.
    let port = edge.dns.listeners.local_addrs("lo-only")[0].port();
    let m = udp_q(([127, 0, 0, 1], port).into(), &Q::new("x.example", 1)).await;
    assert_eq!(m.rcode, 0);
    // Adding interfaces opens it and clears the condition.
    cfg["listeners"][1]["interfaces"] = json!(["lo"]);
    env.set_config(&cfg).await;
    assert!(wait_until(T, || !edge.dns.listeners.local_addrs("open4").is_empty()).await);
    assert!(
        wait_until(T, || {
            !edge
                .conditions
                .snapshot()
                .iter()
                .any(|c| c.kind == "listener_failed" && c.key.as_deref() == Some("open4"))
        })
        .await
    );
    env.shutdown().await;
}

/// D8 (edge.md §6, §8, §13): after an upstream's endpoint or a group's membership changes,
/// neither cached answers nor in-flight work from the old servers are reused: the group's
/// generation is part of the cache and coalescing keys. An unchanged group keeps its entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_changes_never_reuse_old_answers() {
    let old = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        let ans = Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.1", 300)]));
        if m.qname == "slow.example" {
            Act::Delay(Duration::from_millis(400), Box::new(ans))
        } else {
            ans
        }
    })
    .await;
    let new = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.2", 300)]))
    })
    .await;
    let cfg = one_upstream(&old, "udp");
    let env = start(cfg.clone(), |_| {}).await;
    let edge = Arc::clone(env.edge());
    let addr = env.dns();
    let ip = |s: &str| vec![s.parse::<std::net::IpAddr>().unwrap()];
    assert_eq!(udp_q(addr, &Q::new("x.example", 1)).await.ips(), ip("192.0.2.1"));
    // An unchanged config keeps the group's generation (and so its cache entries).
    let gen_before = edge.dns.pool.group("g").unwrap().generation;
    let parsed: picket_api::edge_config::EdgeConfig = serde_json::from_value(cfg.clone()).unwrap();
    edge.dns.pool.configure(&parsed);
    assert_eq!(edge.dns.pool.group("g").unwrap().generation, gen_before);
    // Work in flight at the old server...
    let slow = tokio::spawn(async move { udp_q(addr, &Q::new("slow.example", 1)).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // ...when the upstream moves to another server under the same id.
    let mut moved = cfg.clone();
    moved["upstreams"]["up1"] = plain_upstream(&new, "udp");
    let parsed: picket_api::edge_config::EdgeConfig = serde_json::from_value(moved.clone()).unwrap();
    edge.dns.pool.configure(&parsed);
    assert_ne!(edge.dns.pool.group("g").unwrap().generation, gen_before);
    assert_eq!(
        udp_q(addr, &Q::new("slow.example", 1)).await.ips(),
        ip("192.0.2.2"),
        "a new query doesn't join the old server's work"
    );
    assert_eq!(
        slow.await.unwrap().ips(),
        ip("192.0.2.1"),
        "the old query ends as it began"
    );
    assert_eq!(
        udp_q(addr, &Q::new("x.example", 1)).await.ips(),
        ip("192.0.2.2"),
        "the old server's cached answer isn't served"
    );
    assert_eq!(new.count(), 2);
    // A membership change does the same.
    let mut two = moved.clone();
    two["upstreams"]["up2"] = plain_upstream(&old, "udp");
    two["upstream_groups"]["g"]["upstreams"] = json!(["up2"]);
    env.set_config(&two).await;
    assert_eq!(udp_q(addr, &Q::new("x.example", 1)).await.ips(), ip("192.0.2.1"));
    env.shutdown().await;
}

/// D9 (README §2 Restarts, edge.md §3, §5): a renewal torn on disk (the current pair doesn't
/// load) still leaves the edge serving DoT after a restart with core down: the pair the renewal
/// replaced is kept and served. Before, the key and the certificate were replaced in two writes,
/// and a crash between them left a pair that never loaded again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_torn_certificate_store_still_serves_dot_after_a_restart_without_core() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let listeners = |ip: &str| {
        json!([
            {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
            {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0", "ips": [ip], "tls": {"managed": "dns.home.arpa"}},
        ])
    };
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = listeners("192.168.1.1");
    let core = MockCore::start().await;
    let signer =
        |ip: &str| support::CsrSigner::new(&["dns.home.arpa", "*.dns.home.arpa"], &[ip], (2026, 11, 1));
    let first = signer("192.168.1.1");
    let ca = first.ca_cert_pem.clone();
    core.with(|s| s.csr_signer = Some(first));
    let env = start_with_core(core, cfg.clone()).await;
    let edge = Arc::clone(env.edge());
    assert!(wait_until(T, || edge.dns.certs.slot("lan-dot").is_some_and(|s| s.has_cert())).await);
    // The listener's IPs change: a second leaf replaces the first, which is kept.
    let mut second = signer("192.168.1.2");
    second.ca_key_pem = env
        .core
        .with(|s| s.csr_signer.as_ref().unwrap().ca_key_pem.clone());
    second.ca_cert_pem = ca.clone();
    env.core.with(|s| s.csr_signer = Some(second));
    cfg["listeners"] = listeners("192.168.1.2");
    env.set_config(&cfg).await;
    let ip2: std::net::IpAddr = "192.168.1.2".parse().unwrap();
    assert!(
        wait_until(T, || edge
            .dns
            .certs
            .slot("lan-dot")
            .is_some_and(|s| s.info().ip_sans.contains(&ip2)))
        .await
    );
    drop(edge);
    let Env { core, _d: d, r } = env;
    r.shutdown().await;
    drop(core);
    // The current pair is torn. The previous pair holds the first leaf (192.168.1.1).
    let prev_leaf = rustls_pki_types::CertificateDer::pem_file_iter(d.data.join("tls/lan-dot.prev.pem"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let cur = d.data.join("tls/lan-dot.pem");
    let bytes = std::fs::read(&cur).unwrap();
    std::fs::write(&cur, &bytes[..bytes.len() / 2]).unwrap();
    // Restart with core gone.
    let r = service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        tuning(&d),
        |_| {},
    )
    .await
    .unwrap();
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.dns.certs.slot("lan-dot").is_some_and(|s| s.has_cert())).await,
        "the previous pair is served"
    );
    assert!(wait_until(T, || !edge.dns.listeners.local_addrs("lan-dot").is_empty()).await);
    // ER9: it is the previous certificate, by its SANs and by what the handshake presents.
    let ip1: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let info = edge.dns.certs.slot("lan-dot").unwrap().info();
    assert_eq!(info.ip_sans, vec![ip1], "the previous leaf's SANs: {info:?}");
    let dot_addr = edge.dns.listeners.local_addrs("lan-dot")[0];
    let tcp = tokio::net::TcpStream::connect(dot_addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(client_tls(&ca, &[]))
        .connect(
            rustls_pki_types::ServerName::try_from("dns.home.arpa".to_owned()).unwrap(),
            tcp,
        )
        .await
        .expect("DoT handshake with the kept certificate");
    let presented = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    assert!(presented == prev_leaf, "the handshake presents the previous leaf");
    drop(tls);
    let replies = dot(dot_addr, "dns.home.arpa", &ca, &[Q::new("x.example", 1).bytes()])
        .await
        .expect("DoT handshake with the kept certificate");
    assert_eq!(parse(&replies[0]).rcode, 0);
    drop(edge);
    r.shutdown().await;
}

fn loopback_source() -> picket_edge::dns::profiles::DeviceKey {
    picket_edge::dns::profiles::DeviceKey::Addr([127, 0, 0, 1].into())
}

/// True when the peer closed `s` within `within` (EOF or a reset), reading off what it sent.
async fn closed_within(s: &mut tokio::net::TcpStream, within: Duration) -> bool {
    use tokio::io::AsyncReadExt;
    let mut b = [0u8; 4096];
    let end = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(end, s.read(&mut b)).await {
            Err(_) => return false,
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => {}
        }
    }
}

/// D4 (README §2 Bounded; edge.md §5, §16): one source holds at most its share of the stream
/// listeners' connections, across TCP, DoT and DoH and counted from `accept` (a TLS handshake
/// holds one); and a connection that makes no progress (bytes trickled into a partial frame) is
/// closed after the idle timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_connections_are_capped_per_source_and_trickling_isnt_progress() {
    use picket_edge::dns::listeners::share::PER_SOURCE_CONNECTIONS;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    let (c, k) = self_signed("dns.example.lan");
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("c.pem"), &c).unwrap();
    std::fs::write(tmp.path().join("k.pem"), &k).unwrap();
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0", "limits": {"idle_timeout_ms": 8000}},
        {"id": "slow", "proto": "dns", "bind": "127.0.0.1:0", "limits": {"idle_timeout_ms": 1000}},
        {"id": "lan-dot", "proto": "dot", "bind": "127.0.0.1:0",
         "tls": {"cert_file": tmp.path().join("c.pem").to_str().unwrap(), "key_file": tmp.path().join("k.pem").to_str().unwrap()}},
    ]);
    let env = start(cfg, |_| {}).await;
    let edge = Arc::clone(env.edge());
    assert!(wait_until(T, || !edge.dns.listeners.local_addrs("lan-dot").is_empty()).await);
    let shares = Arc::clone(&edge.dns.listeners.shares);
    let me = loopback_source();
    // A connection still in its TLS handshake holds a share.
    let handshaking = tokio::net::TcpStream::connect(env.addr("lan-dot")).await.unwrap();
    assert!(wait_until(T, || shares.connections(&me) == 1).await);
    let mut held = vec![handshaking];
    for _ in 1..PER_SOURCE_CONNECTIONS {
        held.push(tokio::net::TcpStream::connect(env.dns()).await.unwrap());
    }
    assert!(wait_until(T, || shares.connections(&me) == PER_SOURCE_CONNECTIONS).await);
    // Over the share: closed at once, on any stream listener.
    let mut over = tokio::net::TcpStream::connect(env.dns()).await.unwrap();
    assert!(
        closed_within(&mut over, Duration::from_secs(2)).await,
        "TCP over the share"
    );
    let mut over = tokio::net::TcpStream::connect(env.addr("lan-dot")).await.unwrap();
    assert!(
        closed_within(&mut over, Duration::from_secs(2)).await,
        "DoT over the share"
    );
    assert_eq!(shares.connections(&me), PER_SOURCE_CONNECTIONS);
    // A connection given back makes room.
    held.pop();
    assert!(wait_until(T, || shares.connections(&me) < PER_SOURCE_CONNECTIONS).await);
    let ok = tcp(env.dns(), &[Q::new("x.example", 1).bytes()]).await;
    assert_eq!(parse(&ok[0]).rcode, 0);
    drop(held);
    assert!(wait_until(T, || shares.connections(&me) == 0).await);
    // Trickling bytes of a frame that never completes isn't progress: closed after the idle
    // timeout (1 s) although bytes keep arriving.
    let s = tokio::net::TcpStream::connect(env.addr("slow")).await.unwrap();
    let (mut rd, mut wr) = s.into_split();
    let trickle = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _ = wr.write_all(&[0x01, 0x00]).await; // a 256-byte frame...
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if wr.write_all(&[0]).await.is_err() {
                return;
            }
        }
    });
    use tokio::io::AsyncReadExt;
    let mut b = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(4), rd.read(&mut b)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "closed while trickling: {r:?}"
    );
    trickle.abort();
    env.shutdown().await;
}

/// D4: a client that stops reading its replies loses its connection within the write timeout:
/// the writer gives up, is cancelled, and the reader (waiting on the pipeline's in-flight limit)
/// stops with it, so the connection's share is given back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_never_reads_loses_its_connection() {
    use picket_edge::dns::listeners::stream::WRITE_TIMEOUT;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0", "limits": {"idle_timeout_ms": 600000}},
    ]);
    cfg["limits"] = json!({"client_qps": 100000, "client_inflight": 4096});
    let env = start(cfg, |_| {}).await;
    let edge = Arc::clone(env.edge());
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    sock.set_recv_buffer_size(2048).unwrap();
    sock.connect(&env.dns().into()).unwrap();
    sock.set_nonblocking(true).unwrap();
    let s = tokio::net::TcpStream::from_std(std::net::TcpStream::from(sock)).unwrap();
    let (_rd, mut wr) = s.into_split();
    // Queries for a name the edge answers itself (fast), never reading a reply.
    let mut frame = Vec::new();
    for _ in 0..200 {
        let q = Q::new("x.home.arpa", 1).bytes();
        frame.extend_from_slice(&(q.len() as u16).to_be_bytes());
        frame.extend_from_slice(&q);
    }
    let writer = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        for _ in 0..500 {
            if tokio::time::timeout(Duration::from_secs(1), wr.write_all(&frame))
                .await
                .is_err()
            {
                break;
            }
        }
        wr
    });
    let me = loopback_source();
    let shares = Arc::clone(&edge.dns.listeners.shares);
    assert!(wait_until(T, || shares.connections(&me) == 1).await);
    let start = std::time::Instant::now();
    assert!(
        wait_until(WRITE_TIMEOUT + T, || shares.connections(&me) == 0).await,
        "the connection is closed though the client keeps it open"
    );
    let took = start.elapsed();
    assert!(
        took >= WRITE_TIMEOUT / 2 && took < WRITE_TIMEOUT + Duration::from_secs(8),
        "closed by the write timeout: {took:?}"
    );
    let _wr = writer.await.unwrap();
    env.shutdown().await;
}

type DohBody = http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>;

async fn doh_conn(addr: std::net::SocketAddr, ca: &str) -> hyper::client::conn::http2::SendRequest<DohBody> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(client_tls(ca, &[b"h2"]))
        .connect(
            rustls_pki_types::ServerName::try_from("dns.example.lan".to_owned()).unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let (s, conn) = hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .handshake(hyper_util::rt::TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    s
}

fn doh_post(len: Option<usize>, body: DohBody) -> http::Request<DohBody> {
    let mut b = http::Request::builder()
        .method("POST")
        .uri("https://dns.example.lan/dns-query")
        .header("content-type", "application/dns-message");
    if let Some(n) = len {
        b = b.header("content-length", n.to_string());
    }
    b.body(body).unwrap()
}

/// A body that never sends a byte.
fn stalled() -> DohBody {
    use http_body_util::BodyExt as _;
    http_body_util::StreamBody::new(futures_util::stream::pending::<
        Result<hyper::body::Frame<bytes::Bytes>, std::convert::Infallible>,
    >())
    .boxed()
}

fn whole(q: &[u8]) -> DohBody {
    use http_body_util::BodyExt as _;
    http_body_util::Full::new(bytes::Bytes::from(q.to_vec())).boxed()
}

/// D5 (README §2; edge.md §16, §17): a DoH POST body is read only after the device's limits
/// admitted the query (a device over them gets 429 at once, ER4), and bodies being read are
/// charged to the source's budget: one that doesn't fit is refused at once, so partial bodies
/// can't pile up memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_bodies_are_read_after_admission_and_within_the_source_budget() {
    use http_body_util::BodyExt as _;
    use picket_edge::dns::listeners::share::PER_SOURCE_BODY_BYTES;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    let (c, k) = self_signed("dns.example.lan");
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("c.pem"), &c).unwrap();
    std::fs::write(tmp.path().join("k.pem"), &k).unwrap();
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-doh", "proto": "doh", "bind": "127.0.0.1:0",
         "tls": {"cert_file": tmp.path().join("c.pem").to_str().unwrap(), "key_file": tmp.path().join("k.pem").to_str().unwrap()}},
    ]);
    cfg["limits"] = json!({"client_qps": 100000, "client_inflight": 2});
    let env = start(cfg.clone(), |_| {}).await;
    let edge = Arc::clone(env.edge());
    assert!(wait_until(T, || edge.dns.certs.slot("lan-doh").is_some_and(|s| s.has_cert())).await);
    let addr = env.addr("lan-doh");
    let q = Q::new("www.example.com", 1).bytes();
    // Two bodies still arriving hold the device's two in-flight slots...
    let mut s = doh_conn(addr, &c).await;
    let p1 = tokio::spawn(s.send_request(doh_post(Some(100), stalled())));
    let p2 = tokio::spawn(s.send_request(doh_post(Some(100), stalled())));
    let shares = Arc::clone(&edge.dns.listeners.shares);
    assert!(wait_until(T, || shares.body_bytes() == 200).await);
    // ...so a third query is refused (429), its body unread; a GET, whose message is in the URL,
    // gets REFUSED as on every transport.
    let r = s.send_request(doh_post(Some(q.len()), whole(&q))).await.unwrap();
    assert_eq!(r.status(), 429, "over the in-flight limit");
    let get = http::Request::builder()
        .method("GET")
        .uri(format!(
            "https://dns.example.lan/dns-query?dns={}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &q)
        ))
        .body(whole(&[]))
        .unwrap();
    let r = s.send_request(get).await.unwrap();
    assert_eq!(r.status(), 200);
    let body = r.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(parse(&body).rcode, 5, "over the in-flight limit: REFUSED");
    // Abandoned bodies give their slots and bytes back.
    p1.abort();
    p2.abort();
    drop(s);
    assert!(wait_until(T, || shares.body_bytes() == 0).await);
    let mut s = doh_conn(addr, &c).await;
    let mut ok = false;
    for _ in 0..50 {
        let r = s.send_request(doh_post(Some(q.len()), whole(&q))).await.unwrap();
        let body = r.into_body().collect().await.unwrap().to_bytes();
        if parse(&body).rcode == 0 {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "answered once the slots are back");
    drop(s);
    // The source's body budget: bodies of the DNS maximum fill it; the next is refused (503).
    cfg["limits"] = json!({"client_qps": 100000, "client_inflight": 64});
    env.set_config(&cfg).await;
    let s = doh_conn(addr, &c).await;
    let fits = PER_SOURCE_BODY_BYTES / 65_535;
    let mut pending = vec![];
    for _ in 0..fits {
        pending.push(tokio::spawn({
            let mut s = s.clone();
            async move { s.send_request(doh_post(Some(65_535), stalled())).await }
        }));
    }
    assert!(wait_until(T, || shares.body_bytes() == fits * 65_535).await);
    let mut s2 = s.clone();
    let r = tokio::time::timeout(
        Duration::from_secs(2),
        s2.send_request(doh_post(Some(65_535), stalled())),
    )
    .await
    .expect("refused at once")
    .unwrap();
    assert_eq!(r.status(), 503);
    // A body over the DNS maximum: 413.
    let r = s2.send_request(doh_post(Some(70_000), stalled())).await.unwrap();
    assert_eq!(r.status(), 413);
    for p in pending {
        p.abort();
    }
    drop((s, s2));
    assert!(wait_until(T, || shares.body_bytes() == 0).await);
    env.shutdown().await;
}

/// edge.md §11 (D12's lazy `q` record): the profile's `log` decides which records are kept, and
/// a kept record carries every field whatever the level: `blocked` keeps blocks (not allowed
/// answers), `off` keeps nothing, `full` everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_levels_keep_records_as_their_profile_says() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!(["b"]);
    cfg["profiles"]["default"]["log"] = "blocked".into();
    let env = start(cfg.clone(), |_| {}).await;
    set_bundles(
        env.edge(),
        vec![("b", bundle("b", BundleAction::Block, &["||ads.example^"]))],
    );
    let addr = env.dns();
    udp_q(addr, &Q::new("allowed.example", 1)).await;
    udp_q(addr, &Q::new("allowed.example", 1)).await;
    udp_q(addr, &Q::new("ads.example", 1)).await;
    let rec = env.q_record("ads.example").await;
    assert_eq!(rec["decision"], "block");
    assert_eq!(rec["rcode"], "NOERROR");
    assert_eq!(rec["qtype"], "A");
    assert_eq!(rec["client"], "127.0.0.1");
    assert_eq!(rec["profile"], "default");
    assert_eq!(rec["listener"], "lan-dns");
    assert_eq!(rec["reason"]["bundle"], "b");
    assert_eq!(rec["reason"]["step"], 3);
    assert!(rec["reason"]["block_id"].is_string());
    assert_eq!(rec["answers"], json!(["0.0.0.0"]));
    assert!(rec["versions"]["bundles"]["b"].is_string(), "{}", rec["versions"]);
    assert!(
        !env.q_records().iter().any(|r| r["qname"] == "allowed.example"),
        "blocked: allowed answers aren't kept"
    );
    // off: nothing; then full: everything.
    cfg["profiles"]["default"]["log"] = "off".into();
    env.set_config(&cfg).await;
    set_bundles(
        env.edge(),
        vec![("b", bundle("b", BundleAction::Block, &["||ads.example^"]))],
    );
    udp_q(addr, &Q::new("x.ads.example", 1)).await;
    cfg["profiles"]["default"]["log"] = "full".into();
    env.set_config(&cfg).await;
    udp_q(addr, &Q::new("allowed.example", 1)).await;
    let rec = env.q_record("allowed.example").await;
    assert_eq!(rec["decision"], "allow");
    assert_eq!(rec["upstream"]["cached"], true);
    assert!(rec["answer_id"].is_string());
    assert_eq!(rec["answers"], json!(["93.184.216.34"]));
    assert!(
        !env.q_records().iter().any(|r| r["qname"] == "x.ads.example"),
        "off keeps nothing"
    );
    env.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Review round 2 (re-check of the edge DNS data path): regressions for the validated findings.

/// ER1 (README §2 Bounded; RFC 7766 §6.2.3; edge.md §16): idle expiry is absolute. A connection
/// with nothing outstanding that made no progress (a complete query read or a reply written) for
/// `idle_timeout_ms` is closed even when a trickled read is ready at the same moment as the
/// deadline. The runtime's only worker is blocked across the deadline, so the timer and the read
/// are both ready when it resumes; the trickle comes from plain threads, every 100 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn idle_expiry_is_absolute_when_a_read_is_ready_at_the_deadline() {
    use std::sync::atomic::AtomicBool;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0", "limits": {"idle_timeout_ms": 1000}},
    ]);
    let env = start(cfg, |_| {}).await;
    let addr = env.dns();
    const CONNS: usize = 16;
    let stop = Arc::new(AtomicBool::new(false));
    let t0 = std::time::Instant::now();
    let mut readers = vec![];
    for _ in 0..CONNS {
        let s = std::net::TcpStream::connect(addr).unwrap();
        let mut w = s.try_clone().unwrap();
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = w.write_all(&[0x01, 0x00]); // a 256-byte frame that never completes
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                if w.write_all(&[0]).is_err() {
                    return;
                }
            }
        });
        readers.push(std::thread::spawn(move || {
            use std::io::Read;
            let mut s = s;
            s.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            let mut b = [0u8; 64];
            loop {
                match s.read(&mut b) {
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        return None;
                    }
                    Ok(0) | Err(_) => return Some(t0.elapsed()),
                    Ok(_) => {}
                }
            }
        }));
    }
    // Block the only worker from 0.8 s to 1.3 s: the 1 s deadline passes meanwhile.
    tokio::time::sleep_until(tokio::time::Instant::from_std(t0 + Duration::from_millis(800))).await;
    tokio::spawn(async { std::thread::sleep(Duration::from_millis(500)) });
    let closed: Vec<Option<Duration>> =
        tokio::task::spawn_blocking(move || readers.into_iter().map(|r| r.join().unwrap()).collect())
            .await
            .unwrap();
    stop.store(true, Ordering::Relaxed);
    let open = closed
        .iter()
        .filter(|c| c.is_none_or(|t| t > Duration::from_millis(2500)))
        .count();
    assert_eq!(open, 0, "connections left open by trickled reads: {closed:?}");
    env.shutdown().await;
}

/// Records every firewall ensure call with each address's `client_ttl`.
type FwAddrCalls = Arc<std::sync::Mutex<Vec<Vec<(std::net::IpAddr, u32)>>>>;

struct RecFwAddrs(FwAddrCalls);

#[async_trait::async_trait]
impl picket_edge::dns::FirewallEnsure for RecFwAddrs {
    async fn ensure(&self, req: &picket_edge::dns::FwRequest<'_>) -> picket_edge::dns::FwOutcome {
        self.0
            .lock()
            .unwrap()
            .push(req.addrs.iter().map(|a| (a.ip, a.client_ttl)).collect());
        Default::default()
    }
}

/// ER2 (edge-firewall.md §3: `client_ttl = clamp(record_ttl)` per record, "rewritten in place in
/// the answer"): each address reaches the firewall with the TTL its own record carries in the
/// reply the client got, aged and clamped as served, never the answer-wide minimum (here the
/// CNAME's 5 s). A CNAME rewrite's target addresses likewise; a stale answer's are `stale_ttl`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_firewall_gets_each_addresses_own_ttl() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| match m.qtype {
        1 => Act::Answer(Ans::records(vec![
            cname(&m.qname, "cdn.example", 5),
            a("cdn.example", "192.0.2.10", 300),
        ])),
        65 => Act::Answer(Ans::records(vec![Rr {
            owner: m.qname.clone(),
            rtype: 65,
            ttl: 200,
            rdata: picket_edge::dns::pipeline::svcb_rdata(
                1,
                ".",
                &[("ipv4hint".into(), "192.0.2.20".into())],
            )
            .unwrap(),
        }])),
        _ => Act::Answer(Ans::records(vec![])),
    })
    .await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!(["rw"]);
    cfg["profiles"]["default"]["ttl"] = json!({"min": 60, "max": 3600});
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![(
            "rw",
            bundle(
                "rw",
                BundleAction::Block,
                &["||c.example^$dnsrewrite=NOERROR;CNAME;mixed.example"],
            ),
        )],
    );
    let rec = Arc::new(std::sync::Mutex::new(vec![]));
    env.edge()
        .dns
        .hooks
        .firewall
        .store(Arc::new(Box::new(RecFwAddrs(Arc::clone(&rec)))));
    let addr = env.dns();
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    // The A record's 300 s as served, not the CNAME's 5 s (served clamped to 60).
    let m = udp_q(addr, &Q::new("mixed.example", 1)).await;
    assert_eq!(m.ttls(), vec![60, 300]);
    assert_eq!(rec.lock().unwrap().pop().unwrap(), vec![(ip("192.0.2.10"), 300)]);
    // A hit, aged as served.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let m = udp_q(addr, &Q::new("mixed.example", 1)).await;
    let a_ttl = m.ttls()[1];
    assert!(a_ttl < 300, "aged: {:?}", m.ttls());
    assert_eq!(
        rec.lock().unwrap().pop().unwrap(),
        vec![(ip("192.0.2.10"), a_ttl)]
    );
    // HTTPS hints carry their record's TTL.
    let _ = udp_q(addr, &Q::new("svc.example", 65)).await;
    assert_eq!(rec.lock().unwrap().pop().unwrap(), vec![(ip("192.0.2.20"), 200)]);
    // A CNAME rewrite: the target's A record's TTL, not its CNAME's.
    let m = udp_q(addr, &Q::new("c.example", 1)).await;
    assert_eq!(m.types(), vec![5, 5, 1]);
    let served = m.ttls()[2];
    assert!(served > 200 && served <= 300, "{:?}", m.ttls());
    assert_eq!(
        rec.lock().unwrap().pop().unwrap(),
        vec![(ip("192.0.2.10"), served)]
    );
    env.shutdown().await;
}

/// ER4 (edge.md §16; README §2 Bounded): a POST from a device over its limits is refused at once,
/// without reading (or charging) its body: a stalled over-limit POST can't hold a stream or body
/// budget until the body timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_posts_over_the_device_limits_are_refused_without_reading_the_body() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    let (c, k) = self_signed("dns.example.lan");
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("c.pem"), &c).unwrap();
    std::fs::write(tmp.path().join("k.pem"), &k).unwrap();
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "lan-doh", "proto": "doh", "bind": "127.0.0.1:0",
         "tls": {"cert_file": tmp.path().join("c.pem").to_str().unwrap(), "key_file": tmp.path().join("k.pem").to_str().unwrap()}},
    ]);
    cfg["limits"] = json!({"client_qps": 100000, "client_inflight": 1});
    let env = start(cfg, |_| {}).await;
    let edge = Arc::clone(env.edge());
    assert!(wait_until(T, || edge.dns.certs.slot("lan-doh").is_some_and(|s| s.has_cert())).await);
    let mut s = doh_conn(env.addr("lan-doh"), &c).await;
    // The first stalled POST holds the device's only in-flight slot and charges its body.
    let p1 = tokio::spawn(s.send_request(doh_post(Some(100), stalled())));
    let shares = Arc::clone(&edge.dns.listeners.shares);
    assert!(wait_until(T, || shares.body_bytes() == 100).await);
    // The second is over the limit: answered at once, its body never read or charged.
    let r = tokio::time::timeout(
        Duration::from_secs(2),
        s.send_request(doh_post(Some(100), stalled())),
    )
    .await
    .expect("refused at once")
    .unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(shares.body_bytes(), 100, "the refused body isn't charged");
    p1.abort();
    drop(s);
    assert!(wait_until(T, || shares.body_bytes() == 0).await);
    env.shutdown().await;
}

/// ER5 (edge.md §4 EDE table, §7 step 3; core.md §6): an upstream answer carrying EDE 3 reaches a
/// client without DO as a stale answer: EDE 3 `cause=stale`, every TTL `stale_ttl` (what core
/// rebuilds for `upstream.stale`), logged with `upstream.stale` and the cause.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upstreams_stale_answer_is_served_and_logged_as_stale() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans {
            answers: vec![a(&m.qname, "192.0.2.9", 60)],
            ede: vec![(3, String::new())],
            opt: true,
            ..Default::default()
        })
    })
    .await;
    let env = start(one_upstream(&up, "udp"), |_| {}).await;
    let m = udp_q(env.dns(), &Q::new("st.example", 1)).await;
    assert_eq!(m.ips(), vec!["192.0.2.9".parse::<std::net::IpAddr>().unwrap()]);
    assert_eq!(m.ede(), vec![(3, "cause=stale".to_owned())]);
    assert_eq!(m.ttls(), vec![30]);
    let rec = env.q_record("st.example").await;
    assert_eq!(rec["upstream"]["stale"], true, "{rec}");
    assert_eq!(rec["upstream"]["cause"], "stale");
    assert!(env.edge().metrics.snapshot().stale_served >= 1);
    env.shutdown().await;
}

/// A block bundle whose keys are all in its cold part (no page reader in tests, so every cold
/// lookup is unchecked: edge.md §9).
fn cold_bundle(name: &str, rules: &[&str]) -> Arc<picket_bundle::matcher::Bundle> {
    use picket_bundle::compile::{BuildOptions, CompileOptions, build, compile_rules, load_bundle};
    use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};
    let cfg = ParseConfig::new(Format::Adblock, DomainsAs::Exact, Timestamp::now());
    let mut rs = vec![];
    parse_lines(rules.join("\n").as_bytes(), &cfg, |e| rs.push(e.rule)).unwrap();
    let compiled = compile_rules(&rs, &CompileOptions::new(BundleAction::Block, None));
    let cold = |_: &str, _: picket_rules::Flags| picket_rules::compile::Part::Cold;
    let mut o = BuildOptions::new(name, BundleAction::Block);
    o.part_of = Some(&cold);
    let built = build(&compiled, &o).unwrap();
    assert!(!built.cold_keys.is_empty());
    Arc::new(
        load_bundle(
            &built.head_blob.bytes,
            &built.blobs,
            None,
            picket_bundle::patterns::DEFAULT_BUDGET,
        )
        .unwrap(),
    )
}

/// ER7 (edge.md §11; api.md §5): with `log: blocked` and `response_checks: all`, an allowed answer
/// whose response check finds an unchecked cold lookup is kept, and it carries the allow's reason
/// (step 2), built when the record is filled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_allowed_record_carries_the_allows_reason() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![
            cname(&m.qname, "cdn.example", 60),
            a("cdn.example", "192.0.2.30", 60),
        ]))
    })
    .await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["allow"] = json!(["ok"]);
    cfg["profiles"]["default"]["block"] = json!(["cold"]);
    cfg["profiles"]["default"]["log"] = "blocked".into();
    cfg["profiles"]["default"]["response_checks"] = "all".into();
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![
            ("ok", bundle("ok", BundleAction::Allow, &["||allowed.example^"])),
            ("cold", cold_bundle("cold", &["||cdn.example^"])),
        ],
    );
    let m = udp_q(env.dns(), &Q::new("www.allowed.example", 1)).await;
    assert_eq!(m.rcode, 0);
    let rec = env.q_record("www.allowed.example").await;
    assert_eq!(rec["decision"], "allow");
    assert_eq!(rec["cold_unchecked"], json!(["cold"]), "{rec}");
    assert_eq!(rec["reason"]["step"], 2, "{rec}");
    assert_eq!(rec["reason"]["bundle"], "ok");
    env.shutdown().await;
}

/// Review fix-w5a N15 (core.md §6 "an allow by an allow bundle or exception"; api.md §5): a
/// query a block bundle's exception lets through is logged with that exception as its `reason`
/// (step 3, the bundle, the key and kind, stage `query`), the first such bundle in profile order
/// even when a later bundle has one too; a plain pass carries none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exception_pass_is_logged_with_its_reason() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        Act::Answer(Ans::records(vec![a(&m.qname, "192.0.2.31", 60)]))
    })
    .await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!(["b1", "b2"]);
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![
            (
                "b1",
                bundle(
                    "b1",
                    BundleAction::Block,
                    &["||ads.example^", "@@||ok.ads.example^"],
                ),
            ),
            ("b2", bundle("b2", BundleAction::Block, &["@@||ads.example^"])),
        ],
    );
    let m = udp_q(env.dns(), &Q::new("www.ok.ads.example", 1)).await;
    assert_eq!(m.rcode, 0);
    let rec = env.q_record("www.ok.ads.example").await;
    assert_eq!(rec["decision"], "allow", "{rec}");
    assert_eq!(rec["reason"]["step"], 3, "{rec}");
    assert_eq!(rec["reason"]["bundle"], "b1", "{rec}");
    assert_eq!(rec["reason"]["key"], "ok.ads.example", "{rec}");
    assert_eq!(rec["reason"]["kind"], "subs", "{rec}");
    assert_eq!(rec["reason"]["stage"], "query", "{rec}");
    assert!(rec["reason"].get("block_id").is_none_or(Value::is_null), "{rec}");
    let m = udp_q(env.dns(), &Q::new("plain.example", 1)).await;
    assert_eq!(m.rcode, 0);
    let rec = env.q_record("plain.example").await;
    assert!(rec["reason"].is_null(), "a plain pass has no reason: {rec}");
    env.shutdown().await;
}

/// ER10 (edge.md §4 EDE table, D11): a CNAME rewrite built from a stale target answer carries
/// EDE 3 with its cause: an upstream's stale answer (`stale`) and an optimistic cache hit
/// (`optimistic`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cname_rewrites_of_stale_targets_carry_ede_3() {
    let up = FakeUpstream::plain(|m: &Msg, _q: &[u8]| {
        let rr = vec![a(&m.qname, "192.0.2.40", 1)];
        if m.qname.starts_with("st.") {
            Act::Answer(Ans {
                answers: rr,
                ede: vec![(3, String::new())],
                opt: true,
                ..Default::default()
            })
        } else {
            Act::Answer(Ans::records(rr))
        }
    })
    .await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["profiles"]["default"]["block"] = json!(["rw"]);
    let env = start(cfg, |_| {}).await;
    set_bundles(
        env.edge(),
        vec![(
            "rw",
            bundle(
                "rw",
                BundleAction::Block,
                &[
                    "||c1.example^$dnsrewrite=NOERROR;CNAME;st.example",
                    "||c2.example^$dnsrewrite=NOERROR;CNAME;opt.example",
                ],
            ),
        )],
    );
    let addr = env.dns();
    let m = udp_q(addr, &Q::new("c1.example", 1)).await;
    assert_eq!(m.types(), vec![5, 1]);
    assert_eq!(m.ede(), vec![(3, "cause=stale".to_owned())]);
    // The target cached, then expired: served optimistically, with EDE 3.
    let m = udp_q(addr, &Q::new("c2.example", 1)).await;
    assert!(m.ede().is_empty(), "fresh: no EDE: {:?}", m.ede());
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let m = udp_q(addr, &Q::new("c2.example", 1)).await;
    assert_eq!(m.types(), vec![5, 1]);
    assert_eq!(m.ede(), vec![(3, "cause=optimistic".to_owned())]);
    assert_eq!(m.ttls()[1], 30, "the target's records at stale_ttl");
    env.shutdown().await;
}

/// Runs the watchdog's test query until it gives `want`, for at most `within`.
async fn self_test_until(edge: &Arc<picket_edge::edge::Edge>, want: bool, within: Duration) -> bool {
    let end = std::time::Instant::now() + within;
    loop {
        if picket_edge::dns::pipeline::self_test(edge).await == want {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// edge.md §16 "Watchdog": the internal test query passes through the primary UDP listener's
/// socket (a loopback datagram, let through whatever `interfaces` lists, then the limiter and the
/// profile choice), with no log record; so a listener whose receive loop stalled with its socket
/// still open (no "connection refused" to fail fast on) leaves the query unanswered, fails the
/// test and systemd restarts the edge. Marks go stale only after a minute here, so the
/// unanswered query is what fails it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_watchdog_test_query_goes_through_the_udp_listener() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    // A wildcard bind for an interface the loopback datagram doesn't arrive on.
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "0.0.0.0:0", "interfaces": ["picket-test0"]},
    ]);
    let env = start(cfg, |t| t.dns.listener_stale = Duration::from_secs(60)).await;
    let edge = Arc::clone(env.edge());
    let port = env.dns().port();
    let local = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    assert!(
        udp(local, &Q::new("x.example", 1).bytes()).await.is_none(),
        "a client on another interface is dropped"
    );
    assert!(
        self_test_until(&edge, true, T).await,
        "the test query is let through"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !env.q_records()
            .iter()
            .any(|r| r["qname"] == "picket-watchdog.home.arpa"),
        "the test query is never logged"
    );
    // Every loop of the listener stalls at its next turn; datagrams from many source ports (and
    // a connection) give each one that turn now.
    assert!(edge.dns.listeners.stall_tasks_for_test("lan-dns").await > 0);
    let mut wake = Vec::new();
    for _ in 0..64 {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(&Q::new("x.example", 1).bytes(), local).unwrap();
        wake.push(s);
    }
    let _tcp = tokio::net::TcpStream::connect(local).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The sockets stay open: a datagram gets no "connection refused", just no answer.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    probe.connect(local).unwrap();
    probe.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    probe.send(&Q::new("x.example", 1).bytes()).unwrap();
    let err = probe.recv(&mut [0u8; 512]).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{err}"
    );
    assert!(
        edge.dns
            .listeners
            .stale_listener(Duration::from_secs(60))
            .is_none()
    );
    assert!(
        !picket_edge::dns::pipeline::self_test(&edge).await,
        "a stalled receive loop fails the test query"
    );
    env.shutdown().await;
}

/// edge.md §16 "Watchdog": every listener's receive and accept loops (UDP, TCP, DoT, DoH) must
/// be alive for the test to pass; one that stalled or ended stops it within `listener_stale`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_watchdog_test_needs_every_listener_loop_alive() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = one_upstream(&up, "udp");
    cfg["listeners"] = json!([
        {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
        {"id": "other", "proto": "dns", "bind": "127.0.0.1:0"},
    ]);
    let env = start(cfg, |t| t.dns.listener_stale = Duration::from_secs(2)).await;
    let edge = Arc::clone(env.edge());
    assert!(wait_until(T, || !edge.dns.listeners.local_addrs("other").is_empty()).await);
    assert!(self_test_until(&edge, true, T).await);
    assert!(edge.dns.listeners.end_tasks_for_test("other").await > 0);
    assert!(
        self_test_until(&edge, false, T).await,
        "a stopped loop of another listener fails the test"
    );
    env.shutdown().await;
}

/// edge.md §16 "Watchdog": the test query never competes with clients for a UDP in-flight slot.
/// With every slot held by client queries waiting on a silent upstream, it still passes, and it
/// never counts as a rejected client query, so sustained saturation doesn't restart the edge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_watchdog_test_passes_while_client_queries_fill_every_udp_slot() {
    use std::sync::atomic::Ordering::Relaxed;
    let up = FakeUpstream::plain(|_m: &Msg, _q: &[u8]| Act::Drop).await;
    let env = start(one_upstream(&up, "udp"), |t| {
        t.dns.udp_inflight = 2;
        t.dns.attempt_timeout = Duration::from_secs(30);
        t.dns.resolve_budget = Duration::from_secs(40);
    })
    .await;
    let edge = Arc::clone(env.edge());
    assert!(self_test_until(&edge, true, T).await);
    // Client queries from many source ports, so SO_REUSEPORT fills every socket's slots.
    let mut clients = Vec::new();
    for i in 0..64 {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.send_to(&Q::new(&format!("q{i}.example"), 1).bytes(), env.dns())
            .await
            .unwrap();
        clients.push(s);
    }
    let rejected = || edge.metrics.rejected.load(Relaxed);
    assert!(
        wait_until(T, || rejected() >= 32).await,
        "every slot is held: {}",
        rejected()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = rejected();
    for _ in 0..3 {
        assert!(
            picket_edge::dns::pipeline::self_test(&edge).await,
            "the test query found no slot"
        );
    }
    assert_eq!(rejected(), before, "the test query isn't a rejected client query");
    env.shutdown().await;
}
