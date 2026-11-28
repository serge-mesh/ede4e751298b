//! Temporary allows, the bypass API and the recent-blocks ring (edge.md §12; api.md §6;
//! browser-extension.md §3; build-and-test.md §5 "Temporary allows", "Bypass scope"): the
//! extension's DoH probes, DNS allows by block id with every limit, persistence in
//! `allows.json`, revocation by the extension and by core, the browser protections, and IP allows
//! through the real helper engine (with the PTR probe).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod bundlekit;
mod dnsh;
mod helperkit;
mod support;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use serde_json::{Value, json};
use tokio::net::TcpStream;

use bundlekit::*;
use dnsh::*;
use picket_api::time::Timestamp;
use picket_edge::service::{self, Options, Running, Tuning};
use support::{CsrSigner, MockCore, wait_until, write_edge_json};

const T: Duration = Duration::from_secs(30);
const SNI: &str = "dns.home.arpa";

struct Dirs {
    _tmp: tempfile::TempDir,
    config: PathBuf,
    data: PathBuf,
    run: PathBuf,
}

fn dirs() -> Dirs {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Dirs {
        config: root.join("dev/edge.json"),
        data: root.join("dev/edge"),
        run: root.join("dev/run"),
        _tmp: tmp,
    }
}

fn tuning(d: &Dirs, socket: PathBuf) -> Tuning {
    let mut t = Tuning {
        platform: Some(picket_edge::paths::HostPlatform::Debian),
        clock: Some(picket_edge::clock::Clock::fixed(true)),
        neighbours: Some(picket_edge::neighbours::Neighbours::new()),
        update_result: Some(d.data.join("no-update-result.json")),
        service: Some(false),
        firmware_file: d.data.join("no-such-version-file"),
        ..Default::default()
    };
    t.session.heartbeat = Duration::from_millis(300);
    t.session.backoff_min = Duration::from_millis(50);
    t.session.backoff_max = Duration::from_millis(300);
    t.convergence.retry_min = Duration::from_millis(50);
    t.convergence.retry_max = Duration::from_millis(300);
    t.shipper.tick = Duration::from_millis(50);
    t.shipper.retry_min = Duration::from_millis(20);
    t.shipper.retry_max = Duration::from_millis(100);
    t.supervisor.min = Duration::from_millis(20);
    t.firewall.socket = socket;
    t.firewall.reconnect = (Duration::from_millis(50), Duration::from_millis(300));
    t.firewall.seed_wait = Duration::from_millis(500);
    t
}

fn ok_upstream() -> impl Fn(&Msg, &[u8]) -> Act + Send + Sync + 'static {
    |m: &Msg, _q: &[u8]| match m.qtype {
        1 => Act::Answer(Ans::records(vec![a(&m.qname, "93.184.216.34", 300)])),
        _ => Act::Answer(Ans::records(vec![])),
    }
}

fn config(up: &FakeUpstream, head: &str, bypass: Value, firewall: Value) -> Value {
    json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
        "listeners": [
            {"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"},
            {"id": "lan-doh", "proto": "doh", "bind": "127.0.0.1:0", "tls": {"managed": SNI}, "api": true},
        ],
        "default_profile": "default",
        "profiles": {"default": {"upstream": "g", "block": ["b"], "bypass": bypass,
            "block_response": {"type": "null_ip", "ttl": 10}}},
        "upstreams": {"up1": plain_upstream(up, "udp")},
        "upstream_groups": {"g": {"upstreams": ["up1"], "strategy": "failover"}},
        "bundles": {"b": head},
        "firewall": firewall,
        "logging": {"spool_after_s": 1},
    })
}

struct Env {
    core: MockCore,
    up: FakeUpstream,
    r: Running,
    ca: String,
    head: String,
    _d: Dirs,
}

async fn env(bypass: Value, firewall: Value, socket: Option<PathBuf>) -> Env {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let signer = CsrSigner::new(&[SNI, &format!("*.{SNI}")], &[], (2026, 1, 1));
    core.with(|s| s.csr_signer = Some(signer.clone()));
    let b = build_bundle(
        "b",
        &[
            "||blocked.example^",
            "||block2.example^",
            "||block3.example^",
            "||block4.example^",
        ],
        None,
    );
    let head = publish(&core, &b.head, &b.blobs);
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&config(&up, &head, bypass, firewall));
    let sock = socket.unwrap_or_else(|| d.run.join("no-helper.sock"));
    let r = service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        tuning(&d, sock),
        |_| {},
    )
    .await
    .unwrap();
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())
            && !edge.dns.listeners.local_addrs("lan-dns").is_empty()
            && edge.dns.certs.slot("lan-doh").is_some_and(|s| s.has_cert())
            && !edge.dns.listeners.local_addrs("lan-doh").is_empty())
        .await,
        "config live, listeners bound"
    );
    Env {
        core,
        up,
        r,
        ca: signer.ca_cert_pem.clone(),
        head,
        _d: d,
    }
}

impl Env {
    fn dns(&self) -> SocketAddr {
        *self.r.edge.dns.listeners.local_addrs("lan-dns").first().unwrap()
    }
    fn doh(&self) -> SocketAddr {
        *self.r.edge.dns.listeners.local_addrs("lan-doh").first().unwrap()
    }
    /// The extension's DoH probe.
    async fn probe(&self, name: &str, qtype: u16) -> Msg {
        let (st, h, body) = doh(
            self.doh(),
            SNI,
            &self.ca,
            "/dns-query",
            &Q::new(name, qtype).bytes(),
            false,
            &[("x-picket-client", "extension")],
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(h.get("cache-control").unwrap(), "no-store");
        parse(&body)
    }
    /// A bypass API call: (status, headers, JSON body).
    async fn api(
        &self,
        method: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> (u16, http::HeaderMap, Value) {
        let tcp = TcpStream::connect(self.doh()).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(client_tls(&self.ca, &[b"h2"]))
            .connect(ServerName::try_from(SNI.to_owned()).unwrap(), tcp)
            .await
            .unwrap();
        let (mut s, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut b = http::Request::builder()
            .method(method)
            .uri(format!("https://{SNI}/v1/temporary-allows"));
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let payload = body.map(|v| serde_json::to_vec(&v).unwrap()).unwrap_or_default();
        if !payload.is_empty() {
            b = b.header("content-type", "application/json");
        }
        let resp = s
            .send_request(b.body(Full::new(Bytes::from(payload))).unwrap())
            .await
            .unwrap();
        let st = resp.status().as_u16();
        let h = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or(Value::Null)
        };
        (st, h, v)
    }
    async fn ext(&self, method: &str, body: Option<Value>) -> (u16, Value) {
        let (st, h, v) = self
            .api(
                method,
                body,
                &[
                    ("x-picket-client", "extension"),
                    ("origin", "moz-extension://abc"),
                ],
            )
            .await;
        assert!(
            !h.keys().any(|k| k.as_str().starts_with("access-control-")),
            "no CORS headers, ever"
        );
        (st, v)
    }
    fn allow_records(&self) -> Vec<Value> {
        self.core
            .with(|s| s.logs.iter().filter(|l| l["t"] == "allow").cloned().collect())
    }
}

fn block_id(m: &Msg) -> String {
    let text = &m.ede()[0].1;
    text.split(' ')
        .find_map(|t| t.strip_prefix("block="))
        .expect("block= token")
        .to_owned()
}

/// The reverse-lookup name the extension's PTR probe asks for an IP.
fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v) => {
            let hex = format!("{:032x}", u128::from(v));
            let nibbles: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

/// This host's address on its default route, if it has one (nothing is sent).
fn own_address() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let a = s.local_addr().ok()?.ip();
    (!a.is_loopback() && !a.is_unspecified()).then_some(a)
}

fn now() -> i64 {
    Timestamp::now().as_second()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ring_answers_probes_and_dns_allows_follow_every_limit() {
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": false, "max_active": 2, "rate_per_hour": 3}),
        json!({"interfaces": []}),
        None,
    )
    .await;
    // A block by DNS: recorded in the device's ring.
    let m = udp_q(e.dns(), &Q::new("blocked.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4]);
    let bid = block_id(&m);
    // The extension's probe answers as that block did, whatever profile it gets.
    let p = e.probe("blocked.example", 1).await;
    assert_eq!(p.ede_codes(), vec![15, 4]);
    assert_eq!(block_id(&p), bid);
    // A probe that misses: NOERROR, no records, no EDE; nothing else happens.
    let seen = e.up.count();
    let p = e.probe("never-blocked.example", 1).await;
    assert_eq!(p.rcode, 0);
    assert!(p.answers.is_empty() && p.ede().is_empty());
    assert_eq!(e.up.count(), seen, "no resolution for a probe");

    // Browser protections: the header, an extension origin, no preflight.
    let (st, _, _) = e.api("GET", None, &[]).await;
    assert_eq!(st, 403);
    let (st, _, _) = e
        .api(
            "GET",
            None,
            &[
                ("x-picket-client", "extension"),
                ("origin", "https://evil.example"),
            ],
        )
        .await;
    assert_eq!(st, 403);
    let (st, _, _) = e.api("OPTIONS", None, &[("x-picket-client", "extension")]).await;
    assert_eq!(st, 403);
    let (st, v) = e.ext("GET", None).await;
    assert_eq!((st, v), (200, json!([])));

    // A DNS allow by block id: shortened to max_duration, with retry_after_s.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": bid, "expires_at": now() + 7200}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let a = &v[0];
    assert_eq!(a["kind"], "dns");
    assert_eq!(a["target"], "blocked.example");
    assert!(
        a["expires_at"].as_i64().unwrap() <= now() + 3600,
        "max_duration 1h"
    );
    let ra = a["retry_after_s"].as_u64().unwrap();
    assert!((55..=65).contains(&ra), "hold = max(65 s, block TTL 10): {ra}");
    let allow_id = a["allow_id"].as_str().unwrap().to_owned();
    // It applies at ladder step 1.
    let m = udp_q(e.dns(), &Q::new("blocked.example", 1)).await;
    assert_eq!(m.rcode, 0);
    assert!(m.ede().is_empty(), "allowed: {:?}", m.ede());
    // Recorded and logged (security class).
    assert!(e._d.data.join("allows.json").exists());
    let stored: Value =
        serde_json::from_slice(&std::fs::read(e._d.data.join("allows.json")).unwrap()).unwrap();
    assert_eq!(stored["allows"][0]["allow_id"], allow_id.as_str());
    assert!(
        wait_until(T, || e.allow_records().iter().any(|r| r["action"] == "created"
            && r["via"] == "extension"
            && r["allow_id"] == allow_id.as_str()))
        .await
    );
    // A block id the ring doesn't hold: 409, with the entry's index.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": "zzzzzzzz", "expires_at": now() + 60}])),
        )
        .await;
    assert_eq!(st, 409);
    assert_eq!(v["error"]["index"], 0);
    // max_active 2: a second allow fits, a third doesn't.
    let b2 = block_id(&udp_q(e.dns(), &Q::new("block2.example", 1)).await);
    let b3 = block_id(&udp_q(e.dns(), &Q::new("block3.example", 1)).await);
    let (st, _) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": b2, "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": b3, "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(v["error"]["code"], "max_active");
    // rate_per_hour 3: two created so far; a re-time is the third, and the next is refused.
    let (st, _) = e
        .ext(
            "PATCH",
            Some(json!([{"allow_id": allow_id, "expires_at": now() + 900}])),
        )
        .await;
    assert_eq!(st, 200);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"allow_id": allow_id, "expires_at": now() + 800}])),
        )
        .await;
    assert_eq!(st, 403);
    assert_eq!(v["error"]["code"], "rate_limited");
    // A past expiry revokes (always allowed); PUT [] revokes the rest.
    let (st, v) = e
        .ext("PATCH", Some(json!([{"allow_id": allow_id, "expires_at": 1}])))
        .await;
    assert_eq!(st, 200);
    assert_eq!(v.as_array().unwrap().len(), 1);
    let (st, v) = e.ext("PUT", Some(json!([]))).await;
    assert_eq!((st, v), (200, json!([])));
    assert!(
        wait_until(T, || e
            .allow_records()
            .iter()
            .filter(|r| r["action"] == "revoked")
            .count()
            == 2)
        .await,
        "{:#?}",
        e.allow_records()
    );
    let m = udp_q(e.dns(), &Q::new("blocked.example", 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4], "blocked again");
    e.r.shutdown().await;
}

/// Pushes a config whose profile has `bypass` and a 600 s NXDOMAIN block answer, and waits for it.
async fn with_block_ttl_600(e: &Env, bypass: Value) {
    let mut cfg = config(&e.up, &e.head, bypass, json!({"interfaces": []}));
    cfg["profiles"]["default"]["block_response"] = json!({"type": "nxdomain", "ttl": 600});
    let id = e.core.set_config(&cfg);
    e.core.changed(&id);
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
}

/// #50: a DNS allow must outlast its block's cached answer (hold max(65 s, TTL + 5 s), then 5 s
/// for the reload). One that would end sooner is refused with `403 too_short`, whether the
/// profile's `max_duration` or the request is short, with nothing recorded and no limit used; a
/// compatible one reports the full hold as its countdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dns_allow_that_ends_inside_its_blocks_cache_hold_is_refused() {
    let e = env(json!({"mode": "off"}), json!({"interfaces": []}), None).await;
    // A fresh 600 s block under a 5 min maximum: the grant would be shortened to 300 s.
    with_block_ttl_600(
        &e,
        json!({"mode": "self", "max_duration": "5m", "rate_per_hour": 2}),
    )
    .await;
    let m = udp_q(e.dns(), &Q::new("blocked.example", 1)).await;
    assert_eq!(m.rcode, 3);
    let bid = block_id(&m);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": bid, "expires_at": now() + 3600}])),
        )
        .await;
    assert_eq!(st, 403, "{v}");
    assert_eq!(v["error"]["code"], "too_short");
    assert_eq!(v["error"]["index"], 0);
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ask again in") && msg.contains("max_duration"),
        "{msg}"
    );
    assert_eq!(e.ext("GET", None).await, (200, json!([])), "nothing recorded");

    // Under a 1 h maximum, a short request is refused too, saying how long it needs.
    with_block_ttl_600(
        &e,
        json!({"mode": "self", "max_duration": "1h", "rate_per_hour": 2}),
    )
    .await;
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": bid, "expires_at": now() + 300}])),
        )
        .await;
    assert_eq!(st, 403, "{v}");
    assert_eq!(v["error"]["code"], "too_short");
    let msg = v["error"]["message"].as_str().unwrap();
    let need: u64 = msg
        .rsplit("at least ")
        .next()
        .and_then(|t| t.trim_end_matches(" s").parse().ok())
        .unwrap_or_else(|| panic!("{msg}"));
    assert!(
        (600..=610).contains(&need),
        "hold 605 s + 5 s, less the time since the block: {need}"
    );

    // A compatible request (15 min): created, its countdown the rest of the hold.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": bid, "expires_at": now() + 900}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let ra = v[0]["retry_after_s"].as_u64().unwrap();
    assert!((590..=605).contains(&ra), "the hold, not cut short: {ra}");
    let allow_id = v[0]["allow_id"].as_str().unwrap().to_owned();
    let expires = v[0]["expires_at"].as_i64().unwrap();
    // Re-timing it to end inside the hold: refused, the allow keeps its end.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"allow_id": allow_id, "expires_at": now() + 120}])),
        )
        .await;
    assert_eq!((st, &v["error"]["code"]), (403, &json!("too_short")), "{v}");
    let (_, v) = e.ext("GET", None).await;
    assert_eq!(v[0]["expires_at"], expires);
    // None of the refusals counted against rate_per_hour 2: a re-time past the hold is the
    // second change this hour.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"allow_id": allow_id, "expires_at": now() + 1800}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    e.r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bypass_off_is_refused_and_core_revokes_allows() {
    let e = env(json!({"mode": "off"}), json!({"interfaces": []}), None).await;
    let bid = block_id(&udp_q(e.dns(), &Q::new("blocked.example", 1)).await);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": bid, "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 403, "{v}");

    // A profile with bypass on: an allow, then core's revoke list ends it.
    let up = FakeUpstream::plain(ok_upstream()).await;
    let mut cfg = config(
        &up,
        &e.head,
        json!({"mode": "self", "max_duration": "1h"}),
        json!({"interfaces": []}),
    );
    cfg["upstreams"] = json!({"up1": plain_upstream(&e.up, "udp")});
    let id = e.core.set_config(&cfg);
    e.core.changed(&id);
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": bid, "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let allow_id = v[0]["allow_id"].as_str().unwrap().to_owned();
    cfg["revoked_allows"] = json!({"id": "00112233445566ff", "allows": [allow_id, "a-unknown"]});
    let id = e.core.set_config(&cfg);
    e.core.changed(&id);
    assert!(
        wait_until(T, || edge.state.get().applied.revoked_allows.as_deref()
            == Some("00112233445566ff"))
        .await
    );
    assert!(edge.allows.list().is_empty());
    assert!(
        wait_until(T, || e
            .allow_records()
            .iter()
            .any(|r| r["action"] == "revoked" && r["via"] == "core"))
        .await
    );
    // After a config activation that turns bypass off, every allow is revoked `via: config`.
    let (st, _) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": bid, "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200);
    let mut off = cfg.clone();
    off["profiles"]["default"]["bypass"] = json!({"mode": "off"});
    off["revoked_allows"] = Value::Null;
    let id = e.core.set_config(&off);
    e.core.changed(&id);
    assert!(
        wait_until(T, || e
            .allow_records()
            .iter()
            .any(|r| r["action"] == "revoked" && r["via"] == "config"))
        .await,
        "{:#?}",
        e.allow_records()
    );
    assert!(edge.allows.list().is_empty());
    e.r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ip_allows_go_through_the_firewall_and_the_ptr_probe_sees_them() {
    let h = helperkit::start();
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        json!({"interfaces": [{"name": "lo", "mode": "enforce"}], "static_allow": ["192.168.1.0/24"], "ack_wait_ms": 1000}),
        Some(h.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(
        wait_until(T, || edge.fw.state.load().connected).await,
        "helper connected"
    );
    // 1.2.3.4 counts as blocked for this device: the extension's PTR probe says so.
    let p = e.probe("4.3.2.1.in-addr.arpa", 12).await;
    assert_eq!(p.rcode, 3);
    assert_eq!(p.ede(), vec![(15, "cause=firewall".to_owned())]);
    // An IP no allow may name (not unicast, or the edge itself) gets no firewall answer, though
    // `lo` enforces: the probe reports only blocks the API would lift (edge.md §12).
    let mut not_allowable: Vec<IpAddr> = [
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "::ffff:127.0.0.1",
        "ff02::1",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    if let Some(own) = own_address().filter(|a| edge.dns.interfaces.is_local(*a)) {
        not_allowable.push(own);
    }
    for ip in &not_allowable {
        let p = e.probe(&ptr_name(*ip), 12).await;
        assert_eq!(p.rcode, 0, "{ip}");
        assert!(p.ede().is_empty(), "{ip}: {:?}", p.ede());
        let (st, v) = e
            .ext(
                "PATCH",
                Some(json!([{"ip": ip.to_string(), "expires_at": now() + 600}])),
            )
            .await;
        assert_eq!(st, 409, "{ip}: {v}");
    }
    // An IP allow: a per-client pair for the device's addresses, acked by the helper.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v[0]["kind"], "ip");
    assert_eq!(v[0]["retry_after_s"], 0);
    assert!(
        h.has("picket4", Some("127.0.0.1"), "1.2.3.4"),
        "{:?}",
        h.members("picket4")
    );
    let t = h
        .members("picket4")
        .into_iter()
        .find(|(_, d, _)| *d == Some("1.2.3.4".parse().unwrap()))
        .and_then(|(_, _, t)| t)
        .unwrap();
    assert!((590..=600).contains(&t), "timeout = the allow's duration: {t}");
    let p = e.probe("4.3.2.1.in-addr.arpa", 12).await;
    assert_eq!(p.rcode, 0, "not blocked any more");
    assert!(p.ede().is_empty());
    // Not blocked: in static_allow, or the edge itself.
    let (st, _) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "192.168.1.5", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 409);
    let (st, _) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "127.0.0.1", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 409);
    // Revoking deletes the entry (no DNS grant keeps it).
    let allow_id = v[0]["allow_id"].as_str().unwrap().to_owned();
    let (st, _) = e
        .ext("PATCH", Some(json!([{"allow_id": allow_id, "expires_at": 1}])))
        .await;
    assert_eq!(st, 200);
    assert!(
        wait_until(T, || !h.has("picket4", Some("127.0.0.1"), "1.2.3.4")).await,
        "{:?}",
        h.members("picket4")
    );
    e.r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ip_allow_the_helper_can_not_take_is_refused_with_503_and_not_recorded() {
    let d = dirs();
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        json!({"interfaces": [{"name": "lo", "mode": "enforce"}], "ack_wait_ms": 100}),
        Some(d.run.join("nobody.sock")),
    )
    .await;
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 503, "{v}");
    assert_eq!(v["error"]["index"], 0);
    assert!(e.r.edge.allows.list().is_empty(), "nothing recorded");
    e.r.shutdown().await;
}

/// A DNS block's id for `name` (queried over plain DNS from the test's address).
async fn block_of(e: &Env, name: &str) -> String {
    let m = udp_q(e.dns(), &Q::new(name, 1)).await;
    assert_eq!(m.ede_codes(), vec![15, 4], "{name} blocked");
    block_id(&m)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_entries_for_one_allow_count_once_and_conflicting_ones_are_refused() {
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": false, "max_active": 2, "rate_per_hour": 50}),
        json!({"interfaces": []}),
        None,
    )
    .await;
    let (b1, b2, b3, b4) = (
        block_of(&e, "blocked.example").await,
        block_of(&e, "block2.example").await,
        block_of(&e, "block3.example").await,
        block_of(&e, "block4.example").await,
    );
    let end = now() + 600;
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": b1, "expires_at": end}, {"block_id": b2, "expires_at": end}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let a1 = v[0]["allow_id"].as_str().unwrap().to_owned();
    // Revoking one allow twice while creating two: still three active, over max_active 2.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([
                {"allow_id": a1, "expires_at": 1},
                {"allow_id": a1, "expires_at": 1},
                {"block_id": b3, "expires_at": end},
                {"block_id": b4, "expires_at": end},
            ])),
        )
        .await;
    assert_eq!(st, 403, "{v}");
    assert_eq!(v["error"]["code"], "max_active");
    assert_eq!(e.r.edge.allows.list().len(), 2, "nothing changed");
    // The same allow named twice with different expiries: refused, naming the second entry.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([
                {"allow_id": a1, "expires_at": end},
                {"block_id": b1, "expires_at": 1},
            ])),
        )
        .await;
    assert_eq!(st, 400, "{v}");
    assert_eq!(v["error"]["index"], 1);
    // The same entry twice: one allow.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(
                json!([{"allow_id": a1, "expires_at": 1}, {"allow_id": a1, "expires_at": 1},
                {"block_id": b3, "expires_at": end}, {"block_id": b3, "expires_at": end}]),
            ),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(e.r.edge.allows.list().len(), 2, "{:?}", e.r.edge.allows.list());
    e.r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_batch_leaves_existing_ip_allows_as_they_were() {
    let h = helperkit::start();
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        json!({"interfaces": [{"name": "lo", "mode": "enforce"}], "ack_wait_ms": 1000}),
        Some(h.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.fw.state.load().connected).await);
    let timeout_of = |ip: &str| {
        h.members("picket4")
            .into_iter()
            .find(|(_, d, _)| *d == Some(ip.parse().unwrap()))
            .and_then(|(_, _, t)| t)
    };
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 600},
                {"ip": "5.6.7.8", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let before = edge.allows.list();
    // Extend one, shorten the other, then an entry the firewall can't take (this IPv4-only
    // device has no IPv6 address to pair it with): 503, and nothing changes.
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([
                {"ip": "1.2.3.4", "expires_at": now() + 1200},
                {"ip": "5.6.7.8", "expires_at": now() + 60},
                {"ip": "2001:db8::1", "expires_at": now() + 600},
            ])),
        )
        .await;
    assert_eq!(st, 503, "{v}");
    let mut after = edge.allows.list();
    let mut b = before.clone();
    after.sort_by(|x, y| x.allow_id.cmp(&y.allow_id));
    b.sort_by(|x, y| x.allow_id.cmp(&y.allow_id));
    assert_eq!(after, b, "the stored allows are unchanged");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t1 = timeout_of("1.2.3.4").expect("1.2.3.4 keeps its entry");
    let t2 = timeout_of("5.6.7.8").expect("5.6.7.8 keeps its entry");
    assert!((560..=600).contains(&t1), "1.2.3.4 back at its old expiry: {t1}");
    assert!((560..=600).contains(&t2), "5.6.7.8 not shortened: {t2}");
    e.r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_huge_max_duration_is_bounded_and_never_panics() {
    let e = env(
        json!({"mode": "self", "max_duration": "18446744073709551615", "ips": false}),
        json!({"interfaces": []}),
        None,
    )
    .await;
    let b1 = block_of(&e, "blocked.example").await;
    let far = now() + 100 * 365 * 86_400;
    let (st, v) = e
        .ext("PATCH", Some(json!([{"block_id": b1, "expires_at": far}])))
        .await;
    assert_eq!(st, 200, "{v}");
    assert!(
        v[0]["expires_at"].as_i64().unwrap() < far,
        "shortened to the bound"
    );
    e.r.shutdown().await;
}

/// A bypass PATCH whose body declares `len` bytes and never arrives.
async fn stalled_patch(e: &Env, len: usize) -> Result<u16, ()> {
    use futures_util::StreamExt;
    let tcp = TcpStream::connect(e.doh()).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(client_tls(&e.ca, &[b"h2"]))
        .connect(ServerName::try_from(SNI.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    let (mut s, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let body = http_body_util::StreamBody::new(
        futures_util::stream::iter(vec![Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(
            Bytes::from_static(b"["),
        ))])
        .chain(futures_util::stream::pending()),
    );
    let req = http::Request::builder()
        .method("PATCH")
        .uri(format!("https://{SNI}/v1/temporary-allows"))
        .header("x-picket-client", "extension")
        .header("content-type", "application/json")
        .header("content-length", len.to_string())
        .body(body)
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(2), s.send_request(req)).await {
        Ok(Ok(r)) => Ok(r.status().as_u16()),
        _ => Err(()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bypass_bodies_are_charged_to_the_shared_body_budget_before_they_are_read() {
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": false}),
        json!({"interfaces": []}),
        None,
    )
    .await;
    // A source's bodies share its 1 MiB budget: 20 stalled 64 KiB bodies don't all fit, and the
    // ones that don't are refused at once instead of being buffered.
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let ee = &e;
        tasks.push(async move { stalled_patch(ee, 64 << 10).await });
    }
    let results = futures_util::future::join_all(tasks).await;
    let refused = results.iter().filter(|r| **r == Ok(503)).count();
    assert!(refused >= 4, "{results:?}");
    e.r.shutdown().await;
}

/// A helper that answers everything but `ensure` (an ack that never comes).
fn mute_helper(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    use futures_util::{SinkExt, StreamExt};
    use picket_api::helper::{Frame, PROTO_VERSION, kind};
    let l = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut io =
                    tokio_util::codec::Framed::new(sock, tokio_util::codec::LengthDelimitedCodec::new());
                while let Some(Ok(b)) = io.next().await {
                    let f: Frame = serde_json::from_slice(&b).unwrap();
                    let data = match f.kind.as_str() {
                        kind::HELLO => json!({"proto_version": PROTO_VERSION, "rules_ok": true}),
                        kind::DUMP => json!({"entries": []}),
                        kind::APPLY => json!({"ok": true, "rules_ok": true}),
                        kind::STATUS => json!({"rules_ok": true}),
                        kind::ENSURE | kind::DELETE => continue,
                        _ => json!({}),
                    };
                    let out = Frame {
                        kind: f.kind.clone(),
                        id: f.id,
                        data,
                    };
                    if io
                        .send(Bytes::from(serde_json::to_vec(&out).unwrap()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_ip_allow_request_still_ends_cleanly() {
    let d = dirs();
    let sock = d.run.join("mute.sock");
    std::fs::create_dir_all(&d.run).unwrap();
    let _h = mute_helper(&sock);
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        json!({"interfaces": [{"name": "lo", "mode": "enforce"}], "ack_wait_ms": 100}),
        Some(sock.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.fw.state.load().connected).await);
    // The request goes away (a stream reset) while it waits for the helper's ack.
    let r = tokio::time::timeout(
        Duration::from_millis(400),
        e.ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 600}])),
        ),
    )
    .await;
    assert!(r.is_err(), "still waiting for the ack");
    // The change still ends as the spec says for no ack: nothing recorded, and the IP counts as
    // blocked again (the extension's PTR probe sees it).
    assert!(
        wait_until(T, || edge
            .fw
            .ip_blocked("127.0.0.1".parse().unwrap(), "1.2.3.4".parse().unwrap()))
        .await,
        "the shadow map gave the key back"
    );
    assert!(edge.allows.list().is_empty());
    e.r.shutdown().await;
}

/// An address that moved to another device never gets the first device's IP allow back, not even
/// when the first device later gains another address (edge.md §12; edge-firewall.md §1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_moved_address_never_gets_the_old_devices_ip_allow_back() {
    use picket_edge::neighbours::{Change, format_mac};
    let h = helperkit::start();
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        json!({"interfaces": [{"name": "lo", "mode": "enforce"}], "ack_wait_ms": 1000}),
        Some(h.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.fw.state.load().connected).await);
    let (a, b) = ([0x02, 0, 0, 0, 0, 0x0a], [0x02, 0, 0, 0, 0, 0x0b]);
    let (x, y): (IpAddr, IpAddr) = ("127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap());
    edge.neighbours.apply(&[Change::Upsert { ip: x, mac: a }]);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let id = v[0]["allow_id"].as_str().unwrap().to_owned();
    let stored = || edge.allows.list().into_iter().find(|s| s.allow_id == id).unwrap();
    assert_eq!(stored().device, format_mac(&a));
    assert!(h.has("picket4", Some("127.0.0.1"), "1.2.3.4"));
    // The address moves to device b: a's allow stops covering it.
    edge.neighbours.apply(&[Change::Upsert { ip: x, mac: b }]);
    assert!(
        wait_until(T, || !h.has("picket4", Some("127.0.0.1"), "1.2.3.4")
            && stored().addresses.is_empty())
        .await,
        "{:?} {:?}",
        h.members("picket4"),
        stored().addresses
    );
    // Device a gains another address: its allow covers that one, and b's address stays out.
    edge.neighbours.apply(&[Change::Upsert { ip: y, mac: a }]);
    assert!(
        wait_until(T, || h.has("picket4", Some("127.0.0.2"), "1.2.3.4")).await,
        "{:?}",
        h.members("picket4")
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !h.has("picket4", Some("127.0.0.1"), "1.2.3.4"),
        "b got a's allow back: {:?}",
        h.members("picket4")
    );
    assert_eq!(stored().addresses, vec!["127.0.0.2".to_owned()]);
    e.r.shutdown().await;
}

/// The real helper behind a socket of its own that holds back `ensure` acks while `hold` is set
/// (the requests go through at once, so the entries reach the helper; only the edge's wait for
/// the ack is stretched). `held` counts the acks it held back.
struct AckGate {
    path: PathBuf,
    hold: tokio::sync::watch::Sender<bool>,
    held: Arc<std::sync::atomic::AtomicUsize>,
}

fn ack_gate(upstream: PathBuf, path: PathBuf) -> AckGate {
    use futures_util::{SinkExt, StreamExt};
    use picket_api::helper::{Frame, kind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};
    let l = tokio::net::UnixListener::bind(&path).unwrap();
    let (hold, _) = tokio::sync::watch::channel(false);
    let held = Arc::new(AtomicUsize::new(0));
    let (hold2, held2) = (hold.clone(), Arc::clone(&held));
    tokio::spawn(async move {
        while let Ok((sock, _)) = l.accept().await {
            let up = tokio::net::UnixStream::connect(&upstream).await.unwrap();
            let (mut csink, mut cstream) = Framed::new(sock, LengthDelimitedCodec::new()).split();
            let (mut usink, mut ustream) = Framed::new(up, LengthDelimitedCodec::new()).split();
            tokio::spawn(async move {
                while let Some(Ok(b)) = cstream.next().await {
                    if usink.send(b.freeze()).await.is_err() {
                        return;
                    }
                }
            });
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
            tokio::spawn(async move {
                while let Some(b) = rx.recv().await {
                    if csink.send(b).await.is_err() {
                        return;
                    }
                }
            });
            let (hold, held) = (hold2.clone(), Arc::clone(&held2));
            tokio::spawn(async move {
                while let Some(Ok(b)) = ustream.next().await {
                    let b = b.freeze();
                    let ensure = serde_json::from_slice::<Frame>(&b).is_ok_and(|f| f.kind == kind::ENSURE);
                    if ensure && *hold.borrow() {
                        held.fetch_add(1, Ordering::SeqCst);
                        let (tx, mut rx) = (tx.clone(), hold.subscribe());
                        tokio::spawn(async move {
                            let _ = rx.wait_for(|h| !*h).await;
                            let _ = tx.send(b);
                        });
                    } else if tx.send(b).is_err() {
                        return;
                    }
                }
            });
        }
    });
    AckGate { path, hold, held }
}

/// An address that moves to another device while a new or extended IP allow waits for the
/// helper's ack isn't listed by the allow the request stores, and its new owner gets no entry
/// from it (edge.md §12; edge-firewall.md §1). The device's other address stays covered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_address_that_moves_during_the_ack_wait_is_not_stored_with_the_allow() {
    use picket_edge::neighbours::Change;
    use std::sync::atomic::Ordering;
    let h = helperkit::start();
    let d = dirs();
    std::fs::create_dir_all(&d.run).unwrap();
    let gate = ack_gate(h.path.clone(), d.run.join("gate.sock"));
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        enforce_lo(),
        Some(gate.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.fw.state.load().connected).await);
    let (a, b) = ([0x02, 0, 0, 0, 0, 0x0a], [0x02, 0, 0, 0, 0, 0x0b]);
    let (x, y): (IpAddr, IpAddr) = ("127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap());
    let (xs, ys) = ("127.0.0.1".to_owned(), "127.0.0.2".to_owned());
    // One request while `x` moves from a to b, its acks held back until the move is through.
    let moving = |entry: Value| {
        let (edge, gate, h) = (Arc::clone(&edge), &gate, &h);
        let e = &e;
        async move {
            edge.neighbours.apply(&[Change::Upsert { ip: x, mac: a }]);
            gate.held.store(0, Ordering::SeqCst);
            gate.hold.send_replace(true);
            let req = e.ext("PATCH", Some(json!([entry])));
            let mover = async {
                assert!(wait_until(T, || gate.held.load(Ordering::SeqCst) > 0).await);
                edge.neighbours.apply(&[Change::Upsert { ip: x, mac: b }]);
                // The firewall has handled the move once the old device's allow no longer
                // covers the address in its own view (the kernel follows after the ack).
                assert!(
                    wait_until(Duration::from_secs(1), || edge
                        .fw
                        .ip_blocked(x, "1.2.3.4".parse().unwrap()))
                    .await,
                    "the move went through before the ack"
                );
                gate.hold.send_replace(false);
            };
            let ((st, v), ()) = tokio::join!(req, mover);
            assert_eq!(st, 200, "{v}");
            assert!(
                wait_until(T, || !h.has("picket4", Some("127.0.0.1"), "1.2.3.4")).await,
                "b got a's allow: {:?}",
                h.members("picket4")
            );
            v
        }
    };
    edge.neighbours
        .apply(&[Change::Upsert { ip: x, mac: a }, Change::Upsert { ip: y, mac: a }]);
    // A new allow: made for both of a's addresses, stored with only the one a still holds.
    let v = moving(json!({"ip": "1.2.3.4", "expires_at": now() + 600})).await;
    let id = v[0]["allow_id"].as_str().unwrap().to_owned();
    let stored = || edge.allows.list().into_iter().find(|s| s.allow_id == id).unwrap();
    assert_eq!(stored().addresses, vec![ys.clone()]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !h.has("picket4", Some("127.0.0.1"), "1.2.3.4"),
        "b got a's allow: {:?}",
        h.members("picket4")
    );
    assert!(h.has("picket4", Some("127.0.0.2"), "1.2.3.4"));
    // Device a gets x back (it gains it again): a re-check lists it again.
    edge.neighbours.apply(&[Change::Upsert { ip: x, mac: a }]);
    assert!(
        wait_until(T, || stored().addresses.contains(&xs)
            && h.has("picket4", Some("127.0.0.1"), "1.2.3.4"))
        .await,
        "{:?} {:?}",
        stored().addresses,
        h.members("picket4")
    );
    // An extension while x moves again: the stored allow drops it and keeps y, at the new expiry.
    let until = now() + 1200;
    moving(json!({"allow_id": id, "expires_at": until})).await;
    assert_eq!(stored().addresses, vec![ys.clone()]);
    assert_eq!(stored().expires_at.as_second(), until);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !h.has("picket4", Some("127.0.0.1"), "1.2.3.4"),
        "b got a's allow: {:?}",
        h.members("picket4")
    );
    assert!(h.has("picket4", Some("127.0.0.2"), "1.2.3.4"));
    // allows.json holds the same.
    let file: Value = serde_json::from_slice(&std::fs::read(e._d.data.join("allows.json")).unwrap()).unwrap();
    let rec = file["allows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["allow_id"] == id.as_str())
        .unwrap();
    assert_eq!(rec["addresses"], json!([ys]));
    e.r.shutdown().await;
}

/// A DNS allow from a profile with `bypass: self` (1 h), on an edge whose config the tests then
/// change; returns the allow's id.
async fn one_dns_allow(e: &Env) -> String {
    let bid = block_id(&udp_q(e.dns(), &Q::new("blocked.example", 1)).await);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"block_id": bid, "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    v[0]["allow_id"].as_str().unwrap().to_owned()
}

/// Activates the env's config with `bypass` as the default profile's.
async fn activate_bypass(e: &Env, bypass: Value) {
    let id = e
        .core
        .set_config(&config(&e.up, &e.head, bypass, json!({"interfaces": []})));
    e.core.changed(&id);
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
}

fn revoked_by_config(e: &Env) -> bool {
    e.allow_records()
        .iter()
        .any(|r| r["action"] == "revoked" && r["via"] == "config")
}

/// The re-check after a config activation needs a synchronised clock (README §2 Clocks); one it
/// skipped runs once the clock syncs (edge.md §12 "After each config activation").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recheck_skipped_while_the_clock_is_unsynchronised_runs_once_it_syncs() {
    let e = env(
        json!({"mode": "self", "max_duration": "1h"}),
        json!({"interfaces": []}),
        None,
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    one_dns_allow(&e).await;
    edge.clock.set(false);
    activate_bypass(&e, json!({"mode": "off"})).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        edge.allows.list().len(),
        1,
        "no re-check on an unsynchronised clock"
    );
    edge.clock.set(true);
    assert!(
        wait_until(Duration::from_secs(10), || edge.allows.list().is_empty()).await,
        "the skipped re-check ran once the clock synced"
    );
    assert!(wait_until(T, || revoked_by_config(&e)).await);
    e.r.shutdown().await;
}

/// A re-check's revocation holds in memory when `allows.json` can't be written, and the write is
/// retried until it lands (edge.md §12; README §2 Restarts).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rechecks_failed_allows_json_write_holds_in_memory_and_is_retried() {
    let e = env(
        json!({"mode": "self", "max_duration": "1h"}),
        json!({"interfaces": []}),
        None,
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    one_dns_allow(&e).await;
    // A non-empty directory where allows.json goes: no rename replaces it, not even root's.
    let path = e._d.data.join("allows.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir_all(path.join("x")).unwrap();
    activate_bypass(&e, json!({"mode": "off"})).await;
    assert!(
        wait_until(T, || edge.allows.list().is_empty()).await,
        "the revocation holds in memory"
    );
    assert!(wait_until(T, || revoked_by_config(&e)).await);
    assert!(
        udp_q(e.dns(), &Q::new("blocked.example", 1))
            .await
            .ede_codes()
            .contains(&15),
        "queries follow the memory"
    );
    std::fs::remove_dir_all(&path).unwrap();
    let stored = || -> Option<Value> { serde_json::from_slice(&std::fs::read(&path).ok()?).ok() };
    assert!(
        wait_until(T, || stored().is_some_and(|v| v["allows"] == json!([]))).await,
        "the write is retried until it lands: {:?}",
        stored()
    );
    e.r.shutdown().await;
}

/// Neighbour events the re-check task missed (its broadcast channel overflowed) are made up by a
/// full re-check: a device's IP allow still covers the address it gained meanwhile (edge.md §12).
/// On this single-threaded runtime one burst of changes sends every event before the task reads
/// any, so the device's `Gained` is gone when it does.
#[tokio::test(flavor = "current_thread")]
async fn missed_neighbour_events_are_made_up_by_a_full_recheck() {
    use picket_edge::neighbours::Change;
    let h = helperkit::start();
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        json!({"interfaces": [{"name": "lo", "mode": "enforce"}], "ack_wait_ms": 1000}),
        Some(h.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.fw.state.load().connected).await);
    let a = [0x02, 0, 0, 0, 0, 0x0a];
    let (x, y): (IpAddr, IpAddr) = ("127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap());
    edge.neighbours.apply(&[Change::Upsert { ip: x, mac: a }]);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    assert!(h.has("picket4", Some("127.0.0.1"), "1.2.3.4"));
    let mut burst = vec![Change::Upsert { ip: y, mac: a }];
    for i in 0..3000u32 {
        burst.push(Change::Upsert {
            ip: IpAddr::from([10, 99, (i >> 8) as u8, i as u8]),
            mac: [0x02, 0, 0, 0, 1, (i % 200) as u8],
        });
    }
    edge.neighbours.apply(&burst);
    assert!(
        wait_until(T, || h.has("picket4", Some("127.0.0.2"), "1.2.3.4")).await,
        "{:?}",
        h.members("picket4")
    );
    e.r.shutdown().await;
}

/// Activates the env's config with `bypass` as the default profile's and `firewall` as is.
async fn activate_with(e: &Env, bypass: Value, firewall: Value) {
    let id = e.core.set_config(&config(&e.up, &e.head, bypass, firewall));
    e.core.changed(&id);
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.active().object_id.as_deref() == Some(id.as_str())).await);
}

fn enforce_lo() -> Value {
    json!({"interfaces": [{"name": "lo", "mode": "enforce"}], "ack_wait_ms": 1000})
}

/// An IP allow expanded to an address the device gained holds that address in memory even when
/// `allows.json` can't be written, so a later revocation removes that address's kernel entry
/// too (edge.md §12 re-checks; edge-firewall.md §3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expansion_allows_json_cannot_take_is_still_revoked_in_full() {
    use picket_edge::neighbours::Change;
    let h = helperkit::start();
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        enforce_lo(),
        Some(h.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.fw.state.load().connected).await);
    let a = [0x02, 0, 0, 0, 0, 0x0a];
    let (x, y): (IpAddr, IpAddr) = ("127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap());
    edge.neighbours.apply(&[Change::Upsert { ip: x, mac: a }]);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    // A non-empty directory where allows.json goes: no rename replaces it, not even root's.
    let path = e._d.data.join("allows.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir_all(path.join("x")).unwrap();
    edge.neighbours.apply(&[Change::Upsert { ip: y, mac: a }]);
    assert!(
        wait_until(T, || h.has("picket4", Some("127.0.0.2"), "1.2.3.4")).await,
        "{:?}",
        h.members("picket4")
    );
    // The profile turns IP allows off: the re-check revokes the allow on every address.
    activate_with(
        &e,
        json!({"mode": "self", "max_duration": "1h", "ips": false}),
        enforce_lo(),
    )
    .await;
    assert!(wait_until(T, || edge.allows.list().is_empty()).await);
    assert!(
        wait_until(T, || !h.has("picket4", Some("127.0.0.1"), "1.2.3.4")
            && !h.has("picket4", Some("127.0.0.2"), "1.2.3.4"))
        .await,
        "the revoked allow's entries stay: {:?}",
        h.members("picket4")
    );
    e.r.shutdown().await;
}

/// A catch-up re-check (here: after the clock syncs) that must both shorten an IP allow and
/// cover an address its device gained meanwhile does both (edge.md §12).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catch_up_both_shortens_and_expands_an_ip_allow() {
    use picket_edge::neighbours::Change;
    let h = helperkit::start();
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        enforce_lo(),
        Some(h.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.fw.state.load().connected).await);
    let a = [0x02, 0, 0, 0, 0, 0x0a];
    let (x, y): (IpAddr, IpAddr) = ("127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap());
    edge.neighbours.apply(&[Change::Upsert { ip: x, mac: a }]);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 3000}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let id = v[0]["allow_id"].as_str().unwrap().to_owned();
    let stored = || edge.allows.list().into_iter().find(|s| s.allow_id == id).unwrap();
    // While the clock is unsynchronised the profile's limit drops and the device gains an
    // address; both re-checks are skipped.
    edge.clock.set(false);
    activate_with(
        &e,
        json!({"mode": "self", "max_duration": "10m", "ips": true}),
        enforce_lo(),
    )
    .await;
    edge.neighbours.apply(&[Change::Upsert { ip: y, mac: a }]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(stored().addresses, vec!["127.0.0.1".to_owned()]);
    assert!(stored().expires_at.as_second() > now() + 2000);
    edge.clock.set(true);
    assert!(
        wait_until(T, || stored().expires_at.as_second() <= now() + 600
            && stored().addresses.contains(&"127.0.0.2".to_owned()))
        .await,
        "{:?} until {}",
        stored().addresses,
        stored().expires_at
    );
    assert!(
        wait_until(T, || h.has("picket4", Some("127.0.0.2"), "1.2.3.4")).await,
        "{:?}",
        h.members("picket4")
    );
    e.r.shutdown().await;
}

/// Neighbour events the firewall's loop missed (its channel overflowed) are made up from the
/// current neighbour table: an address that moved meanwhile loses the old device's IP-allow
/// entry, so its new owner doesn't get it (edge-firewall.md §1; edge.md §12). On this
/// single-threaded runtime one burst of changes sends every event before the loop reads any.
#[tokio::test(flavor = "current_thread")]
async fn a_move_the_firewall_missed_still_takes_the_old_devices_entries_off() {
    use picket_edge::neighbours::Change;
    let h = helperkit::start();
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true}),
        enforce_lo(),
        Some(h.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    assert!(wait_until(T, || edge.fw.state.load().connected).await);
    let (a, b) = ([0x02, 0, 0, 0, 0, 0x0a], [0x02, 0, 0, 0, 0, 0x0b]);
    let x: IpAddr = "127.0.0.1".parse().unwrap();
    edge.neighbours.apply(&[Change::Upsert { ip: x, mac: a }]);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "1.2.3.4", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    let id = v[0]["allow_id"].as_str().unwrap().to_owned();
    assert!(h.has("picket4", Some("127.0.0.1"), "1.2.3.4"));
    let mut burst = vec![Change::Upsert { ip: x, mac: b }];
    for i in 0..3000u32 {
        burst.push(Change::Upsert {
            ip: IpAddr::from([10, 99, (i >> 8) as u8, i as u8]),
            mac: [0x02, 0, 0, 0, 1, (i % 200) as u8],
        });
    }
    edge.neighbours.apply(&burst);
    assert!(
        wait_until(T, || !h.has("picket4", Some("127.0.0.1"), "1.2.3.4")).await,
        "the new owner kept the old device's allow: {:?}",
        h.members("picket4")
    );
    let stored = edge.allows.list().into_iter().find(|s| s.allow_id == id).unwrap();
    assert!(stored.addresses.is_empty(), "{:?}", stored.addresses);
    e.r.shutdown().await;
}

/// UniFi's local networks never reach Picket's jump (issue #47):
/// the helper reads the `…local_zoned_subnets` set that guards `lo`'s zone→External chain, and
/// the PTR probe and IP allows treat its members as not blocked, scoped by interface and family,
/// while every other destination still counts as blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unifi_local_networks_get_no_firewall_block_and_no_ip_allow() {
    use picket_edge_helper::ipset::{Elem, SetFamily, SetType};
    use picket_edge_helper::iptables::{Family, TableName};
    let h = helperkit::start();
    // `lo` is one of the Internal zone's interfaces here.
    let lo =
        "-A UBIOS_FORWARD_IN_USER -i lo -m comment --comment \"UBIOS zone Internal\" -j UBIOS_LAN_IN_USER\n";
    for (f, fx) in [
        (Family::V4, "filter-block-all-reject.rules"),
        (Family::V6, "filter6-block-all-reject.rules"),
    ] {
        h.b.set_table(f, TableName::Filter, &format!("{}{lo}", helperkit::fx(fx)));
    }
    let net = |s: &str| {
        let (a, l) = s.split_once('/').unwrap();
        (Elem::net(a.parse().unwrap(), l.parse().unwrap()), false)
    };
    let local4 = |nets: &[&str]| {
        let m: Vec<_> = nets.iter().map(|s| net(s)).collect();
        h.b.put_set("UBIOS_local_zoned_subnets", SetType::HashNet, SetFamily::Inet, &m);
    };
    // The NAS VLAN, and a routed network no interface of this host is on.
    local4(&["198.51.100.0/24", "203.0.113.0/26"]);
    h.b.put_set(
        "UBIOS6_local_zoned_subnets",
        SetType::HashNet,
        SetFamily::Inet6,
        &[net("2001:db8:20::/64")],
    );
    let e = env(
        json!({"mode": "self", "max_duration": "1h", "ips": true, "max_active": 1, "rate_per_hour": 1}),
        json!({"interfaces": [{"name": "lo", "mode": "enforce"}], "ack_wait_ms": 1000}),
        Some(h.path.clone()),
    )
    .await;
    let edge = Arc::clone(&e.r.edge);
    let client: IpAddr = "127.0.0.1".parse().unwrap();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert!(
        wait_until(T, || !edge.fw.ip_blocked(client, ip("198.51.100.10"))).await,
        "the helper's local networks reach the edge: {:?}",
        edge.fw.state.load().conditions.local_dst
    );
    for local in ["198.51.100.10", "203.0.113.5"] {
        let p = e.probe(&ptr_name(ip(local)), 12).await;
        assert_eq!(p.rcode, 0, "{local}");
        assert!(p.ede().is_empty(), "{local}: {:?}", p.ede());
        let (st, v) = e
            .ext("PATCH", Some(json!([{"ip": local, "expires_at": now() + 600}])))
            .await;
        assert_eq!(st, 409, "{local}: {v}");
        assert_eq!(v["error"]["code"], "not_blocked", "{v}");
    }
    assert!(edge.allows.list().is_empty());
    assert!(h.members("picket4").is_empty(), "{:?}", h.members("picket4"));
    // IPv6 has its own set; an IPv4 member doesn't make the same bits local in IPv6.
    assert!(!edge.fw.ip_blocked(client, ip("2001:db8:20::10")));
    assert!(edge.fw.ip_blocked(client, ip("2001:db8:99::10")));
    // Outside the set (the WAN side, or the rest of a routed /24): blocked, and allowable with the
    // one allow the limits leave (the refusals above spent none of them).
    assert!(edge.fw.ip_blocked(client, ip("203.0.113.70")));
    let p = e.probe(&ptr_name(ip("192.0.2.5")), 12).await;
    assert_eq!(p.rcode, 3);
    assert_eq!(p.ede(), vec![(15, "cause=firewall".to_owned())]);
    let (st, v) = e
        .ext(
            "PATCH",
            Some(json!([{"ip": "192.0.2.5", "expires_at": now() + 600}])),
        )
        .await;
    assert_eq!(st, 200, "{v}");
    assert!(h.has("picket4", Some("127.0.0.1"), "192.0.2.5"));
    // A network edit on the gateway shows at the helper's next pass.
    local4(&["203.0.113.0/26"]);
    assert!(
        wait_until(T, || edge.fw.ip_blocked(client, ip("198.51.100.10"))).await,
        "the NAS VLAN left UniFi's local networks"
    );
    assert!(!edge.fw.ip_blocked(client, ip("203.0.113.5")));
    // A set the helper can't fully read is not used at all.
    h.b.put_set(
        "UBIOS_local_zoned_subnets",
        SetType::HashNet,
        SetFamily::Inet,
        &[net("203.0.113.0/24"), (net("203.0.113.64/26").0, true)],
    );
    assert!(wait_until(T, || edge.fw.ip_blocked(client, ip("203.0.113.5"))).await);
    // The snapshot counts only while the helper is connected.
    local4(&["203.0.113.0/26"]);
    assert!(wait_until(T, || !edge.fw.ip_blocked(client, ip("203.0.113.5"))).await);
    let mut st = picket_edge::firewall::HelperState::clone(&edge.fw.state.load());
    st.connected = false;
    edge.fw.state.store(Arc::new(st));
    assert!(edge.fw.ip_blocked(client, ip("203.0.113.5")));
    e.r.shutdown().await;
}
