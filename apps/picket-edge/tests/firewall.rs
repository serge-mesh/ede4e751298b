//! The firewall client against the real picket-edge-helper engine in process (edge.md §9;
//! edge-firewall.md §3–§5; build-and-test.md §5 "Independence", "Edge pipeline"): seeding from a
//! dump, `apply` once the config is active, answers' addresses in the sets before the reply, the
//! reconcile, a recreated set refilled, a config without the helper replacing one with it, and an
//! unreachable helper.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod dnsh;
mod helperkit;
mod support;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use dnsh::*;
use picket_api::helper::{EnsureRequest, EnsureResponse, SetEntry, kind};
use picket_edge::firewall::shadow::{FwKey, SetId};
use picket_edge::service::{self, Options, Running, Tuning};
use support::{MockCore, wait_until, write_edge_json};

const T: Duration = Duration::from_secs(30);
const WAN: &str = "UBIOS_LAN_WAN_USER";

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
    t.firewall.unreachable_after = Duration::from_millis(300);
    t.firewall.reconcile_every = Duration::from_secs(2);
    t
}

fn ok_upstream() -> impl Fn(&Msg, &[u8]) -> Act + Send + Sync + 'static {
    |m: &Msg, _q: &[u8]| match m.qtype {
        1 => Act::Answer(Ans::records(vec![a(&m.qname, "93.184.216.34", 300)])),
        _ => Act::Answer(Ans::records(vec![])),
    }
}

fn config(up: &FakeUpstream, interfaces: Value) -> Value {
    json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "unifi"},
        "listeners": [{"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"}],
        "default_profile": "default",
        "profiles": {"default": {"upstream": "g", "ttl": {"min": 0, "max": 300},
            "firewall": {"add_entries": true, "granularity": "per_client_ip", "grace_s": 120}}},
        "upstreams": {"up1": plain_upstream(up, "udp")},
        "upstream_groups": {"g": {"upstreams": ["up1"], "strategy": "failover"}},
        "firewall": {"interfaces": interfaces, "static_allow": ["192.168.1.0/24"], "exempt_sources": [], "ack_wait_ms": 1000},
        "logging": {"spool_after_s": 1},
    })
}

async fn start(d: &Dirs, t: Tuning) -> Running {
    service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        t,
        |_| {},
    )
    .await
    .unwrap()
}

async fn live(r: &Running, id: &str) {
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.active().object_id.as_deref() == Some(id)
            && !edge.dns.listeners.local_addrs("lan-dns").is_empty())
        .await,
        "config live"
    );
}

fn addr(r: &Running) -> std::net::SocketAddr {
    *r.edge.dns.listeners.local_addrs("lan-dns").first().unwrap()
}

fn key(src: &str, dst: &str) -> FwKey {
    FwKey {
        set: SetId::P4,
        src: Some(src.parse().unwrap()),
        dst: dst.parse().unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seeding_apply_and_answers_in_the_set_before_the_reply() {
    let h = helperkit::start();
    // An entry from before this edge started (a helper that kept its sets): seeded from `dump`.
    let r0: EnsureResponse = h
        .call(
            kind::ENSURE,
            &EnsureRequest {
                entries: vec![SetEntry {
                    set: "picket4".into(),
                    src: Some("10.0.0.9".parse().unwrap()),
                    dst: "1.2.3.4".parse().unwrap(),
                    timeout_s: 100,
                }],
            },
        )
        .await;
    assert!(r0.ok);
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&config(&up, json!([{"name": "br0", "mode": "enforce"}])));
    let r = start(&d, tuning(&d, h.path.clone())).await;
    live(&r, &id).await;
    // `apply` once the config is active: the jump sits above the Block All.
    assert!(
        wait_until(T, || h
            .rules(WAN)
            .iter()
            .any(|x| x.contains("-i br0 -j PICKET-FWD")))
        .await,
        "{:#?}",
        h.rules(WAN)
    );
    assert!(
        r.edge.fw.live_exp(&key("10.0.0.9", "1.2.3.4")).is_some(),
        "seeded from the dump"
    );
    assert!(r.edge.fw.state.load().connected);
    // An allowed answer's address is in picket4 for the client before the reply leaves.
    let m = udp_q(addr(&r), &Q::new("www.example.com", 1)).await;
    assert_eq!(m.rcode, 0);
    assert!(
        h.has("picket4", Some("127.0.0.1"), "93.184.216.34"),
        "{:?}",
        h.members("picket4")
    );
    let t = h
        .members("picket4")
        .into_iter()
        .find(|(a, _, _)| *a == "127.0.0.1".parse::<IpAddr>().unwrap())
        .and_then(|(_, _, t)| t)
        .unwrap();
    assert!((400..=420).contains(&t), "client_ttl 300 + grace 120: {t}");
    // The record says it added the entry; a repeat finds it in the shadow map.
    assert!(
        wait_until(T, || core.with(|s| s.logs.iter().any(|l| l["t"] == "q"
            && l["qname"] == "www.example.com"
            && l["fw"]["added"] == 1)))
        .await
    );
    let _ = udp_q(addr(&r), &Q::new("www.example.com", 1)).await;
    assert!(r.edge.fw.live_exp(&key("127.0.0.1", "93.184.216.34")).is_some());
    // A heartbeat carries the helper's numbers (api.md §3 `fw`).
    assert!(
        wait_until(T, || core.with(|s| s.heartbeats.iter().any(|hb| hb.fw.is_some()))).await,
        "fw in heartbeats"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reconcile_deletes_unknown_entries_and_a_recreated_set_is_refilled() {
    let h = helperkit::start();
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&config(&up, json!([{"name": "br0", "mode": "enforce"}])));
    let r = start(&d, tuning(&d, h.path.clone())).await;
    live(&r, &id).await;
    let _ = udp_q(addr(&r), &Q::new("www.example.com", 1)).await;
    assert!(h.has("picket4", Some("127.0.0.1"), "93.184.216.34"));
    // An entry the edge never asked for: the reconcile deletes it and holds `fw_drift`.
    let _: EnsureResponse = h
        .call(
            kind::ENSURE,
            &EnsureRequest {
                entries: vec![SetEntry {
                    set: "picket4".into(),
                    src: Some("10.0.0.77".parse().unwrap()),
                    dst: "5.6.7.8".parse().unwrap(),
                    timeout_s: 3000,
                }],
            },
        )
        .await;
    assert!(
        wait_until(T, || !h.has("picket4", Some("10.0.0.77"), "5.6.7.8")).await,
        "the unknown entry is deleted"
    );
    assert!(
        wait_until(T, || core.with(|s| s.logs.iter().any(|l| l["t"] == "condition"
            && l["kind"] == "fw_drift"
            && l["change"] == "appeared")))
        .await
    );
    assert!(
        h.has("picket4", Some("127.0.0.1"), "93.184.216.34"),
        "the edge's own entry stays"
    );
    // The set is destroyed behind the helper's back (a reboot-like loss): the helper recreates
    // it empty and reports it; the edge re-sends its live entries.
    h.b.destroy_behind_back("picket4");
    assert!(
        wait_until(T, || h.has("picket4", Some("127.0.0.1"), "93.184.216.34")).await,
        "refilled after rules_repaired"
    );
    assert!(
        wait_until(T, || core.with(|s| s
            .logs
            .iter()
            .any(|l| l["t"] == "event" && l["kind"] == "rules_repaired")))
        .await
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_without_the_helper_replaces_one_with_it_only_after_an_empty_apply() {
    let h = helperkit::start();
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&config(&up, json!([{"name": "br0", "mode": "enforce"}])));
    let r = start(&d, tuning(&d, h.path.clone())).await;
    live(&r, &id).await;
    assert!(wait_until(T, || h.rules(WAN).iter().any(|x| x.contains("PICKET-FWD"))).await);
    let id2 = core.set_config(&config(&up, json!([])));
    core.changed(&id2);
    live(&r, &id2).await;
    assert!(
        !h.rules(WAN).iter().any(|x| x.contains("PICKET")),
        "the jumps went before the config did: {:#?}",
        h.rules(WAN)
    );
    assert!(!r.edge.fw.needed());
    // Without the helper nothing is added.
    let _ = udp_q(addr(&r), &Q::new("other.example", 1)).await;
    assert!(!h.has("picket4", Some("127.0.0.1"), "93.184.216.34"));
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_helper_holds_its_condition_and_dns_keeps_answering() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let id = core.set_config(&config(&up, json!([{"name": "br0", "mode": "enforce"}])));
    let mut t = tuning(&d, d.run.join("nobody-listens.sock"));
    t.firewall.seed_wait = Duration::from_millis(200);
    let r = start(&d, t).await;
    live(&r, &id).await;
    assert!(
        wait_until(T, || r.edge.conditions.is_set("helper_unreachable", None)).await,
        "helper_unreachable"
    );
    // The answer still goes out (after ack_wait), and the late ack is counted.
    let m = udp_q(addr(&r), &Q::new("www.example.com", 1)).await;
    assert_eq!(m.rcode, 0);
    assert!(r.edge.metrics.snapshot().fw_ack_late >= 1);
    r.shutdown().await;
}
