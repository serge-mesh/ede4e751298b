//! The helper socket end to end, over real Unix sockets with the fake backend
//! (edge-firewall.md §4 "Socket", "Watchdog"; edge.md §15).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use common::fx;
use picket_edge_helper::engine::{self, Cmd, Engine};
use picket_edge_helper::fake::FakeBackend;
use picket_edge_helper::fast::{self, FastHandle};
use picket_edge_helper::iptables::{Family, Platform, TableName};
use picket_edge_helper::server::{self, Server, ServerConfig, codec};
use picket_edge_helper::shared::Shared;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder};

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

struct H {
    path: PathBuf,
    b: Arc<FakeBackend>,
    fast: FastHandle,
    shared: Arc<Shared>,
    _dir: tempfile::TempDir,
    _stop: watch::Sender<bool>,
}

fn harness(cfg: ServerConfig) -> H {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("helper.sock");
    let b = Arc::new(FakeBackend::new());
    b.set_table(
        Family::V4,
        TableName::Filter,
        &fx("filter-block-all-reject.rules"),
    );
    b.set_table(
        Family::V6,
        TableName::Filter,
        &fx("filter6-block-all-reject.rules"),
    );
    let shared = Shared::new();
    let mut e = Engine::new(b.clone(), shared.clone(), Platform::Unifi);
    e.startup();
    let (etx, erx) = sync_channel::<Cmd>(16);
    std::thread::spawn(move || engine::run(e, erx));
    let fast = fast::spawn(b.clone(), shared.clone(), etx.clone()).expect("the fast worker starts");
    let l = server::bind(&path, None).unwrap();
    let l = tokio::net::UnixListener::from_std(l).unwrap();
    let (stop, rx) = watch::channel(false);
    let srv = Server::new(b.clone(), shared.clone(), etx, fast.clone(), cfg);
    tokio::spawn(srv.serve(l, rx));
    H {
        path,
        b,
        fast,
        shared,
        _dir: dir,
        _stop: stop,
    }
}

fn admin_cfg() -> ServerConfig {
    ServerConfig {
        admin_uid: me(),
        ..ServerConfig::default()
    }
}

struct Client {
    s: UnixStream,
    buf: BytesMut,
    id: u64,
}

impl Client {
    async fn connect(h: &H) -> Client {
        Client {
            s: UnixStream::connect(&h.path).await.unwrap(),
            buf: BytesMut::new(),
            id: 0,
        }
    }
    async fn send_raw(&mut self, payload: Vec<u8>) {
        let mut out = BytesMut::new();
        codec().encode(Bytes::from(payload), &mut out).unwrap();
        self.s.write_all(&out).await.unwrap();
    }
    async fn send(&mut self, kind: &str, data: Value) -> u64 {
        self.id += 1;
        let f = json!({"type": kind, "id": self.id, "data": data});
        self.send_raw(serde_json::to_vec(&f).unwrap()).await;
        self.id
    }
    /// The next frame, or `None` once the helper closed the connection.
    async fn recv(&mut self) -> Option<Value> {
        let mut c = codec();
        loop {
            if let Some(f) = c.decode(&mut self.buf).unwrap() {
                return Some(serde_json::from_slice(&f).unwrap());
            }
            match timeout(Duration::from_secs(10), self.s.read_buf(&mut self.buf))
                .await
                .expect("no answer")
            {
                Ok(0) | Err(_) => return None,
                Ok(_) => {}
            }
        }
    }
    /// Sends a request and returns its response, skipping events.
    async fn call(&mut self, kind: &str, data: Value) -> Value {
        let id = self.send(kind, data).await;
        loop {
            let f = self.recv().await.expect("connection closed");
            if f["id"] == id {
                return f;
            }
        }
    }
    async fn closed(&mut self) -> bool {
        matches!(timeout(Duration::from_secs(3), self.recv()).await, Ok(None))
    }
}

#[tokio::test]
async fn hello_subscribes_to_events() {
    let h = harness(ServerConfig {
        admin_conns: 4,
        ..admin_cfg()
    });
    let mut edge = Client::connect(&h).await;
    let r = edge.call("hello", json!({"proto_version": 1})).await;
    assert_eq!(r["type"], "hello");
    assert_eq!(r["data"]["proto_version"], 1);
    assert_eq!(r["data"]["helper_version"], picket_api::VERSION);
    // The CLI disables; the subscribed connection hears about it.
    let mut cli = Client::connect(&h).await;
    let r = cli.call("disable", Value::Null).await;
    assert_eq!(r["type"], "disable");
    assert_eq!(r["data"]["conditions"]["helper_disabled"], true);
    let ev = edge.recv().await.unwrap();
    assert_eq!(ev["type"], "conditions");
    assert!(ev.get("id").is_none());
    assert_eq!(ev["data"]["helper_disabled"], true);
    // A connection that opted out gets no events.
    let mut quiet = Client::connect(&h).await;
    quiet
        .call("hello", json!({"proto_version": 1, "events": false}))
        .await;
    cli.call("enable", json!({})).await;
    let ev = edge.recv().await.unwrap();
    assert_eq!(ev["data"]["helper_disabled"], false);
    let r = quiet.call("status", Value::Null).await;
    assert_eq!(r["type"], "status", "only the response, no event first");
}

#[tokio::test]
async fn ensure_delete_dump_status() {
    let h = harness(admin_cfg());
    let mut c = Client::connect(&h).await;
    let r = c
        .call(
            "ensure",
            json!({"entries": [
                {"set": "picket4", "src": "192.168.1.10", "dst": "93.184.216.34", "timeout_s": 0},
                {"set": "UBIOS_ADDRv4_br0", "dst": "1.1.1.1", "timeout_s": 60},
                {"set": "picket-g4", "dst": "1.1.1.1", "timeout_s": 4000000000u64},
            ]}),
        )
        .await;
    assert_eq!(r["type"], "ensure");
    assert_eq!(r["data"]["ok"], false);
    assert_eq!(
        r["data"]["failed"],
        json!([{"index": 1, "reason": "invalid_set"}])
    );
    let m = h.b.members("picket4");
    assert_eq!(m[0].1, Some(1), "timeout 0 clamped to 1");
    assert_eq!(
        h.b.members("picket-g4")[0].1,
        Some(2_147_483),
        "clamped to the kernel's maximum"
    );

    let r = c.call("dump", json!({"set": "picket-g4", "limit": 10})).await;
    assert_eq!(
        r["data"]["entries"],
        json!([{"dst": "1.1.1.1", "timeout_s": 2_147_483}])
    );
    assert!(r["data"].get("next_cursor").is_none());

    let r = c
        .call(
            "delete",
            json!({"entries": [{"set": "picket-g4", "dst": "1.1.1.1"}]}),
        )
        .await;
    assert_eq!(r["data"]["ok"], true);
    assert!(h.b.members("picket-g4").is_empty());

    let r = c.call("status", Value::Null).await;
    assert_eq!(r["data"]["rejects"], 0);
    assert_eq!(r["data"]["sets"].as_array().unwrap().len(), 4);
    assert_eq!(r["data"]["sets"][0]["name"], "picket4");
    assert_eq!(r["data"]["sets"][0]["entries"], 1);
    assert_eq!(r["data"]["sets"][0]["max"], 262_144);
}

#[tokio::test]
async fn bad_requests_get_errors() {
    let h = harness(admin_cfg());
    let mut c = Client::connect(&h).await;
    let r = c.call("frobnicate", json!({})).await;
    assert_eq!(r["type"], "error");
    assert_eq!(r["data"]["code"], "unknown_type");
    let r = c.call("dump", json!({"set": "picket-static4", "limit": 1})).await;
    assert_eq!(r["data"]["code"], "invalid");
    let r = c
        .call(
            "apply",
            json!({"interfaces": [{"name": "br0+", "mode": "enforce"}]}),
        )
        .await;
    assert_eq!(r["data"]["code"], "invalid");
    let many: Vec<Value> = (0..4097)
        .map(|_| json!({"set": "picket-g4", "dst": "1.1.1.1"}))
        .collect();
    let r = c.call("ensure", json!({"entries": many})).await;
    assert_eq!(r["data"]["code"], "invalid");
    let r = c.call("ensure", json!({"entries": "lots"})).await;
    assert_eq!(r["data"]["code"], "invalid");
    let r = c
        .call(
            "apply",
            json!({"interfaces": [{"name": "br0\n-A FORWARD -j ACCEPT", "mode": "enforce"}]}),
        )
        .await;
    assert_eq!(r["data"]["code"], "invalid");
    c.send_raw(b"{not json".to_vec()).await;
    let r = c.recv().await.unwrap();
    assert_eq!(r["data"]["code"], "invalid");
    // Still serving.
    assert_eq!(c.call("status", Value::Null).await["type"], "status");
}

#[tokio::test]
async fn peers_other_than_the_edge_and_root_are_refused() {
    let h = harness(ServerConfig {
        admin_uid: me().wrapping_add(1),
        edge_uid: None,
        ..ServerConfig::default()
    });
    let mut c = Client::connect(&h).await;
    c.send("status", Value::Null).await;
    assert!(c.closed().await);
}

#[tokio::test]
async fn connection_caps_per_user() {
    // The edge's own cap.
    let h = harness(ServerConfig {
        admin_uid: me().wrapping_add(1),
        edge_uid: Some(me()),
        edge_conns: 1,
        ..ServerConfig::default()
    });
    let mut a = Client::connect(&h).await;
    assert_eq!(a.call("status", Value::Null).await["type"], "status");
    let mut b = Client::connect(&h).await;
    b.send("status", Value::Null).await;
    assert!(b.closed().await, "over the edge's cap");
    drop(a);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c = Client::connect(&h).await;
    assert_eq!(
        c.call("status", Value::Null).await["type"],
        "status",
        "slot released"
    );
}

#[tokio::test]
async fn admin_slots_are_separate_from_the_edge_ones() {
    use picket_edge_helper::server::ServerConfig as C;
    // Root (here: the test's UID) has its own slots: the edge filling its cap can't lock it out.
    let h = harness(C {
        admin_uid: me(),
        edge_uid: Some(me().wrapping_add(7)),
        edge_conns: 0,
        admin_conns: 2,
        ..C::default()
    });
    let mut a = Client::connect(&h).await;
    let mut b = Client::connect(&h).await;
    assert_eq!(a.call("status", Value::Null).await["type"], "status");
    assert_eq!(b.call("status", Value::Null).await["type"], "status");
    let mut c = Client::connect(&h).await;
    c.send("status", Value::Null).await;
    assert!(c.closed().await);
}

#[tokio::test]
async fn socket_mode_is_0660() {
    use std::os::unix::fs::PermissionsExt;
    let h = harness(admin_cfg());
    let md = std::fs::metadata(&h.path).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o660);
    // A second bind replaces a stale socket but refuses to clobber anything else.
    let other = h.path.with_file_name("not-a-socket");
    std::fs::write(&other, b"x").unwrap();
    assert!(server::bind(&other, None).is_err());
}

#[tokio::test]
async fn slow_frames_are_cut_off() {
    let h = harness(ServerConfig {
        frame_deadline: Duration::from_millis(200),
        ..admin_cfg()
    });
    let mut c = Client::connect(&h).await;
    // A frame announcing 100 bytes that never completes.
    c.s.write_all(&[0, 0, 0, 100, b'{', b'"']).await.unwrap();
    assert!(c.closed().await);
    // Idle connections without a started frame stay open.
    let mut idle = Client::connect(&h).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(idle.call("status", Value::Null).await["type"], "status");
}

#[tokio::test]
async fn oversized_frames_close_the_connection() {
    let h = harness(admin_cfg());
    let mut c = Client::connect(&h).await;
    let n: u32 = 2 << 20;
    c.s.write_all(&n.to_be_bytes()).await.unwrap();
    assert!(c.closed().await);
}

#[tokio::test]
async fn ensure_never_waits_behind_a_held_restore() {
    let h = harness(admin_cfg());
    h.b.close_gate(); // iptables-restore now waits, as on the xtables lock
    let mut control = Client::connect(&h).await;
    let mut fast_conn = Client::connect(&h).await;
    let apply_id = control
        .send(
            "apply",
            json!({"interfaces": [{"name": "br0", "mode": "enforce"}], "static": [], "exempt": []}),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let t0 = std::time::Instant::now();
    let r = fast_conn
        .call(
            "ensure",
            json!({"entries": [{"set": "picket-g4", "dst": "9.9.9.9", "timeout_s": 60}]}),
        )
        .await;
    assert_eq!(r["data"]["ok"], true);
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    // A dump and a status on the fast connection don't wait for the engine either.
    assert_eq!(
        fast_conn
            .call("dump", json!({"set": "picket-g4", "limit": 5}))
            .await["type"],
        "dump"
    );
    h.b.open_gate();
    let r = loop {
        let f = control.recv().await.unwrap();
        if f["id"] == apply_id {
            break f;
        }
    };
    assert_eq!(r["type"], "apply");
    assert_eq!(r["data"]["ok"], true);
}

#[tokio::test]
async fn cli_disable_and_enable() {
    let h = harness(admin_cfg());
    let r = picket_edge_helper::cli::control(&h.path, "disable")
        .await
        .unwrap();
    assert!(r.conditions.helper_disabled);
    let r = picket_edge_helper::cli::control(&h.path, "enable").await.unwrap();
    assert!(!r.conditions.helper_disabled);
    // Refused peers get a clear error.
    let h2 = harness(ServerConfig {
        admin_uid: me().wrapping_add(1),
        ..ServerConfig::default()
    });
    let e = picket_edge_helper::cli::control(&h2.path, "disable")
        .await
        .unwrap_err();
    assert!(e.to_string().contains("closed the connection"), "{e}");
}

#[tokio::test]
async fn watchdog_probe_detects_a_stalled_fast_path() {
    let h = harness(admin_cfg());
    assert!(server::probe(&h.fast, Duration::from_secs(2)).await);
    h.b.probe_hang.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(!server::probe(&h.fast, Duration::from_millis(300)).await);
    h.b.probe_hang.store(false, std::sync::atomic::Ordering::SeqCst);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watchdog_is_not_fed_while_the_engine_thread_stalls() {
    // edge-firewall.md §4 "Watchdog", §5: a hung helper is restarted once its watchdog lapses.
    let h = harness(admin_cfg());
    let wait = Duration::from_secs(2);
    assert!(server::feed_watchdog(&h.fast, &h.shared, &*h.b, wait).await);
    // The next re-assert has a chain to repair, and its iptables-restore hangs (held here).
    h.b.close_gate();
    {
        let mut st = h.b.st();
        let t = st.tables.get_mut(&(Family::V4, TableName::Filter)).unwrap();
        t.chains
            .iter_mut()
            .find(|c| c.name == "PICKET-FWD")
            .unwrap()
            .rules
            .pop();
    }
    tokio::time::sleep(engine::REASSERT + Duration::from_millis(700)).await;
    // The fast path still answers, but no pass has finished for longer than ENGINE_STALL.
    h.b.advance(server::ENGINE_STALL + Duration::from_secs(1));
    assert!(server::probe(&h.fast, wait).await);
    assert!(!server::feed_watchdog(&h.fast, &h.shared, &*h.b, wait).await);
    // Still stuck a re-assert period later (an idle engine would have finished a pass by now).
    tokio::time::sleep(engine::REASSERT + Duration::from_millis(500)).await;
    assert!(!server::feed_watchdog(&h.fast, &h.shared, &*h.b, wait).await);
    // The engine thread gets going again: fed again once its pass ends.
    h.b.open_gate();
    let mut fed = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if server::feed_watchdog(&h.fast, &h.shared, &*h.b, wait).await {
            fed = true;
            break;
        }
    }
    assert!(fed);
}

#[tokio::test]
async fn disable_and_enable_need_root() {
    // The peer is the edge, not root: the emergency switch is the CLI's alone, so a (buggy or
    // compromised) edge can't lift an admin's `disable` or set one.
    let h = harness(ServerConfig {
        admin_uid: me().wrapping_add(1),
        edge_uid: Some(me()),
        ..ServerConfig::default()
    });
    let mut c = Client::connect(&h).await;
    for k in ["disable", "enable"] {
        let r = c.call(k, json!({})).await;
        assert_eq!(r["type"], "error", "{k}");
        assert_eq!(r["data"]["code"], "forbidden", "{k}");
    }
    let r = c.call("status", Value::Null).await;
    assert_eq!(r["data"]["conditions"]["helper_disabled"], false);
}

#[tokio::test]
async fn ensure_into_a_full_set_fails_and_sends_set_full() {
    let h = harness(admin_cfg());
    let mut events = Client::connect(&h).await;
    events.call("hello", json!({"proto_version": 1})).await;
    // Shrink picket-g4 to two entries and fill it.
    h.b.st().sets.get_mut("picket-g4").unwrap().maxelem = 2;
    let mut c = Client::connect(&h).await;
    let r = c
        .call(
            "ensure",
            json!({"entries": [
                {"set": "picket-g4", "dst": "203.0.113.1", "timeout_s": 60},
                {"set": "picket-g4", "dst": "203.0.113.2", "timeout_s": 60},
                {"set": "picket-g4", "dst": "203.0.113.3", "timeout_s": 60},
            ]}),
        )
        .await;
    assert_eq!(r["data"]["ok"], false);
    assert_eq!(r["data"]["failed"], json!([{"index": 2, "reason": "set_full"}]));
    let ev = loop {
        let f = events.recv().await.expect("set_full event");
        if f["type"] == "set_full" {
            break f;
        }
    };
    assert_eq!(ev["data"]["set"], "picket-g4");
    assert!(ev.get("id").is_none());
}

#[tokio::test]
async fn dump_pages_a_large_set_within_the_frame_limit() {
    use picket_edge_helper::backend::{Backend, SetOp};
    use picket_edge_helper::ipset::Elem;
    let h = harness(admin_cfg());
    // The widest entries there are: IPv6 pairs with full-length addresses, the longest timeout.
    let ops: Vec<SetOp> = (0..10_000u32)
        .map(|i| {
            let src: std::net::Ipv6Addr = format!("fd12:3456:789a:ffff:ffff:ffff:ffff:{:x}", i)
                .parse()
                .unwrap();
            let dst: std::net::Ipv6Addr = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
            SetOp {
                set: "picket6",
                elem: Elem::host_pair(src.into(), dst.into()),
                timeout: Some(picket_api::helper::MAX_TIMEOUT_S),
            }
        })
        .collect();
    assert!(h.b.ipset_add(&ops).iter().all(|r| r.is_ok()));
    let mut c = Client::connect(&h).await;
    let mut cursor: Option<String> = None;
    let mut pages = Vec::new();
    loop {
        let mut req = json!({"set": "picket6", "limit": 4096});
        if let Some(cur) = &cursor {
            req["cursor"] = json!(cur);
        }
        let r = c.call("dump", req).await;
        assert_eq!(r["type"], "dump", "{r}");
        assert!(serde_json::to_vec(&r).unwrap().len() < picket_api::helper::MAX_FRAME);
        pages.push(r["data"]["entries"].as_array().unwrap().len());
        match r["data"]["next_cursor"].as_str() {
            Some(n) => cursor = Some(n.to_string()),
            None => break,
        }
    }
    assert_eq!(pages, vec![4096, 4096, 1808]);
    // The finished dump's cursor is gone.
    let r = c
        .call(
            "dump",
            json!({"set": "picket6", "limit": 10, "cursor": cursor.unwrap()}),
        )
        .await;
    assert_eq!(r["data"]["code"], "cursor_expired");
}
