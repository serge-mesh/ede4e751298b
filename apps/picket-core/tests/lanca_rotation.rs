//! LAN CA rotation (core.md §11 `lanca.zones`, security.md §2; `lanca::rotation`): a zones change
//! in `PUT settings` makes a new root, committed with the settings; the real edge re-issues its
//! managed listener certificate (edge.md §5) while core's DNSSEC validator keeps reaching its DoH
//! listener (core.md §8); the previous root is kept while an edge serves a certificate from it,
//! and blocks another rotation (`409`) until then; a stop at any step is recovered at start; a
//! refused request changes nothing; a restore with other zones points to rotating first.

use crate::common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::edge::FakeEdge;
use hickory_net::proto::rr::RecordType;
use jiff::Timestamp;
use picket_core::config::Actor;
use picket_core::dnssec::validator::ChainResolver;
use picket_core::lanca::rotation::{STEPS, Step};
use picket_core::state::SharedState;
use picket_edge::service::{self, Options, Tuning};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------------------------
// Helpers

/// A UI API request, over HTTPS when the web port serves the managed certificate (the test
/// client accepts it without trusting it).
fn ui(c: &common::Core, method: Method, path: &str) -> reqwest::RequestBuilder {
    let scheme = if c.state.settings().web.tls == picket_core::settings::WebTls::Off {
        "http"
    } else {
        "https"
    };
    common::client()
        .request(method, format!("{}/api/ui/v1{path}", c.base(scheme)))
        .basic_auth("admin", Some(&c.init.password))
        .header("X-Picket-UI", "1")
}

async fn get(c: &common::Core, path: &str) -> (StatusCode, Value) {
    let r = ui(c, Method::GET, path).send().await.unwrap();
    let st = r.status();
    (st, r.json().await.unwrap_or(Value::Null))
}

async fn put_entity(c: &common::Core, kind: &str, body: Value) {
    let r = ui(c, Method::POST, &format!("/{kind}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
}

/// The UI events of `kinds` until `done` holds for those seen, within 60 s (other events are
/// skipped).
async fn events_until(
    rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>,
    kinds: &[&str],
    done: impl Fn(&[(String, Value)]) -> bool,
) -> Vec<(String, Value)> {
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !done(&seen) {
            match rx.recv().await {
                Ok(e) if kinds.contains(&e.kind.as_str()) => seen.push((e.kind, e.data)),
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("events closed: {e}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out; saw {seen:?}"));
    seen
}

/// Waits (generously: CI runs as root on a slower shared machine) until `f` holds.
async fn eventually<F, Fut>(mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let end = tokio::time::Instant::now() + Duration::from_secs(45);
    while tokio::time::Instant::now() < end {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f().await
}

struct EdgeDirs {
    _tmp: tempfile::TempDir,
    config: PathBuf,
    data: PathBuf,
    run: PathBuf,
    result: PathBuf,
}

fn edge_dirs() -> EdgeDirs {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    EdgeDirs {
        config: root.join("dev/edge.json"),
        data: root.join("dev/edge"),
        run: root.join("dev/run"),
        result: root.join("bin/update-result.json"),
        _tmp: tmp,
    }
}

fn edge_tuning(d: &EdgeDirs) -> Tuning {
    let mut t = Tuning {
        platform: Some(picket_edge::paths::HostPlatform::Debian),
        clock: Some(picket_edge::clock::Clock::fixed(true)),
        update_result: Some(d.result.clone()),
        service: Some(false),
        firmware_file: d.data.join("no-such-version-file"),
        import_every: Duration::from_millis(200),
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
    t.dns.rebind_every = Duration::from_millis(200);
    t.dns.certs_every = Duration::from_millis(200);
    t.dns.csr_backoff = (Duration::from_millis(50), Duration::from_millis(300));
    t
}

/// Starts the real edge against `c` (its data in `d`, so a restart keeps its key and
/// certificates).
async fn start_edge(c: &common::Core, d: &EdgeDirs) -> service::Running {
    std::fs::create_dir_all(d.config.parent().unwrap()).unwrap();
    std::fs::write(
        &d.config,
        serde_json::to_vec_pretty(&json!({
            "core_url": format!("https://127.0.0.1:{}", c.info.edge.port()),
            "core_key": c.info.fingerprint,
            "updates_enabled": false,
        }))
        .unwrap(),
    )
    .unwrap();
    service::start(
        Options {
            config: Some(d.config.clone()),
            data_dir: Some(d.data.clone()),
            runtime_dir: d.run.clone(),
        },
        edge_tuning(d),
        |_| {},
    )
    .await
    .unwrap()
}

/// The real edge, approved under `name`, with a managed DoH listener (`lan-doh`, `dns.home.arpa`)
/// on a free loopback port. Returns the edge and its id.
async fn edge_with_doh(c: &common::Core, d: &EdgeDirs, name: &str) -> (service::Running, String) {
    let r = start_edge(c, d).await;
    let fp = r.edge.identity.fingerprint.clone();
    assert!(
        eventually(|| async {
            picket_core::edges::list_pending(&c.state.db)
                .await
                .unwrap()
                .iter()
                .any(|p| p.key == fp)
        })
        .await,
        "the edge's key shows up as pending"
    );
    let id = picket_core::edges::approve_pending(
        &c.state.config,
        &fp,
        picket_core::config::model::EdgeDef {
            name: name.into(),
            ..Default::default()
        },
        Actor::cli(),
    )
    .await
    .unwrap()
    .id;
    let port = common::free_port();
    put_entity(
        c,
        "listeners",
        json!({"id": "lan-doh", "name": "lan-doh", "proto": "doh", "bind": format!("127.0.0.1:{port}"),
               "tls": {"managed": "dns.home.arpa"}, "edges": [id]}),
    )
    .await;
    (r, id)
}

/// True when the real edge's listener `id` is bound on `port`.
fn listening_on(r: &service::Running, id: &str, port: u16) -> bool {
    r.edge.dns.listeners.status().iter().any(|s| {
        s.id == id
            && s.local
                .as_ref()
                .is_some_and(|l| l.iter().any(|a| a.port() == port))
    })
}

/// The root that issued the real edge's `lan-doh` certificate.
fn edge_root(r: &service::Running) -> Option<String> {
    r.edge
        .dns
        .certs
        .slot("lan-doh")
        .and_then(|s| s.info().root.clone())
}

/// core.md §8: the validator's own query over DoH to the edge's listener (by IP with the
/// listener's TLS name, trusting the LAN CA's roots). The edge answers its managed name itself.
async fn validator_reaches(state: &SharedState) -> Result<(), String> {
    let r = picket_core::dnssec::resolver::EdgeDoh::new(Arc::downgrade(state), &Default::default());
    r.query(&common::zones::name("dns.home.arpa."), RecordType::A)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn put_settings(c: &common::Core, patch: Value) -> (StatusCode, Value) {
    let r = ui(c, Method::PUT, "/settings").json(&patch).send().await.unwrap();
    let status = r.status();
    let text = r.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(json!(text)))
}

/// `PUT settings` asking for a rotation: the patch with `lanca.rotate_from` naming the current
/// root, which a `lanca.zones` change needs (an explicit rotation).
async fn rotate(c: &common::Core, mut patch: Value) -> (StatusCode, Value) {
    let fp = c.state.lanca.load().fingerprint();
    match patch.get_mut("lanca").and_then(Value::as_object_mut) {
        Some(l) => {
            l.insert("rotate_from".into(), json!(fp));
        }
        None => patch["lanca.rotate_from"] = json!(fp),
    }
    put_settings(c, patch).await
}

/// The staging directories left in `lanca/` (`next-<hex>`, module docs of `lanca::rotation`).
fn staging_dirs(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir.join("lanca"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("next"))
        .collect()
}

fn file_fingerprint(dir: &Path) -> String {
    let pem = std::fs::read_to_string(dir.join("lanca/ca.crt")).unwrap();
    let der = picket_core::identity::pem_to_der(&pem, "CERTIFICATE").unwrap();
    picket_api::ids::cert_fingerprint(&der)
}

async fn db_i64(state: &SharedState, sql: &'static str) -> i64 {
    state
        .db
        .read(move |c| Ok::<_, anyhow::Error>(c.query_row(sql, [], |r| r.get(0))?))
        .await
        .unwrap()
}

async fn db_text(state: &SharedState, sql: &'static str) -> Option<String> {
    state
        .db
        .read(move |c| {
            use rusqlite::OptionalExtension as _;
            Ok::<_, anyhow::Error>(c.query_row(sql, [], |r| r.get(0)).optional()?)
        })
        .await
        .unwrap()
}

/// Stops `c` and starts a core on a snapshot of its data directory, as after a crash.
async fn restart(c: common::Core) -> (tempfile::TempDir, SharedState, CancellationToken) {
    restart_with(c, true).await
}

/// [`restart`], with the restarted core's clock pinned synchronised or not.
async fn restart_with(
    c: common::Core,
    clock_synced: bool,
) -> (tempfile::TempDir, SharedState, CancellationToken) {
    c.stop.cancel();
    let copy = tempfile::tempdir().unwrap();
    common::snapshot_dir(c.dir.path(), copy.path());
    let stop = CancellationToken::new();
    let opts = picket_core::run::StartOptions {
        release_dir: PathBuf::from("/nonexistent/picket-core/edge"),
        any_port: true,
        clock_synced: Some(clock_synced),
        disk_watch: false,
        ..Default::default()
    };
    let (state, _) = picket_core::run::start_with(copy.path(), stop.clone(), opts)
        .await
        .unwrap();
    (copy, state, stop)
}

// ---------------------------------------------------------------------------------------------
// Tests

/// The whole rotation with the real edge: the new root is committed with the settings, the edge
/// re-issues its listener certificate from it, core's validator reaches the edge's DoH listener
/// throughout (trusting both roots meanwhile), the previous root is dropped once unused, and the
/// web certificate comes from the new root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rotation_reaches_the_real_edge_and_the_validator_keeps_reaching_it() {
    let c = common::start_core(Some(json!({"dnssec": {"source_ips": ["127.0.0.1/32"]}}))).await;
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let d = edge_dirs();
    let (edge, id) = edge_with_doh(&c, &d, "ucg").await;
    let old = c.state.lanca.load().fingerprint();
    assert!(
        eventually(|| async { edge_root(&edge).as_deref() == Some(old.as_str()) }).await,
        "the edge serves a certificate from the first root"
    );
    let mut reached = false;
    for _ in 0..50 {
        if validator_reaches(&c.state).await.is_ok() {
            reached = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(reached, "{:?}", validator_reaches(&c.state).await);
    let (_, before) = get(&c, "/settings").await;
    assert_eq!(before["lanca"]["fingerprint"], json!(old));
    assert_eq!(before["lanca"]["can_rotate"], json!(true));
    assert_eq!(before["read_only"], json!([]));
    let mut events = c.state.events.subscribe();

    // The rotation, with the rest of the patch.
    let (status, body) = rotate(
        &c,
        json!({"lanca": {"zones": ["home.arpa", "lan.example"]}, "dnssec": {"max_per_minute": 90}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new = body["lanca"]["fingerprint"].as_str().unwrap().to_string();
    assert_ne!(new, old);
    assert_eq!(body["lanca"]["zones"], json!(["home.arpa", "lan.example"]));
    assert_eq!(
        body["settings"]["lanca"]["zones"],
        json!(["home.arpa", "lan.example"])
    );
    assert_eq!(body["settings"]["dnssec"]["max_per_minute"], json!(90));
    assert_eq!(
        file_fingerprint(c.dir.path()),
        new,
        "lanca/ca.crt is the new root"
    );
    assert!(staging_dirs(c.dir.path()).is_empty());
    // The validator trusts both roots until the edge has re-issued: it reaches the edge whichever
    // certificate the edge serves at this moment.
    validator_reaches(&c.state).await.unwrap();

    // The edge's config object names the new root; the edge re-issues from it.
    assert!(
        eventually(|| async {
            c.state
                .edges
                .publisher
                .current(&id)
                .is_some_and(|p| p.config.lanca_root.as_deref() == Some(new.as_str()))
        })
        .await
    );
    assert!(
        eventually(|| async { edge_root(&edge).as_deref() == Some(new.as_str()) }).await,
        "the edge replaces its certificate from the old root"
    );
    // The old root is dropped once no edge uses it; the validator still reaches the edge, now
    // trusting the new root alone.
    assert!(
        eventually(|| async { c.state.lanca.load().previous.is_empty() }).await,
        "the previous root goes once unused"
    );
    assert_eq!(
        c.state
            .lanca
            .load()
            .trust_pem()
            .matches("BEGIN CERTIFICATE")
            .count(),
        1
    );
    validator_reaches(&c.state).await.unwrap();
    assert_eq!(
        db_i64(&c.state, "SELECT count(*) FROM lanca_roots").await,
        1,
        "only the current root is kept"
    );
    let (_, after) = get(&c, "/settings").await;
    assert_eq!(after["lanca"]["previous"], json!([]));
    assert_eq!(after["lanca"]["can_rotate"], json!(true));
    // F4, F9 (api.md §7 UI events): `lanca` `rotated` names the new root and the one it replaced;
    // the edge's move to the new root is a `lanca_served` event naming it; `previous_dropped`
    // names the dropped root once the rotation is done. No polling needed.
    let dropped = |s: &[(String, Value)]| {
        s.iter()
            .any(|(k, v)| k == "lanca" && v["event"] == "previous_dropped")
    };
    let served = |s: &[(String, Value)]| {
        s.iter().any(|(k, v)| {
            k == "lanca_served" && v["edges"].as_array().is_some_and(|e| e.contains(&json!(id)))
        })
    };
    let seen = events_until(&mut events, &["lanca", "lanca_served"], |s| {
        dropped(s) && served(s)
    })
    .await;
    let rotated = seen
        .iter()
        .find(|(k, v)| k == "lanca" && v["event"] == "rotated")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("no rotated event: {seen:?}"));
    assert_eq!(rotated["root"], json!(new), "{rotated}");
    assert_eq!(rotated["previous"], json!(old), "{rotated}");
    assert_eq!(rotated["current"], json!(new), "{rotated}");
    let (_, d) = seen
        .iter()
        .find(|(k, v)| k == "lanca" && v["event"] == "previous_dropped")
        .unwrap();
    assert_eq!(d["root"], json!(old), "{d}");
    assert_eq!(d["previous"], json!(old), "{d}");
    assert_eq!(d["current"], json!(new), "{d}");
    let (_, s) = seen.iter().find(|(k, _)| k == "lanca_served").unwrap();
    assert!(s["reports"].as_u64().unwrap() >= 1, "{s}");
    // The web certificate comes from the new root, and the download is the new root.
    let served = c
        .state
        .web_cert
        .get()
        .expect("managed web certificate")
        .0
        .load_full();
    assert!(c.state.lanca.load().signed(served.cert[0].as_ref()));
    let der = common::client()
        .get(format!("{}/lanca/ca.crt", c.base("https")))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(picket_api::ids::cert_fingerprint(&der), new);
    // The journal records the rotation.
    assert_eq!(
        db_i64(
            &c.state,
            "SELECT count(*) FROM config_changes WHERE entity = 'settings' AND entity_id = 'lanca'"
        )
        .await,
        1
    );
    edge.shutdown().await;
}

/// The previous root stays in use while an edge that was offline at the rotation still serves a
/// certificate from it: core keeps trusting it, the settings say which edge, a second rotation is
/// refused (409 naming the edge) and changes nothing; once the edge reconnects it re-issues, the
/// root goes, and the second rotation passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offline_edge_reissues_on_reconnect_and_blocks_a_second_rotation_until_then() {
    let c = common::start_core(Some(
        json!({"web": {"tls": "off"}, "dnssec": {"source_ips": ["127.0.0.1/32"]}}),
    ))
    .await;
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let d = edge_dirs();
    let (edge, id) = edge_with_doh(&c, &d, "ucg").await;
    let old = c.state.lanca.load().fingerprint();
    assert!(eventually(|| async { edge_root(&edge).as_deref() == Some(old.as_str()) }).await);
    // The edge goes offline.
    edge.shutdown().await;
    assert!(eventually(|| async { c.state.edges.hub.session(&id).is_none() }).await);

    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa", "lan.example"]}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new = body["lanca"]["fingerprint"].as_str().unwrap().to_string();
    // The old root is still in use by the offline edge: shown, and still trusted.
    let prev = &body["lanca"]["previous"];
    assert_eq!(prev.as_array().unwrap().len(), 1, "{body}");
    assert_eq!(prev[0]["fingerprint"], json!(old));
    assert_eq!(prev[0]["zones"], json!(["home.arpa"]));
    assert_eq!(prev[0]["edges"][0]["edge_name"], json!("ucg"));
    assert_eq!(prev[0]["edges"][0]["listeners"], json!(["lan-doh"]));
    assert_eq!(prev[0]["edges"][0]["online"], json!(false));
    assert_eq!(body["lanca"]["can_rotate"], json!(false));
    // A prune pass changes nothing while it is in use.
    picket_core::lanca::rotation::prune(&c.state).await.unwrap();
    assert_eq!(c.state.lanca.load().previous.len(), 1);
    assert!(
        c.state
            .lanca
            .load()
            .trust_pem()
            .contains(&old_pem(&c.state, &old))
    );

    // A second rotation waits: 409 naming the edge, and nothing changes.
    let (status, body) = rotate(
        &c,
        json!({"lanca": {"zones": ["lan.example"]}, "dnssec": {"max_per_minute": 90}}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // F1: `conflict`, apart from `lanca_root_changed` (the UI waits instead of reloading).
    assert_eq!(body["error"]["code"], "conflict", "{body}");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ucg") && msg.contains("lan-doh") && msg.contains("offline"),
        "{msg}"
    );
    assert_eq!(c.state.lanca.load().fingerprint(), new);
    assert_eq!(file_fingerprint(c.dir.path()), new);
    assert!(staging_dirs(c.dir.path()).is_empty());
    let (_, s) = get(&c, "/settings").await;
    assert_eq!(
        s["settings"]["lanca"]["zones"],
        json!(["home.arpa", "lan.example"])
    );
    assert_eq!(s["settings"]["dnssec"]["max_per_minute"], json!(120));

    // The edge reconnects: it fetches the config naming the new root and re-issues. (Its listener
    // moves to another port meanwhile: the stopped edge's DNS tasks live on in this test process.)
    let port = common::free_port();
    let r = ui(&c, Method::PUT, "/listeners/lan-doh")
        .json(
            &json!({"id": "lan-doh", "name": "lan-doh", "proto": "doh", "bind": format!("127.0.0.1:{port}"),
                      "tls": {"managed": "dns.home.arpa"}, "edges": [id]}),
        )
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    let edge = start_edge(&c, &d).await;
    assert!(
        eventually(|| async { edge_root(&edge).as_deref() == Some(new.as_str()) }).await,
        "the reconnected edge re-issues from the new root"
    );
    assert!(eventually(|| async { c.state.lanca.load().previous.is_empty() }).await);
    let (_, s) = get(&c, "/settings").await;
    assert_eq!(s["lanca"]["can_rotate"], json!(true));
    // The listener binds its new port on its own schedule: the edge re-issues and reports the
    // certificate (and core drops the old root) without waiting for the bind (edge.md §5: the
    // certificate task and the listener task are apart; a failed bind is retried). Core's
    // validator reaches the listener once it is bound.
    assert!(
        eventually(|| async { listening_on(&edge, "lan-doh", port) }).await,
        "the reconnected edge binds its listener's new port"
    );
    validator_reaches(&c.state).await.unwrap();
    // Another rotation may start now. One that would orphan the listener's name is refused for
    // that, naming it (core.md §2); narrowing back to its zone passes.
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["lan.example"]}})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("dns.home.arpa (listener lan-doh)"),
        "{body}"
    );
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa"]}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["lanca"]["fingerprint"], json!(new));
    edge.shutdown().await;
}

fn old_pem(state: &SharedState, fp: &str) -> String {
    state
        .lanca
        .load()
        .previous
        .iter()
        .find(|p| p.fingerprint == fp)
        .map(|p| p.cert_pem.trim().to_string())
        .unwrap_or_default()
}

/// A refused zones change changes nothing: not the root, the files, the roots table, the
/// settings (the rest of the patch included) nor the journal. A rotation is asked for explicitly
/// (`lanca.rotate_from` naming the current root): other zones without it, or with a root that is
/// no longer current (an old tab's merged form), are refused too.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_rotation_changes_nothing() {
    let c = common::start_core(Some(json!({"web": {"tls": "off", "names": ["core.home.arpa"]}}))).await;
    let edge = FakeEdge::registered(&c, "e1").await;
    put_entity(
        &c,
        "listeners",
        json!({"id": "lan-dot", "name": "lan-dot", "proto": "dot", "bind": "192.168.1.1:853",
               "tls": {"managed": "dns.home.arpa"}, "edges": [edge.id]}),
    )
    .await;
    let fp = c.state.lanca.load().fingerprint();
    let journal = db_i64(&c.state, "SELECT count(*) FROM config_changes").await;
    let stale = picket_api::ids::cert_fingerprint(b"an older root");
    let unprocessable = StatusCode::UNPROCESSABLE_ENTITY;
    for (explicit, patch, want, needle) in [
        // The names in use would be orphaned (core.md §2).
        (
            true,
            json!({"lanca": {"zones": ["lan.example"]}, "dnssec": {"max_per_minute": 90}}),
            unprocessable,
            "dns.home.arpa (listener lan-dot)",
        ),
        (
            true,
            json!({"lanca": {"zones": ["lan.example"]}}),
            unprocessable,
            "core.home.arpa (web.names)",
        ),
        // web.names in the same patch, outside the new zones.
        (
            true,
            json!({"lanca": {"zones": ["home.arpa", "lan.example"]}, "web": {"names": ["core.other.example"]}}),
            unprocessable,
            "core.other.example",
        ),
        // The rest of the patch is invalid.
        (
            true,
            json!({"lanca": {"zones": ["home.arpa", "lan.example"]}, "dnssec": {"max_per_minute": 0}}),
            unprocessable,
            "max_per_minute",
        ),
        // Not zones a LAN CA may hold.
        (
            true,
            json!({"lanca.zones": ["com"]}),
            unprocessable,
            "public suffix",
        ),
        (
            true,
            json!({"lanca": {"zones": ["not a name"]}}),
            unprocessable,
            "DNS name",
        ),
        (
            true,
            json!({"lanca": {"zones": "home.arpa"}}),
            unprocessable,
            "list",
        ),
        // Not asked for: other zones without lanca.rotate_from (an old tab's "keep my changes"
        // merging the zones it loaded), in either form.
        (
            false,
            json!({"lanca": {"zones": ["home.arpa", "lan.example"]}, "dnssec": {"max_per_minute": 90}}),
            unprocessable,
            "lanca.rotate_from",
        ),
        (
            false,
            json!({"lanca.zones": ["home.arpa", "lan.example"]}),
            unprocessable,
            "lanca.rotate_from",
        ),
        (
            false,
            json!({"lanca": {"zones": ["home.arpa", "lan.example"], "rotate_from": 7}}),
            unprocessable,
            "fingerprint",
        ),
        // F6: null is the same as leaving it out (the schema's type is string or null).
        (
            false,
            json!({"lanca": {"zones": ["home.arpa", "lan.example"], "rotate_from": null}}),
            unprocessable,
            "lanca.rotate_from",
        ),
        // Asked for from a root that is no longer the current one.
        (
            false,
            json!({"lanca": {"zones": ["home.arpa", "lan.example"], "rotate_from": stale}, "dnssec": {"max_per_minute": 90}}),
            StatusCode::CONFLICT,
            "another change replaced it",
        ),
    ] {
        let (status, body) = if explicit {
            rotate(&c, patch.clone()).await
        } else {
            put_settings(&c, patch.clone()).await
        };
        assert_eq!(status, want, "{patch}: {body}");
        assert!(body.to_string().contains(needle), "{patch}: {body}");
        if want == StatusCode::CONFLICT {
            // F1: a replaced root has its own code, apart from a previous root still in use.
            assert_eq!(body["error"]["code"], "lanca_root_changed", "{patch}: {body}");
        }
        assert_eq!(c.state.lanca.load().fingerprint(), fp, "{patch}");
        assert_eq!(file_fingerprint(c.dir.path()), fp, "{patch}");
        assert!(staging_dirs(c.dir.path()).is_empty(), "{patch}");
        assert_eq!(db_i64(&c.state, "SELECT count(*) FROM lanca_roots").await, 1);
        let (_, s) = get(&c, "/settings").await;
        assert_eq!(s["settings"]["lanca"]["zones"], json!(["home.arpa"]), "{patch}");
        assert_eq!(s["settings"]["dnssec"]["max_per_minute"], json!(120), "{patch}");
        assert_eq!(
            s["settings"]["web"]["names"],
            json!(["core.home.arpa"]),
            "{patch}"
        );
        assert_eq!(
            db_i64(&c.state, "SELECT count(*) FROM config_changes").await,
            journal,
            "{patch}"
        );
    }
    // The same zones, in another order and case, are no change: the rest of the patch applies
    // (a rotate_from, stale, null or not, is then ignored).
    let (status, body) = put_settings(
        &c,
        json!({"lanca": {"zones": ["Home.Arpa."], "rotate_from": null}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = put_settings(
        &c,
        json!({"lanca": {"zones": ["Home.Arpa."], "rotate_from": stale}, "dnssec": {"max_per_minute": 90}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lanca"]["fingerprint"], json!(fp));
    assert_eq!(body["settings"]["dnssec"]["max_per_minute"], json!(90));
}

/// A stop at each step of a rotation (module docs of `lanca::rotation`) is recovered at start: the
/// old root (stopped before the commit) or the new one (after it), consistently in the files,
/// `lanca_roots`, `lanca.zones` and the edges' config objects, with no staged root left and the
/// web certificate from that root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_at_each_step_of_a_rotation_is_recovered_at_start() {
    for &step in STEPS {
        let c = common::start_core(None).await; // managed web TLS
        let old = c.state.lanca.load().fingerprint();
        c.state.lanca_rt.fail_at(Some(step));
        let (status, body) = rotate(&c, json!({"lanca": {"zones": ["lan.example"]}})).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{step:?}: {body}");
        let committed = !matches!(step, Step::KeyStaged | Step::Staged);
        let (dir, state, stop) = restart(c).await;
        let fp = state.lanca.load().fingerprint();
        let want_zones: Vec<String> = if committed {
            vec!["lan.example".into()]
        } else {
            vec!["home.arpa".into()]
        };
        if committed {
            assert_ne!(fp, old, "{step:?}: the committed root applies");
        } else {
            assert_eq!(fp, old, "{step:?}: the rotation never committed");
        }
        assert_eq!(state.lanca.load().zones(), want_zones.as_slice(), "{step:?}");
        assert_eq!(state.settings().lanca.zones, want_zones, "{step:?}");
        assert_eq!(file_fingerprint(dir.path()), fp, "{step:?}");
        assert!(staging_dirs(dir.path()).is_empty(), "{step:?}");
        assert_eq!(
            db_text(
                &state,
                "SELECT fingerprint FROM lanca_roots WHERE retired_at IS NULL"
            )
            .await,
            Some(fp.clone()),
            "{step:?}"
        );
        // The web certificate is the current root's (re-issued at start when needed).
        let served = state
            .web_cert
            .get()
            .expect("managed web certificate")
            .0
            .load_full();
        assert!(state.lanca.load().signed(served.cert[0].as_ref()), "{step:?}");
        // An edge's config object names the current root, and its CSR is signed by it.
        let id = picket_core::edges::add(
            &state.config,
            picket_core::config::model::EdgeDef {
                name: "e1".into(),
                key: picket_api::ids::fingerprint_spki(b"e1"),
                ..Default::default()
            },
            Actor::cli(),
        )
        .await
        .unwrap()
        .id;
        assert!(
            eventually(|| async {
                state
                    .edges
                    .publisher
                    .current(&id)
                    .is_some_and(|p| p.config.lanca_root.as_deref() == Some(fp.as_str()))
            })
            .await,
            "{step:?}"
        );
        stop.cancel();
    }
}

/// core.md §2: a document whose `lanca.zones` differ is refused before anything changes, and the
/// message says to rotate first.
#[tokio::test(flavor = "multi_thread")]
async fn a_restore_with_other_zones_points_to_rotating_first() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let r = ui(&c, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let mut doc: Value = r.json().await.unwrap();
    doc["configuration"]["settings"]["lanca.zones"] = json!(["lan.example"]);
    let r = ui(&c, Method::PUT, "/config/export")
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = r.text().await.unwrap();
    assert!(
        body.contains("lan.example") && body.contains("change lanca.zones") && body.contains("rotation"),
        "{body}"
    );
}

// ---------------------------------------------------------------------------------------------
// Review round 1

/// The root staged in `lanca/` by a rotation (whatever the staging directory's name).
fn staged_root(dir: &Path) -> Option<(String, String)> {
    staging_dirs(dir).into_iter().find_map(|n| {
        let pem = std::fs::read_to_string(dir.join("lanca").join(&n).join("ca.crt")).ok()?;
        let der = picket_core::identity::pem_to_der(&pem, "CERTIFICATE").ok()?;
        Some((n, picket_api::ids::cert_fingerprint(&der)))
    })
}

/// R1 (module docs of `lanca::rotation`, A rotation): a caller that goes away while its rotation
/// waits for the writer drops only its wait. The rotation keeps its lock and its staged root to
/// the end, so a second rotation can't replace what the first stages; the first commits and puts
/// its own root in place; runtime, files, `lanca_roots` and the settings name the same root, and
/// a start recovers that root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rotation_outlives_its_caller_and_installs_only_its_own_root() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    common::settled(&c).await;
    let fp0 = c.state.lanca.load().fingerprint();
    // The writer is busy: the first rotation's transaction waits behind this.
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let db = c.state.db.clone();
    let barrier = tokio::spawn(async move {
        db.write(move |_| {
            let _ = entered_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(60));
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap()
    });
    entered_rx.await.unwrap();
    let (st, from) = (c.state.clone(), fp0.clone());
    let first = tokio::spawn(async move {
        picket_core::lanca::rotation::rotate(
            &st,
            vec!["home.arpa".into(), "a.example".into()],
            json!({}),
            from,
            Actor::cli(),
        )
        .await
    });
    assert!(
        eventually(|| async { staged_root(c.dir.path()).is_some() && c.state.db.pending_writes() > 0 }).await
    );
    let (_, first_fp) = staged_root(c.dir.path()).unwrap();
    // The caller goes away (a closed tab).
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let (st, from) = (c.state.clone(), fp0.clone());
    let second = tokio::spawn(async move {
        picket_core::lanca::rotation::rotate(
            &st,
            vec!["home.arpa".into(), "b.example".into()],
            json!({}),
            from,
            Actor::cli(),
        )
        .await
    });
    // Give the second rotation every chance to stage and queue its transaction meanwhile.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while c.state.db.pending_writes() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    release_tx.send(()).unwrap();
    barrier.await.unwrap();
    // The second was asked for from the root the first replaced.
    let refused = second.await.unwrap().unwrap_err().to_string();
    assert!(
        refused.to_lowercase().contains("reload the settings"),
        "{refused}"
    );
    // The first rotation finished without its caller, with its own root throughout.
    assert!(eventually(|| async { c.state.lanca.load().fingerprint() == first_fp }).await);
    let ca = c.state.lanca.load_full();
    assert_eq!(ca.zones(), ["home.arpa", "a.example"]);
    assert_eq!(
        file_fingerprint(c.dir.path()),
        first_fp,
        "lanca/ca.crt is the committed root"
    );
    assert_eq!(
        picket_core::lanca::LanCa::load(&c.dir.path().join("lanca"))
            .unwrap()
            .fingerprint(),
        first_fp,
        "lanca/ca.key is its key"
    );
    assert_eq!(
        db_text(
            &c.state,
            "SELECT fingerprint FROM lanca_roots WHERE retired_at IS NULL"
        )
        .await,
        Some(first_fp.clone())
    );
    assert_eq!(c.state.settings().lanca.zones, ["home.arpa", "a.example"]);
    assert!(staging_dirs(c.dir.path()).is_empty());
    // A start recovers the same root, matching the settings.
    let recovered = picket_core::lanca::rotation::open(c.dir.path(), &c.state.db)
        .await
        .unwrap();
    assert_eq!(recovered.fingerprint(), first_fp);
    assert!(picket_core::lanca::same_zones(
        recovered.zones(),
        &c.state.settings().lanca.zones
    ));
}

/// R2 (module docs of `lanca::rotation`, Previous roots; edge.md §5; core.md §8): core trusts a
/// previous root until the edge *reports* serving a certificate from the current one, not when it
/// signs one. The real edge can't store the certificates core signs after a rotation: it keeps
/// serving the old one and reporting it, so core keeps the old root (the validator still reaches
/// the listener) and refuses another rotation, naming the edge; once the store works again the
/// edge installs the new certificate, reports it, and core drops the old root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_the_edge_never_installs_keeps_the_previous_root_trusted() {
    let c = common::start_core(Some(
        json!({"web": {"tls": "off"}, "dnssec": {"source_ips": ["127.0.0.1/32"]}}),
    ))
    .await;
    let d = edge_dirs();
    let (edge, id) = edge_with_doh(&c, &d, "ucg").await;
    let old = c.state.lanca.load().fingerprint();
    assert!(eventually(|| async { edge_root(&edge).as_deref() == Some(old.as_str()) }).await);
    assert!(eventually(|| async { validator_reaches(&c.state).await.is_ok() }).await);
    assert!(
        eventually(|| async {
            db_text(
                &c.state,
                "SELECT root FROM lanca_served WHERE listener_id = 'lan-doh'",
            )
            .await
            .as_deref()
                == Some(old.as_str())
        })
        .await,
        "the edge reports what it serves"
    );
    // The edge's certificate store fails (without relying on uid permission checks).
    let slot = edge.edge.dns.certs.slot("lan-doh").unwrap();
    let error_before = slot.info().last_error.clone();
    let tls = d.data.join("tls");
    std::fs::rename(&tls, d.data.join("tls.saved")).unwrap();
    std::fs::write(&tls, b"storage unavailable").unwrap();
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa", "lan.example"]}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new = body["lanca"]["fingerprint"].as_str().unwrap().to_string();
    // Core signs; the edge fails to store it, and keeps serving the old certificate.
    assert!(
        eventually(|| async {
            let e = slot.info().last_error.clone();
            e.is_some() && e != error_before
        })
        .await,
        "the edge asked for a certificate and couldn't store it"
    );
    tokio::time::sleep(Duration::from_millis(1000)).await;
    picket_core::lanca::rotation::prune(&c.state).await.unwrap();
    assert_eq!(edge_root(&edge).as_deref(), Some(old.as_str()));
    let prev: Vec<String> = c
        .state
        .lanca
        .load()
        .previous
        .iter()
        .map(|p| p.fingerprint.clone())
        .collect();
    assert_eq!(prev, vec![old.clone()], "the old root stays trusted");
    validator_reaches(&c.state).await.unwrap();
    let (_, s) = get(&c, "/settings").await;
    assert_eq!(s["lanca"]["can_rotate"], json!(false));
    assert_eq!(s["lanca"]["previous"][0]["edges"][0]["edge_id"], json!(id));
    assert_eq!(
        s["lanca"]["previous"][0]["edges"][0]["listeners"],
        json!(["lan-doh"])
    );
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa", "another.example"]}})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("ucg (lan-doh)"), "{body}");
    assert_eq!(c.state.lanca.load().fingerprint(), new);
    // The store works again: the edge installs the new certificate and reports it.
    std::fs::remove_file(&tls).unwrap();
    std::fs::rename(d.data.join("tls.saved"), &tls).unwrap();
    assert!(eventually(|| async { edge_root(&edge).as_deref() == Some(new.as_str()) }).await);
    assert!(
        eventually(|| async { c.state.lanca.load().previous.is_empty() }).await,
        "the old root goes once the edge reports the new one"
    );
    validator_reaches(&c.state).await.unwrap();
    let (_, s) = get(&c, "/settings").await;
    assert_eq!(s["lanca"]["can_rotate"], json!(true));
    edge.shutdown().await;
}

/// The `lanca` UI events received so far.
fn lanca_events(rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>) -> Vec<Value> {
    let mut out = Vec::new();
    while let Ok(e) = rx.try_recv() {
        if e.kind == "lanca" {
            out.push(e.data);
        }
    }
    out
}

/// R2, R7 (module docs of `lanca::rotation`; api.md §3 `cert_roots`): the previous root stays
/// until every assigned managed listener reports a certificate from the current root: one still
/// on the old root, one with no certificate, and an offline edge's last report all keep it, and a
/// second rotation is refused naming what waits. Reports on the current root drop it, with a
/// `lanca` UI event, as the rotation sent one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_previous_root_stays_until_every_assigned_listener_reports_the_current_one() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let edge = FakeEdge::registered(&c, "e1").await;
    for (id, name) in [("lan-dot", "dns.home.arpa"), ("lan-doh", "doh.home.arpa")] {
        put_entity(
            &c,
            "listeners",
            json!({"id": id, "name": id, "proto": if id == "lan-dot" { "dot" } else { "doh" },
                   "bind": if id == "lan-dot" { "192.168.1.1:853" } else { "192.168.1.1:9853" },
                   "tls": {"managed": name}, "edges": [edge.id]}),
        )
        .await;
    }
    let old = c.state.lanca.load().fingerprint();
    let mut rx = c.state.events.subscribe();
    let served = |root: &str| {
        let root = root.to_string();
        let st = c.state.clone();
        async move {
            st.db
                .read(move |c| {
                    Ok::<_, anyhow::Error>(c.query_row(
                        "SELECT count(*) FROM lanca_served WHERE root = ?1",
                        [&root],
                        |r| r.get::<_, i64>(0),
                    )?)
                })
                .await
                .unwrap()
        }
    };
    let mut hello = common::edge::hello("b1");
    hello["cert_roots"] = json!({"lan-dot": old, "lan-doh": old, "not-assigned": old});
    let (mut ws, _) = edge.session(hello).await;
    assert!(eventually(|| async { served(&old).await == 3 }).await);

    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa", "lan.example"]}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new = body["lanca"]["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(body["lanca"]["can_rotate"], json!(false));
    let users = &body["lanca"]["previous"][0]["edges"];
    assert_eq!(users[0]["listeners"], json!(["lan-doh", "lan-dot"]), "{body}");
    assert_eq!(users[0]["online"], json!(true));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ev = lanca_events(&mut rx);
    assert!(
        ev.iter()
            .any(|e| e["event"] == "rotated" && e["root"] == json!(new) && e["current"] == json!(new)),
        "{ev:?}"
    );

    // One listener on the new root, the other with no certificate: still in use.
    let mut hb = common::edge::heartbeat("b1", Timestamp::now(), 1000, 0);
    hb["cert_roots"] = json!({"lan-dot": new});
    common::edge::send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    assert!(eventually(|| async { served(&new).await == 1 && served(&old).await == 0 }).await);
    picket_core::lanca::rotation::prune(&c.state).await.unwrap();
    assert_eq!(c.state.lanca.load().previous.len(), 1);
    let (_, s) = get(&c, "/settings").await;
    assert_eq!(
        s["lanca"]["previous"][0]["edges"][0]["listeners"],
        json!(["lan-doh"])
    );
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa"]}})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("e1 (lan-doh)"), "{body}");

    // Offline, its last report stands.
    drop(ws);
    assert!(eventually(|| async { c.state.edges.hub.session(&edge.id).is_none() }).await);
    picket_core::lanca::rotation::prune(&c.state).await.unwrap();
    assert_eq!(c.state.lanca.load().previous.len(), 1);
    let (_, s) = get(&c, "/settings").await;
    assert_eq!(s["lanca"]["previous"][0]["edges"][0]["online"], json!(false));
    assert!(lanca_events(&mut rx).is_empty());

    // Back, with both on the new root: the old root goes, with an event.
    let mut hello = common::edge::hello("b2");
    hello["cert_roots"] = json!({"lan-dot": new, "lan-doh": new});
    let (_ws, _) = edge.session(hello).await;
    assert!(eventually(|| async { c.state.lanca.load().previous.is_empty() }).await);
    assert_eq!(db_i64(&c.state, "SELECT count(*) FROM lanca_roots").await, 1);
    let (_, s) = get(&c, "/settings").await;
    assert_eq!(s["lanca"]["can_rotate"], json!(true));
    assert_eq!(s["lanca"]["previous"], json!([]));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let ev = lanca_events(&mut rx);
    assert!(
        ev.iter().any(|e| e["event"] == "previous_dropped"
            && e["root"] == json!(old)
            && e["current"] == json!(new)),
        "{ev:?}"
    );
}

/// R3 (README §2 Clocks): a rotation dates a new root and certificates, so it waits for a
/// synchronised clock (503, nothing changes), and so does signing a listener certificate.
#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_and_signing_wait_for_a_synchronised_clock() {
    let c = common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: PathBuf::from("/nonexistent/picket-core/edge"),
            clock_synced: Some(false),
            ..Default::default()
        },
    )
    .await;
    let edge = FakeEdge::registered(&c, "e1").await;
    put_entity(
        &c,
        "listeners",
        json!({"id": "lan-dot", "name": "lan-dot", "proto": "dot", "bind": "192.168.1.1:853",
               "tls": {"managed": "dns.home.arpa"}, "edges": [edge.id]}),
    )
    .await;
    let fp = c.state.lanca.load().fingerprint();
    let (_, s) = get(&c, "/settings").await;
    assert_eq!(s["lanca"]["clock_synced"], json!(false));
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa", "lan.example"]}})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.to_string().contains("synchronised"), "{body}");
    assert_eq!(c.state.lanca.load().fingerprint(), fp);
    assert_eq!(file_fingerprint(c.dir.path()), fp);
    assert!(staging_dirs(c.dir.path()).is_empty());
    assert_eq!(c.state.settings().lanca.zones, ["home.arpa"]);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let post = || {
        edge.http
            .post(edge.url("/v1/csr"))
            .json(&json!({"csr_pem": csr, "listener": "lan-dot"}))
            .send()
    };
    let r = post().await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(r.text().await.unwrap().contains("clock"));
    // Synchronised: both proceed.
    c.state.clock.pin(true);
    assert_eq!(post().await.unwrap().status(), StatusCode::OK);
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa", "lan.example"]}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(c.state.lanca.load().fingerprint(), fp);
}

/// True when `lanca/web.key` is the key of `lanca/web.crt`.
fn web_pair_matches(dir: &Path) -> bool {
    let crt = std::fs::read_to_string(dir.join("lanca/web.crt")).unwrap();
    let key = std::fs::read_to_string(dir.join("lanca/web.key")).unwrap();
    let der = picket_core::identity::pem_to_der(&crt, "CERTIFICATE").unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let kp = rcgen::KeyPair::from_pem(&key).unwrap();
    cert.tbs_certificate.subject_pki.raw == rcgen::PublicKeyData::subject_public_key_info(&kp)
}

/// R4 (core.md §11 `web.tls` managed; README §2 Restarts): a web key that isn't its
/// certificate's (a stop between the two writes) is never served: the load re-issues the pair.
#[tokio::test(flavor = "multi_thread")]
async fn a_mismatched_web_pair_on_disk_is_reissued() {
    let c = common::start_core(None).await; // managed web TLS
    let (names, ips) = picket_core::web::web_cert_sans(&c.state);
    let (_, other_key) = c
        .state
        .lanca
        .load()
        .issue_with_new_key(&names, &ips, picket_core::lanca::LEAF_VALIDITY)
        .unwrap();
    std::fs::write(c.dir.path().join("lanca/web.key"), other_key).unwrap();
    assert!(!web_pair_matches(c.dir.path()));
    let ck = picket_core::web::managed_web_cert(&c.state, &picket_core::identity::crypto_provider()).unwrap();
    assert!(ck.keys_match().is_ok());
    assert!(web_pair_matches(c.dir.path()));
    assert!(c.state.lanca.load().signed(ck.cert[0].as_ref()));
}

/// R4: two web-certificate refreshes at once (the rotation's and the minute task's) never both
/// issue: one at a time, the second finds the fresh certificate, and the pair on disk is the one
/// served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_web_certificate_refreshes_issue_once_and_keep_one_pair() {
    let c = common::start_core(None).await; // managed web TLS
    for round in 0..30 {
        // Other web.names: the served certificate is stale, so both refreshes want to issue.
        let names = if round % 2 == 0 {
            json!(["core.home.arpa"])
        } else {
            json!(["core2.home.arpa"])
        };
        c.state
            .config
            .patch_settings(json!({"web": {"names": names}}), Actor::cli())
            .await
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let (st, b) = (c.state.clone(), barrier.clone());
                std::thread::spawn(move || {
                    b.wait();
                    picket_core::web::refresh_web_cert(&st).unwrap()
                })
            })
            .collect();
        let issued = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|&i| i)
            .count();
        assert!(issued <= 1, "round {round}: both refreshes issued");
        assert!(web_pair_matches(c.dir.path()), "round {round}");
        let served = c.state.web_cert.get().unwrap().0.load_full();
        let crt = std::fs::read_to_string(c.dir.path().join("lanca/web.crt")).unwrap();
        assert_eq!(
            served.cert[0].as_ref(),
            picket_core::identity::pem_to_der(&crt, "CERTIFICATE")
                .unwrap()
                .as_slice(),
            "round {round}: the served certificate is the stored one"
        );
    }
}

/// R5 (core.md §2): the document's `lanca.zones` are compared as a set, as everywhere else, so
/// the same zones in another order restore.
#[tokio::test(flavor = "multi_thread")]
async fn a_restore_with_the_same_zones_in_another_order_passes() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa", "lan.example"]}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let r = ui(&c, Method::GET, "/config/export").send().await.unwrap();
    let mut doc: Value = r.json().await.unwrap();
    doc["configuration"]["settings"]["lanca.zones"] = json!(["lan.example", "home.arpa"]);
    let r = ui(&c, Method::PUT, "/config/export")
        .json(&doc)
        .send()
        .await
        .unwrap();
    let status = r.status();
    let text = r.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{text}");
}

/// R3 (README §2 Clocks; module docs of `lanca::rotation`, steps 1–2): the clock is checked again
/// right before the new root is dated, so a clock that stops being synchronised while the rotation
/// waits for its checks makes no root (`503`, nothing changes).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clock_lost_while_the_rotation_waits_for_its_checks_makes_no_root() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    common::settled(&c).await;
    // Every reader held: the rotation passes its first clock check, then waits for its checks'
    // read.
    let mut readers = Vec::new();
    let mut releases = Vec::new();
    for _ in 0..picket_core::db::DbOptions::core(c.dir.path()).readers {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (entered_tx, entered) = tokio::sync::oneshot::channel();
        let db = c.state.db.clone();
        readers.push(tokio::spawn(async move {
            db.read(move |_| {
                let _ = entered_tx.send(());
                let _ = wait.recv_timeout(Duration::from_secs(60));
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap();
        }));
        entered.await.unwrap();
        releases.push(release);
    }
    let fp = c.state.lanca.load().fingerprint();
    let (st, from) = (c.state.clone(), fp.clone());
    let rotation = tokio::spawn(async move {
        picket_core::lanca::rotation::rotate(
            &st,
            vec!["home.arpa".into(), "lan.example".into()],
            json!({}),
            from,
            Actor::cli(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert!(!rotation.is_finished(), "the rotation waits for a reader");
    c.state.clock.pin(false);
    for r in releases {
        let _ = r.send(());
    }
    for r in readers {
        r.await.unwrap();
    }
    let result = rotation.await.unwrap();
    assert!(
        matches!(result, Err(picket_core::error::CoreError::Unavailable(_))),
        "a root dated by an unsynchronised clock: {result:?}"
    );
    assert_eq!(c.state.lanca.load().fingerprint(), fp);
    assert_eq!(file_fingerprint(c.dir.path()), fp);
    assert!(staging_dirs(c.dir.path()).is_empty());
    assert_eq!(c.state.settings().lanca.zones, ["home.arpa"]);
    assert_eq!(db_i64(&c.state, "SELECT count(*) FROM lanca_roots").await, 1);
}

/// R3 (README §2 Clocks; core.md §11 `web.tls` managed): a new root re-issues the managed web
/// certificate only on a synchronised clock. Before that the certificate from the previous root
/// (dated while the clock was synchronised) stays, at start too, and the minute refresh re-issues
/// it from the new root once the clock is synchronised.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_web_certificate_follows_a_new_root_once_the_clock_is_synchronised() {
    let c = common::start_core(None).await; // managed web TLS
    let served = |st: &SharedState| st.web_cert.get().expect("managed web certificate").0.load_full();
    let before = served(&c.state).cert[0].as_ref().to_vec();
    // The rotation stops once the running core uses the new root, before the web certificate.
    c.state.lanca_rt.fail_at(Some(Step::Switched));
    // The first zone stays, so the certificate's names don't change.
    let (status, body) = rotate(&c, json!({"lanca": {"zones": ["home.arpa", "lan.example"]}})).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    c.state.lanca_rt.fail_at(None);
    assert!(!c.state.lanca.load().signed(&before));
    c.state.clock.pin(false);
    assert!(!picket_core::web::refresh_web_cert(&c.state).unwrap());
    assert_eq!(served(&c.state).cert[0].as_ref(), before.as_slice());
    // At start too.
    let (_dir, state, stop) = restart_with(c, false).await;
    assert_eq!(served(&state).cert[0].as_ref(), before.as_slice());
    assert!(!state.lanca.load().signed(&before));
    // Synchronised: the refresh re-issues it from the new root.
    state.clock.pin(true);
    assert!(picket_core::web::refresh_web_cert(&state).unwrap());
    assert!(state.lanca.load().signed(served(&state).cert[0].as_ref()));
    stop.cancel();
}

/// README §2 Bounded (module docs of `lanca::rotation`, Previous roots): an edge's changed
/// `cert_roots` are stored at once after a quiet storage window, then at most once per window,
/// the newest report at its end, so an edge alternating its reports can't keep the writer busy
/// and what is stored ends up the newest report.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changing_cert_roots_are_stored_at_most_once_per_window_the_newest_last() {
    let window = picket_core::edges::hub::HEARTBEAT_STORE_EVERY;
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let edge = FakeEdge::registered(&c, "e1").await;
    put_entity(
        &c,
        "listeners",
        json!({"id": "lan-dot", "name": "lan-dot", "proto": "dot", "bind": "192.168.1.1:853",
               "tls": {"managed": "dns.home.arpa"}, "edges": [edge.id]}),
    )
    .await;
    // Counts the reports stored (one row each: one listener), on the writer's own connection.
    c.state
        .db
        .write(|c| {
            c.execute_batch(
                "CREATE TEMP TABLE served_writes (n INTEGER);
                 CREATE TEMP TRIGGER served_count AFTER INSERT ON main.lanca_served
                 BEGIN INSERT INTO served_writes VALUES (1); END;",
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let writes = || async {
        c.state
            .db
            .write(|c| {
                Ok::<_, anyhow::Error>(
                    c.query_row("SELECT count(*) FROM served_writes", [], |r| r.get::<_, i64>(0))?,
                )
            })
            .await
            .unwrap()
    };
    let stored = || async {
        db_text(
            &c.state,
            "SELECT root FROM lanca_served WHERE listener_id = 'lan-dot'",
        )
        .await
    };
    let [a, b, cc] = [b"a", b"b", b"c"].map(|k| picket_api::ids::cert_fingerprint(k));
    let mut hello = common::edge::hello("b1");
    hello["cert_roots"] = json!({"lan-dot": a});
    let (mut ws, _) = edge.session(hello).await;
    assert!(eventually(|| async { stored().await.as_deref() == Some(a.as_str()) }).await);
    let report = |up_ms: u64, root: &str| {
        let mut hb = common::edge::heartbeat("b1", Timestamp::now(), up_ms, 0);
        hb["cert_roots"] = json!({"lan-dot": root});
        json!({"type": "heartbeat", "data": hb})
    };
    // The first change goes through at once (the report right after a new certificate).
    let b_sent = tokio::time::Instant::now();
    common::edge::send(&mut ws, report(1, &b)).await;
    assert!(eventually(|| async { stored().await.as_deref() == Some(b.as_str()) }).await);
    assert!(
        b_sent.elapsed() < window,
        "the first change waited for the window"
    );
    assert_eq!(writes().await, 2);
    // Then alternating reports, the newest one C.
    let n = 201u64;
    for i in 0..n {
        let root = if i % 2 == 0 { &cc } else { &b };
        common::edge::send(&mut ws, report(2 + i, root)).await;
    }
    let last = 2 + n - 1;
    let id = edge.id.clone();
    assert!(
        eventually(|| async {
            c.state
                .edges
                .hub
                .live(&id)
                .heartbeat
                .is_some_and(|h| h.up_ms == last)
        })
        .await
    );
    let burst = b_sent.elapsed();
    if burst < window {
        // B's write opened the window no earlier than it was sent.
        assert_eq!(
            stored().await.as_deref(),
            Some(b.as_str()),
            "a change inside the window"
        );
        assert_eq!(writes().await, 2, "a change inside the window");
    }
    assert!(
        eventually(|| async { stored().await.as_deref() == Some(cc.as_str()) }).await,
        "the newest report is stored at the end of the window"
    );
    let bound = 3 + (burst.as_secs() / window.as_secs()) as i64;
    let w = writes().await;
    assert!(
        w <= bound,
        "{w} writes for {n} reports in {burst:?} (at most {bound})"
    );
}

/// R3 (README §2 Clocks; api.md §2 `POST /v1/csr`): a CSR refused while core's clock isn't
/// synchronised spends none of the edge's CSR budget, so an edge that kept retrying meanwhile
/// gets its certificates as soon as the clock is synchronised.
#[tokio::test(flavor = "multi_thread")]
async fn csrs_refused_for_the_clock_spend_none_of_the_budget() {
    let c = common::start_core_with(
        Some(json!({"web": {"tls": "off"}})),
        picket_core::run::StartOptions {
            release_dir: PathBuf::from("/nonexistent/picket-core/edge"),
            clock_synced: Some(false),
            ..Default::default()
        },
    )
    .await;
    let edge = FakeEdge::registered(&c, "e1").await;
    put_entity(
        &c,
        "listeners",
        json!({"id": "lan-dot", "name": "lan-dot", "proto": "dot", "bind": "192.168.1.1:853",
               "tls": {"managed": "dns.home.arpa"}, "edges": [edge.id]}),
    )
    .await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let post = || {
        edge.http
            .post(edge.url("/v1/csr"))
            .json(&json!({"csr_pem": csr, "listener": "lan-dot"}))
            .send()
    };
    for i in 0..picket_core::edge_api::api::CSR_PER_WINDOW + 5 {
        let r = post().await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "attempt {i}");
    }
    c.state.clock.pin(true);
    let r = post().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn csr_refuses_declared_core_address_even_if_conflicting_listener_is_stored() {
    let c = common::start_core(Some(
        json!({"web": {"tls": "off", "addresses": ["192.168.55.8"]}}),
    ))
    .await;
    let edge = FakeEdge::registered(&c, "e1").await;
    put_entity(&c, "listeners", json!({"id": "lan-dot", "name": "lan-dot", "proto": "dot", "bind": "192.168.55.9:853", "tls": {"managed": "dns.home.arpa"}, "edges": [edge.id]})).await;
    // Simulate stale or externally altered stored configuration; the CSR boundary must still refuse it.
    c.state
        .config
        .change(|tx| {
            let mut l = picket_core::config::store::load_model(tx)?
                .listeners
                .remove("lan-dot")
                .unwrap();
            l.ips = vec!["::ffff:192.168.55.8".parse().unwrap()];
            picket_core::config::store::write_listener(tx, &l)?;
            Ok(())
        })
        .await
        .unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let r = edge
        .http
        .post(edge.url("/v1/csr"))
        .json(&json!({"csr_pem": csr, "listener": "lan-dot"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(r.json::<Value>().await.unwrap()["error"]["code"], "conflict");
}
