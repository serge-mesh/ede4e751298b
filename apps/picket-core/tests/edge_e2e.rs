//! The real edge foundation (`picket-edge`) against this core over real TLS: the check of the
//! edge↔core contract (api.md §1–§5). TOFU on core's side (the unknown key listed as pending,
//! then approved), the session (hello, welcome, heartbeats), convergence on the config object
//! (fetch, `changed` after an edit, `versions` showing it active), requests applied and
//! acknowledged, and log shipping with answers carried ahead of their records.

use crate::common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::edge::eventually;
use jiff::Timestamp;
use rusqlite::OptionalExtension;
use picket_api::logs::Decision;
use picket_core::config::model::EntityKind;
use picket_core::config::{Actor, Op};
use picket_edge::service::{self, Options, Tuning};
use serde_json::json;

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
    t
}

fn sample_q(qname: &str) -> picket_api::logs::QueryRecord {
    let r: picket_api::logs::LogRecord = serde_json::from_value(json!({
        "t": "q", "ts": "2026-11-13T10:22:01.123456Z", "boot": "x", "seq": 0,
        "listener": "lan-dns", "proto": "doh", "client": "192.168.1.140", "qname": qname, "qtype": "A",
        "rcode": "NOERROR", "decision": "allow"
    }))
    .unwrap();
    match r {
        picket_api::logs::LogRecord::Query(q) => *q,
        _ => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_edge_converges_reports_and_ships_logs() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    // The edge is tuned to heartbeat every 300 ms: core stores each (one per 20 s otherwise).
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let d = dirs();
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
    let fp = edge.identity.fingerprint.clone();

    // TOFU on core's side: the unknown key is listed as pending; the admin approves it.
    assert!(
        eventually(|| async {
            picket_core::edges::list_pending(&c.state.db)
                .await
                .unwrap()
                .iter()
                .any(|p| p.key == fp)
        })
        .await,
        "the edge's key shows up under Edges → Pending"
    );
    let out = picket_core::edges::approve_pending(
        &c.state.config,
        &fp,
        picket_core::config::model::EdgeDef {
            name: "ucg".into(),
            ..Default::default()
        },
        Actor::cli(),
    )
    .await
    .unwrap();
    let id = out.id.clone();

    // The session comes up: welcome names the edge; core holds its hello.
    assert!(
        eventually(|| async {
            edge.session.load().state == picket_edge::edge::CoreState::Connected
                && c.state.edges.hub.session(&id).is_some()
        })
        .await,
        "session up"
    );
    assert_eq!(edge.session.load().edge_id.as_deref(), Some(id.as_str()));
    assert_eq!(edge.session.load().edge_name.as_deref(), Some("ucg"));
    assert_eq!(
        c.state.edges.hub.live(&id).hello.unwrap().edge_version,
        picket_api::VERSION
    );

    // Convergence: the edge activates the object core publishes, and its heartbeats show it.
    let published = || c.state.edges.publisher.current(&id).map(|p| p.id.clone());
    assert!(
        eventually(|| async { published().is_some() && edge.active().object_id == published() }).await,
        "the edge runs core's config object"
    );
    assert!(
        eventually(|| async {
            picket_core::edges::status::view(&c.state, &id)
                .await
                .unwrap()
                .named
                .iter()
                .any(|n| n.kind == "config" && n.active_at.is_some())
        })
        .await,
        "a heartbeat's versions show the config active: {:?} / {:?}",
        picket_core::edges::status::view(&c.state, &id)
            .await
            .unwrap()
            .named,
        c.state
            .db
            .read(|db| {
                let mut st =
                    db.prepare("SELECT kind, detail_json FROM edge_events ORDER BY at DESC LIMIT 10")?;
                let v = st
                    .query_map([], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
            .unwrap()
    );

    // A config edit → `changed` → the edge fetches and activates the new object. First the
    // startup builds settle (their heads publish objects of their own, late on a loaded machine),
    // and the edge runs what core names then.
    common::settled(&c).await;
    assert!(
        eventually(|| async { published().is_some() && edge.active().object_id == published() }).await,
        "the edge runs core's config object once the startup builds are in"
    );
    let before = published().unwrap();
    c.state
        .config
        .apply(
            EntityKind::Client,
            Op::Create(json!({"name": "office-pc", "macs": ["aa:bb:cc:dd:ee:01"]})),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    assert!(
        eventually(|| async {
            let p = published();
            p.is_some() && p.as_deref() != Some(before.as_str()) && edge.active().object_id == p
        })
        .await,
        "the edge converges on the edited config"
    );
    assert!(
        edge.active()
            .config
            .as_ref()
            .unwrap()
            .clients
            .iter()
            .any(|cl| cl.name == "office-pc")
    );

    // A flush request: applied by the edge, acknowledged in its heartbeats.
    let rid = picket_core::edges::requests::flush(&c.state, &id, None)
        .await
        .unwrap();
    assert!(
        eventually(|| async {
            picket_core::edges::status::view(&c.state, &id)
                .await
                .unwrap()
                .requests
                .iter()
                .any(|q| q.kind == "flush_dns" && q.request_id == rid && !q.pending)
        })
        .await,
        "the flush is applied and acknowledged"
    );

    // Logs: a query with its upstream answer, and an event; stored once, answer by id.
    let ans = picket_edge::logs::Answer::new(bytes::Bytes::from_static(b"\x12\x34\x81\x80scrubbed-answer"))
        .unwrap();
    let mut q = sample_q("example.com");
    q.decision = Decision::Allow;
    for _ in 0..3 {
        edge.logs.emit_query(
            q.clone(),
            picket_edge::logs::AnswerSlot::Attached(Arc::clone(&ans)),
        );
    }
    edge.logs
        .event("panic", picket_edge::logs::fields(&[("task", json!("test"))]));
    let store = picket_core::logs::LogStore::new(&c.state.data_dir);
    let count = |sql: &'static str| {
        let store = store.clone();
        let edge_id = id.clone();
        move || {
            let mut n = 0i64;
            for (_, path) in store.list().unwrap() {
                let conn = rusqlite::Connection::open(path).unwrap();
                n += conn
                    .query_row(sql, [&edge_id], |r| r.get::<_, i64>(0))
                    .unwrap_or(0);
            }
            n
        }
    };
    let events = count("SELECT count(*) FROM events WHERE edge_id = ?1");
    assert!(
        eventually(|| async { events() == 3 }).await,
        "three query records stored"
    );
    let with_answer = count(
        "SELECT count(*) FROM events WHERE edge_id = ?1 AND answer_missing = 0 AND answer_id IS NOT NULL",
    );
    assert_eq!(with_answer(), 3, "the answer travelled ahead of its records");
    let answers = count("SELECT count(*) FROM answers WHERE ?1 IS NOT NULL");
    assert_eq!(answers(), 1, "stored once by id");
    assert!(
        eventually(|| async {
            c.state
                .alerts
                .get_by_key(&format!("edge_panic:{id}"))
                .await
                .unwrap()
                .is_some()
        })
        .await,
        "the panic event raised edge_panic"
    );
    // The boot that logged them is the hello's (release known).
    let boot = edge.boot.clone();
    let id2 = id.clone();
    let version: Option<String> = c
        .state
        .db
        .read(move |conn| {
            Ok::<_, anyhow::Error>(conn.query_row(
                "SELECT edge_version FROM edge_boots WHERE edge_id = ?1 AND boot = ?2",
                [&id2, &boot],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(version.as_deref(), Some(picket_api::VERSION));
    // Heartbeats reached metrics.db.
    let mdb = c.state.metrics_db.clone();
    let id3 = id.clone();
    let samples: i64 = mdb
        .read(move |conn| {
            Ok::<_, anyhow::Error>(conn.query_row(
                "SELECT count(*) FROM samples WHERE edge_id = ?1",
                [id3],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(samples > 0);

    // Replacing the key refuses the old one from then on (api.md §1 Key change).
    let mut body = serde_json::to_value(
        c.state
            .config
            .model_of(EntityKind::Edge)
            .await
            .unwrap()
            .edges
            .get(&id)
            .cloned()
            .unwrap(),
    )
    .unwrap();
    body["key"] = json!(picket_api::ids::fingerprint_spki(b"another key"));
    c.state
        .config
        .apply(EntityKind::Edge, Op::Update(id.clone(), body), Actor::cli(), None)
        .await
        .unwrap();
    assert!(
        eventually(|| async { c.state.edges.hub.session(&id).is_none() }).await,
        "the old key's session is closed"
    );
    r.shutdown().await;
}

/// A DNS query for `name` (type A) with an OPT record, as UDP bytes.
fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    // OPT: root name, type 41, UDP 1232, no extended rcode, DO=0, no options.
    q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    q
}

/// Skips a (possibly compressed) name at `i`.
fn skip_name(m: &[u8], mut i: usize) -> usize {
    while i < m.len() {
        let l = m[i] as usize;
        if l == 0 {
            return i + 1;
        }
        if l & 0xc0 == 0xc0 {
            return i + 2;
        }
        i += 1 + l;
    }
    i
}

/// The EDE info codes in a response's OPT record.
fn ede_codes(m: &[u8]) -> Vec<u16> {
    let n = |i: usize| u16::from_be_bytes([m[i], m[i + 1]]) as usize;
    let (qd, an, ns, ar) = (n(4), n(6), n(8), n(10));
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(m, i) + 4;
    }
    for _ in 0..an + ns {
        i = skip_name(m, i);
        i += 10 + n(i + 8);
    }
    let mut out = Vec::new();
    for _ in 0..ar {
        i = skip_name(m, i);
        let (t, len) = (n(i), n(i + 8));
        let rdata = i + 10;
        if t == 41 {
            let mut j = rdata;
            while j + 4 <= rdata + len {
                let (code, olen) = (n(j), n(j + 2));
                if code == 15 && olen >= 2 {
                    out.push(n(j + 4) as u16);
                }
                j += 4 + olen;
            }
        }
        i = rdata + len;
    }
    out
}

/// True when the edge's listener at `addr` blocks `name`: an answer with EDE 15 (Blocked).
async fn blocked(addr: std::net::SocketAddr, name: &str) -> bool {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(&dns_query(0x4242, name), addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => ede_codes(&buf[..n]).contains(&15),
        _ => false,
    }
}

/// Bundles end to end (build-and-test.md §5 "Bundles"; bundles.md §7, edge.md §13): core builds
/// `block-common` from a manual feed and names its head in the edge's config object; the real
/// edge downloads the head and its blobs, verifies and activates them, reports them active, and
/// its DNS listener blocks the name; a second version reaches it as a delta and blocks the new
/// name too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_edge_activates_a_bundle_and_blocks_a_name() {
    use common::bundles::{build, put_entity, save};
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    save(&c, "manual-block", "||blocked.example^\n").await;
    let h1 = build(&c, "block-common").await.unwrap();
    let d = dirs();
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
    let fp = edge.identity.fingerprint.clone();
    assert!(
        eventually(|| async {
            picket_core::edges::list_pending(&c.state.db)
                .await
                .unwrap()
                .iter()
                .any(|p| p.key == fp)
        })
        .await
    );
    let id = picket_core::edges::approve_pending(
        &c.state.config,
        &fp,
        picket_core::config::model::EdgeDef {
            name: "ucg".into(),
            ..Default::default()
        },
        Actor::cli(),
    )
    .await
    .unwrap()
    .id;
    put_entity(
        &c,
        "listeners",
        "lan-dns",
        json!({"id": "lan-dns", "name": "lan-dns", "proto": "dns",
               "bind": format!("127.0.0.1:{}", common::free_port()), "edges": [id]}),
    )
    .await;
    let runs_head = |edge: &Arc<picket_edge::edge::Edge>, h: &str| {
        let short = picket_api::ids::short_id(h).to_owned();
        edge.active().versions.as_ref().is_some_and(|v| {
            v.bundles.get("block-common") == Some(&picket_api::logs::BundleVersion::Plain(short))
        })
    };
    assert!(
        eventually_long(|| async {
            runs_head(&edge, &h1) && !edge.dns.listeners.local_addrs("lan-dns").is_empty()
        })
        .await,
        "the edge runs block-common {h1} with its listener up: versions {:?}",
        edge.active().versions
    );
    let addr = edge.dns.listeners.local_addrs("lan-dns")[0];
    assert!(
        blocked(addr, "blocked.example").await,
        "blocked through the edge's listener"
    );
    assert!(
        blocked(addr, "sub.blocked.example").await,
        "||d^ covers subdomains"
    );
    // Core sees the head active in the edge's heartbeats.
    assert!(
        eventually_long(|| async {
            picket_core::edges::status::view(&c.state, &id)
                .await
                .unwrap()
                .named
                .iter()
                .any(|n| n.kind == "bundle" && n.target == "block-common" && n.active_at.is_some())
        })
        .await
    );
    // A second version: a delta on the same base.
    save(&c, "manual-block", "||blocked.example^\n||second.example^\n").await;
    let h2 = build(&c, "block-common").await.unwrap();
    assert_ne!(h1, h2);
    assert!(
        eventually_long(|| async { runs_head(&edge, &h2) }).await,
        "the edge runs block-common {h2}: versions {:?}",
        edge.active().versions
    );
    assert!(blocked(addr, "second.example").await, "the delta's key blocks");
    assert!(blocked(addr, "blocked.example").await);
    r.shutdown().await;
}

/// [`eventually`] with room for builds and activations on a slow shared machine.
async fn eventually_long<F, Fut>(mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..1200 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f().await
}

/// With the real edge: an allow the extension creates is committed to the edge's allow store as
/// the bypass API commits it (`AllowsStore::commit`, `via: extension`, edge.md §12), shipped as an
/// `allow` record through the edge's spool, and kept in core's temporary-allow history; it raises
/// no alert (issue 79).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_allow_the_extension_creates_on_the_real_edge_reaches_the_history() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let d = dirs();
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
    let fp = edge.identity.fingerprint.clone();
    assert!(
        eventually(|| async {
            picket_core::edges::list_pending(&c.state.db)
                .await
                .unwrap()
                .iter()
                .any(|p| p.key == fp)
        })
        .await
    );
    let id = picket_core::edges::approve_pending(
        &c.state.config,
        &fp,
        picket_core::config::model::EdgeDef {
            name: "ucg".into(),
            ..Default::default()
        },
        Actor::cli(),
    )
    .await
    .unwrap()
    .id;
    let now = Timestamp::now();
    let allow = picket_edge::allows::StoredAllow {
        allow_id: "a-ext-1".into(),
        kind: picket_api::logs::AllowKind::Dns,
        device: "aa:bb:cc:dd:ee:02".into(),
        device_name: Some("emma-tablet".into()),
        client: "192.168.1.140".into(),
        target: "videos.example.org".into(),
        subdomains: Some(false),
        block_id: Some("b-42".into()),
        profile: Some("kids".into()),
        block_time: Some(now),
        block_ttl: Some(300),
        addresses: vec![],
        created_at: now,
        expires_at: now + jiff::SignedDuration::from_mins(30),
        extra: Default::default(),
    };
    let allows = Arc::clone(&edge.allows);
    tokio::task::spawn_blocking(move || {
        allows.commit(
            &[(allow, picket_api::logs::AllowAction::Created)],
            &[],
            picket_api::logs::AllowAction::Revoked,
            "extension",
        )
    })
    .await
    .unwrap()
    .unwrap();
    let row = || {
        let (db, id) = (c.state.db.clone(), id.clone());
        async move {
            db.read(move |conn| {
                Ok::<_, anyhow::Error>(
                    conn.query_row(
                        "SELECT target, device, created_at IS NOT NULL FROM temp_allows WHERE edge_id = ?1 AND allow_id = 'a-ext-1'",
                        [id],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, bool>(2)?)),
                    )
                    .optional()?,
                )
            })
            .await
            .unwrap()
        }
    };
    assert!(
        eventually_long(|| async { row().await.is_some() }).await,
        "the shipped allow record reached the history"
    );
    assert_eq!(
        row().await,
        Some(("videos.example.org".into(), "emma-tablet".into(), true))
    );
    let security = c
        .state
        .db
        .read(|conn| {
            Ok::<_, anyhow::Error>(conn.query_row(
                "SELECT count(*) FROM alerts WHERE type = 'security'",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(security, 0, "an allow raises no alert");
    r.shutdown().await;
}
