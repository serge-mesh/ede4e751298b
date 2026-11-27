//! Core follow-ups the web UI needed (api.md §7; core.md §2, §9, §12): the lookup provider status
//! from core.db, the restore's warnings and `restore` event, MACs of client-named devices, a
//! profile view's temporary allows, evidence paging, the `revoked` allow state and the coalesced
//! `temp_allow` events.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

mod common;

use std::time::Duration;

use common::Core;
use common::bundles::{get, ui};
use common::edge::{FakeEdge, heartbeat, hello, send};
use jiff::Timestamp;
use picket_core::config::{Actor, EntityKind, Op};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

async fn core() -> Core {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    c.state.clock.pin(true);
    c
}

fn ts(t: Timestamp) -> String {
    t.strftime("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// Polls `f` until it holds, generously (CI is slow and the host can stall for seconds).
async fn until<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let end = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < end {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(f().await, "timed out waiting for {what}");
}

/// The next UI event of `kind` within 60 s.
async fn next_event(
    rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>,
    kind: &str,
) -> Value {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match rx.recv().await {
                Ok(ev) if ev.kind == kind => return ev.data,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("events: {e}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} event"))
}

fn http_json(id: &str) -> Value {
    json!({"id": id, "name": id, "module": "http_json",
        "config": {"url": "https://lookup.example/{domain}", "verdict": {"pointer": "/risk", "block_if": ">= 7"}},
        "recheck": {"enabled": false}})
}

/// C1 (api.md §7 `lookup-providers/{id}/status`): the status reports what core.db holds, not the
/// runtime's model, which follows a commit only after its reload: a provider just created shows
/// at once, and so does the generation a flush just moved on. A provider written to core.db that
/// the runtime never reloaded (no publish) still shows, deterministically.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_provider_status_follows_core_db_at_once() {
    let c = core().await;
    let r = ui(&c, Method::POST, "/lookup-providers")
        .json(&http_json("p1"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    let (st, s) = get(&c, "/lookup-providers/p1/status").await;
    assert_eq!(st, StatusCode::OK, "right after the create: {s}");
    assert_eq!(s["provider"], "p1");
    let db_gen = |c: &Core| {
        let db = c.state.db.clone();
        async move {
            db.read(|c| {
                Ok::<String, anyhow::Error>(c.query_row(
                    "SELECT cache_generation FROM lookup_providers WHERE id = 'p1'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap()
        }
    };
    assert_eq!(s["cache_generation"], json!(db_gen(&c).await));
    let r = ui(&c, Method::POST, "/lookup-providers/p1/flush")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let flushed: Value = r.json().await.unwrap();
    let (_, s) = get(&c, "/lookup-providers/p1/status").await;
    assert_eq!(
        s["cache_generation"], flushed["cache_generation"],
        "right after the flush"
    );
    // Written to core.db without a publish: the runtime never sees it, the status does.
    c.state
        .db
        .write(|db| {
            let tx = db.transaction()?;
            let mut def: picket_core::config::model::LookupProviderDef =
                serde_json::from_value(http_json("p2"))?;
            def.cache_generation = "00000000000000aa".into();
            picket_core::config::store::write_provider(&tx, &def)?;
            tx.execute(
                "UPDATE lookup_providers SET cache_generation = '00000000000000bb' WHERE id = 'p1'",
                [],
            )?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    assert!(!c.state.lookups.model().lookup_providers.contains_key("p2"));
    let (st, s) = get(&c, "/lookup-providers/p2/status").await;
    assert_eq!(st, StatusCode::OK, "{s}");
    assert_eq!(s["cache_generation"], "00000000000000aa");
    assert_eq!(s["calls"], 0, "no client yet: its counters read 0");
    let (_, s) = get(&c, "/lookup-providers/p1/status").await;
    assert_eq!(s["cache_generation"], "00000000000000bb");
    let (st, _) = get(&c, "/lookup-providers/nope/status").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// Review Q5 (api.md §7 `lookup-providers/{id}/test`; providers.md §4 Self-tests): Test now
/// tests the committed config, as the status reads it: right after a create it waits for the
/// runtime's reload rather than answering 404, and a provider the runtime can't reach (here
/// written to core.db with no reload) is `409` "provider is being reloaded" after a bounded
/// wait, never a test of another config.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_now_tests_the_committed_config() {
    let c = core().await;
    // A module whose self-test always passes (no network).
    let module = picket_lookup::testkit::ScriptedModule::with_self_test(
        "http_json",
        picket_lookup::SelfTest {
            name: "malware.testcategory.example".into(),
            expect: picket_lookup::Expect::Block,
            cron: "0 0 1 1 *".into(),
        },
        |_cfg, _name, _n| {
            Box::pin(async {
                Ok(picket_lookup::Answer {
                    verdict: picket_lookup::Verdict::Block {
                        score: None,
                        reason: "malware".into(),
                    },
                    detail: None,
                })
            })
        },
    );
    let mut r = picket_lookup::Registry::builtin();
    r.insert(module);
    c.state.lookups.set_registry(&c.state, r).await;
    for i in 0..5 {
        let id = format!("t{i}");
        let r = ui(&c, Method::POST, "/lookup-providers")
            .json(&http_json(&id))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "{}", r.text().await.unwrap());
        let r = ui(&c, Method::POST, &format!("/lookup-providers/{id}/test"))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        let st = r.status();
        let body: Value = r.json().await.unwrap();
        assert_eq!(st, StatusCode::OK, "right after the create: {body}");
        assert_eq!(body["trigger"], "manual", "{body}");
        assert_eq!(body["result"], "pass", "{body}");
    }
    c.state
        .db
        .write(|db| {
            let tx = db.transaction()?;
            let def: picket_core::config::model::LookupProviderDef =
                serde_json::from_value(http_json("unseen"))?;
            picket_core::config::store::write_provider(&tx, &def)?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let r = ui(&c, Method::POST, "/lookup-providers/unseen/test")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let st = r.status();
    let body: Value = r.json().await.unwrap();
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["message"], "provider is being reloaded", "{body}");
    let r = ui(&c, Method::POST, "/lookup-providers/nope/test")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

/// C2 and C9 (core.md §2 Export and restore; api.md §7): the restore's `warnings` say what it
/// leaves for the admin (here: lookup providers with new generations, a disabled feed provider's
/// feeds waiting, an edge the document doesn't hold, a setting this release doesn't know, a
/// document from another release), and a `restore` event tells every open tab to resync.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_reports_its_warnings_and_tells_the_ui() {
    let c = core().await;
    c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Create(http_json("p1")),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    c.state
        .config
        .apply(
            EntityKind::FeedProvider,
            Op::Create(
                json!({"id": "off", "name": "off", "enabled": false, "module": "http",
                "config": {"url": "https://lists.example/a.txt"},
                "files": [{"match": "response", "feed": {"format": "plain"}}]}),
            ),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    let r = ui(&c, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let mut doc: Value = r.json().await.unwrap();
    assert!(
        doc["configuration"]["feeds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["provider"] == "off"),
        "the disabled provider's feed is in the document"
    );
    // An edge registered after the export, a key from a newer release, another release.
    let gone = FakeEdge::registered(&c, "later-edge").await;
    doc["configuration"]["settings"]["web.future_knob"] = json!(true);
    doc["core_version"] = json!("0.0.1-older");
    let mut events = c.state.events.subscribe();
    let r = ui(&c, Method::PUT, "/config/export")
        .json(&doc)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    let res: Value = r.json().await.unwrap();
    let warnings: Vec<String> = serde_json::from_value(res["warnings"].clone()).unwrap();
    let has = |needle: &str| warnings.iter().any(|w| w.contains(needle));
    assert!(
        has("lookup provider(s) start with empty verdict caches"),
        "{warnings:?}"
    );
    assert!(has("Disabled feed provider(s) off"), "{warnings:?}");
    assert!(has("Edge(s) later-edge aren't in the document"), "{warnings:?}");
    assert!(has("web.future_knob"), "{warnings:?}");
    assert!(has("release 0.0.1-older"), "{warnings:?}");
    assert!(!c.state.config.model().await.unwrap().edges.contains_key(&gone.id));
    let ev = next_event(&mut events, "restore").await;
    assert!(ev["generation"].as_u64().unwrap() >= 1, "{ev}");
    assert!(ev["at"].as_str().is_some(), "{ev}");
    // F8 (api.md §7 `restore` event): the response carries the generation its event carries, so
    // the restoring tab knows the event for its own.
    assert_eq!(res["generation"], ev["generation"], "{res}");
    assert_eq!(res["generation"], json!(c.state.restore.generation()), "{res}");
}

/// Review Q6 (core.md §2 Export and restore; README §2 Restarts): a restore that committed is
/// reported as done, with its warnings and missing secrets, even when rendering the edges'
/// configs after it fails: the response says so in a warning, and core renders again until it
/// works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_that_committed_succeeds_when_its_render_fails() {
    let c = core().await;
    let edge = FakeEdge::registered(&c, "e1").await;
    let r = ui(&c, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let mut doc: Value = r.json().await.unwrap();
    doc["configuration"]["profiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "restored", "name": "restored"}));
    c.state.restore.fail_next_render();
    let r = ui(&c, Method::PUT, "/config/export")
        .json(&doc)
        .send()
        .await
        .unwrap();
    let st = r.status();
    let res: Value = r.json().await.unwrap();
    assert_eq!(st, StatusCode::OK, "{res}");
    assert_eq!(res["restored"], true, "{res}");
    assert!(res["missing_secrets"].is_array(), "{res}");
    let warnings: Vec<String> = serde_json::from_value(res["warnings"].clone()).unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("edges' configs could not be rendered")),
        "{warnings:?}"
    );
    until(
        "the edge's config rendered again with the restored profile",
        || {
            let ok = c
                .state
                .edges
                .publisher
                .current(&edge.id)
                .is_some_and(|p| p.config.profiles.contains_key("restored"));
            async move { ok }
        },
    )
    .await;
}

/// Posts `lines` from `edge`, asserting the ack.
async fn post(edge: &FakeEdge, lines: &[Value]) {
    let r = edge.post_logs(lines).await;
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
}

fn q_rec(seq: u64, qname: &str, client: &str, device: Option<&str>, profile: &str) -> Value {
    let mut v = common::edge::query("b1", seq, &ts(Timestamp::now()), qname, None);
    v["client"] = json!(client);
    v["device"] = json!(device);
    v["profile"] = json!(profile);
    v
}

/// C4 (core.md §12 Clients; api.md §5 `device`): a device the edges key by its client name gets
/// the MACs core knows for it: its client entry's, which are authoritative (not a MAC logged at
/// its address before the entry named it); an address-keyed device lists the MAC logged for its
/// address as a hint, with no `mac`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_keyed_by_a_client_name_carry_their_macs() {
    let c = core().await;
    for (name, mac) in [("office-pc", "aa:bb:cc:dd:ee:01"), ("tv", "AA:BB:CC:DD:EE:02")] {
        c.state
            .config
            .apply(
                EntityKind::Client,
                Op::Create(json!({"name": name, "macs": [mac]})),
                Actor::cli(),
                None,
            )
            .await
            .unwrap();
    }
    let edge = FakeEdge::registered(&c, "e1").await;
    post(
        &edge,
        &[
            q_rec(1, "a.example", "192.168.1.50", Some("02:11:22:33:44:55"), "kids"),
            q_rec(2, "b.example", "192.168.1.50", Some("office-pc"), "kids"),
            q_rec(3, "c.example", "192.168.1.60", Some("tv"), "kids"),
            q_rec(4, "d.example", "192.168.1.70", Some("02:66:77:88:99:aa"), "kids"),
            q_rec(5, "e.example", "192.168.1.70", None, "kids"),
        ],
    )
    .await;
    let (st, v) = get(&c, "/devices").await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let dev = |key: &str| {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["key"] == key)
            .cloned()
            .unwrap_or_else(|| panic!("no device {key}: {v}"))
    };
    // Its client entry's MACs are authoritative (review Q2): the MAC logged at its address
    // earlier isn't listed.
    let pc = dev("office-pc");
    assert_eq!(pc["mac"], "aa:bb:cc:dd:ee:01", "{pc}");
    assert_eq!(pc["macs"], json!(["aa:bb:cc:dd:ee:01"]), "{pc}");
    assert_eq!(pc["client"], "office-pc");
    let tv = dev("tv");
    assert_eq!(tv["mac"], "aa:bb:cc:dd:ee:02", "{tv}");
    // An address-keyed device lists the MAC logged at its address but has no `mac`.
    let by_ip = dev("192.168.1.70");
    assert_eq!(by_ip["macs"], json!(["02:66:77:88:99:aa"]), "{by_ip}");
    assert!(by_ip["mac"].is_null(), "{by_ip}");
    let mac_keyed = dev("02:11:22:33:44:55");
    assert_eq!(mac_keyed["mac"], "02:11:22:33:44:55");
    assert_eq!(mac_keyed["macs"], json!(["02:11:22:33:44:55"]));
}

/// F5 (core.md §12 Clients: the private-MAC mark acts on a device's MAC): a client-named device
/// has only a MAC core currently knows, its client entry's now. One whose entry names it by
/// `source_ips` has none, though a MAC was logged at its address before the entry named it (the
/// address may have changed hands since); another edge's records at the same address (another
/// network) give none either. When the entry's MACs are removed, or the entry is renamed, the
/// name in older records has no MAC any more: the mapping that put it there is gone. An
/// address-keyed device lists the MAC logged at its address as a hint, never as its `mac`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_macs_are_only_those_core_currently_knows() {
    let c = core().await;
    let client = |op: Op| {
        let c = &c;
        async move {
            c.state
                .config
                .apply(EntityKind::Client, op, Actor::cli(), None)
                .await
                .unwrap();
        }
    };
    for body in [
        json!({"name": "laptop", "source_ips": ["192.168.1.80"]}),
        json!({"name": "printer", "source_ips": ["192.168.1.90"]}),
        json!({"name": "phone", "macs": ["02:00:00:00:00:a1"]}),
        json!({"name": "tablet", "macs": ["02:00:00:00:00:b1"]}),
    ] {
        client(Op::Create(body)).await;
    }
    let e1 = FakeEdge::registered(&c, "e1").await;
    let e2 = FakeEdge::registered(&c, "e2").await;
    let base = Timestamp::now() - jiff::SignedDuration::from_mins(30);
    let at = |seq: u64, client: &str, device: Option<&str>, mins: i64| {
        let mut v = q_rec(seq, "x.example", client, device, "kids");
        v["ts"] = json!(ts(base + jiff::SignedDuration::from_mins(mins)));
        v
    };
    post(
        &e1,
        &[
            // laptop: its address under a MAC, then named there by its entry's source_ips.
            at(1, "192.168.1.80", Some("02:00:00:00:00:80"), 3),
            at(2, "192.168.1.80", Some("laptop"), 4),
            // printer: named, then its address went to a device the edge keys by MAC.
            at(3, "192.168.1.90", Some("printer"), 5),
            at(4, "192.168.1.90", Some("02:00:00:00:00:90"), 6),
            // phone and tablet: named by their entries' MACs.
            at(5, "192.168.1.100", Some("02:00:00:00:00:a1"), 7),
            at(6, "192.168.1.100", Some("phone"), 8),
            at(7, "192.168.1.110", Some("tablet"), 8),
            // An address-keyed device, with a MAC logged at its address before.
            at(8, "192.168.1.70", Some("02:66:77:88:99:aa"), 8),
            at(9, "192.168.1.70", None, 9),
        ],
    )
    .await;
    // Another network: the same addresses under other MACs, later, on e2.
    post(
        &e2,
        &[
            at(1, "192.168.1.80", Some("02:00:00:00:e2:80"), 10),
            at(2, "192.168.1.90", Some("02:00:00:00:e2:90"), 10),
            // The address-keyed device's address under another MAC there: its hint stays e1's.
            at(3, "192.168.1.70", Some("02:00:00:00:e2:70"), 10),
        ],
    )
    .await;
    let devices = || {
        let c = &c;
        async move {
            let (st, v) = get(c, "/devices").await;
            assert_eq!(st, StatusCode::OK, "{v}");
            v
        }
    };
    let dev = |v: &Value, key: &str| {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["key"] == key)
            .cloned()
            .unwrap_or_else(|| panic!("no device {key}: {v}"))
    };
    let v = devices().await;
    for key in ["laptop", "printer"] {
        let d = dev(&v, key);
        assert!(d["mac"].is_null(), "{d}");
        assert_eq!(d["macs"], json!([]), "{d}");
        assert_eq!(d["client"], key, "{d}");
    }
    let phone = dev(&v, "phone");
    assert_eq!(phone["mac"], "02:00:00:00:00:a1", "{phone}");
    assert_eq!(phone["macs"], json!(["02:00:00:00:00:a1"]), "{phone}");
    let by_ip = dev(&v, "192.168.1.70");
    assert_eq!(by_ip["macs"], json!(["02:66:77:88:99:aa"]), "{by_ip}");
    assert!(by_ip["mac"].is_null(), "{by_ip}");
    // The phone's entry loses its MAC (it names the phone by address now), and the tablet's
    // entry gives way to one of another name: the names in the older records have no MAC any
    // more.
    client(Op::Update(
        "phone".into(),
        json!({"name": "phone", "source_ips": ["192.168.1.100"]}),
    ))
    .await;
    client(Op::Delete("tablet".into())).await;
    client(Op::Create(
        json!({"name": "slate", "macs": ["02:00:00:00:00:b1"]}),
    ))
    .await;
    let v = devices().await;
    for key in ["phone", "tablet"] {
        let d = dev(&v, key);
        assert!(d["mac"].is_null(), "{key}: {d}");
        assert_eq!(d["macs"], json!([]), "{key}: {d}");
    }
    assert!(dev(&v, "tablet")["client"].is_null(), "no entry has the old name");
}

fn allow_rec(seq: u64, id: &str, device: &str, client: &str, action: &str, expires: Timestamp) -> Value {
    json!({"t": "allow", "ts": ts(Timestamp::now()), "boot": "b1", "seq": seq, "action": action, "allow_id": id,
           "client": client, "device": device, "kind": "dns", "target": format!("{id}.example"),
           "expires_at": ts(expires), "via": "extension"})
}

/// C6 (core.md §12: a view per device, "and per profile for its devices", with temporary
/// allows): the profile view lists the allows of the devices its records in the window name;
/// another profile's device's allow isn't listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_profile_view_lists_its_devices_temporary_allows() {
    let c = core().await;
    let edge = FakeEdge::registered(&c, "e1").await;
    let later = Timestamp::now() + jiff::SignedDuration::from_hours(1);
    post(
        &edge,
        &[
            q_rec(1, "a.example", "192.168.1.140", Some("emma-tablet"), "kids"),
            q_rec(2, "b.example", "192.168.1.141", None, "kids"),
            q_rec(3, "c.example", "192.168.1.150", Some("dad-pc"), "adults"),
            allow_rec(4, "a-1", "emma-tablet", "192.168.1.140", "created", later),
            allow_rec(5, "a-2", "dad-pc", "192.168.1.150", "created", later),
        ],
    )
    .await;
    // An address-keyed device's allow (no device name in the allow record).
    let mut by_ip = allow_rec(6, "a-3", "", "192.168.1.141", "created", later);
    by_ip["device"] = Value::Null;
    post(&edge, &[by_ip]).await;
    let (st, v) = get(&c, "/query-summary?profile=kids&window=1h").await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let mut ids: Vec<String> = v["temporary_allows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["allow_id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    assert_eq!(ids, ["a-1", "a-3"], "{v}");
    assert!(
        v["temporary_allows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["state"] == "active"),
        "{v}"
    );
    let (_, v) = get(&c, "/query-summary?device=dad-pc&window=1h").await;
    assert_eq!(v["temporary_allows"][0]["allow_id"], "a-2", "{v}");
}

/// Review Q3 (core.md §12 views per device and per profile; temporary allows are per edge,
/// api.md §5 `allow`): a profile's view lists the allows of its devices on the edges they were
/// seen on; the same address on another edge (another network) is another device, so its allow
/// isn't listed, with `edge` or without; a device view with `edge` lists that edge's allows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn summary_allows_keep_the_edge_of_their_device() {
    let c = core().await;
    let e1 = FakeEdge::registered(&c, "e1").await;
    let e2 = FakeEdge::registered(&c, "e2").await;
    let later = Timestamp::now() + jiff::SignedDuration::from_hours(1);
    let by_ip = |seq: u64, id: &str| {
        let mut a = allow_rec(seq, id, "", "192.168.1.141", "created", later);
        a["device"] = Value::Null;
        a
    };
    post(
        &e1,
        &[
            q_rec(1, "a.example", "192.168.1.141", None, "kids"),
            by_ip(2, "on-e1"),
        ],
    )
    .await;
    post(
        &e2,
        &[
            q_rec(1, "b.example", "192.168.1.141", None, "adults"),
            by_ip(2, "on-e2"),
        ],
    )
    .await;
    let ids = |v: &Value| -> Vec<String> {
        let mut ids: Vec<String> = v["temporary_allows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["allow_id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };
    let (st, v) = get(&c, "/query-summary?profile=kids&window=1h").await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(ids(&v), ["on-e1"], "{v}");
    let (_, v) = get(
        &c,
        &format!("/query-summary?profile=kids&window=1h&edge={}", e1.id),
    )
    .await;
    assert_eq!(ids(&v), ["on-e1"], "{v}");
    let (_, v) = get(
        &c,
        &format!("/query-summary?profile=kids&window=1h&edge={}", e2.id),
    )
    .await;
    assert_eq!(ids(&v), Vec::<String>::new(), "kids has no device on e2: {v}");
    let (_, v) = get(
        &c,
        &format!("/query-summary?device=192.168.1.141&window=1h&edge={}", e2.id),
    )
    .await;
    assert_eq!(ids(&v), ["on-e2"], "{v}");
    let (_, v) = get(&c, "/query-summary?device=192.168.1.141&window=1h").await;
    assert_eq!(
        ids(&v),
        ["on-e1", "on-e2"],
        "the device view over every edge: {v}"
    );
}

/// C7 and review Q4 (api.md §7 cursor pagination; core.md §9 Evidence): `GET
/// alerts/{id}/evidence` pages its copies newest stored first, whatever their event times (a
/// backfill or an edge's late spool stores older records later); each page carries the answers
/// its copies reference; the first page also the answers no copy references, the counts and the
/// rule; `total` counts every copy as the page was read. A copy stored while paging comes first
/// on a fresh first page, never behind the cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alert_evidence_pages_its_copies() {
    let c = core().await;
    let a = c
        .state
        .alerts
        .raise(picket_core::alerts::RaiseSpec::new(
            "dnssec_bogus",
            picket_core::alerts::Severity::Critical,
            "dnssec_bogus:paged.example",
            "paged",
            json!({}),
        ))
        .await
        .unwrap();
    let id = a.id;
    c.state
        .db
        .write(move |db| {
            let tx = db.transaction()?;
            // Stored in seq order; event times in another order.
            for (i, sec) in [(0i64, 2), (1, 0), (2, 4), (3, 1), (4, 3)] {
                tx.execute(
                    "INSERT INTO alert_evidence(alert_id, edge_id, boot, seq, ts, record_json) VALUES (?1, 'e', 'b', ?2, ?3, ?4)",
                    rusqlite::params![
                        id,
                        i,
                        format!("2026-11-24T10:00:0{sec}.000000Z"),
                        json!({"seq": i, "answer_id": format!("ans{i}")}).to_string()
                    ],
                )?;
                tx.execute(
                    "INSERT INTO alert_evidence_answers(alert_id, answer_id, source, wire) VALUES (?1, ?2, 'log', x'00')",
                    rusqlite::params![id, format!("ans{i}")],
                )?;
            }
            tx.execute(
                "INSERT INTO alert_evidence_answers(alert_id, answer_id, source, wire) VALUES (?1, 'dnskey:x', 'validator', x'00')",
                [id],
            )?;
            tx.execute(
                "INSERT INTO alert_evidence_counts(alert_id, kind, key, count) VALUES (?1, 'name', 'paged.example', 5)",
                [id],
            )?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let (st, p1) = get(&c, &format!("/alerts/{id}/evidence?limit=2")).await;
    assert_eq!(st, StatusCode::OK, "{p1}");
    let seqs = |p: &Value| -> Vec<i64> {
        p["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["seq"].as_i64().unwrap())
            .collect()
    };
    let answers = |p: &Value| -> Vec<String> {
        let mut v: Vec<String> = p["answers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["answer_id"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    };
    assert_eq!(seqs(&p1), [4, 3]);
    assert_eq!(p1["total"], 5);
    assert_eq!(answers(&p1), ["ans3", "ans4", "dnskey:x"]);
    assert_eq!(p1["counts"]["name"]["paged.example"], 5);
    let cur = p1["next_cursor"].as_str().expect("more pages").to_string();
    let (_, p2) = get(&c, &format!("/alerts/{id}/evidence?limit=2&cursor={cur}")).await;
    assert_eq!(seqs(&p2), [2, 1]);
    assert_eq!(answers(&p2), ["ans1", "ans2"], "only this page's answers");
    assert_eq!(p2["counts"], json!({}), "the counts come with the first page");
    // A copy stored now with the oldest event time (a late spool) doesn't land behind the cursor.
    c.state
        .db
        .write(move |db| {
            db.execute(
                "INSERT INTO alert_evidence(alert_id, edge_id, boot, seq, ts, record_json)
                 VALUES (?1, 'e', 'b', 5, '2026-11-24T09:00:00.000000Z', ?2)",
                rusqlite::params![id, json!({"seq": 5}).to_string()],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let cur = p2["next_cursor"].as_str().unwrap().to_string();
    let (_, p3) = get(&c, &format!("/alerts/{id}/evidence?limit=2&cursor={cur}")).await;
    assert_eq!(seqs(&p3), [0]);
    assert!(p3["next_cursor"].is_null());
    assert_eq!(p3["total"], 6, "exact as the page was read");
    let (_, fresh) = get(&c, &format!("/alerts/{id}/evidence?limit=2")).await;
    assert_eq!(seqs(&fresh), [5, 4], "the newest copy first");
    let (st, _) = get(&c, &format!("/alerts/{id}/evidence?cursor=!!")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = get(&c, &format!("/alerts/{id}/evidence?limit=0")).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // The default page holds every copy of a small alert.
    let (_, all) = get(&c, &format!("/alerts/{id}/evidence")).await;
    assert_eq!(seqs(&all), [5, 4, 3, 2, 1, 0]);
    assert!(all["next_cursor"].is_null());
}

/// C8 and C9 (core.md §12 Temporary allows; api.md §4 `revoked_allows`, §7 events): an allow
/// whose revoke the edge acknowledged is `revoked` (no longer `active`, listed as recent) while
/// its log hasn't reported the end; then `ended`. Allow records, revoke requests, acknowledgements
/// and passing expiries each send a coalesced `temp_allow` event naming the edge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_allows_and_temp_allow_events() {
    let c = core().await;
    let a = FakeEdge::registered(&c, "edge-a").await;
    let (mut ws, _) = a.session(hello("b1")).await;
    let mut events = c.state.events.subscribe();
    let later = Timestamp::now() + jiff::SignedDuration::from_hours(1);
    post(
        &a,
        &[allow_rec(
            1,
            "a-19",
            "emma-tablet",
            "192.168.1.140",
            "created",
            later,
        )],
    )
    .await;
    let ev = next_event(&mut events, "temp_allow").await;
    assert_eq!(ev["edges"], json!([a.id]), "{ev}");
    assert!(ev["ingested"].as_u64().unwrap() >= 1, "{ev}");
    let list = |state: &'static str| {
        let c = &c;
        async move {
            let (st, v) = get(c, &format!("/temp-allows?state={state}")).await;
            assert_eq!(st, StatusCode::OK, "{v}");
            v["items"].as_array().unwrap().clone()
        }
    };
    assert_eq!(list("active").await[0]["state"], "active");
    let rid = picket_core::edges::requests::revoke_allow(&c.state, &a.id, "a-19")
        .await
        .unwrap();
    let ev = next_event(&mut events, "temp_allow").await;
    assert!(ev["revoke_requested"].as_u64().unwrap() >= 1, "{ev}");
    let mut hb = heartbeat("b1", Timestamp::now(), 3000, 0);
    hb["applied"] = json!({"revoked_allows": rid});
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    let ev = next_event(&mut events, "temp_allow").await;
    assert_eq!(ev["revoke_acked"], 1, "{ev}");
    let recent = list("recent").await;
    assert_eq!(recent.len(), 1, "{recent:?}");
    assert_eq!(recent[0]["state"], "revoked");
    assert!(recent[0]["revoke_acked_at"].is_string());
    assert!(recent[0]["ended_at"].is_null());
    assert_eq!(recent[0]["revoke_pending"], false);
    assert!(list("active").await.is_empty(), "a revoked allow isn't active");
    // F11: the device's summary gives the allow the same state as GET temp-allows.
    let (st, sum) = get(&c, "/query-summary?device=emma-tablet").await;
    assert_eq!(st, StatusCode::OK, "{sum}");
    assert_eq!(sum["temporary_allows"][0]["allow_id"], "a-19", "{sum}");
    assert_eq!(sum["temporary_allows"][0]["state"], "revoked", "{sum}");
    // The edge's log reports the end: `ended`.
    post(
        &a,
        &[allow_rec(
            2,
            "a-19",
            "emma-tablet",
            "192.168.1.140",
            "revoked",
            later,
        )],
    )
    .await;
    until("the end recorded", || async {
        list("recent").await[0]["state"] == "ended"
    })
    .await;
    // A reported expiry passing sends an event too (no record arrives for it).
    let soon = Timestamp::now() + jiff::SignedDuration::from_millis(1500);
    post(
        &a,
        &[allow_rec(
            3,
            "a-20",
            "emma-tablet",
            "192.168.1.140",
            "created",
            soon,
        )],
    )
    .await;
    let ev = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let ev = next_event(&mut events, "temp_allow").await;
            if ev["expired"].as_u64().unwrap_or(0) >= 1 {
                return ev;
            }
        }
    })
    .await
    .expect("an expired event");
    assert_eq!(ev["edges"], json!([a.id]), "{ev}");
    until("the allow expired", || async {
        list("recent")
            .await
            .iter()
            .any(|x| x["allow_id"] == "a-20" && x["state"] == "expired")
    })
    .await;
}

/// F7 (api.md §7: the UI's client is generated from the OpenAPI document; README §2 Untrusted
/// input): every `limit` the document declares has the bounds core enforces: 0 and one past the
/// maximum are refused (`400` naming the range, nothing quietly clamped), the maximum is taken.
/// So are the backtest's `days` and `k`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_limit_has_the_bounds_core_enforces() {
    let c = core().await;
    // The objects the paths name: system feeds and bundles exist; a feed provider is added.
    let r = ui(&c, Method::POST, "/feed-providers")
        .json(
            &json!({"id": "p", "name": "P", "module": "http", "enabled": false,
                      "config": {"url": "https://lists.example/p.txt"}}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "{}", r.text().await.unwrap());
    let (st, doc) = get(&c, "/openapi.json").await;
    assert_eq!(st, StatusCode::OK);
    let mut checked = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        let Some(params) = item["get"]["parameters"].as_array() else {
            continue;
        };
        let Some(limit) = params.iter().find(|p| p["name"] == "limit") else {
            continue;
        };
        assert_eq!(limit["schema"]["minimum"], 1, "{path}");
        let max = limit["schema"]["maximum"]
            .as_u64()
            .unwrap_or_else(|| panic!("{path}: no maximum"));
        let rel = path.trim_start_matches("/api/ui/v1");
        let id = if rel.starts_with("/feeds/") {
            "manual-allow"
        } else if rel.starts_with("/bundles/") {
            "block-common"
        } else if rel.starts_with("/feed-providers/") {
            "p"
        } else {
            "1"
        };
        // The other required parameters, with a value they accept.
        let mut base = rel.replace("{id}", id) + "?";
        for p in params
            .iter()
            .filter(|p| p["in"] == "query" && p["required"] == true)
        {
            let v = p["schema"]["enum"][0].as_str().unwrap_or("x");
            base += &format!("{}={v}&", p["name"].as_str().unwrap());
        }
        for bad in [0, max + 1] {
            let (st, v) = get(&c, &format!("{base}limit={bad}")).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{base}limit={bad}: {v}");
            assert_eq!(v["error"]["message"], format!("limit: 1 to {max}"), "{base}: {v}");
        }
        let (st, v) = get(&c, &format!("{base}limit={max}")).await;
        assert!(
            st == StatusCode::OK || (rel == "/alerts/{id}/evidence" && st == StatusCode::NOT_FOUND),
            "{base}limit={max}: {st} {v}"
        );
        checked.push(rel.to_string());
    }
    assert!(checked.len() >= 25, "{checked:?}");
    for p in [
        "/top",
        "/logs",
        "/alerts/{id}/evidence",
        "/temp-allows",
        "/dnssec/queue",
        "/feeds",
    ] {
        assert!(checked.iter().any(|c| c == p), "{p}: {checked:?}");
    }
    for (q, ok) in [
        ("days=0", false),
        ("days=61", false),
        ("days=60", true),
        ("k=0.05", false),
        ("k=50.5", false),
        ("k=0.1", true),
    ] {
        let (st, v) = get(&c, &format!("/feed-providers/p/backtest?{q}")).await;
        assert_eq!(st == StatusCode::OK, ok, "{q}: {st} {v}");
        if !ok {
            assert_eq!(st, StatusCode::BAD_REQUEST, "{q}: {v}");
        }
    }
}

/// api.md §7, README §2 Bounded: a burst of alert changes (many raises, then a bulk delete of
/// them all) reaches the UI as coalesced `alert` events: at most one per second (plus the first,
/// sent at once), each listing at most 64 alerts once with their latest state, counting every
/// change; the delete's events name the deleted alerts with their kind. Before, each change was
/// its own event, and a bulk delete of thousands lagged every open socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_alert_changes_reaches_the_ui_coalesced_and_bounded() {
    use picket_core::alerts::{RaiseSpec, Severity};
    let c = core().await;
    let mut rx = c.state.events.subscribe();
    let started = tokio::time::Instant::now();
    const N: usize = 150;
    let mut ids = Vec::new();
    for i in 0..N {
        let spec = RaiseSpec::new(
            "feed_held",
            Severity::Warning,
            format!("feed_held:burst{i}"),
            "held",
            json!({}),
        )
        .feed(format!("burst{i}"));
        ids.push(c.state.alerts.raise(spec).await.unwrap().id);
    }
    assert_eq!(c.state.alerts.delete(ids.clone()).await.unwrap(), N);
    // Every change (N raises, N deletes) is counted by one event (another alert core raised
    // meanwhile would be counted too, so at least 2N), up to those naming the deleted alerts.
    let (mut events, mut changes, mut deleted) = (0u64, 0u64, std::collections::BTreeSet::new());
    let mut truncated = false;
    while changes < 2 * N as u64 || deleted.is_empty() {
        let ev = next_event(&mut rx, "alert").await;
        events += 1;
        changes += ev["changes"].as_u64().expect("changes");
        let listed = ev["alerts"].as_array().expect("alerts");
        assert!(listed.len() <= 64, "{ev}");
        truncated |= ev["alerts_truncated"] == json!(true);
        let mut seen = std::collections::BTreeSet::new();
        for a in listed {
            let id = a["id"].as_i64().unwrap();
            assert!(seen.insert(id), "each alert once: {ev}");
            if !ids.contains(&id) {
                continue;
            }
            assert_eq!(a["kind"], "feed_held", "{a}");
            if a["deleted"] == json!(true) {
                assert_eq!(a["state"], Value::Null, "{a}");
                deleted.insert(id);
            }
        }
    }
    assert!(truncated, "more than 64 changed alerts in one second");
    // One event per COALESCE_GAP (1 s) at most, plus the first: a rate bound, not a timing guess.
    let secs = started.elapsed().as_secs_f64();
    assert!(
        events as f64 <= secs + 2.0,
        "{events} alert events in {secs:.1} s for {} changes",
        2 * N
    );
}

/// The `alert` event's item for alert `id`, if it lists it.
fn listed(ev: &Value, id: i64) -> Option<Value> {
    ev["alerts"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["id"] == json!(id)).cloned())
}

/// Exports the configuration (`GET config/export`).
async fn export(c: &Core) -> Value {
    let r = ui(c, Method::GET, "/config/export").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.json().await.unwrap()
}

/// Restores `doc` (`PUT config/export`).
async fn restore(c: &Core, doc: &Value) {
    let r = ui(c, Method::PUT, "/config/export")
        .json(doc)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
}

/// K1 (core.md §2 Export and restore: "It looks atomic to the user"; api.md §7): the coalesced
/// `alert` events respect a restore. A deletion noted before it goes out before the `restore`
/// event, and an alert the restore brings back that is raised again after it is listed live
/// (open, its count), not as the deletion from before the restore. Before, a deletion stayed
/// sticky for its id until the next event, so delete → restore → raise within a second gave
/// `deleted: true, state: null` for an open alert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alert_events_respect_a_restore() {
    use picket_core::alerts::{AlertState, RaiseSpec, Severity};
    let c = core().await;
    // A wide gap between events of a type, so what is noted below waits while the restore runs
    // (without the restore boundary, the deletion would still be waiting after it).
    c.state.events.coalesced().set_gap(Duration::from_secs(5));
    let spec =
        || RaiseSpec::new("feed_held", Severity::Warning, "feed_held:k1", "held", json!({})).feed("k1");
    let mut rx = c.state.events.subscribe();
    let id = c.state.alerts.raise(spec()).await.unwrap().id;
    // The raise's event goes out at once (nothing was waiting); the next one waits for the gap.
    loop {
        let ev = next_event(&mut rx, "alert").await;
        if listed(&ev, id).is_some() {
            break;
        }
    }
    let doc = export(&c).await;
    assert_eq!(c.state.alerts.delete(vec![id]).await.unwrap(), 1);
    restore(&c, &doc).await;
    let again = c.state.alerts.raise(spec()).await.unwrap();
    assert_eq!(
        (again.id, again.count, again.state),
        (id, 2, AlertState::Open),
        "the restore brought the alert back"
    );
    let (mut restored, mut deleted_before) = (false, false);
    let after = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let ev = match rx.recv().await {
                Ok(ev) => ev,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(e) => panic!("events: {e}"),
            };
            match ev.kind.as_str() {
                "restore" => restored = true,
                "alert" => match listed(&ev.data, id) {
                    Some(a) if restored => return a,
                    Some(a) => deleted_before |= a["deleted"] == json!(true),
                    None => {}
                },
                _ => {}
            }
        }
    })
    .await
    .expect("the alert listed after the restore");
    assert_eq!(
        (
            after["state"].clone(),
            after["count"].clone(),
            after["deleted"].clone()
        ),
        (json!("open"), json!(2), json!(false)),
        "listed live after the restore: {after}"
    );
    assert!(deleted_before, "the deletion went out before the restore event");
}

/// K1 (core.md §2 "It looks atomic to the user"; api.md §7; review UE2): a feed run stored just
/// before a restore reaches the UI in a `feed_run` event before the `restore` event, never after
/// it (where a manual feed's editor would take a pre-restore save for one after the restore).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn feed_runs_stored_before_a_restore_go_out_before_its_event() {
    let c = core().await;
    // A wide gap between events of a type, so the second run's note waits while the restore runs.
    c.state.events.coalesced().set_gap(Duration::from_secs(5));
    let doc = export(&c).await;
    let run_ids = || async {
        c.state
            .db
            .read(|db| {
                let mut st =
                    db.prepare("SELECT id FROM feed_runs WHERE feed_id = 'manual-block' ORDER BY id")?;
                let v = st
                    .query_map([], |r| r.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, anyhow::Error>(v)
            })
            .await
            .unwrap()
    };
    let mut rx = c.state.events.subscribe();
    let lists = |ev: &Value, run: i64| {
        ev["runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["feed"] == "manual-block" && r["run"] == json!(run))
    };
    // The run a save stored: the feed's newest (the event names the run's final row).
    common::bundles::save(&c, "manual-block", "||k1-first.example^\n").await;
    let first = *run_ids().await.last().unwrap();
    // Its event goes out at once (nothing was waiting); the next one waits for the gap.
    loop {
        if lists(&next_event(&mut rx, "feed_run").await, first) {
            break;
        }
    }
    common::bundles::save(&c, "manual-block", "||k1-second.example^\n").await;
    let second = *run_ids().await.last().unwrap();
    assert_ne!(first, second);
    restore(&c, &doc).await;
    let mut before = false;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match rx.recv().await {
                Ok(ev) if ev.kind == "restore" => return,
                Ok(ev) if ev.kind == "feed_run" => before |= lists(&ev.data, second),
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("events: {e}"),
            }
        }
    })
    .await
    .expect("the restore event");
    assert!(
        before,
        "the run stored before the restore went out before its event"
    );
}
