//! Bundle and verdict-set activation end to end (edge.md §3, §10, §13, §17; bundles.md §4–§7;
//! build-and-test.md §5 "Convergence", "Bundles", "Hot and cold parts", "Verdict caches"): a real
//! edge against an in-process mock core whose objects bucket serves bundles and verdict sets
//! built with picket-bundle's writer.

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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use bundlekit::*;
use dnsh::*;
use picket_api::logs::BundleVersion;
use picket_api::time::Timestamp;
use picket_bundle::verdict::VerdictKind;
use picket_edge::service::{self, Options, Running, Tuning};
use support::{MockCore, wait_until, write_edge_json};

const T: Duration = Duration::from_secs(30);

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

fn tuning(d: &Dirs, synced: bool) -> Tuning {
    let mut t = Tuning {
        platform: Some(picket_edge::paths::HostPlatform::Debian),
        clock: Some(picket_edge::clock::Clock::fixed(synced)),
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
    t.bundles.start_retry = Duration::from_millis(200);
    t.bundles.follow_every = Duration::from_millis(500);
    t.bundles.refetch_backoff = (Duration::from_millis(100), Duration::from_millis(500));
    // Every delta of a chain on its own (a run per delta), as a big chain would go in runs.
    t.bundles.chain_run = 1;
    t.firewall.socket = d.run.join("no-helper.sock");
    t
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

fn ok_upstream() -> impl Fn(&Msg, &[u8]) -> Act + Send + Sync + 'static {
    |m: &Msg, _q: &[u8]| match m.qtype {
        1 => Act::Answer(Ans::records(vec![a(&m.qname, "93.184.216.34", 300)])),
        _ => Act::Answer(Ans::records(vec![])),
    }
}

fn config(up: &FakeUpstream, bundles: Value) -> Value {
    json!({
        "edge": {"id": "e-01", "name": "test-edge", "platform": "debian"},
        "listeners": [{"id": "lan-dns", "proto": "dns", "bind": "127.0.0.1:0"}],
        "default_profile": "default",
        "profiles": {"default": {"upstream": "g", "block": ["b"], "block_response": {"type": "nxdomain", "ttl": 10}}},
        "upstreams": {"up1": plain_upstream(up, "udp")},
        "upstream_groups": {"g": {"upstreams": ["up1"], "strategy": "failover"}},
        "bundles": bundles,
        "logging": {"spool_after_s": 1},
    })
}

/// True when `name` is blocked: NXDOMAIN with EDE 15.
async fn blocked(r: &Running, name: &str) -> bool {
    let addr = *r
        .edge
        .dns
        .listeners
        .local_addrs("lan-dns")
        .first()
        .expect("listener bound");
    let m = udp_q(addr, &Q::new(name, 1)).await;
    m.rcode == 3 && m.ede_codes().contains(&15)
}

async fn wait_live(r: &Running, id: &str) {
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.active().object_id.as_deref() == Some(id)
            && !edge.dns.listeners.local_addrs("lan-dns").is_empty())
        .await,
        "object {id} live; convergence {:?}",
        edge.convergence.load()
    );
}

/// Waits until bundle `b` runs head `id` complete (a plain `versions` entry).
async fn wait_head(r: &Running, b: &str, id: &str) {
    let edge = Arc::clone(&r.edge);
    let short = picket_api::ids::short_id(id).to_owned();
    assert!(
        wait_until(T, || {
            let rec = edge.bundles.record();
            rec.heads.get(b).is_some_and(|h| h.active == id && h.complete)
                && edge
                    .active()
                    .versions
                    .as_ref()
                    .is_some_and(|v| v.bundles.get(b) == Some(&BundleVersion::Plain(short.clone())))
        })
        .await,
        "bundle {b} at head {short}: versions {:?}, record {:?}",
        edge.active().versions,
        edge.bundles.record().heads.get(b)
    );
}

fn events(core: &MockCore, kind: &str) -> Vec<Value> {
    core.with(|s| {
        s.logs
            .iter()
            .filter(|l| l["t"] == "event" && l["kind"] == kind)
            .cloned()
            .collect()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn base_deltas_hot_cold_moves_and_a_head_without_a_cold_part() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    // v1: one hot key, two cold.
    let p1 = cold_if(&["cold1", "moveme"]);
    let lines1 = ["||hot.example^", "||cold1.example^", "||moveme.example^"];
    let b1 = build_bundle("b", &lines1, Some(&p1));
    assert!(!b1.cold_keys.is_empty(), "a cold part");
    let id1 = publish(&core, &b1.head, &b1.blobs);
    assert_eq!(id1, b1.head_blob.id);
    let cfg_id = core.set_config(&config(&up, json!({"b": id1})));
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg_id).await;
    wait_head(&r, "b", &id1).await;
    for n in [
        "hot.example",
        "cold1.example",
        "moveme.example",
        "x.moveme.example",
    ] {
        assert!(blocked(&r, n).await, "{n} blocked by v1");
    }
    assert!(!blocked(&r, "other.example").await);
    assert!(
        r.edge
            .metrics
            .snapshot()
            .cold
            .get("b")
            .is_some_and(|c| c.page_reads > 0),
        "cold keys were read from the page file"
    );
    // The files are on disk (Debian: data_dir holds hot and cold parts), with active.json.
    assert!(d.data.join("bundles/active.json").exists());
    assert!(d.data.join(format!("bundles/b/heads/{id1}.json")).exists());
    for f in page_files(&b1.head, &b1.blobs) {
        assert!(
            d.data.join(format!("bundles/b/cold/{f}")).exists(),
            "page file on disk"
        );
    }

    // v2 as deltas: `moveme` moves cold → hot, `hot` goes, `new` arrives (hot).
    let p2 = cold_if(&["cold1"]);
    let lines2 = ["||cold1.example^", "||moveme.example^", "||new.example^"];
    let (h2, s2, _hot2, _cold2) = incremental(
        &b1.head,
        &b1.blobs,
        &b1.hot_keys,
        &b1.cold_keys,
        &lines2,
        Some(&p2),
        1,
    );
    assert!(h2.shards.iter().any(|s| !s.deltas.is_empty()), "hot deltas");
    assert!(h2.cold_shards.iter().any(|s| !s.deltas.is_empty()), "cold deltas");
    let id2 = publish(&core, &h2, &s2);
    let cfg2 = core.set_config(&config(&up, json!({"b": id2})));
    core.changed(&cfg2);
    wait_live(&r, &cfg2).await;
    wait_head(&r, "b", &id2).await;
    for n in ["cold1.example", "moveme.example", "new.example"] {
        assert!(blocked(&r, n).await, "{n} blocked by v2");
    }
    assert!(!blocked(&r, "hot.example").await, "removed by v2");
    // Each step logged `activated` with its part, then the completion without one.
    let short2 = picket_api::ids::short_id(&id2).to_owned();
    assert!(
        wait_until(T, || {
            let ev = events(&core, "activated");
            let of2: Vec<&Value> = ev
                .iter()
                .filter(|e| e["bundle"] == "b" && e["head"] == short2.as_str())
                .collect();
            of2.iter().any(|e| e["part"] == "head")
                && of2
                    .iter()
                    .any(|e| e["part"].as_str().is_some_and(|p| p.starts_with("shards/")))
                && of2
                    .iter()
                    .any(|e| e["part"].as_str().is_some_and(|p| p.starts_with("cold_shards/")))
                && of2.iter().any(|e| e.get("part").is_none())
        })
        .await,
        "{:#?}",
        events(&core, "activated")
    );
    // `have` lists the active head first, then the previous one (api.md §3).
    let have = picket_edge::report::have(&r.edge);
    assert_eq!(have.bundles["b"], vec![id2.clone(), id1.clone()]);

    // v3: a full rebuild without a cold part. The previous cold part stays until the hot swaps
    // are done, then goes; every key it held is hot now.
    let b3 = build_bundle("b", &lines2, None);
    assert!(b3.head.cold_shards.is_empty());
    let id3 = publish(&core, &b3.head, &b3.blobs);
    let cfg3 = core.set_config(&config(&up, json!({"b": id3})));
    core.changed(&cfg3);
    wait_live(&r, &cfg3).await;
    wait_head(&r, "b", &id3).await;
    let b = r.edge.active().bundles.get("b").cloned().unwrap();
    assert!(
        matches!(b.cold(), picket_bundle::matcher::Cold::None),
        "the previous cold part is gone"
    );
    for n in ["cold1.example", "moveme.example", "new.example"] {
        assert!(blocked(&r, n).await, "{n} blocked by v3");
    }
    // Garbage: v1 is neither active nor previous any more; its head file goes.
    assert!(
        wait_until(T, || !d.data.join(format!("bundles/b/heads/{id1}.json")).exists()).await,
        "v1's head deleted"
    );
    assert!(
        d.data.join(format!("bundles/b/heads/{id2}.json")).exists(),
        "previous head kept"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_failing_its_checksum_fails_open_and_is_refetched() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let p1 = cold_if(&["cold"]);
    let b1 = build_bundle("b", &["||hot.example^", "||cold.example^"], Some(&p1));
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let cfg_id = core.set_config(&config(&up, json!({"b": id1})));
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg_id).await;
    wait_head(&r, "b", &id1).await;
    assert!(blocked(&r, "cold.example").await);
    // Corrupt the record page on disk.
    let pf = page_files(&b1.head, &b1.blobs).remove(0);
    let path = d.data.join(format!("bundles/b/cold/{pf}"));
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[4096 + 40] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    // The cold lookup fails open (unchecked), and the file is fetched again.
    assert!(
        !blocked(&r, "cold.example").await,
        "fails open while the page can't be read"
    );
    assert!(
        wait_until(T, || !events(&core, "page_file_refetched").is_empty()).await,
        "page_file_refetched logged"
    );
    assert_eq!(events(&core, "page_file_refetched")[0]["bundle"], "b");
    assert!(
        wait_until(T, || r
            .edge
            .metrics
            .snapshot()
            .cold
            .get("b")
            .is_some_and(|c| c.unchecked > 0))
        .await
    );
    assert!(
        wait_until(T, || std::fs::read(&path)
            .is_ok_and(|b| picket_api::ids::object_id(&b) == pf))
        .await,
        "the page file is back"
    );
    let mut ok = false;
    for _ in 0..50 {
        if blocked(&r, "cold.example").await {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "checked again once the file is back");
    // The query that couldn't be checked says so in its record (api.md §5 `cold_unchecked`).
    assert!(
        wait_until(T, || core.with(|s| s.logs.iter().any(|l| l["t"] == "q"
            && l["qname"] == "cold.example"
            && l["cold_unchecked"]
                .as_array()
                .is_some_and(|a| a.contains(&json!("b"))))))
        .await
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_head_over_the_budget_is_held_and_the_running_one_stays() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let b1 = build_bundle("b", &["||one.example^"], None);
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let cfg1 = core.set_config(&config(&up, json!({"b": id1})));
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "b", &id1).await;
    // The next head would push the edge past `bundle_budget_mib` 0.
    let b2 = build_bundle("b", &["||one.example^", "||two.example^"], None);
    let id2 = publish(&core, &b2.head, &b2.blobs);
    let mut c2 = config(&up, json!({"b": id2}));
    c2["memory"] = json!({"bundle_budget_mib": 0, "overlay_budget_mib": 4});
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed")
            .iter()
            .any(|e| e["bundle"] == "b" && e["stage"] == "budget"))
        .await,
        "{:#?}",
        events(&core, "activation_failed")
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        r.edge.active().object_id.as_deref(),
        Some(cfg1.as_str()),
        "the running object stays"
    );
    assert!(blocked(&r, "one.example").await);
    assert!(!blocked(&r, "two.example").await);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_mid_activation_then_an_offline_start_from_disk() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let p1 = cold_if(&["cold"]);
    let lines1 = ["||hot.example^", "||cold.example^"];
    let b1 = build_bundle("b", &lines1, Some(&p1));
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let cfg1 = core.set_config(&config(&up, json!({"b": id1})));
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "b", &id1).await;
    // v2 can't finish: one of its deltas isn't served yet.
    let lines2 = [
        "||hot.example^",
        "||cold.example^",
        "||new.example^",
        "||colder.example^",
    ];
    let (h2, s2, _, _) = incremental(
        &b1.head,
        &b1.blobs,
        &b1.hot_keys,
        &b1.cold_keys,
        &lines2,
        Some(&p1),
        1,
    );
    let id2 = publish(&core, &h2, &s2);
    let withheld = h2.shards[0].deltas[0].blake3.clone();
    let withheld_bytes = core.with(|s| s.objects.remove(&format!("blobs/{withheld}")).unwrap());
    let cfg2 = core.set_config(&config(&up, json!({"b": id2})));
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed").iter().any(
            |e| e["bundle"] == "b" && e["head"] == picket_api::ids::short_id(&id2)
        ))
        .await
    );
    let rec = r.edge.bundles.record();
    assert_eq!(rec.heads["b"].active, id2);
    assert!(!rec.heads["b"].complete, "recorded part-way");
    assert_eq!(rec.heads["b"].previous.as_deref(), Some(id1.as_str()));
    assert!(
        blocked(&r, "hot.example").await,
        "the parts already active keep deciding"
    );
    r.shutdown().await;

    // A restart with core up and the delta now served: the edge carries on to v2.
    core.with(|s| s.objects.insert(format!("blobs/{withheld}"), withheld_bytes));
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg2).await;
    wait_head(&r, "b", &id2).await;
    assert!(blocked(&r, "new.example").await);
    assert!(blocked(&r, "colder.example").await);
    r.shutdown().await;

    // Core down for good: the edge starts from what is on disk (active.json and the files).
    drop(core);
    let r = start(&d, tuning(&d, true)).await;
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.active().config.is_some()
            && !edge.dns.listeners.local_addrs("lan-dns").is_empty())
        .await,
        "serves from disk without core"
    );
    wait_head(&r, "b", &id2).await;
    for n in ["hot.example", "cold.example", "new.example", "colder.example"] {
        assert!(blocked(&r, n).await, "{n} from disk");
    }
    r.shutdown().await;

    // A head recorded part-way whose files are gone falls back to its previous, complete head.
    let mut rec = picket_edge::bundles::record::Record::load(&d.data.join("bundles")).unwrap();
    let e = rec.heads.get_mut("b").unwrap();
    e.active = id2.clone();
    e.previous = Some(id1.clone());
    e.complete = false;
    rec.save(&d.data.join("bundles")).unwrap();
    std::fs::remove_file(d.data.join(format!("bundles/b/blobs/{withheld}"))).unwrap();
    let r = start(&d, tuning(&d, true)).await;
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.active().config.is_some()).await,
        "starts on the previous head"
    );
    let v = edge.active().versions.clone().unwrap();
    assert_eq!(
        v.bundles.get("b"),
        Some(&BundleVersion::Plain(picket_api::ids::short_id(&id1).to_owned()))
    );
    r.shutdown().await;
}

fn lookup_config(up: &FakeUpstream, sets: Value) -> Value {
    let mut c = config(up, json!({}));
    c["profiles"]["default"]["block"] = json!([]);
    c["profiles"]["default"]["lookups"] = json!([{"provider": "vp", "mode": "sync"}]);
    c["profiles"]["default"]["lookup_budget_ms"] = 500.into();
    c["lookup_providers"] = json!({"vp": {"module": "scripted", "config": {}, "cache_generation": "0123456789abcdef",
        "sync_timeout_ms": 500, "async_timeout_ms": 2000, "fail_mode": "open",
        "scope": {"exclude_bundles": [], "qtypes": ["A", "AAAA"]}}});
    c["verdict_sets"] = sets;
    c
}

fn scripted() -> (
    Arc<picket_lookup::testkit::ScriptedModule>,
    Arc<picket_lookup::Registry>,
) {
    use picket_lookup::{Answer, Verdict};
    let module = picket_lookup::testkit::ScriptedModule::new("scripted", |_cfg, _name, _n| {
        Box::pin(async move {
            Ok(Answer {
                verdict: Verdict::Clean,
                detail: None,
            })
        })
    });
    let mut reg = picket_lookup::Registry::empty();
    reg.insert(module.clone());
    (module, Arc::new(reg))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_sets_answer_before_the_provider_base_and_delta() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let generation = "0123456789abcdef";
    let (vh, vs) = verdict_set(
        "vp",
        generation,
        &[
            ("listed.example", VerdictKind::Block),
            ("fine.example", VerdictKind::Clean),
        ],
    );
    let vid = publish_set(&core, &vh, &vs);
    let cfg = core.set_config(&lookup_config(&up, json!({"vp": vid})));
    let (module, reg) = scripted();
    let mut t = tuning(&d, true);
    t.lookup_registry = Some(reg);
    let r = start(&d, t).await;
    wait_live(&r, &cfg).await;
    assert!(
        wait_until(T, || r
            .edge
            .active()
            .versions
            .as_ref()
            .is_some_and(|v| v.not_loaded.is_empty()))
        .await,
        "the verdict set is loaded"
    );
    let addr = *r.edge.dns.listeners.local_addrs("lan-dns").first().unwrap();
    let m = udp_q(addr, &Q::new("listed.example", 1)).await;
    assert!(
        m.ede()
            .first()
            .is_some_and(|e| e.1.starts_with("lookup=vp verdict=block")),
        "{:?}",
        m.ede()
    );
    let m = udp_q(addr, &Q::new("fine.example", 1)).await;
    assert_eq!(m.rcode, 0);
    assert_eq!(module.calls(), 0, "the verdict set answered both");
    let _ = udp_q(addr, &Q::new("unknown.example", 1)).await;
    assert_eq!(module.calls(), 1, "a name the set lacks calls the provider");
    assert!(
        d.data.join(format!("verdicts/vp/blobs/{}", vh.base)).exists(),
        "the base page file on disk"
    );

    // A delta head: the same base plus one delta adding a Block.
    let seed = picket_bundle::hash::verdict_hash_seed("vp", generation);
    let rec = picket_bundle::verdict::VerdictRecord {
        verdict: VerdictKind::Block,
        obtained_at: Timestamp::now() - jiff::SignedDuration::from_secs(1),
        score: None,
        reason: Some("later".into()),
    };
    let (blob, hdr) = picket_bundle::verdict::write_delta(
        "vp",
        generation,
        &vh.base,
        1,
        vh.checksum,
        &[picket_bundle::verdict::VerdictChange {
            hash: picket_bundle::verdict::name_hash(seed, "later.example"),
            old: None,
            new: Some(rec),
        }],
        CREATED,
    )
    .unwrap();
    let mut vh2 = vh.clone();
    vh2.deltas.push(picket_bundle::head::DeltaRef {
        seq: 1,
        blake3: blob.id.clone(),
        size: blob.size(),
    });
    vh2.seq = 1;
    vh2.checksum = hdr.new_checksum;
    let mut vs2 = Store::new();
    vs2.insert(blob.id.clone(), blob.bytes.clone());
    let vid2 = publish_set(&core, &vh2, &vs2);
    let cfg2 = core.set_config(&lookup_config(&up, json!({"vp": vid2})));
    core.changed(&cfg2);
    wait_live(&r, &cfg2).await;
    let before = module.calls();
    let m = udp_q(addr, &Q::new("later.example", 1)).await;
    assert!(
        m.ede()
            .first()
            .is_some_and(|e| e.1.starts_with("lookup=vp verdict=block")),
        "{:?}",
        m.ede()
    );
    assert_eq!(module.calls(), before, "answered by the delta");
    assert_eq!(
        picket_edge::report::have(&r.edge).verdict_sets["vp"],
        vec![vid2.clone(), vid.clone()]
    );
    assert!(
        events(&core, "activated")
            .iter()
            .any(|e| e["verdict_set"] == "vp" && e["part"] == "set")
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_sets_wait_for_a_synchronised_clock() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let (vh, vs) = verdict_set(
        "vp",
        "0123456789abcdef",
        &[("listed.example", VerdictKind::Block)],
    );
    let vid = publish_set(&core, &vh, &vs);
    let cfg = core.set_config(&lookup_config(&up, json!({"vp": vid})));
    let (module, reg) = scripted();
    let mut t = tuning(&d, false);
    t.lookup_registry = Some(reg);
    let r = start(&d, t).await;
    wait_live(&r, &cfg).await;
    let addr = *r.edge.dns.listeners.local_addrs("lan-dns").first().unwrap();
    let m = udp_q(addr, &Q::new("listed.example", 1)).await;
    assert_eq!(
        m.rcode, 0,
        "a record's expiry can't be judged yet: the set answers nothing"
    );
    assert_eq!(module.calls(), 1, "the provider answers instead");
    r.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// The SSD (edge-unifi.md §1), with its checks stood in for: the real ones need a second
// filesystem. Its files are hidden (renamed away) while it counts as unmounted.

struct Ssd {
    ok: Arc<std::sync::atomic::AtomicBool>,
    vol: PathBuf,
    root: PathBuf,
    own: PathBuf,
}

fn ssd(d: &Dirs) -> Ssd {
    let vol = d._tmp.path().join("volume1");
    let root = vol.join(".picket");
    for sub in ["bundles", "spool", "verdicts"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    let own = d._tmp.path().join("own-mountinfo");
    std::fs::write(&own, "0").unwrap();
    Ssd {
        ok: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        vol,
        root,
        own,
    }
}

impl Ssd {
    fn tune(&self, t: &mut Tuning) {
        t.mounts = picket_edge::storage::MountTables {
            host: self.own.clone(),
            own: self.own.clone(),
        };
        let ok = Arc::clone(&self.ok);
        t.storage.ssd_check = Some(Arc::new(move || {
            if ok.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(())
            } else {
                Err(picket_edge::storage::SsdFailure::Unmounted)
            }
        }));
    }
    /// Mounts or unmounts it (the edge notices the mount table change within a second).
    fn set(&self, on: bool) {
        self.ok.store(on, std::sync::atomic::Ordering::SeqCst);
        let n: u64 = std::fs::read_to_string(&self.own).unwrap().parse().unwrap();
        std::fs::write(&self.own, (n + 1).to_string()).unwrap();
    }
    fn hide(&self) {
        std::fs::rename(&self.vol, self.vol.with_file_name("volume1-away")).unwrap();
    }
    fn unhide(&self) {
        std::fs::rename(self.vol.with_file_name("volume1-away"), &self.vol).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_reboot_with_core_down_the_edge_starts_once_the_ssd_mounts() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    let s = ssd(&d);
    write_edge_json(&d.config, Some(&core), json!({"ssd_dir": s.root}));
    let b1 = build_bundle("b", &["||one.example^"], None);
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let cfg1 = core.set_config(&config(&up, json!({"b": id1})));
    let mut t = tuning(&d, true);
    s.tune(&mut t);
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "b", &id1).await;
    assert!(
        s.root.join("bundles/active.json").exists(),
        "the record is on the SSD"
    );
    assert!(!d.data.join("bundles/active.json").exists(), "no eMMC copy");
    assert!(
        wait_until(T, || r
            .edge
            .state
            .get()
            .configs
            .first()
            .is_some_and(|c| c.object == cfg1))
        .await,
        "the config is stored"
    );
    r.shutdown().await;

    // A reboot (a firmware update, say) with core down: UniFi mounts the drive only after boot.
    drop(core);
    s.hide();
    s.set(false);
    let mut t = tuning(&d, true);
    s.tune(&mut t);
    let r = start(&d, t).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        r.edge.dns.listeners.local_addrs("lan-dns").is_empty(),
        "no bundles yet: nothing bound (edge.md §3)"
    );
    s.unhide();
    s.set(true);
    let edge = Arc::clone(&r.edge);
    assert!(
        wait_until(T, || edge.active().config.is_some()
            && !edge.dns.listeners.local_addrs("lan-dns").is_empty())
        .await,
        "serves from the SSD once it mounts; record {:?}",
        edge.bundles.record()
    );
    assert!(blocked(&r, "one.example").await);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_emmc_copy_is_kept_until_the_ssd_holds_everything_and_a_failed_move_is_retried() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    let s = ssd(&d);
    write_edge_json(&d.config, Some(&core), json!({"ssd_dir": s.root}));
    let b1 = build_bundle("b", &["||one.example^"], None);
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let cfg1 = core.set_config(&config(&up, json!({"b": id1})));
    // The SSD fails from the start, past the start window: the hot files go to an eMMC copy.
    s.set(false);
    let mut t = tuning(&d, true);
    s.tune(&mut t);
    t.storage.start_window = Duration::ZERO;
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "b", &id1).await;
    let emmc = d.data.join("bundles");
    assert!(
        wait_until(T, || emmc.join("active.json").exists()).await,
        "the eMMC copy"
    );
    // The drive returns, but writes there fail between checks (UniFi pulling it, say).
    std::fs::write(s.root.join("bundles/b"), "in the way").unwrap();
    s.set(true);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        emmc.join("active.json").exists() && emmc.join(format!("b/heads/{id1}.json")).exists(),
        "the eMMC copy stays while the SSD lacks its files"
    );
    assert!(blocked(&r, "one.example").await);
    // Once writes work again, the move is retried without another state change.
    std::fs::remove_file(s.root.join("bundles/b")).unwrap();
    assert!(
        wait_until(T, || !emmc.join("active.json").exists()
            && s.root.join("bundles/active.json").exists()
            && s.root.join(format!("bundles/b/heads/{id1}.json")).exists())
        .await,
        "moved to the SSD"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_replacing_one_bundle_with_another_fits_the_budget_alone() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    // Names that don't share structure, so the FST can't fold them away.
    let lines = |p: &str| {
        let mut x: u64 = if p == "x" { 7 } else { 11 };
        (0..45_000)
            .map(|i| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                format!("||{p}{}-{:012x}.example^", i, x >> 16)
            })
            .collect::<Vec<_>>()
    };
    let (lx, ly) = (lines("x"), lines("y"));
    let bx = build_bundle("x", &lx.iter().map(String::as_str).collect::<Vec<_>>(), None);
    let by = build_bundle("y", &ly.iter().map(String::as_str).collect::<Vec<_>>(), None);
    let idx = publish(&core, &bx.head, &bx.blobs);
    let idy = publish(&core, &by.head, &by.blobs);
    let mem = json!({"bundle_budget_mib": 1, "overlay_budget_mib": 4});
    let mut c1 = config(&up, json!({"x": idx}));
    c1["profiles"]["default"]["block"] = json!(["x"]);
    c1["memory"] = mem.clone();
    let cfg1 = core.set_config(&c1);
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg1).await;
    let mx = r.edge.active().bundles.get("x").unwrap().memory_usage();
    assert!(
        mx <= 1 << 20 && 2 * mx > 1 << 20,
        "x takes {mx} bytes: each bundle fits 1 MiB alone, both don't"
    );
    // Replace x with y: y alone fits the budget core checked.
    let mut c2 = config(&up, json!({"y": idy}));
    c2["profiles"]["default"]["block"] = json!(["y"]);
    c2["memory"] = mem;
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    wait_live(&r, &cfg2).await;
    let name = |l: &str| l.trim_start_matches("||").trim_end_matches('^').to_owned();
    assert!(blocked(&r, &name(&ly[7])).await);
    assert!(!blocked(&r, &name(&lx[7])).await);
    assert!(
        r.edge.active().bundles.get("x").is_none(),
        "x unloaded after the swap"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_firewall_changes_only_when_the_config_goes_live() {
    let h = helperkit::start();
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let b1 = build_bundle("b", &["||one.example^"], None);
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let mut c1 = config(&up, json!({"b": id1}));
    c1["firewall"] = json!({"interfaces": [{"name": "br0", "mode": "enforce"}], "ack_wait_ms": 1000});
    let cfg1 = core.set_config(&c1);
    let mut t = tuning(&d, true);
    t.firewall.socket = h.path.clone();
    t.firewall.seed_wait = Duration::from_millis(500);
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    let edge = Arc::clone(&r.edge);
    let jumped = || {
        h.rules("UBIOS_LAN_WAN_USER")
            .iter()
            .any(|x| x.contains("PICKET-FWD"))
    };
    assert!(wait_until(T, jumped).await, "the jump is in");
    // A config without the helper whose bundle can't be fetched: it never goes live.
    let b2 = build_bundle("b2", &["||two.example^"], None);
    let id2 = publish(&core, &b2.head, &b2.blobs);
    core.with(|s| {
        let k = b2.blobs.keys().next().unwrap();
        s.objects.remove(&format!("blobs/{k}"));
    });
    let mut c2 = config(&up, json!({"b2": id2}));
    c2["profiles"]["default"]["block"] = json!(["b2"]);
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed")
            .iter()
            .any(|e| e["bundle"] == "b2"))
        .await
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(edge.active().object_id.as_deref(), Some(cfg1.as_str()));
    assert!(edge.fw.needed(), "the running config still uses the helper");
    assert!(
        jumped(),
        "its jump is still in: {:?}",
        h.rules("UBIOS_LAN_WAN_USER")
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_manifest_for_another_shard_is_refused() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let lines: Vec<String> = (0..40).map(|i| format!("||n{i}.example^")).collect();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let c = compile(&refs);
    let mut o = picket_bundle::compile::BuildOptions::new("b", picket_rules::matcher::BundleAction::Block);
    o.max_shard_keys = 16;
    let b1 = picket_bundle::compile::build(&c, &o).unwrap();
    assert!(b1.head.shards.len() >= 2, "{} shards", b1.head.shards.len());
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let cfg1 = core.set_config(&config(&up, json!({"b": id1})));
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "b", &id1).await;
    // The next head names shard 1's base for shard 0 (with its seq and checksum).
    let mut h2 = b1.head.clone();
    let s1 = h2.shards[1].clone();
    h2.shards[0].base = s1.base.clone();
    h2.shards[0].base_seq = s1.base_seq;
    h2.shards[0].seq = s1.seq;
    h2.shards[0].checksum = s1.checksum;
    h2.shards[0].deltas = s1.deltas.clone();
    h2.issued_at = "2026-11-21T02:00:00Z".into();
    let id2 = publish(&core, &h2, &b1.blobs);
    let cfg2 = core.set_config(&config(&up, json!({"b": id2})));
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed")
            .iter()
            .any(|e| e["bundle"] == "b" && e["stage"] == "verify"))
        .await,
        "{:#?}",
        events(&core, "activation_failed")
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delta_bigger_than_the_budget_is_refused_before_it_is_fetched() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let lines1 = ["||one.example^"];
    let b1 = build_bundle("b", &lines1, None);
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let cfg1 = core.set_config(&config(&up, json!({"b": id1})));
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "b", &id1).await;
    let (mut h2, s2, _, _) = incremental(
        &b1.head,
        &b1.blobs,
        &b1.hot_keys,
        &b1.cold_keys,
        &["||one.example^", "||two.example^"],
        None,
        1,
    );
    // The head says the delta is 100 MiB: more than this edge's overlays could ever hold.
    let dk = h2.shards[0].deltas[0].blake3.clone();
    h2.shards[0].deltas[0].size = 100 << 20;
    let id2 = publish(&core, &h2, &s2);
    let mut c2 = config(&up, json!({"b": id2}));
    c2["memory"] = json!({"bundle_budget_mib": 64, "overlay_budget_mib": 4});
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed")
            .iter()
            .any(|e| e["bundle"] == "b" && e["stage"] == "verify"))
        .await,
        "{:#?}",
        events(&core, "activation_failed")
    );
    assert_eq!(
        core.with(|s| s.object_gets.get(&format!("blobs/{dk}")).copied().unwrap_or(0)),
        0,
        "never fetched"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_verdict_set_head_that_fails_leaves_the_running_configs_versions_alone() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let generation = "0123456789abcdef";
    let (vh, vs) = verdict_set("vp", generation, &[("listed.example", VerdictKind::Block)]);
    let vid = publish_set(&core, &vh, &vs);
    let cfg1 = core.set_config(&lookup_config(&up, json!({"vp": vid})));
    let (_module, reg) = scripted();
    let mut t = tuning(&d, true);
    t.lookup_registry = Some(reg);
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    let edge = Arc::clone(&r.edge);
    let loaded = || {
        edge.active()
            .versions
            .as_ref()
            .is_some_and(|v| v.not_loaded.is_empty())
    };
    assert!(wait_until(T, loaded).await);
    // The next config adds provider vq, whose set can't be fetched: it never goes live.
    let (qh, qs) = verdict_set("vq", generation, &[("other.example", VerdictKind::Block)]);
    let qid = publish_set(&core, &qh, &qs);
    core.with(|s| s.objects.remove(&format!("blobs/{}", qh.base)));
    let mut c2 = lookup_config(&up, json!({"vp": vid, "vq": qid}));
    c2["lookup_providers"]["vq"] = c2["lookup_providers"]["vp"].clone();
    c2["profiles"]["default"]["lookups"] =
        json!([{"provider": "vp", "mode": "sync"}, {"provider": "vq", "mode": "sync"}]);
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed")
            .iter()
            .any(|e| e["verdict_set"] == "vq"))
        .await
    );
    // A few follower rounds later, the running config's versions still say all is loaded.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(edge.active().object_id.as_deref(), Some(cfg1.as_str()));
    assert!(loaded(), "{:?}", edge.active().versions);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_file_still_bad_after_its_refetch_backs_off() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let p1 = cold_if(&["cold"]);
    let b1 = build_bundle("b", &["||hot.example^", "||cold.example^"], Some(&p1));
    // Core itself serves a page file with a broken page (its BLAKE3 matches what it names).
    let mut head = b1.head.clone();
    let mut blobs = b1.blobs.clone();
    let base = head.cold_shards[0].base.clone();
    let mut m = picket_bundle::head::Manifest::from_bytes(&blobs[&base]).unwrap();
    let pf = m.files[picket_bundle::head::COLD_PAGES].blake3.clone();
    let mut bad = blobs[&pf].clone();
    bad[4096 + 40] ^= 0xff;
    let bad_id = picket_api::ids::object_id(&bad);
    blobs.insert(bad_id.clone(), bad);
    m.files.get_mut(picket_bundle::head::COLD_PAGES).unwrap().blake3 = bad_id.clone();
    let (mb, mid) = m.to_blob();
    blobs.insert(mid.clone(), mb);
    head.cold_shards[0].base = mid;
    let id1 = publish(&core, &head, &blobs);
    let cfg = core.set_config(&config(&up, json!({"b": id1})));
    let mut t = tuning(&d, true);
    t.bundles.refetch_backoff = (Duration::from_secs(5), Duration::from_secs(30));
    let r = start(&d, t).await;
    wait_live(&r, &cfg).await;
    wait_head(&r, "b", &id1).await;
    let gets = || {
        core.with(|s| {
            s.object_gets
                .get(&format!("blobs/{bad_id}"))
                .copied()
                .unwrap_or(0)
        })
    };
    let first = gets();
    for _ in 0..20 {
        assert!(!blocked(&r, "cold.example").await, "fails open");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        gets() <= first + 1,
        "one refetch, then a backoff: {} downloads",
        gets() - first
    );
    assert!(
        wait_until(T, || events(&core, "page_file_refetched")
            .iter()
            .any(|e| e["still_bad"] == true))
        .await,
        "{:#?}",
        events(&core, "page_file_refetched")
    );
    r.shutdown().await;
}

/// A config that moves an existing provider to a new set head and then fails leaves the running
/// config's set as it was: no head flips back and forth between the follower and the retries
/// (edge.md §13).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_config_never_swaps_a_running_providers_set() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let generation = "0123456789abcdef";
    let (vh, vs) = verdict_set("vp", generation, &[("listed.example", VerdictKind::Block)]);
    let vid = publish_set(&core, &vh, &vs);
    let cfg1 = core.set_config(&lookup_config(&up, json!({"vp": vid})));
    let (_module, reg) = scripted();
    let mut t = tuning(&d, true);
    t.lookup_registry = Some(reg);
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    let edge = Arc::clone(&r.edge);
    let loaded = || {
        edge.active()
            .versions
            .as_ref()
            .is_some_and(|v| v.not_loaded.is_empty())
    };
    assert!(wait_until(T, loaded).await);
    // The next config moves vp to a new head and adds vq, whose set can't be fetched.
    let (vh2, vs2) = verdict_set("vp", generation, &[("listed2.example", VerdictKind::Block)]);
    let vid2 = publish_set(&core, &vh2, &vs2);
    let (qh, qs) = verdict_set("vq", generation, &[("other.example", VerdictKind::Block)]);
    let qid = publish_set(&core, &qh, &qs);
    core.with(|s| s.objects.remove(&format!("blobs/{}", qh.base)));
    let mut c2 = lookup_config(&up, json!({"vp": vid2, "vq": qid}));
    c2["lookup_providers"]["vq"] = c2["lookup_providers"]["vp"].clone();
    c2["profiles"]["default"]["lookups"] =
        json!([{"provider": "vp", "mode": "sync"}, {"provider": "vq", "mode": "sync"}]);
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed")
            .iter()
            .any(|e| e["verdict_set"] == "vq"))
        .await
    );
    let mut heads = Vec::new();
    let mut not_loaded = 0;
    for _ in 0..40 {
        if let Some(s) = edge.bundles.record().sets.get("vp")
            && heads.last() != Some(&s.active)
        {
            heads.push(s.active.clone());
        }
        if !loaded() {
            not_loaded += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let acts = events(&core, "activated")
        .iter()
        .filter(|e| e["verdict_set"] == "vp" && e.get("part").is_none())
        .count();
    assert_eq!(edge.active().object_id.as_deref(), Some(cfg1.as_str()));
    assert_eq!(heads, vec![vid.clone()], "the running config's head throughout");
    assert_eq!((acts, not_loaded), (1, 0), "no flip-flop");
    r.shutdown().await;
}

/// The eMMC copy's fill is tracked as such: an activation step writing the copy's `active.json`
/// doesn't make a fill that failed count as done (edge-unifi.md §1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_emmc_fill_is_retried_after_an_activation_writes_the_record() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    let s = ssd(&d);
    write_edge_json(&d.config, Some(&core), json!({"ssd_dir": s.root}));
    let ba = build_bundle("a", &["||one.example^"], None);
    let ida = publish(&core, &ba.head, &ba.blobs);
    let bb1 = build_bundle("b", &["||two.example^"], None);
    let idb1 = publish(&core, &bb1.head, &bb1.blobs);
    let mut c1 = config(&up, json!({"a": ida, "b": idb1}));
    c1["profiles"]["default"]["block"] = json!(["a", "b"]);
    let cfg1 = core.set_config(&c1);
    let mut t = tuning(&d, true);
    s.tune(&mut t);
    t.storage.start_window = Duration::ZERO;
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "a", &ida).await;
    wait_head(&r, "b", &idb1).await;
    // Core loses bundle a's files for a while, then the SSD fails: the fill fails.
    let saved: Vec<(String, Vec<u8>)> = core.with(|st| {
        let keys: Vec<String> = st
            .objects
            .keys()
            .filter(|k| k.starts_with("bundles/a/") || ba.blobs.keys().any(|b| **k == format!("blobs/{b}")))
            .cloned()
            .collect();
        keys.into_iter()
            .map(|k| {
                let v = st.objects.remove(&k).unwrap();
                (k, v)
            })
            .collect()
    });
    s.set(false);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    // A new head of b goes live: its steps write active.json into the eMMC copy.
    let bb2 = build_bundle("b", &["||three.example^"], None);
    let idb2 = publish(&core, &bb2.head, &bb2.blobs);
    let mut c2 = config(&up, json!({"a": ida, "b": idb2}));
    c2["profiles"]["default"]["block"] = json!(["a", "b"]);
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    wait_live(&r, &cfg2).await;
    // Core has a's files again: a later follower round completes the fill.
    core.with(|st| {
        for (k, v) in saved {
            st.objects.insert(k, v);
        }
    });
    let emmc = d.data.join("bundles");
    assert!(
        wait_until(T, || emmc.join(format!("a/heads/{ida}.json")).exists()).await,
        "the eMMC copy lacks bundle a: a restart with core down couldn't start"
    );
    r.shutdown().await;
}

/// Moving to the SSD copies every head a restart may load, not just each bundle's newest: while
/// a config that moved a bundle to a new head hasn't gone live, the running config still needs
/// the old head's files (edge-unifi.md §1; edge.md §3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moving_to_the_ssd_keeps_the_running_configs_heads() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    let s = ssd(&d);
    write_edge_json(&d.config, Some(&core), json!({"ssd_dir": s.root}));
    let b1 = build_bundle("b", &["||one.example^"], None);
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let cfg1 = core.set_config(&config(&up, json!({"b": id1})));
    // The SSD fails from the start, past the start window: the hot files go to an eMMC copy.
    s.set(false);
    let mut t = tuning(&d, true);
    s.tune(&mut t);
    t.storage.start_window = Duration::ZERO;
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "b", &id1).await;
    let emmc = d.data.join("bundles");
    assert!(wait_until(T, || emmc.join("active.json").exists()).await);
    // The next config moves b to a new head (complete) and adds c, which can't be fetched: it
    // never goes live, so the running config still names b's first head.
    let b2 = build_bundle("b", &["||two.example^"], None);
    let id2 = publish(&core, &b2.head, &b2.blobs);
    let bc = build_bundle("c", &["||three.example^"], None);
    let idc = publish(&core, &bc.head, &bc.blobs);
    core.with(|st| {
        for k in bc.blobs.keys() {
            st.objects.remove(&format!("blobs/{k}"));
        }
    });
    let mut c2 = config(&up, json!({"b": id2, "c": idc}));
    c2["profiles"]["default"]["block"] = json!(["b", "c"]);
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed")
            .iter()
            .any(|e| e["bundle"] == "c"))
        .await
    );
    assert!(
        wait_until(T, || r
            .edge
            .active()
            .bundles
            .get("b")
            .is_some_and(|x| x.head() == id2))
        .await
    );
    assert_eq!(r.edge.active().object_id.as_deref(), Some(cfg1.as_str()));
    // The SSD returns: the move copies what a restart needs, then deletes the eMMC copy.
    s.set(true);
    assert!(
        wait_until(T, || !emmc.join("active.json").exists()).await,
        "moved to the SSD"
    );
    let dir = s.root.join("bundles/b");
    assert!(
        dir.join(format!("heads/{id1}.json")).exists(),
        "the running config's head"
    );
    for id in b1.blobs.keys() {
        assert!(
            dir.join(format!("blobs/{id}")).exists(),
            "blob {id} of the running head"
        );
    }
    r.shutdown().await;
}

/// Once the hot files are on the SSD, a follower round with nothing to move rewrites nothing
/// (here every round runs: a verdict set waits for a blob core lacks).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_follower_round_with_nothing_to_move_writes_nothing() {
    use std::os::unix::fs::MetadataExt;
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    let s = ssd(&d);
    write_edge_json(&d.config, Some(&core), json!({"ssd_dir": s.root}));
    let generation = "0123456789abcdef";
    let (vh, vs) = verdict_set("vp", generation, &[("listed.example", VerdictKind::Block)]);
    let vid = publish_set(&core, &vh, &vs);
    core.with(|st| st.objects.remove(&format!("blobs/{}", vh.base)));
    let b1 = build_bundle("b", &["||one.example^"], None);
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let mut c1 = lookup_config(&up, json!({"vp": vid}));
    c1["bundles"] = json!({"b": id1});
    c1["profiles"]["default"]["block"] = json!(["b"]);
    let cfg1 = core.set_config(&c1);
    // The config goes live while the SSD fails (verdict sets don't hold it up), then it passes.
    s.set(false);
    let (_module, reg) = scripted();
    let mut t = tuning(&d, true);
    s.tune(&mut t);
    t.lookup_registry = Some(reg);
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    s.set(true);
    let rec = s.root.join("bundles/active.json");
    assert!(wait_until(T, || rec.exists()).await);
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let ino = std::fs::metadata(&rec).unwrap().ino();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        !r.edge
            .active()
            .versions
            .as_ref()
            .unwrap()
            .not_loaded
            .verdict_sets
            .is_empty(),
        "the set still waits"
    );
    assert_eq!(
        std::fs::metadata(&rec).unwrap().ino(),
        ino,
        "active.json rewritten with nothing to move"
    );
    r.shutdown().await;
}

/// A page file still bad after its refetch isn't downloaded again when the failing reads come
/// further apart than the backoff (bundles.md §4 "Reading").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_file_still_bad_is_not_downloaded_again_by_rare_reads() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let p1 = cold_if(&["cold"]);
    let b1 = build_bundle("b", &["||hot.example^", "||cold.example^"], Some(&p1));
    // Core itself serves a page file with a broken page (its BLAKE3 matches what it names).
    let mut head = b1.head.clone();
    let mut blobs = b1.blobs.clone();
    let base = head.cold_shards[0].base.clone();
    let mut m = picket_bundle::head::Manifest::from_bytes(&blobs[&base]).unwrap();
    let pf = m.files[picket_bundle::head::COLD_PAGES].blake3.clone();
    let mut bad = blobs[&pf].clone();
    bad[4096 + 40] ^= 0xff;
    let bad_id = picket_api::ids::object_id(&bad);
    blobs.insert(bad_id.clone(), bad);
    m.files.get_mut(picket_bundle::head::COLD_PAGES).unwrap().blake3 = bad_id.clone();
    let (mb, mid) = m.to_blob();
    blobs.insert(mid.clone(), mb);
    head.cold_shards[0].base = mid;
    let id1 = publish(&core, &head, &blobs);
    let cfg = core.set_config(&config(&up, json!({"b": id1})));
    let mut t = tuning(&d, true);
    t.bundles.refetch_backoff = (Duration::from_millis(100), Duration::from_millis(300));
    let r = start(&d, t).await;
    wait_live(&r, &cfg).await;
    wait_head(&r, "b", &id1).await;
    let gets = || {
        core.with(|s| {
            s.object_gets
                .get(&format!("blobs/{bad_id}"))
                .copied()
                .unwrap_or(0)
        })
    };
    let first = gets();
    for _ in 0..6 {
        assert!(!blocked(&r, "cold.example").await, "fails open");
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    assert!(
        gets() <= first + 1,
        "one refetch, then no more: {} downloads",
        gets() - first
    );
    assert!(
        events(&core, "page_file_refetched")
            .iter()
            .any(|e| e["still_bad"] == true),
        "{:#?}",
        events(&core, "page_file_refetched")
    );
    r.shutdown().await;
}

/// A config that needs the room of a bundle it drops, and then fails, gives that bundle back to
/// the running config (bundles.md §6 "if memory is short"; edge.md §13: a config that doesn't go
/// live leaves the running one as it was).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_unloaded_to_make_room_comes_back_when_the_config_fails() {
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    let lines = |p: &str| {
        let mut x: u64 = if p == "x" { 7 } else { 11 };
        (0..45_000)
            .map(|i| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                format!("||{p}{}-{:012x}.example^", i, x >> 16)
            })
            .collect::<Vec<_>>()
    };
    let build = |name: &str, l: &[String]| {
        let refs: Vec<&str> = l.iter().map(String::as_str).collect();
        let mut o =
            picket_bundle::compile::BuildOptions::new(name, picket_rules::matcher::BundleAction::Block);
        o.max_shard_keys = 6_000;
        picket_bundle::compile::build(&compile(&refs), &o).unwrap()
    };
    let (lx, ly) = (lines("x"), lines("y"));
    let (bx, by) = (build("x", &lx), build("y", &ly));
    assert!(by.head.shards.len() >= 4, "{} shards", by.head.shards.len());
    let idx = publish(&core, &bx.head, &bx.blobs);
    let idy = publish(&core, &by.head, &by.blobs);
    // y's last shard can't be fetched: its load fails after x had to make room.
    let last = by.head.shards.iter().max_by_key(|s| s.shard).unwrap();
    let m = picket_bundle::head::Manifest::from_bytes(&by.blobs[&last.base]).unwrap();
    let fst = m.files[picket_bundle::head::DOMAINS_FST].blake3.clone();
    core.with(|st| st.objects.remove(&format!("blobs/{fst}")));
    let mem = json!({"bundle_budget_mib": 1, "overlay_budget_mib": 4});
    let mut c1 = config(&up, json!({"x": idx}));
    c1["profiles"]["default"]["block"] = json!(["x"]);
    c1["memory"] = mem.clone();
    let cfg1 = core.set_config(&c1);
    let r = start(&d, tuning(&d, true)).await;
    wait_live(&r, &cfg1).await;
    let mx = r.edge.active().bundles.get("x").unwrap().memory_usage();
    assert!(mx <= 1 << 20 && 2 * mx > 1 << 20, "x takes {mx} bytes");
    let name = |l: &str| l.trim_start_matches("||").trim_end_matches('^').to_owned();
    assert!(blocked(&r, &name(&lx[7])).await);
    let edge = Arc::clone(&r.edge);
    let gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watch = {
        let (edge, gone) = (Arc::clone(&edge), Arc::clone(&gone));
        tokio::spawn(async move {
            loop {
                if edge.active().bundles.get("x").is_none() {
                    gone.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };
    let mut c2 = config(&up, json!({"y": idy}));
    c2["profiles"]["default"]["block"] = json!(["y"]);
    c2["memory"] = mem;
    let cfg2 = core.set_config(&c2);
    core.changed(&cfg2);
    assert!(
        wait_until(T, || events(&core, "activation_failed")
            .iter()
            .any(|e| e["bundle"] == "y"))
        .await
    );
    assert!(
        wait_until(T, || edge.active().bundles.get("x").is_some()).await,
        "x is back"
    );
    watch.abort();
    assert!(
        gone.load(std::sync::atomic::Ordering::SeqCst),
        "x made room for y"
    );
    assert_eq!(edge.active().object_id.as_deref(), Some(cfg1.as_str()));
    assert!(
        blocked(&r, &name(&lx[7])).await,
        "the running config blocks with x again"
    );
    assert!(edge.active().bundles.get("y").is_none(), "y isn't held unused");
    r.shutdown().await;
}

/// build-and-test.md §5 "queries held across back-to-back swaps" (bundles.md §6 Activation: the
/// old part is freed when the last in-flight query drops it, and the next swap waits until it is
/// freed). A query held in a slow lookup keeps the state it loaded, hence the replaced shard,
/// alive; the second of two back-to-back hot swaps waits for it however long it takes (well past
/// the 2 s the edge used to wait), queries keep being answered meanwhile, and the held query
/// answers from the versions it started with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queries_held_across_back_to_back_swaps() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let up = FakeUpstream::plain(ok_upstream()).await;
    let core = MockCore::start().await;
    let d = dirs();
    write_edge_json(&d.config, Some(&core), json!({}));
    // A lookup that holds `held.example` until the test lets it go.
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let entered = Arc::new(AtomicBool::new(false));
    let (g, en) = (Arc::clone(&gate), Arc::clone(&entered));
    let module = picket_lookup::testkit::ScriptedModule::new("scripted", move |_cfg, name, _n| {
        let (g, en) = (Arc::clone(&g), Arc::clone(&en));
        Box::pin(async move {
            if name == "held.example" {
                en.store(true, Ordering::SeqCst);
                let _ = g.acquire().await;
            }
            Ok(picket_lookup::Answer {
                verdict: picket_lookup::Verdict::Clean,
                detail: None,
            })
        })
    });
    let mut reg = picket_lookup::Registry::empty();
    reg.insert(module);
    // v1: several hot shards; v2 adds keys to at least two of them (two hot swaps).
    let v1: Vec<String> = (0..8).map(|i| format!("||k{i}.example^")).collect();
    let v1: Vec<&str> = v1.iter().map(String::as_str).collect();
    let b1 = build_sharded("b", &v1, None, 2);
    assert!(b1.head.shards.len() >= 2, "several hot shards");
    let id1 = publish(&core, &b1.head, &b1.blobs);
    let mut v2: Vec<String> = v1.iter().map(|s| s.to_string()).collect();
    v2.extend((0..20).map(|i| format!("||n{i}.example^")));
    let v2: Vec<&str> = v2.iter().map(String::as_str).collect();
    let (h2, s2, _, _) = incremental(&b1.head, &b1.blobs, &b1.hot_keys, &b1.cold_keys, &v2, None, 1);
    let changed: Vec<u32> = h2
        .shards
        .iter()
        .filter(|s| !s.deltas.is_empty())
        .map(|s| s.shard)
        .collect();
    assert!(changed.len() >= 2, "two hot swaps: {changed:?}");
    let id2 = publish(&core, &h2, &s2);
    let cfg = |bundle: &str| {
        let mut c = config(&up, json!({"b": bundle}));
        c["profiles"]["default"]["lookups"] = json!([{"provider": "vp", "mode": "sync"}]);
        c["profiles"]["default"]["lookup_budget_ms"] = 30_000.into();
        c["lookup_providers"] = json!({"vp": {"module": "scripted", "config": {},
            "cache_generation": "0123456789abcdef", "sync_timeout_ms": 30_000,
            "async_timeout_ms": 30_000, "fail_mode": "open",
            "scope": {"exclude_bundles": [], "qtypes": ["A", "AAAA"]}}});
        c
    };
    let cfg1 = core.set_config(&cfg(&id1));
    let mut t = tuning(&d, true);
    t.lookup_registry = Some(Arc::new(reg));
    let r = start(&d, t).await;
    wait_live(&r, &cfg1).await;
    wait_head(&r, "b", &id1).await;
    let addr = r.edge.dns.listeners.local_addrs("lan-dns")[0];
    // The held query: in flight, holding the active state it loaded (pipeline.rs).
    let held = tokio::spawn(async move {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.send_to(&Q::new("held.example", 1).bytes(), addr).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(60), s.recv_from(&mut buf))
            .await
            .expect("the held query is answered")
            .unwrap();
        parse(&buf[..n])
    });
    assert!(wait_until(T, || entered.load(Ordering::SeqCst)).await);
    // Back-to-back swaps: the first goes through, the second waits for the held query.
    let edge = Arc::clone(&r.edge);
    let on_v1 = move || {
        let b = edge.active().bundles.get("b").cloned().unwrap();
        b.hot_shards()
            .iter()
            .filter(|s| changed.contains(&s.number) && *s.head == *id1)
            .count()
    };
    let n = on_v1();
    let cfg2 = core.set_config(&cfg(&id2));
    core.changed(&cfg2);
    assert!(wait_until(T, || on_v1() == n - 1).await, "the first hot swap");
    let first = std::time::Instant::now();
    while first.elapsed() < Duration::from_secs(4) {
        assert_eq!(
            on_v1(),
            n - 1,
            "the next swap waits until the replaced shard is freed"
        );
        assert!(blocked(&r, "k1.example").await, "queries are answered meanwhile");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    gate.add_permits(1);
    let m = held.await.unwrap();
    assert_eq!(m.rcode, 0);
    assert_eq!(m.answers.len(), 1, "the held query answers");
    wait_head(&r, "b", &id2).await;
    assert!(blocked(&r, "n7.example").await, "v2 is live");
    // The held query logged the versions it loaded: v1 whole.
    let short1 = picket_api::ids::short_id(&b1.head_blob.id).to_owned();
    assert!(
        wait_until(T, || core.with(|s| s.logs.iter().any(|l| l["t"] == "q"
            && l["qname"] == "held.example"
            && l["versions"]["bundles"]["b"] == short1.as_str())))
        .await,
        "{:?}",
        core.with(|s| s
            .logs
            .iter()
            .filter(|l| l["qname"] == "held.example")
            .cloned()
            .collect::<Vec<_>>())
    );
    r.shutdown().await;
}
