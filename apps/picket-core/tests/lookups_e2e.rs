//! The real picket-edge against this core: core publishes a provider's verdict set (a base, then
//! a delta), names it in the edge's config object, and the edge activates it and answers from it
//! (core.md §7; edge.md §10, §13; providers.md §4 "Verdict cache"; bundles.md §4–§5).

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
use std::time::Duration;

use common::edge::eventually;
use jiff::Timestamp;
use picket_bundle::verdict::VerdictKind;
use picket_core::config::model::EntityKind;
use picket_core::config::{Actor, Op};
use picket_core::lookups::store::{Incoming, ProviderView};
use picket_edge::service::{self, Options, Tuning};
use picket_lookup::{Source, StoredVerdict, SyncRequest, SyncResult};
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

/// Records a verdict straight into core's store, as a log batch would.
async fn record(c: &common::Core, name: &str, v: VerdictKind) {
    let model = c.state.config.model().await.unwrap();
    let p = model.lookup_providers["q9"].clone();
    let name = name.to_string();
    c.state
        .db
        .write(move |db| {
            let tx = db.transaction()?;
            let now = Timestamp::now();
            picket_core::lookups::store::record(
                &tx,
                &ProviderView {
                    id: "q9",
                    generation: &p.cache_generation,
                    cache: &p.settings.cache,
                },
                &Incoming {
                    name: &name,
                    verdict: v,
                    score: Some(9.5),
                    reason: Some("risk >= 7"),
                    detail: None,
                    obtained_at: now,
                    generation: &p.cache_generation,
                    source: picket_core::lookups::store::Source::Core,
                },
                &picket_core::lookups::store::RecordClock {
                    now,
                    block_cutoff: Some(now - jiff::SignedDuration::from_hours(72)),
                    synced: true,
                },
            )?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
}

/// A lookup on the edge: the RAM tier, then the verdict set, then (with `call`) the provider. A
/// cache-only one (`call: false`) returns only a live Block, else a miss (edge.md §10).
async fn lookup(edge: &picket_edge::edge::Edge, name: &str, call: bool) -> SyncResult {
    let client = edge.dns.lookups.get("q9").expect("the edge's client for q9");
    client
        .lookup_sync(SyncRequest {
            name,
            deadline: tokio::time::Instant::now() + Duration::from_secs(2),
            call,
            tag: None,
        })
        .await
        .result
}

async fn ask(edge: &picket_edge::edge::Edge, name: &str) -> SyncResult {
    lookup(edge, name, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_edge_activates_a_published_verdict_set_and_answers_from_it() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    // Verdict sets wait for a synchronised clock (README §2 Clocks).
    c.state.clock.pin(true);
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Create(json!({"id": "q9", "name": "Q9", "module": "http_json",
                "config": {"url": "https://lookup.example/{domain}", "verdict": {"pointer": "/risk", "block_if": ">= 7"}},
                "recheck": {"enabled": false}})),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    c.state
        .config
        .apply(
            EntityKind::Profile,
            Op::Create(
                json!({"id": "kids", "name": "Kids", "lookup_providers": [{"provider": "q9", "mode": "sync"}]}),
            ),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    assert!(
        eventually(|| async { c.state.lookups.model().profiles.contains_key("kids") }).await,
        "the lookups runtime sees the profile"
    );
    record(&c, "bad.example.org", VerdictKind::Block).await;
    record(&c, "good.example.org", VerdictKind::Clean).await;
    // Core publishes on its own (a base for the new `sync` provider, then deltas); this makes the
    // first base hold both verdicts at once.
    picket_core::lookups::verdict_sets::rebuild_base(&c.state, "q9")
        .await
        .unwrap();

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

    // The edge activates the head its config names (core's current one), and reports it in `have`.
    let current = || {
        let st = c.state.clone();
        async move {
            st.db
                .read(|db| {
                    Ok::<_, anyhow::Error>(db.query_row(
                        "SELECT head_id FROM verdict_set_state WHERE provider_id = 'q9'",
                        [],
                        |r| r.get::<_, String>(0),
                    )?)
                })
                .await
                .unwrap()
        }
    };
    let active_current = || {
        let st = c.state.clone();
        let id = id.clone();
        async move {
            let head = st
                .db
                .read(|db| {
                    Ok::<_, anyhow::Error>(db.query_row(
                        "SELECT head_id FROM verdict_set_state WHERE provider_id = 'q9'",
                        [],
                        |r| r.get::<_, String>(0),
                    )?)
                })
                .await
                .unwrap();
            st.edges
                .hub
                .live(&id)
                .have
                .verdict_sets
                .get("q9")
                .and_then(|l| l.first().cloned())
                == Some(head)
        }
    };
    let mut ok = false;
    for _ in 0..3 {
        if eventually(active_current).await {
            ok = true;
            break;
        }
    }
    assert!(
        ok,
        "the edge activates the verdict set: {:?} / {}",
        c.state.edges.hub.live(&id).have,
        current().await
    );
    match ask(&edge, "bad.example.org").await {
        SyncResult::Verdict {
            verdict: StoredVerdict::Block { reason, .. },
            source: Source::Set,
            obtained_at: Some(_),
            ..
        } => assert_eq!(&*reason, "risk >= 7"),
        other => panic!("bad.example.org from the set: {other:?}"),
    }
    // A Clean comes from the set too, with no call to the provider.
    assert!(matches!(
        lookup(&edge, "good.example.org", true).await,
        SyncResult::Verdict {
            verdict: StoredVerdict::Clean,
            source: Source::Set,
            ..
        }
    ));
    assert!(matches!(
        ask(&edge, "unknown.example.org").await,
        SyncResult::Miss
    ));

    // A delta: a new Block reaches the edge on the same base.
    let before = current().await;
    record(&c, "bad2.example.org", VerdictKind::Block).await;
    let _ = picket_core::lookups::verdict_sets::publish_delta(&c.state, "q9")
        .await
        .unwrap();
    assert!(
        eventually(|| async { current().await != before }).await,
        "a new head"
    );
    let mut ok = false;
    for _ in 0..3 {
        if eventually(active_current).await {
            ok = true;
            break;
        }
    }
    assert!(ok, "the edge activates the delta");
    assert!(matches!(
        ask(&edge, "bad2.example.org").await,
        SyncResult::Verdict {
            verdict: StoredVerdict::Block { .. },
            source: Source::Set,
            ..
        }
    ));
    assert!(matches!(
        ask(&edge, "bad.example.org").await,
        SyncResult::Verdict {
            verdict: StoredVerdict::Block { .. },
            source: Source::Set,
            ..
        }
    ));
    // The activation is a delta on the same base (the edge reports activation events per step).
    let events: i64 = c
        .state
        .db
        .read(|db| {
            Ok::<_, anyhow::Error>(db.query_row(
                "SELECT count(*) FROM edge_events WHERE kind = 'activation_failed'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(events, 0, "no activation failed");
    r.shutdown().await;
}
