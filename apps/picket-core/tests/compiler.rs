//! The compiler's review-round-1 fixes end to end (bundles.md §2–§5, §8; core.md §3–§4;
//! storage.md §4; README §2 Restarts): budgets across a restart, head stability, warnings on
//! every changed key and on warninglist patterns, the overlay budget over IP and other bundles'
//! overlays, staged fresh builds, blobs of a build in progress, bounded steps that keep results
//! identical, feed retention pins and purged feeds.

use crate::common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::bundles::*;
use common::{Core, start_core};
use picket_core::scheduler::HeavyJob;
use reqwest::Method;
use serde_json::{Value, json};

async fn core() -> Core {
    let c = start_core(Some(json!({"web": {"tls": "off"}}))).await;
    c.state
        .compiler
        .set_fixed_time(Some("2026-11-21T00:00:00.000000Z".into()));
    c
}

/// Makes every version of `bundle` committed from now on (other than `except`) look 1 GiB large
/// in memory on an edge, in the commit's own transaction, so no render ever sees it small.
async fn inflate_from_now(c: &Core, bundle: &str, except: &str) {
    let sql = format!(
        "CREATE TRIGGER \"inflate_{bundle}\" AFTER INSERT ON bundle_versions
         WHEN NEW.bundle_id = '{bundle}' AND NEW.head_id <> '{except}'
         BEGIN UPDATE bundle_versions SET stats_json = json_set(stats_json, '$.edge_mem_bytes', 1073741824)
           WHERE bundle_id = NEW.bundle_id AND head_id = NEW.head_id; END"
    );
    c.state
        .db
        .write(move |db| {
            db.execute(&sql, [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
}

/// Adds `bundle` to the default profile's block bundles.
async fn block_in_default(c: &Core, bundle: &str) {
    let (_, mut p) = get(c, "/profiles/default").await;
    let mut block: Vec<Value> = p["block"].as_array().cloned().unwrap_or_default();
    block.push(json!(bundle));
    p["block"] = Value::Array(block);
    let r = ui(c, Method::PUT, "/profiles/default")
        .json(&p)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
}

/// An edge registered with an overlay budget.
async fn edge_with_overlay(c: &Core, name: &str, overlay_mib: u32) -> common::edge::FakeEdge {
    let mut e = common::edge::FakeEdge::new(c, name);
    let out = picket_core::edges::add(
        &c.state.config,
        picket_core::config::model::EdgeDef {
            name: name.into(),
            key: e.fingerprint.clone(),
            settings: picket_core::config::model::EdgeSettings {
                overlay_budget_mib: Some(overlay_mib),
                ..Default::default()
            },
            ..Default::default()
        },
        picket_core::config::Actor::cli(),
    )
    .await
    .unwrap();
    e.id = out.id;
    e
}

async fn q<T: rusqlite::types::FromSql + Send + 'static>(c: &Core, sql: &str) -> T {
    let s = sql.to_string();
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&s, [], |r| r.get(0))?))
        .await
        .unwrap()
}

/// Budgets across a restart (review round 1, CP1; bundles.md §2 Budget; README §2 Restarts): a
/// restarted core restores what each edge was given before its first render, so an edge kept on
/// a bundle's older head stays on it, and a held config stays held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budgets_hold_across_a_restart() {
    let c = core().await;
    let edge = common::edge::FakeEdge::registered(&c, "e1").await;
    save(&c, "manual-block", "||blocked.example^\n").await;
    let h1 = build(&c, "block-common").await.unwrap();
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    inflate_from_now(&c, "block-common", &h1).await;
    save(&c, "manual-block", "||blocked.example^\n||also.example^\n").await;
    let h2 = build(&c, "block-common").await.unwrap();
    assert_ne!(h1, h2);
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let named = |p: &picket_core::edges::publish::Publisher| {
        p.current(&edge.id)
            .unwrap()
            .config
            .bundles
            .get("block-common")
            .cloned()
    };
    assert_eq!(named(&c.state.edges.publisher).as_deref(), Some(h1.as_str()));
    // A restarted core: nothing in memory; restored from storage before its first render.
    let fresh = picket_core::edges::publish::Publisher::new(Duration::from_millis(1));
    assert_eq!(fresh.restore(&c.state).await.unwrap(), 1);
    fresh.render(&c.state, None).await.unwrap();
    assert_eq!(
        named(&fresh).as_deref(),
        Some(h1.as_str()),
        "the edge stays on block-common's older head"
    );
    // A bundle added to the edge's profile that doesn't fit holds the whole config.
    manual_feed(&c, "bigf", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "big",
        json!({"id": "big", "name": "big", "feeds": [{"feed": "bigf"}]}),
    )
    .await;
    inflate_from_now(&c, "big", "").await;
    save(&c, "bigf", "||big.example^\n").await;
    build(&c, "big").await.unwrap();
    let held = c.state.edges.publisher.current(&edge.id).unwrap().id.clone();
    block_in_default(&c, "big").await;
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    assert_eq!(
        c.state.edges.publisher.current(&edge.id).unwrap().id,
        held,
        "held"
    );
    let fresh = picket_core::edges::publish::Publisher::new(Duration::from_millis(1));
    fresh.restore(&c.state).await.unwrap();
    fresh.render(&c.state, None).await.unwrap();
    let after = fresh.current(&edge.id).unwrap();
    assert_eq!(after.id, held, "still held after the restart");
    assert!(!after.config.bundles.contains_key("big"));
    assert_eq!(
        after.bytes,
        c.state.edges.publisher.current(&edge.id).unwrap().bytes,
        "the same bytes are served"
    );
}

/// A build that changes nothing gives the previous head back (review round 1, CP11; bundles.md
/// §2 Determinism): no new version for a forced build (the daily compaction) of a bundle without
/// a cold part.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_build_that_changes_nothing_keeps_the_head() {
    let c = core().await;
    manual_feed(&c, "pf", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "pb",
        json!({"id": "pb", "name": "pb", "feeds": [{"feed": "pf"}]}),
    )
    .await;
    save(&c, "pf", "||a.example^\n").await;
    let h1 = build(&c, "pb").await.unwrap();
    let versions = |c: &Core| {
        let st = c.state.clone();
        async move {
            st.db
                .read(|db| {
                    Ok::<_, anyhow::Error>(db.query_row(
                        "SELECT count(*) FROM bundle_versions WHERE bundle_id = 'pb'",
                        [],
                        |r| r.get::<_, i64>(0),
                    )?)
                })
                .await
                .unwrap()
        }
    };
    let before = versions(&c).await;
    for _ in 0..2 {
        c.state.compiler.request(
            &c.state,
            "pb",
            picket_core::compiler::Request {
                reasons: ["forced".to_string()].into(),
                force: true,
                ..Default::default()
            },
            picket_core::scheduler::Priority::P0,
        );
        wait("the forced build", || async { c.state.compiler.idle() }).await;
        assert_eq!(settle(&c, "pb").await.unwrap(), h1);
    }
    assert_eq!(versions(&c).await, before, "no new version");
}

/// Warnings on a block bundle whose build changes more keys than one step checks (review round
/// 1, CP10; bundles.md §3): every changed key is checked, a page per step; none is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warnings_cover_every_changed_key() {
    let c = core().await;
    save(&c, "manual-warn", "||yyy.example^\n").await;
    build(&c, "warn-common").await;
    manual_feed(&c, "wf4", json!({"warn_on": ["warn-common"]})).await;
    put_entity(
        &c,
        "bundles",
        "wb4",
        json!({"id": "wb4", "name": "wb4", "feeds": [{"feed": "wf4"}]}),
    )
    .await;
    save(&c, "wf4", "||a.example^\n").await;
    build(&c, "wb4").await.unwrap();
    let mut text = String::new();
    for i in 0..52_000 {
        text.push_str(&format!("||k{i:05}.example^\n"));
    }
    text.push_str("||yyy.example^\n");
    save(&c, "wf4", &text).await;
    build(&c, "wb4").await.unwrap();
    let (_, w) = get(&c, "/bundles/wb4/warnings").await;
    let values: Vec<&str> = w["warnings"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["value"].as_str())
        .collect();
    assert_eq!(values, vec!["yyy.example"], "{w}");
}

/// A warninglist update re-checks existing blocks (review round 1, CP9; bundles.md §3 When;
/// feeds.md §7): a warninglist pattern matches keys anywhere in the block bundle, and a subdomain
/// rule finds every block below its name, past one page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warninglist_patterns_and_deep_subdomains_recheck() {
    let c = core().await;
    manual_feed(&c, "wf", json!({"warn_on": ["warn-common"]})).await;
    put_entity(
        &c,
        "bundles",
        "wb",
        json!({"id": "wb", "name": "wb", "feeds": [{"feed": "wf"}]}),
    )
    .await;
    let mut text = String::from("||ads.mycompany.example^\n||other.example^\n");
    for i in 0..2500 {
        text.push_str(&format!("||n{i:04}.big.example^\n"));
    }
    save(&c, "wf", &text).await;
    build(&c, "wb").await.unwrap();
    // The warninglist changes after the blocks were built.
    save(&c, "manual-warn", "||*mycompany*^\n||big.example^\n").await;
    build(&c, "warn-common").await;
    let warned = |c: &Core| {
        let st = c.state.clone();
        async move {
            st.db
                .read(|db| {
                    Ok::<_, anyhow::Error>(db.query_row(
                        "SELECT count(*), coalesce(sum(value = 'ads.mycompany.example'), 0) FROM warnings
                         WHERE status = 'open' AND bundle_id = 'wb'",
                        [],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                    )?)
                })
                .await
                .unwrap()
        }
    };
    wait("the re-check's warnings", || async {
        warned(&c).await == (2501, 1)
    })
    .await;
    // The warninglist entry goes: the re-check resolves them.
    save(&c, "manual-warn", "||big.example^\n").await;
    build(&c, "warn-common").await;
    wait("the resolve", || async { warned(&c).await == (2500, 0) }).await;
}

/// The overlay budget covers IP shards (review round 1, CP6): IP deltas that would pass an edge's
/// `overlay_budget_mib` become a rebuilt base instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ip_overlays_count_against_the_overlay_budget() {
    let c = core().await;
    let edge = edge_with_overlay(&c, "e1", 1).await;
    manual_feed(
        &c,
        "ipf",
        json!({"modes": {"dns": {"mode": "replace"}, "ip": {"mode": "replace"}}}),
    )
    .await;
    put_entity(
        &c,
        "bundles",
        "ipb",
        json!({"id": "ipb", "name": "ipb", "feeds": [{"feed": "ipf"}]}),
    )
    .await;
    block_in_default(&c, "ipb").await;
    save(&c, "ipf", "||10.255.255.255^\n").await;
    let h1 = build(&c, "ipb").await.unwrap();
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    assert_eq!(
        c.state
            .edges
            .publisher
            .current(&edge.id)
            .unwrap()
            .config
            .bundles
            .get("ipb"),
        Some(&h1)
    );
    // 49,999 disjoint runs in one IP shard: ~1.2 MB of overlay as a delta.
    let mut text = String::from("||10.255.255.255^\n");
    for i in 0..49_999u32 {
        let a = 0x0A00_0000u32 + 2 * i;
        text.push_str(&format!("||{}^\n", std::net::Ipv4Addr::from(a)));
    }
    save(&c, "ipf", &text).await;
    let h2 = build(&c, "ipb").await.unwrap();
    let (_, _, head) = load(&c, &h2);
    let v4 = head
        .ip_shards
        .iter()
        .find(|s| s.ip_shard.to_string() == "v4/10")
        .unwrap();
    assert!(v4.deltas.is_empty(), "a new base, not a delta: {v4:?}");
    let overlay: i64 = q(
        &c,
        "SELECT (SELECT coalesce(sum(overlay_bytes), 0) FROM bundle_ip_shards WHERE bundle_id = 'ipb')
              + (SELECT coalesce(sum(overlay_bytes), 0) FROM bundle_shards WHERE bundle_id = 'ipb')",
    )
    .await;
    assert!(overlay <= 1024 * 1024, "{overlay}");
    let (b, pages, _) = load(&c, &h2);
    assert_eq!(decide(&b, &pages, &Q::ip("10.0.0.2")), "block");
    assert_eq!(decide(&b, &pages, &Q::ip("10.0.0.3")), "none");
}

/// The overlay budget weighs every overlay on the edge, largest first (review round 1, CP6;
/// bundles.md §5): another bundle's larger overlay is requested as its compaction build, and the
/// build in hand rebuilds its own shard so it never publishes past the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_largest_overlay_on_the_edge_is_rebuilt_first() {
    let c = core().await;
    let edge = edge_with_overlay(&c, "e1", 1).await;
    for (f, b) in [("fa", "ba"), ("fb", "bb")] {
        manual_feed(&c, f, json!({})).await;
        put_entity(
            &c,
            "bundles",
            b,
            json!({"id": b, "name": b, "feeds": [{"feed": f}]}),
        )
        .await;
        block_in_default(&c, b).await;
        save(&c, f, &format!("||{b}.example^\n")).await;
        build(&c, b).await.unwrap();
    }
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    // ba: a 30,000-key delta (~900 KB of overlay) still fits the 1 MiB budget.
    let mut text = String::from("||ba.example^\n");
    for i in 0..30_000 {
        text.push_str(&format!("||a{i:05}.example^\n"));
    }
    save(&c, "fa", &text).await;
    let ha = build(&c, "ba").await.unwrap();
    let (_, _, head_a) = load(&c, &ha);
    assert!(!head_a.shards[0].deltas.is_empty(), "ba's change is a delta");
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    assert_eq!(
        c.state
            .edges
            .publisher
            .current(&edge.id)
            .unwrap()
            .config
            .bundles
            .get("ba"),
        Some(&ha)
    );
    // bb: a 5,000-key delta would pass the budget.
    let mut text = String::from("||bb.example^\n");
    for i in 0..5_000 {
        text.push_str(&format!("||b{i:05}.example^\n"));
    }
    save(&c, "fb", &text).await;
    let hb = build(&c, "bb").await.unwrap();
    let (_, _, head_b) = load(&c, &hb);
    assert!(head_b.shards[0].deltas.is_empty(), "bb rebuilt its base");
    // ba, the largest overlay, gets its compaction build.
    wait("ba's compaction", || async {
        q::<i64>(
            &c,
            "SELECT coalesce(sum(overlay_bytes), 0) FROM bundle_shards WHERE bundle_id = 'ba'",
        )
        .await
            == 0
            && c.state.compiler.idle()
    })
    .await;
    let ha2 = build_row(&c, "ba").await.unwrap().1.unwrap();
    assert_ne!(ha2, ha);
    let (b, pages, _) = load(&c, &ha2);
    assert_eq!(decide(&b, &pages, &Q::name("a00042.example")), "block");
}

/// A fresh build stages its keys (review round 1, CP12; README §2 Restarts): until its commit,
/// readers see the bundle's previous keys, whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_build_stages_its_keys() {
    let c = core().await;
    manual_feed(&c, "sf", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "sb",
        json!({"id": "sb", "name": "sb", "feeds": [{"feed": "sf"}]}),
    )
    .await;
    let mut text = String::new();
    for i in 0..25_000 {
        text.push_str(&format!("||s{i}.example^\n"));
    }
    save(&c, "sf", &text).await;
    build(&c, "sb").await.unwrap();
    let before: Vec<(String, i64)> = c
        .state
        .db
        .read(|db| {
            let mut st =
                db.prepare("SELECT key, value FROM bundle_keys WHERE bundle_id = 'sb' ORDER BY key")?;
            let v = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap();
    // No usable previous head: the next build is fresh.
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE bundle_builds SET head_id = NULL WHERE bundle_id = 'sb'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let mut job = picket_core::compiler::build::BuildJob::new(c.state.clone(), "sb");
    let mut saw_keys = false;
    while job.phase_name() != "commit" {
        assert_ne!(job.phase_name(), "done");
        job.step().await.unwrap();
        saw_keys |= job.phase_name() == "plan";
        let now: i64 = q(&c, "SELECT count(*) FROM bundle_keys WHERE bundle_id = 'sb'").await;
        assert_eq!(now as usize, before.len(), "readers see the previous keys whole");
    }
    assert!(saw_keys);
    let staged: i64 = q(
        &c,
        "SELECT count(*) FROM bundle_build_fresh WHERE bundle_id = 'sb'",
    )
    .await;
    assert_eq!(staged as usize, before.len());
    job.step().await.unwrap();
    let after: i64 = q(&c, "SELECT count(*) FROM bundle_keys WHERE bundle_id = 'sb'").await;
    assert_eq!(after as usize, before.len());
    let staged: i64 = q(&c, "SELECT count(*) FROM bundle_build_fresh").await;
    assert_eq!(staged, 0, "the staging rows go with the commit");
}

/// Blobs of a build in progress (review round 1, CP13; storage.md §4): retention never collects
/// a blob a build between writing its files and its commit names, and a build that never commits
/// leaves no file without a row retention can collect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_of_a_build_in_progress_are_kept_and_its_leftovers_collected() {
    use picket_core::retention::RetentionHook;
    let c = core().await;
    manual_feed(&c, "gf", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "gb",
        json!({"id": "gb", "name": "gb", "feeds": [{"feed": "gf"}]}),
    )
    .await;
    save(&c, "gf", "||a.example^\n").await;
    build(&c, "gb").await.unwrap();
    save(&c, "gf", "||a.example^\n||b.example^\n").await;
    // The feed run's own build.
    settle(&c, "gb").await;
    let age = |c: &Core| {
        let st = c.state.clone();
        async move {
            st.db
                .write(|db| {
                    // Every blob old, and no retained version naming any (a retired version's
                    // blobs that the new head reuses).
                    db.execute("UPDATE blobs SET created_at = '2000-01-01T00:00:00.000000Z'", [])?;
                    db.execute("DELETE FROM bundle_version_blobs", [])?;
                    Ok::<_, anyhow::Error>(())
                })
                .await
                .unwrap();
        }
    };
    let retention = |c: &Core| {
        let st = c.state.clone();
        async move {
            let hook = picket_core::compiler::retention::BundleRetention;
            while hook.step(&st).await.unwrap() == picket_core::scheduler::Step::More {}
        }
    };
    // A build stopped right before its commit while retention runs.
    picket_core::compiler::retire(&c.state, "gb").await.unwrap();
    let mut job = picket_core::compiler::build::BuildJob::new(c.state.clone(), "gb");
    while job.phase_name() != "commit" {
        assert_ne!(job.phase_name(), "done");
        job.step().await.unwrap();
    }
    age(&c).await;
    retention(&c).await;
    job.step().await.unwrap();
    drop(job);
    let head = build_row(&c, "gb").await.unwrap().1.unwrap();
    let (b, pages, _) = load(&c, &head);
    assert_eq!(
        decide(&b, &pages, &Q::name("b.example")),
        "block",
        "every named blob is there"
    );
    // A build that never commits (stopped before its commit, then a start empties its work
    // tables): its files have rows, which retention collects.
    picket_core::compiler::retire(&c.state, "gb").await.unwrap();
    let mut job = picket_core::compiler::build::BuildJob::new(c.state.clone(), "gb");
    while job.phase_name() != "commit" {
        assert_ne!(job.phase_name(), "done");
        job.step().await.unwrap();
    }
    drop(job);
    c.state
        .db
        .write(|db| {
            for t in picket_core::compiler::store::WORK_TABLES {
                db.execute(&format!("DELETE FROM {t}"), [])?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    age(&c).await;
    retention(&c).await;
    let all: std::collections::BTreeSet<String> = c
        .state
        .db
        .read(|db| {
            let mut st = db.prepare("SELECT blake3 FROM blobs")?;
            let v = st
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<std::collections::BTreeSet<String>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap();
    let dir = c.dir.path().join("blobs");
    let mut files = 0;
    for fan in std::fs::read_dir(&dir).unwrap() {
        for f in std::fs::read_dir(fan.unwrap().path()).unwrap() {
            let name = f.unwrap().file_name().to_string_lossy().into_owned();
            files += 1;
            assert!(all.contains(&name), "a blob file without a row: {name}");
        }
    }
    assert!(files > 0);
}

/// Descendant expansion runs in bounded steps (review round 1, CP8; core.md §3) with the same
/// result: a new subdomain rule above 30,000 listed names prunes them all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn descendant_expansion_is_bounded_per_step() {
    let c = core().await;
    manual_feed(&c, "ef", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "eb",
        json!({"id": "eb", "name": "eb", "feeds": [{"feed": "ef"}]}),
    )
    .await;
    let mut text = String::new();
    for i in 0..30_000 {
        text.push_str(&format!("||n{i:05}.big.example^\n"));
    }
    save(&c, "ef", &text).await;
    build(&c, "eb").await.unwrap();
    text.push_str("||big.example^\n");
    save(&c, "ef", &text).await;
    let mut job = picket_core::compiler::build::BuildJob::new(c.state.clone(), "eb");
    assert_eq!(job.phase_name(), "setup");
    let mut steps = 0;
    let count = || async {
        q::<i64>(
            &c,
            "SELECT count(*) FROM bundle_build_keys WHERE bundle_id = 'eb'",
        )
        .await
    };
    loop {
        let phase = job.phase_name();
        if phase == "done" {
            break;
        }
        let before = count().await;
        job.step().await.unwrap();
        if phase == "expand" {
            steps += 1;
            let added = count().await - before;
            assert!(
                added as usize <= picket_core::compiler::build::DESCENDANT_ROWS_PER_STEP,
                "{added}"
            );
        }
    }
    assert!(steps >= 2, "{steps} expand steps");
    let head = build_row(&c, "eb").await.unwrap().1.unwrap();
    let keys: i64 = q(&c, "SELECT count(*) FROM bundle_keys WHERE bundle_id = 'eb'").await;
    assert_eq!(keys, 1, "every listed name below big.example is subsumed");
    let (b, pages, _) = load(&c, &head);
    assert_eq!(decide(&b, &pages, &Q::name("n12345.big.example")), "block");
}

fn decisions_of(c: &Core, head: &str, names: &[&str]) -> BTreeMap<String, String> {
    let (b, pages, _) = load(c, head);
    names
        .iter()
        .map(|n| (n.to_string(), decide(&b, &pages, &Q::name(n))))
        .collect()
}

/// urlfilter's exact filing runs in pages across steps (review round 1, CP8; rules.md §4): two
/// rewrites that can match one query decide as the reference does, in an incremental build and
/// in a build from scratch alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_rewrite_order_incremental_equals_fresh() {
    let c = core().await;
    c.state.compiler.set_order_rows(Some(7));
    manual_feed(&c, "rf", json!({})).await;
    manual_feed(&c, "rg", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "rb",
        json!({"id": "rb", "name": "rb", "feeds": [{"feed": "rf"}, {"feed": "rg"}]}),
    )
    .await;
    let mut f = String::new();
    for i in 0..40 {
        f.push_str(&format!("||pad{i}.example^\n"));
    }
    f.push_str(
        "||rw.example^$dnsrewrite=1.2.3.4\n||www.rw.example^$dnsrewrite=NOERROR;CNAME;target.example\n",
    );
    save(&c, "rf", &f).await;
    save(
        &c,
        "rg",
        "||rw.example^$dnsrewrite=NOERROR;CNAME;other.example\n*.rw.example^$dnsrewrite=5.6.7.8\n||x.example^\n",
    )
    .await;
    build(&c, "rb").await.unwrap();
    // Incremental: rules before the rewrites change.
    let mut f2 = String::from("||first.example^\n");
    f2.push_str(&f);
    save(&c, "rf", &f2).await;
    let inc = build(&c, "rb").await.unwrap();
    let names = [
        "rw.example",
        "www.rw.example",
        "a.rw.example",
        "x.example",
        "pad3.example",
    ];
    let reference = reference(&c, "rb").await;
    let mut want = BTreeMap::new();
    for n in names {
        want.insert(n.to_string(), decide_ref(&reference, &Q::name(n)));
    }
    assert_eq!(decisions_of(&c, &inc, &names), want, "incremental");
    let (_, st) = get(&c, "/bundles/rb/status").await;
    assert_eq!(st["stats"]["exact_rewrite_order"], true, "{st}");
    // From scratch.
    picket_core::compiler::retire(&c.state, "rb").await.unwrap();
    let fresh = build(&c, "rb").await.unwrap();
    assert_eq!(decisions_of(&c, &fresh, &names), want, "fresh");
}

/// Feed retention keeps the closed entries a bundle's next incremental build replays (review
/// round 1, CP14): a warn bundle publishes no version, so its last build's runs pin them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_last_builds_runs_pin_closed_entries() {
    use picket_core::retention::RetentionHook;
    let c = core().await;
    manual_feed(&c, "wf", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "ww",
        json!({"id": "ww", "name": "ww", "action": "warn", "feeds": [{"feed": "wf"}]}),
    )
    .await;
    save(&c, "wf", "||a.example^\n||b.example^\n").await;
    build(&c, "ww").await;
    save(&c, "wf", "||a.example^\n").await;
    // The window passes before the warn bundle builds again.
    c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE feed_runs SET downloaded_at = '2000-01-01T00:00:00.000000Z', confirmed_at = NULL,
                   updated_at = '2000-01-01T00:00:00.000000Z'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let hook = picket_core::feeds::retention::FeedRetention;
    while hook.step(&c.state).await.unwrap() == picket_core::scheduler::Step::More {}
    let closed: i64 = q(
        &c,
        "SELECT count(*) FROM feed_entries WHERE feed_id = 'wf' AND key = 'example.b' AND removed_run IS NOT NULL",
    )
    .await;
    assert_eq!(closed, 1, "the warn bundle's next build replays the removal");
}

/// A purged feed id (a feed deleted and created again) no longer gives its old keys to a bundle
/// naming it (review round 1, CP14), even before the new feed's first run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_purged_feed_leaves_the_bundle() {
    let c = core().await;
    manual_feed(&c, "pg", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "pgb",
        json!({"id": "pgb", "name": "pgb", "feeds": [{"feed": "pg"}]}),
    )
    .await;
    save(&c, "pg", "||old.example^\n").await;
    let h1 = build(&c, "pgb").await.unwrap();
    assert_eq!(decisions_of(&c, &h1, &["old.example"])["old.example"], "block");
    // The deletion's purge (as a delete and create of the same id in one change would leave it).
    let run: i64 = c
        .state
        .db
        .write(|db| {
            let tx = db.transaction()?;
            // The deleted feed's file goes with it.
            tx.execute("DELETE FROM manual_files WHERE feed_id = 'pg'", [])?;
            picket_core::feeds::purge::schedule_in(&tx, "pg")?;
            let run: i64 = tx.query_row("SELECT run_id FROM feed_purges WHERE feed_id = 'pg'", [], |r| {
                r.get(0)
            })?;
            tx.commit()?;
            Ok::<_, anyhow::Error>(run)
        })
        .await
        .unwrap();
    let mut job = picket_core::feeds::purge::PurgeJob::new(c.state.clone(), "pg", run);
    while job.step().await.unwrap() == picket_core::scheduler::Step::More {}
    drop(job);
    wait("the bundle's build after the purge", || async {
        match build_row(&c, "pgb").await {
            Some((_, Some(h), runs)) => h != h1 && runs.get("pg").is_some_and(|r| *r >= run),
            _ => false,
        }
    })
    .await;
    let h2 = build_row(&c, "pgb").await.unwrap().1.unwrap();
    assert_eq!(decisions_of(&c, &h2, &["old.example"])["old.example"], "none");
}
