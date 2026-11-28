//! The compiler's and browser lists' review-round-2 fixes end to end (bundles.md §2, §3, §5, §8;
//! core.md §3–§4; storage.md §4; README §2 Bounded, Restarts): both budgets at every publish,
//! warnings that follow their block bundles, IP warnings, the warn matcher's rule types, rechecks
//! across a restart, warnings per block bundle, and blobs collected only when unreferenced.

use crate::common;

use common::bundles::*;
use common::{Core, start_core};
use reqwest::Method;
use serde_json::{Value, json};

async fn core() -> Core {
    let c = start_core(Some(json!({"web": {"tls": "off"}}))).await;
    c.state
        .compiler
        .set_fixed_time(Some("2026-11-21T00:00:00.000000Z".into()));
    c
}

async fn q<T: rusqlite::types::FromSql + Send + 'static>(c: &Core, sql: &str) -> T {
    let s = sql.to_string();
    c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&s, [], |r| r.get(0))?))
        .await
        .unwrap()
}

/// Waits until no build, warning re-check or other heavy job runs or waits.
async fn idle(c: &Core) {
    wait("the heavy lane to idle", || async {
        c.state.compiler.idle()
            && c.state.scheduler.heavy.depth() == 0
            && c.state.scheduler.heavy.stats().running.is_none()
    })
    .await;
}

/// Open warnings as (by bundle, value, feed, block bundle).
async fn open_warnings(c: &Core) -> Vec<(String, String, String, String)> {
    c.state
        .db
        .read(|db| {
            let mut st = db.prepare(
                "SELECT by_bundle_id, value, feed_id, coalesce(bundle_id, '') FROM warnings
                 WHERE status = 'open' ORDER BY by_bundle_id, value, feed_id, bundle_id",
            )?;
            let v = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap()
}

async fn alert_state(c: &Core, key: &str) -> Option<String> {
    let k = key.to_string();
    c.state
        .db
        .read(move |db| {
            Ok::<_, anyhow::Error>(
                db.query_row("SELECT state FROM alerts WHERE dedupe_key = ?1", [k], |r| {
                    r.get(0)
                })
                .ok(),
            )
        })
        .await
        .unwrap()
}

async fn delete_entity(c: &Core, kind: &str, id: &str) {
    let r = ui(c, Method::DELETE, &format!("/{kind}/{id}"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
}

/// CR1 (bundles.md §2 Budget, §5; edge.md §17): an edge added after a build that left a large
/// overlay isn't named a head past its `overlay_budget_mib`: it keeps out of the config, the
/// alert says so, and the compaction build it asks for brings a head that fits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_overlay_budget_holds_for_an_edge_added_later() {
    let c = core().await;
    save(&c, "manual-block", "||first.example^\n").await;
    build(&c, "block-common").await.unwrap();
    let mut text = "||first.example^\n".to_string();
    for i in 0..40_000 {
        text.push_str(&format!("||q{i:05}.example^\n"));
    }
    save(&c, "manual-block", &text).await;
    let big = build(&c, "block-common").await.unwrap();
    let over: i64 = q(
        &c,
        &format!(
            "SELECT json_extract(stats_json, '$.overlay_bytes') FROM bundle_versions WHERE head_id = '{big}'"
        ),
    )
    .await;
    assert!(
        over > 1024 * 1024,
        "the fixture needs an overlay past 1 MiB: {over}"
    );
    let mut e = common::edge::FakeEdge::new(&c, "e1");
    e.id = picket_core::edges::add(
        &c.state.config,
        picket_core::config::model::EdgeDef {
            name: "e1".into(),
            key: e.fingerprint.clone(),
            settings: picket_core::config::model::EdgeSettings {
                overlay_budget_mib: Some(1),
                ..Default::default()
            },
            ..Default::default()
        },
        picket_core::config::Actor::cli(),
    )
    .await
    .unwrap()
    .id;
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let p = c.state.edges.publisher.current(&e.id).unwrap();
    assert_ne!(
        p.config.bundles.get("block-common"),
        Some(&big),
        "never a head past the edge's overlay budget"
    );
    assert_eq!(
        alert_state(&c, &format!("bundle_over_budget:{}:block-common", e.id))
            .await
            .as_deref(),
        Some("open")
    );
    // The compaction build it asked for rebuilds the bases: the new head fits and is named.
    idle(&c).await;
    let compacted = settle(&c, "block-common").await.unwrap();
    assert_ne!(compacted, big, "a compaction build ran");
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let p = c.state.edges.publisher.current(&e.id).unwrap();
    assert_eq!(p.config.bundles.get("block-common"), Some(&compacted));
    assert_eq!(
        alert_state(&c, &format!("bundle_over_budget:{}:block-common", e.id))
            .await
            .as_deref(),
        Some("resolved")
    );
}

/// CR1 (bundles.md §2 Budget): lowering an edge's `bundle_budget_mib` below what it runs keeps
/// the edge on its current config and keeps the alert open; raising it again releases the change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lowered_budget_keeps_the_current_config() {
    let c = core().await;
    let e = common::edge::FakeEdge::registered(&c, "e1").await;
    save(&c, "manual-block", "||blocked.example^\n").await;
    let h = build(&c, "block-common").await.unwrap();
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let before = c.state.edges.publisher.current(&e.id).unwrap();
    assert_eq!(before.config.bundles.get("block-common"), Some(&h));
    let hb = h.clone();
    c.state
        .db
        .write(move |db| {
            db.execute(
                "UPDATE bundle_versions SET stats_json = json_set(stats_json, '$.edge_mem_bytes', 20971520) WHERE head_id = ?1",
                [hb],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let set_budget = |mib: u32| {
        let st = c.state.clone();
        let id = e.id.clone();
        async move {
            let m = st.config.model().await.unwrap();
            let mut def = m.edges.get(&id).unwrap().clone();
            def.settings.bundle_budget_mib = mib;
            let body = serde_json::to_value(&def).unwrap();
            st.config
                .apply(
                    picket_core::config::EntityKind::Edge,
                    picket_core::config::store::Op::Update(id.clone(), body),
                    picket_core::config::Actor::cli(),
                    None,
                )
                .await
                .unwrap();
        }
    };
    set_budget(16).await;
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let now = c.state.edges.publisher.current(&e.id).unwrap();
    assert_eq!(now.id, before.id, "the edge keeps its current config");
    assert_eq!(
        alert_state(&c, &format!("bundle_over_budget:{}:block-common", e.id))
            .await
            .as_deref(),
        Some("open")
    );
    // Rendering again keeps the alert open (it isn't resolved while the edge can't move).
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    assert_eq!(
        alert_state(&c, &format!("bundle_over_budget:{}:block-common", e.id))
            .await
            .as_deref(),
        Some("open")
    );
    set_budget(64).await;
    c.state.edges.publisher.render(&c.state, None).await.unwrap();
    let after = c.state.edges.publisher.current(&e.id).unwrap();
    assert_ne!(after.id, before.id);
    assert_eq!(after.config.memory.bundle_budget_mib, 64);
    assert_eq!(
        alert_state(&c, &format!("bundle_over_budget:{}:block-common", e.id))
            .await
            .as_deref(),
        Some("resolved")
    );
}

/// CR7 (bundles.md §1 rule_types, §3): a warn bundle that takes only a feed's IP rules doesn't
/// match its DNS rules.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_warn_matcher_respects_rule_types() {
    let c = core().await;
    manual_feed(&c, "iponly", json!({})).await;
    save(&c, "iponly", "||ads.example^\n").await;
    manual_feed(&c, "ipf", json!({"format": "plain"})).await;
    save(&c, "ipf", "10.1.2.3\n").await;
    put_entity(
        &c,
        "bundles",
        "warnip",
        json!({"id": "warnip", "name": "warnip", "action": "warn",
               "feeds": [{"feed": "iponly", "rule_types": ["ip"]}, {"feed": "ipf", "rule_types": ["ip"]}]}),
    )
    .await;
    build(&c, "warnip").await;
    let model = c.state.config.model().await.unwrap();
    let (dns, ip) = c
        .state
        .db
        .read(move |db| {
            let spec = picket_core::compiler::spec::Spec::of(&model.bundles["warnip"], &model);
            let m = picket_core::compiler::warn::Matcher::load(db, &model, &spec)?;
            let ip = m.matches_ip(&picket_rules::ip::IpRange::from_text("10.1.2.3").unwrap());
            Ok::<_, anyhow::Error>((m.matches_key("example.ads"), ip))
        })
        .await
        .unwrap();
    assert_eq!(dns, None, "an IP-only warn bundle never matches a DNS name");
    assert_eq!(ip.as_deref(), Some("ipf"), "its IP rules still match");
}

/// CR6 (bundles.md §3): removing an IP rule from its block feed resolves its warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_ip_rule_resolves_its_warning() {
    let c = core().await;
    manual_feed(&c, "manual-warn", json!({"format": "plain"})).await;
    save(&c, "manual-warn", "1.2.3.0/24\n").await;
    build(&c, "warn-common").await;
    manual_feed(&c, "wf", json!({"warn_on": ["warn-common"], "format": "plain"})).await;
    put_entity(
        &c,
        "bundles",
        "wb",
        json!({"id": "wb", "name": "wb", "feeds": [{"feed": "wf"}]}),
    )
    .await;
    save(&c, "wf", "1.2.3.4/32\n9.9.9.9\n").await;
    build(&c, "wb").await;
    idle(&c).await;
    let w = open_warnings(&c).await;
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!(
        alert_state(&c, "warninglist_hit:warn-common:wf").await.as_deref(),
        Some("open")
    );
    save(&c, "wf", "9.9.9.9\n").await;
    build(&c, "wb").await;
    idle(&c).await;
    assert!(open_warnings(&c).await.is_empty(), "the warning resolves");
    assert_eq!(
        alert_state(&c, "warninglist_hit:warn-common:wf").await.as_deref(),
        Some("resolved")
    );
}

/// CR5 (bundles.md §3 "a block bundle holding the feed"): a warning resolves when its feed leaves
/// the block bundle (the feed itself stays), and when the block bundle is deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warnings_follow_their_feed_out_of_the_block_bundle() {
    let c = core().await;
    save(&c, "manual-warn", "||mycompany.example^\n").await;
    build(&c, "warn-common").await;
    manual_feed(&c, "wf", json!({"warn_on": ["warn-common"]})).await;
    manual_feed(&c, "wf2", json!({})).await;
    put_entity(
        &c,
        "bundles",
        "wb",
        json!({"id": "wb", "name": "wb", "feeds": [{"feed": "wf"}, {"feed": "wf2"}]}),
    )
    .await;
    save(&c, "wf", "||ads.mycompany.example^\n").await;
    save(&c, "wf2", "||other.example^\n").await;
    build(&c, "wb").await.unwrap();
    idle(&c).await;
    assert_eq!(open_warnings(&c).await.len(), 1);
    // wf leaves wb.
    put_entity(
        &c,
        "bundles",
        "wb",
        json!({"id": "wb", "name": "wb", "feeds": [{"feed": "wf2"}]}),
    )
    .await;
    build(&c, "wb").await.unwrap();
    idle(&c).await;
    assert!(
        open_warnings(&c).await.is_empty(),
        "{:?}",
        open_warnings(&c).await
    );
    assert_eq!(
        alert_state(&c, "warninglist_hit:warn-common:wf").await.as_deref(),
        Some("resolved")
    );
    // Back in, then the block bundle (in no profile) is deleted.
    put_entity(
        &c,
        "bundles",
        "wb",
        json!({"id": "wb", "name": "wb", "feeds": [{"feed": "wf"}, {"feed": "wf2"}]}),
    )
    .await;
    build(&c, "wb").await.unwrap();
    idle(&c).await;
    assert_eq!(open_warnings(&c).await.len(), 1);
    delete_entity(&c, "bundles", "wb").await;
    idle(&c).await;
    wait("the warning to resolve", || async {
        open_warnings(&c).await.is_empty()
    })
    .await;
}

/// CR9 (bundles.md §3): a feed in two block bundles with different rule types: one bundle's build
/// never clears or relabels the warning the other raised (warnings are per block bundle).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warnings_are_per_block_bundle() {
    let c = core().await;
    save(&c, "manual-warn", "||mycompany.example^\n").await;
    build(&c, "warn-common").await;
    manual_feed(&c, "wf", json!({"warn_on": ["warn-common"]})).await;
    manual_feed(&c, "g", json!({})).await;
    save(&c, "wf", "||ads.mycompany.example^\n").await;
    save(&c, "g", "||ads.mycompany.example^\n").await;
    put_entity(
        &c,
        "bundles",
        "b2",
        json!({"id": "b2", "name": "b2", "feeds": [{"feed": "wf"}]}),
    )
    .await;
    put_entity(
        &c,
        "bundles",
        "b1",
        json!({"id": "b1", "name": "b1", "feeds": [{"feed": "wf", "rule_types": ["ip"]}, {"feed": "g"}]}),
    )
    .await;
    build(&c, "b2").await.unwrap();
    idle(&c).await;
    build(&c, "b1").await.unwrap();
    idle(&c).await;
    assert_eq!(
        open_warnings(&c).await,
        vec![(
            "warn-common".to_string(),
            "ads.mycompany.example".to_string(),
            "wf".to_string(),
            "b2".to_string()
        )],
        "b1 takes no DNS rules from wf: it neither clears nor takes b2's warning"
    );
    assert_eq!(
        alert_state(&c, "warninglist_hit:warn-common:wf").await.as_deref(),
        Some("open")
    );
}

/// CR5 (bundles.md §3): an allow override resolves when its allow bundle has no downloaded feed
/// left to match it (the allow bundle's build re-checks its own warnings).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_allow_override_resolves_without_a_downloaded_allow_feed() {
    let c = core().await;
    save(&c, "manual-block", "||ads.example^\n").await;
    build(&c, "block-common").await.unwrap();
    // As if a downloaded feed of allow-common had matched ads.example (no downloaded feeds in
    // tests): its warning on block-common, with the default profile pairing the two.
    c.state
        .db
        .write(|db| {
            db.execute(
                "INSERT INTO warnings(kind, by_bundle_id, by_feed_id, value, feed_id, raw, bundle_id, first_seen,
                    last_seen, status) VALUES ('allow', 'allow-common', 'gone-download', 'ads.example', 'manual-block',
                    '||ads.example^', 'block-common', '2026-11-21T00:00:00Z', '2026-11-21T00:00:00Z', 'open')",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    save(&c, "manual-allow", "||unrelated.example^\n").await;
    build(&c, "allow-common").await;
    idle(&c).await;
    assert!(
        open_warnings(&c).await.is_empty(),
        "{:?}",
        open_warnings(&c).await
    );
}

/// CR8 (README §2 Restarts; bundles.md §3 When): a re-check a stop interrupted runs again at
/// start, and a pairing change made while core was down re-checks everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_rechecks_run_again_at_start() {
    let c = core().await;
    manual_feed(&c, "wf", json!({"warn_on": ["warn-common"]})).await;
    put_entity(
        &c,
        "bundles",
        "wb",
        json!({"id": "wb", "name": "wb", "feeds": [{"feed": "wf"}]}),
    )
    .await;
    save(&c, "wf", "||ads.mycompany.example^\n").await;
    build(&c, "wb").await.unwrap();
    save(&c, "manual-warn", "||mycompany.example^\n").await;
    build(&c, "warn-common").await;
    idle(&c).await;
    assert_eq!(open_warnings(&c).await.len(), 1);
    let pending: i64 = q(&c, "SELECT count(*) FROM warning_rechecks").await;
    assert_eq!(pending, 0, "a finished re-check leaves no record");
    // A stop interrupted warn-common's re-check: its record stands, its warnings aren't there.
    c.state
        .db
        .write(|db| {
            db.execute("DELETE FROM warnings", [])?;
            db.execute(
                "INSERT INTO warning_rechecks(target, seq) VALUES ('by:warn-common', 3)",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let model = c.state.config.model().await.unwrap();
    picket_core::compiler::warn::resume(&c.state, &model)
        .await
        .unwrap();
    idle(&c).await;
    assert_eq!(open_warnings(&c).await.len(), 1, "the re-check ran again");
    let pending: i64 = q(&c, "SELECT count(*) FROM warning_rechecks").await;
    assert_eq!(pending, 0);
    // A pairing digest other than the stored one: everything is re-checked.
    c.state
        .db
        .write(|db| {
            db.execute("DELETE FROM warnings", [])?;
            db.execute("UPDATE warning_pairing SET digest = 'older'", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    picket_core::compiler::warn::resume(&c.state, &model)
        .await
        .unwrap();
    idle(&c).await;
    assert_eq!(open_warnings(&c).await.len(), 1, "the full re-check ran");
    let pending: i64 = q(&c, "SELECT count(*) FROM warning_rechecks").await;
    assert_eq!(pending, 0);
}

/// Feeds and a bundle that exercise every bounded phase: IP rules in many IPv4 shards (one range
/// crossing a /8), IPv6, entity rules on keys and patterns, rewrites, patterns, and an
/// intelligent-tiering feed under `hot_max_mib`.
async fn every_phase_bundle(c: &Core) {
    manual_feed(c, "ipf", json!({"format": "plain"})).await;
    let mut ips = String::from("10.0.0.0/7\n2001:db8::/32\n2001:db8:1::5\n192.168.0.0/16\n");
    for i in 0..60 {
        ips.push_str(&format!("{}.{}.0.0/24\n{}.{}.7.9\n", 20 + i, i, 20 + i, i));
    }
    save(c, "ipf", &ips).await;
    manual_feed(c, "nf", json!({})).await;
    let mut names = String::from(
        "||ads*.example^\n/track[0-9]+/\n||rw.example^$dnsrewrite=1.2.3.4\n||rw.example^$dnsrewrite=NXDOMAIN;;\n\
         ||denyent.example^$denyallow=tracker.*\n*$denyallow=tracker.*|example.*,dnstype=AAAA\n@@||ok.a.example^\n",
    );
    for i in 0..40 {
        names.push_str(&format!(
            "||e{i}.example^$denyallow=site{i}.*\n||p{i}x*.example^\n||k{i}.example^\n"
        ));
    }
    save(c, "nf", &names).await;
    manual_feed(c, "itf", json!({})).await;
    let mut it = String::new();
    for i in 0..200 {
        it.push_str(&format!("||it{i}.example^\n"));
    }
    save(c, "itf", &it).await;
    put_entity(
        c,
        "bundles",
        "sb",
        json!({"id": "sb", "name": "sb", "hot_max_mib": 1, "feeds": [{"feed": "ipf"}, {"feed": "nf"},
               {"feed": "itf", "tier": "intelligent-tiering"}]}),
    )
    .await;
}

/// CR2 (core.md §3; README §2 Bounded): the IP pass, the pattern admission, the bundle-wide
/// inputs and the re-rank run a bounded amount per step, and tiny steps give the same,
/// byte-identical head as the defaults.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tiny_steps_give_the_same_head() {
    use picket_core::scheduler::HeavyJob;
    let a = core().await;
    let b = core().await;
    b.state.compiler.set_step_rows(Some(2));
    b.state.compiler.set_order_rows(Some(2));
    every_phase_bundle(&a).await;
    every_phase_bundle(&b).await;
    let ha = build(&a, "sb").await.unwrap();
    let hb = build(&b, "sb").await.unwrap();
    assert_eq!(ha, hb, "a fresh build: the same head, byte for byte");
    // An incremental build with new IP rules and a new pattern, step by step on b.
    for c in [&a, &b] {
        let mut ips = String::from("10.0.0.0/7\n2001:db8::/32\n2001:db8:1::5\n192.168.0.0/16\n");
        for i in 0..70 {
            ips.push_str(&format!("{}.{}.0.0/24\n{}.{}.7.9\n", 20 + i, i, 20 + i, i));
        }
        save(c, "ipf", &ips).await;
        let (_, f) = get(c, "/feeds/nf/file").await;
        let text = format!("{}||newpat*.example^\n", f["content"].as_str().unwrap());
        save(c, "nf", &text).await;
    }
    let ha = build(&a, "sb").await.unwrap();
    let mut job = picket_core::compiler::build::BuildJob::new(b.state.clone(), "sb");
    let mut phases: std::collections::BTreeMap<&'static str, usize> = Default::default();
    loop {
        let phase = job.phase_name();
        if phase == "done" {
            break;
        }
        *phases.entry(phase).or_default() += 1;
        job.step().await.unwrap();
    }
    // The job's "building" mark goes with it (the heavy lane drops a finished job).
    drop(job);
    let hb = settle(&b, "sb").await.unwrap();
    assert_eq!(ha, hb, "an incremental build: the same head ({phases:?})");
    for p in ["ips", "ipfold", "wide", "patterns", "ipshard"] {
        assert!(phases.get(p).copied().unwrap_or(0) >= 10, "{p}: {phases:?}");
    }
    // A re-rank (the daily one, or past hot_max_mib).
    let rerank = || picket_core::compiler::Request {
        reasons: ["rerank".to_string()].into(),
        rerank: true,
        ..Default::default()
    };
    for c in [&a, &b] {
        c.state
            .compiler
            .request(&c.state, "sb", rerank(), picket_core::scheduler::Priority::P0);
        idle(c).await;
    }
    let ha = settle(&a, "sb").await.unwrap();
    let hb = settle(&b, "sb").await.unwrap();
    assert_eq!(ha, hb, "the same head after a re-rank");
    let ta: String = q(&a, "SELECT state_json FROM bundle_builds WHERE bundle_id = 'sb'").await;
    let tb: String = q(&b, "SELECT state_json FROM bundle_builds WHERE bundle_id = 'sb'").await;
    // The same cutoff keys (the rank times are each core's ingest times).
    let tier = |s: &str| {
        let t = serde_json::from_str::<Value>(s).unwrap()["tier"].clone();
        (
            t["enter"]["hash"].clone(),
            t["stay"]["hash"].clone(),
            t["hot_tier_over"].clone(),
        )
    };
    assert_eq!(tier(&ta), tier(&tb), "the same cutoffs");
    assert!(tier(&ta).0.is_string(), "{ta}");
}
