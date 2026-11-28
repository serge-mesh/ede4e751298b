//! The tiering dry run (bundles.md §2 Tiering), the reply of a TC record (core.md §6; api.md §5)
//! and the per-device and per-profile summary (core.md §12; api.md §7), on the logs fixture
//! ([`common::logs::Setup`]).

use crate::common;

use std::time::Duration;

use common::bundles::{build_row, get, put_entity, save, settle, ui, wait};
use common::logs::{Setup, short, ts};
use jiff::Timestamp;
use serde_json::{Value, json};

/// A TC reply is the header, the question and any OPT, with TC set (core.md §6; api.md §5;
/// edge.md §8): a rewrite the edge made but cut to that form over UDP shows the question only,
/// never the records it built, which the client never got.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_truncated_rewrite_shows_the_tc_form() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut r = s.q(
        "b-tc",
        1,
        now,
        "www.example.com",
        "rewrite",
        json!({"step": 3, "bundle": "b1", "key": "www.example.com", "kind": "rich", "stage": "query"}),
    );
    r["tc"] = json!(true);
    r["answers"] = json!(["192.0.2.9"]);
    r["cname"] = json!(["mine.example"]);
    r["edns"] = json!({"udp": 1232});
    s.post(vec![r]).await;
    let id = picket_core::logs::record::record_id(&ts(now), &s.edge.id, "b-tc", 1);
    let (st, d) = get(&s.c, &format!("/logs/{id}")).await;
    assert_eq!(st, 200, "{d}");
    assert_eq!(d["response"]["source"], "tc", "{d}");
    assert_eq!(d["response"]["tc"], true);
    assert_eq!(d["response"]["incomplete"], false, "{d}");
    let recs = d["response"]["records"].as_array().unwrap();
    assert!(!recs.is_empty(), "the question: {d}");
    // The question and the OPT, never an answer record of the preview.
    assert!(
        recs.iter().all(|r| {
            let r = r.as_str().unwrap();
            r.starts_with(';') || r.contains(" OPT ")
        }),
        "a TC reply holds the question and OPT only, not the preview: {d}"
    );
    assert!(
        !recs
            .iter()
            .any(|r| r.as_str().unwrap().contains("CNAME") || r.as_str().unwrap().contains("192.0.2.9")),
        "{d}"
    );
    assert!(
        recs.iter()
            .any(|r| r.as_str().unwrap().contains("www.example.com")),
        "{d}"
    );
    assert!(d["response"]["wire"].as_str().is_some(), "{d}");
    // The preview stays in the record itself.
    assert_eq!(d["answers"], json!(["192.0.2.9"]), "{d}");
}

/// GET query-summary reads what it needs from core.db first and releases the reader before it
/// reads the log partitions (README §2 Bounded: the read pool is small and shared): while the
/// summary waits on a locked partition, every core.db reader stays free.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_summary_holds_no_core_db_reader_while_it_reads_partitions() {
    let s = Setup::new(None).await;
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    s.post(vec![s.block("b-s", 1, now, "ads.example", "ads.example")])
        .await;
    // An older partition in the window that only this test opens, locked so its reader waits.
    let old =
        picket_core::logs::partition::hour_start(&(Timestamp::now() - jiff::SignedDuration::from_hours(3)));
    let path =
        s.c.dir
            .path()
            .join("logs")
            .join(picket_core::logs::partition::partition_file_name(&old));
    drop(picket_core::logs::Partition::open(&path).unwrap());
    let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
    let (unlock_tx, unlock_rx) = std::sync::mpsc::channel::<()>();
    let locker = std::thread::spawn(move || {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA locking_mode = EXCLUSIVE; BEGIN EXCLUSIVE; CREATE TABLE lock_probe(x);")
            .unwrap();
        locked_tx.send(()).unwrap();
        let _ = unlock_rx.recv_timeout(Duration::from_secs(60));
        c.execute_batch("ROLLBACK").unwrap();
    });
    locked_rx.recv().unwrap();
    let req = ui(
        &s.c,
        reqwest::Method::GET,
        "/query-summary?device=tablet&window=24h",
    );
    let summary = tokio::spawn(async move { req.send().await.map(|r| r.status()) });
    // The summary is inside its partition scan, waiting on the lock (a 5 s busy timeout).
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = std::sync::Arc::new(std::sync::Mutex::new(go_rx));
    let mut reads = Vec::new();
    for _ in 0..4 {
        let (tx, rx) = (started_tx.clone(), go_rx.clone());
        let db = s.c.state.db.clone();
        reads.push(tokio::spawn(async move {
            db.read(move |_| {
                tx.send(()).unwrap();
                let _ = rx.lock().unwrap().recv_timeout(Duration::from_secs(20));
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap();
        }));
    }
    let mut started = 0;
    let until = std::time::Instant::now() + Duration::from_millis(2500);
    while started < 4 {
        let left = until.saturating_duration_since(std::time::Instant::now());
        if started_rx.recv_timeout(left).is_err() {
            break;
        }
        started += 1;
    }
    for _ in 0..4 {
        let _ = go_tx.send(());
    }
    for r in reads {
        r.await.unwrap();
    }
    let _ = unlock_tx.send(());
    locker.join().unwrap();
    let _ = summary.await;
    assert_eq!(
        started, 4,
        "every core.db reader is free while the summary reads log partitions"
    );
    // Unlocked, the summary answers.
    let (st, sum) = get(&s.c, "/query-summary?device=tablet&window=24h").await;
    assert_eq!(st, 200, "{sum}");
    assert_eq!(sum["queries"], 1, "{sum}");
    assert_eq!(sum["blocked"], 1, "{sum}");
    assert_eq!(sum["top_blocked"][0]["key"], "ads.example", "{sum}");
}

/// The bundle's `bundle_builds` row: (definition hash, head, built at).
async fn build_state(s: &Setup, bundle: &str) -> (String, Option<String>, Option<String>) {
    let b = bundle.to_string();
    s.c.state
        .db
        .read(move |db| Ok::<_, anyhow::Error>(picket_core::compiler::store::build_row(db, &b)?))
        .await
        .unwrap()
        .map(|r| (r.definition_hash, r.head_id, r.built_at))
        .unwrap()
}

async fn cold_keys(s: &Setup, bundle: &str) -> i64 {
    s.scalar_core(&format!(
        "SELECT count(*) FROM bundle_keys WHERE bundle_id = '{bundle}' AND part = 'cold'"
    ))
    .await
}

/// The current spec of a bundle.
async fn spec_of(s: &Setup, bundle: &str) -> picket_core::compiler::spec::Spec {
    let model = s.c.state.config.model().await.unwrap();
    picket_core::compiler::spec::Spec::of(model.bundles.get(bundle).unwrap(), &model)
}

/// b1 with `sec-only.example` only in f-sec, and the window's blocks: three of `ads.example`
/// (also in f-priv) and two under `sec-only.example`.
async fn blocks_in_window(s: &Setup, boot: &str) {
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n||sec-only.example^\n",
    )
    .await;
    common::bundles::build(&s.c, "b1").await.unwrap();
    let now = Timestamp::now() - jiff::SignedDuration::from_secs(30);
    let mut lines = Vec::new();
    for i in 0..3u64 {
        lines.push(s.block(boot, i + 1, now, "ads.example", "ads.example"));
    }
    for i in 0..2u64 {
        lines.push(s.block(boot, i + 10, now, "x.sec-only.example", "sec-only.example"));
    }
    s.post(lines).await;
}

/// bundles.md §2 Tiering: the dry run reports before the first split. A tier change is dry run
/// as soon as core sees it; until the report, builds go on with the split last applied (none
/// here: every key hot), and the report builds the split.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_split_waits_for_its_dry_run() {
    let s = Setup::new(None).await;
    blocks_in_window(&s, "b-h").await;
    let before = build_state(&s, "b1").await;
    s.c.state.compiler.set_dry_runs_paused(true);
    put_entity(
        &s.c,
        "bundles",
        "b1",
        json!({"id": "b1", "name": "b1", "feeds": [{"feed": "f-sec", "tier": "cold"}, {"feed": "f-priv"}]}),
    )
    .await;
    let spec = spec_of(&s, "b1").await;
    assert!(spec.cold_capable());
    // A feed update builds meanwhile, with every key still hot.
    save(
        &s.c,
        "f-sec",
        "||ads.example^\n||tracker.example^\n||198.51.100.7^\n||sec-only.example^\n||more.example^\n",
    )
    .await;
    s.c.state.compiler.request(
        &s.c.state,
        "b1",
        picket_core::compiler::Request::default(),
        picket_core::scheduler::Priority::P0,
    );
    wait("the held build", || async {
        let st = build_state(&s, "b1").await;
        !s.c.state.compiler.busy("b1") && st.1 != before.1
    })
    .await;
    let held = build_state(&s, "b1").await;
    assert_eq!(held.0, before.0, "built with the split last applied");
    assert_ne!(held.0, spec.def_hash);
    assert_eq!(
        cold_keys(&s, "b1").await,
        0,
        "no key cold before the dry run reports"
    );
    let eff = picket_core::compiler::tier::effective_spec(&s.c.state, spec.clone())
        .await
        .unwrap();
    assert!(!eff.cold_capable(), "{eff:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(build_state(&s, "b1").await.0, before.0, "still held");
    // The dry run, submitted as soon as the bundles are looked at (a configuration change, a
    // start, or the analysis loop's backstop); its report builds the split.
    s.c.state.compiler.set_dry_runs_paused(false);
    picket_core::compiler::tier::submit_dry_runs(&s.c.state).await;
    settle(&s.c, "b1").await;
    let (_, st) = get(&s.c, "/bundles/b1/status").await;
    assert_eq!(st["dry_run"]["status"], "done", "{st}");
    assert_eq!(st["dry_run"]["blocks"], 5, "{st}");
    // ads.example is also listed by f-priv (hot): only sec-only.example's two blocks go cold.
    assert_eq!(st["dry_run"]["cold_blocks"], 2, "{st}");
    let split = build_state(&s, "b1").await;
    assert_eq!(split.0, spec.def_hash);
    assert!(cold_keys(&s, "b1").await > 0, "the split is built");
    let finished = st["dry_run"]["finished_at"].as_str().unwrap().to_string();
    assert!(
        finished.as_str() <= split.2.as_deref().unwrap(),
        "the report came before the split: {finished} vs {:?}",
        split.2
    );
    let head = build_row(&s.c, "b1").await.unwrap().1.unwrap();
    let (_, _, h) = common::bundles::load(&s.c, &head);
    assert!(!h.cold_shards.is_empty());
}

/// bundles.md §2 Tiering: a dry run that hasn't reported within `DRY_RUN_HOLD` of core first
/// seeing the proposal no longer holds the split (policy choice: a tier change takes effect within
/// that bound).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_split_waits_at_most_the_hold() {
    let s = Setup::new(None).await;
    blocks_in_window(&s, "b-t").await;
    s.c.state.compiler.set_dry_runs_paused(true);
    put_entity(
        &s.c,
        "bundles",
        "b1",
        json!({"id": "b1", "name": "b1", "feeds": [{"feed": "f-sec", "tier": "cold"}, {"feed": "f-priv"}]}),
    )
    .await;
    let spec = spec_of(&s, "b1").await;
    let proposed = picket_core::compiler::tier::proposed(&spec).to_string();
    // Seen 31 minutes ago, its dry run still running.
    let seen = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_mins(31)));
    let p2 = proposed.clone();
    s.c.state
        .db
        .write(move |c| {
            c.execute(
                "INSERT INTO tier_dry_runs(bundle_id, definition_hash, proposed_json, status, started_at)
                 VALUES ('b1', 'h', ?1, 'running', ?2)",
                rusqlite::params![p2, seen],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let eff = picket_core::compiler::tier::effective_spec(&s.c.state, spec.clone())
        .await
        .unwrap();
    assert_eq!(eff.def_hash, spec.def_hash, "the hold is over");
    let released: Option<String> = s
        .scalar_core("SELECT released_json FROM tier_dry_runs WHERE bundle_id = 'b1'")
        .await;
    assert_eq!(released.as_deref(), Some(proposed.as_str()));
    // Seen just now: held.
    let now = picket_core::util::now_ts();
    s.c.state
        .db
        .write(move |c| {
            c.execute(
                "UPDATE tier_dry_runs SET started_at = ?1, released_json = NULL WHERE bundle_id = 'b1'",
                [now],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let eff = picket_core::compiler::tier::effective_spec(&s.c.state, spec.clone())
        .await
        .unwrap();
    assert_ne!(eff.def_hash, spec.def_hash, "held");
}

/// core.md §3 and README §2 Restarts: the dry run runs in bounded steps that persist their
/// position and counts, so a stop resumes it without counting a block twice; a newer proposal
/// replaces it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dry_run_steps_and_resumes() {
    use picket_core::scheduler::HeavyJob;
    let s = Setup::new(None).await;
    blocks_in_window(&s, "b-r").await;
    // More keys and two partitions: an older hour's blocks too.
    let then = Timestamp::now() - jiff::SignedDuration::from_hours(2);
    s.post(vec![
        s.block("b-r", 20, then, "y.sec-only.example", "sec-only.example"),
        s.block("b-r", 21, then, "tracker.example", "tracker.example"),
    ])
    .await;
    s.c.state.compiler.set_dry_runs_paused(true);
    s.c.state.compiler.set_step_rows(Some(1));
    put_entity(
        &s.c,
        "bundles",
        "b1",
        json!({"id": "b1", "name": "b1", "feeds": [{"feed": "f-sec", "tier": "cold"}, {"feed": "f-priv"}]}),
    )
    .await;
    let spec = spec_of(&s, "b1").await;
    let mut job = picket_core::compiler::tier::DryRunJob::new(s.c.state.clone(), spec.clone());
    assert!(matches!(
        job.step().await.unwrap(),
        picket_core::scheduler::Step::More
    ));
    assert!(matches!(
        job.step().await.unwrap(),
        picket_core::scheduler::Step::More
    ));
    let status: String = s
        .scalar_core("SELECT status FROM tier_dry_runs WHERE bundle_id = 'b1'")
        .await;
    assert_eq!(status, "running");
    let progress: Option<String> = s
        .scalar_core("SELECT progress_json FROM tier_dry_runs WHERE bundle_id = 'b1'")
        .await;
    assert!(progress.is_some());
    // A stop: the job is gone; a new one resumes from the stored position.
    drop(job);
    let mut job = picket_core::compiler::tier::DryRunJob::new(s.c.state.clone(), spec.clone());
    let mut steps = 0;
    while matches!(job.step().await.unwrap(), picket_core::scheduler::Step::More) {
        steps += 1;
        assert!(steps < 100);
    }
    assert!(steps >= 2, "one key per step: {steps}");
    let (_, st) = get(&s.c, "/bundles/b1/status").await;
    assert_eq!(st["dry_run"]["status"], "done", "{st}");
    assert_eq!(st["dry_run"]["blocks"], 7, "{st}");
    // sec-only.example: two blocks now, one two hours ago; ads and tracker are in f-priv (hot).
    assert_eq!(st["dry_run"]["cold_blocks"], 3, "{st}");
    assert_eq!(
        st["dry_run"]["detail"]["top_cold_keys"][0],
        json!({"key": "sec-only.example", "blocks": 3}),
        "{st}"
    );
    // A newer proposal: the old one's job stops at its first step.
    put_entity(
        &s.c,
        "bundles",
        "b1",
        json!({"id": "b1", "name": "b1", "feeds": [{"feed": "f-sec", "tier": "cold"}, {"feed": "f-priv", "tier": "cold"}]}),
    )
    .await;
    let mut stale = picket_core::compiler::tier::DryRunJob::new(s.c.state.clone(), spec.clone());
    assert!(matches!(
        stale.step().await.unwrap(),
        picket_core::scheduler::Step::Done
    ));
    let still: String = s
        .scalar_core("SELECT proposed_json FROM tier_dry_runs WHERE bundle_id = 'b1'")
        .await;
    assert_eq!(
        still,
        picket_core::compiler::tier::proposed(&spec).to_string(),
        "the stale job wrote nothing"
    );
    let _ = (short("x"), Value::Null);
}

/// Writes block records of `bundle` straight into the partition of `at`'s hour: `n` blocks, the
/// first `cold` of them answered from the cold part (`reason.cold`), and for the first
/// `attributed` cold ones an attribution naming `feed` decisive. Returns the next `seq`.
#[expect(
    clippy::too_many_arguments,
    reason = "a test record builder: one parameter per field the tests vary"
)]
fn blocks(
    c: &common::Core,
    at: Timestamp,
    seq: u64,
    bundle: &str,
    n: u64,
    cold: u64,
    attributed: u64,
    feed: &str,
) -> u64 {
    let store = c.state.logs.writer().store().clone();
    let p = store
        .open(&picket_core::logs::partition::hour_start(&at), true)
        .unwrap()
        .unwrap();
    for i in 0..n {
        let s = seq + i;
        let reason = json!({"step": 3, "bundle": bundle, "key": format!("org.example.n{s}"), "kind": "exact",
                            "stage": "query", "cold": i < cold});
        p.conn
            .execute(
                "INSERT INTO events(edge_id, boot, seq, ts, decision, bundle, reason_json) VALUES ('e-cold', 'b', ?1, ?2, 'block', ?3, ?4)",
                rusqlite::params![s as i64, ts(at), bundle, reason.to_string()],
            )
            .unwrap();
        if i < cold.min(attributed) {
            let m = json!({"matches": [
                {"bundle": bundle, "feed": feed, "text": "||x^", "role": "decisive", "rule_type": "dns", "stage": "query", "value": "x"},
                {"bundle": bundle, "feed": "f-other", "text": "||x^", "role": "also_matched", "rule_type": "dns", "stage": "query", "value": "x"}
            ], "self_check": "ok"});
            p.conn
                .execute(
                    "INSERT INTO attribution(edge_id, boot, seq, matches_json, status) VALUES ('e-cold', 'b', ?1, ?2, 'complete')",
                    rusqlite::params![s as i64, m.to_string()],
                )
                .unwrap();
        }
    }
    seq + n
}

/// Runs one cold-share check to its end (heavy lane).
async fn check_cold_share(c: &common::Core) {
    let before = c.state.scheduler.heavy.stats().completed;
    c.state.scheduler.heavy.submit(
        picket_core::scheduler::Priority::P3,
        Box::new(picket_core::logs::cold_share::ColdShareJob::new(c.state.clone())),
    );
    let end = tokio::time::Instant::now() + Duration::from_secs(120);
    while tokio::time::Instant::now() < end {
        let s = c.state.scheduler.heavy.stats();
        if s.completed > before && s.queued == 0 && s.running.is_none() {
            assert_eq!(s.failed, 0);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the cold-share check never finished");
}

/// core.md §9 `bundle_cold_share` (operational, warning; bundles.md §6): blocks a bundle's cold
/// part answered (`reason.cold` on the logged blocks) pass 1 % of its logged blocks over the
/// last 24 h; the details give the share per deciding feed (attribution). It resolves once the
/// share falls back to 1 % or below; blocks older than 24 h and bundles without a cold part
/// don't count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundle_cold_share_follows_the_last_24_hours_of_blocks() {
    use common::bundles::manual_feed;
    let s = Setup::new(None).await;
    let c = &s.c;
    c.state.clock.pin(true);
    manual_feed(c, "f-cold", json!({})).await;
    manual_feed(c, "f-hot", json!({})).await;
    put_entity(
        c,
        "bundles",
        "b-tiered",
        json!({"id": "b-tiered", "name": "b-tiered", "feeds": [{"feed": "f-cold", "tier": "cold"}, {"feed": "f-hot"}]}),
    )
    .await;
    put_entity(
        c,
        "bundles",
        "b-flat",
        json!({"id": "b-flat", "name": "b-flat", "feeds": [{"feed": "f-hot"}]}),
    )
    .await;
    let now = Timestamp::now();
    let hour_ago = now - jiff::SignedDuration::from_mins(70);
    let mut seq = 1;
    // 3 cold blocks of 100 (2 of them attributed to f-cold): 3 %.
    seq = blocks(c, hour_ago, seq, "b-tiered", 100, 3, 2, "f-cold");
    // Older than 24 h: not counted.
    seq = blocks(
        c,
        now - jiff::SignedDuration::from_hours(26),
        seq,
        "b-tiered",
        50,
        50,
        0,
        "f-cold",
    );
    // A bundle with no cold part: never alerts, whatever its records say.
    seq = blocks(c, hour_ago, seq, "b-flat", 10, 5, 0, "f-hot");
    check_cold_share(c).await;
    let a = c
        .state
        .alerts
        .get_by_key("bundle_cold_share:b-tiered")
        .await
        .unwrap()
        .expect("raised");
    assert_eq!(a.state, picket_core::alerts::AlertState::Open);
    assert_eq!(a.alert_type, picket_core::alerts::AlertType::Operational);
    assert_eq!(a.severity, picket_core::alerts::Severity::Warning);
    assert_eq!(a.bundle.as_deref(), Some("b-tiered"));
    assert_eq!(a.details["blocks"], 100, "{}", a.details);
    assert_eq!(a.details["cold_blocks"], 3);
    assert!((a.details["share"].as_f64().unwrap() - 0.03).abs() < 1e-9);
    assert_eq!(
        a.details["feeds"],
        json!([{"feed": "f-cold", "cold_blocks": 2, "share": 0.02}])
    );
    assert_eq!(a.details["unattributed_cold_blocks"], 1);
    assert!(
        c.state
            .alerts
            .get_by_key("bundle_cold_share:b-flat")
            .await
            .unwrap()
            .is_none()
    );
    // A second check with the same records changes nothing (no new raise).
    check_cold_share(c).await;
    assert_eq!(
        c.state
            .alerts
            .get_by_key("bundle_cold_share:b-tiered")
            .await
            .unwrap()
            .unwrap()
            .count,
        1
    );
    // 300 more hot blocks: 3 of 400 is 0.75 %, so it resolves.
    blocks(
        c,
        now - jiff::SignedDuration::from_mins(5),
        seq,
        "b-tiered",
        300,
        0,
        0,
        "f-cold",
    );
    check_cold_share(c).await;
    let a = c
        .state
        .alerts
        .get_by_key("bundle_cold_share:b-tiered")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.state, picket_core::alerts::AlertState::Resolved);
}

/// core.md §9 Thresholds: an operational kind fires only once its condition has held for its
/// threshold (`alerts.thresholds.*`; `bundle_cold_share` has no default, so at once). With 12 h
/// set, a share past 1 % raises at the first check 12 h after one first saw it there; it then
/// resolves only once the share has stayed at or below 1 % as long (the practice of
/// `upstream_invalid_spike`, "5 min below its threshold"), so a share hovering at 1 % doesn't
/// raise and resolve every hour. Since when each held is kept in core.db (README §2 Restarts).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundle_cold_share_waits_for_its_threshold_both_ways() {
    use common::bundles::manual_feed;
    let s = Setup::new(Some(
        json!({"alerts": {"thresholds": {"bundle_cold_share": "12h"}}}),
    ))
    .await;
    let c = &s.c;
    c.state.clock.pin(true);
    manual_feed(c, "f-cold", json!({})).await;
    manual_feed(c, "f-hot", json!({})).await;
    put_entity(
        c,
        "bundles",
        "b-tiered",
        json!({"id": "b-tiered", "name": "b-tiered", "feeds": [{"feed": "f-cold", "tier": "cold"}, {"feed": "f-hot"}]}),
    )
    .await;
    let now = Timestamp::now();
    // 3 cold blocks of 100: 3 %.
    let seq = blocks(
        c,
        now - jiff::SignedDuration::from_mins(70),
        1,
        "b-tiered",
        100,
        3,
        0,
        "f-cold",
    );
    let state = || async {
        c.state
            .alerts
            .get_by_key("bundle_cold_share:b-tiered")
            .await
            .unwrap()
            .map(|a| (a.state, a.count))
    };
    let backdate = |col: &'static str| async move {
        let at = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(13)));
        c.state
            .db
            .write(move |db| {
                let n = db.execute(
                    &format!("UPDATE cold_share_state SET {col} = ?1 WHERE bundle_id = 'b-tiered' AND {col} IS NOT NULL"),
                    [at],
                )?;
                Ok::<_, anyhow::Error>(n)
            })
            .await
            .unwrap()
    };
    check_cold_share(c).await;
    assert_eq!(state().await, None, "past 1 % for less than 12 h");
    check_cold_share(c).await;
    assert_eq!(state().await, None);
    // 13 h after the first check found it past 1 %.
    assert_eq!(backdate("above_since").await, 1);
    check_cold_share(c).await;
    assert_eq!(state().await, Some((picket_core::alerts::AlertState::Open, 1)));
    // Back below 1 % (3 of 400): open until it has stayed there 12 h.
    blocks(
        c,
        now - jiff::SignedDuration::from_mins(5),
        seq,
        "b-tiered",
        300,
        0,
        0,
        "f-cold",
    );
    check_cold_share(c).await;
    assert_eq!(state().await, Some((picket_core::alerts::AlertState::Open, 1)));
    assert_eq!(backdate("below_since").await, 1);
    check_cold_share(c).await;
    assert_eq!(
        state().await,
        Some((picket_core::alerts::AlertState::Resolved, 1))
    );
    let rows: i64 = s.scalar_core("SELECT count(*) FROM cold_share_state").await;
    assert_eq!(rows, 0, "nothing held, nothing kept");
}
