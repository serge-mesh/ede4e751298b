//! The retention job (storage.md §4): it deletes what the foundation owns once it is older than
//! its window, keeps what is younger, and never touches alerts.

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

use jiff::Timestamp;
use picket_core::scheduler::Priority;

#[tokio::test(flavor = "multi_thread")]
async fn hourly_job_ages_out_foundation_data() {
    let c = common::start_core(Some(
        serde_json::json!({"web": {"tls": "off"}, "retention": {"config_changes": "1h"}}),
    ))
    .await;
    c.state.clock.pin(true);
    let old = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(80)));
    let recent = picket_core::util::now_ts();
    let (o, r) = (old.clone(), recent.clone());
    c.state
        .db
        .write(move |conn| {
            for (at, id) in [(&o, "old"), (&r, "new")] {
                conn.execute(
                    "INSERT INTO config_changes(at, entity, entity_id, diff_json) VALUES (?1, 'test', ?2, '{}')",
                    rusqlite::params![at, id],
                )?;
                conn.execute(
                    "INSERT INTO edge_events(edge_id, boot, seq, at, kind) VALUES ('e1', 'b', ?1, ?2, 'panic')",
                    rusqlite::params![if id == "old" { 1 } else { 2 }, at],
                )?;
                conn.execute(
                    "INSERT INTO feed_checks(feed_id, t, ok) VALUES ('f', ?1, 1)",
                    [at],
                )?;
            }
            // WITHOUT ROWID tables age out too.
            for (id, at) in [("old", &o), ("new", &r)] {
                conn.execute(
                    "INSERT INTO temp_allows(edge_id, allow_id, created_at, ended_at) VALUES ('e1', ?1, ?2, ?2)",
                    rusqlite::params![id, at],
                )?;
                conn.execute(
                    "INSERT INTO crosscheck_seen(qname, qtype, at) VALUES (?1, 1, ?2)",
                    rusqlite::params![format!("{id}.example"), at],
                )?;
            }
            // Pending edge keys not seen for 30 days are forgotten.
            let stale = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(24 * 31)));
            for (key, seen) in [("SHA256:stale", &stale), ("SHA256:fresh", &o)] {
                conn.execute(
                    "INSERT INTO edge_pending(key_sha256, addr, first_seen, last_seen) VALUES (?1, NULL, ?2, ?2)",
                    rusqlite::params![key, seen],
                )?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    // An old alert stays: alerts are kept until deleted in the UI.
    let a = c
        .state
        .alerts
        .raise(picket_core::alerts::RaiseSpec::new(
            "feed_held",
            picket_core::alerts::Severity::Warning,
            "k",
            "t",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let id = a.id;
    c.state
        .db
        .write(move |conn| {
            conn.execute(
                "UPDATE alerts SET first_seen = ?1, last_seen = ?1 WHERE id = ?2",
                rusqlite::params![old, id],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();

    // The heavy lane first finishes what start-up queued (the manual feeds' runs).
    let idle = |s: &picket_core::scheduler::HeavyStats| s.queued == 0 && s.running.is_none();
    for _ in 0..500 {
        let feeds_busy = [
            "manual-allow",
            "manual-block",
            "manual-warn",
            "lookup-exclude",
            "canaries",
        ]
        .iter()
        .any(|f| c.state.feeds.is_busy(f));
        if idle(&c.state.scheduler.heavy.stats()) && !feeds_busy {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let before = c.state.scheduler.heavy.stats();
    c.state.scheduler.heavy.submit(
        Priority::P3,
        Box::new(picket_core::retention::RetentionJob::new(c.state.clone(), true)),
    );
    for _ in 0..200 {
        let s = c.state.scheduler.heavy.stats();
        if s.completed > before.completed && idle(&s) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut stats = c.state.scheduler.heavy.stats();
    stats.completed -= before.completed;
    stats.failed -= before.failed;
    // Another start-up job (a debounced bundle build on a loaded machine) may finish inside the
    // window too; the counts below show what the retention job itself did.
    assert!(
        stats.completed >= 1 && stats.failed == 0,
        "the retention job ran to the end: {stats:?}"
    );
    let counts: (i64, i64, i64, i64, i64) = c
        .state
        .db
        .read(|conn| {
            Ok::<_, anyhow::Error>((
                conn.query_row(
                    "SELECT count(*) FROM config_changes WHERE entity = 'test' AND entity_id = 'old'",
                    [],
                    |r| r.get(0),
                )?,
                conn.query_row(
                    "SELECT count(*) FROM config_changes WHERE entity = 'test' AND entity_id = 'new'",
                    [],
                    |r| r.get(0),
                )?,
                conn.query_row("SELECT count(*) FROM edge_events", [], |r| r.get(0))?,
                conn.query_row("SELECT count(*) FROM feed_checks WHERE feed_id = 'f'", [], |r| {
                    r.get(0)
                })?,
                conn.query_row("SELECT count(*) FROM alerts", [], |r| r.get(0))?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(counts.0, 0, "config change past its window deleted");
    assert_eq!(counts.1, 1, "recent config change kept");
    assert_eq!(counts.2, 1, "edge events: 72 h window");
    assert_eq!(counts.3, 2, "feed checks keep 60 days");
    assert_eq!(counts.4, 1, "alerts stay until deleted");
    let pending: Vec<String> = c
        .state
        .db
        .read(|conn| {
            let mut st = conn.prepare("SELECT key_sha256 FROM edge_pending ORDER BY key_sha256")?;
            let v = st
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap();
    assert_eq!(pending, vec!["SHA256:fresh"], "stale pending keys forgotten");
    let left: (Vec<String>, Vec<String>) = c
        .state
        .db
        .read(|conn| {
            let mut a = conn.prepare("SELECT allow_id FROM temp_allows")?;
            let mut x = conn.prepare("SELECT qname FROM crosscheck_seen")?;
            Ok::<_, anyhow::Error>((
                a.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?,
                x.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(left.0, vec!["new"], "temporary-allow history: 72 h");
    assert_eq!(
        left.1,
        vec!["new.example"],
        "cross-check admissions: dedupe window"
    );
}

async fn run_retention(c: &common::Core) {
    let before = c.state.scheduler.heavy.stats().completed;
    c.state.scheduler.heavy.submit(
        Priority::P3,
        Box::new(picket_core::retention::RetentionJob::new(c.state.clone(), false)),
    );
    // A deadline generous enough for a loaded CI machine (it was 5 s of polls).
    let end = tokio::time::Instant::now() + Duration::from_secs(120);
    while tokio::time::Instant::now() < end {
        let s = c.state.scheduler.heavy.stats();
        if s.completed > before && s.queued == 0 && s.running.is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the retention job never finished");
}

async fn config_changes_named(c: &common::Core, id: &str) -> i64 {
    let id = id.to_string();
    c.state
        .db
        .read(move |conn| {
            Ok::<_, anyhow::Error>(conn.query_row(
                "SELECT count(*) FROM config_changes WHERE entity = 'test' AND entity_id = ?1",
                [id],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn deletes_wait_for_a_synchronised_clock() {
    // README §2 Clocks: retention cutoffs are wall-clock decisions; with the clock not yet
    // synchronised (it may be far ahead), nothing is deleted.
    let c = common::start_core(Some(
        serde_json::json!({"web": {"tls": "off"}, "retention": {"config_changes": "1h"}}),
    ))
    .await;
    c.state.clock.pin(false);
    let old = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(80)));
    c.state
        .db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO config_changes(at, entity, entity_id, diff_json) VALUES (?1, 'test', 'old', '{}')",
                [old],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(
        config_changes_named(&c, "old").await,
        1,
        "kept while unsynchronised"
    );
    c.state.clock.pin(true);
    run_retention(&c).await;
    assert_eq!(
        config_changes_named(&c, "old").await,
        0,
        "deleted once synchronised"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn temporary_allows_clamp_pins_and_metric_baselines_age_out() {
    // storage.md §4 (review A5, A10, A11): an allow is over when its end is logged, when the edge
    // acknowledged a revoke list holding it (one core never heard of too) or past its expiry;
    // one still on the revoke list stays. Hours of clamped records go with the log window.
    // Metrics keep each series' newest older value with the sample it came with.
    let c = common::start_core(Some(serde_json::json!({"web": {"tls": "off"}}))).await;
    c.state.clock.pin(true);
    let now = Timestamp::now();
    let old = picket_core::util::ts(&(now - jiff::SignedDuration::from_hours(80)));
    let soon = picket_core::util::ts(&(now + jiff::SignedDuration::from_hours(1)));
    let recent = picket_core::util::ts(&now);
    let (o, s, r) = (old.clone(), soon.clone(), recent.clone());
    c.state
        .db
        .write(move |conn| {
            let ins = |id: &str, cols: &str, vals: &[&str]| -> rusqlite::Result<usize> {
                let marks: Vec<String> = (0..vals.len()).map(|i| format!("?{}", i + 3)).collect();
                let mut params: Vec<&dyn rusqlite::ToSql> = vec![&"e1", &id];
                for v in vals {
                    params.push(v);
                }
                conn.execute(
                    &format!(
                        "INSERT INTO temp_allows(edge_id, allow_id, {cols}) VALUES (?1, ?2, {})",
                        marks.join(", ")
                    ),
                    params.as_slice(),
                )
            };
            ins("expired", "expires_at, updated_at", &[&o, &o])?;
            ins("acked-unknown", "revoke_requested_at, revoke_acked_at", &[&o, &o])?;
            ins(
                "listed",
                "revoke_requested_at, expires_at, updated_at",
                &[&o, &o, &o],
            )?;
            ins("open", "expires_at, updated_at", &[&s, &o])?;
            ins("ended", "ended_at, updated_at", &[&o, &o])?;
            ins("no-expiry-recent", "updated_at", &[&r])?;
            for (seq, hour) in [(1, &o), (2, &r)] {
                conn.execute(
                    "INSERT INTO log_clamped(edge_id, boot, lo, hi, hour) VALUES ('e1', 'b', ?1, ?1, ?2)",
                    rusqlite::params![seq, hour],
                )?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    // Metrics: fw.rejects was in the edge's heartbeat at t0 but not at t1 (the newest older
    // sample); queries in both.
    let ms = |h: i64| (now - jiff::SignedDuration::from_hours(h)).as_millisecond();
    let (t0, t1, t2) = (ms(82), ms(81), ms(1));
    c.state
        .metrics_db
        .write(move |conn| {
            for t in [t0, t1, t2] {
                conn.execute(
                    "INSERT INTO samples(edge_id, ts, boot, up_ms) VALUES ('e1', ?1, 'b', 1000)",
                    [t],
                )?;
            }
            conn.execute(
                "INSERT INTO series(name, labels_json) VALUES ('fw.rejects', '{\"edge\":\"e1\"}')",
                [],
            )?;
            let fw = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO series(name, labels_json) VALUES ('queries', '{\"edge\":\"e1\"}')",
                [],
            )?;
            let q = conn.last_insert_rowid();
            for (id, t) in [(fw, t0), (fw, t2), (q, t0), (q, t1), (q, t2)] {
                conn.execute(
                    "INSERT INTO points(series_id, ts, value) VALUES (?1, ?2, 1)",
                    rusqlite::params![id, t],
                )?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    let (allows, clamped): (Vec<String>, Vec<i64>) = c
        .state
        .db
        .read(|conn| {
            let mut a = conn.prepare("SELECT allow_id FROM temp_allows ORDER BY allow_id")?;
            let mut l = conn.prepare("SELECT lo FROM log_clamped ORDER BY lo")?;
            Ok::<_, anyhow::Error>((
                a.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?,
                l.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(allows, vec!["listed", "no-expiry-recent", "open"]);
    assert_eq!(clamped, vec![2]);
    let (samples, points): (Vec<i64>, Vec<(String, i64)>) = c
        .state
        .metrics_db
        .read(|conn| {
            let mut s = conn.prepare("SELECT ts FROM samples WHERE edge_id = 'e1' ORDER BY ts")?;
            let mut p = conn.prepare(
                "SELECT s.name, p.ts FROM points p JOIN series s ON s.id = p.series_id
                 WHERE s.labels_json = '{\"edge\":\"e1\"}' ORDER BY s.name, p.ts",
            )?;
            Ok::<_, anyhow::Error>((
                s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?,
                p.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(samples, vec![t0, t1, t2], "t0 is fw.rejects' baseline sample");
    assert_eq!(
        points,
        vec![
            ("fw.rejects".to_string(), t0),
            ("fw.rejects".to_string(), t2),
            ("queries".to_string(), t1),
            ("queries".to_string(), t2)
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clamped_records_hour_stays_pinned_while_its_partition_is_kept() {
    // storage.md §4, core.md §6 (review round 2, CC3): the hour a clamped record's first attempt
    // went to is kept as long as that hour's partition, which goes once the whole hour is past
    // the window; a retry in between is still a duplicate. The window is chosen so that its
    // start falls mid-hour.
    let now = Timestamp::now();
    let minute = now.as_second().rem_euclid(3600) / 60;
    let minutes = 72 * 60 + (minute - 30).rem_euclid(60);
    let c = common::start_core(Some(
        serde_json::json!({"web": {"tls": "off"}, "retention": {"query_logs": format!("{minutes}m")}}),
    ))
    .await;
    c.state.clock.pin(true);
    let a = common::edge::FakeEdge::registered(&c, "edge-a").await;
    let window = jiff::SignedDuration::from_mins(minutes);
    // The hour the window starts in: it began before the window, it ends inside it.
    let hour = picket_core::logs::partition::hour_start(&(now - window));
    let raw = hour + jiff::SignedDuration::from_hours(1) + jiff::SignedDuration::from_secs(30);
    let line =
        common::edge::query("b1", 7, &picket_api::time::format_micros(&raw), "x.example", None).to_string();
    let attempt = |at: Timestamp| {
        let ctx = picket_core::logs::decode::Context {
            now: at,
            oldest: at - window,
        };
        picket_core::logs::decode::decode_lines(line.as_bytes(), &ctx, &picket_core::logs::decode::LIMITS)
            .unwrap()
    };
    let r1 = c
        .state
        .logs
        .store_batch(
            &c.state,
            &a.id,
            &a.fingerprint,
            attempt(hour + jiff::SignedDuration::from_mins(59)),
        )
        .await
        .unwrap();
    assert_eq!(r1.stored, 1);
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    let r2 = c
        .state
        .logs
        .store_batch(&c.state, &a.id, &a.fingerprint, attempt(Timestamp::now()))
        .await
        .unwrap();
    assert_eq!((r2.stored, r2.duplicates), (0, 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edges_series_share_frees_up_when_its_series_age_out() {
    // README §2 capped shares, core.md §10, storage.md §4 (review round 2, CC4): an edge at its
    // series share has values for new series dropped, cheaply; once retention leaves a series
    // with no value in the window, the series goes and its room in the share comes back.
    use common::edge::{FakeEdge, heartbeat, hello, send};
    use serde_json::json;
    let c = common::start_core(Some(serde_json::json!({"web": {"tls": "off"}}))).await;
    c.state.clock.pin(true);
    c.state.edges.hub.set_heartbeat_interval(Duration::ZERO);
    let a = FakeEdge::registered(&c, "edge-a").await;
    let cap = picket_core::metrics::store::MAX_SERIES_PER_EDGE;
    let old = (Timestamp::now() - jiff::SignedDuration::from_hours(80)).as_millisecond();
    let edge = a.id.clone();
    c.state
        .metrics_db
        .write(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO samples(edge_id, ts, boot, up_ms) VALUES (?1, ?2, 'b0', 1000)",
                rusqlite::params![edge, old],
            )?;
            for i in 0..cap {
                tx.execute(
                    "INSERT INTO series(name, labels_json) VALUES ('upstream.queries', ?1)",
                    [serde_json::json!({"edge": edge, "upstream": format!("gone-{i}")}).to_string()],
                )?;
                tx.execute(
                    "INSERT INTO points(series_id, ts, value) VALUES (?1, ?2, 1)",
                    rusqlite::params![tx.last_insert_rowid(), old],
                )?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let (mut ws, _) = a.session(hello("b1")).await;
    let mut events = c.state.events.subscribe();
    let heartbeat_done = |rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>| {
        let rx = rx.resubscribe();
        async move {
            let mut rx = rx;
            tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    match rx.recv().await {
                        Ok(ev) if ev.kind == "edge_status" && ev.data["event"] == "heartbeat" => return,
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => panic!("events closed"),
                    }
                }
            })
            .await
            .expect("the heartbeat was processed");
        }
    };
    // Many new map keys over the share.
    let mut hb = heartbeat("b1", Timestamp::now(), 1000, 10);
    let ups: serde_json::Map<String, serde_json::Value> = (0..200)
        .map(|i| {
            (
                format!("new-{i}"),
                json!({"queries": 1, "hedges": 0, "errors": 0}),
            )
        })
        .collect();
    hb["metrics"]["upstream"] = serde_json::Value::Object(ups);
    let done = heartbeat_done(&mut events);
    send(&mut ws, json!({"type": "heartbeat", "data": hb})).await;
    done.await;
    assert_eq!(
        c.state.metrics.series.scans(),
        1,
        "one count of the table, not one per value over the share"
    );
    let count = |name: &'static str| {
        let (mdb, edge) = (c.state.metrics_db.clone(), a.id.clone());
        async move {
            mdb.read(move |conn| {
                Ok::<i64, anyhow::Error>(conn.query_row(
                    "SELECT count(*) FROM series WHERE name = ?1 AND json_extract(labels_json, '$.edge') = ?2",
                    rusqlite::params![name, edge],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap()
        }
    };
    assert_eq!(count("queries").await, 0, "over the share");
    assert_eq!(count("upstream.queries").await, cap);
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(count("upstream.queries").await, 0, "no value left in the window");
    let done = heartbeat_done(&mut events);
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": heartbeat("b1", Timestamp::now(), 31_000, 20)}),
    )
    .await;
    done.await;
    assert_eq!(count("queries").await, 1, "room in the share again");
    assert_eq!(c.state.metrics.series.scans(), 1, "the counts follow retention");
}

/// One integer from core.db.
async fn scalar(c: &common::Core, sql: &'static str) -> i64 {
    c.state
        .db
        .read(move |conn| Ok::<i64, anyhow::Error>(conn.query_row(sql, [], |r| r.get(0))?))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn key_hits_go_once_their_key_leaves_the_bundle() {
    // storage.md §4 `bundle_key_hits`: "while the key is in the bundle". Hits whose key left its
    // bundle, a retired bundle's hits and a hit stored without its key go, across more than one
    // step of the walk; a hit of a key still in its bundle stays.
    let c = common::start_core(Some(serde_json::json!({"web": {"tls": "off"}}))).await;
    c.state.clock.pin(true);
    let now = picket_core::util::now_ts();
    c.state
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let hash = |i: u32| (i as u128).to_be_bytes().to_vec();
            tx.execute(
                "INSERT INTO bundle_keys(bundle_id, part, shard, hash128, key, value) VALUES ('zz', 'hot', 0, ?1, 'org.kept', 2)",
                [hash(0)],
            )?;
            tx.execute(
                "INSERT INTO bundle_key_hits(bundle_id, hash128, last_hit_at, key) VALUES ('zz', ?1, ?2, 'org.kept')",
                rusqlite::params![hash(0), now],
            )?;
            // The same key in another bundle that no longer has it.
            tx.execute(
                "INSERT INTO bundle_key_hits(bundle_id, hash128, last_hit_at, key) VALUES ('aa', ?1, ?2, 'org.kept')",
                rusqlite::params![hash(0), now],
            )?;
            tx.execute(
                "INSERT INTO bundle_key_hits(bundle_id, hash128, last_hit_at, key) VALUES ('zz', ?1, ?2, NULL)",
                rusqlite::params![hash(1), now],
            )?;
            let chunk = picket_core::retention::CHUNK as u32;
            for i in 2..2 * chunk + 3 {
                tx.execute(
                    "INSERT INTO bundle_key_hits(bundle_id, hash128, last_hit_at, key) VALUES ('mm', ?1, ?2, ?3)",
                    rusqlite::params![hash(i), now, format!("org.gone{i}")],
                )?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(scalar(&c, "SELECT count(*) FROM bundle_key_hits").await, 1);
    assert_eq!(
        scalar(
            &c,
            "SELECT count(*) FROM bundle_key_hits WHERE bundle_id = 'zz' AND key = 'org.kept'"
        )
        .await,
        1,
        "a key still in its bundle keeps its hit"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edge_boot_stays_while_retained_records_reference_it() {
    // storage.md §4 edge boots: kept while current, the log window after `superseded_at`, and
    // while retained records or kept examples reference them. A superseded boot's spooled
    // records can still arrive for the window after it (the edge ages its spool by the same
    // window, edge.md §11), and the hour of their partition is their own time: an edge clock
    // ahead of core's puts them in a partition that outlives any margin past `superseded_at`
    // (README §2: timestamps are only clamped to core's clock, not to `superseded_at`). So a
    // boot stays while a retained partition or `edge_events` row holds its records.
    let c = common::start_core(Some(serde_json::json!({"web": {"tls": "off"}}))).await;
    c.state.clock.pin(true);
    let ago = |m: i64| picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_mins(m)));
    let window = 72 * 60;
    let (inside, past, long) = (ago(window + 30), ago(window + 61), ago(window + 600));
    let first = ago(window + 900);
    // A record of the skewed boot an hour after it was superseded by core's clock, in a
    // partition kept for most of the window yet; one of the past boot's in a partition past it.
    let store = picket_core::logs::LogStore::new(&c.state.data_dir);
    for (boot, at) in [
        ("skewed", Timestamp::now() - jiff::SignedDuration::from_mins(30)),
        (
            "past",
            Timestamp::now() - jiff::SignedDuration::from_mins(window + 200),
        ),
    ] {
        let hour = picket_core::logs::partition::hour_start(&at);
        let p = store.open(&hour, true).unwrap().unwrap();
        p.conn
            .execute(
                "INSERT INTO events(edge_id, boot, seq, ts) VALUES ('e1', ?1, 1, ?2)",
                rusqlite::params![boot, picket_core::util::ts(&at)],
            )
            .unwrap();
    }
    let recent = ago(10);
    c.state
        .db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO edge_events(edge_id, boot, seq, at, kind) VALUES ('e1', 'event', 1, ?1, 'panic')",
                [&recent],
            )?;
            for (boot, sup) in [
                ("current", None),
                ("last-hour", Some(&inside)),
                ("past", Some(&past)),
                ("skewed", Some(&past)),
                ("event", Some(&long)),
                ("example", Some(&long)),
            ] {
                conn.execute(
                    "INSERT INTO edge_boots(edge_id, boot, edge_version, first_seen, superseded_at) VALUES ('e1', ?1, '1.0.0', ?2, ?3)",
                    rusqlite::params![boot, first, sup],
                )?;
            }
            conn.execute(
                "INSERT INTO wire_examples(alert_id, edge_id, boot, seq, kind, record_json, at) VALUES (1, 'e1', 'example', 1, 'x', '{}', ?1)",
                [&first],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    let boots: Vec<String> = c
        .state
        .db
        .read(|conn| {
            let mut st = conn.prepare("SELECT boot FROM edge_boots ORDER BY boot")?;
            let v = st
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await
        .unwrap();
    assert_eq!(boots, vec!["current", "event", "example", "last-hour", "skewed"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blob_goes_only_once_nothing_names_it() {
    // storage.md §4 (raw downloads: "always keep the blobs named by retained feed_runs rows and
    // by manual_files"; bundle and verdict-set blobs while a retained version names them):
    // blobs are deduplicated by hash and keep the kind they were first registered with, so one
    // blob can be a release, a feed's download, a bundle's or a verdict set's file at once. Each
    // collector deletes a blob of its kinds only once no row of any kind names it.
    let c = common::start_core(Some(serde_json::json!({"web": {"tls": "off"}}))).await;
    c.state.clock.pin(true);
    // Start-up's feed runs and builds first: they register blobs of their own.
    common::settled(&c).await;
    let dir = c.state.data_dir.clone();
    let long_ago = picket_core::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(24 * 30)));
    let blobs: Vec<String> = c
        .state
        .db
        .write(move |conn| {
            use picket_core::blobs::{kind, put};
            let tx = conn.transaction()?;
            let now = picket_core::util::now_ts();
            // Each first registered as one kind and named only by a row of another.
            let release = put(&tx, &dir, kind::RELEASE, b"edge release bytes a feed downloaded")?;
            tx.execute(
                "INSERT INTO feed_runs(feed_id, downloaded_at, status, blob) VALUES ('manual-block', ?2, 'rejected', ?1)",
                rusqlite::params![release, now],
            )?;
            let bundle = put(&tx, &dir, kind::BUNDLE, b"bundle bytes a manual file holds")?;
            tx.execute(
                "INSERT INTO manual_files(feed_id, blob, version, saved_at) VALUES ('no-such-feed', ?1, 'v', ?2)",
                rusqlite::params![bundle, now],
            )?;
            let set = put(&tx, &dir, kind::VERDICT_SET, b"verdict-set bytes a release holds")?;
            tx.execute(
                "INSERT INTO edge_releases(version, arch, blob, minisig, added_at) VALUES ('0.0.7', 'x86_64', ?1, 'sig', ?2)",
                rusqlite::params![set, now],
            )?;
            let download = put(&tx, &dir, kind::DOWNLOAD, b"downloaded bytes a bundle version holds")?;
            tx.execute(
                "INSERT INTO bundle_version_blobs(bundle_id, head_id, blake3) VALUES ('gone', 'h', ?1)",
                [&download],
            )?;
            let blobs = vec![release, bundle, set, download];
            for b in &blobs {
                tx.execute("UPDATE blobs SET created_at = ?1 WHERE blake3 = ?2", [&long_ago, b])?;
            }
            tx.commit()?;
            Ok::<_, anyhow::Error>(blobs)
        })
        .await
        .unwrap();
    let stored = || async {
        let mut out = Vec::new();
        for b in &blobs {
            let p = picket_core::blobs::path(&c.state.data_dir, b).unwrap();
            let b = b.clone();
            let row = c
                .state
                .db
                .read(move |conn| picket_core::blobs::info(conn, &b))
                .await
                .unwrap();
            out.push((row.is_some(), p.exists()));
        }
        out
    };
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(stored().await, vec![(true, true); 4], "each still named");

    // Nothing names them any more: each goes with its kind's collector.
    let named = blobs.clone();
    c.state
        .db
        .write(move |conn| {
            conn.execute("DELETE FROM feed_runs WHERE blob = ?1", [&named[0]])?;
            conn.execute("DELETE FROM manual_files WHERE blob = ?1", [&named[1]])?;
            conn.execute("DELETE FROM edge_releases WHERE blob = ?1", [&named[2]])?;
            conn.execute("DELETE FROM bundle_version_blobs WHERE blake3 = ?1", [&named[3]])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    run_retention(&c).await;
    assert_eq!(c.state.scheduler.heavy.stats().failed, 0);
    assert_eq!(stored().await, vec![(false, false); 4]);
}
