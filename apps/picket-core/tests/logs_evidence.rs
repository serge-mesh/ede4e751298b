//! Alert evidence (core.md §9 "Evidence"; build-and-test.md §5 "Block alerts": evidence at its
//! caps): the rule and its backfill made with the alert, the backfill paging every matching
//! record and resuming after a stop, live capture never overlapping it, the shared budget charged
//! at every insert and recounted at start, full record copies, rules about answers, and deletes.
//!
//! The fixture's analysis is paused; these tests stand in for its two seams: they mark records
//! analysed (`log_progress`, kind `analysis`) and call live capture ([`evidence::capture_in`]) as
//! an analysis transaction would, and raise alerts with [`evidence::raise_security_with_rule_in`].

use crate::common;

use common::bundles::get;
use common::logs::{Setup, answer_record, answer_wire};
use jiff::Timestamp;
use picket_core::alerts::{Changes, RaiseSpec, Severity};
use picket_core::logs::evidence::{self, Capture, EvidenceRule};
use picket_core::logs::partition::{LogStore, hour_key, hour_start};
use picket_core::logs::record::{self, Rec};
use serde_json::{Value, json};

/// Every record of `at`'s partition, by rowid.
fn records(s: &Setup, at: Timestamp) -> Vec<Rec> {
    let store = LogStore::new(s.c.dir.path());
    let p = store.open(&hour_start(&at), false).unwrap().unwrap();
    record::load(&p, "ORDER BY e.rowid", &[]).unwrap()
}

/// Marks `at`'s partition analysed through `rowid`, as the analysis does after a batch.
async fn analysed(s: &Setup, at: Timestamp, rowid: i64) {
    let h = hour_key(&hour_start(&at));
    s.c.state
        .db
        .write(move |c| {
            c.execute(
                "INSERT INTO log_progress(hour, kind, value) VALUES (?1, 'analysis', ?2)
                 ON CONFLICT(hour, kind) DO UPDATE SET value = excluded.value",
                rusqlite::params![h, rowid],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
}

/// Raises a security alert with `rule` in one transaction; the alert's id when the rule was made.
async fn raise(s: &Setup, key: &str, rule: EvidenceRule) -> Option<i64> {
    let alerts = s.c.state.alerts.clone();
    let spec = RaiseSpec::new(
        "category_blocked",
        Severity::Warning,
        key.to_string(),
        "test alert",
        json!({}),
    );
    let (ch, id) =
        s.c.state
            .db
            .write(move |c| {
                let tx = c.transaction()?;
                let mut ch = Changes::default();
                let id = evidence::raise_security_with_rule_in(&alerts, &tx, &spec, &rule, &mut ch)?;
                tx.commit()?;
                alerts.committed(&ch);
                Ok::<_, anyhow::Error>((ch, id))
            })
            .await
            .unwrap();
    s.c.state.alerts.announce(ch);
    id
}

/// Live capture of `recs` in one transaction, as an analysis batch makes it.
async fn live(s: &Setup, cap: Option<std::sync::Arc<Capture>>, recs: Vec<Rec>) -> usize {
    let settings = s.c.state.settings();
    let per = settings.alerts.evidence_per_alert;
    let total = u64::from(settings.alerts.evidence_total_mib) * 1024 * 1024;
    let an = s.c.state.analysis.clone();
    let alerts = s.c.state.alerts.clone();
    s.c.state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let refs: Vec<&Rec> = recs.iter().collect();
            let cap: &Capture = cap.as_deref().unwrap_or(&an.capture);
            let mut touched = evidence::Touched::default();
            let (n, freed) = evidence::capture_in(cap, &tx, &refs, per, total, &mut touched)?;
            tx.commit()?;
            // Evictions give their bytes back once committed, and the alerts are noted for the UI.
            cap.release(freed);
            alerts.evidence_changed(c, &touched);
            Ok::<_, anyhow::Error>(n)
        })
        .await
        .unwrap()
}

async fn backfill(s: &Setup, id: i64) {
    let g = s.c.state.restore.generation();
    evidence::run_backfill(&s.c.state, g, id).await.unwrap();
}

async fn evidence_of(s: &Setup, id: i64) -> Value {
    let (st, ev) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
    assert_eq!(st, 200, "{ev}");
    ev
}

/// The copies' names in event-time order (the evidence view pages newest stored first; the
/// kept copies are the first and the latest by event time, core.md §9).
fn qnames(ev: &Value) -> Vec<String> {
    let mut v: Vec<(String, String)> = ev["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["ts"].as_str().unwrap_or_default().to_string(),
                r["qname"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    v.sort();
    v.into_iter().map(|(_, n)| n).collect()
}

/// The bytes stored, as a recount on the writer finds them.
async fn stored(s: &Setup) -> u64 {
    s.c.state
        .db
        .write(move |c| Ok::<_, anyhow::Error>(Capture::default().recount(c)?))
        .await
        .unwrap()
}

/// A `q` record from `device` at `at` for `qname`, allowed with no reason.
fn allowed(s: &Setup, seq: u64, at: Timestamp, qname: &str, device: &str) -> Value {
    let mut r = s.q("b-ev", seq, at, qname, "allow", Value::Null);
    r["device"] = json!(device);
    r
}

/// N8: the backfill reads every matching record in the window, not a page per hour: exact counts
/// past `evidence_per_alert`, the first and the latest copies, and a device filter applied before
/// any page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backfill_pages_every_matching_record() {
    let s = Setup::new(Some(json!({"alerts": {"evidence_per_alert": 10}}))).await;
    let t0 = Timestamp::now() - jiff::SignedDuration::from_mins(5);
    let mut lines = Vec::new();
    for i in 0..60u64 {
        // Alternate devices: only the tablet's 30 records are the alert's.
        let dev = if i % 2 == 0 { "tablet" } else { "phone" };
        lines.push(allowed(
            &s,
            i + 1,
            t0 + jiff::SignedDuration::from_millis(i as i64 * 10),
            &format!("h{i}.ads.example"),
            dev,
        ));
    }
    lines.push(allowed(&s, 100, t0, "other.example", "tablet"));
    s.post(lines).await;
    let recs = records(&s, t0);
    analysed(&s, t0, recs.last().unwrap().rowid).await;
    let id = raise(
        &s,
        "category_blocked:tablet:ads.example",
        EvidenceRule {
            domain: "ads.example".into(),
            device: Some("tablet".into()),
            ..Default::default()
        },
    )
    .await
    .expect("the rule is made with the alert");
    backfill(&s, id).await;
    let ev = evidence_of(&s, id).await;
    assert_eq!(ev["counts"]["client"]["tablet"], 30, "{ev}");
    assert!(ev["counts"]["client"].get("phone").is_none());
    assert_eq!(ev["counts"]["name"].as_object().unwrap().len(), 30);
    let names = qnames(&ev);
    assert_eq!(names.len(), 10, "{names:?}");
    assert_eq!(names[0], "h0.ads.example");
    assert_eq!(names[4], "h8.ads.example");
    assert_eq!(names[5], "h50.ads.example", "the latest half: {names:?}");
    assert_eq!(names[9], "h58.ads.example");
    let left: Option<String> = s
        .scalar_core(&format!(
            "SELECT backfill_json FROM alert_evidence_rules WHERE alert_id = {id}"
        ))
        .await;
    assert!(left.is_none(), "the backfill is done");
}

/// N3 and N9: the rule and its backfill are made in the raising transaction, so a stop before
/// any capture task ran still backfills; a backfill stopped part-way resumes where it stopped
/// and counts each record once; records analysed after the rule are live capture's alone, even
/// when the caps evicted their copies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupted_backfill_resumes_and_counts_once() {
    let s = Setup::new(Some(json!({"alerts": {"evidence_per_alert": 10}}))).await;
    // Two partitions in the window, 8 matching records each.
    let older = Timestamp::now() - jiff::SignedDuration::from_hours(2);
    let newer = Timestamp::now() - jiff::SignedDuration::from_mins(5);
    let mut lines = Vec::new();
    for i in 0..8u64 {
        lines.push(allowed(
            &s,
            i + 1,
            older + jiff::SignedDuration::from_secs(i as i64),
            &format!("o{i}.bad.example"),
            "tablet",
        ));
        lines.push(allowed(
            &s,
            i + 101,
            newer + jiff::SignedDuration::from_secs(i as i64),
            &format!("n{i}.bad.example"),
            "tablet",
        ));
    }
    s.post(lines).await;
    analysed(&s, older, records(&s, older).last().unwrap().rowid).await;
    analysed(&s, newer, records(&s, newer).last().unwrap().rowid).await;
    let id = raise(
        &s,
        "category_blocked:tablet:bad.example",
        EvidenceRule {
            domain: "bad.example".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // A stop now (no task started) leaves the rule with its whole backfill to do.
    let todo: String = s
        .scalar_core(&format!(
            "SELECT backfill_json FROM alert_evidence_rules WHERE alert_id = {id}"
        ))
        .await;
    assert!(todo.contains(&hour_key(&hour_start(&older))), "{todo}");
    // One step (the older partition), then a stop.
    let g = s.c.state.restore.generation();
    let step = evidence::backfill_step(&s.c.state, g, id).await.unwrap();
    assert_eq!(step, evidence::Step::More);
    let ev = evidence_of(&s, id).await;
    assert_eq!(ev["counts"]["client"]["tablet"], 8, "{ev}");
    // Records ingested and analysed after the rule: live capture's, past the copy cap.
    let mut lines = Vec::new();
    for i in 0..12u64 {
        lines.push(allowed(
            &s,
            i + 201,
            newer + jiff::SignedDuration::from_secs(30 + i as i64),
            &format!("l{i}.bad.example"),
            "tablet",
        ));
    }
    s.post(lines).await;
    let snap = records(&s, newer)
        .iter()
        .filter(|r| r.seq <= 108)
        .map(|r| r.rowid)
        .max()
        .unwrap();
    let later: Vec<Rec> = records(&s, newer)
        .into_iter()
        .filter(|r| r.rowid > snap)
        .collect();
    assert_eq!(later.len(), 12);
    live(&s, None, later).await;
    // The restart: the backfill resumes with the newer partition and finishes once.
    backfill(&s, id).await;
    backfill(&s, id).await;
    let ev = evidence_of(&s, id).await;
    assert_eq!(ev["counts"]["client"]["tablet"], 8 + 8 + 12, "{ev}");
    assert_eq!(ev["counts"]["name"].as_object().unwrap().len(), 28);
    assert!(
        ev["counts"]["name"]
            .as_object()
            .unwrap()
            .values()
            .all(|n| *n == 1),
        "{ev}"
    );
    assert_eq!(qnames(&ev).len(), 10);
}

/// N7: every insert is charged when it is made, and a start (a fresh budget) recounts what is
/// stored before admitting anything, so copies and count rows never pass the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_budget_holds_copies_and_count_rows_from_the_start() {
    let s = Setup::new(Some(
        json!({"alerts": {"evidence_per_alert": 100000, "evidence_total_mib": 1}}),
    ))
    .await;
    let total: u64 = 1024 * 1024;
    let id = raise(
        &s,
        "category_blocked:tablet:fill.example",
        EvidenceRule {
            domain: "fill.example".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Most of the budget is already stored (an earlier run of core).
    let filler = "x".repeat(total as usize - 3000);
    s.c.state
        .db
        .write(move |c| {
            c.execute(
                "INSERT INTO alert_evidence(alert_id, edge_id, boot, seq, ts, record_json) VALUES (?1, 'e', 'b', 999999, '2000-01-01T00:00:00.000000Z', ?2)",
                rusqlite::params![id, filler],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    // A start: a fresh budget that has counted nothing yet.
    let fresh = std::sync::Arc::new(Capture::default());
    let t0 = Timestamp::now() - jiff::SignedDuration::from_mins(5);
    let mut lines = Vec::new();
    for i in 0..400u64 {
        lines.push(allowed(
            &s,
            i + 1,
            t0 + jiff::SignedDuration::from_millis(i as i64),
            &format!("n{i}.fill.example"),
            &format!("dev{i}"),
        ));
    }
    s.post(lines).await;
    let recs = records(&s, t0);
    let copied = live(&s, Some(fresh.clone()), recs).await;
    let used = stored(&s).await;
    assert!(used <= total, "stored {used} of {total}");
    assert!((1..10).contains(&copied), "copies stop at the budget: {copied}");
    let ev = evidence_of(&s, id).await;
    // Counts went on: every record counted, new keys into "other" once the budget was full.
    let client: i64 = ev["counts"]["client"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v.as_i64().unwrap())
        .sum::<i64>()
        + ev["counts"]["client_other"]
            .as_object()
            .map_or(0, |o| o.values().map(|v| v.as_i64().unwrap()).sum());
    assert_eq!(client, 400, "{}", ev["counts"]);
    assert!(ev["incomplete"].as_bool().unwrap());
    assert_eq!(fresh.used(), used, "the budget follows every insert");
}

/// N10: a copy is the whole logged record: lookups (verdict, reason, detail), versions and EDNS
/// survive in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn copies_are_whole_records() {
    let s = Setup::new(None).await;
    let t0 = Timestamp::now() - jiff::SignedDuration::from_mins(5);
    let mut r = allowed(&s, 1, t0, "x.full.example", "tablet");
    r["lookups"] = json!([{"provider": "q9", "verdict": "clean", "cached": false,
        "obtained_at": common::logs::ts(t0), "gen": "b71e4d09a2c63f58", "ms": 12, "timed_out": false,
        "retry": false, "detail": {"server": "9.9.9.9", "rcode": "NOERROR"}}]);
    r["edns"] = json!({"udp": 1232, "pad": true});
    s.post(vec![r]).await;
    let id = raise(
        &s,
        "category_blocked:tablet:full.example",
        EvidenceRule {
            domain: "full.example".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(live(&s, None, records(&s, t0)).await, 1);
    let ev = evidence_of(&s, id).await;
    let item = &ev["items"][0];
    assert_eq!(item["lookups"][0]["provider"], "q9", "{item}");
    assert_eq!(item["lookups"][0]["verdict"], "clean");
    assert_eq!(item["lookups"][0]["detail"]["server"], "9.9.9.9");
    assert_eq!(item["versions"]["config"], json!(common::logs::short(&s.config)));
    assert_eq!(
        item["versions"]["bundles"]["b1"],
        json!(common::logs::short(&s.b1))
    );
    assert_eq!(item["edns"]["udp"], 1232);
    assert_eq!(item["qname"], "x.full.example");
}

/// N11: a rule about a name in answers captures the query whose answer holds it (a CNAME to
/// bad.example in front.example's answer), live and in the backfill, and an address rule the
/// query whose answer holds the address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answer_rules_capture_the_queries_in_front() {
    let s = Setup::new(None).await;
    let t0 = Timestamp::now() - jiff::SignedDuration::from_mins(5);
    let wire = answer_wire("front.example", &["cdn.bad.example"], &[[192, 0, 2, 77]]);
    let (aid, ans) = answer_record("b-ev", 1, t0, &wire);
    let mut q = allowed(&s, 2, t0, "front.example", "tablet");
    q["answer_id"] = json!(aid);
    q["received_at"] = json!(common::logs::ts(t0));
    q["age_s"] = json!(0);
    // A record before the rule (the backfill's) and one after (live capture's).
    let mut q2 = q.clone();
    q2["seq"] = json!(3);
    q2["ts"] = json!(common::logs::ts(t0 + jiff::SignedDuration::from_secs(1)));
    s.post(vec![ans, q, allowed(&s, 4, t0, "unrelated.example", "tablet")])
        .await;
    let first = records(&s, t0);
    analysed(&s, t0, first.last().unwrap().rowid).await;
    let by_name = raise(
        &s,
        "category_answered:feed:f-sec:bad.example",
        EvidenceRule {
            domain: "bad.example".into(),
            answers: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let by_ip = raise(
        &s,
        "category_answered:feed:f-sec:front.example",
        EvidenceRule {
            domain: "nothing-under.example".into(),
            ips: vec!["192.0.2.77".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    backfill(&s, by_name).await;
    backfill(&s, by_ip).await;
    s.post(vec![q2]).await;
    let later: Vec<Rec> = records(&s, t0).into_iter().filter(|r| r.seq == 3).collect();
    assert_eq!(live(&s, None, later).await, 2, "both rules take the later record");
    for id in [by_name, by_ip] {
        let ev = evidence_of(&s, id).await;
        assert_eq!(qnames(&ev), vec!["front.example", "front.example"], "{ev}");
        assert_eq!(ev["counts"]["name"]["front.example"], 2);
        assert_eq!(
            ev["answers"].as_array().unwrap().len(),
            1,
            "one answer copy per alert"
        );
    }
}

/// N6: deleting an alert while capture runs stops its capture at once (no copy or count lands
/// under its id), frees its budget, and a new alert for the same key gets a new id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_an_alert_stops_its_capture() {
    let s = Setup::new(None).await;
    evidence::start_backfills(&s.c.state);
    let t0 = Timestamp::now() - jiff::SignedDuration::from_mins(5);
    s.post(vec![allowed(&s, 1, t0, "ads.example", "tablet")]).await;
    let key = "category_blocked:tablet:ads.example";
    let rule = EvidenceRule {
        domain: "ads.example".into(),
        device: Some("tablet".into()),
        ..Default::default()
    };
    let id = raise(&s, key, rule.clone()).await.unwrap();
    assert_eq!(live(&s, None, records(&s, t0)).await, 1);
    let before = stored(&s).await;
    assert!(before > 0);
    assert_eq!(s.c.state.alerts.delete(vec![id]).await.unwrap(), 1);
    // The budget is given back before the next admission.
    let an = s.c.state.analysis.clone();
    let used =
        s.c.state
            .db
            .write(move |c| {
                an.capture.ensure_counted(c)?;
                Ok::<_, anyhow::Error>(an.capture.used())
            })
            .await
            .unwrap();
    assert_eq!(used, stored(&s).await);
    assert!(used < before, "{used} after, {before} before");
    // More of the same device and domain, captured live.
    s.post(vec![
        allowed(
            &s,
            2,
            t0 + jiff::SignedDuration::from_secs(1),
            "www.ads.example",
            "tablet",
        ),
        allowed(
            &s,
            3,
            t0 + jiff::SignedDuration::from_secs(2),
            "x.ads.example",
            "tablet",
        ),
    ])
    .await;
    let later: Vec<Rec> = records(&s, t0).into_iter().filter(|r| r.seq > 1).collect();
    assert_eq!(live(&s, None, later.clone()).await, 0, "no rule, no copy");
    for t in [
        "alert_evidence",
        "alert_evidence_counts",
        "alert_evidence_answers",
    ] {
        let n: i64 = s
            .scalar_core(&format!("SELECT count(*) FROM {t} WHERE alert_id = {id}"))
            .await;
        assert_eq!(n, 0, "{t} rows under the deleted id");
    }
    // Raised again: a new id, with its own evidence only.
    let id2 = raise(&s, key, rule).await.unwrap();
    assert!(id2 > id, "ids are never reused: {id2} after {id}");
    live(&s, None, later).await;
    let ev = evidence_of(&s, id2).await;
    assert_eq!(qnames(&ev), vec!["www.ads.example", "x.ads.example"]);
    let (st, _) = get(&s.c, &format!("/alerts/{id}/evidence")).await;
    assert_eq!(st, 404);
}

/// The next `alert` UI event listing alert `id` within 60 s (api.md §7: the coalesced event
/// lists each changed alert once), with its item.
async fn listed_in_event(
    rx: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>,
    id: i64,
) -> Option<Value> {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            match rx.recv().await {
                Ok(ev) if ev.kind == "alert" => {
                    if let Some(a) = ev.data["alerts"]
                        .as_array()
                        .and_then(|a| a.iter().find(|x| x["id"] == json!(id)))
                    {
                        return a.clone();
                    }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("events: {e}"),
            }
        }
    })
    .await
    .ok()
}

/// K2 (core.md §9 Evidence; api.md §7): evidence the backfill or live capture copies or counts
/// lists its alert in the coalesced `alert` event (with its state now), so an open alert's view
/// re-reads its evidence then, not only at the alert's next raise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evidence_changes_list_the_alert_in_an_alert_event() {
    let s = Setup::new(None).await;
    let t0 = Timestamp::now() - jiff::SignedDuration::from_mins(5);
    s.post(vec![allowed(&s, 1, t0, "a.k2.example", "tablet")]).await;
    let recs = records(&s, t0);
    analysed(&s, t0, recs.last().unwrap().rowid).await;
    let mut rx = s.c.state.events.subscribe();
    let id = raise(
        &s,
        "category_blocked:tablet:k2.example",
        EvidenceRule {
            domain: "k2.example".into(),
            ..Default::default()
        },
    )
    .await
    .expect("the rule is made with the alert");
    let raised = listed_in_event(&mut rx, id).await.expect("the raise's event");
    assert_eq!(raised["count"], 1, "{raised}");
    // The backfill copies the record logged before the raise.
    backfill(&s, id).await;
    assert_eq!(evidence_of(&s, id).await["total"], 1);
    let a = listed_in_event(&mut rx, id)
        .await
        .expect("the backfill's copy lists the alert");
    assert_eq!(
        (a["state"].clone(), a["count"].clone(), a["deleted"].clone()),
        (json!("open"), json!(1), json!(false)),
        "{a}"
    );
    // The analysis's live capture copies a record ingested after the raise.
    let t1 = Timestamp::now() - jiff::SignedDuration::from_mins(1);
    s.post(vec![allowed(&s, 2, t1, "b.k2.example", "phone")]).await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    assert_eq!(evidence_of(&s, id).await["total"], 2);
    let a = listed_in_event(&mut rx, id)
        .await
        .expect("live capture's copy lists the alert");
    assert_eq!(
        (a["state"].clone(), a["count"].clone()),
        (json!("open"), json!(1)),
        "{a}"
    );
}
