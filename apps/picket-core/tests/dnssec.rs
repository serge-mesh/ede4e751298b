//! DNSSEC validation and the upstream cross-check (core.md §8, §9, §10, §12; build-and-test.md §5
//! rows "DNSSEC" and "Upstream cross-check").
//!
//! Records go in through `POST /v1/logs` from a registered edge; the background analysis and
//! validation loops are paused, so each test runs them itself. Chains come from signed test zones
//! generated in the test (`common::zones`), trusted through the test root's key; the end-to-end
//! test fetches them over DoH from a local server whose certificate core's LAN CA signed.

use crate::common;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::bundles::{put_entity, ui};
use common::edge::FakeEdge;
use common::zones::{Key, World, Zone, ZoneResolver, name, now};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{RData, Record, RecordType};
use jiff::Timestamp;
use picket_lookup::{DnsClientError, DnsServer, DnsServerClient};
use reqwest::Method;
use serde_json::{Value, json};

fn ts(t: Timestamp) -> String {
    picket_api::time::format_micros(&t)
}

const BOOT: &str = "b0";
const UPSTREAM: &str =
    r#"{"group": "cloudflare", "upstream": "cf-dot-1", "ms": 3, "cached": false, "stale": false}"#;

struct Setup {
    c: common::Core,
    edge: FakeEdge,
    world: Arc<World>,
    seq: Mutex<u64>,
}

impl Setup {
    async fn new(settings: Option<Value>) -> Setup {
        let mut patch = json!({"web": {"tls": "off"}});
        if let (Some(p), Some(extra)) = (
            patch.as_object_mut(),
            settings.as_ref().and_then(Value::as_object),
        ) {
            p.extend(extra.clone());
        }
        let c = common::start_core(Some(patch)).await;
        c.state.analysis.set_paused(true);
        c.state.dnssec.set_paused(true);
        // Validation waits for a synchronised clock (README §2 Clocks).
        c.state.clock.pin(true);
        let world = World::standard();
        c.state.dnssec.set_trust_anchors(world.anchors());
        c.state.dnssec.set_resolver(Arc::new(ZoneResolver(world.clone())));
        let edge = FakeEdge::registered(&c, "e1").await;
        Setup {
            c,
            edge,
            world,
            seq: Mutex::new(1),
        }
    }

    fn next(&self) -> u64 {
        let mut g = self.seq.lock().unwrap();
        *g += 1;
        *g
    }

    /// An `answer` record and its id.
    fn answer(&self, wire: &[u8]) -> (Value, String) {
        common::edge::answer(BOOT, self.next(), &ts(Timestamp::now()), wire)
    }

    /// A `q` record.
    #[expect(
        clippy::too_many_arguments,
        reason = "a test record builder: one parameter per field the tests vary"
    )]
    fn q(
        &self,
        qname: &str,
        qtype: &str,
        rcode: &str,
        decision: &str,
        answer: Option<(&str, Timestamp)>,
        answers: &[&str],
        extra: Value,
    ) -> Value {
        let mut v = json!({"t": "q", "ts": ts(Timestamp::now() - jiff::SignedDuration::from_secs(1)), "boot": BOOT, "seq": self.next(),
            "listener": "lan-dns", "proto": "udp", "client": "192.168.1.140", "device": "tablet", "profile": "default",
            "qname": qname, "qtype": qtype, "do": false, "rcode": rcode, "decision": decision,
            "answers": answers, "targets": [], "truncated": false, "cname": [], "lookups": [],
            "upstream": serde_json::from_str::<Value>(UPSTREAM).unwrap(), "fw": null, "us": {"total": 41, "filter": 6},
            "versions": {"config": "0000000000000000", "bundles": {}}});
        if let Some((id, at)) = answer {
            v["answer_id"] = json!(id);
            v["received_at"] = json!(ts(at));
            v["age_s"] = json!(0);
        }
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        v
    }

    /// A logged answer from the world and the `q` record that used it, received at `at`.
    fn logged(&self, qname: &str, qtype: &str, wire: Vec<u8>, at: Timestamp) -> Vec<Value> {
        let m = Message::from_vec(&wire).unwrap();
        let rcode = picket_wire::types::rcode_mnemonic(u16::from(m.metadata.response_code))
            .unwrap()
            .to_string();
        let addrs: Vec<String> = m
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0.to_string()),
                _ => None,
            })
            .collect();
        let addrs: Vec<&str> = addrs.iter().map(String::as_str).collect();
        let (a, id) = self.answer(&wire);
        vec![
            a,
            self.q(qname, qtype, &rcode, "allow", Some((&id, at)), &addrs, json!({})),
        ]
    }

    async fn post(&self, lines: Vec<Value>) {
        let r = self.edge.post_logs(&lines).await;
        let st = r.status();
        assert_eq!(st, 200, "{}", r.text().await.unwrap());
    }

    async fn run(&self) {
        picket_core::logs::analysis::drain(&self.c.state).await.unwrap();
        picket_core::dnssec::drain(&self.c.state).await.unwrap();
    }

    async fn sql<T: rusqlite::types::FromSql + Send + 'static>(&self, sql: &str) -> T {
        let sql = sql.to_string();
        self.c
            .state
            .db
            .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&sql, [], |r| r.get::<_, T>(0))?))
            .await
            .unwrap()
    }

    /// The results for a name: (outcome, detail).
    async fn results(&self, qname: &str) -> Vec<(String, Value)> {
        let q = qname.to_string();
        self.c
            .state
            .db
            .read(move |db| {
                let mut st =
                    db.prepare("SELECT outcome, detail FROM dnssec_results WHERE qname = ?1 ORDER BY id")?;
                let rows = st.query_map([q], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        serde_json::from_str::<Value>(&r.get::<_, String>(1)?).unwrap_or(Value::Null),
                    ))
                })?;
                Ok::<_, anyhow::Error>(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .await
            .unwrap()
    }

    async fn outcome(&self, qname: &str) -> String {
        let r = self.results(qname).await;
        assert_eq!(r.len(), 1, "{qname}: {r:?}");
        r[0].0.clone()
    }

    /// The sum of a core series' increments whose labels hold every pair.
    async fn metric(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        let n = name.to_string();
        let want: Vec<(String, String)> = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.c
            .state
            .metrics_db
            .read(move |db| {
                let mut st = db.prepare(
                    "SELECT s.labels_json, coalesce(sum(p.value), 0) FROM series s JOIN points p ON p.series_id = s.id
                     WHERE s.name = ?1 GROUP BY s.id",
                )?;
                let rows = st.query_map([n], |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?)))?;
                let mut total = 0.0;
                for r in rows {
                    let (lj, v) = r?;
                    let l: BTreeMap<String, String> = serde_json::from_str(&lj).unwrap_or_default();
                    if want.iter().all(|(k, v)| l.get(k) == Some(v)) {
                        total += v;
                    }
                }
                Ok::<_, anyhow::Error>(total)
            })
            .await
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logged_answers_are_validated_as_the_edge_got_them() {
    let s = Setup::new(None).await;
    let w = s.world.clone();
    let at = Timestamp::now() - jiff::SignedDuration::from_mins(5);
    let mut lines = Vec::new();
    lines.extend(s.logged("www.test", "A", w.answer(&name("www.test."), RecordType::A), at));
    lines.extend(s.logged(
        "www.unsigned.test",
        "A",
        w.answer(&name("www.unsigned.test."), RecordType::A),
        at,
    ));
    lines.extend(s.logged(
        "mail.test",
        "A",
        w.stripped(&name("mail.test."), RecordType::A),
        at,
    ));
    lines.extend(s.logged(
        "www.expired.test",
        "A",
        w.answer(&name("www.expired.test."), RecordType::A),
        at,
    ));
    lines.extend(s.logged(
        "www.nokey.test",
        "A",
        w.answer(&name("www.nokey.test."), RecordType::A),
        at,
    ));
    // Denial: a signed NXDOMAIN and NODATA validate after scrubbing; a bogus NODATA doesn't.
    lines.extend(s.logged("nope.test", "A", w.answer(&name("nope.test."), RecordType::A), at));
    lines.extend(s.logged(
        "www.test",
        "AAAA",
        w.answer(&name("www.test."), RecordType::AAAA),
        at,
    ));
    lines.extend(s.logged(
        "www.test",
        "MX",
        w.bogus_nodata(&name("www.test."), RecordType::MX),
        at,
    ));
    let mut events = s.c.state.events.subscribe();
    s.post(lines).await;
    s.run().await;
    // C9 (api.md §7): stored results reach the UI as coalesced `dnssec` events, by outcome.
    let mut outcomes: std::collections::BTreeMap<String, u64> = Default::default();
    tokio::time::timeout(Duration::from_secs(60), async {
        while outcomes.values().sum::<u64>() < 8 {
            match events.recv().await {
                Ok(ev) if ev.kind == "dnssec" => {
                    for (k, v) in ev.data["outcomes"].as_object().unwrap() {
                        *outcomes.entry(k.clone()).or_insert(0) += v.as_u64().unwrap();
                    }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("{e}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("dnssec events: {outcomes:?}"));
    assert_eq!(outcomes.get("secure"), Some(&3), "{outcomes:?}");
    assert_eq!(outcomes.get("bogus"), Some(&4), "{outcomes:?}");

    let www = s.results("www.test").await;
    assert_eq!(www.len(), 3, "A, AAAA and MX: {www:?}");
    assert_eq!(www[0].0, "secure", "a logged signed answer: {www:?}");
    assert_eq!(s.outcome("www.unsigned.test").await, "insecure");
    assert_eq!(
        w.asked("www.unsigned.test.", "A"),
        0,
        "an unsigned-zone answer is validated itself, with no fallback query"
    );
    assert_eq!(s.metric("dnssec_fallback", &[]).await, 0.0);
    let stripped = s.results("mail.test").await;
    assert_eq!(
        stripped[0].0, "bogus",
        "a signed zone's answer without signatures: {stripped:?}"
    );
    assert_eq!(stripped[0].1["ede"], json!(10), "{stripped:?}");
    let expired = s.results("www.expired.test").await;
    assert_eq!(expired[0].0, "bogus");
    assert_eq!(expired[0].1["ede"], json!(7), "Signature Expired: {expired:?}");
    assert_eq!(expired[0].1["zone"], json!("expired.test"), "{expired:?}");
    let nokey = s.results("www.nokey.test").await;
    assert_eq!(nokey[0].0, "bogus");
    assert_eq!(nokey[0].1["ede"], json!(9), "DNSKEY Missing: {nokey:?}");
    let nx = s.results("nope.test").await;
    assert_eq!(nx[0].0, "secure", "a signed NXDOMAIN: {nx:?}");
    assert_eq!(www[1].0, "secure", "a signed NODATA: {www:?}");
    assert_eq!(www[2].0, "bogus", "a bogus denial: {www:?}");

    // dnssec_bogus: one per broken zone, with the code, hickory's proof error, the validator
    // group, the names, edges and clients, and the validator's DNSKEY and DS answers.
    let (st, alerts) = common::bundles::get(&s.c, "/alerts?kind=dnssec_bogus").await;
    assert_eq!(st, 200);
    let items = alerts["items"].as_array().unwrap();
    let a = items
        .iter()
        .find(|a| a["dedupe_key"] == json!("dnssec_bogus:expired.test"))
        .unwrap_or_else(|| panic!("{alerts}"));
    assert_eq!(a["type"], json!("security"));
    assert_eq!(a["details"]["ede"], json!(7));
    assert_eq!(a["details"]["validator_group"], json!("cloudflare"));
    assert!(
        a["details"]["proof"].as_str().is_some_and(|p| !p.is_empty()),
        "{a}"
    );
    let names = a["details"]["names"].as_array().unwrap();
    assert_eq!(names[0]["name"], json!("www.expired.test"));
    assert_eq!(names[0]["edges"], json!([s.edge.id]));
    assert_eq!(names[0]["clients"], json!(["tablet"]));
    assert_eq!(names[0]["groups"], json!(["cloudflare"]));
    let id = a["id"].as_i64().unwrap();
    let validator: i64 = s
        .sql(&format!(
            "SELECT count(*) FROM alert_evidence_answers WHERE alert_id = {id} AND source = 'validator'"
        ))
        .await;
    assert!(
        validator >= 1,
        "the validator's DNSKEY and DS answers are evidence"
    );
    // Evidence copies of the records under the zone.
    assert!(
        common::edge::eventually(|| async {
            s.sql::<i64>(&format!(
                "SELECT count(*) FROM alert_evidence WHERE alert_id = {id}"
            ))
            .await
                >= 1
        })
        .await
    );
    // Metrics: results by outcome and coverage, one per answer.
    assert_eq!(s.metric("dnssec_results", &[("outcome", "secure")]).await, 3.0);
    assert_eq!(s.metric("dnssec_results", &[("outcome", "bogus")]).await, 4.0);
    assert_eq!(s.metric("dnssec_answers", &[]).await, 8.0);
    assert_eq!(s.metric("dnssec_coverage", &[("class", "secure")]).await, 3.0);
    assert_eq!(s.metric("dnssec_coverage", &[("class", "bogus")]).await, 4.0);
    assert_eq!(s.metric("dnssec_coverage", &[("class", "insecure")]).await, 1.0);
    // The UI's routes.
    let (st, r) = common::bundles::get(&s.c, "/dnssec/results?outcome=bogus").await;
    assert_eq!(st, 200);
    assert_eq!(r["items"].as_array().unwrap().len(), 4, "{r}");
    assert!(
        r["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["zone"] == json!("expired.test")
                && i["ede"] == json!(7)
                && i["group"] == json!("cloudflare"))
    );
    let (st, q) = common::bundles::get(&s.c, "/dnssec/queue").await;
    assert_eq!(st, 200);
    assert_eq!(q["depth"], json!(0), "{q}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validation_is_as_of_the_receive_time() {
    let s = Setup::new(None).await;
    let w = s.world.clone();
    // past.test's signatures expired an hour ago: valid when received two hours ago.
    let wire = w.answer(&name("www.past.test."), RecordType::A);
    let (a, id) = s.answer(&wire);
    let early = Timestamp::now() - jiff::SignedDuration::from_hours(2);
    let late = Timestamp::now() - jiff::SignedDuration::from_mins(10);
    let earlier = Timestamp::now() - jiff::SignedDuration::from_mins(170);
    s.post(vec![
        a,
        s.q(
            "www.past.test",
            "A",
            "NOERROR",
            "allow",
            Some((&id, early)),
            &["192.0.2.6"],
            json!({}),
        ),
        s.q(
            "www.past.test",
            "A",
            "NOERROR",
            "allow",
            Some((&id, late)),
            &["192.0.2.6"],
            json!({}),
        ),
    ])
    .await;
    s.run().await;
    let r = s.results("www.past.test").await;
    assert_eq!(r.len(), 2, "one verdict per (id, received_at): {r:?}");
    let outcomes: Vec<&str> = r.iter().map(|x| x.0.as_str()).collect();
    assert!(
        outcomes.contains(&"secure") && outcomes.contains(&"bogus"),
        "{r:?}"
    );
    // Another receive time in the same validity cell reuses the crypto work.
    let asked = w.total_asked();
    s.post(vec![s.q(
        "www.past.test",
        "A",
        "NOERROR",
        "allow",
        Some((&id, earlier)),
        &["192.0.2.6"],
        json!({}),
    )])
    .await;
    s.run().await;
    let r = s.results("www.past.test").await;
    assert_eq!(r.len(), 3);
    assert_eq!(r[2].0, "secure");
    assert_eq!(r[2].1["reused"], json!(true), "{r:?}");
    assert_eq!(w.total_asked(), asked, "no request for a reused verdict");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_core_does_not_hold_take_the_fallback_query() {
    let s = Setup::new(None).await;
    let w = s.world.clone();
    // Over 4 KiB: no answer_id, truncated. Then a record whose answer the batch lacks
    // (answer_missing), for the same name: one fallback query per dedupe window.
    s.post(vec![
        s.q(
            "www.test",
            "A",
            "NOERROR",
            "allow",
            None,
            &["192.0.2.1"],
            json!({"truncated": true}),
        ),
        s.q(
            "www.test",
            "A",
            "NOERROR",
            "allow",
            Some(("0123456789abcdef", Timestamp::now())),
            &["192.0.2.1"],
            json!({}),
        ),
    ])
    .await;
    s.run().await;
    let r = s.results("www.test").await;
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].0, "secure");
    assert_eq!(r[0].1["kind"], json!("fallback"));
    assert_eq!(w.asked("www.test.", "A"), 1, "one fallback query");
    assert_eq!(s.metric("dnssec_fallback", &[]).await, 1.0);
    // A logged answer the client got that differs from a Secure fallback answer counts as
    // fallback, not Secure, with the fallback's outcome alongside.
    assert_eq!(
        s.metric("dnssec_coverage", &[("class", "fallback"), ("outcome", "secure")])
            .await,
        2.0
    );
    assert_eq!(s.metric("dnssec_coverage", &[("class", "secure")]).await, 0.0);
    // A later record for the same name inside the window takes that query's result.
    s.post(vec![s.q(
        "www.test",
        "A",
        "NOERROR",
        "allow",
        None,
        &["192.0.2.1"],
        json!({"truncated": true}),
    )])
    .await;
    s.run().await;
    assert_eq!(w.asked("www.test.", "A"), 1);
    assert_eq!(
        s.metric("dnssec_coverage", &[("class", "fallback"), ("outcome", "secure")])
            .await,
        3.0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upstream_servfail_is_a_candidate_never_retried() {
    let s = Setup::new(None).await;
    s.world
        .servfail
        .lock()
        .unwrap()
        .insert("www.expired.test.".into());
    s.post(vec![s.q(
        "www.expired.test",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    )])
    .await;
    s.run().await;
    let r = s.results("www.expired.test").await;
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].0, "indeterminate");
    assert_eq!(r[0].1["kind"], json!("servfail"));
    assert_eq!(s.world.asked("www.expired.test.", "A"), 1, "not retried");
    assert_eq!(picket_core::dnssec::queue_depth(&s.c.state).await.unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn items_wait_while_no_edge_is_reachable() {
    let s = Setup::new(Some(
        json!({"alerts": {"thresholds": {"dnssec_unavailable": "1s"}}}),
    ))
    .await;
    s.world
        .unreachable
        .store(true, std::sync::atomic::Ordering::Relaxed);
    s.post(s.logged(
        "www.test",
        "A",
        s.world.answer(&name("www.test."), RecordType::A),
        Timestamp::now(),
    ))
    .await;
    s.run().await;
    assert_eq!(
        picket_core::dnssec::queue_depth(&s.c.state).await.unwrap(),
        1,
        "nothing is dropped"
    );
    assert_eq!(
        s.sql::<i64>("SELECT attempts FROM dnssec_queue").await,
        0,
        "waiting uses no attempt"
    );
    assert!(s.results("www.test").await.is_empty());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    picket_core::dnssec::unavailable_check(&s.c.state).await.unwrap();
    let open = || async {
        s.sql::<i64>("SELECT count(*) FROM alerts WHERE kind = 'dnssec_unavailable' AND state = 'open'")
            .await
    };
    assert_eq!(open().await, 1, "candidates wait and none is validated");
    // An edge comes back: the backlog drains.
    s.world
        .unreachable
        .store(false, std::sync::atomic::Ordering::Relaxed);
    s.c.state
        .db
        .write(|c| {
            Ok::<_, anyhow::Error>(c.execute(
                "UPDATE dnssec_queue SET next_at = '2000-01-01T00:00:00.000000Z'",
                [],
            )?)
        })
        .await
        .unwrap();
    picket_core::dnssec::drain(&s.c.state).await.unwrap();
    assert_eq!(s.outcome("www.test").await, "secure");
    picket_core::dnssec::unavailable_check(&s.c.state).await.unwrap();
    assert_eq!(open().await, 0, "resolved once the queue drains");
}

/// A plain upstream group `local` and the forward zone `home.arpa` for the default profile.
async fn forward_zone(s: &Setup) {
    put_entity(&s.c, "upstreams", "dnsmasq", json!({"id": "dnsmasq", "name": "dnsmasq", "protocol": "udp", "ip": "10.0.0.53", "port": 53, "operator": "lan"})).await;
    put_entity(
        &s.c,
        "upstream-groups",
        "local",
        json!({"id": "local", "name": "local", "upstreams": ["dnsmasq"]}),
    )
    .await;
    put_entity(
        &s.c,
        "forward-zones",
        "lan",
        json!({"id": "lan", "zone": "home.arpa", "group": "local"}),
    )
    .await;
    let (st, mut p) = common::bundles::get(&s.c, "/profiles/default").await;
    assert_eq!(st, 200, "{p}");
    p["forward_zones"] = json!(["lan"]);
    put_entity(&s.c, "profiles", "default", p).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coverage_adds_up_with_unchecked_dropped_and_queued_answers() {
    let s = Setup::new(None).await;
    // A plain upstream and a forward zone for the default profile.
    forward_zone(&s).await;
    s.c.state.dnssec.set_queue_cap(2);
    let w = s.world.clone();
    let mut lines = vec![
        // edge: the edge made the answer.
        s.q(
            "cached.example",
            "A",
            "NOERROR",
            "allow",
            None,
            &["192.0.2.9"],
            json!({"upstream": null}),
        ),
        // forward zone.
        s.q(
            "nas.home.arpa",
            "A",
            "NOERROR",
            "allow",
            None,
            &["10.0.0.9"],
            json!({"upstream": {"group": "local", "upstream": "dnsmasq"}}),
        ),
        // plain upstream.
        s.q(
            "other.example",
            "A",
            "NOERROR",
            "allow",
            None,
            &["10.0.0.8"],
            json!({"upstream": {"group": "local", "upstream": "dnsmasq"}}),
        ),
        // blocked: not an answer a client got.
        s.q(
            "ads.example",
            "A",
            "NOERROR",
            "block",
            None,
            &["0.0.0.0"],
            json!({}),
        ),
    ];
    lines.extend(s.logged(
        "www.test",
        "A",
        w.answer(&name("www.test."), RecordType::A),
        Timestamp::now(),
    ));
    lines.extend(s.logged(
        "mail.test",
        "A",
        w.answer(&name("mail.test."), RecordType::A),
        Timestamp::now(),
    ));
    // Over the cap of 2: dropped.
    lines.extend(s.logged(
        "www.unsigned.test",
        "A",
        w.answer(&name("www.unsigned.test."), RecordType::A),
        Timestamp::now(),
    ));
    s.post(lines).await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    assert_eq!(s.metric("dnssec_answers", &[]).await, 6.0);
    assert_eq!(s.metric("dnssec_coverage", &[("class", "edge")]).await, 1.0);
    assert_eq!(
        s.metric("dnssec_coverage", &[("class", "forward_zone")]).await,
        1.0
    );
    assert_eq!(
        s.metric("dnssec_coverage", &[("class", "plain_upstream")]).await,
        1.0
    );
    assert_eq!(s.metric("dnssec_coverage", &[("class", "dropped")]).await, 1.0);
    assert_eq!(s.metric("dnssec_dropped", &[("reason", "full")]).await, 1.0);
    // Still queued: dnssec_answers less the coverage total.
    let classified = s.metric("dnssec_coverage", &[]).await;
    let queued = picket_core::dnssec::queue_depth(&s.c.state).await.unwrap() as f64;
    assert_eq!(classified + queued, 6.0, "every answer is classified or queued");
    // Validation off: `off`.
    let r = ui(&s.c, Method::PUT, "/settings")
        .json(&json!({"dnssec": {"enabled": false}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    s.post(s.logged(
        "x.test",
        "A",
        w.answer(&name("x.test."), RecordType::A),
        Timestamp::now(),
    ))
    .await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    assert_eq!(s.metric("dnssec_coverage", &[("class", "off")]).await, 1.0);
    // Back on: the queued checks end, and the shares add up to every answer logged.
    let r = ui(&s.c, Method::PUT, "/settings")
        .json(&json!({"dnssec": {"enabled": true}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    picket_core::dnssec::drain(&s.c.state).await.unwrap();
    assert_eq!(s.metric("dnssec_coverage", &[]).await, 7.0);
    assert_eq!(s.metric("dnssec_answers", &[]).await, 7.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_doh_path_reaches_an_edge_listener_under_the_validator_profile() {
    let s = Setup::new(None).await;
    // The production resolver: DoH to the edge's listener, trusting the LAN CA.
    s.c.state
        .dnssec
        .set_resolver(Arc::new(picket_core::dnssec::resolver::EdgeDoh::new(
            Arc::downgrade(&s.c.state),
            &Default::default(),
        )));
    let (addr, paths) =
        common::zones::doh_server(s.world.clone(), &s.c.state.lanca.load(), "dns.home.arpa").await;
    put_entity(
        &s.c,
        "listeners",
        "lan-doh",
        json!({"id": "lan-doh", "name": "lan-doh", "proto": "doh", "bind": format!("127.0.0.1:{}", addr.port()),
               "tls": {"managed": "dns.home.arpa"}, "edges": [s.edge.id]}),
    )
    .await;
    // No session yet: no listener on a connected edge, so the item waits.
    s.post(s.logged(
        "www.test",
        "A",
        s.world.answer(&name("www.test."), RecordType::A),
        Timestamp::now(),
    ))
    .await;
    s.run().await;
    assert_eq!(picket_core::dnssec::queue_depth(&s.c.state).await.unwrap(), 1);
    // The edge connects: the chain comes over DoH at /dns-query/dnssec-validator, DO=1, CD=1.
    let (_ws, _) = s.edge.session(common::edge::hello(BOOT)).await;
    tokio::time::sleep(picket_core::dnssec::resolver::DOWN_FOR + Duration::from_millis(200)).await;
    s.c.state
        .db
        .write(|c| {
            Ok::<_, anyhow::Error>(c.execute(
                "UPDATE dnssec_queue SET next_at = '2000-01-01T00:00:00.000000Z'",
                [],
            )?)
        })
        .await
        .unwrap();
    picket_core::dnssec::drain(&s.c.state).await.unwrap();
    assert_eq!(s.outcome("www.test").await, "secure");
    let p = paths.lock().unwrap().clone();
    assert!(!p.is_empty());
    assert!(
        p.iter()
            .all(|x| x == "/dns-query/dnssec-validator cd=true do=true"),
        "{p:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The cross-check

/// One canned answer: (rcode, A addresses, CNAME target, EDE).
type Canned = (u16, Vec<Ipv4Addr>, Option<String>, Option<u16>);

/// A cross-check resolver answering from a table of canned answers by name.
#[derive(Default)]
struct FakeResolver {
    answers: Mutex<BTreeMap<String, Canned>>,
    asked: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl DnsServerClient for FakeResolver {
    async fn query(&self, _s: &DnsServer, query: &[u8], _t: Duration) -> Result<Vec<u8>, DnsClientError> {
        let q = Message::from_vec(query).map_err(|e| DnsClientError::Transport(e.to_string()))?;
        let question = q.queries[0].clone();
        let n = question.name().to_string().trim_end_matches('.').to_string();
        self.asked.lock().unwrap().push(n.clone());
        let (rcode, addrs, cname, ede) =
            self.answers
                .lock()
                .unwrap()
                .get(&n)
                .cloned()
                .unwrap_or((3, vec![], None, None));
        let mut m = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.metadata.recursion_available = true;
        m.metadata.response_code = hickory_proto::op::ResponseCode::from(0, u8::try_from(rcode).unwrap());
        m.add_query(Query::query(question.name().clone(), question.query_type()));
        let mut owner = question.name().clone();
        if let Some(t) = cname {
            let target = name(&t);
            m.answers.push(Record::from_rdata(
                owner.clone(),
                60,
                RData::CNAME(CNAME(target.clone())),
            ));
            owner = target;
        }
        for a in addrs {
            m.answers
                .push(Record::from_rdata(owner.clone(), 60, RData::A(A(a))));
        }
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        if let Some(code) = ede {
            edns.options_mut()
                .insert(EdnsOption::Unknown(15, code.to_be_bytes().to_vec()));
        }
        m.edns = Some(edns);
        Ok(m.to_vec().unwrap())
    }
}

const RESOLVER: &str = r#"{"protocol": "dot", "ip": "9.9.9.10", "port": 853, "tls_host": "dns10.quad9.net", "operator": "quad9"}"#;

async fn crosscheck_setup(on: bool) -> (Setup, Arc<FakeResolver>) {
    let settings = if on {
        json!({"crosscheck": {"enabled": true, "resolver": serde_json::from_str::<Value>(RESOLVER).unwrap()}})
    } else {
        json!({})
    };
    let s = Setup::new(Some(settings)).await;
    let f = Arc::new(FakeResolver::default());
    s.c.state.dnssec.crosscheck.set_client(f.clone());
    (s, f)
}

async fn run_all(s: &Setup) {
    s.run().await;
    picket_core::dnssec::crosscheck::drain(&s.c.state).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_false_nxdomain_for_an_unsigned_name_raises_upstream_disagrees() {
    let (s, f) = crosscheck_setup(true).await;
    f.answers.lock().unwrap().insert(
        "blocked.unsigned.test".into(),
        (0, vec![Ipv4Addr::new(192, 0, 2, 77)], None, None),
    );
    let mut events = s.c.state.events.subscribe();
    // The upstream said NXDOMAIN for a name in an unsigned zone (Insecure from the DS chain).
    let wire = s.world.answer(&name("blocked.unsigned.test."), RecordType::A);
    s.post(s.logged("blocked.unsigned.test", "A", wire, Timestamp::now()))
        .await;
    run_all(&s).await;
    assert_eq!(s.outcome("blocked.unsigned.test").await, "insecure");
    // F9 (api.md §7): queueing sends `dnssec_queued` events (coalesced), not only storing
    // results: the answer queued for validation, then the negative cross-check it led to.
    let (mut validation, mut crosscheck) = (0, 0);
    tokio::time::timeout(Duration::from_secs(60), async {
        while validation < 1 || crosscheck < 1 {
            match events.recv().await {
                Ok(e) if e.kind == "dnssec_queued" => {
                    validation += e.data["validation"].as_u64().unwrap();
                    crosscheck += e.data["crosscheck"].as_u64().unwrap();
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("events closed: {e}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("dnssec_queued: validation {validation}, crosscheck {crosscheck}"));
    assert_eq!((validation, crosscheck), (1, 1));
    assert_eq!(f.asked.lock().unwrap().as_slice(), ["blocked.unsigned.test"]);
    let key = "upstream_disagrees:unsigned.test:cloudflare";
    let details: String = s
        .sql(&format!(
            "SELECT details_json FROM alerts WHERE dedupe_key = '{key}'"
        ))
        .await;
    let d: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(d["check"], json!("negative"));
    assert_eq!(d["upstream"]["rcode"], json!("NXDOMAIN"));
    assert_eq!(d["resolver"]["addresses"], json!(["192.0.2.77"]));
    assert_eq!(d["edges"], json!([s.edge.id]));
    let id: i64 = s
        .sql(&format!("SELECT id FROM alerts WHERE dedupe_key = '{key}'"))
        .await;
    assert_eq!(
        s.sql::<i64>(&format!(
            "SELECT count(*) FROM alert_evidence_answers WHERE alert_id = {id} AND source = 'crosscheck'"
        ))
        .await,
        1,
        "the resolver's answer is evidence"
    );
    assert_eq!(
        s.metric("crosscheck", &[("check", "negative"), ("result", "disagree")])
            .await,
        1.0
    );
    // Checked once per dedupe window.
    s.post(s.logged(
        "blocked.unsigned.test",
        "A",
        s.world.answer(&name("blocked.unsigned.test."), RecordType::A),
        Timestamp::now(),
    ))
    .await;
    run_all(&s).await;
    assert_eq!(f.asked.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sinkhole_answers_are_checked_and_filtering_answers_never_disagree() {
    let (s, f) = crosscheck_setup(true).await;
    forward_zone(&s).await;
    // The lookup-exclude bundle's feed is ingested at start.
    assert!(
        common::edge::eventually(|| async {
            s.sql::<i64>(
                "SELECT count(*) FROM feed_runs WHERE feed_id = 'lookup-exclude' AND status = 'applied'",
            )
            .await
                > 0
        })
        .await
    );
    {
        let mut a = f.answers.lock().unwrap();
        a.insert(
            "ads.example.com".into(),
            (0, vec![Ipv4Addr::new(93, 184, 216, 34)], None, None),
        );
        a.insert(
            "sink.example.org".into(),
            (0, vec![Ipv4Addr::new(0, 0, 0, 0)], None, None),
        );
        a.insert("filtered.example.net".into(), (3, vec![], None, Some(15)));
        a.insert(
            "alias.unsigned.test".into(),
            (0, vec![], Some("target.unsigned.test".into()), None),
        );
    }
    let up = json!({"upstream": serde_json::from_str::<Value>(UPSTREAM).unwrap()});
    s.post(vec![
        s.q(
            "ads.example.com",
            "A",
            "NOERROR",
            "allow",
            None,
            &["0.0.0.0"],
            up.clone(),
        ),
        s.q(
            "sink.example.org",
            "A",
            "NOERROR",
            "allow",
            None,
            &["127.0.0.1"],
            up.clone(),
        ),
        s.q(
            "filtered.example.net",
            "A",
            "NOERROR",
            "allow",
            None,
            &["10.1.1.1"],
            up.clone(),
        ),
        // A forward-zone name and a blocked record are skipped.
        s.q(
            "ads.home.arpa",
            "A",
            "NOERROR",
            "allow",
            None,
            &["0.0.0.0"],
            up.clone(),
        ),
        s.q(
            "blocked.example.com",
            "A",
            "NOERROR",
            "block",
            None,
            &["0.0.0.0"],
            up.clone(),
        ),
    ])
    .await;
    // A CNAME plus NODATA from both (negative check of an A query): agreement. The upstream's
    // answer is the CNAME alone (no A RRset at the end of the chain), as the edge logs it.
    let mut m = s.world.answer_message(&name("www.unsigned.test."), RecordType::A);
    m.queries = vec![Query::query(name("alias.unsigned.test."), RecordType::A)];
    m.metadata.response_code = hickory_proto::op::ResponseCode::NoError;
    m.answers = vec![Record::from_rdata(
        name("alias.unsigned.test."),
        300,
        RData::CNAME(CNAME(name("target.unsigned.test."))),
    )];
    m.authorities.clear();
    let (a, id) = s.answer(&m.to_vec().unwrap());
    s.post(vec![
        a,
        s.q(
            "alias.unsigned.test",
            "A",
            "NOERROR",
            "allow",
            Some((&id, Timestamp::now())),
            &[],
            json!({"cname": ["target.unsigned.test"]}),
        ),
    ])
    .await;
    run_all(&s).await;
    let asked = f.asked.lock().unwrap().clone();
    assert!(
        !asked
            .iter()
            .any(|n| n == "ads.home.arpa" || n == "blocked.example.com"),
        "{asked:?}"
    );
    assert_eq!(
        s.metric("crosscheck", &[("check", "sinkhole"), ("result", "disagree")])
            .await,
        1.0
    );
    assert_eq!(
        s.metric("crosscheck", &[("check", "sinkhole"), ("result", "agree")])
            .await,
        1.0
    );
    assert_eq!(
        s.metric("crosscheck", &[("check", "sinkhole"), ("result", "no_answer")])
            .await,
        1.0,
        "EDE 15 is no answer"
    );
    assert_eq!(
        s.metric("crosscheck", &[("check", "negative"), ("result", "agree")])
            .await,
        1.0,
        "{asked:?}"
    );
    let keys: Vec<String> = {
        let rows: String = s
            .sql("SELECT coalesce(group_concat(dedupe_key, ' '), '') FROM alerts WHERE kind = 'upstream_disagrees'")
            .await;
        rows.split(' ')
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        keys,
        vec!["upstream_disagrees:example.com:cloudflare".to_string()],
        "only the contradicted sinkhole"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_sent_while_the_cross_check_is_off() {
    let (s, f) = crosscheck_setup(false).await;
    let up = json!({"upstream": serde_json::from_str::<Value>(UPSTREAM).unwrap()});
    s.post(vec![s.q(
        "ads.example.com",
        "A",
        "NOERROR",
        "allow",
        None,
        &["0.0.0.0"],
        up,
    )])
    .await;
    s.post(s.logged(
        "gone.unsigned.test",
        "A",
        s.world.answer(&name("gone.unsigned.test."), RecordType::A),
        Timestamp::now(),
    ))
    .await;
    run_all(&s).await;
    assert!(f.asked.lock().unwrap().is_empty());
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resolver_run_by_an_upstreams_operator_is_refused() {
    let s = Setup::new(None).await;
    // Cloudflare 1.0.0.1 over DoH against the cloudflare group's 1.1.1.1 over DoT.
    let r = ui(&s.c, Method::PUT, "/settings")
        .json(&json!({"crosscheck": {"enabled": true, "resolver": {"protocol": "doh", "ip": "1.0.0.1", "port": 443,
            "tls_host": "cloudflare-dns.com", "path": "/dns-query", "operator": "cloudflare"}}}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error(), "{}", r.status());
    let body = r.text().await.unwrap();
    assert!(body.contains("crosscheck"), "{body}");
    let r = ui(&s.c, Method::PUT, "/settings")
        .json(&json!({"crosscheck": {"enabled": true, "resolver": serde_json::from_str::<Value>(RESOLVER).unwrap()}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
}

// ---------------------------------------------------------------------------------------------
// Review round 1 (wave 5C)

/// A root and `test.` with `www.test.` A, the root's and the zone's signatures in their windows.
fn two_zones(root: &Arc<Key>, test: &Arc<Key>, window: (u32, u32), root_window: (u32, u32)) -> Arc<World> {
    Arc::new(World {
        zones: vec![
            Zone {
                apex: hickory_proto::rr::Name::root(),
                key: Some(root.clone()),
                published: None,
                ds_key: None,
                window: root_window,
                data_window: None,
                records: vec![],
            },
            Zone {
                apex: name("test."),
                key: Some(test.clone()),
                published: None,
                ds_key: None,
                window,
                data_window: None,
                records: vec![Record::from_rdata(
                    name("www.test."),
                    300,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
                )],
            },
        ],
        root_key: root.clone(),
        asked: Mutex::new(vec![]),
        servfail: Mutex::new(Default::default()),
        unreachable: std::sync::atomic::AtomicBool::new(false),
    })
}

/// core.md §8: a logged answer is checked as of its record's `received_at`, its chain from the
/// validator group's view as fetched now. A zone (or its parent) that re-signed after the answer
/// was received has chain signatures newer than `received_at`; the answer is still Secure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_resigned_since_the_answer_was_received_still_validates() {
    let s = Setup::new(None).await;
    let t = now();
    let good = (t - 2 * 86_400, t + 30 * 86_400);
    let resigned = (t - 600, t + 30 * 86_400);
    for (label, zone_window, root_window) in [("dnskey", resigned, good), ("ds", good, resigned)] {
        let (root, test) = (Key::generate(), Key::generate());
        // What the edge got an hour ago, and the chain core fetches now.
        let then = two_zones(&root, &test, good, good);
        let current = two_zones(&root, &test, zone_window, root_window);
        s.c.state.dnssec.set_trust_anchors(current.anchors());
        s.c.state
            .dnssec
            .set_resolver(Arc::new(ZoneResolver(current.clone())));
        let at = Timestamp::now() - jiff::SignedDuration::from_hours(1);
        s.post(s.logged(
            "www.test",
            "A",
            then.answer(&name("www.test."), RecordType::A),
            at,
        ))
        .await;
        s.run().await;
        let r = s.results("www.test").await;
        let last = r.last().unwrap_or_else(|| panic!("{label}: no result"));
        assert_eq!(last.0, "secure", "{label} re-signed since: {r:?}");
    }
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM alerts WHERE kind = 'dnssec_bogus'")
            .await,
        0
    );
}

/// RFC 8914 §4.12: a zone signed by a key without the Zone Key bit is EDE 11.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_without_the_zone_bit_is_ede_11() {
    let s = Setup::new(None).await;
    let w = s.world.clone();
    s.post(s.logged(
        "www.nozone.test",
        "A",
        w.answer(&name("www.nozone.test."), RecordType::A),
        Timestamp::now(),
    ))
    .await;
    s.run().await;
    let r = s.results("www.nozone.test").await;
    assert_eq!(r[0].0, "bogus", "{r:?}");
    assert_eq!(r[0].1["ede"], json!(11), "No Zone Key Bit Set: {r:?}");
    assert_eq!(r[0].1["zone"], json!("nozone.test"), "{r:?}");
}

/// Refuses every request, as an edge does when `dnssec.source_ips` is wrong (README §3).
struct Refusing;

#[async_trait::async_trait]
impl picket_core::dnssec::validator::ChainResolver for Refusing {
    async fn query(
        &self,
        _q: &hickory_proto::rr::Name,
        _t: RecordType,
    ) -> Result<Vec<u8>, picket_core::dnssec::validator::ResolveError> {
        Err(picket_core::dnssec::validator::ResolveError::Failed(
            "HTTP 403".into(),
        ))
    }
}

/// core.md §8: `dnssec_unavailable` while candidates wait and none is validated. An
/// Indeterminate result (a SERVFAIL candidate whose one query the edge refused) validated
/// nothing, so it doesn't hold the condition off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn indeterminate_results_do_not_hold_off_dnssec_unavailable() {
    let s = Setup::new(None).await;
    s.c.state.dnssec.set_resolver(Arc::new(Refusing));
    let open = || async {
        s.sql::<i64>("SELECT count(*) FROM alerts WHERE kind = 'dnssec_unavailable' AND state = 'open'")
            .await
    };
    // A fallback candidate waiting for two hours, its requests refused and retried.
    s.post(vec![s.q(
        "www.test",
        "A",
        "NOERROR",
        "allow",
        None,
        &["192.0.2.1"],
        json!({"truncated": true}),
    )])
    .await;
    s.run().await;
    s.c.state
        .db
        .write(|db| {
            Ok::<_, anyhow::Error>(db.execute(
                "UPDATE dnssec_queue SET first_seen = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-2 hours')",
                [],
            )?)
        })
        .await
        .unwrap();
    // An upstream SERVFAIL now: its one query is refused too (never retried): Indeterminate.
    s.post(vec![s.q(
        "mail.test",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    )])
    .await;
    s.run().await;
    assert_eq!(s.outcome("mail.test").await, "indeterminate");
    picket_core::dnssec::unavailable_check(&s.c.state).await.unwrap();
    assert_eq!(
        open().await,
        1,
        "candidates waited two hours and none was validated"
    );
}

/// README §2 Clocks: validation (signatures are checked against the wall clock) and drops by
/// age wait until the clock is synchronised.
/// README §2 Clocks, core.md §8: while the wall clock isn't synchronised nothing is validated or
/// dropped by age, and admission's stamps wait for it too: items admitted meanwhile are stamped
/// when it synchronises, so they are neither dropped as old (a clock behind) nor held until a
/// date a clock ahead gave, and `dnssec_unavailable` isn't raised from those stamps. An item
/// stamped by a synchronised clock still goes once it is older than the retention window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validation_and_admission_stamps_wait_for_a_synchronised_clock() {
    let (s, f) = crosscheck_setup(true).await;
    wait_lookup_exclude(&s).await;
    s.c.state.clock.pin(false);
    s.post(vec![s.q(
        "www.expired.test",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    )])
    .await;
    s.post(vec![s.q(
        "ads.example.com",
        "A",
        "NOERROR",
        "allow",
        None,
        &["0.0.0.0"],
        json!({}),
    )])
    .await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    // What an unsynchronised clock stamps: long ago, or far ahead.
    s.c.state
        .db
        .write(|db| {
            for t in ["dnssec_queue", "crosscheck_queue"] {
                db.execute(
                    &format!(
                        "UPDATE {t} SET first_seen = '2000-01-01T00:00:00.000000Z', next_at = '2100-01-01T00:00:00.000000Z'"
                    ),
                    [],
                )?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    picket_core::dnssec::drain(&s.c.state).await.unwrap();
    f.answers.lock().unwrap().insert(
        "ads.example.com".into(),
        (0, vec![Ipv4Addr::new(0, 0, 0, 0)], None, None),
    );
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM dnssec_results").await,
        0,
        "no validation"
    );
    // The SERVFAIL candidate and the sinkhole record's fallback query.
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM dnssec_queue").await,
        2,
        "nothing dropped"
    );
    picket_core::dnssec::crosscheck::drain(&s.c.state).await.unwrap();
    assert_eq!(s.metric("dnssec_dropped", &[]).await, 0.0);
    assert_eq!(
        s.metric("crosscheck", &[("result", "dropped")]).await,
        0.0,
        "nothing dropped"
    );
    // Synchronised: the items are stamped now; none is dropped as old, none waits until 2100,
    // and nothing waited long enough for `dnssec_unavailable`.
    s.c.state.clock.pin(true);
    picket_core::dnssec::unavailable_check(&s.c.state).await.unwrap();
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM alerts WHERE kind = 'dnssec_unavailable' AND state = 'open'")
            .await,
        0
    );
    picket_core::dnssec::drain(&s.c.state).await.unwrap();
    picket_core::dnssec::crosscheck::drain(&s.c.state).await.unwrap();
    assert_eq!(s.metric("dnssec_dropped", &[]).await, 0.0);
    assert_eq!(s.metric("crosscheck", &[("result", "dropped")]).await, 0.0);
    assert_eq!(
        s.results("www.expired.test").await.len(),
        1,
        "validated once the clock is synchronised"
    );
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await,
        0,
        "the sinkhole check ran"
    );
    // An item a synchronised clock stamped long ago goes, counted.
    s.post(vec![s.q(
        "www.nokey.test",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    )])
    .await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    s.c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE dnssec_queue SET first_seen = '2000-01-01T00:00:00.000000Z', next_at = '2100-01-01T00:00:00.000000Z'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    picket_core::dnssec::drain(&s.c.state).await.unwrap();
    assert_eq!(s.metric("dnssec_dropped", &[]).await, 1.0);
}

/// core.md §8: work beyond `dnssec.max_per_minute` waits; the wait doesn't count against the
/// validation's timeout (a validation needing several requests at one a minute still ends
/// Secure, not timed out).
#[tokio::test(start_paused = true)]
async fn rate_waits_do_not_use_up_the_validation_timeout() {
    use picket_core::dnssec::validator::{self, ChainCache, Limiter, Shared, Subject};
    let w = World::standard();
    let shared = Shared {
        resolver: Arc::new(ZoneResolver(w.clone())),
        cache: Arc::new(ChainCache::default()),
        limiter: Arc::new(Limiter::new(1)),
        anchors: Arc::new(w.anchors()),
        generation: 0,
    };
    // Five chain requests (past.test's DNSKEY and DS, test.'s, the root's DNSKEY): four waits of
    // a minute. The answer was received two hours ago, inside its signatures' window.
    let q = validator::question(&name("www.past.test."), RecordType::A);
    let wire = w.answer(&name("www.past.test."), RecordType::A);
    let started = tokio::time::Instant::now();
    let v = validator::validate(
        &shared,
        Subject::Logged {
            query: q,
            wire: &wire,
        },
        u64::from(now()) - 7200,
    )
    .await;
    assert!(
        started.elapsed() > validator::VALIDATION_TIMEOUT,
        "the requests took longer than the timeout at one a minute: {:?}",
        started.elapsed()
    );
    assert_eq!(v.failed, None, "{v:?}");
    assert_eq!(v.outcome, Some(validator::Outcome::Secure), "{v:?}");
}

/// core.md §8 Outcomes: a record that takes a known Bogus result joins its alert's names, edges,
/// clients and groups.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_client_joins_a_known_bogus_alert() {
    let s = Setup::new(None).await;
    let wire = s.world.answer(&name("www.expired.test."), RecordType::A);
    let (a, id) = s.answer(&wire);
    let at = Timestamp::now();
    s.post(vec![
        a,
        s.q(
            "www.expired.test",
            "A",
            "NOERROR",
            "allow",
            Some((&id, at)),
            &["192.0.2.4"],
            json!({}),
        ),
    ])
    .await;
    s.run().await;
    s.post(vec![s.q(
        "www.expired.test",
        "A",
        "NOERROR",
        "allow",
        Some((&id, at)),
        &["192.0.2.4"],
        json!({"device": "second-client", "client": "192.168.1.141"}),
    )])
    .await;
    s.run().await;
    assert_eq!(
        s.results("www.expired.test").await.len(),
        1,
        "the result is reused"
    );
    let d: Value = serde_json::from_str(
        &s.sql::<String>("SELECT details_json FROM alerts WHERE kind = 'dnssec_bogus'")
            .await,
    )
    .unwrap();
    let name0 = &d["names"][0];
    assert_eq!(name0["clients"], json!(["tablet", "second-client"]), "{d}");
    assert!(
        name0["resolved_by"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["client"] == json!("second-client")),
        "{d}"
    );
    assert_eq!(
        s.sql::<i64>("SELECT count FROM alerts WHERE kind = 'dnssec_bogus'")
            .await,
        1,
        "not raised again: the verdict isn't new"
    );
}

/// core.md §8: each record counts once; a batch admitted again (its partition write failed, or a
/// stop came between) counts, queues and joins nothing twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_admitted_again_counts_once() {
    let s = Setup::new(None).await;
    let up = serde_json::from_str::<Value>(UPSTREAM).unwrap().to_string();
    let recs: Vec<picket_core::logs::record::Rec> = (0..3)
        .map(|i| picket_core::logs::record::Rec {
            edge: s.edge.id.clone(),
            boot: BOOT.into(),
            seq: 100 + i,
            ts: ts(Timestamp::now()),
            qname: "www.test".into(),
            qtype: "A".into(),
            rcode: "NOERROR".into(),
            decision: "allow".into(),
            client_ip: "192.168.1.140".into(),
            profile: Some("default".into()),
            upstream_json: Some(up.clone()),
            truncated: true,
            answers: vec!["192.0.2.1".into()],
            ..Default::default()
        })
        .collect();
    let g = s.c.state.restore.generation();
    let first = picket_core::dnssec::admit(&s.c.state, &recs, g).await.unwrap();
    let again = picket_core::dnssec::admit(&s.c.state, &recs, g).await.unwrap();
    // The counts wait in the metric outbox for the analysis's flush.
    picket_core::metrics::outbox::flush(&s.c.state).await.unwrap();
    assert_eq!(
        s.metric("dnssec_answers", &[]).await,
        3.0,
        "each record counts once"
    );
    let ctx: Value =
        serde_json::from_str(&s.sql::<String>("SELECT context_json FROM dnssec_queue").await).unwrap();
    assert_eq!(ctx["n"], json!(3), "{ctx}");
    // Once the analysis is done with them, their keys go.
    picket_core::dnssec::admitted(&s.c.state, first).await;
    picket_core::dnssec::admitted(&s.c.state, again).await;
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM dnssec_admitted").await, 0);
}

/// Holds the first chain query until released.
struct Gate {
    world: Arc<World>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    once: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl picket_core::dnssec::validator::ChainResolver for Gate {
    async fn query(
        &self,
        n: &hickory_proto::rr::Name,
        t: RecordType,
    ) -> Result<Vec<u8>, picket_core::dnssec::validator::ResolveError> {
        if !self.once.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        Ok(self.world.answer(n, t))
    }
}

/// The `lookup-exclude` bundle's feed is ingested at start; the sinkhole check needs it.
async fn wait_lookup_exclude(s: &Setup) {
    assert!(
        common::edge::eventually(|| async {
            s.sql::<i64>(
                "SELECT count(*) FROM feed_runs WHERE feed_id = 'lookup-exclude' AND status = 'applied'",
            )
            .await
                > 0
        })
        .await
    );
}

/// Restores this core's own export (everything queued goes, core.md §2).
async fn restore_own_export(s: &Setup) {
    let dir = s.c.dir.path().to_path_buf();
    let doc =
        s.c.state
            .db
            .read(move |c| picket_core::config::export::export(c, &dir))
            .await
            .unwrap();
    picket_core::config::export::restore(&s.c.state, doc, None)
        .await
        .unwrap();
}

/// core.md §2 "the old state until it completes, then only the new one": a validation in flight
/// when a restore commits stores nothing after it (no result, no alert).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_validation_in_flight_stores_nothing_after_a_restore() {
    let s = Setup::new(None).await;
    let gate = Arc::new(Gate {
        world: s.world.clone(),
        entered: Default::default(),
        release: Default::default(),
        once: Default::default(),
    });
    s.c.state.dnssec.set_resolver(gate.clone());
    s.post(s.logged(
        "www.expired.test",
        "A",
        s.world.answer(&name("www.expired.test."), RecordType::A),
        Timestamp::now(),
    ))
    .await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    let st = s.c.state.clone();
    let task = tokio::spawn(async move { picket_core::dnssec::turn(&st).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(20), gate.entered.notified())
        .await
        .unwrap();
    restore_own_export(&s).await;
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM dnssec_queue").await, 0);
    gate.release.notify_one();
    task.await.unwrap();
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM dnssec_results").await,
        0,
        "no pre-restore result"
    );
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM alerts WHERE kind = 'dnssec_bogus'")
            .await,
        0,
        "no pre-restore alert"
    );
}

/// A cross-check resolver that holds its first query until released, then contradicts.
struct GatedResolver {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl DnsServerClient for GatedResolver {
    async fn query(&self, s: &DnsServer, query: &[u8], t: Duration) -> Result<Vec<u8>, DnsClientError> {
        self.entered.notify_one();
        self.release.notified().await;
        let f = FakeResolver::default();
        f.answers.lock().unwrap().insert(
            "ads.example.com".into(),
            (0, vec![Ipv4Addr::new(93, 184, 216, 34)], None, None),
        );
        f.query(s, query, t).await
    }
}

/// The same for a cross-check in flight: no `upstream_disagrees` from before the restore.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cross_check_in_flight_stores_nothing_after_a_restore() {
    let (s, _f) = crosscheck_setup(true).await;
    wait_lookup_exclude(&s).await;
    let gate = Arc::new(GatedResolver {
        entered: Default::default(),
        release: Default::default(),
    });
    s.c.state.dnssec.crosscheck.set_client(gate.clone());
    s.post(vec![s.q(
        "ads.example.com",
        "A",
        "NOERROR",
        "allow",
        None,
        &["0.0.0.0"],
        json!({}),
    )])
    .await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 1);
    let st = s.c.state.clone();
    let task = tokio::spawn(async move { picket_core::dnssec::crosscheck::turn(&st).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(20), gate.entered.notified())
        .await
        .unwrap();
    restore_own_export(&s).await;
    gate.release.notify_one();
    task.await.unwrap();
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM alerts WHERE kind = 'upstream_disagrees'")
            .await,
        0,
        "no pre-restore alert"
    );
}

/// core.md §9: the validator's DNSKEY and DS answers are charged to the shared evidence budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_evidence_is_charged_to_the_shared_budget() {
    let s = Setup::new(None).await;
    s.post(s.logged(
        "www.expired.test",
        "A",
        s.world.answer(&name("www.expired.test."), RecordType::A),
        Timestamp::now(),
    ))
    .await;
    s.run().await;
    assert!(
        s.sql::<i64>("SELECT count(*) FROM alert_evidence_answers WHERE source = 'validator'")
            .await
            > 0
    );
    let stored = || async {
        s.sql::<i64>(
            "SELECT coalesce((SELECT sum(octet_length(record_json)) FROM alert_evidence), 0)
                  + coalesce((SELECT sum(octet_length(wire)) FROM alert_evidence_answers), 0)
                  + coalesce((SELECT sum(octet_length(record_json) + coalesce(octet_length(wire), 0)
                                        + coalesce(octet_length(decoded_json), 0)) FROM wire_examples), 0)
                  + (SELECT count(*) * 64 FROM alert_evidence_counts WHERE kind IN ('client', 'name'))",
        )
        .await as u64
    };
    // Once the evidence backfill is done, what is stored is what the budget holds.
    assert!(
        common::edge::eventually(|| async { s.c.state.analysis.capture.used() == stored().await }).await,
        "used {} stored {}",
        s.c.state.analysis.capture.used(),
        stored().await
    );
}

// ---------------------------------------------------------------------------------------------
// Review round 2

/// core.md §2: a validation in flight when a restore commits refills neither the crypto memo nor
/// the chain cache the restore emptied (the new generation's work starts from nothing).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_validation_in_flight_refills_no_cache_after_a_restore() {
    let s = Setup::new(None).await;
    let gate = Arc::new(Gate {
        world: s.world.clone(),
        entered: Default::default(),
        release: Default::default(),
        once: Default::default(),
    });
    s.c.state.dnssec.set_resolver(gate.clone());
    let at = Timestamp::now();
    let wire = s.world.answer(&name("www.test."), RecordType::A);
    let records = s.logged("www.test", "A", wire, at);
    let aid = records[1]["answer_id"].as_str().unwrap().to_string();
    s.post(records).await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    let st = s.c.state.clone();
    let task = tokio::spawn(async move { picket_core::dnssec::turn(&st).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(20), gate.entered.notified())
        .await
        .unwrap();
    restore_own_export(&s).await;
    gate.release.notify_one();
    task.await.unwrap();
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM dnssec_results").await, 0);
    assert!(
        s.c.state.dnssec.memo.get(&aid, at.as_second() as u64).is_none(),
        "a pre-restore validation refilled the crypto memo"
    );
    assert!(
        s.c.state.dnssec.cache.is_empty(),
        "a pre-restore validation refilled the chain cache ({} entries)",
        s.c.state.dnssec.cache.len()
    );
}

/// core.md §2, §6: records an edge sends after a restore commits are kept: the restore empties
/// only the partitions' pre-restore records (meanwhile the edge's batches are answered 503 and
/// wait in its spool), even when emptying them takes a retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_sent_after_a_restore_commits_are_kept() {
    let s = Setup::new(None).await;
    // Emptying metrics.db fails until the trigger goes, so the restore's clean-up is retried.
    s.c.state
        .metrics_db
        .write(|db| {
            db.execute_batch(
                "INSERT OR IGNORE INTO series(name, labels_json) VALUES ('test_series', '{}');
                 CREATE TRIGGER test_keep_series BEFORE DELETE ON series BEGIN SELECT RAISE(FAIL, 'test: metrics.db busy'); END;",
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    restore_own_export(&s).await;
    assert!(
        s.c.state.restore.logs_pending(),
        "the clean-up waits for its retry"
    );
    let lines = vec![s.q(
        "www.expired.test",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    )];
    let r = s.edge.post_logs_once(&lines).await;
    let acked = r.status() == 200;
    if !acked {
        assert_eq!(r.status(), 503, "{}", r.text().await.unwrap());
    }
    s.c.state
        .metrics_db
        .write(|db| {
            db.execute_batch("DROP TRIGGER test_keep_series;")?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    assert!(
        common::edge::eventually(|| async { !s.c.state.restore.logs_pending() }).await,
        "the clean-up's retry ran"
    );
    if !acked {
        // The edge sends the batch again from its spool.
        s.post(lines).await;
    }
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM dnssec_queue").await,
        1,
        "the record sent after the restore was kept and analysed"
    );
}

/// core.md §8, §10, README §2 Restarts: admission's and validation's counts go through the
/// metric outbox in the transactions that admit and store, so a failed metrics write (or a stop
/// between the two databases) loses none, and a batch admitted again adds none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dnssec_counts_survive_a_failed_metrics_write() {
    let s = Setup::new(None).await;
    let rec = picket_core::logs::record::Rec {
        edge: s.edge.id.clone(),
        boot: BOOT.into(),
        seq: 1_000_000,
        ts: ts(Timestamp::now()),
        qname: "www.test".into(),
        qtype: "A".into(),
        rcode: "NOERROR".into(),
        decision: "allow".into(),
        client_ip: "192.168.1.140".into(),
        profile: Some("default".into()),
        upstream_json: Some(UPSTREAM.to_string()),
        truncated: true,
        answers: vec!["192.0.2.1".into()],
        ..Default::default()
    };
    s.c.state
        .metrics_db
        .write(|db| {
            db.execute_batch(
                "CREATE TRIGGER test_fail_points BEFORE INSERT ON points BEGIN SELECT RAISE(FAIL, 'test: metrics.db failing'); END;",
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let g = s.c.state.restore.generation();
    let first = picket_core::dnssec::admit(&s.c.state, std::slice::from_ref(&rec), g)
        .await
        .unwrap();
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM dnssec_admitted").await, 1);
    picket_core::dnssec::drain(&s.c.state).await.unwrap();
    assert_eq!(s.outcome("www.test").await, "secure");
    s.c.state
        .metrics_db
        .write(|db| {
            db.execute_batch("DROP TRIGGER test_fail_points;")?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let again = picket_core::dnssec::admit(&s.c.state, &[rec], g).await.unwrap();
    picket_core::metrics::outbox::flush(&s.c.state).await.unwrap();
    assert_eq!(
        s.metric("dnssec_answers", &[]).await,
        1.0,
        "admission counted once"
    );
    assert_eq!(
        s.metric("dnssec_results", &[("outcome", "secure")]).await,
        1.0,
        "the result counted"
    );
    assert_eq!(
        s.metric("dnssec_coverage", &[("class", "fallback")]).await,
        1.0,
        "its coverage counted"
    );
    picket_core::dnssec::admitted(&s.c.state, first).await;
    picket_core::dnssec::admitted(&s.c.state, again).await;
}

/// core.md §9 Dedupe: a record that takes a known Bogus result after its `dnssec_bogus` alert
/// was resolved raises it again (reopened, counted, the new client listed), as when the alert
/// was deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_known_bogus_result_reopens_a_resolved_alert() {
    let s = Setup::new(None).await;
    let wire = s.world.answer(&name("www.expired.test."), RecordType::A);
    let (a, id) = s.answer(&wire);
    let at = Timestamp::now();
    s.post(vec![
        a,
        s.q(
            "www.expired.test",
            "A",
            "NOERROR",
            "allow",
            Some((&id, at)),
            &["192.0.2.4"],
            json!({}),
        ),
    ])
    .await;
    s.run().await;
    let key: String = s
        .sql("SELECT dedupe_key FROM alerts WHERE kind = 'dnssec_bogus'")
        .await;
    s.c.state.alerts.resolve(&key, None).await.unwrap();
    s.post(vec![s.q(
        "www.expired.test",
        "A",
        "NOERROR",
        "allow",
        Some((&id, at)),
        &["192.0.2.4"],
        json!({"device": "second-client", "client": "192.168.1.141"}),
    )])
    .await;
    s.run().await;
    assert_eq!(
        s.results("www.expired.test").await.len(),
        1,
        "the result is reused"
    );
    assert_eq!(
        s.sql::<String>("SELECT state FROM alerts WHERE kind = 'dnssec_bogus'")
            .await,
        "open"
    );
    assert_eq!(
        s.sql::<i64>("SELECT count FROM alerts WHERE kind = 'dnssec_bogus'")
            .await,
        2
    );
    let d = s
        .sql::<String>("SELECT details_json FROM alerts WHERE kind = 'dnssec_bogus'")
        .await;
    assert!(d.contains("second-client"), "{d}");
    // Deleted by hand: the next record raises it anew.
    s.c.state
        .db
        .write(|db| {
            db.execute("DELETE FROM alerts WHERE kind = 'dnssec_bogus'", [])?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    s.post(vec![s.q(
        "www.expired.test",
        "A",
        "NOERROR",
        "allow",
        Some((&id, at)),
        &["192.0.2.4"],
        json!({"device": "third-client", "client": "192.168.1.142"}),
    )])
    .await;
    s.run().await;
    let d = s
        .sql::<String>("SELECT details_json FROM alerts WHERE kind = 'dnssec_bogus' AND state = 'open'")
        .await;
    assert!(d.contains("third-client") && d.contains("\"ede\":7"), "{d}");
}

/// Holds every chain query for one zone apex until released.
struct HoldZone {
    world: Arc<World>,
    apex: String,
    entered: tokio::sync::Notify,
    /// No permits until released.
    release: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl picket_core::dnssec::validator::ChainResolver for HoldZone {
    async fn query(
        &self,
        n: &hickory_proto::rr::Name,
        t: RecordType,
    ) -> Result<Vec<u8>, picket_core::dnssec::validator::ResolveError> {
        if n.to_string().eq_ignore_ascii_case(&self.apex) {
            self.entered.notify_one();
            let _held = self.release.acquire().await;
        }
        Ok(self.world.answer(n, t))
    }
}

/// core.md §8 Queue: a turn's results are stored as its validations end, not when its slowest
/// one does (one stuck on its requests holds back nobody else's result).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn results_are_stored_as_validations_end() {
    let s = Setup::new(None).await;
    let hold = Arc::new(HoldZone {
        world: s.world.clone(),
        apex: "expired.test.".into(),
        entered: Default::default(),
        release: tokio::sync::Semaphore::new(0),
    });
    s.c.state.dnssec.set_resolver(hold.clone());
    let at = Timestamp::now();
    let mut lines = s.logged(
        "www.expired.test",
        "A",
        s.world.answer(&name("www.expired.test."), RecordType::A),
        at,
    );
    lines.extend(s.logged(
        "www.test",
        "A",
        s.world.answer(&name("www.test."), RecordType::A),
        at,
    ));
    s.post(lines).await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    let st = s.c.state.clone();
    let task = tokio::spawn(async move { picket_core::dnssec::turn(&st).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(20), hold.entered.notified())
        .await
        .unwrap();
    let stored = common::edge::eventually(|| async { s.results("www.test").await.len() == 1 }).await;
    hold.release.add_permits(1 << 20);
    task.await.unwrap();
    assert!(
        stored,
        "www.test's result waited for www.expired.test's validation"
    );
    assert_eq!(s.outcome("www.test").await, "secure");
    picket_core::dnssec::drain(&s.c.state).await.unwrap();
    assert_eq!(s.outcome("www.expired.test").await, "bogus");
}

// ---------------------------------------------------------------------------------------------
// Final check (wave 5 part C, round 3)

/// core.md §2 "the old state until it completes, then only the new one"; core.md §6 (ack once
/// durable): a log batch admitted before a restore commits, whose partition write reaches the log
/// writer only after the commit, isn't stored (and acked) just to be emptied with the
/// pre-restore records: it is refused (`503`, the edge retries), and its retry once the old
/// partitions are gone is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_crossing_a_restore_is_refused_not_acked_then_emptied() {
    let s = Setup::new(None).await;
    s.post(vec![s.q(
        "seed.example",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    )])
    .await;
    let writer = s.c.state.logs.writer().clone();
    let store = writer.store().clone();
    let hour = tokio::task::spawn_blocking(move || store.list())
        .await
        .unwrap()
        .unwrap()[0]
        .0;
    // The log writer busy while the batch passes ingest's early check.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let held = tokio::spawn(async move {
        writer
            .with_partition(hour, move |_| {
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
            .await
            .unwrap();
    });
    entered_rx.await.unwrap();
    let mut q = s.q(
        "crossing.example",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    );
    q["boot"] = json!("race-boot");
    let body = common::edge::gzip(format!("{q}\n").as_bytes());
    let post = |body: Vec<u8>| {
        let http = s.edge.http.clone();
        let url = s.edge.url("/v1/logs");
        async move {
            let r = http
                .post(url)
                .header("Content-Type", "application/jsonl")
                .header("Content-Encoding", "gzip")
                .body(body)
                .send()
                .await
                .unwrap();
            let status = r.status();
            (status, r.text().await.unwrap())
        }
    };
    let posted = tokio::spawn(post(body.clone()));
    assert!(
        common::edge::eventually(|| async {
            s.sql::<i64>("SELECT count(*) FROM edge_boots WHERE boot = 'race-boot'")
                .await
                == 1
        })
        .await,
        "the batch reached ingest"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let state = s.c.state.clone();
    let generation = state.restore.generation();
    let restored = tokio::spawn(async move {
        let dir = state.data_dir.clone();
        let doc = state
            .db
            .read(move |c| picket_core::config::export::export(c, &dir))
            .await
            .unwrap();
        picket_core::config::export::restore(&state, doc, None)
            .await
            .unwrap();
    });
    assert!(
        common::edge::eventually(|| async { s.c.state.restore.generation() != generation }).await,
        "the restore committed while the batch waits for the log writer"
    );
    release_tx.send(()).unwrap();
    held.await.unwrap();
    let (status, text) = posted.await.unwrap();
    restored.await.unwrap();
    assert_eq!(status, 503, "{text}");
    assert!(!s.c.state.restore.logs_pending());
    let kept = || async {
        let writer = s.c.state.logs.writer().clone();
        writer
            .with_partition(hour, |p| {
                Ok(p.conn.query_row(
                    "SELECT count(*) FROM events WHERE qname = 'crossing.example'",
                    [],
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap()
            .unwrap_or(0)
    };
    assert_eq!(kept().await, 0);
    // The edge's retry, after the old partitions are gone, is stored and kept. Resent while core
    // answers 503 (a partition busy past its busy_timeout under load), as the edge resends and
    // `FakeEdge::post_logs` does, for up to LOG_RETRY_FOR.
    let end = tokio::time::Instant::now() + common::edge::LOG_RETRY_FOR;
    let (status, text) = loop {
        let (status, text) = post(body.clone()).await;
        if status != 503 || tokio::time::Instant::now() > end {
            break (status, text);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(status, 200, "{text}");
    assert_eq!(kept().await, 1);
}

/// README §2 Clocks, core.md §8 cross-check "each (qname, qtype) is checked once per
/// `crosscheck.dedupe_window`": an item admitted before the wall clock is synchronised isn't
/// checked until it is stamped (with its dedupe marker), so the check runs once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unstamped_cross_check_waits_for_the_clock() {
    let (s, f) = crosscheck_setup(true).await;
    wait_lookup_exclude(&s).await;
    s.c.state.clock.pin(false);
    f.answers.lock().unwrap().insert(
        "ads.example.com".into(),
        (0, vec![Ipv4Addr::new(1, 2, 3, 4)], None, None),
    );
    let sinkholed = || {
        s.q(
            "ads.example.com",
            "A",
            "NOERROR",
            "allow",
            None,
            &["0.0.0.0"],
            json!({}),
        )
    };
    s.post(vec![sinkholed()]).await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    assert_eq!(
        s.sql::<i64>("SELECT count(*) FROM crosscheck_queue WHERE stamped = 0")
            .await,
        1
    );
    picket_core::dnssec::crosscheck::drain(&s.c.state).await.unwrap();
    assert!(
        f.asked.lock().unwrap().is_empty(),
        "nothing asked before the clock is synchronised"
    );
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 1);
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_seen").await, 0);
    s.c.state.clock.pin(true);
    s.post(vec![sinkholed()]).await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    picket_core::dnssec::crosscheck::drain(&s.c.state).await.unwrap();
    assert_eq!(
        f.asked.lock().unwrap().len(),
        1,
        "checked once, after the clock is synchronised"
    );
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_seen").await, 1);
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 0);
}

/// Holds the query for one name until released; answers like [`FakeResolver`].
struct HoldResolver {
    inner: FakeResolver,
    held: String,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl DnsServerClient for HoldResolver {
    async fn query(&self, s: &DnsServer, query: &[u8], t: Duration) -> Result<Vec<u8>, DnsClientError> {
        let q = Message::from_vec(query).map_err(|e| DnsClientError::Transport(e.to_string()))?;
        if q.queries[0].name().to_string().trim_end_matches('.') == self.held {
            self.entered.notify_one();
            let _held = self.release.acquire().await;
        }
        self.inner.query(s, query, t).await
    }
}

/// core.md §8 Queue, README §2 Restarts: a cross-check turn stores each result as its check
/// ends (a slow query holds back no other result, and a restart loses only the check in
/// flight), and takes about a minute of `crosscheck.max_per_minute` queries.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_check_results_are_stored_as_checks_end_in_turns_sized_to_the_rate() {
    let (s, _f) = crosscheck_setup(true).await;
    wait_lookup_exclude(&s).await;
    let hold = Arc::new(HoldResolver {
        inner: FakeResolver::default(),
        held: "slow.example.com".into(),
        entered: Default::default(),
        release: tokio::sync::Semaphore::new(0),
    });
    s.c.state.dnssec.crosscheck.set_client(hold.clone());
    let sinkholed = |n: &str| s.q(n, "A", "NOERROR", "allow", None, &["0.0.0.0"], json!({}));
    for n in ["fast.example.com", "slow.example.com"] {
        s.post(vec![sinkholed(n)]).await;
        picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 2);
    let st = s.c.state.clone();
    let task = tokio::spawn(async move { picket_core::dnssec::crosscheck::turn(&st).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(20), hold.entered.notified())
        .await
        .unwrap();
    let stored = common::edge::eventually(|| async {
        s.sql::<i64>("SELECT count(*) FROM crosscheck_queue WHERE qname = 'fast.example.com'")
            .await
            == 0
    })
    .await;
    hold.release.add_permits(1 << 20);
    assert_eq!(task.await.unwrap(), 2);
    assert!(
        stored,
        "fast.example.com's result waited for slow.example.com's query"
    );
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 0);
    // At one query a minute, a turn takes one item.
    let resolver: Value = serde_json::from_str(RESOLVER).unwrap();
    let r = ui(&s.c, Method::PUT, "/settings")
        .json(&json!({"crosscheck": {"enabled": true, "resolver": resolver, "max_per_minute": 1}}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.text().await.unwrap());
    for n in ["one.example.com", "two.example.com", "three.example.com"] {
        s.post(vec![sinkholed(n)]).await;
    }
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 3);
    assert_eq!(
        picket_core::dnssec::crosscheck::turn(&s.c.state).await.unwrap(),
        1
    );
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 2);
}

/// A cross-check resolver that can't be reached: every query fails in transport, so the check is
/// retried with backoff (core.md §8 Cross-check: 3 attempts).
struct FailingResolver;

#[async_trait::async_trait]
impl DnsServerClient for FailingResolver {
    async fn query(&self, _s: &DnsServer, _q: &[u8], _t: Duration) -> Result<Vec<u8>, DnsClientError> {
        Err(DnsClientError::Transport("connection refused".into()))
    }
}

/// Adds up the `dnssec_queued` events' counts into `sums` until `done` holds for them.
async fn queued_until(
    events: &mut tokio::sync::broadcast::Receiver<picket_core::state::UiEvent>,
    sums: &mut BTreeMap<String, u64>,
    done: impl Fn(&BTreeMap<String, u64>) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while !done(sums) {
            match events.recv().await {
                Ok(e) if e.kind == "dnssec_queued" => {
                    for (k, v) in e.data.as_object().expect("an object") {
                        *sums.entry(k.clone()).or_default() += v.as_u64().expect("a count");
                    }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("events closed: {e}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("dnssec_queued counts so far: {sums:?}"));
}

/// Makes every item of `table` due now.
async fn due_now(s: &Setup, table: &'static str) {
    s.c.state
        .db
        .write(move |c| {
            Ok::<_, anyhow::Error>(c.execute(
                &format!("UPDATE {table} SET next_at = '2000-01-01T00:00:00.000000Z'"),
                [],
            )?)
        })
        .await
        .unwrap();
}

/// api.md §7, core.md §8: every change to the queues `GET dnssec/queue` shows sends a coalesced
/// `dnssec_queued` event, so the UI's queue view needn't poll while its socket is open: besides
/// checks queued, a validation retried after a failed request, a record joining a queued
/// validation, a validation waiting for a reachable edge, a cross-check retried after a failed
/// query, and a cross-check that ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_queue_change_sends_dnssec_queued() {
    let (s, f) = crosscheck_setup(true).await;
    let mut events = s.c.state.events.subscribe();
    let mut sums = BTreeMap::new();
    let n = |m: &BTreeMap<String, u64>, k: &str| m.get(k).copied().unwrap_or(0);
    let attempts = || async { s.sql::<i64>("SELECT attempts FROM dnssec_queue").await };
    // A fallback candidate whose requests the edge refuses: retried with backoff.
    s.c.state.dnssec.set_resolver(Arc::new(Refusing));
    let fallback = || {
        s.q(
            "www.test",
            "A",
            "NOERROR",
            "allow",
            None,
            &["192.0.2.1"],
            json!({"truncated": true}),
        )
    };
    s.post(vec![fallback()]).await;
    s.run().await;
    assert_eq!(attempts().await, 1, "one failed request");
    queued_until(&mut events, &mut sums, |m| {
        n(m, "validation") >= 1 && n(m, "retried") >= 1
    })
    .await;
    // A later record of the same query joins the queued item (its records, edges and clients).
    s.post(vec![fallback()]).await;
    s.run().await;
    queued_until(&mut events, &mut sums, |m| n(m, "joined") >= 1).await;
    // No edge DoH listener reachable: the due item waits without using an attempt.
    s.c.state
        .dnssec
        .set_resolver(Arc::new(ZoneResolver(s.world.clone())));
    s.world
        .unreachable
        .store(true, std::sync::atomic::Ordering::Relaxed);
    due_now(&s, "dnssec_queue").await;
    s.run().await;
    queued_until(&mut events, &mut sums, |m| n(m, "waiting") >= 1).await;
    assert_eq!(attempts().await, 1, "waiting uses no attempt");
    s.world
        .unreachable
        .store(false, std::sync::atomic::Ordering::Relaxed);
    // An Insecure NXDOMAIN is cross-checked; the resolver can't be reached, so it is retried,
    // and once it answers the check ends and leaves the queue.
    s.c.state.dnssec.crosscheck.set_client(Arc::new(FailingResolver));
    let wire = s.world.answer(&name("blocked.unsigned.test."), RecordType::A);
    s.post(s.logged("blocked.unsigned.test", "A", wire, Timestamp::now()))
        .await;
    run_all(&s).await;
    assert_eq!(s.outcome("blocked.unsigned.test").await, "insecure");
    queued_until(&mut events, &mut sums, |m| {
        n(m, "crosscheck") >= 1 && n(m, "crosscheck_retried") >= 1
    })
    .await;
    assert_eq!(s.sql::<i64>("SELECT attempts FROM crosscheck_queue").await, 1);
    s.c.state.dnssec.crosscheck.set_client(f.clone());
    due_now(&s, "crosscheck_queue").await;
    picket_core::dnssec::crosscheck::drain(&s.c.state).await.unwrap();
    queued_until(&mut events, &mut sums, |m| n(m, "crosscheck_ended") >= 1).await;
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 0);
    assert_eq!(f.asked.lock().unwrap().as_slice(), ["blocked.unsigned.test"]);
}

/// K3 (build-and-test.md §5; api.md §7, core.md §8, README §2 Clocks): the queue changes no check
/// makes send `dnssec_queued` too, so the queue view needn't poll: items of both queues stamped
/// once the wall clock is synchronised, a cross-check dropped past the retention window, and a
/// validation dropped past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stamps_and_drops_send_dnssec_queued() {
    let (s, _f) = crosscheck_setup(true).await;
    wait_lookup_exclude(&s).await;
    let mut events = s.c.state.events.subscribe();
    let mut sums = BTreeMap::new();
    let n = |m: &BTreeMap<String, u64>, k: &str| m.get(k).copied().unwrap_or(0);
    // Admitted while the wall clock isn't synchronised: unstamped, in both queues.
    s.c.state.clock.pin(false);
    s.post(vec![s.q(
        "www.expired.test",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    )])
    .await;
    s.post(vec![s.q(
        "ads.example.com",
        "A",
        "NOERROR",
        "allow",
        None,
        &["0.0.0.0"],
        json!({}),
    )])
    .await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    let unstamped = s
        .sql::<i64>("SELECT count(*) FROM dnssec_queue WHERE stamped = 0")
        .await
        + s.sql::<i64>("SELECT count(*) FROM crosscheck_queue WHERE stamped = 0")
            .await;
    assert_eq!(
        unstamped, 3,
        "the SERVFAIL candidate, the sinkhole's fallback and its cross-check"
    );
    queued_until(&mut events, &mut sums, |m| n(m, "validation") >= 2).await;
    assert_eq!(n(&sums, "stamped"), 0);
    // Synchronised: the next turn stamps all three.
    s.c.state.clock.pin(true);
    picket_core::dnssec::turn(&s.c.state).await.unwrap();
    queued_until(&mut events, &mut sums, |m| n(m, "stamped") >= 3).await;
    // The cross-check, once older than the retention window, is dropped by its turn.
    s.c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE crosscheck_queue SET first_seen = '2000-01-01T00:00:00.000000Z'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    picket_core::dnssec::crosscheck::turn(&s.c.state).await.unwrap();
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM crosscheck_queue").await, 0);
    queued_until(&mut events, &mut sums, |m| n(m, "dropped") >= 1).await;
    // A validation older than the window is dropped by the next validation turn.
    s.post(vec![s.q(
        "www.nokey.test",
        "A",
        "SERVFAIL",
        "servfail",
        None,
        &[],
        json!({}),
    )])
    .await;
    picket_core::logs::analysis::drain(&s.c.state).await.unwrap();
    s.c.state
        .db
        .write(|db| {
            db.execute(
                "UPDATE dnssec_queue SET first_seen = '2000-01-01T00:00:00.000000Z', next_at = '2100-01-01T00:00:00.000000Z'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    let before = n(&sums, "dropped");
    picket_core::dnssec::turn(&s.c.state).await.unwrap();
    assert_eq!(s.sql::<i64>("SELECT count(*) FROM dnssec_queue").await, 0);
    queued_until(&mut events, &mut sums, |m| n(m, "dropped") > before).await;
}

/// K5 (api.md §7, core.md §8 "items that need a request wait"): while no edge DoH listener is
/// reachable, each reschedule of a due item moves its `next_at` 30 s on, which `GET dnssec/queue`
/// shows (and orders by), so each sends `dnssec_queued` (`waiting`); a turn with nothing due
/// moves nothing and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiting_reschedule_moves_next_at_in_the_queue_view() {
    let s = Setup::new(None).await;
    let mut events = s.c.state.events.subscribe();
    let mut sums = BTreeMap::new();
    let n = |m: &BTreeMap<String, u64>, k: &str| m.get(k).copied().unwrap_or(0);
    s.world
        .unreachable
        .store(true, std::sync::atomic::Ordering::Relaxed);
    s.post(vec![s.q(
        "www.test",
        "A",
        "NOERROR",
        "allow",
        None,
        &["192.0.2.1"],
        json!({"truncated": true}),
    )])
    .await;
    s.run().await;
    queued_until(&mut events, &mut sums, |m| n(m, "waiting") >= 1).await;
    let next_at = || async {
        let (st, q) = common::bundles::get(&s.c, "/dnssec/queue").await;
        assert_eq!(st, 200, "{q}");
        assert_eq!(q["items"].as_array().unwrap().len(), 1, "{q}");
        assert_eq!(q["items"][0]["attempts"], 0, "waiting uses no attempt: {q}");
        q["items"][0]["next_at"].as_str().unwrap().to_string()
    };
    let first = next_at().await;
    // Not due yet: a turn moves nothing.
    picket_core::dnssec::turn(&s.c.state).await.unwrap();
    assert_eq!(next_at().await, first);
    // Due again and still unreachable: it waits again, its `next_at` moves on, and the view
    // changes with it.
    due_now(&s, "dnssec_queue").await;
    let due = next_at().await;
    picket_core::dnssec::turn(&s.c.state).await.unwrap();
    let again = next_at().await;
    assert!(again > due && again != first, "{due} → {again} (first {first})");
    queued_until(&mut events, &mut sums, |m| n(m, "waiting") >= 2).await;
    assert_eq!(n(&sums, "waiting"), 2, "{sums:?}");
}
