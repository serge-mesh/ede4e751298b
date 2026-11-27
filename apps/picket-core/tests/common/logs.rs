//! The logs-analysis fixture (core.md §6, §9): a core with manual feeds in a block bundle and a
//! trial bundle, profiles that enforce or trial them, and a registered edge whose published config
//! the records name; records go in through `POST /v1/logs`. The background analysis is paused, so
//! each test runs the analysis itself ([`picket_core::logs::analysis::drain`]).

use std::time::Duration;

use base64::Engine;
use jiff::Timestamp;
use serde_json::{Value, json};

use crate::common::bundles::{build, manual_feed, put_entity, save, wait};
use crate::common::edge::FakeEdge;

pub struct Setup {
    pub c: crate::common::Core,
    pub edge: FakeEdge,
    pub config: String,
    pub b1: String,
}

pub fn ts(t: Timestamp) -> String {
    picket_api::time::format_micros(&t)
}

pub fn short(id: &str) -> String {
    id.chars().take(16).collect()
}

impl Setup {
    pub async fn new(settings: Option<Value>) -> Setup {
        let mut patch = json!({"web": {"tls": "off"}});
        if let (Some(p), Some(extra)) = (
            patch.as_object_mut(),
            settings.as_ref().and_then(Value::as_object),
        ) {
            p.extend(extra.clone());
        }
        let c = crate::common::start_core(Some(patch)).await;
        c.state.analysis.set_paused(true);
        manual_feed(&c, "f-sec", json!({"category": "security"})).await;
        manual_feed(&c, "f-priv", json!({"category": "privacy"})).await;
        manual_feed(&c, "f-trial", json!({"category": "security"})).await;
        save(
            &c,
            "f-sec",
            "||ads.example^\n||tracker.example^\n||198.51.100.7^\n",
        )
        .await;
        save(
            &c,
            "f-priv",
            "||ads.example^\n||tracker.example^$badfilter\n|tracker.example^\n",
        )
        .await;
        save(
            &c,
            "f-trial",
            "||trial.example^\n@@||ok.trial.example^\n||203.0.113.9^\n",
        )
        .await;
        put_entity(
            &c,
            "bundles",
            "b1",
            json!({"id": "b1", "name": "b1", "feeds": [{"feed": "f-sec"}, {"feed": "f-priv"}]}),
        )
        .await;
        put_entity(
            &c,
            "bundles",
            "trial-b",
            json!({"id": "trial-b", "name": "trial-b", "feeds": [{"feed": "f-trial"}]}),
        )
        .await;
        let b1 = build(&c, "b1").await.expect("b1 head");
        build(&c, "trial-b").await.expect("trial head");
        put_entity(
            &c,
            "profiles",
            "p1",
            json!({"id": "p1", "name": "p1", "block": ["b1"], "trial_bundles": ["trial-b"],
                   "ttl": {"min": 30, "max": 120}}),
        )
        .await;
        put_entity(
            &c,
            "profiles",
            "p2",
            json!({"id": "p2", "name": "p2", "trial_bundles": ["b1"]}),
        )
        .await;
        let edge = FakeEdge::registered(&c, "e1").await;
        c.state.edges.publisher.render(&c.state, None).await.unwrap();
        let mut config = String::new();
        wait("the edge's config naming b1", || {
            let cur = c.state.edges.publisher.current(&edge.id);
            if let Some(p) = &cur {
                config = p.id.clone();
            }
            let ok = cur.is_some();
            async move { ok }
        })
        .await;
        let s = Setup { c, edge, config, b1 };
        // The published config holds the profiles and b1, never the trial bundle.
        let body: Value = s
            .scalar_core::<String>(&format!(
                "SELECT body_json FROM edge_configs WHERE config_id = '{}'",
                s.config
            ))
            .await
            .parse::<Value>()
            .unwrap();
        assert_eq!(body["profiles"]["p1"]["block"], json!(["b1"]));
        assert!(body["bundles"].get("b1").is_some(), "{body}");
        assert!(
            body["bundles"].get("trial-b").is_none(),
            "a trial bundle never reaches an edge"
        );
        assert!(body["profiles"]["p1"].get("trial_bundles").is_none());
        s
    }

    pub fn versions(&self) -> Value {
        json!({"config": short(&self.config), "bundles": {"b1": short(&self.b1)}})
    }

    /// A `q` record.
    pub fn q(
        &self,
        boot: &str,
        seq: u64,
        at: Timestamp,
        qname: &str,
        decision: &str,
        reason: Value,
    ) -> Value {
        json!({"t": "q", "ts": ts(at), "boot": boot, "seq": seq, "listener": "lan-dns", "proto": "udp",
               "client": "192.0.2.10", "device": "tablet", "profile": "p1", "qname": qname, "qtype": "A",
               "do": false, "rcode": "NOERROR", "decision": decision,
               "reason": reason, "answers": [], "targets": [], "truncated": false, "cname": [], "lookups": [],
               "upstream": null, "fw": null, "us": {"total": 41, "filter": 6}, "versions": self.versions()})
    }

    pub fn block(&self, boot: &str, seq: u64, at: Timestamp, qname: &str, key: &str) -> Value {
        self.q(
            boot,
            seq,
            at,
            qname,
            "block",
            json!({"step": 3, "bundle": "b1", "key": key, "kind": "subs", "stage": "query"}),
        )
    }

    pub async fn post(&self, lines: Vec<Value>) {
        let r = self.edge.post_logs(&lines).await;
        let st = r.status();
        assert_eq!(st, 200, "{}", r.text().await.unwrap());
    }

    /// Leaves `bundle` (just defined, its feeds never run) with no head and no build racing the
    /// test: core builds a new bundle in the background, an empty feed's too, and that head can
    /// land before or after the test's first analysis. Waits for that build, then takes its head
    /// away.
    pub async fn without_head(&self, bundle: &str) {
        crate::common::bundles::settle(&self.c, bundle).await;
        let b = bundle.to_string();
        self.c
            .state
            .db
            .write(move |c| {
                c.execute(
                    "UPDATE bundle_builds SET head_id = NULL WHERE bundle_id = ?1",
                    [b],
                )?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap();
    }

    pub async fn drain(&self) -> usize {
        picket_core::logs::analysis::drain(&self.c.state).await.unwrap()
    }

    pub async fn scalar_core<T: rusqlite::types::FromSql + Send + 'static>(&self, sql: &str) -> T {
        let sql = sql.to_string();
        self.c
            .state
            .db
            .read(move |db| Ok::<_, anyhow::Error>(db.query_row(&sql, [], |r| r.get::<_, T>(0))?))
            .await
            .unwrap()
    }

    /// One value from the partition of `at`.
    pub fn part<T: rusqlite::types::FromSql>(&self, at: Timestamp, sql: &str) -> T {
        let p = self
            .c
            .dir
            .path()
            .join("logs")
            .join(picket_core::logs::partition::partition_file_name(&at));
        let conn = rusqlite::Connection::open(p).unwrap();
        conn.query_row(sql, [], |r| r.get::<_, T>(0)).unwrap()
    }

    pub async fn metric_total(&self, name: &str, label: &str) -> f64 {
        let (n, l) = (name.to_string(), label.to_string());
        self.c
            .state
            .metrics_db
            .read(move |db| {
                Ok::<_, anyhow::Error>(db.query_row(
                    "SELECT coalesce(sum(p.value), 0) FROM points p JOIN series s ON s.id = p.series_id
                     WHERE s.name = ?1 AND s.labels_json LIKE '%' || ?2 || '%'",
                    rusqlite::params![n, l],
                    |r| r.get::<_, f64>(0),
                )?)
            })
            .await
            .unwrap()
    }

    pub async fn alert(&self, key: &str) -> Option<Value> {
        let a = self.c.state.alerts.get_by_key(key).await.unwrap()?;
        Some(serde_json::to_value(a).unwrap())
    }
}

pub async fn run_retention(c: &crate::common::Core) {
    let before = c.state.scheduler.heavy.stats().completed;
    c.state.scheduler.heavy.submit(
        picket_core::scheduler::Priority::P3,
        Box::new(picket_core::retention::RetentionJob::new(c.state.clone(), false)),
    );
    for _ in 0..1000 {
        let st = c.state.scheduler.heavy.stats();
        if st.completed > before && st.queued == 0 && st.running.is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the retention job never finished");
}

pub fn answer_wire(qname: &str, chain: &[&str], addrs: &[[u8; 4]]) -> Vec<u8> {
    pub fn name(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in n.split('.').filter(|l| !l.is_empty()) {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }
    let count = chain.len() + addrs.len();
    let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, count as u8, 0, 0, 0, 0];
    m.extend(name(qname));
    m.extend_from_slice(&[0, 1, 0, 1]);
    let mut owner = qname.to_string();
    for c in chain {
        m.extend(name(&owner));
        m.extend_from_slice(&[0, 5, 0, 1, 0, 0, 1, 0]);
        let t = name(c);
        m.extend_from_slice(&(t.len() as u16).to_be_bytes());
        m.extend(t);
        owner = c.to_string();
    }
    for a in addrs {
        m.extend(name(&owner));
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 1, 0, 0, 4]);
        m.extend_from_slice(a);
    }
    m
}

pub fn answer_record(boot: &str, seq: u64, at: Timestamp, wire: &[u8]) -> (String, Value) {
    let id: String = blake3::hash(wire).to_hex().chars().take(16).collect();
    let rec = json!({"t": "answer", "ts": ts(at), "boot": boot, "seq": seq, "id": id,
                     "wire": base64::engine::general_purpose::STANDARD.encode(wire)});
    (id, rec)
}
