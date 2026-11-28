//! The Prometheus export (api.md §7; build-and-test.md §5 Metrics: "`/metrics` read by a
//! Prometheus text parser, and off while `metrics.allow_cidrs` is empty"): every series core
//! records or receives (`metrics::HEARTBEAT_SERIES`, `metrics::CORE_SERIES`, and the export's own
//! `export_only`, bundle statistics included) appears in `/metrics` under its name, type and
//! labels. A series added to either list, or a heartbeat field added to picket-api, without being
//! exported fails here.

use crate::common;

use std::collections::{BTreeMap, BTreeSet};

use common::edge::{FakeEdge, eventually, hello, send};
use common::prom::{self, LabelSet};
use jiff::Timestamp;
use picket_core::config::model::EntityKind;
use picket_core::config::{Actor, Op};
use picket_core::metrics::export::{BUNDLE_PUBLISHED, BUNDLE_STATS, export_only};
use picket_core::metrics::{CORE_SERIES, HEARTBEAT_SERIES, Kind, Series};
use prometheus_scraper::owned::MetricType;
use reqwest::StatusCode;
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

/// A serializer that builds the JSON value of what it serialises, as serde_json does, and marks
/// every field a struct leaves out (`skip_serializing_if`) as [`probe::SKIPPED`]: a map the test
/// heartbeat leaves empty can't hide, whether it serialises as `{}` or not at all.
mod probe {
    use serde::Serialize;
    use serde::ser;
    use serde_json::{Map, Value};

    pub const SKIPPED: &str = "<skipped>";
    type E = serde_json::Error;

    pub fn to_value<T: Serialize>(v: &T) -> Value {
        v.serialize(Probe).unwrap()
    }

    struct Probe;

    macro_rules! leaf {
        ($($f:ident: $t:ty),*) => {
            $(fn $f(self, v: $t) -> Result<Value, E> {
                serde_json::value::Serializer.$f(v)
            })*
        };
    }

    impl ser::Serializer for Probe {
        type Ok = Value;
        type Error = E;
        type SerializeSeq = Seq;
        type SerializeTuple = Seq;
        type SerializeTupleStruct = Seq;
        type SerializeTupleVariant = Seq;
        type SerializeMap = MapOf;
        type SerializeStruct = Struct;
        type SerializeStructVariant = Struct;
        leaf!(serialize_bool: bool, serialize_i8: i8, serialize_i16: i16, serialize_i32: i32,
              serialize_i64: i64, serialize_u8: u8, serialize_u16: u16, serialize_u32: u32,
              serialize_u64: u64, serialize_f32: f32, serialize_f64: f64, serialize_char: char,
              serialize_str: &str, serialize_bytes: &[u8]);
        fn serialize_none(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn serialize_some<T: ?Sized + Serialize>(self, v: &T) -> Result<Value, E> {
            v.serialize(Probe)
        }
        fn serialize_unit(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn serialize_unit_struct(self, _: &'static str) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn serialize_unit_variant(self, _: &'static str, _: u32, v: &'static str) -> Result<Value, E> {
            Ok(Value::String(v.into()))
        }
        fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, v: &T) -> Result<Value, E> {
            v.serialize(Probe)
        }
        fn serialize_newtype_variant<T: ?Sized + Serialize>(
            self,
            _: &'static str,
            _: u32,
            k: &'static str,
            v: &T,
        ) -> Result<Value, E> {
            Ok(Value::Object(Map::from_iter([(
                k.to_string(),
                v.serialize(Probe)?,
            )])))
        }
        fn serialize_seq(self, _: Option<usize>) -> Result<Seq, E> {
            Ok(Seq(Vec::new()))
        }
        fn serialize_tuple(self, _: usize) -> Result<Seq, E> {
            Ok(Seq(Vec::new()))
        }
        fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Seq, E> {
            Ok(Seq(Vec::new()))
        }
        fn serialize_tuple_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Seq, E> {
            Ok(Seq(Vec::new()))
        }
        fn serialize_map(self, _: Option<usize>) -> Result<MapOf, E> {
            Ok(MapOf(Map::new(), None))
        }
        fn serialize_struct(self, _: &'static str, _: usize) -> Result<Struct, E> {
            Ok(Struct(Map::new()))
        }
        fn serialize_struct_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Struct, E> {
            Ok(Struct(Map::new()))
        }
    }

    struct Seq(Vec<Value>);

    impl Seq {
        fn push<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), E> {
            self.0.push(v.serialize(Probe)?);
            Ok(())
        }
    }

    impl ser::SerializeSeq for Seq {
        type Ok = Value;
        type Error = E;
        fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), E> {
            self.push(v)
        }
        fn end(self) -> Result<Value, E> {
            Ok(Value::Array(self.0))
        }
    }

    impl ser::SerializeTuple for Seq {
        type Ok = Value;
        type Error = E;
        fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), E> {
            self.push(v)
        }
        fn end(self) -> Result<Value, E> {
            Ok(Value::Array(self.0))
        }
    }

    impl ser::SerializeTupleStruct for Seq {
        type Ok = Value;
        type Error = E;
        fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), E> {
            self.push(v)
        }
        fn end(self) -> Result<Value, E> {
            Ok(Value::Array(self.0))
        }
    }

    impl ser::SerializeTupleVariant for Seq {
        type Ok = Value;
        type Error = E;
        fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), E> {
            self.push(v)
        }
        fn end(self) -> Result<Value, E> {
            Ok(Value::Array(self.0))
        }
    }

    struct MapOf(Map<String, Value>, Option<String>);

    impl ser::SerializeMap for MapOf {
        type Ok = Value;
        type Error = E;
        fn serialize_key<T: ?Sized + Serialize>(&mut self, k: &T) -> Result<(), E> {
            self.1 = Some(match k.serialize(Probe)? {
                Value::String(s) => s,
                other => other.to_string(),
            });
            Ok(())
        }
        fn serialize_value<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), E> {
            let k = self.1.take().unwrap_or_default();
            self.0.insert(k, v.serialize(Probe)?);
            Ok(())
        }
        fn end(self) -> Result<Value, E> {
            Ok(Value::Object(self.0))
        }
    }

    struct Struct(Map<String, Value>);

    impl ser::SerializeStruct for Struct {
        type Ok = Value;
        type Error = E;
        fn serialize_field<T: ?Sized + Serialize>(&mut self, k: &'static str, v: &T) -> Result<(), E> {
            self.0.insert(k.into(), v.serialize(Probe)?);
            Ok(())
        }
        fn skip_field(&mut self, k: &'static str) -> Result<(), E> {
            self.0.insert(k.into(), Value::String(SKIPPED.into()));
            Ok(())
        }
        fn end(self) -> Result<Value, E> {
            Ok(Value::Object(self.0))
        }
    }

    impl ser::SerializeStructVariant for Struct {
        type Ok = Value;
        type Error = E;
        fn serialize_field<T: ?Sized + Serialize>(&mut self, k: &'static str, v: &T) -> Result<(), E> {
            ser::SerializeStruct::serialize_field(self, k, v)
        }
        fn skip_field(&mut self, k: &'static str) -> Result<(), E> {
            ser::SerializeStruct::skip_field(self, k)
        }
        fn end(self) -> Result<Value, E> {
            Ok(Value::Object(self.0))
        }
    }
}

/// The key of every map in the test heartbeat (upstream, provider, bundle and reason).
const KEY: &str = "k-1";

/// A heartbeat with every field api.md §3 names set and each map holding [`KEY`].
fn full_heartbeat(ts: Timestamp) -> Value {
    let mut h = picket_api::Histogram::default();
    h.record(1_500, 1_500);
    h.record(70_000, 70_000);
    let hist = serde_json::to_value(&h).unwrap();
    let mut n = 0u64;
    let mut next = || {
        n += 1;
        n
    };
    json!({
        "ts": picket_api::time::format_micros(&ts), "boot": "b1", "up_ms": 60_000,
        "metrics": {
            "queries": next(),
            "by_decision": {"allow": next(), "block": next(), "rewrite": next(), "refused": next(), "servfail": next()},
            "rejected": next(), "refused": next(), "cache_hits": next(), "cache_misses": next(),
            "stale_served": next(), "latency_us": hist, "panics": next(), "fw_ack_late": next(),
            "upstream": {KEY: {"queries": next(), "hedges": next(), "rtt_ms": hist, "errors": next(),
                               "invalid": {KEY: next()}, "scrubbed": {KEY: next()}}},
            "lookups": {KEY: {"calls": next(), "call_ms": hist, "timeouts": next(), "late": next(),
                              "errors": next(), "rejected": next(), "breaker_open": 1, "paused": next(),
                              "cache_hits": next(), "set_hits": next(), "cache_misses": next(),
                              "evictions": next(), "entries": next(), "bytes": next()}},
            "cold": {KEY: {"blocks": next(), "unchecked": next(), "page_reads": next()}}
        },
        "spool": {"bytes": next(), "oldest_ts": picket_api::time::format_micros(&(ts - jiff::SignedDuration::from_mins(5)))},
        "logs": {"dropped": {KEY: next()}},
        "rss": next(), "mem_available": next(),
        "cpu_ms": {"edge": next(), "helper": next()},
        "cgroup_mem": {"unit": next(), "helper_rss": next()},
        "disk": {"data_dir": {"used": next(), "free": next()}, "ssd_dir": {"used": next(), "free": next()}},
        "fw": {"entries": next(), "max": next(), "rejects": next(), "mon_rejects": next()},
        "have": {}, "conditions": [], "applied": {}
    })
}

/// Heartbeat fields that aren't metrics (api.md §3).
const NOT_METRICS: &[&str] = &[
    "ts",
    "boot",
    "up_ms",
    "versions",
    "ready_version",
    "have",
    "conditions",
    "applied",
    "update",
    "cert_roots",
];

/// The series names a heartbeat's fields make: leaf paths with map keys taken out and `metrics.`
/// dropped, a histogram (an object with `buckets`) as one leaf, null (an optional value) too.
fn heartbeat_paths(v: &Value, path: &mut Vec<String>, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) if !m.contains_key("buckets") => {
            for (k, v) in m {
                if path.is_empty() && NOT_METRICS.contains(&k.as_str()) {
                    continue;
                }
                let key = k != KEY;
                if key {
                    path.push(k.clone());
                }
                heartbeat_paths(v, path, out);
                if key {
                    path.pop();
                }
            }
        }
        _ => {
            let p: Vec<&str> = path
                .iter()
                .map(String::as_str)
                .skip_while(|s| *s == "metrics")
                .collect();
            out.insert(p.join("."));
        }
    }
}

/// The metric fields the test heartbeat leaves without a value: maps left empty (`{}`) and fields
/// a struct leaves out ([`probe::SKIPPED`], `skip_serializing_if`), by path.
fn unfilled(v: &Value, path: &str, out: &mut Vec<String>) {
    let Value::Object(m) = v else { return };
    if m.is_empty() {
        out.push(path.to_string());
    }
    for (k, v) in m {
        if path.is_empty() && NOT_METRICS.contains(&k.as_str()) {
            continue;
        }
        let p = if path.is_empty() {
            k.clone()
        } else {
            format!("{path}.{k}")
        };
        if v == probe::SKIPPED {
            out.push(p);
        } else {
            unfilled(v, &p, out);
        }
    }
}

fn unfilled_of(hb: &Value) -> Vec<String> {
    let hb: picket_api::session::Heartbeat = serde_json::from_value(hb.clone()).unwrap();
    let mut out = Vec::new();
    unfilled(&probe::to_value(&hb), "", &mut out);
    out
}

#[test]
fn the_test_heartbeat_fills_every_map() {
    // Every map of picket-api's heartbeat holds KEY in the test heartbeat, so a field added there
    // (a map included) shows up below and must be registered, exported and charted.
    let full = full_heartbeat(Timestamp::now());
    assert_eq!(unfilled_of(&full), Vec::<String>::new());
    // A map left empty is named, also one skipped when empty, which serde_json leaves out.
    let mut hb = full.clone();
    hb["metrics"]["upstream"][KEY]
        .as_object_mut()
        .unwrap()
        .remove("scrubbed");
    hb["logs"]["dropped"] = json!({});
    assert_eq!(
        unfilled_of(&hb),
        [
            "logs.dropped".to_string(),
            format!("metrics.upstream.{KEY}.scrubbed")
        ]
    );
    let parsed: picket_api::session::Heartbeat = serde_json::from_value(hb).unwrap();
    assert!(
        serde_json::to_value(&parsed).unwrap()["metrics"]["upstream"][KEY]
            .get("scrubbed")
            .is_none()
    );
}

#[test]
fn every_heartbeat_field_is_a_registered_series() {
    // Through picket-api's types: a field added there shows up in the re-serialised heartbeat
    // (numbers as 0, optional values as null) and must be registered, exported and charted.
    let hb: picket_api::session::Heartbeat =
        serde_json::from_value(full_heartbeat(Timestamp::now())).unwrap();
    let mut paths = BTreeSet::new();
    heartbeat_paths(&probe::to_value(&hb), &mut Vec::new(), &mut paths);
    let registered: BTreeSet<String> = HEARTBEAT_SERIES.iter().map(|s| s.name.to_string()).collect();
    assert_eq!(paths, registered);
    // And core's flattening yields each one, with the registry's labels.
    let flat = picket_core::metrics::store::flatten("e-1", &hb);
    let got: BTreeMap<String, BTreeSet<String>> = flat
        .iter()
        .map(|(n, l, _)| (n.clone(), l.keys().cloned().collect()))
        .collect();
    for s in HEARTBEAT_SERIES {
        let want: BTreeSet<String> = s.labels.iter().map(|l| l.to_string()).collect();
        assert_eq!(got.get(s.name), Some(&want), "{}", s.name);
    }
    assert_eq!(got.len(), HEARTBEAT_SERIES.len());
}

/// The family a series is exported as (api.md §7): `picket_` plus the name (or the export name
/// the registry gives it) with `_` for `.`, counters ending in `_total`.
fn family_of(s: &Series) -> (String, MetricType) {
    let base = format!("picket_{}", s.export.unwrap_or(s.name).replace('.', "_"));
    match s.kind {
        Kind::Counter | Kind::CoreCounter => (format!("{base}_total"), MetricType::Counter),
        Kind::Gauge | Kind::CoreGauge => (base, MetricType::Gauge),
        Kind::Histogram | Kind::CoreHistogram => (base, MetricType::Histogram),
    }
}

fn all() -> impl Iterator<Item = Series> {
    HEARTBEAT_SERIES
        .iter()
        .chain(CORE_SERIES)
        .copied()
        .chain(export_only())
}

#[test]
fn every_series_has_its_own_names() {
    // No two series share a family, nor a family a histogram's or counter's sample name; `_total`
    // ends only counters (Prometheus's naming rule).
    let mut names = BTreeSet::new();
    for s in all() {
        let (f, t) = family_of(&s);
        assert!(
            t == MetricType::Counter || !f.ends_with("_total"),
            "{} is no counter: no _total",
            s.name
        );
        let samples = match t {
            MetricType::Histogram => vec![format!("{f}_bucket"), format!("{f}_sum"), format!("{f}_count"), f],
            _ => vec![f],
        };
        for n in samples {
            assert!(names.insert(n.clone()), "{n} ({}) is taken", s.name);
        }
    }
}

#[test]
fn a_sample_twice_is_refused() {
    // The parser keeps one of two samples with the same labels: the helper reads the raw text.
    let twice = |a: &str, b: &str| {
        format!(
            "# TYPE picket_jobs_dropped_total counter\npicket_jobs_dropped_total{{{a}}} 1\npicket_jobs_dropped_total{{{b}}} 2\n"
        )
    };
    let refused = |text: String| std::panic::catch_unwind(move || prom::parse(&text)).is_err();
    assert!(refused(twice(r#"lane="light""#, r#"lane="light""#)));
    assert!(
        refused(twice(r#"a="1",b="2""#, r#"b="2",a="1""#)),
        "labels in another order"
    );
    assert!(refused(
        "# TYPE picket_up gauge\npicket_up 1\npicket_up 1\n".into()
    ));
    let h = "# TYPE picket_job_ms histogram\npicket_job_ms_bucket{kind=\"a\",le=\"+Inf\"} 1\npicket_job_ms_bucket{kind=\"a\",le=\"+Inf\"} 1\npicket_job_ms_sum{kind=\"a\"} 1\npicket_job_ms_count{kind=\"a\"} 1\n";
    assert!(refused(h.into()), "a bucket twice");
    let ok = prom::parse(&twice(r#"lane="light""#, r#"lane="heavy""#));
    assert_eq!(
        ok.value("picket_jobs_dropped_total", &[("lane", "heavy")]),
        Some(2.0)
    );
}

/// Ids of entities that exist (core prunes series of deleted ones): a lookup provider the test
/// creates, and a feed, bundle and profile core starts with.
struct Ids {
    provider: String,
    feed: String,
    bundle: String,
    profile: String,
}

fn http_provider(id: &str) -> Value {
    json!({"id": id, "name": id, "module": "http_json",
           "config": {"url": "https://lookup.invalid/{domain}", "verdict": {"pointer": "/risk", "block_if": ">= 7"}},
           "recheck": {"enabled": false}})
}

async fn ids(c: &common::Core) -> Ids {
    c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Create(http_provider("q9")),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    let m = c.state.config.model().await.unwrap();
    let first = |k: Vec<&String>| k.first().map(|s| s.to_string()).expect("an entity");
    Ids {
        provider: "q9".into(),
        feed: first(m.feeds.keys().collect()),
        bundle: first(m.bundles.keys().collect()),
        profile: first(m.profiles.keys().collect()),
    }
}

/// The labels the test records a core series with: an entity's id for `provider`, `feed`,
/// `bundle` and `profile`, the registered fake edge for `edge`, else `v-<key>`.
fn core_labels(s: &Series, edge: &str, ids: &Ids) -> LabelSet {
    s.labels
        .iter()
        .map(|k| {
            let v = match *k {
                "edge" => edge.to_string(),
                "provider" => ids.provider.clone(),
                "feed" => ids.feed.clone(),
                "bundle" => ids.bundle.clone(),
                "profile" => ids.profile.clone(),
                k => format!("v-{k}"),
            };
            (k.to_string(), v)
        })
        .collect()
}

/// A bundle's current version (`bundle_builds.head_id`): its id, publish time and statistics.
async fn current_bundle(c: &common::Core) -> Option<(String, String, Value)> {
    c.state
        .db
        .read(|conn| {
            Ok::<_, anyhow::Error>(
                conn.query_row(
                    "SELECT v.bundle_id, v.published_at, v.stats_json FROM bundle_builds b
                     JOIN bundle_versions v ON v.bundle_id = b.bundle_id AND v.head_id = b.head_id
                     WHERE v.stats_json IS NOT NULL ORDER BY v.bundle_id LIMIT 1",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?,
            )
        })
        .await
        .unwrap()
        .map(|(b, p, s)| (b, p, serde_json::from_str(&s).unwrap()))
}

async fn wait_current_bundle(c: &common::Core) -> (String, String, Value) {
    for _ in 0..1200 {
        if let Some(b) = current_bundle(c).await {
            return b;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no bundle got a version");
}

async fn scrape(c: &common::Core) -> (String, prom::Scrape) {
    let r = common::client()
        .get(format!("{}/metrics", c.base("http")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let text = r.text().await.unwrap();
    let s = prom::parse(&text);
    (text, s)
}

fn exporting() -> Option<Value> {
    Some(json!({"web": {"tls": "off"}, "metrics": {"allow_cidrs": ["127.0.0.0/8", "::1/128"]}}))
}

#[tokio::test(flavor = "multi_thread")]
async fn each_bundles_current_version_statistics_are_exported() {
    // core.md §10 "Per bundle": the statistics stored with the version the bundle serves now.
    let c = common::start_core(exporting()).await;
    let (bundle, published, stats) = wait_current_bundle(&c).await;
    let (_, s) = scrape(&c).await;
    for (series, key) in BUNDLE_STATS {
        assert_eq!(
            s.value(&format!("picket_{series}"), &[("bundle", &bundle)]),
            Some(stats[key].as_f64().unwrap_or(0.0)),
            "{series} ({key}) of {bundle}: {stats}"
        );
        assert_eq!(s.kind(&format!("picket_{series}")), Some(MetricType::Gauge));
    }
    let ts = picket_api::time::parse(&published).unwrap().as_second() as f64;
    assert_eq!(
        s.value(&format!("picket_{BUNDLE_PUBLISHED}"), &[("bundle", &bundle)]),
        Some(ts)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleted_providers_and_feeds_leave_the_export() {
    // A deleted lookup provider's breaker, pause, queue and verdict set, its call totals and a
    // deleted feed's series aren't reported forever (outside alerts would keep firing).
    let c = common::start_core(exporting()).await;
    c.state
        .config
        .apply(
            EntityKind::LookupProvider,
            Op::Create(http_provider("gone")),
            Actor::cli(),
            None,
        )
        .await
        .unwrap();
    common::feeds::create_feed(
        &c,
        json!({"id": "gone-feed", "name": "Gone", "provider": "manual", "format": "plain"}),
    )
    .await;
    let (st, db) = (&c.state, &c.state.metrics_db);
    let p = || picket_core::metrics::labels("", &[("provider", "gone")]);
    let f = |extra: (&str, &str)| picket_core::metrics::labels("", &[("feed", "gone-feed"), extra]);
    let now = Timestamp::now().as_millisecond();
    let mut h = picket_api::Histogram::default();
    h.record(20_000, 20);
    let gauges: Vec<(String, LabelSet, f64)> = [
        "lookup_breaker_open",
        "lookup_paused",
        "lookup_queue",
        "verdict_set_records",
        "verdict_set_overlay_bytes",
    ]
    .map(|n| (n.to_string(), p(), 1.0))
    .into_iter()
    .chain([("feed_records_total".to_string(), f(("type", "dns")), 4.0)])
    .collect();
    st.metrics.gauges(db, gauges).await;
    st.metrics
        .count(
            db,
            vec![
                ("lookup_calls".into(), p(), now, 1.0),
                ("feed_hits".into(), f(("role", "decisive")), now, 1.0),
            ],
        )
        .await;
    st.metrics
        .histograms(db, vec![("lookup_call_ms".into(), p(), now, h)])
        .await;
    let named = |text: &str| text.contains(r#"provider="gone""#) || text.contains(r#"feed="gone-feed""#);
    let (text, _) = scrape(&c).await;
    assert!(named(&text), "{text}");
    for (kind, id) in [
        (EntityKind::LookupProvider, "gone"),
        (EntityKind::Feed, "gone-feed"),
    ] {
        c.state
            .config
            .apply(kind, Op::Delete(id.into()), Actor::cli(), None)
            .await
            .unwrap();
    }
    assert!(
        eventually(|| async { !named(&scrape(&c).await.0) }).await,
        "{}",
        scrape(&c).await.0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_is_off_without_allow_cidrs() {
    let c = common::start_core(Some(json!({"web": {"tls": "off"}}))).await;
    let r = common::client()
        .get(format!("{}/metrics", c.base("http")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_series_is_exported_with_its_type_and_labels() {
    let c = common::start_core(exporting()).await;
    let ids = ids(&c).await;
    let edge = FakeEdge::registered(&c, "edge-a").await;
    // A bundle with a version, for the bundle statistics.
    wait_current_bundle(&c).await;
    // An edge's last heartbeat, through its session.
    let (mut ws, _) = edge.session(hello("b1")).await;
    send(
        &mut ws,
        json!({"type": "heartbeat", "data": full_heartbeat(Timestamp::now())}),
    )
    .await;
    // One value of every core series, recorded as core records it (core.md §10).
    let (st, db) = (&c.state, &c.state.metrics_db);
    let now = Timestamp::now().as_millisecond();
    let mut h = picket_api::Histogram::default();
    h.record(20_000, 20);
    for s in CORE_SERIES {
        let l = core_labels(s, &edge.id, &ids);
        let name = s.name.to_string();
        match s.kind {
            Kind::CoreCounter => st.metrics.count(db, vec![(name, l, now, 2.0)]).await,
            Kind::CoreGauge => st.metrics.gauges(db, vec![(name, l, 3.0)]).await,
            // Job durations are totalled as jobs end (metrics::resources::JobTimes).
            Kind::CoreHistogram if s.name == "job_ms" => st.metrics.jobs.record(&l["kind"], 20),
            Kind::CoreHistogram => st.metrics.histograms(db, vec![(name, l, now, h.clone())]).await,
            k => panic!("{}: a core series of heartbeat kind {k:?}", s.name),
        }
    }
    let url = format!("{}/metrics", c.base("http"));
    let fetch = || async {
        let r = common::client().get(&url).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        r.text().await.unwrap()
    };
    let probe = format!("picket_fw_mon_rejects_total{{edge=\"{}\"}}", edge.id);
    assert!(
        eventually(|| async { fetch().await.contains(&probe) }).await,
        "the heartbeat never reached the export"
    );
    let text = fetch().await;
    let scrape = prom::parse(&text);

    for s in all() {
        let (family, kind) = family_of(&s);
        let f = scrape.family(&family);
        assert_eq!(f.r#type, kind, "{} as {family}", s.name);
        let want_keys: BTreeSet<&str> = s.labels.iter().copied().collect();
        let sets: Vec<LabelSet> = f.metric.iter().map(prom::labels).collect();
        assert!(
            sets.iter()
                .all(|l| l.keys().map(String::as_str).collect::<BTreeSet<_>>() == want_keys),
            "{family}: labels {sets:?}, want keys {want_keys:?}"
        );
        // The values recorded above, under their labels.
        let is_heartbeat = HEARTBEAT_SERIES.contains(&s);
        let want: LabelSet = if is_heartbeat {
            s.labels
                .iter()
                .map(|k| {
                    let v = if *k == "edge" {
                        edge.id.clone()
                    } else {
                        KEY.to_string()
                    };
                    (k.to_string(), v)
                })
                .collect()
        } else if CORE_SERIES.contains(&s) {
            core_labels(&s, &edge.id, &ids)
        } else {
            continue;
        };
        assert!(sets.contains(&want), "{family}: no {want:?} in {sets:?}");
        let pairs: Vec<(&str, &str)> = want.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        match (s.kind, is_heartbeat) {
            (Kind::Histogram | Kind::CoreHistogram, _) => {
                let got = scrape.histogram(&family, &pairs).unwrap();
                assert!(got.count >= 1, "{family}: {got:?}");
            }
            (Kind::CoreCounter, false) => assert_eq!(scrape.value(&family, &pairs), Some(2.0), "{family}"),
            (Kind::CoreGauge, false) => assert_eq!(scrape.value(&family, &pairs), Some(3.0), "{family}"),
            _ => assert!(scrape.value(&family, &pairs).unwrap() > 0.0, "{family}"),
        }
    }
    // Units: `_ms` histograms have `le` in milliseconds, others in microseconds (api.md §7). A
    // value counts first in the bucket of the layout's first bound at or above it.
    let bound = |us: u64| picket_api::histogram::BOUNDS_US[picket_api::histogram::bucket_index(us)] as f64;
    let first = |h: &prom::Hist| h.buckets.iter().find(|b| b.1 > 0).map(|b| b.0);
    let ms = scrape
        .histogram("picket_lookup_call_ms", &[("provider", "q9")])
        .unwrap();
    assert_eq!(first(&ms), Some(bound(20_000) / 1000.0), "{ms:?}");
    assert_eq!((ms.count, ms.sum), (1, 20.0));
    let us = scrape
        .histogram("picket_latency_us", &[("edge", &edge.id)])
        .unwrap();
    assert_eq!(first(&us), Some(bound(1_500)), "{us:?}");
    assert_eq!((us.count, us.sum), (2, 71_500.0));
    assert_eq!(
        us.buckets.len(),
        picket_api::histogram::BUCKETS,
        "every bound and +Inf"
    );
    // The lanes' depths are read now, once per lane, never also as their last sample. The light
    // lane counts running jobs too, and q9's first self-test (against lookup.invalid) can still
    // be running at a scrape, so wait for one that sees the lane idle.
    let light = |s: &prom::Scrape| {
        s.family("picket_queue_depth")
            .metric
            .iter()
            .filter(|m| prom::labels(m).get("queue").map(String::as_str) == Some("light"))
            .count()
    };
    assert_eq!(light(&scrape), 1, "one light-lane depth per scrape");
    assert!(
        eventually(|| async {
            prom::parse(&fetch().await).value("picket_queue_depth", &[("queue", "light")]) == Some(0.0)
        })
        .await,
        "the light lane never went idle"
    );
    assert_eq!(scrape.value("picket_up", &[]), Some(1.0));
    // Core's histograms are totals since core started: a second sample adds to the first.
    st.metrics
        .histograms(
            db,
            vec![(
                "lookup_call_ms".into(),
                picket_core::metrics::labels("", &[("provider", "q9")]),
                now,
                h.clone(),
            )],
        )
        .await;
    let again = prom::parse(&fetch().await);
    assert_eq!(
        again
            .histogram("picket_lookup_call_ms", &[("provider", "q9")])
            .unwrap()
            .count,
        2
    );
    drop(ws);
}
