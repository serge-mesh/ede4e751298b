//! The Prometheus export (`GET /metrics`, api.md §7): core's counters and histograms as totals
//! since core started, its gauges, and the counters, histograms and gauges of each edge's last
//! heartbeat, labelled `edge`. A name is `picket_` plus the series name or field path with `_`
//! for `.`, map keys as labels; counter names end in `_total`. A histogram is `_bucket{le=…}`
//! (cumulative, up to `+Inf`), `_sum` and `_count`, with `le` in the histogram's unit (`_ms`
//! fields in milliseconds, others in microseconds).
//!
//! Every series of [`super::HEARTBEAT_SERIES`] and [`super::CORE_SERIES`] is exported once it
//! has a value, plus the few only the export holds ([`EXPORT_ONLY`]). The body is bounded by the
//! series caps it reads ([`super::CoreCounters`], each edge's live heartbeat) and costs one walk
//! of them (README §2 Bounded).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use picket_api::histogram::{BOUNDS_US, BUCKETS};

use super::store::{Value, flatten};
use super::{Kind, Labels, Series, kind_of};
use crate::state::AppState;

/// Series only the export holds, read when it renders: `up`, the heavy lane's finished jobs by
/// result, the jobs each lane refused while full, and the values core's series maps refused at
/// their caps ([`super::Dropped`]). The UI shows the lanes' figures from `GET jobs` (System → Jobs),
/// not as charts: core keeps no history of them.
pub const EXPORT_ONLY: &[Series] = &[
    Series {
        name: "up",
        kind: Kind::CoreGauge,
        labels: &[],
        export: None,
    },
    Series {
        name: "heavy_jobs",
        kind: Kind::CoreCounter,
        labels: &["result"],
        export: None,
    },
    Series {
        name: "jobs_dropped",
        kind: Kind::CoreCounter,
        labels: &["lane"],
        export: None,
    },
    Series {
        name: "metrics_dropped",
        kind: Kind::CoreCounter,
        labels: &["map"],
        export: None,
    },
];

/// Each bundle's current version's statistics (`bundle_versions.stats_json`, core.md §10 "Per
/// bundle"), exported as gauges labelled `bundle`: `(series, stats key)`. The UI shows them on the
/// bundle's page (Versions, Cold).
pub const BUNDLE_STATS: &[(&str, &str)] = &[
    ("bundle_hot_keys", "hot_keys"),
    ("bundle_cold_keys", "cold_keys"),
    ("bundle_hot_bytes", "hot_bytes"),
    ("bundle_cold_filter_bytes", "cold_filter_bytes"),
    ("bundle_cold_page_bytes", "cold_page_bytes"),
    ("bundle_edge_mem_bytes", "edge_mem_bytes"),
    ("bundle_overlay_bytes", "overlay_bytes"),
    ("bundle_base_bytes", "base_bytes"),
    ("bundle_delta_bytes", "delta_bytes"),
    ("bundle_keys_added", "keys_added"),
    ("bundle_keys_deleted", "keys_deleted"),
    ("bundle_keys_changed", "keys_changed"),
    ("bundle_shards", "shards"),
    ("bundle_cold_shards", "cold_shards"),
    ("bundle_patterns", "patterns"),
];

/// The current version's publish time of each bundle, Unix seconds (a gauge labelled `bundle`).
pub const BUNDLE_PUBLISHED: &str = "bundle_published_ts";

/// Every series only the export holds: [`EXPORT_ONLY`], then the bundle statistics.
pub fn export_only() -> impl Iterator<Item = Series> {
    let gauge = |name: &'static str| Series {
        name,
        kind: Kind::CoreGauge,
        labels: &["bundle"],
        export: None,
    };
    EXPORT_ONLY
        .iter()
        .copied()
        .chain(BUNDLE_STATS.iter().map(move |(n, _)| gauge(n)))
        .chain(std::iter::once(gauge(BUNDLE_PUBLISHED)))
}

/// The family a series is exported as (api.md §7): `picket_` plus its name (or its export name)
/// with `_` for `.`, counters ending in `_total`.
pub fn family(s: &Series) -> String {
    let base = metric_name(s.export.unwrap_or(s.name));
    match s.kind {
        Kind::Counter | Kind::CoreCounter => format!("{base}_total"),
        _ => base,
    }
}

/// The current version of a bundle: its id, publish time (Unix seconds) and statistics.
#[derive(Clone, Debug, Default)]
pub struct BundleRow {
    pub bundle: String,
    pub published_s: Option<i64>,
    pub stats: serde_json::Value,
}

/// Bundles read at most per export (README §2 Bounded; the configuration's bundle cap is lower).
const MAX_BUNDLES: i64 = 10_000;

/// Each bundle's current version and its statistics, from core.db.
pub async fn bundle_rows(state: &AppState) -> anyhow::Result<Vec<BundleRow>> {
    state
        .db
        .read(|c| {
            let mut st = c.prepare_cached(&format!(
                "SELECT v.bundle_id, v.published_at, v.stats_json FROM bundle_builds b
                 JOIN bundle_versions v ON v.bundle_id = b.bundle_id AND v.head_id = b.head_id
                 ORDER BY v.bundle_id LIMIT {MAX_BUNDLES}"
            ))?;
            let rows = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(
                rows.into_iter()
                    .map(|(bundle, published, stats)| BundleRow {
                        bundle,
                        published_s: crate::util::parse_ts(&published).map(|t| t.as_second()),
                        stats: stats
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default(),
                    })
                    .collect(),
            )
        })
        .await
}

/// The export body for `GET /metrics`: the bundles' rows read from core.db, then rendered on a
/// blocking thread, off the async workers (README §2: a large body never stalls them).
pub async fn body(state: &crate::state::SharedState) -> String {
    let bundles = bundle_rows(state).await.unwrap_or_else(|e| {
        tracing::warn!(error = %format!("{e:#}"), "cannot read the bundles' statistics for the export");
        Vec::new()
    });
    let st = state.clone();
    match tokio::task::spawn_blocking(move || render(&st, &bundles)).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "the export failed to render");
            String::new()
        }
    }
}

/// Escapes a label value (backslash, double quote, newline).
pub fn escape(v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            c => s.push(c),
        }
    }
    s
}

fn metric_name(series: &str) -> String {
    let mut n = String::from("picket_");
    for c in series.chars() {
        n.push(if c.is_ascii_alphanumeric() || c == '_' {
            c
        } else {
            '_'
        });
    }
    n
}

/// The name a series is exported under ([`Series::export`]).
fn exported(series: &str) -> &str {
    match super::series(series).and_then(|s| s.export) {
        Some(e) => e,
        None => series,
    }
}

fn label_text(l: &Labels, extra: Option<(&str, &str)>) -> String {
    let mut parts: Vec<String> = l.iter().map(|(k, v)| format!("{k}=\"{}\"", escape(v))).collect();
    if let Some((k, v)) = extra {
        parts.push(format!("{k}=\"{}\"", escape(v)));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

fn number(v: f64) -> String {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", crate::util::f64_to_i64(v))
    } else if v.is_finite() {
        format!("{v}")
    } else if v.is_nan() {
        "NaN".into()
    } else if v > 0.0 {
        "+Inf".into()
    } else {
        "-Inf".into()
    }
}

/// Families of samples, grouped as the text format requires.
#[derive(Default)]
struct Families {
    fams: BTreeMap<String, (&'static str, Vec<String>)>,
}

impl Families {
    fn push(&mut self, family: &str, kind: &'static str, line: String) {
        self.fams
            .entry(family.to_string())
            .or_insert_with(|| (kind, Vec::new()))
            .1
            .push(line);
    }

    fn render(self) -> String {
        let mut out = String::new();
        for (name, (kind, lines)) in self.fams {
            let _ = writeln!(out, "# TYPE {name} {kind}");
            for l in lines {
                out.push_str(&l);
                out.push('\n');
            }
        }
        out
    }

    fn counter(&mut self, series: &str, l: &Labels, v: f64) {
        let name = format!("{}_total", metric_name(exported(series)));
        let line = format!("{name}{} {}", label_text(l, None), number(v));
        self.push(&name, "counter", line);
    }

    fn gauge(&mut self, series: &str, l: &Labels, v: f64) {
        let name = metric_name(exported(series));
        let line = format!("{name}{} {}", label_text(l, None), number(v));
        self.push(&name, "gauge", line);
    }

    /// `ms`: the field's unit is milliseconds (bounds and sum as given in ms).
    fn histogram(&mut self, series: &str, l: &Labels, h: &picket_api::Histogram, ms: bool) {
        let name = metric_name(exported(series));
        let mut lines = Vec::new();
        let mut cum = 0u64;
        for (i, bound) in BOUNDS_US.iter().enumerate().take(BUCKETS - 1) {
            cum = cum.saturating_add(h.bucket(i));
            let le = if ms {
                number(*bound as f64 / 1000.0)
            } else {
                bound.to_string()
            };
            lines.push(format!("{name}_bucket{} {cum}", label_text(l, Some(("le", &le)))));
        }
        cum = cum.saturating_add(h.bucket(BUCKETS - 1));
        lines.push(format!(
            "{name}_bucket{} {cum}",
            label_text(l, Some(("le", "+Inf")))
        ));
        lines.push(format!("{name}_sum{} {}", label_text(l, None), h.sum));
        lines.push(format!("{name}_count{} {}", label_text(l, None), h.count));
        for line in lines {
            self.push(&name, "histogram", line);
        }
    }
}

/// The export body, with the bundles' current versions (`bundles`, [`bundle_rows`]).
pub fn render(state: &AppState, bundles: &[BundleRow]) -> String {
    let mut f = Families::default();
    let core = |extra: &[(&str, &str)]| super::labels("", extra);
    // Export-only series (EXPORT_ONLY).
    let h = state.scheduler.heavy.stats();
    f.gauge("up", &Labels::new(), 1.0);
    f.counter(
        "heavy_jobs",
        &core(&[("result", "completed")]),
        h.completed as f64,
    );
    f.counter("heavy_jobs", &core(&[("result", "failed")]), h.failed as f64);
    f.counter(
        "jobs_dropped",
        &core(&[("lane", "light")]),
        state.scheduler.light.dropped() as f64,
    );
    f.counter("jobs_dropped", &core(&[("lane", "heavy")]), h.dropped as f64);
    let d = state.metrics.counters.dropped();
    for (map, n) in super::DROPPED_MAPS
        .iter()
        .zip([d.counters, d.gauges, d.histograms])
    {
        f.counter("metrics_dropped", &core(&[("map", map)]), n as f64);
    }
    // Each bundle's current version (core.md §10 "Per bundle"), for bundles that exist.
    for b in bundles {
        if !state.metrics.counters.bundle_exists(&b.bundle) {
            continue;
        }
        let l = core(&[("bundle", &b.bundle)]);
        for (series, key) in BUNDLE_STATS {
            if let Some(v) = b.stats.get(key).and_then(serde_json::Value::as_f64) {
                f.gauge(series, &l, v);
            }
        }
        if let Some(t) = b.published_s {
            f.gauge(BUNDLE_PUBLISHED, &l, t as f64);
        }
    }
    // Core's counters and histograms since it started.
    for ((name, l), v) in state.metrics.counters.totals() {
        f.counter(&name, &l, v);
    }
    for ((name, l), h) in state.metrics.counters.histograms() {
        f.histogram(&name, &l, &h, name.ends_with("_ms"));
    }
    // Job durations since core started, by job kind (api.md §7), in milliseconds.
    for (kind, h) in state.metrics.jobs.totals() {
        f.histogram("job_ms", &core(&[("kind", &kind)]), &h, true);
    }
    // Core's gauges: the last sampled values, with the lanes' depths read now in place of their
    // last samples (one sample per series and label set).
    let mut gauges: BTreeMap<(String, Labels), f64> = state.metrics.counters.gauges().into_iter().collect();
    for (lane, depth) in [
        ("light", state.scheduler.light.depth()),
        ("heavy", state.scheduler.heavy.depth()),
    ] {
        gauges.insert(("queue_depth".into(), core(&[("queue", lane)])), depth as f64);
    }
    for ((name, l), v) in gauges {
        f.gauge(&name, &l, v);
    }
    // Each edge's last heartbeat.
    for (edge, live) in state.edges.hub.all_live() {
        let Some(hb) = live.heartbeat else { continue };
        for (name, l, v) in flatten(&edge, &hb) {
            match (kind_of(&name), v) {
                (Some(Kind::Counter), Value::Number(n)) => f.counter(&name, &l, n),
                (Some(Kind::Gauge), Value::Number(n)) => f.gauge(&name, &l, n),
                (Some(Kind::Histogram), Value::Hist(h)) => f.histogram(&name, &l, &h, name.ends_with("_ms")),
                _ => {}
            }
        }
    }
    f.render()
}

#[cfg(test)]
mod tests {
    use prometheus_scraper::owned::{BucketCount, MetricFamily, MetricType, MetricValue};
    use prometheus_scraper::{Format, TextFormat, parse_payload};

    use super::*;

    /// The body read with a Prometheus text parser (build-and-test.md §5 Metrics).
    fn parse(text: &str) -> Vec<MetricFamily> {
        parse_payload(text.as_bytes(), Format::Text(TextFormat::Prometheus))
            .map(|f| f.unwrap_or_else(|e| panic!("{e}\n{text}")).into_owned())
            .collect()
    }

    #[test]
    fn names_labels_and_histograms() {
        let mut f = Families::default();
        // A label value with every character the format escapes.
        let odd = "cf\"dot\\\nx";
        let l = super::super::labels("e-01", &[("upstream", odd)]);
        f.counter("upstream.queries", &l, 5.0);
        let mut h = picket_api::Histogram::default();
        h.record(5, 5);
        h.record(100_000_000, 100);
        f.histogram("upstream.rtt_ms", &l, &h, true);
        f.histogram("latency_us", &l, &h, false);
        f.gauge("rss", &Labels::new(), f64::INFINITY);
        f.gauge("mem_available", &Labels::new(), 1.5);
        let fams = parse(&f.render());
        let fam = |n: &str| fams.iter().find(|f| f.name == n).unwrap_or_else(|| panic!("{n}"));
        let labels = |f: &MetricFamily| -> Vec<(String, String)> {
            f.metric[0]
                .label
                .iter()
                .map(|p| (p.name.clone(), p.value.clone()))
                .collect()
        };

        let q = fam("picket_upstream_queries_total");
        assert_eq!(q.r#type, MetricType::Counter);
        assert_eq!(
            labels(q),
            [("edge".into(), "e-01".into()), ("upstream".into(), odd.into())]
        );
        let MetricValue::Counter(c) = &q.metric[0].value else {
            panic!()
        };
        assert_eq!(c.value.as_f64(), 5.0);

        // `le` in the field's unit: milliseconds for `_ms`, microseconds otherwise; cumulative
        // up to +Inf, which holds the overflow bucket.
        for (name, first) in [("picket_upstream_rtt_ms", 0.01), ("picket_latency_us", 10.0)] {
            let r = fam(name);
            assert_eq!(r.r#type, MetricType::Histogram);
            assert_eq!(labels(r).len(), 2, "le is no label of the series");
            let MetricValue::Histogram(h) = &r.metric[0].value else {
                panic!()
            };
            let BucketCount::Int {
                sample_count,
                buckets,
            } = &h.counts
            else {
                panic!()
            };
            assert_eq!(buckets.len(), BUCKETS);
            assert_eq!((buckets[0].upper_bound, buckets[0].cumulative_count), (first, 1));
            assert_eq!(buckets[BUCKETS - 2].cumulative_count, 1);
            assert_eq!(
                (
                    buckets[BUCKETS - 1].upper_bound,
                    buckets[BUCKETS - 1].cumulative_count
                ),
                (f64::INFINITY, 2)
            );
            assert_eq!(*sample_count, Some(2));
            assert_eq!(h.sample_sum.map(|s| s.as_f64()), Some(105.0));
        }

        let MetricValue::Gauge(g) = &fam("picket_rss").metric[0].value else {
            panic!()
        };
        assert_eq!(g.as_f64(), f64::INFINITY);
        let MetricValue::Gauge(g) = &fam("picket_mem_available").metric[0].value else {
            panic!()
        };
        assert_eq!(g.as_f64(), 1.5);
    }
}
