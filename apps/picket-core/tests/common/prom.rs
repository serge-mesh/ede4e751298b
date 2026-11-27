//! `/metrics` read with a Prometheus text parser (build-and-test.md §5 Metrics; api.md §7).
//!
//! `prometheus-scraper` (a dev-dependency only) parses the body into metric families the way
//! Prometheus models them: typed counters and gauges, histograms with their cumulative buckets,
//! `_sum` and `_count`, label values unescaped. A line it can't read fails the test. It accepts
//! the union of the Prometheus and OpenMetrics dialects, so [`parse`] adds what Prometheus itself
//! refuses: metric and label names outside `[a-zA-Z_:][a-zA-Z0-9_:]*` / `[a-zA-Z_][a-zA-Z0-9_]*`,
//! one family twice, a label twice, and histogram buckets that aren't cumulative up to `+Inf`.

use std::collections::BTreeMap;

use prometheus_scraper::owned::{BucketCount, Metric, MetricFamily, MetricType, MetricValue};
use prometheus_scraper::{Format, TextFormat, parse_payload, text_parse_family};

pub type LabelSet = BTreeMap<String, String>;

/// A parsed export, by family name.
pub struct Scrape {
    pub families: BTreeMap<String, MetricFamily>,
}

/// A histogram's samples for one label set.
#[derive(Clone, Debug, PartialEq)]
pub struct Hist {
    /// `(le, cumulative count)`, ending with `+Inf`.
    pub buckets: Vec<(f64, u64)>,
    pub sum: f64,
    pub count: u64,
}

fn is_metric_name(s: &str) -> bool {
    let mut c = s.chars();
    c.next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_' || f == ':')
        && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':')
}

fn is_label_name(s: &str) -> bool {
    let mut c = s.chars();
    !s.starts_with("__")
        && c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// A metric's labels (a histogram's without `le`).
pub fn labels(m: &Metric) -> LabelSet {
    let mut out = LabelSet::new();
    for l in &m.label {
        assert!(is_label_name(&l.name), "label name {:?}", l.name);
        assert!(
            out.insert(l.name.clone(), l.value.clone()).is_none(),
            "label {:?} twice",
            l.name
        );
    }
    out
}

fn hist_of(v: &MetricValue) -> Option<Hist> {
    let MetricValue::Histogram(h) = v else { return None };
    let (buckets, count): (Vec<(f64, u64)>, Option<u64>) = match &h.counts {
        BucketCount::Int {
            sample_count,
            buckets,
        } => (
            buckets
                .iter()
                .map(|b| (b.upper_bound, b.cumulative_count))
                .collect(),
            *sample_count,
        ),
        BucketCount::Float { .. } => panic!("histogram counts must be integers"),
    };
    Some(Hist {
        buckets,
        sum: h.sample_sum.map(|s| s.as_f64()).expect("a histogram has a _sum"),
        count: count.expect("a histogram has a _count"),
    })
}

/// Every sample once: Prometheus refuses a scrape that has one twice, while the parser keeps one
/// of them. Each sample line is read alone, by the parser, and keyed by its name and its labels
/// in any order (`le` included).
fn assert_samples_once(text: &str) {
    let mut seen = std::collections::BTreeSet::new();
    for line in text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
    {
        let one = format!("{line}\n");
        let f = text_parse_family(&one, TextFormat::Prometheus)
            .unwrap_or_else(|e| panic!("{e}: {line}"))
            .into_owned();
        assert_eq!(f.metric.len(), 1, "{line}");
        assert!(
            seen.insert((f.name.clone(), labels(&f.metric[0]))),
            "a sample twice: {line}"
        );
    }
}

/// Parses an export body; panics on anything Prometheus wouldn't read (module docs).
pub fn parse(text: &str) -> Scrape {
    assert_samples_once(text);
    let mut families = BTreeMap::new();
    for f in parse_payload(text.as_bytes(), Format::Text(TextFormat::Prometheus)) {
        let f = f.unwrap_or_else(|e| panic!("{e}\n{text}")).into_owned();
        assert!(is_metric_name(&f.name), "metric name {:?}", f.name);
        assert!(!f.metric.is_empty(), "family {} has no samples", f.name);
        let mut seen = std::collections::BTreeSet::new();
        for m in &f.metric {
            assert!(seen.insert(labels(m)), "{}: one label set twice", f.name);
            if let Some(h) = hist_of(&m.value) {
                assert_eq!(h.buckets.last().map(|b| b.0), Some(f64::INFINITY), "{}", f.name);
                assert!(
                    h.buckets.windows(2).all(|w| w[0].0 < w[1].0 && w[0].1 <= w[1].1),
                    "{}: buckets must be cumulative in ascending le",
                    f.name
                );
                assert_eq!(
                    h.buckets.last().map(|b| b.1),
                    Some(h.count),
                    "{}: +Inf = _count",
                    f.name
                );
            }
        }
        let name = f.name.clone();
        assert!(families.insert(name.clone(), f).is_none(), "family {name} twice");
    }
    Scrape { families }
}

impl Scrape {
    pub fn family(&self, name: &str) -> &MetricFamily {
        self.families.get(name).unwrap_or_else(|| {
            panic!(
                "no family {name}; families: {:?}",
                self.families.keys().collect::<Vec<_>>()
            )
        })
    }

    fn metric(&self, name: &str, want: &[(&str, &str)]) -> Option<&Metric> {
        let want: LabelSet = want.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        self.families.get(name)?.metric.iter().find(|m| labels(m) == want)
    }

    /// The value of counter or gauge `name` with exactly these labels.
    pub fn value(&self, name: &str, want: &[(&str, &str)]) -> Option<f64> {
        match &self.metric(name, want)?.value {
            MetricValue::Counter(c) => Some(c.value.as_f64()),
            MetricValue::Gauge(g) | MetricValue::Untyped(g) => Some(g.as_f64()),
            _ => None,
        }
    }

    /// The histogram `name` with exactly these labels (`le` aside).
    pub fn histogram(&self, name: &str, want: &[(&str, &str)]) -> Option<Hist> {
        hist_of(&self.metric(name, want)?.value)
    }

    /// The type of family `name`.
    pub fn kind(&self, name: &str) -> Option<MetricType> {
        self.families.get(name).map(|f| f.r#type)
    }
}
