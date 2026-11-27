//! The metrics registry (edge.md §11, api.md §3): in-memory counters, gauges and histograms,
//! lock-free on the hot path. Counters and histograms are running totals since the process
//! started, never reset by a heartbeat (a lost heartbeat loses nothing); the edge stores no
//! metrics, so a restart starts every total from 0 under a new `boot`. Durations use the one fixed
//! histogram layout of [`picket_api::histogram`].
//!
//! Per-upstream, per-provider and per-bundle maps hand out `Arc` counter sets: callers keep the
//! `Arc` (an upstream actor holds its own) and increment atomics without touching the map.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use arc_swap::ArcSwap;

use picket_api::histogram::{BUCKETS, Histogram, bucket_index};
use picket_api::logs::Decision;
use picket_api::session::{
    ByDecision, ColdMetrics, LookupMetrics, Metrics as MetricsSnapshot, UpstreamMetrics,
};

/// Most keys a keyed map tracks (bounded; keys come from the config). Further keys share an
/// `other` entry.
pub const MAX_KEYS: usize = 1024;

/// A histogram on the fixed layout, recorded with atomics. `sum` is kept in µs whatever the
/// field's unit, so a field in ms (`rtt_ms`, `call_ms`) is converted once, at snapshot, from the
/// exact total: rounding each 1–2 ms sample down to whole ms would make its sum run 25–50 % low
/// (api.md §3).
pub struct AtomicHistogram {
    buckets: [AtomicU64; BUCKETS],
    sum_us: AtomicU64,
    count: AtomicU64,
}

impl Default for AtomicHistogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl AtomicHistogram {
    /// Records a duration of `us` microseconds.
    pub fn record_us(&self, us: u64) {
        self.buckets[bucket_index(us).min(BUCKETS - 1)].fetch_add(1, Relaxed);
        self.sum_us.fetch_add(us, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }

    /// The running totals with `sum` in µs (`latency_us`).
    pub fn snapshot(&self) -> Histogram {
        self.snapshot_with_sum(self.sum_us.load(Relaxed))
    }

    fn snapshot_with_sum(&self, sum: u64) -> Histogram {
        let mut h = Histogram {
            buckets: self.buckets.iter().map(|b| b.load(Relaxed)).collect(),
            sum,
            count: self.count.load(Relaxed),
        };
        h.trim();
        h
    }
}

/// A duration histogram whose field reports `sum` in ms (`rtt_ms`, `call_ms`). Samples are still
/// recorded in µs (the bucket layout is in µs); see [`AtomicHistogram`].
#[derive(Default)]
pub struct MsHistogram(AtomicHistogram);

impl MsHistogram {
    /// Records a duration of `us` microseconds.
    pub fn record_ms_from_us(&self, us: u64) {
        self.0.record_us(us);
    }

    /// The running totals with `sum` in ms, from the exact µs total.
    pub fn snapshot(&self) -> Histogram {
        self.0.snapshot_with_sum(self.0.sum_us.load(Relaxed) / 1000)
    }
}

/// A map from a config id to a counter set, copy-on-write behind `ArcSwap`.
pub struct Keyed<T> {
    map: ArcSwap<BTreeMap<String, Arc<T>>>,
}

impl<T: Default> Default for Keyed<T> {
    fn default() -> Self {
        Self {
            map: ArcSwap::from_pointee(BTreeMap::new()),
        }
    }
}

impl<T: Default> Keyed<T> {
    /// The counter set for `key`, created on first use. Past [`MAX_KEYS`] keys, new keys share
    /// the `other` entry so the map stays bounded.
    pub fn get(&self, key: &str) -> Arc<T> {
        if let Some(v) = self.map.load().get(key) {
            return Arc::clone(v);
        }
        let mut out = None;
        self.map.rcu(|m| {
            if let Some(v) = m.get(key) {
                out = Some(Arc::clone(v));
                return Arc::clone(m);
            }
            let mut next = BTreeMap::clone(m);
            let k = if next.len() >= MAX_KEYS { "other" } else { key };
            let v = Arc::clone(next.entry(k.to_owned()).or_default());
            out = Some(v);
            Arc::new(next)
        });
        out.unwrap_or_default()
    }

    pub fn snapshot<S>(&self, f: impl Fn(&T) -> S) -> BTreeMap<String, S> {
        self.map.load().iter().map(|(k, v)| (k.clone(), f(v))).collect()
    }
}

/// Counters by reason (e.g. `invalid{reason: n}`).
pub type Reasons = Keyed<AtomicU64>;

#[derive(Default)]
pub struct UpstreamCounters {
    pub queries: AtomicU64,
    pub hedges: AtomicU64,
    pub rtt_ms: MsHistogram,
    pub errors: AtomicU64,
    pub invalid: Reasons,
    /// Records the scrub removed, by reason (edge.md §7 step 3).
    pub scrubbed: Reasons,
}

#[derive(Default)]
pub struct LookupCounters {
    pub calls: AtomicU64,
    pub call_ms: MsHistogram,
    pub timeouts: AtomicU64,
    pub late: AtomicU64,
    pub errors: AtomicU64,
    pub rejected: AtomicU64,
    /// Gauge: 1 while the breaker is open.
    pub breaker_open: AtomicU64,
    pub paused: AtomicU64,
    pub cache_hits: AtomicU64,
    pub set_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub evictions: AtomicU64,
    /// Gauge.
    pub entries: AtomicU64,
    /// Gauge.
    pub bytes: AtomicU64,
}

#[derive(Default)]
pub struct ColdCounters {
    pub blocks: AtomicU64,
    pub unchecked: AtomicU64,
    pub page_reads: AtomicU64,
}

/// Every metric `heartbeat.metrics` carries (api.md §3).
#[derive(Default)]
pub struct Metrics {
    pub queries: AtomicU64,
    by_decision: [AtomicU64; 5],
    pub rejected: AtomicU64,
    pub refused: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub stale_served: AtomicU64,
    pub latency_us: AtomicHistogram,
    pub panics: AtomicU64,
    pub fw_ack_late: AtomicU64,
    pub upstream: Keyed<UpstreamCounters>,
    pub lookups: Keyed<LookupCounters>,
    pub cold: Keyed<ColdCounters>,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Counts one decided query: `by_decision` and `queries`, their sum (api.md §3). A `refused`
    /// decision also counts in `refused`.
    pub fn count_decision(&self, d: Decision) {
        let i = match d {
            Decision::Allow => 0,
            Decision::Block => 1,
            Decision::Rewrite => 2,
            Decision::Refused => 3,
            Decision::Servfail => 4,
        };
        self.by_decision[i].fetch_add(1, Relaxed);
        self.queries.fetch_add(1, Relaxed);
        if d == Decision::Refused {
            self.refused.fetch_add(1, Relaxed);
        }
    }

    /// The running totals now.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let g = |a: &AtomicU64| a.load(Relaxed);
        MetricsSnapshot {
            queries: g(&self.queries),
            by_decision: ByDecision {
                allow: g(&self.by_decision[0]),
                block: g(&self.by_decision[1]),
                rewrite: g(&self.by_decision[2]),
                refused: g(&self.by_decision[3]),
                servfail: g(&self.by_decision[4]),
            },
            rejected: g(&self.rejected),
            refused: g(&self.refused),
            cache_hits: g(&self.cache_hits),
            cache_misses: g(&self.cache_misses),
            stale_served: g(&self.stale_served),
            latency_us: self.latency_us.snapshot(),
            panics: g(&self.panics),
            fw_ack_late: g(&self.fw_ack_late),
            upstream: self.upstream.snapshot(|u| UpstreamMetrics {
                queries: g(&u.queries),
                hedges: g(&u.hedges),
                rtt_ms: u.rtt_ms.snapshot(),
                errors: g(&u.errors),
                invalid: u.invalid.snapshot(|c| g(c)),
                scrubbed: u.scrubbed.snapshot(|c| g(c)),
            }),
            lookups: self.lookups.snapshot(|l| LookupMetrics {
                calls: g(&l.calls),
                call_ms: l.call_ms.snapshot(),
                timeouts: g(&l.timeouts),
                late: g(&l.late),
                errors: g(&l.errors),
                rejected: g(&l.rejected),
                breaker_open: g(&l.breaker_open),
                paused: g(&l.paused),
                cache_hits: g(&l.cache_hits),
                set_hits: g(&l.set_hits),
                cache_misses: g(&l.cache_misses),
                evictions: g(&l.evictions),
                entries: g(&l.entries),
                bytes: g(&l.bytes),
            }),
            cold: self.cold.snapshot(|c| ColdMetrics {
                blocks: g(&c.blocks),
                unchecked: g(&c.unchecked),
                page_reads: g(&c.page_reads),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_totals_survive_snapshots() {
        let m = Metrics::new();
        m.count_decision(Decision::Allow);
        m.count_decision(Decision::Refused);
        m.latency_us.record_us(12);
        let up = m.upstream.get("cf-dot");
        up.queries.fetch_add(3, Relaxed);
        up.rtt_ms.record_ms_from_us(4_000);
        up.invalid.get("structure").fetch_add(1, Relaxed);
        let a = m.snapshot();
        let b = m.snapshot();
        assert_eq!(a, b, "a snapshot (heartbeat) never resets anything");
        assert_eq!(a.queries, 2);
        assert_eq!(a.by_decision.refused, 1);
        assert_eq!(a.refused, 1);
        assert_eq!(a.latency_us.count, 1);
        assert_eq!(a.latency_us.bucket(1), 1);
        assert_eq!(a.upstream["cf-dot"].queries, 3);
        assert_eq!(a.upstream["cf-dot"].rtt_ms.sum, 4);
        assert_eq!(a.upstream["cf-dot"].invalid["structure"], 1);
        m.count_decision(Decision::Block);
        let c = m.snapshot();
        assert_eq!(c.queries, 3);
        assert_eq!(c.by_decision.block, 1);
        // A new boot is a new registry: totals start from 0.
        assert_eq!(Metrics::new().snapshot().queries, 0);
    }

    #[test]
    fn keyed_maps_are_bounded() {
        let k: Keyed<AtomicU64> = Keyed::default();
        for i in 0..(MAX_KEYS + 10) {
            k.get(&format!("k{i}")).fetch_add(1, Relaxed);
        }
        let s = k.snapshot(|c| c.load(Relaxed));
        assert!(s.len() <= MAX_KEYS + 1);
        assert_eq!(s["other"], 10);
        assert!(Arc::ptr_eq(&k.get("k1"), &k.get("k1")));
    }

    #[test]
    fn millisecond_sums_keep_sub_millisecond_parts() {
        // api.md §3: `sum` is the total of the samples, so averages over a window come out right
        // at the 1–2 ms RTTs the edge sees.
        let m = Metrics::new();
        let up = m.upstream.get("cf-dot");
        for _ in 0..4 {
            up.rtt_ms.record_ms_from_us(1_500);
        }
        let s = m.snapshot();
        assert_eq!(s.upstream["cf-dot"].rtt_ms.sum, 6);
        assert_eq!(s.upstream["cf-dot"].rtt_ms.count, 4);
    }

    #[test]
    fn histogram_uses_fixed_layout() {
        let h = AtomicHistogram::default();
        h.record_us(5);
        h.record_us(u64::MAX / 2);
        let s = h.snapshot();
        assert_eq!(s.bucket(0), 1);
        assert_eq!(s.bucket(BUCKETS - 1), 1);
        assert_eq!(s.buckets.len(), BUCKETS);
    }
}
