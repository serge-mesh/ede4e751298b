//! Per-provider counters for the heartbeat's `lookups{provider: {...}}` (api.md §3): running
//! totals since the process started, never reset; `breaker_open`, `entries` and `bytes` are
//! gauges.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use picket_api::Histogram;
use picket_api::session::LookupMetrics;

#[derive(Debug, Default)]
pub(crate) struct Metrics {
    /// Provider calls started.
    pub calls: AtomicU64,
    /// Lookups that returned a timeout: a sync deadline that passed, or an async call that ran
    /// out of `async_timeout_ms`.
    pub timeouts: AtomicU64,
    /// Answers that came after a sync lookup waiting for them timed out.
    pub late: AtomicU64,
    /// Calls that ended in an error (`Failed` or `Other`, a call that ran out of
    /// `async_timeout_ms` included).
    pub errors: AtomicU64,
    /// Calls the provider rejected.
    pub rejected: AtomicU64,
    /// Lookups answered at once because the provider is paused after a rejection.
    pub paused: AtomicU64,
    /// RAM-tier hits (verdicts, and cached errors that stopped a call).
    pub cache_hits: AtomicU64,
    /// Verdict-set hits.
    pub set_hits: AtomicU64,
    /// Lookups no tier answered.
    pub cache_misses: AtomicU64,
    /// Calls made, from start to answer or failure, late answers included.
    pub call_ms: Mutex<Histogram>,
}

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_call(&self, d: Duration) {
        let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.call_ms
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .record(us, ms);
    }

    pub fn snapshot(&self, breaker_open: bool, ram: Option<(u64, u64, u64)>) -> LookupMetrics {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let (evictions, entries, bytes) = ram.unwrap_or_default();
        LookupMetrics {
            calls: get(&self.calls),
            call_ms: self.call_ms.lock().unwrap_or_else(|p| p.into_inner()).clone(),
            timeouts: get(&self.timeouts),
            late: get(&self.late),
            errors: get(&self.errors),
            rejected: get(&self.rejected),
            breaker_open: u64::from(breaker_open),
            paused: get(&self.paused),
            cache_hits: get(&self.cache_hits),
            set_hits: get(&self.set_hits),
            cache_misses: get(&self.cache_misses),
            evictions,
            entries,
            bytes,
        }
    }
}
