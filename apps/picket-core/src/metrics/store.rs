//! Storing metrics in `metrics.db` (storage.md §3): series by name and labels, points,
//! histogram rows and heartbeat samples.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use picket_api::Histogram;
use picket_api::session::Heartbeat;
use rusqlite::{OptionalExtension, Transaction, params};

use super::{Labels, labels};
use crate::db::Db;

/// Core's own event counts are binned to this step at their event time (core.md §10: core
/// samples its gauges every 30 s), and core writes a presence sample this often.
pub const CORE_BIN_MS: i64 = 30_000;
/// Series ids cached in memory (README §2, Bounded); a miss reads the table.
const MAX_CACHED_SERIES: usize = 100_000;
/// Distinct series one edge may create (README §2, Bounded: map keys come from the edge). A
/// heartbeat value whose series would pass it is dropped. Series with no value left in the
/// metrics window age out ([`super::MetricsRetention`]), which frees their room.
pub const MAX_SERIES_PER_EDGE: i64 = 8_192;
/// Series keys remembered as refused for their edge's share (README §2, Bounded); past it the
/// set starts over, and a refused key costs an index read again.
const MAX_REFUSED: usize = 100_000;

/// `(name, labels JSON)`.
type Key = (String, String);

/// Series ids by `(name, labels)`, each edge's series count and the keys refused for an edge's
/// share, kept on the metrics writer (README §2, capped shares: an edge at its share costs no
/// table scan per value). Every use is inside a writer transaction, and what a transaction
/// resolved is published only after it commits ([`SeriesCache::publish`]), so a rolled-back
/// series never leaves its id behind (README §2 Restarts) and the counts follow `series` in
/// commit order; retention takes out what it deletes in its own transaction
/// ([`SeriesCache::forget`]).
#[derive(Clone, Default)]
pub struct SeriesCache {
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    inner: Mutex<Inner>,
    scans: AtomicU64,
}

#[derive(Default)]
struct Inner {
    ids: HashMap<Key, i64>,
    /// Committed series per `edge` label; loaded with one scan when a share is first checked.
    per_edge: Option<HashMap<String, i64>>,
    /// Keys refused for their edge's share since the share last shrank.
    refused: HashSet<Key>,
}

/// What one transaction resolved and created, published by [`SeriesCache::publish`] once it
/// committed (and dropped with it otherwise).
#[derive(Default)]
pub struct Pending {
    ids: HashMap<Key, i64>,
    created: HashMap<String, i64>,
    refused: Vec<Key>,
}

impl SeriesCache {
    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.shared.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The id of `(name, labels)` in `tx`, creating the series. With `capped`, `None` when the
    /// series is new and its `edge` is at its share (README §2, capped shares).
    pub fn resolve(
        &self,
        tx: &Transaction<'_>,
        name: &str,
        l: &Labels,
        capped: bool,
        p: &mut Pending,
    ) -> rusqlite::Result<Option<i64>> {
        let key: Key = (
            name.to_string(),
            serde_json::to_string(l).unwrap_or_else(|_| "{}".into()),
        );
        if let Some(id) = p.ids.get(&key) {
            return Ok(Some(*id));
        }
        {
            let g = self.inner();
            if let Some(id) = g.ids.get(&key) {
                return Ok(Some(*id));
            }
            if capped && g.refused.contains(&key) {
                return Ok(None);
            }
        }
        let existing: Option<i64> = tx
            .prepare_cached("SELECT id FROM series WHERE name = ?1 AND labels_json = ?2")?
            .query_row(params![key.0, key.1], |r| r.get(0))
            .optional()?;
        let edge = l.get("edge");
        let id = match existing {
            Some(id) => id,
            None => {
                if capped && let Some(edge) = edge {
                    let n = self.edge_count(tx, edge, p)? + p.created.get(edge).copied().unwrap_or(0);
                    if n >= MAX_SERIES_PER_EDGE {
                        p.refused.push(key);
                        return Ok(None);
                    }
                }
                tx.prepare_cached("INSERT INTO series(name, labels_json) VALUES (?1, ?2)")?
                    .execute(params![key.0, key.1])?;
                if let Some(edge) = edge {
                    *p.created.entry(edge.clone()).or_insert(0) += 1;
                }
                tx.last_insert_rowid()
            }
        };
        p.ids.insert(key, id);
        Ok(Some(id))
    }

    /// `edge`'s committed series count. The first call scans the table once (this transaction's
    /// own new rows left out); later counts follow commits and retention.
    fn edge_count(&self, tx: &Transaction<'_>, edge: &str, p: &Pending) -> rusqlite::Result<i64> {
        if let Some(m) = self.inner().per_edge.as_ref() {
            return Ok(m.get(edge).copied().unwrap_or(0));
        }
        self.shared.scans.fetch_add(1, Ordering::Relaxed);
        let mut st = tx.prepare(
            "SELECT CAST(json_extract(labels_json, '$.edge') AS TEXT), count(*) FROM series
             WHERE json_extract(labels_json, '$.edge') IS NOT NULL GROUP BY 1",
        )?;
        let mut m: HashMap<String, i64> = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (e, n) in &p.created {
            if let Some(c) = m.get_mut(e) {
                *c -= n;
            }
        }
        let n = m.get(edge).copied().unwrap_or(0);
        self.inner().per_edge = Some(m);
        Ok(n)
    }

    /// Publishes what a transaction resolved, right after it committed (on the writer).
    pub fn publish(&self, p: Pending) {
        let mut g = self.inner();
        let g = &mut *g;
        if g.ids.len() + p.ids.len() > MAX_CACHED_SERIES {
            g.ids.clear();
        }
        for (k, id) in p.ids {
            if g.ids.len() < MAX_CACHED_SERIES {
                g.ids.insert(k, id);
            }
        }
        if let Some(m) = g.per_edge.as_mut() {
            for (e, n) in p.created {
                *m.entry(e).or_insert(0) += n;
            }
        }
        if g.refused.len() + p.refused.len() > MAX_REFUSED {
            g.refused.clear();
        }
        g.refused.extend(p.refused);
    }

    /// Takes out series a committed transaction deleted (`(key, edge label)`), on the writer
    /// right after that commit: their ids, their room in each edge's share, and every refusal
    /// (a share that shrank may admit them now).
    pub fn forget(&self, removed: Vec<(String, String, Option<String>)>) {
        if removed.is_empty() {
            return;
        }
        let mut g = self.inner();
        let g = &mut *g;
        for (name, lj, edge) in removed {
            g.ids.remove(&(name, lj));
            if let (Some(e), Some(m)) = (edge, g.per_edge.as_mut())
                && let Some(c) = m.get_mut(&e)
            {
                *c -= 1;
                if *c <= 0 {
                    m.remove(&e);
                }
            }
        }
        g.refused.clear();
    }

    /// Full-table counts of series per edge since start (one is expected; diagnostics, tests).
    pub fn scans(&self) -> u64 {
        self.shared.scans.load(Ordering::Relaxed)
    }
}

/// One value of a heartbeat.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Number(f64),
    Hist(Histogram),
}

/// A heartbeat's values: `(series name, labels, value)`, labels including `edge`. Names and
/// kinds are those of [`super::HEARTBEAT_SERIES`]; null values (no helper, no `ssd_dir`, a value
/// the edge couldn't read) are left out.
pub fn flatten(edge: &str, hb: &Heartbeat) -> Vec<(String, Labels, Value)> {
    let mut out: Vec<(String, Labels, Value)> = Vec::new();
    let base = labels(edge, &[]);
    let mut num = |name: &str, l: &Labels, v: Option<u64>| {
        if let Some(v) = v {
            out.push((name.to_string(), l.clone(), Value::Number(v as f64)));
        }
    };
    let m = &hb.metrics;
    num("queries", &base, Some(m.queries));
    num("by_decision.allow", &base, Some(m.by_decision.allow));
    num("by_decision.block", &base, Some(m.by_decision.block));
    num("by_decision.rewrite", &base, Some(m.by_decision.rewrite));
    num("by_decision.refused", &base, Some(m.by_decision.refused));
    num("by_decision.servfail", &base, Some(m.by_decision.servfail));
    num("rejected", &base, Some(m.rejected));
    num("refused", &base, Some(m.refused));
    num("cache_hits", &base, Some(m.cache_hits));
    num("cache_misses", &base, Some(m.cache_misses));
    num("stale_served", &base, Some(m.stale_served));
    num("panics", &base, Some(m.panics));
    num("fw_ack_late", &base, Some(m.fw_ack_late));
    for (id, u) in &m.upstream {
        let l = labels(edge, &[("upstream", id)]);
        num("upstream.queries", &l, Some(u.queries));
        num("upstream.hedges", &l, Some(u.hedges));
        num("upstream.errors", &l, Some(u.errors));
        for (reason, n) in &u.invalid {
            num(
                "upstream.invalid",
                &labels(edge, &[("upstream", id), ("reason", reason)]),
                Some(*n),
            );
        }
        for (reason, n) in &u.scrubbed {
            num(
                "upstream.scrubbed",
                &labels(edge, &[("upstream", id), ("reason", reason)]),
                Some(*n),
            );
        }
    }
    for (p, s) in &m.lookups {
        let l = labels(edge, &[("provider", p)]);
        num("lookups.calls", &l, Some(s.calls));
        num("lookups.timeouts", &l, Some(s.timeouts));
        num("lookups.late", &l, Some(s.late));
        num("lookups.errors", &l, Some(s.errors));
        num("lookups.rejected", &l, Some(s.rejected));
        num("lookups.breaker_open", &l, Some(s.breaker_open));
        num("lookups.paused", &l, Some(s.paused));
        num("lookups.cache_hits", &l, Some(s.cache_hits));
        num("lookups.set_hits", &l, Some(s.set_hits));
        num("lookups.cache_misses", &l, Some(s.cache_misses));
        num("lookups.evictions", &l, Some(s.evictions));
        num("lookups.entries", &l, Some(s.entries));
        num("lookups.bytes", &l, Some(s.bytes));
    }
    for (b, c) in &m.cold {
        let l = labels(edge, &[("bundle", b)]);
        num("cold.blocks", &l, Some(c.blocks));
        num("cold.unchecked", &l, Some(c.unchecked));
        num("cold.page_reads", &l, Some(c.page_reads));
    }
    num("spool.bytes", &base, Some(hb.spool.bytes));
    num(
        "spool.oldest_ts",
        &base,
        hb.spool.oldest_ts.map(|t| crate::util::nonneg(t.as_second())),
    );
    for (reason, n) in &hb.logs.dropped {
        num("logs.dropped", &labels(edge, &[("reason", reason)]), Some(*n));
    }
    num("rss", &base, hb.rss);
    num("mem_available", &base, hb.mem_available);
    num("cpu_ms.edge", &base, hb.cpu_ms.edge);
    num("cpu_ms.helper", &base, hb.cpu_ms.helper);
    num("cgroup_mem.unit", &base, hb.cgroup_mem.unit);
    num("cgroup_mem.helper_rss", &base, hb.cgroup_mem.helper_rss);
    if let Some(d) = hb.disk.data_dir {
        num("disk.data_dir.used", &base, d.used);
        num("disk.data_dir.free", &base, d.free);
    }
    if let Some(d) = hb.disk.ssd_dir {
        num("disk.ssd_dir.used", &base, d.used);
        num("disk.ssd_dir.free", &base, d.free);
    }
    if let Some(fw) = hb.fw {
        num("fw.entries", &base, Some(fw.entries));
        num("fw.max", &base, Some(fw.max));
        num("fw.rejects", &base, Some(fw.rejects));
        num("fw.mon_rejects", &base, Some(fw.mon_rejects));
    }
    out.push((
        "latency_us".into(),
        base.clone(),
        Value::Hist(m.latency_us.clone()),
    ));
    for (id, u) in &m.upstream {
        out.push((
            "upstream.rtt_ms".into(),
            labels(edge, &[("upstream", id)]),
            Value::Hist(u.rtt_ms.clone()),
        ));
    }
    for (p, s) in &m.lookups {
        out.push((
            "lookups.call_ms".into(),
            labels(edge, &[("provider", p)]),
            Value::Hist(s.call_ms.clone()),
        ));
    }
    out
}

/// Stores one heartbeat: its sample, then each value at the heartbeat's `ts` (Unix ms, already
/// clamped to core's clock). Returns how many values were dropped for the edge's series share.
pub async fn store_heartbeat(
    db: &Db,
    cache: &std::sync::Arc<super::Metrics>,
    edge: &str,
    ts_ms: i64,
    hb: &Heartbeat,
) -> anyhow::Result<usize> {
    let values = flatten(edge, hb);
    let (edge, boot, up) = (edge.to_string(), hb.boot.clone(), crate::util::sat_i64(hb.up_ms));
    let m = cache.clone();
    db.write(move |c| {
        let tx = c.transaction()?;
        tx.execute(
            "INSERT INTO samples(edge_id, ts, boot, up_ms) VALUES (?1, ?2, ?3, ?4)",
            params![edge, ts_ms, boot, up],
        )?;
        let mut pending = Pending::default();
        let mut dropped = 0;
        for (name, l, v) in &values {
            let Some(id) = m.series.resolve(&tx, name, l, true, &mut pending)? else {
                dropped += 1;
                continue;
            };
            match v {
                Value::Number(n) => {
                    tx.prepare_cached("INSERT INTO points(series_id, ts, value) VALUES (?1, ?2, ?3)")?
                        .execute(params![id, ts_ms, n])?;
                }
                Value::Hist(h) => {
                    let mut h = h.clone();
                    h.trim();
                    tx.prepare_cached(
                        "INSERT INTO histograms(series_id, ts, buckets, sum, count) VALUES (?1, ?2, ?3, ?4, ?5)",
                    )?
                    .execute(params![
                        id,
                        ts_ms,
                        serde_json::to_string(&h.buckets).unwrap_or_else(|_| "[]".into()),
                        h.sum as f64,
                        crate::util::sat_i64(h.count)
                    ])?;
                }
            }
        }
        tx.commit()?;
        m.series.publish(pending);
        Ok::<_, anyhow::Error>(dropped)
    })
    .await
}

/// Writes `(name, labels, ts ms, histogram)` rows of core's own histograms (`job_ms`, core.md
/// §10: one row per sample, holding the durations since the previous one).
pub async fn write_histograms(
    db: &Db,
    cache: &SeriesCache,
    items: Vec<(String, Labels, i64, Histogram)>,
) -> anyhow::Result<()> {
    let cache = cache.clone();
    db.write(move |c| {
        let tx = c.transaction()?;
        let mut pending = Pending::default();
        for (name, l, ts, h) in &items {
            if let Some(id) = cache.resolve(&tx, name, l, false, &mut pending)? {
                tx.prepare_cached(
                    "INSERT INTO histograms(series_id, ts, buckets, sum, count) VALUES (?1, ?2, ?3, ?4, ?5)",
                )?
                .execute(params![
                    id,
                    ts,
                    serde_json::to_string(&h.buckets).unwrap_or_else(|_| "[]".into()),
                    h.sum as f64,
                    crate::util::sat_i64(h.count)
                ])?;
            }
        }
        tx.commit()?;
        cache.publish(pending);
        Ok::<_, anyhow::Error>(())
    })
    .await
}

/// Writes `(name, labels, ts ms, value)` points (core's own series: not capped). Ids are
/// resolved inside the writer and published after the commit, like a heartbeat's.
pub async fn write_points(
    db: &Db,
    cache: &SeriesCache,
    items: Vec<(String, Labels, i64, f64)>,
) -> anyhow::Result<()> {
    let cache = cache.clone();
    db.write(move |c| {
        let tx = c.transaction()?;
        let mut pending = Pending::default();
        for (name, l, ts, v) in &items {
            if let Some(id) = cache.resolve(&tx, name, l, false, &mut pending)? {
                tx.prepare_cached("INSERT INTO points(series_id, ts, value) VALUES (?1, ?2, ?3)")?
                    .execute(params![id, ts, v])?;
            }
        }
        tx.commit()?;
        cache.publish(pending);
        Ok::<_, anyhow::Error>(())
    })
    .await
}
