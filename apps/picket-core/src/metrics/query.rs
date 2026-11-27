//! Charts from `metrics.db` (`GET /api/ui/v1/metrics`, api.md §7; core.md §10 Charts).
//!
//! - Windows `1h`, `6h`, `24h`, `72h`, ending now, in fixed steps of 30 s, 2 min, 5 min and
//!   15 min (≤ 300 points). A window longer than the metrics retention is refused (`422`).
//! - **Heartbeat series:** a heartbeat covers the time since the edge's previous heartbeat of
//!   the same `boot`, or, for a boot's first, since the process started (`ts − up_ms`). A
//!   counter's count over that time is the difference of the two totals (a boot's first total
//!   counts from 0), spread over the steps the time overlaps in proportion, and summed across
//!   edges. Histogram buckets are spread and summed the same way; `.p50` and `.p99` are read from
//!   each step's sum, interpolated within a bucket, in the field's unit. A gauge counts in each
//!   step its time overlaps (the overlap-weighted mean per edge, summed across edges). A step no
//!   heartbeat covers is a gap (`null`), never a zero. Each series' own last value before the
//!   window, with its boot, is its baseline (an optional value may be missing from the edge's
//!   last heartbeat before the window).
//! - **Core's series** are binned at their event or sample time: a step in which core ran and
//!   counted nothing is zero; a step with no core sample is a gap. `convergence_lag_s` is never
//!   summed: each edge and kind keeps its own line.

use std::collections::{BTreeMap, HashMap};

use picket_api::Histogram;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use super::{Kind, Labels, kind_of, map_label};
use crate::error::{CoreError, CoreResult};

/// A chart window and its step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub secs: i64,
    pub step_s: i64,
}

impl Window {
    pub fn parse(s: &str) -> Option<Self> {
        let (secs, step_s) = match s {
            "1h" => (3600, 30),
            "6h" => (6 * 3600, 120),
            "24h" => (24 * 3600, 300),
            "72h" => (72 * 3600, 900),
            _ => return None,
        };
        Some(Self { secs, step_s })
    }
}

/// Which edges a chart covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeSel {
    /// Summed across edges.
    All,
    /// One line per edge.
    Each,
    One(String),
}

impl EdgeSel {
    pub fn parse(s: Option<&str>) -> Self {
        match s {
            None | Some("all") | Some("") => Self::All,
            Some("each") => Self::Each,
            Some(e) => Self::One(e.to_string()),
        }
    }
}

/// One chart line.
#[derive(Clone, Debug, Serialize, PartialEq, schemars::JsonSchema)]
pub struct Line {
    pub name: String,
    pub labels: Labels,
    /// The edge, or null for a line summed across edges and for a core series without one.
    pub edge: Option<String>,
    /// `[step start (Unix s), value or null]`.
    pub points: Vec<(i64, Option<f64>)>,
}

/// The reply of `GET metrics`.
#[derive(Clone, Debug, Serialize, PartialEq, schemars::JsonSchema)]
pub struct Chart {
    pub step_s: i64,
    pub series: Vec<Line>,
}

/// A parsed series request: the stored name, label filters and a percentile.
#[derive(Clone, Debug, PartialEq)]
pub struct SeriesReq {
    pub requested: String,
    pub name: String,
    pub filters: Labels,
    pub pct: Option<f64>,
}

/// Parses a series name as api.md §7 writes them: field paths with map keys
/// (`upstream.<id>.queries`, `logs.dropped.<reason>`), or without them for every key
/// (`upstream.queries`), core series by name, and `.p50`/`.p99` on a histogram.
pub fn parse_series(s: &str) -> Option<SeriesReq> {
    if s.is_empty() || s.len() > 256 {
        return None;
    }
    let (base, pct) = match s.rsplit_once('.') {
        Some((b, "p50")) => (b, Some(0.5)),
        Some((b, "p99")) => (b, Some(0.99)),
        _ => (s, None),
    };
    let done = |name: &str, filters: Labels| -> Option<SeriesReq> {
        let k = kind_of(name)?;
        if pct.is_some() != matches!(k, Kind::Histogram | Kind::CoreHistogram) {
            return None;
        }
        Some(SeriesReq {
            requested: s.to_string(),
            name: name.to_string(),
            filters,
            pct,
        })
    };
    if kind_of(base).is_some() {
        return done(base, Labels::new());
    }
    let parts: Vec<&str> = base.split('.').collect();
    match parts.as_slice() {
        ["logs", "dropped", reason] => done(
            "logs.dropped",
            Labels::from([("reason".into(), (*reason).into())]),
        ),
        // `<family>.<key>.<field>`, else (no such field) one reason of every upstream's
        // `invalid` or `scrubbed`: `upstream.invalid.queries` is upstream `invalid`'s queries.
        [family, key, field] if map_label(family).is_some() => {
            let label = map_label(family)?;
            done(
                &format!("{family}.{field}"),
                Labels::from([(label.into(), (*key).into())]),
            )
            .or_else(|| match (*family, *key) {
                ("upstream", by @ ("invalid" | "scrubbed")) => done(
                    &format!("upstream.{by}"),
                    Labels::from([("reason".into(), (*field).into())]),
                ),
                _ => None,
            })
        }
        ["upstream", key, field @ ("invalid" | "scrubbed"), reason] => done(
            &format!("upstream.{field}"),
            Labels::from([
                ("upstream".into(), (*key).into()),
                ("reason".into(), (*reason).into()),
            ]),
        ),
        _ => None,
    }
}

/// One time interval a stored value covers, with what it adds.
struct Span {
    from_ms: i64,
    to_ms: i64,
    add: Add,
}

enum Add {
    Count(f64),
    Gauge(f64),
    Hist(Histogram),
}

/// The grid of steps for a window ending at `now_ms`.
#[derive(Clone, Copy)]
struct Grid {
    start_ms: i64,
    step_ms: i64,
    n: usize,
}

impl Grid {
    fn new(w: Window, now_ms: i64) -> Self {
        let step_ms = w.step_s * 1000;
        let end = now_ms - now_ms.rem_euclid(step_ms) + step_ms;
        let n = crate::util::nonneg_usize(w.secs / w.step_s);
        Self {
            start_ms: end - crate::util::sat_i64(n) * step_ms,
            step_ms,
            n,
        }
    }

    fn end_ms(&self) -> i64 {
        self.start_ms + crate::util::sat_i64(self.n) * self.step_ms
    }

    /// `(step index, overlap fraction of the span)` for each step `(from, to]` overlaps.
    fn spread(&self, from: i64, to: i64) -> Vec<(usize, f64)> {
        let mut out = Vec::new();
        if to <= self.start_ms || from >= self.end_ms() {
            if to > self.start_ms && to <= self.end_ms() && from >= to {
                // An empty span sits where it ends.
            } else {
                return out;
            }
        }
        if to <= from {
            let i = crate::util::nonneg_usize((to - 1 - self.start_ms).max(0) / self.step_ms);
            if i < self.n && to > self.start_ms {
                out.push((i, 1.0));
            }
            return out;
        }
        let len = (to - from) as f64;
        let first = crate::util::nonneg_usize((from.max(self.start_ms) - self.start_ms) / self.step_ms);
        for i in first..self.n {
            let s = self.start_ms + crate::util::sat_i64(i) * self.step_ms;
            let e = s + self.step_ms;
            if s >= to {
                break;
            }
            let ov = (e.min(to) - s.max(from)) as f64;
            if ov > 0.0 {
                out.push((i, ov / len));
            }
        }
        out
    }
}

/// An edge's samples: `ts → (boot, up_ms)`, from its newest sample before `from_ms` on.
fn samples(
    c: &Connection,
    edge: &str,
    from_ms: i64,
    to_ms: i64,
) -> rusqlite::Result<Vec<(i64, String, i64)>> {
    let mut out: Vec<(i64, String, i64)> = Vec::new();
    let mut st = c.prepare_cached(
        "SELECT ts, boot, up_ms FROM samples WHERE edge_id = ?1 AND ts < ?2 ORDER BY ts DESC LIMIT 1",
    )?;
    if let Some(r) = st
        .query_map(params![edge, from_ms], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .next()
    {
        out.push(r?);
    }
    let mut st = c.prepare_cached(
        "SELECT ts, boot, up_ms FROM samples WHERE edge_id = ?1 AND ts >= ?2 AND ts <= ?3 ORDER BY ts",
    )?;
    for r in st.query_map(params![edge, from_ms, to_ms], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })? {
        out.push(r?);
    }
    Ok(out)
}

fn points(c: &Connection, id: i64, from_ms: i64, to_ms: i64) -> rusqlite::Result<Vec<(i64, f64)>> {
    let mut out = Vec::new();
    let mut st = c.prepare_cached(
        "SELECT ts, value FROM points WHERE series_id = ?1 AND ts < ?2 ORDER BY ts DESC LIMIT 1",
    )?;
    if let Some(r) = st
        .query_map(params![id, from_ms], |r| Ok((r.get(0)?, r.get(1)?)))?
        .next()
    {
        out.push(r?);
    }
    let mut st = c.prepare_cached(
        "SELECT ts, value FROM points WHERE series_id = ?1 AND ts >= ?2 AND ts <= ?3 ORDER BY ts",
    )?;
    for r in st.query_map(params![id, from_ms, to_ms], |r| Ok((r.get(0)?, r.get(1)?)))? {
        out.push(r?);
    }
    Ok(out)
}

/// A heartbeat series' baseline: its own newest value before `from_ms`, whichever heartbeat
/// last carried it, with that heartbeat's boot (core.md §10: each series' last sample before
/// the window). An optional value (no helper status, no `ssd_dir`, a map key) may be missing
/// from the edge's last heartbeats before the window, so the edge's last sample isn't enough.
fn baseline_point(
    c: &Connection,
    id: i64,
    edge: &str,
    from_ms: i64,
) -> rusqlite::Result<Option<(i64, f64, String)>> {
    c.prepare_cached(
        "SELECT p.ts, p.value, s.boot FROM points p JOIN samples s ON s.edge_id = ?2 AND s.ts = p.ts
         WHERE p.series_id = ?1 AND p.ts < ?3 ORDER BY p.ts DESC LIMIT 1",
    )?
    .query_row(params![id, edge, from_ms], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })
    .optional()
}

fn in_window_points(c: &Connection, id: i64, from_ms: i64, to_ms: i64) -> rusqlite::Result<Vec<(i64, f64)>> {
    let mut st = c.prepare_cached(
        "SELECT ts, value FROM points WHERE series_id = ?1 AND ts >= ?2 AND ts <= ?3 ORDER BY ts",
    )?;
    st.query_map(params![id, from_ms, to_ms], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect()
}

fn hist_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, Histogram)> {
    let buckets: Vec<u64> = serde_json::from_str(&r.get::<_, String>(1)?).unwrap_or_default();
    Ok((
        r.get(0)?,
        Histogram {
            buckets,
            sum: crate::util::f64_to_u64(r.get::<_, f64>(2)?.max(0.0)),
            count: crate::util::nonneg(r.get(3)?),
        },
    ))
}

/// [`baseline_point`] for a histogram series.
fn baseline_hist(
    c: &Connection,
    id: i64,
    edge: &str,
    from_ms: i64,
) -> rusqlite::Result<Option<(i64, Histogram, String)>> {
    c.prepare_cached(
        "SELECT h.ts, h.buckets, h.sum, h.count, s.boot FROM histograms h JOIN samples s ON s.edge_id = ?2 AND s.ts = h.ts
         WHERE h.series_id = ?1 AND h.ts < ?3 ORDER BY h.ts DESC LIMIT 1",
    )?
    .query_row(params![id, edge, from_ms], |r| {
        let (ts, h) = hist_row(r)?;
        Ok((ts, h, r.get(4)?))
    })
    .optional()
}

fn in_window_hists(
    c: &Connection,
    id: i64,
    from_ms: i64,
    to_ms: i64,
) -> rusqlite::Result<Vec<(i64, Histogram)>> {
    let mut st = c.prepare_cached(
        "SELECT ts, buckets, sum, count FROM histograms WHERE series_id = ?1 AND ts >= ?2 AND ts <= ?3 ORDER BY ts",
    )?;
    st.query_map(params![id, from_ms, to_ms], hist_row)?.collect()
}

/// The time a heartbeat value at `ts` covers: from the previous sample of the same boot, or
/// from the process start for a boot's first sample.
fn covered(samples: &[(i64, String, i64)], ts: i64) -> Option<(i64, String)> {
    let i = samples.binary_search_by_key(&ts, |s| s.0).ok()?;
    let (_, boot, up) = &samples[i];
    match samples[..i].iter().rev().find(|s| s.1 == *boot) {
        Some(prev) => Some((prev.0, boot.clone())),
        None => Some((ts - up, boot.clone())),
    }
}

/// The spans one heartbeat series of one edge adds. A running total's count is its difference
/// from the series' previous value of the same boot (its own baseline before the window),
/// covering the time since that value; with none in the boot it counts from 0 over the time the
/// heartbeat covers (api.md §3 Running totals).
fn heartbeat_spans(
    c: &Connection,
    kind: Kind,
    id: i64,
    edge: &str,
    grid: Grid,
) -> rusqlite::Result<Vec<Span>> {
    let from = grid.start_ms;
    let to = grid.end_ms();
    let smp = samples(c, edge, from, to)?;
    let mut spans = Vec::new();
    match kind {
        Kind::Gauge => {
            for (ts, v) in in_window_points(c, id, from, to)? {
                let Some((start, _)) = covered(&smp, ts) else {
                    continue;
                };
                spans.push(Span {
                    from_ms: start,
                    to_ms: ts,
                    add: Add::Gauge(v),
                });
            }
        }
        Kind::Counter => {
            let mut prev: Option<(i64, f64, String)> = baseline_point(c, id, edge, from)?;
            for (ts, v) in in_window_points(c, id, from, to)? {
                let Some((covers, boot)) = covered(&smp, ts) else {
                    continue;
                };
                let (start, count) = match prev.as_ref().filter(|p| p.2 == boot) {
                    Some((pts, pv, _)) => (*pts, (v - pv).max(0.0)),
                    None => (covers, v),
                };
                spans.push(Span {
                    from_ms: start,
                    to_ms: ts,
                    add: Add::Count(count),
                });
                prev = Some((ts, v, boot));
            }
        }
        Kind::Histogram => {
            let mut prev: Option<(i64, Histogram, String)> = baseline_hist(c, id, edge, from)?;
            for (ts, h) in in_window_hists(c, id, from, to)? {
                let Some((covers, boot)) = covered(&smp, ts) else {
                    continue;
                };
                let (start, d) = match prev.as_ref().filter(|p| p.2 == boot) {
                    Some((pts, ph, _)) => (*pts, h.delta(ph)),
                    None => (covers, h.clone()),
                };
                spans.push(Span {
                    from_ms: start,
                    to_ms: ts,
                    add: Add::Hist(d),
                });
                prev = Some((ts, h, boot));
            }
        }
        _ => {}
    }
    Ok(spans)
}

/// Accumulates spans into steps.
#[derive(Clone)]
struct Acc {
    counts: Vec<Option<f64>>,
    gauge_w: Vec<f64>,
    gauge_v: Vec<f64>,
    /// Bucket counts per step, fractional: a span's buckets are spread in proportion.
    hists: Vec<Option<Vec<f64>>>,
}

impl Acc {
    fn new(n: usize) -> Self {
        Self {
            counts: vec![None; n],
            gauge_w: vec![0.0; n],
            gauge_v: vec![0.0; n],
            hists: vec![None; n],
        }
    }

    fn add(&mut self, grid: &Grid, s: &Span) {
        for (i, frac) in grid.spread(s.from_ms, s.to_ms) {
            match &s.add {
                Add::Count(c) => *self.counts[i].get_or_insert(0.0) += c * frac,
                Add::Gauge(v) => {
                    let ov = frac * (s.to_ms - s.from_ms).max(1) as f64;
                    self.gauge_w[i] += ov;
                    self.gauge_v[i] += v * ov;
                }
                Add::Hist(h) => {
                    let acc = self.hists[i].get_or_insert_with(|| vec![0.0; picket_api::histogram::BUCKETS]);
                    for (b, slot) in acc.iter_mut().enumerate() {
                        *slot += h.bucket(b) as f64 * frac;
                    }
                }
            }
        }
    }

    /// One edge's gauge means, as values to sum across edges.
    fn gauge_values(&self) -> Vec<Option<f64>> {
        self.gauge_w
            .iter()
            .zip(&self.gauge_v)
            .map(|(w, v)| (*w > 0.0).then(|| v / w))
            .collect()
    }
}

/// The `q` quantile of fractional bucket counts, in µs, interpolated within a bucket as
/// [`Histogram::quantile_us`] does; the overflow bucket reports the last finite bound.
fn quantile(buckets: &[f64], q: f64) -> Option<f64> {
    use picket_api::histogram::{BOUNDS_US, BUCKETS};
    let total: f64 = buckets.iter().sum();
    if total <= 0.0 {
        return None;
    }
    // As the integer form: at least the first observation (or the whole of a fraction of one).
    let target = (q.clamp(0.0, 1.0) * total).max(total.min(1.0));
    let mut seen = 0.0;
    for (i, c) in buckets.iter().enumerate().take(BUCKETS) {
        if *c <= 0.0 {
            continue;
        }
        if seen + c >= target {
            let lo = if i == 0 { 0.0 } else { BOUNDS_US[i - 1] as f64 };
            let Some(hi) = picket_api::histogram::bound_us(i) else {
                return Some(BOUNDS_US[BUCKETS - 2] as f64);
            };
            let frac = ((target - seen) / c).clamp(0.0, 1.0);
            return Some(lo + (hi as f64 - lo) * frac);
        }
        seen += c;
    }
    Some(BOUNDS_US[BUCKETS - 2] as f64)
}

fn sum_into(total: &mut [Option<f64>], add: &[Option<f64>]) {
    for (t, a) in total.iter_mut().zip(add) {
        if let Some(a) = a {
            *t.get_or_insert(0.0) += a;
        }
    }
}

/// Builds a chart. `retention_s` is the metrics retention (a longer window is refused).
pub fn chart(
    c: &Connection,
    series: &[String],
    w: Window,
    edges: &EdgeSel,
    now_ms: i64,
    retention_s: i64,
) -> CoreResult<Chart> {
    if w.secs > retention_s {
        return Err(CoreError::Invalid(
            "the window is longer than the metrics retention".into(),
        ));
    }
    if series.len() > 32 {
        return Err(CoreError::Invalid("at most 32 series per chart".into()));
    }
    let grid = Grid::new(w, now_ms);
    let mut lines = Vec::new();
    for s in series {
        let req = parse_series(s).ok_or_else(|| CoreError::Invalid(format!("unknown series {s:?}")))?;
        let kind = kind_of(&req.name).unwrap_or(Kind::Counter);
        // Candidate series rows.
        let rows: Vec<(i64, Labels)> = {
            let mut st = c.prepare_cached("SELECT id, labels_json FROM series WHERE name = ?1")?;
            st.query_map([&req.name], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
                .filter_map(Result::ok)
                .filter_map(|(id, lj)| serde_json::from_str::<Labels>(&lj).ok().map(|l| (id, l)))
                .filter(|(_, l)| req.filters.iter().all(|(k, v)| l.get(k) == Some(v)))
                .filter(|(_, l)| match edges {
                    EdgeSel::One(e) => l.get("edge") == Some(e),
                    _ => true,
                })
                .take(10_000)
                .collect()
        };
        // Group: per label set without `edge` (summed), or with it (each / lags / one edge).
        let keep_edge = matches!(edges, EdgeSel::Each | EdgeSel::One(_)) || kind == Kind::CoreGauge;
        let mut groups: BTreeMap<Labels, Vec<(i64, Labels)>> = BTreeMap::new();
        for (id, l) in rows {
            let mut key = l.clone();
            if !keep_edge {
                key.remove("edge");
            }
            groups.entry(key).or_default().push((id, l));
        }
        let mut core: Option<Vec<bool>> = None;
        for (key, members) in groups {
            let mut values: Vec<Option<f64>> = vec![None; grid.n];
            let mut hist_total: Vec<Option<Vec<f64>>> = vec![None; grid.n];
            for (id, l) in &members {
                let edge = l.get("edge").cloned().unwrap_or_default();
                match kind {
                    Kind::Counter | Kind::Gauge | Kind::Histogram => {
                        let mut acc = Acc::new(grid.n);
                        for sp in heartbeat_spans(c, kind, *id, &edge, grid)? {
                            acc.add(&grid, &sp);
                        }
                        match kind {
                            Kind::Counter => sum_into(&mut values, &acc.counts),
                            Kind::Gauge => sum_into(&mut values, &acc.gauge_values()),
                            _ => {
                                for (t, h) in hist_total.iter_mut().zip(acc.hists) {
                                    if let Some(h) = h {
                                        let t = t
                                            .get_or_insert_with(|| vec![0.0; picket_api::histogram::BUCKETS]);
                                        for (a, b) in t.iter_mut().zip(h) {
                                            *a += b;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Kind::CoreHistogram => {
                        // One row per sample, holding what ended since the previous one: summed
                        // per step; a step without jobs has no percentile (core.md §10).
                        for (ts, h) in in_window_hists(c, *id, grid.start_ms, grid.end_ms())? {
                            if ts < grid.start_ms {
                                continue;
                            }
                            let i = crate::util::nonneg_usize((ts - grid.start_ms) / grid.step_ms);
                            let Some(t) = hist_total.get_mut(i) else { continue };
                            let t = t.get_or_insert_with(|| vec![0.0; picket_api::histogram::BUCKETS]);
                            for (k, a) in t.iter_mut().enumerate() {
                                *a += h.bucket(k) as f64;
                            }
                        }
                    }
                    Kind::CoreCounter | Kind::CoreGauge => {
                        let core = match &core {
                            Some(c) => c.clone(),
                            None => {
                                let up = core_steps(c, grid)?;
                                core = Some(up.clone());
                                up
                            }
                        };
                        let pts = points(c, *id, grid.start_ms, grid.end_ms())?;
                        let mut v: Vec<Option<f64>> = core.iter().map(|up| up.then_some(0.0)).collect();
                        let mut last: HashMap<usize, f64> = HashMap::new();
                        for (ts, x) in pts {
                            if ts < grid.start_ms {
                                continue;
                            }
                            let i = crate::util::nonneg_usize((ts - grid.start_ms) / grid.step_ms);
                            if i >= grid.n {
                                continue;
                            }
                            if kind == Kind::CoreCounter {
                                *v[i].get_or_insert(0.0) += x;
                            } else {
                                last.insert(i, x);
                            }
                        }
                        if kind == Kind::CoreGauge {
                            v = (0..grid.n).map(|i| last.get(&i).copied()).collect();
                        }
                        sum_into(&mut values, &v);
                    }
                }
            }
            if let Some(p) = req.pct {
                let ms = req.name.ends_with("_ms");
                values = hist_total
                    .iter()
                    .map(|h| {
                        h.as_ref()
                            .and_then(|h| quantile(h, p))
                            .map(|us| if ms { us / 1000.0 } else { us })
                    })
                    .collect();
            }
            let edge = key.get("edge").cloned();
            let mut labels = key.clone();
            labels.remove("edge");
            lines.push(Line {
                name: req.requested.clone(),
                labels,
                edge,
                points: values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| ((grid.start_ms + crate::util::sat_i64(i) * grid.step_ms) / 1000, v))
                    .collect(),
            });
        }
    }
    Ok(Chart {
        step_s: w.step_s,
        series: lines,
    })
}

/// Which steps core ran in (it has a presence sample there).
fn core_steps(c: &Connection, grid: Grid) -> rusqlite::Result<Vec<bool>> {
    let mut up = vec![false; grid.n];
    let mut st = c.prepare_cached("SELECT ts FROM samples WHERE edge_id = '' AND ts >= ?1 AND ts < ?2")?;
    for ts in st.query_map(params![grid.start_ms, grid.end_ms()], |r| r.get::<_, i64>(0))? {
        let i = crate::util::nonneg_usize((ts? - grid.start_ms) / grid.step_ms);
        if i < grid.n {
            up[i] = true;
        }
    }
    Ok(up)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn series_names() {
        let r = parse_series("upstream.cf-dot.queries").unwrap();
        assert_eq!(r.name, "upstream.queries");
        assert_eq!(r.filters.get("upstream").map(String::as_str), Some("cf-dot"));
        assert_eq!(parse_series("latency_us.p99").unwrap().pct, Some(0.99));
        assert!(
            parse_series("latency_us").is_none(),
            "a histogram is charted by percentile"
        );
        assert!(
            parse_series("queries.p50").is_none(),
            "a counter has no percentile"
        );
        assert_eq!(parse_series("logs.dropped.too_old").unwrap().name, "logs.dropped");
        assert_eq!(
            parse_series("lookups.q9.call_ms.p50").unwrap().name,
            "lookups.call_ms"
        );
        assert_eq!(
            parse_series("by_decision.block").unwrap().name,
            "by_decision.block"
        );
        assert!(parse_series("convergence_lag_s").is_some());
        let r = parse_series("upstream.cf.scrubbed.ttl").unwrap();
        assert_eq!(r.name, "upstream.scrubbed");
        assert_eq!(r.filters["upstream"], "cf");
        assert_eq!(r.filters["reason"], "ttl");
        assert_eq!(
            parse_series("upstream.scrubbed.ttl").unwrap().filters,
            Labels::from([("reason".into(), "ttl".into())])
        );
        assert_eq!(
            parse_series("upstream.invalid.bad_id").unwrap().name,
            "upstream.invalid"
        );
        let q = parse_series("upstream.invalid.queries").unwrap();
        assert_eq!(
            (q.name.as_str(), q.filters["upstream"].as_str()),
            ("upstream.queries", "invalid"),
            "an upstream named invalid"
        );
        assert_eq!(
            parse_series("upstream.cf.scrubbed").unwrap().name,
            "upstream.scrubbed"
        );
        assert!(parse_series("analysis_skipped").is_some());
        assert!(parse_series("nope").is_none());
    }

    #[test]
    fn fractional_quantiles_match_the_histogram_ones() {
        let mut h = Histogram::default();
        for us in [5u64, 10, 11, 100, 1000, 5000, 5000, 70_000_000] {
            h.record(us, us);
        }
        let f: Vec<f64> = (0..picket_api::histogram::BUCKETS)
            .map(|i| h.bucket(i) as f64)
            .collect();
        for q in [0.1, 0.5, 0.9, 0.99] {
            assert_eq!(quantile(&f, q), h.quantile_us(q), "{q}");
        }
        assert!(quantile(&[0.0; 3], 0.5).is_none());
    }

    /// A fresh `metrics.db` and a connection to it.
    fn metrics_db() -> (tempfile::TempDir, Connection) {
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::metrics(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::METRICS).unwrap();
        let c = crate::db::open_connection(&opts, 1024).unwrap();
        (d, c)
    }

    fn series(c: &Connection, name: &str) -> i64 {
        c.execute(
            "INSERT INTO series(name, labels_json) VALUES (?1, '{\"edge\":\"e1\"}')",
            [name],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    fn total(chart: &Chart) -> f64 {
        chart.series[0].points.iter().filter_map(|p| p.1).sum()
    }

    #[test]
    fn a_window_starting_mid_boot_counts_from_each_series_own_baseline() {
        // core.md §10 Charts (review A10; build-and-test.md §5 Metrics): a boot that started
        // before the window is charted from each series' last value before it. fw.rejects grows
        // by 10 every 30 s, but the edge's last heartbeat before the window had no fw (a failed
        // helper status call): the window must still count only its own growth, never the
        // running total since the boot.
        let (_d, c) = metrics_db();
        let fw = series(&c, "fw.rejects");
        let q = series(&c, "queries");
        let now: i64 = 1_800_000_000_000;
        let grid = Grid::new(Window::parse("1h").unwrap(), now);
        // Heartbeats every 30 s, off the step grid (so one interval straddles the window's
        // start), from 2 h before the window to its end.
        let boot_start = grid.start_ms - 2 * 3_600_000 - 7_000;
        let mut ts = boot_start + 30_000;
        let mut n = 0i64;
        while ts <= now {
            n += 1;
            c.execute(
                "INSERT INTO samples(edge_id, ts, boot, up_ms) VALUES ('e1', ?1, 'b1', ?2)",
                rusqlite::params![ts, ts - boot_start],
            )
            .unwrap();
            c.execute(
                "INSERT INTO points(series_id, ts, value) VALUES (?1, ?2, ?3)",
                rusqlite::params![q, ts, (n * 10) as f64],
            )
            .unwrap();
            // The last heartbeat before the window has no fw.
            let last_before = ts < grid.start_ms && ts + 30_000 >= grid.start_ms;
            if !last_before {
                c.execute(
                    "INSERT INTO points(series_id, ts, value) VALUES (?1, ?2, ?3)",
                    rusqlite::params![fw, ts, (n * 10) as f64],
                )
                .unwrap();
            }
            ts += 30_000;
        }
        let chart = |name: &str| {
            super::chart(
                &c,
                &[name.to_string()],
                Window::parse("1h").unwrap(),
                &EdgeSel::All,
                now,
                72 * 3600,
            )
            .unwrap()
        };
        // 1 h of 10 per 30 s: 1200, give or take the step the window starts in.
        let queries = total(&chart("queries"));
        assert!((1150.0..=1210.0).contains(&queries), "queries {queries}");
        let rejects = total(&chart("fw.rejects"));
        assert!((1150.0..=1210.0).contains(&rejects), "fw.rejects {rejects}");
    }

    #[test]
    fn spans_spread_in_proportion() {
        let g = Grid {
            start_ms: 0,
            step_ms: 1000,
            n: 4,
        };
        let s = g.spread(500, 2500);
        assert_eq!(s, vec![(0, 0.25), (1, 0.5), (2, 0.25)]);
        assert!(g.spread(5000, 6000).is_empty());
        assert_eq!(g.spread(-1000, 1000), vec![(0, 0.5)]);
    }
}
