//! Core's own resource gauges and work series (core.md §10 "Core"; §12 System → Resources, Work),
//! sampled every 30 s with core's presence sample:
//!
//! - `core_rss` (bytes, from `/proc/self/status` `VmRSS`) and `core_cpu_ms` (CPU time from
//!   `/proc/self/stat`, `utime + stime`, counted as the milliseconds used since the previous
//!   sample, so a chart step's value over its length is the CPU share; 100 % is one core);
//! - `core_disk_used` (the data directory's size, walked with a bound) and `core_disk_free`
//!   (`statvfs` free bytes on its filesystem);
//! - `db_bytes{db}`: `core`, `metrics` and `logs` (all partitions), each with its WAL;
//! - `queue_depth{queue}` for the `light` and `heavy` lanes (the other queues sample their own);
//! - `job_ms{kind}`: a histogram of the job durations that ended since the previous sample, one
//!   row per kind and sample ([`JobTimes`], fed by the heavy lane's job reports and the light
//!   lane's timed jobs).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use picket_api::Histogram;

use crate::state::AppState;

/// Directory entries the data-directory walk visits at most (README §2 Bounded): past it the
/// size counts what it saw.
pub const MAX_WALK: usize = 500_000;
/// Job kinds one sample keeps at most; others count under `other`.
pub const MAX_KINDS: usize = 64;

/// Job durations per kind: since the last sample (the `job_ms` series, core.md §10), and since
/// core started (the Prometheus export, api.md §7: "`job_ms` as totals since core started").
#[derive(Default)]
pub struct JobTimes {
    inner: Mutex<BTreeMap<String, Histogram>>,
    totals: Mutex<BTreeMap<String, Histogram>>,
}

/// One histogram per kind, at most [`MAX_KINDS`] (others under `other`).
fn record_in(m: &mut BTreeMap<String, Histogram>, kind: &str, ms: u64) {
    let key = if m.contains_key(kind) || m.len() < MAX_KINDS {
        kind.to_string()
    } else {
        "other".to_string()
    };
    m.entry(key).or_default().record(ms.saturating_mul(1000), ms);
}

impl JobTimes {
    /// Records one ended job of `kind` that took `ms`.
    pub fn record(&self, kind: &str, ms: u64) {
        if let Ok(mut g) = self.inner.lock() {
            record_in(&mut g, kind, ms);
        }
        if let Ok(mut g) = self.totals.lock() {
            record_in(&mut g, kind, ms);
        }
    }

    /// The histograms since core started.
    pub fn totals(&self) -> BTreeMap<String, Histogram> {
        self.totals.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// The histograms since the previous call.
    pub fn take(&self) -> BTreeMap<String, Histogram> {
        self.inner
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }
}

/// `VmRSS` in bytes.
pub fn rss_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib.saturating_mul(1024))
}

/// `utime + stime` in milliseconds.
pub fn cpu_ms() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/stat").ok()?;
    // The command name may hold spaces: the fields after it start past the last ')'.
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // Fields 14 and 15 of the full line are 12 and 13 here (state is field 3).
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    let hz = rustix::param::clock_ticks_per_second().max(1);
    Some((utime + stime).saturating_mul(1000) / hz)
}

/// The size of the files under `dir`, without following links.
pub fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut seen = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > MAX_WALK {
                return total;
            }
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else if m.is_file() {
                total = total.saturating_add(m.len());
            }
        }
    }
    total
}

fn file_len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// A database file with its WAL.
fn db_with_wal(p: &Path) -> u64 {
    let wal = p.with_file_name(format!(
        "{}-wal",
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    file_len(p) + file_len(&wal)
}

/// One resource sample.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sample {
    pub rss: Option<u64>,
    pub cpu_ms: Option<u64>,
    pub disk_used: u64,
    pub disk_free: Option<u64>,
    pub db: BTreeMap<&'static str, u64>,
}

/// Reads one sample of the data directory `dir` (blocking: run it off the runtime).
pub fn sample(dir: &Path) -> Sample {
    let logs: u64 = std::fs::read_dir(dir.join("logs"))
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".db"))
                .map(|e| db_with_wal(&e.path()))
                .sum()
        })
        .unwrap_or(0);
    let mut db = BTreeMap::new();
    db.insert("core", db_with_wal(&dir.join("core.db")));
    db.insert("metrics", db_with_wal(&dir.join("metrics.db")));
    db.insert("logs", logs);
    Sample {
        rss: rss_bytes(),
        cpu_ms: cpu_ms(),
        disk_used: dir_bytes(dir),
        disk_free: crate::run::disk_space(dir).ok().map(|(free, _)| free),
        db,
    }
}

/// The CPU time at the previous sample.
#[derive(Default)]
pub struct CpuBase(Mutex<Option<u64>>);

/// Writes one sample's gauges, the CPU time used since the previous one, the lanes' depths and
/// the job durations since the previous sample.
pub async fn write(state: &AppState, base: &CpuBase) {
    let dir = state.data_dir.clone();
    let Ok(s) = tokio::task::spawn_blocking(move || sample(&dir)).await else {
        return;
    };
    let l = |extra: &[(&str, &str)]| super::labels("", extra);
    let mut gauges: Vec<(String, super::Labels, f64)> = vec![
        ("core_disk_used".into(), l(&[]), s.disk_used as f64),
        (
            "queue_depth".into(),
            l(&[("queue", "light")]),
            state.scheduler.light.depth() as f64,
        ),
        (
            "queue_depth".into(),
            l(&[("queue", "heavy")]),
            state.scheduler.heavy.depth() as f64,
        ),
    ];
    if let Some(r) = s.rss {
        gauges.push(("core_rss".into(), l(&[]), r as f64));
    }
    if let Some(f) = s.disk_free {
        gauges.push(("core_disk_free".into(), l(&[]), f as f64));
    }
    for (name, bytes) in &s.db {
        gauges.push(("db_bytes".into(), l(&[("db", name)]), *bytes as f64));
    }
    state.metrics.gauges(&state.metrics_db, gauges).await;
    if let Some(now) = s.cpu_ms {
        let prev = base.0.lock().ok().and_then(|mut g| g.replace(now));
        if let Some(prev) = prev {
            let used = now.saturating_sub(prev);
            state
                .metrics
                .count(
                    &state.metrics_db,
                    vec![(
                        "core_cpu_ms".into(),
                        l(&[]),
                        jiff::Timestamp::now().as_millisecond(),
                        used as f64,
                    )],
                )
                .await;
        }
    }
    let jobs = state.metrics.jobs.take();
    if !jobs.is_empty() {
        let ts = jiff::Timestamp::now().as_millisecond();
        let items: Vec<(String, super::Labels, i64, Histogram)> = jobs
            .into_iter()
            .map(|(kind, mut h)| {
                h.trim();
                ("job_ms".to_string(), l(&[("kind", &kind)]), ts, h)
            })
            .collect();
        if let Err(e) = super::store::write_histograms(&state.metrics_db, &state.metrics.series, items).await
        {
            tracing::warn!(error = %e, "cannot store job durations");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_times_reset_per_sample() {
        let j = JobTimes::default();
        j.record("compile", 1500);
        j.record("compile", 20);
        j.record("ingest", 3);
        let t = j.take();
        assert_eq!(t["compile"].count, 2);
        assert_eq!(t["compile"].sum, 1520);
        assert!(j.take().is_empty());
        assert_eq!(j.totals()["compile"].count, 2, "totals since start stay");
    }

    #[test]
    fn process_figures_read() {
        assert!(rss_bytes().unwrap() > 0);
        assert!(cpu_ms().is_some());
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("logs")).unwrap();
        std::fs::write(d.path().join("logs/2026-11-24T10.db"), b"12345").unwrap();
        std::fs::write(d.path().join("core.db"), b"123").unwrap();
        std::fs::write(d.path().join("core.db-wal"), b"12").unwrap();
        let s = sample(d.path());
        assert_eq!(s.db["core"], 5);
        assert_eq!(s.db["logs"], 5);
        assert_eq!(s.disk_used, 10);
        assert!(s.disk_free.is_some());
    }
}
