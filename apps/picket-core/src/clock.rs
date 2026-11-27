//! Wall-clock synchronisation (README §2 Clocks): decisions that need wall-clock time wait
//! until it is synchronised; durations use the monotonic clock.
//!
//! Core's time decisions wait for [`Clock::synced`]: those that discard by age (retention
//! cutoffs, storage.md §4; feed entry expiry; verdict-set rebuilds) and those that stamp or
//! schedule by the wall clock (async lookups, re-checks and self-tests, core.md §7; DNSSEC
//! validations and cross-checks, §8). Without `unsafe` there is no `adjtimex`, so core asks the
//! system, as the edge does: systemd-timesyncd's `/run/systemd/timesync/synchronized`, then
//! `timedatectl show -p NTPSynchronized`, which reports the kernel's sync state whatever NTP
//! client sets it. Unknown counts as not synchronised: data is kept longer and that work waits
//! (nothing is lost, only delayed). `PICKET_CLOCK_SYNCED=1` states
//! that the host keeps the clock synchronised where neither can be read (the container image,
//! pipelines.md §10: "the host must be NTP-synced").

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

const TIMESYNCD_FLAG: &str = "/run/systemd/timesync/synchronized";
/// The environment override (`1`: synchronised).
pub const ENV_SYNCED: &str = "PICKET_CLOCK_SYNCED";

/// The synchronisation flag, refreshed by [`Clock::spawn`].
#[derive(Debug, Default)]
pub struct Clock {
    synced: AtomicBool,
    /// Pinned by the environment or a test: never probed.
    pinned: AtomicBool,
}

impl Clock {
    /// Not synchronised until probed, unless `PICKET_CLOCK_SYNCED=1`.
    pub fn new() -> Self {
        let c = Self::default();
        if std::env::var(ENV_SYNCED).is_ok_and(|v| v == "1") {
            c.pin(true);
        }
        c
    }

    pub fn synced(&self) -> bool {
        self.synced.load(Relaxed)
    }

    /// Fixes the answer (tests, and the environment override).
    pub fn pin(&self, synced: bool) {
        self.pinned.store(true, Relaxed);
        self.synced.store(synced, Relaxed);
    }

    /// Probes now (blocking: may run `timedatectl`).
    pub fn probe_now(&self) -> bool {
        if self.pinned.load(Relaxed) {
            return self.synced();
        }
        let s = probe();
        if !self.pinned.load(Relaxed) {
            self.synced.store(s, Relaxed);
        }
        s
    }

    /// Probes at once, then every minute until synchronised and every 10 minutes after.
    pub fn spawn(self: Arc<Self>, shutdown: CancellationToken) {
        tokio::spawn(async move {
            loop {
                let me = self.clone();
                let s = tokio::task::spawn_blocking(move || me.probe_now())
                    .await
                    .unwrap_or(false);
                let wait = if s {
                    Duration::from_secs(600)
                } else {
                    Duration::from_secs(60)
                };
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(wait) => {}
                }
            }
        });
    }
}

fn probe() -> bool {
    if std::path::Path::new(TIMESYNCD_FLAG).exists() {
        return true;
    }
    timedatectl()
}

fn timedatectl() -> bool {
    use std::process::{Command, Stdio};
    let child = Command::new("timedatectl")
        .args(["show", "-p", "NTPSynchronized", "--value"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return false };
    // Bounded: give it 3 s, then kill it.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
    let mut out = String::new();
    if let Some(so) = child.stdout.take() {
        use std::io::Read;
        let _ = so.take(64).read_to_string(&mut out);
    }
    out.trim() == "yes"
}

/// When a condition started holding, as a wall-clock time for the alert engine, measured with
/// the monotonic clock: `now_wall` minus the monotonic time since `start` (README §2 Clocks: a
/// wall-clock step doesn't change how long the condition has held).
pub fn held_since(
    start: Option<tokio::time::Instant>,
    now_mono: tokio::time::Instant,
    now_wall: jiff::Timestamp,
) -> Option<jiff::Timestamp> {
    let held = now_mono.saturating_duration_since(start?);
    Some(now_wall - jiff::SignedDuration::try_from(held).unwrap_or(jiff::SignedDuration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_never_probes() {
        let c = Clock::default();
        assert!(!c.synced());
        c.pin(true);
        assert!(c.probe_now());
        c.pin(false);
        assert!(!c.probe_now());
    }

    #[test]
    fn held_time_follows_the_monotonic_clock() {
        let start = tokio::time::Instant::now();
        let later = start + Duration::from_secs(90);
        let wall = jiff::Timestamp::now();
        // However the wall clock stepped, the condition has held for 90 s.
        for jump in [-3600i64, 0, 7200] {
            let now_wall = wall + jiff::SignedDuration::from_secs(jump);
            let since = held_since(Some(start), later, now_wall).unwrap();
            assert_eq!((now_wall - since).as_secs(), 90);
        }
        assert!(held_since(None, later, wall).is_none());
    }
}
