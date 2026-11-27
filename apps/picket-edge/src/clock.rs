//! Wall-clock synchronisation (README §2 Clocks): decisions that need wall-clock time (here: the
//! log retention window) wait until the clock is synchronised. Durations use the monotonic clock
//! everywhere else.
//!
//! Without `unsafe` there is no `adjtimex`, so the edge asks the system: systemd-timesyncd's
//! `/run/systemd/timesync/synchronized`, then `timedatectl show -p NTPSynchronized`, which
//! reports the kernel's sync state whatever NTP client sets it. Unknown counts as not
//! synchronised, which only ever keeps records longer. There are no "clock sanity" heuristics
//! (such as a minimum year).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::time::Duration;

use tokio::sync::watch;

const TIMESYNCD_FLAG: &str = "/run/systemd/timesync/synchronized";

/// The synchronisation flag, refreshed by [`Clock::run`].
pub struct Clock {
    synced: AtomicBool,
    /// Nothing probes: tests and `PICKET_CLOCK_SYNCED` pin the answer (tests may [`Clock::set`]
    /// it).
    pinned: bool,
    /// Every change of the flag, for work that waits for a synchronised clock (README §2 Clocks;
    /// edge.md §12: a temporary-allow re-check skipped while unsynchronised runs once it syncs).
    changes: watch::Sender<bool>,
}

impl Clock {
    pub fn new() -> Arc<Self> {
        Self::with(false, false)
    }

    /// A clock nothing probes (tests, and `PICKET_CLOCK_SYNCED`); only [`Clock::set`] changes it.
    pub fn fixed(synced: bool) -> Arc<Self> {
        Self::with(synced, true)
    }

    fn with(synced: bool, pinned: bool) -> Arc<Self> {
        Arc::new(Self {
            synced: AtomicBool::new(synced),
            pinned,
            changes: watch::channel(synced).0,
        })
    }

    /// The flag, sequentially consistent with [`Clock::set`]: work skipped on an unsynchronised
    /// clock pairs it with a flag of its own (edge.md §12: the bypass re-check stores `skipped`,
    /// then reads this; the task that follows the clock reads this, then swaps `skipped`), and
    /// that store-then-load handshake needs both sides SeqCst, or each can miss the other's write
    /// (ARM64 reorders a later relaxed load before an earlier store) and the re-check never runs.
    pub fn synced(&self) -> bool {
        self.synced.load(SeqCst)
    }

    /// Records the state (the probe; tests), telling subscribers when it changed.
    pub fn set(&self, synced: bool) {
        self.synced.store(synced, SeqCst);
        self.changes
            .send_if_modified(|v| std::mem::replace(v, synced) != synced);
    }

    /// The state's changes ([`watch::Receiver::changed`] wakes on each).
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.changes.subscribe()
    }

    /// Probes now (blocking: may run `timedatectl`).
    pub fn probe_now(&self) -> bool {
        if self.pinned {
            return self.synced();
        }
        let s = probe();
        self.set(s);
        s
    }

    /// Re-probes every minute until synchronised, then every 10 minutes.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        if self.pinned {
            return Ok(());
        }
        loop {
            let me = Arc::clone(&self);
            let s = tokio::task::spawn_blocking(move || me.probe_now())
                .await
                .unwrap_or(false);
            tokio::time::sleep(if s {
                Duration::from_secs(600)
            } else {
                Duration::from_secs(60)
            })
            .await;
        }
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
    if let Some(mut so) = child.stdout.take() {
        use std::io::Read;
        let _ = (&mut so).take(64).read_to_string(&mut out);
    }
    out.trim() == "yes"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribers_hear_each_change() {
        let c = Clock::fixed(false);
        let mut rx = c.subscribe();
        c.set(false);
        assert!(!rx.has_changed().unwrap(), "no change, no wake-up");
        c.set(true);
        assert!(rx.has_changed().unwrap());
        assert!(*rx.borrow_and_update() && c.synced() && c.probe_now());
    }
}
