//! systemd notification (edge.md §3, §16): `READY=1` at startup step 3 (`Type=notify`), and the
//! watchdog (`WatchdogSec=30`).
//!
//! Until listeners are bound (waiting for a config, the SSD or core) a runtime tick feeds the
//! watchdog, so a deliberate wait never triggers a restart; a stalled runtime still does. Once
//! listeners are bound, the listener manager calls [`Watchdog::use_pipeline`]
//! ([`crate::dns::listeners`]), and the DNS data path calls [`Watchdog::pipeline_passed`] after
//! each internal test query (a name the edge answers itself, sent through a listener's socket)
//! made it through ([`crate::dns::pipeline::self_test`]); `WATCHDOG=1` is then sent only while
//! those keep passing.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use sd_notify::NotifyState;

/// `READY=1` plus a status line. A no-op outside systemd.
pub fn notify_ready(status: &str) {
    let _ = sd_notify::notify(&[NotifyState::Ready, NotifyState::Status(status)]);
}

/// `STATUS=…`.
pub fn notify_status(status: &str) {
    let _ = sd_notify::notify(&[NotifyState::Status(status)]);
}

/// `STOPPING=1`.
pub fn notify_stopping() {
    let _ = sd_notify::notify(&[NotifyState::Stopping]);
}

/// The watchdog feeder and its mode switch.
pub struct Watchdog {
    started: Instant,
    pipeline: AtomicBool,
    /// Milliseconds since `started` of the last passing test query.
    last_pass_ms: AtomicU64,
    /// Watchdog pings sent (for tests and status).
    pub pings: AtomicU64,
}

impl Watchdog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            pipeline: AtomicBool::new(false),
            last_pass_ms: AtomicU64::new(0),
            pings: AtomicU64::new(0),
        })
    }

    /// From now on, feed only after passing test queries.
    pub fn use_pipeline(&self) {
        self.pipeline_passed();
        self.pipeline.store(true, Relaxed);
    }

    /// Back to the runtime tick (listeners unbound again).
    pub fn use_tick(&self) {
        self.pipeline.store(false, Relaxed);
    }

    pub fn in_pipeline_mode(&self) -> bool {
        self.pipeline.load(Relaxed)
    }

    /// The internal test query passed.
    pub fn pipeline_passed(&self) {
        self.last_pass_ms.store(
            picket_api::duration::as_millis_u64(self.started.elapsed()),
            Relaxed,
        );
    }

    /// Whether a ping is due now, given the watchdog interval.
    pub fn should_feed(&self, interval: Duration) -> bool {
        if !self.pipeline.load(Relaxed) {
            return true;
        }
        let now = picket_api::duration::as_millis_u64(self.started.elapsed());
        now.saturating_sub(self.last_pass_ms.load(Relaxed)) < picket_api::duration::as_millis_u64(interval)
    }

    /// Feeds the watchdog at half its interval, if systemd set one.
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let Some(interval) = sd_notify::watchdog_enabled() else {
            return Ok(());
        };
        let period = (interval / 2).max(Duration::from_millis(100));
        let mut tick = tokio::time::interval(period);
        loop {
            tick.tick().await;
            if self.should_feed(interval) {
                let _ = sd_notify::notify(&[NotifyState::Watchdog]);
                self.pings.fetch_add(1, Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_mode_always_feeds_and_pipeline_mode_needs_passes() {
        let w = Watchdog::new();
        let iv = Duration::from_millis(50);
        assert!(w.should_feed(iv));
        w.use_pipeline();
        assert!(w.should_feed(iv), "a fresh switch counts as a pass");
        std::thread::sleep(Duration::from_millis(80));
        assert!(!w.should_feed(iv), "no recent pass, no ping");
        w.pipeline_passed();
        assert!(w.should_feed(iv));
        w.use_tick();
        std::thread::sleep(Duration::from_millis(80));
        assert!(w.should_feed(iv));
    }
}
