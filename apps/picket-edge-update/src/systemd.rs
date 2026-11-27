//! `systemctl`, as the updater uses it. Every verb that could start, stop or restart a unit
//! refuses the updater's own service (edge.md §14, "Never its own service"; edge-unifi.md §2,
//! "The update service is left alone").

use std::time::Duration;

use crate::error::{Error, Result};
use crate::system::System;
use crate::units::UPDATE_SERVICE;

/// The `systemctl` wrapper.
pub struct Systemd<'a> {
    pub sys: &'a dyn System,
}

/// A rollback step is retried with backoff, at most 3 times (edge.md §14 step 4).
pub const RETRIES: u32 = 3;
const FIRST_BACKOFF: Duration = Duration::from_secs(1);

/// True when `is-active` output means the unit is running (anything but `inactive` or `failed`,
/// edge.md §14 step 4).
pub fn is_running(state: &str) -> bool {
    !matches!(state, "inactive" | "failed" | "")
}

impl Systemd<'_> {
    fn run(&self, args: &[&str]) -> Result<()> {
        let out = self
            .sys
            .systemctl(args)
            .map_err(|e| Error::msg(format!("systemctl {}: {e}", args.join(" "))))?;
        if !out.success() {
            return Err(Error::msg(format!(
                "systemctl {} failed ({:?}): {}",
                args.join(" "),
                out.status,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    /// Refuses verbs that would start, stop or restart the updater's own service.
    fn guard(&self, verb: &str, unit: &str) -> Result<()> {
        if unit == UPDATE_SERVICE {
            return Err(Error::msg(format!(
                "refusing to {verb} {UPDATE_SERVICE}: only its path unit starts it"
            )));
        }
        Ok(())
    }

    pub fn daemon_reload(&self) -> Result<()> {
        self.run(&["daemon-reload"])
    }

    /// `systemctl is-enabled`'s word (`enabled`, `disabled`, `static`, `masked`, …; empty if
    /// the unit is unknown).
    pub fn is_enabled(&self, unit: &str) -> Result<String> {
        let out = self
            .sys
            .systemctl(&["is-enabled", unit])
            .map_err(|e| Error::msg(format!("systemctl is-enabled {unit}: {e}")))?;
        Ok(out.word().to_string())
    }

    /// `systemctl is-active`'s word (`active`, `inactive`, `failed`, `activating`, …).
    pub fn is_active(&self, unit: &str) -> Result<String> {
        let out = self
            .sys
            .systemctl(&["is-active", unit])
            .map_err(|e| Error::msg(format!("systemctl is-active {unit}: {e}")))?;
        Ok(out.word().to_string())
    }

    pub fn enable(&self, unit: &str) -> Result<()> {
        self.run(&["enable", unit])
    }

    /// Re-enables a unit so its links match its current `[Install]` section.
    pub fn reenable(&self, unit: &str) -> Result<()> {
        self.run(&["reenable", unit])
    }

    pub fn disable(&self, unit: &str) -> Result<()> {
        self.guard("disable", unit)?;
        self.run(&["disable", unit])
    }

    /// `disable --now`: returns once the unit has stopped.
    pub fn disable_now(&self, unit: &str) -> Result<()> {
        self.guard("stop", unit)?;
        self.run(&["disable", "--now", unit])
    }

    pub fn start(&self, unit: &str) -> Result<()> {
        self.guard("start", unit)?;
        self.run(&["start", unit])
    }

    pub fn stop(&self, unit: &str) -> Result<()> {
        self.guard("stop", unit)?;
        self.run(&["stop", unit])
    }

    pub fn restart(&self, unit: &str) -> Result<()> {
        self.guard("restart", unit)?;
        self.run(&["restart", unit])
    }

    /// Runs a step, retrying a failure with backoff (1 s, 2 s, 4 s) at most [`RETRIES`] times.
    pub fn retry<T>(&self, what: &str, mut f: impl FnMut() -> Result<T>) -> Result<T> {
        let mut delay = FIRST_BACKOFF;
        let mut attempt = 0;
        loop {
            match f() {
                Ok(v) => return Ok(v),
                Err(e) if attempt < RETRIES => {
                    crate::log(&format!("{what} failed ({e}); retrying in {} s", delay.as_secs()));
                    self.sys.sleep(delay);
                    delay *= 2;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
}
