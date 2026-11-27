//! UniFi firmware (edge-unifi.md §1): the first line of `/usr/lib/version` (≤ 128 bytes, read
//! without running anything) goes to `hello` as `firmware`; null elsewhere.
//!
//! **Self-check after a firmware change:** the edge keeps the firmware string it last ran on in
//! `state.json`. On a different one it checks, within the SSD's 10-minute window, every
//! registered [`SelfCheck`] (helper `rules_ok` and the redirect from [`crate::firewall`]; listeners
//! bound and the SSD are here), each bounded in time. From the window's end, while any fails, it holds
//! `firmware_check_failed` (detail `{from, to, failed}`), re-checking every 10 minutes and at each
//! start. The last result is kept in `state.json`, so after a restart a failed result holds the
//! condition from the start until a check passes. The new string is recorded only once every
//! check passes.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use picket_api::session::condition_kind;
use picket_api::time::Timestamp;

use crate::edge::Edge;
use crate::fsutil;
use crate::hooks::SelfCheck;
use crate::paths::HostPlatform;
use crate::state::FirmwareCheck;
use crate::storage::SsdState;

pub const VERSION_FILE: &str = "/usr/lib/version";
pub const MAX_FIRMWARE: usize = 128;

/// The firmware string on UniFi, else `None`.
pub fn read(platform: HostPlatform, path: &Path) -> Option<String> {
    if platform != HostPlatform::Unifi {
        return None;
    }
    parse(&fsutil::read_bounded(path, 64 << 10).ok()?)
}

/// The firmware string in the contents of `/usr/lib/version` (untrusted UniFi state, README §2):
/// its first line, control characters removed, trimmed, at most [`MAX_FIRMWARE`] bytes; `None`
/// when that leaves nothing.
pub fn parse(bytes: &[u8]) -> Option<String> {
    let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    let first = &first[..first.len().min(MAX_FIRMWARE)];
    let s = String::from_utf8_lossy(first);
    let s: String = s
        .trim_end_matches('\r')
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    // A lossy cut may have grown the text (U+FFFD); keep the 128-byte bound.
    Some(
        crate::diag::truncate(s.trim(), MAX_FIRMWARE)
            .trim_end_matches('…')
            .trim()
            .to_owned(),
    )
    .filter(|s| !s.is_empty())
}

/// The edge's listeners are bound: `ready_version` is set this run (edge.md §3 step 6). The
/// DNS data path may install a finer check under the same name.
pub struct ListenersCheck;

#[async_trait]
impl SelfCheck for ListenersCheck {
    fn name(&self) -> &'static str {
        "listeners"
    }
    async fn passes(&self, edge: &Edge) -> bool {
        edge.state.get().ready_version.is_some()
    }
}

/// The SSD passes its checks (only with `ssd_dir`).
pub struct SsdCheck;

#[async_trait]
impl SelfCheck for SsdCheck {
    fn name(&self) -> &'static str {
        "ssd"
    }
    fn applies(&self, edge: &Edge) -> bool {
        edge.storage.ssd.is_some()
    }
    async fn passes(&self, edge: &Edge) -> bool {
        edge.storage.ssd_state() == SsdState::Passing
    }
}

/// Self-check timing; tests shorten it.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    /// The SSD's window after start (10 min).
    pub window: Duration,
    /// How often to try inside the window.
    pub during: Duration,
    /// How often to re-check after the window while failing (10 min).
    pub after: Duration,
    /// How long one check may take; one that hangs (a helper that never answers) fails.
    pub check_timeout: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            window: crate::storage::START_WINDOW,
            during: Duration::from_secs(60),
            after: Duration::from_secs(600),
            check_timeout: Duration::from_secs(30),
        }
    }
}

/// Runs the registered checks that apply, each bounded by `timeout`; returns the names that
/// failed.
pub async fn run_checks(edge: &Edge, timeout: Duration) -> Vec<String> {
    let mut failed = vec![];
    for c in edge.hooks.self_checks().iter() {
        if c.applies(edge)
            && !tokio::time::timeout(timeout, c.passes(edge))
                .await
                .unwrap_or(false)
        {
            failed.push(c.name().to_owned());
        }
    }
    failed
}

fn detail(from: Option<&str>, to: &str, failed: &[String]) -> serde_json::Value {
    serde_json::json!({"from": from, "to": to, "failed": failed})
}

/// The self-check task.
pub async fn self_check(edge: Arc<Edge>, t: Timings) -> anyhow::Result<()> {
    let Some(current) = edge.firmware.clone() else {
        return Ok(());
    };
    let fw = edge.state.get().firmware.clone();
    let prev = match fw.last.clone() {
        // First start ever: nothing to compare with.
        None => {
            let c = current.clone();
            edge.state
                .update_async(move |s| s.firmware.last = Some(c))
                .await?;
            return Ok(());
        }
        Some(l) if l == current => {
            if fw.check.is_some() {
                edge.state.update_async(|s| s.firmware.check = None).await?;
            }
            return Ok(());
        }
        Some(l) => l,
    };
    tracing::warn!("firmware changed from {prev} to {current}; running the self-checks");
    // A failed result from before this start holds the condition from the start.
    if let Some(c) = fw
        .check
        .as_ref()
        .filter(|c| c.to == current && !c.failed.is_empty())
    {
        edge.conditions.set(
            condition_kind::FIRMWARE_CHECK_FAILED,
            None,
            Some(detail(c.from.as_deref(), &c.to, &c.failed)),
        );
    }
    let window_end = edge.started + t.window;
    loop {
        let failed = run_checks(&edge, t.check_timeout).await;
        if failed.is_empty() {
            tracing::warn!("firmware self-checks passed on {current}");
            let c = current.clone();
            edge.state
                .update_async(move |s| {
                    s.firmware.last = Some(c);
                    s.firmware.check = None;
                })
                .await?;
            edge.conditions.clear(condition_kind::FIRMWARE_CHECK_FAILED, None);
            return Ok(());
        }
        let now = std::time::Instant::now();
        if now >= window_end {
            let check = FirmwareCheck {
                from: Some(prev.clone()),
                to: current.clone(),
                failed: failed.clone(),
                at: Timestamp::now(),
            };
            let changed = edge
                .state
                .get()
                .firmware
                .check
                .as_ref()
                .map(|c| (&c.to, &c.failed))
                != Some((&check.to, &check.failed));
            if changed {
                edge.state
                    .update_async(move |s| s.firmware.check = Some(check))
                    .await?;
            }
            edge.conditions.set(
                condition_kind::FIRMWARE_CHECK_FAILED,
                None,
                Some(detail(Some(&prev), &current, &failed)),
            );
            tokio::time::sleep(t.after).await;
        } else {
            tokio::time::sleep(t.during.min(window_end - now)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_first_line_bounded_and_only_on_unifi() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("version");
        std::fs::write(&p, "UCGF.ipq9574.v6.0.17.1234.250101.0000\nsecond line\n").unwrap();
        assert_eq!(
            read(HostPlatform::Unifi, &p).as_deref(),
            Some("UCGF.ipq9574.v6.0.17.1234.250101.0000")
        );
        assert_eq!(read(HostPlatform::Debian, &p), None);
        std::fs::write(&p, "x".repeat(500)).unwrap();
        assert!(read(HostPlatform::Unifi, &p).unwrap().len() <= MAX_FIRMWARE);
        std::fs::write(&p, "é".repeat(100)).unwrap();
        assert!(read(HostPlatform::Unifi, &p).unwrap().len() <= MAX_FIRMWARE);
        assert_eq!(read(HostPlatform::Unifi, &d.path().join("missing")), None);
    }

    #[test]
    fn parse_keeps_one_clean_bounded_line() {
        assert_eq!(
            parse(b"UCGF.ipq9574.v6.0.17\r\nx").as_deref(),
            Some("UCGF.ipq9574.v6.0.17")
        );
        for bad in [&b""[..], b"\n", b"  \t\x01 \n", b"\xff"] {
            let p = parse(bad);
            assert!(
                p.as_deref()
                    .is_none_or(|s| !s.is_empty() && !s.chars().any(char::is_control))
            );
        }
        let long = [b"\xe2\x82\xac".repeat(60), b"\xff\xfe".repeat(40)].concat();
        let p = parse(&long).unwrap();
        assert!(p.len() <= MAX_FIRMWARE, "{}", p.len());
    }
}
