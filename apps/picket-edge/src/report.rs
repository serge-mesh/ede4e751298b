//! `hello` and `heartbeat` contents (api.md §3).

use std::sync::Arc;

use picket_api::session::{CgroupMem, CpuMs, Have, Heartbeat, Hello, InProgress, LogsInfo, SpoolInfo};
use picket_api::time::Timestamp;

use crate::convergence::have_configs;
use crate::edge::Edge;
use crate::hooks::HelperSnapshot;
use crate::sysinfo;

/// `have`: the config, bundle heads and verdict-set heads on disk, active first then previous,
/// plus what is in progress and the newest fetched ETag.
pub fn have(edge: &Edge) -> Have {
    let state = edge.state.get();
    let active = edge.active();
    let conv = edge.convergence.load();
    let hp = edge.hooks.have();
    Have {
        config: have_configs(&active, &state),
        bundles: hp.bundles(),
        verdict_sets: hp.verdict_sets(),
        release: Some(picket_api::VERSION.to_owned()),
        in_progress: InProgress {
            config: conv.in_progress.clone(),
            bundles: hp.in_progress_bundles(),
            verdict_sets: hp.in_progress_verdict_sets(),
        },
        fetched: conv.fetched.clone(),
    }
}

/// The first message of a session.
pub fn hello(edge: &Edge) -> Hello {
    let (mem_total, mem_available) = sysinfo::meminfo();
    let state = edge.state.get();
    Hello {
        edge_version: picket_api::VERSION.to_owned(),
        arch: sysinfo::arch().to_owned(),
        os: sysinfo::os(),
        kernel: sysinfo::kernel(),
        platform: edge.platform.as_str().to_owned(),
        firmware: edge.firmware.clone(),
        mem_total,
        mem_available,
        allowed_binds: edge.local.allowed_binds.clone(),
        updates_enabled: edge.local.updates_enabled,
        have: have(edge),
        boot: edge.boot.clone(),
        starts: state.starts,
        conditions: edge.conditions.snapshot(),
        applied: state.applied.clone(),
        update: state.update.clone(),
        cert_roots: edge.dns.certs.served_roots(),
    }
}

/// The helper's CPU time as a counter across helper restarts: the growth seen per pid, added up.
#[derive(Default)]
pub struct HelperCpu {
    last: Option<(u32, u64)>,
    total: u64,
}

impl HelperCpu {
    pub fn observe(&mut self, s: &HelperSnapshot) -> Option<u64> {
        let (pid, raw) = (s.pid?, s.cpu_ms?);
        match self.last {
            Some((p, prev)) if p == pid => self.total = self.total.saturating_add(raw.saturating_sub(prev)),
            Some(_) => self.total = self.total.saturating_add(raw),
            None => {}
        }
        self.last = Some((pid, raw));
        Some(self.total)
    }
}

/// A heartbeat now. Counters are running totals since start.
pub async fn heartbeat(edge: &Edge, helper_cpu: &mut HelperCpu) -> Heartbeat {
    // The helper is another process: bound the wait so heartbeats keep flowing without it.
    let helper = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        edge.hooks.helper_probe().snapshot(),
    )
    .await
    .unwrap_or_default();
    let state = edge.state.get();
    let status = edge.log_control.status.load();
    let (_, mem_available) = sysinfo::meminfo();
    Heartbeat {
        ts: Timestamp::now(),
        boot: edge.boot.clone(),
        up_ms: edge.up_ms(),
        metrics: {
            let mut m = edge.metrics.snapshot();
            // Lookup clients keep their own running totals (picket-lookup).
            m.lookups.extend(edge.dns.lookups.metrics());
            m
        },
        spool: SpoolInfo {
            bytes: status.spool_bytes,
            oldest_ts: status.oldest_ts,
        },
        logs: LogsInfo {
            dropped: edge.logs.dropped().snapshot(),
        },
        rss: sysinfo::rss(None),
        mem_available,
        cpu_ms: CpuMs {
            edge: sysinfo::cpu_ms(None),
            helper: helper_cpu.observe(&helper),
        },
        cgroup_mem: CgroupMem {
            unit: sysinfo::cgroup_memory(),
            helper_rss: helper.rss,
        },
        disk: edge.storage.disk_snapshot(),
        fw: helper.fw,
        versions: edge.active().versions.as_deref().cloned(),
        ready_version: state.ready_version.clone(),
        have: have(edge),
        conditions: edge.conditions.snapshot(),
        applied: state.applied.clone(),
        update: state.update.clone(),
        cert_roots: edge.dns.certs.served_roots(),
    }
}

/// For `status`: a snapshot shared with the admin socket.
pub fn arc_hello(edge: &Arc<Edge>) -> Hello {
    hello(edge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_cpu_survives_restarts() {
        let mut c = HelperCpu::default();
        let s = |pid, cpu| HelperSnapshot {
            pid: Some(pid),
            cpu_ms: Some(cpu),
            ..Default::default()
        };
        assert_eq!(c.observe(&s(10, 500)), Some(0));
        assert_eq!(c.observe(&s(10, 700)), Some(200));
        assert_eq!(
            c.observe(&s(11, 50)),
            Some(250),
            "a new pid counts from its start"
        );
        assert_eq!(c.observe(&s(11, 80)), Some(280));
        assert_eq!(c.observe(&HelperSnapshot::default()), None);
    }
}
