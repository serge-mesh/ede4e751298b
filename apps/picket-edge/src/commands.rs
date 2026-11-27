//! The admin commands this build answers (edge.md §15): `status`, `allows.list`,
//! `allows.revoke`, `flush`, `update` (and `explain`, registered by the DNS data path).

use std::sync::Arc;

use serde_json::{Value, json};

use crate::admin::{AdminError, AdminRegistry};
use crate::edge::Edge;
use crate::report;
use crate::storage::SsdState;
use crate::sysinfo;

/// Registers the built-in commands.
pub fn register(reg: &AdminRegistry) {
    reg.register("status", |edge, _args| async move { Ok(status(&edge)) });
    reg.register("allows.list", |edge, _args| async move {
        serde_json::to_value(edge.allows.list()).map_err(AdminError::internal)
    });
    reg.register("allows.revoke", |edge, args| async move {
        let id = args
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or_else(|| AdminError::bad_args("allows.revoke needs an id"))?
            .to_owned();
        let ids = vec![id.clone()];
        // An IP allow's set entries follow at once (edge.md §12).
        let b = Arc::clone(&edge.bypass);
        let ended = b.revoke(&edge, &ids, "cli").await.map_err(AdminError::internal)?;
        if ended.is_empty() {
            return Err(AdminError::new("not_found", format!("no active allow {id}")));
        }
        Ok(json!({"revoked": id}))
    });
    reg.register("update", |edge, args| async move {
        let install = !args.get("check").and_then(Value::as_bool).unwrap_or(true);
        crate::release::update_command(&edge, install)
            .await
            .map_err(AdminError::internal)
    });
    reg.register("flush", |edge, args| async move {
        let dns = args.get("dns").and_then(Value::as_bool).unwrap_or(false);
        let lookups = args.get("lookups").and_then(Value::as_str).map(str::to_owned);
        let (dns, lookups) = if !dns && lookups.is_none() {
            (true, Some("*".to_owned()))
        } else {
            (dns, lookups)
        };
        let h = edge.hooks.requests();
        if dns {
            h.flush_dns(&edge).await.map_err(AdminError::internal)?;
        }
        match lookups.as_deref() {
            Some("*") => h.flush_all_lookups(&edge).await.map_err(AdminError::internal)?,
            Some(p) => h.flush_lookups(&edge, p).await.map_err(AdminError::internal)?,
            None => {}
        }
        Ok(json!({"dns": dns, "lookups": lookups}))
    });
}

/// `picket-edge status`: versions, core session, listeners, bundles, memory, spool, firewall.
pub fn status(edge: &Edge) -> Value {
    let state = edge.state.get();
    let active = edge.active();
    let have = report::have(edge);
    let ship = edge.log_control.status.load();
    let (mem_total, mem_available) = sysinfo::meminfo();
    let ssd = match edge.storage.ssd_state() {
        SsdState::NotConfigured => json!(null),
        SsdState::Unknown => json!({"state": "unknown"}),
        SsdState::Passing => json!({"state": "passing"}),
        SsdState::Failing(f) => json!({"state": "failing", "reason": f.as_str()}),
    };
    json!({
        "edge_version": picket_api::VERSION,
        "boot": edge.boot,
        "up_ms": edge.up_ms(),
        "platform": edge.platform.as_str(),
        "firmware": edge.firmware,
        "name": edge.identity.name,
        "fingerprint": edge.identity.fingerprint,
        "paths": {
            "config": edge.config_path,
            "data_dir": edge.layout.root,
            "runtime_dir": edge.runtime_dir,
            "ssd_dir": edge.local.ssd_dir,
        },
        "versions": active.versions.as_deref(),
        "config": active.config_version.as_deref().map(picket_api::ids::short_id),
        "ready_version": state.ready_version,
        "core": &**edge.session.load(),
        "convergence": &**edge.convergence.load(),
        "listeners": &*edge.dns.listeners.status(),
        "upstreams": edge.dns.pool.status(),
        "dns_cache": {
            "entries": edge.dns.resolver.cache.len(),
            "bytes": edge.dns.resolver.cache.weight(),
        },
        "lookup_providers": edge.dns.lookups.ids(),
        "bundles": have.bundles,
        "verdict_sets": have.verdict_sets,
        "memory": {
            "rss": sysinfo::rss(None),
            "mem_total": mem_total,
            "mem_available": mem_available,
            "cgroup": sysinfo::cgroup_memory(),
        },
        "spool": {
            "mode": ship.mode,
            "buffered": ship.buffered,
            "bytes": ship.spool_bytes,
            "segments": ship.spool_segments,
            "oldest_ts": ship.oldest_ts.map(|t| picket_api::time::format_micros(&t)),
            "dropped": edge.logs.dropped().snapshot(),
        },
        "firewall": if edge.fw.needed() {
            let st = edge.fw.state.load();
            json!({
                "connected": st.connected,
                "rules_ok": st.rules_ok,
                "helper_version": st.helper_version,
                "entries": edge.fw.live_count(),
            })
        } else {
            json!(null)
        },
        "ssd": ssd,
        "disk": edge.storage.disk_snapshot(),
        "neighbours": {
            "available": edge.neighbours.available(),
            "addresses": edge.neighbours.snapshot().by_ip.len(),
            "devices": edge.neighbours.snapshot().by_mac.len(),
        },
        "watchdog": if edge.watchdog.in_pipeline_mode() { "pipeline" } else { "runtime_tick" },
        "conditions": edge.conditions.snapshot(),
        "applied": state.applied,
        "update": state.update,
        "starts": state.starts,
        "commands": edge.admin.names(),
    })
}
