//! Edges (core.md §4–§5): the registry (add by key, pending keys, approve, delete), edge status
//! for `/healthz`, and the runtime ([`Runtime`]):
//!
//! - [`hub`]: one session per edge, the pinned-key registry, each edge's live state;
//! - [`messages`]: decoding the edge's session messages (fuzzed);
//! - [`status`]: hello and heartbeat processing, conditions → alerts, the watcher, the UI view;
//! - [`render`] and [`publish`]: config objects, published on change with `changed`, pins and
//!   convergence tracking;
//! - [`requests`]: Update, flushes and revokes as config-object state;
//! - [`releases`]: the edge release bundled with core and its signature check.

pub mod hub;
pub mod messages;
pub mod publish;
pub mod releases;
pub mod render;
pub mod requests;
pub mod status;

use std::sync::Arc;

use jiff::Timestamp;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

use crate::config::model::{EdgeDef, EntityKind, PendingEdge};
use crate::config::{Actor, ConfigStore, Op, Outcome};
use crate::db::Db;
use crate::error::{CoreError, CoreResult};
pub use render::{EdgeState, Rendered, render};

/// A failed registry refresh is retried after this long, doubling up to [`REFRESH_RETRY_MAX`].
const REFRESH_RETRY_MIN: std::time::Duration = std::time::Duration::from_millis(250);
const REFRESH_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(10);

/// An edge is offline after 90 s without a heartbeat (core.md §4).
pub const OFFLINE_AFTER: std::time::Duration = std::time::Duration::from_secs(90);
/// At most this many pending keys are kept (oldest `last_seen` evicted).
pub const MAX_PENDING: usize = 256;
/// Pending keys kept per source (README §2, Bounded: a capped share each), an IPv4 address or
/// an IPv6 /64 ([`crate::net::share_key`]: one host has as many privacy addresses as it likes);
/// a new key from a source at its share replaces that source's oldest, so one host can't push
/// other hosts' keys out of the list. The spec leaves the value open.
pub const MAX_PENDING_PER_ADDR: usize = 8;

/// The edge side of core at runtime.
pub struct Runtime {
    pub hub: Arc<hub::Hub>,
    pub publisher: Arc<publish::Publisher>,
    pub releases: Arc<releases::Releases>,
    pub spikes: status::SpikeTracker,
    /// Per-edge CSR admission (`POST /v1/csr`).
    pub csr: crate::edge_api::api::CsrLimiter,
    /// When this core process started (monotonic): no edge can have been seen later than its
    /// stored last-seen time and earlier than this (core.md §9 `edge_offline`).
    started: tokio::time::Instant,
    /// Added to the time since start (tests stand for an older core process).
    backdate_ms: std::sync::atomic::AtomicU64,
}

impl Runtime {
    /// A runtime offering the release found under `release_dir`, verified against `release_keys`.
    pub fn new(release_dir: std::path::PathBuf, release_keys: Vec<String>) -> Self {
        Self {
            hub: Arc::new(hub::Hub::new()),
            publisher: Arc::new(publish::Publisher::default()),
            releases: Arc::new(releases::Releases::new(release_dir, release_keys)),
            spikes: status::SpikeTracker::default(),
            csr: Default::default(),
            started: tokio::time::Instant::now(),
            backdate_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// When this core process started, as a wall time measured back from `now` on the
    /// monotonic clock (README §2 Clocks).
    pub fn core_started_at(&self, now: Timestamp) -> Timestamp {
        let up = self.started.elapsed()
            + std::time::Duration::from_millis(self.backdate_ms.load(std::sync::atomic::Ordering::Relaxed));
        now - jiff::SignedDuration::try_from(up).unwrap_or(jiff::SignedDuration::ZERO)
    }

    /// Makes the process look `by` older (tests of `edge_offline` after a long uptime).
    pub fn backdate_start(&self, by: std::time::Duration) {
        self.backdate_ms.fetch_add(
            picket_api::duration::as_millis_u64(by),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Starts the edge runtime: loads the registry, live state and pin sequence, registers the
/// bundled release, renders every config once, then keeps configs, the registry and the
/// watcher running (core.md §4–§5).
pub async fn start(state: &crate::state::SharedState) -> anyhow::Result<()> {
    let rt = &state.edges;
    let (hub, publisher) = (rt.hub.clone(), rt.publisher.clone());
    state
        .db
        .read(move |c| {
            hub.refresh_registry(c)?;
            hub.load_live(c)?;
            publisher.load_served_seq(c)?;
            Ok::<_, anyhow::Error>(())
        })
        .await?;
    if let Err(e) = rt.releases.register(state).await {
        tracing::warn!(error = %format!("{e:#}"), "cannot register the bundled edge release");
    }
    // What each edge was last given, before the first render: budgets resolve against it
    // (README §2 Restarts; bundles.md §2 Budget).
    let restored = rt.publisher.restore(state).await?;
    tracing::debug!(edges = restored, "edge configs restored from storage");
    rt.publisher.render(state, None).await?;
    tokio::spawn(rt.publisher.clone().run(state.clone()));
    // Every configuration commit: refresh the registry (a deleted edge or replaced key loses its
    // session) and re-render. A refresh that fails is logged and retried (api.md §1 Key change:
    // the old key must not keep working until the next commit).
    let st = state.clone();
    tokio::spawn(async move {
        let mut rx = st.config.subscribe();
        loop {
            tokio::select! {
                _ = st.shutdown.cancelled() => return,
                r = rx.changed() => if r.is_err() { return },
            }
            let mut wait = REFRESH_RETRY_MIN;
            loop {
                let hub = st.edges.hub.clone();
                match st
                    .db
                    .read(move |c| Ok::<_, anyhow::Error>(hub.refresh_registry(c)?))
                    .await
                {
                    Ok(()) => break,
                    Err(e) => {
                        tracing::warn!(error = %format!("{e:#}"), retry_in = ?wait, "cannot refresh the edge key registry");
                        tokio::select! {
                            _ = st.shutdown.cancelled() => return,
                            _ = tokio::time::sleep(wait) => {}
                        }
                        wait = (wait * 2).min(REFRESH_RETRY_MAX);
                    }
                }
            }
            st.metrics.counters.retain_edges(&st.edges.hub.edge_ids());
            st.edges.publisher.trigger(None);
        }
    });
    status::spawn_watcher(state.clone());
    state.retention.register(Arc::new(EdgesRetention));
    state.retention.register(Arc::new(releases::ReleaseRetention));
    Ok(())
}

/// Ages out edge data (storage.md §4): published configs no edge uses, unpinned and not current,
/// the query-log window after they were last used; and edge boots.
///
/// **Edge boots** are kept while current, for the log window after core first saw a newer boot
/// (`superseded_at`), and while retained records, pending checks or kept examples reference
/// them. The records a superseded boot can still send are spooled ones, and the edge ages its
/// spool by the same window on its own clock (edge.md §11), so none arrives later than about the
/// window after `superseded_at`, whatever the clocks; [`BOOT_ARRIVAL_MARGIN`] covers their
/// delivery. But a record's partition is the hour of its own time, clamped only to core's clock
/// (README §2), so an edge clock ahead of core's puts the boot's last records in a partition
/// that outlives any margin past `superseded_at`. So past that time a boot stays while a
/// retained partition holds one of its query records (pending checks live in those records),
/// an `edge_events` row holds one of its events, or a kept wire-mismatch example names it.
pub struct EdgesRetention;

/// Added to the log window before a superseded boot's records can no longer arrive (module docs).
pub const BOOT_ARRIVAL_MARGIN: std::time::Duration = std::time::Duration::from_secs(3600);
/// Boots one step considers.
const BOOT_CHUNK: i64 = 1000;

impl crate::retention::RetentionHook for EdgesRetention {
    fn name(&self) -> &str {
        "edges"
    }

    fn step<'a>(
        &'a self,
        state: &'a crate::state::AppState,
    ) -> crate::scheduler::BoxFuture<'a, anyhow::Result<crate::scheduler::Step>> {
        Box::pin(async move {
            let window = state.settings().retention.query_logs.as_duration();
            let cutoff_at = crate::util::window_start(Timestamp::now(), window);
            let cutoff = crate::util::ts(&cutoff_at);
            let margin = jiff::SignedDuration::try_from(BOOT_ARRIVAL_MARGIN)
                .unwrap_or(jiff::SignedDuration::from_hours(1));
            let boots_cutoff = crate::util::ts(&picket_api::time::saturating_sub(cutoff_at, margin));
            let current: Vec<String> = state
                .edges
                .hub
                .edge_ids()
                .iter()
                .filter_map(|e| state.edges.publisher.current(e).map(|p| p.id.clone()))
                .collect();
            let current = serde_json::to_string(&current).unwrap_or_else(|_| "[]".into());
            let configs = state
                .db
                .write(move |c| {
                    Ok::<_, anyhow::Error>(c.execute(
                        "DELETE FROM edge_configs WHERE config_id IN (
                           SELECT cf.config_id FROM edge_configs cf
                           WHERE coalesce(cf.last_used_at, cf.published_at) < ?1
                             AND NOT EXISTS (SELECT 1 FROM edge_pins p WHERE p.kind = 'config' AND p.id = cf.config_id)
                             AND cf.config_id NOT IN (SELECT value FROM json_each(?2))
                           LIMIT 5000)",
                        params![cutoff, current],
                    )?)
                })
                .await?;
            // Boots past the window and the margin that no event or kept example names.
            let bc = boots_cutoff.clone();
            let candidates: Vec<(String, String)> = state
                .db
                .read(move |c| {
                    let mut st = c.prepare(
                        "SELECT b.edge_id, b.boot FROM edge_boots b
                         WHERE b.superseded_at IS NOT NULL AND b.superseded_at < ?1
                           AND NOT EXISTS (SELECT 1 FROM wire_examples w WHERE w.edge_id = b.edge_id AND w.boot = b.boot)
                           AND NOT EXISTS (SELECT 1 FROM edge_events v WHERE v.edge_id = b.edge_id AND v.boot = b.boot)
                         ORDER BY b.superseded_at LIMIT ?2",
                    )?;
                    Ok::<_, anyhow::Error>(
                        st.query_map(params![bc, BOOT_CHUNK], |r| Ok((r.get(0)?, r.get(1)?)))?
                            .collect::<rusqlite::Result<_>>()?,
                    )
                })
                .await?;
            let gone = if candidates.is_empty() {
                Vec::new()
            } else {
                // Those no retained partition holds a record of (`logs::LogRetention` keeps a
                // partition until its whole hour is past the window).
                let store = state.logs.writer().store().clone();
                tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, String)>> {
                    let mut left = candidates;
                    for (hour, _) in store.list()? {
                        if picket_api::time::saturating_add(hour, jiff::SignedDuration::from_hours(1))
                            <= cutoff_at
                            || left.is_empty()
                        {
                            continue;
                        }
                        // A partition retention deleted meanwhile holds nothing.
                        let Some(p) = store.open(&hour, false)? else {
                            continue;
                        };
                        let mut st = p
                            .conn
                            .prepare("SELECT 1 FROM events WHERE edge_id = ?1 AND boot = ?2 LIMIT 1")?;
                        let mut unseen = Vec::new();
                        for (e, b) in left {
                            if !st.exists(params![e, b])? {
                                unseen.push((e, b));
                            }
                        }
                        left = unseen;
                    }
                    Ok(left)
                })
                .await??
            };
            let boots = if gone.is_empty() {
                0
            } else {
                state
                    .db
                    .write(move |c| {
                        let tx = c.transaction()?;
                        let mut n = 0;
                        for (e, b) in &gone {
                            n += tx.execute(
                                "DELETE FROM edge_boots WHERE edge_id = ?1 AND boot = ?2
                                   AND superseded_at IS NOT NULL AND superseded_at < ?3
                                   AND NOT EXISTS (SELECT 1 FROM wire_examples w WHERE w.edge_id = ?1 AND w.boot = ?2)
                                   AND NOT EXISTS (SELECT 1 FROM edge_events v WHERE v.edge_id = ?1 AND v.boot = ?2)",
                                params![e, b, boots_cutoff],
                            )?;
                        }
                        tx.commit()?;
                        Ok::<_, anyhow::Error>(n)
                    })
                    .await?
            };
            // A full chunk of deleted boots may leave more; boots kept for their records are
            // looked at again next run (they age out with their partitions).
            Ok(if configs >= 5000 || crate::util::sat_i64(boots) >= BOOT_CHUNK {
                crate::scheduler::Step::More
            } else {
                crate::scheduler::Step::Done
            })
        })
    }
}

/// Checks and canonicalises a `SHA256:…` fingerprint.
pub fn normalize_key(key: &str) -> CoreResult<String> {
    let hash = picket_api::ids::parse_fingerprint(key.trim()).ok_or_else(|| {
        CoreError::Invalid("the key must be a SHA256:… fingerprint from `picket-edge key`".into())
    })?;
    Ok(picket_api::ids::fingerprint_from_hash(&hash))
}

/// Registers an edge by name and key (UI "Edges → Add", `picket-core edges add`).
pub async fn add(config: &ConfigStore, mut edge: EdgeDef, actor: Actor) -> CoreResult<Outcome> {
    edge.key = normalize_key(&edge.key)?;
    let body = serde_json::to_value(&edge).map_err(anyhow::Error::from)?;
    // The save also drops the key from the pending list, in its transaction.
    config
        .apply(EntityKind::Edge, Op::Create(body), actor, None)
        .await
}

/// Records an unknown key that tried to connect (bounded, with a capped share per address;
/// core.md §4).
pub async fn record_pending(
    db: &Db,
    key: &str,
    addr: Option<String>,
    claimed_name: Option<String>,
) -> CoreResult<()> {
    let key = normalize_key(key)?;
    let claimed = claimed_name.map(|n| crate::util::sanitize_for_message(&n, 128));
    db.write(move |c| {
        let now = crate::util::now_ts();
        c.execute(
            "INSERT INTO edge_pending(key_sha256, addr, first_seen, last_seen, claimed_name) VALUES (?1, ?2, ?3, ?3, ?4)
             ON CONFLICT(key_sha256) DO UPDATE SET addr = excluded.addr, last_seen = excluded.last_seen,
                claimed_name = excluded.claimed_name",
            params![key, addr, now, claimed],
        )?;
        if let Some(share) = addr.as_deref().and_then(share_of) {
            // The list holds at most MAX_PENDING + 1 rows here, so reading it is cheap.
            let mut st = c.prepare(
                "SELECT key_sha256, addr FROM edge_pending ORDER BY last_seen DESC, key_sha256",
            )?;
            let same: Vec<String> = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))?
                .filter_map(Result::ok)
                .filter(|(_, a)| a.as_deref().and_then(share_of) == Some(share))
                .map(|(k, _)| k)
                .collect();
            drop(st);
            for k in same.iter().skip(MAX_PENDING_PER_ADDR) {
                c.execute("DELETE FROM edge_pending WHERE key_sha256 = ?1", [k])?;
            }
        }
        c.execute(
            "DELETE FROM edge_pending WHERE key_sha256 IN (
                SELECT key_sha256 FROM edge_pending ORDER BY last_seen DESC LIMIT -1 OFFSET ?1)",
            [MAX_PENDING],
        )?;
        Ok::<_, CoreError>(())
    })
    .await
}

/// The share a stored source address belongs to.
fn share_of(addr: &str) -> Option<std::net::IpAddr> {
    addr.parse().ok().map(crate::net::share_key)
}

pub async fn list_pending(db: &Db) -> CoreResult<Vec<PendingEdge>> {
    db.read(|c| {
        let mut st = c.prepare(
            "SELECT key_sha256, addr, claimed_name, first_seen, last_seen FROM edge_pending ORDER BY last_seen DESC",
        )?;
        let v = st
            .query_map([], |r| {
                let key: String = r.get(0)?;
                let key_path = picket_api::ids::parse_fingerprint(&key)
                    .map(|h| picket_api::ids::fingerprint_path(&h))
                    .unwrap_or_default();
                Ok(PendingEdge {
                    key,
                    key_path,
                    addr: r.get(1)?,
                    claimed_name: r.get(2)?,
                    first_seen: r.get(3)?,
                    last_seen: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, CoreError>(v)
    })
    .await
}

pub async fn delete_pending(db: &Db, key: &str) -> CoreResult<bool> {
    let key = normalize_key(key)?;
    db.write(move |c| {
        Ok::<_, CoreError>(c.execute("DELETE FROM edge_pending WHERE key_sha256 = ?1", [key])? > 0)
    })
    .await
}

/// Approves a pending key: registers it under `name` (core.md §4: "approving one stores its
/// key").
pub async fn approve_pending(
    config: &ConfigStore,
    key: &str,
    mut edge: EdgeDef,
    actor: Actor,
) -> CoreResult<Outcome> {
    let key = normalize_key(key)?;
    let k2 = key.clone();
    let exists: bool = config
        .db()
        .read(move |c| {
            Ok::<_, CoreError>(
                c.query_row("SELECT 1 FROM edge_pending WHERE key_sha256 = ?1", [k2], |_| {
                    Ok(())
                })
                .optional()?
                .is_some(),
            )
        })
        .await?;
    if !exists {
        return Err(CoreError::NotFound("no pending edge with that key".into()));
    }
    edge.key = key;
    add(config, edge, actor).await
}

/// The registered edge holding `key`, if any (the edge API pins by it).
pub async fn by_key(db: &Db, key: &str) -> CoreResult<Option<(String, String)>> {
    let key = normalize_key(key)?;
    db.read(move |c| {
        Ok::<_, CoreError>(
            c.query_row("SELECT id, name FROM edges WHERE key_sha256 = ?1", [key], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?,
        )
    })
    .await
}

/// The edge whose name an unknown key's certificate claims (`edge_key_mismatch`, core.md §4).
pub async fn by_name(db: &Db, name: &str) -> CoreResult<Option<String>> {
    let name = name.to_string();
    db.read(move |c| {
        Ok::<_, CoreError>(
            c.query_row(
                "SELECT id FROM edges WHERE lower(name) = lower(?1)",
                [name],
                |r| r.get(0),
            )
            .optional()?,
        )
    })
    .await
}

/// One edge's status summary (core.md §4: online/offline, open conditions).
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct StatusSummary {
    pub edge: String,
    pub last_seen: Option<String>,
    pub online: bool,
    /// Open conditions as last reported (`[{kind, key?, since, detail?}]`).
    pub conditions: serde_json::Value,
}

/// Every registered edge's status, from `edge_status` (written by the session, next wave).
pub async fn statuses(db: &Db, now: Timestamp) -> CoreResult<Vec<StatusSummary>> {
    db.read(move |c| {
        let mut st = c.prepare(
            "SELECT e.id, s.last_seen, s.conditions_json FROM edges e LEFT JOIN edge_status s ON s.edge_id = e.id ORDER BY e.id",
        )?;
        let v = st
            .query_map([], |r| {
                let last: Option<String> = r.get(1)?;
                let online = last
                    .as_deref()
                    .and_then(crate::util::parse_ts)
                    .is_some_and(|t| std::time::Duration::try_from(now - t).unwrap_or_default() < OFFLINE_AFTER);
                let conditions = r
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(serde_json::Value::Array(vec![]));
                Ok(StatusSummary {
                    edge: r.get(0)?,
                    last_seen: last,
                    online,
                    conditions,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, CoreError>(v)
    })
    .await
}

/// True when every edge is online with no open condition (`/healthz?edges=1`).
pub async fn all_healthy(db: &Db, now: Timestamp) -> CoreResult<bool> {
    Ok(statuses(db, now)
        .await?
        .iter()
        .all(|s| s.online && s.conditions.as_array().is_none_or(|a| a.is_empty())))
}

/// Stores a published config without secret values (`edge_configs`, core.md §6). Idempotent.
pub async fn store_published(db: &Db, edge_id: &str, rendered: &Rendered) -> CoreResult<()> {
    let (edge, id, body) = (
        edge_id.to_string(),
        rendered.id.clone(),
        rendered.stored_body.clone(),
    );
    db.write(move |c| {
        c.execute(
            "INSERT INTO edge_configs(config_id, edge_id, published_at, body_json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(config_id) DO NOTHING",
            params![id, edge, crate::util::now_ts(), body],
        )?;
        Ok::<_, CoreError>(())
    })
    .await
}

/// Reads the request rows of an edge into render inputs (`edge_requests`, storage.md §3).
pub async fn requests(db: &Db, edge_id: &str) -> CoreResult<render::Requests> {
    let edge = edge_id.to_string();
    db.read(move |c| {
        let mut out = render::Requests::default();
        let mut st = c.prepare("SELECT kind, provider, request_id, version, blake3 FROM edge_requests WHERE edge_id = ?1")?;
        let rows = st.query_map([&edge], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        for row in rows {
            let (kind, provider, id, version, blake3) = row?;
            match kind.as_str() {
                "flush_dns" => out.flush_dns = Some(id),
                "flush_lookups" => {
                    out.flush_lookups.insert(provider, id);
                }
                "install_now" => {
                    out.install_now = Some(render::InstallRequest {
                        id,
                        version: version.unwrap_or_default(),
                        blake3: blake3.unwrap_or_default(),
                    })
                }
                "revoked_allows" => {
                    // The allows still listed (not ended, not acknowledged) (storage.md §3).
                    let mut s2 = c.prepare(
                        "SELECT allow_id FROM temp_allows WHERE edge_id = ?1 AND revoke_requested_at IS NOT NULL
                           AND ended_at IS NULL AND revoke_acked_at IS NULL ORDER BY allow_id",
                    )?;
                    let allows = s2.query_map([&edge], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
                    out.revoked_allows = Some(picket_api::edge_config::RevokedAllows { id, allows });
                }
                _ => {}
            }
        }
        Ok::<_, CoreError>(out)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let fp = picket_api::ids::fingerprint_spki(b"k");
        assert_eq!(normalize_key(&format!("  {fp}=")).unwrap(), fp);
        assert!(normalize_key("SHA256:short").is_err());
        assert!(normalize_key("nope").is_err());
    }

    #[tokio::test]
    async fn pending_shares_group_ipv6_by_slash_64() {
        // README §2 Bounded (CC10): one host rotating privacy addresses keeps one share of the
        // pending list, so another host's key stays listed.
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::core(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::CORE).unwrap();
        let db = Db::open(opts).unwrap();
        let other = picket_api::ids::fingerprint_spki(b"other");
        record_pending(&db, &other, Some("192.0.2.1".into()), None)
            .await
            .unwrap();
        for i in 0..(MAX_PENDING as u16 + 8) {
            let fp = picket_api::ids::fingerprint_spki(&i.to_be_bytes());
            let addr = std::net::IpAddr::from([0x2001, 0xdb8, 1, 2, i, 0, 0, 1]).to_string();
            record_pending(&db, &fp, Some(addr), None).await.unwrap();
        }
        let list = list_pending(&db).await.unwrap();
        let from_host = list
            .iter()
            .filter(|p| p.addr.as_deref().is_some_and(|a| a.starts_with("2001:db8:1:2:")))
            .count();
        assert_eq!(from_host, MAX_PENDING_PER_ADDR);
        assert!(list.iter().any(|p| p.key == other));
    }
}
