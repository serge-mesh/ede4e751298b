//! The UI endpoints of lookups (api.md §7; core.md §12 Lookup providers, Temporary allows):
//!
//! | Route | What |
//! |---|---|
//! | `GET lookup-modules` | each lookup module with its `Config` schema and presets (id, title, parameter schema) |
//! | `POST lookup-modules/{module}/presets/{preset}` | the parameters → `{config, category?}`; changes nothing |
//! | `POST lookup-providers/{id}/flush` | flush on every edge and core: a new `cache_generation` |
//! | `POST lookup-providers/{id}/test` | **Test now**: one self-test on core, in the light lane |
//! | `GET lookup-providers/{id}/status` | breaker, pause, error rate, latency, queue, verdicts, verdict set, last self-test |
//! | `GET temp-allows` | active and recent temporary allows across edges, with their revoke state |

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Actor;
use crate::state::SharedState;
use crate::web::api::{Page, decode_cursor, encode_cursor};
use crate::web::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::web::protect::PeerAddr;

fn actor(peer: Option<axum::Extension<PeerAddr>>) -> Actor {
    Actor::ui(peer.map(|p| crate::net::canonical_ip(p.0.0.ip()).to_string()))
}

/// A lookup module preset (providers.md §4 "Presets").
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LookupPresetInfo {
    pub id: String,
    pub title: String,
    /// The parameters' JSON Schema (the UI renders the form from it).
    pub params_schema: Value,
}

/// A lookup module and its config form (api.md §7 `lookup-modules`).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LookupModuleInfo {
    pub id: String,
    /// The `Config` JSON Schema (the UI renders the provider form from it; field warnings as
    /// `x-picket-warning`).
    pub config_schema: Value,
    pub presets: Vec<LookupPresetInfo>,
}

/// A preset's built config (api.md §7): it fills the form and is saved like one typed by hand.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LookupPresetBuilt {
    pub config: Value,
    /// The category the preset suggests: `security`, `privacy` or `mixed`.
    pub category: Option<String>,
}

/// A flush's result: the provider's new `cache_generation`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LookupFlushed {
    pub provider: String,
    pub cache_generation: String,
}

/// p50 and p99 of core's calls, in milliseconds.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LookupLatency {
    pub p50: Option<f64>,
    pub p99: Option<f64>,
}

/// The provider's verdict set as core publishes it.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct VerdictSetView {
    pub head: String,
    pub generation: String,
    /// Deltas since the base.
    pub seq: u64,
    pub base_records: i64,
    pub overlay_entries: i64,
    /// What its chain costs an edge's overlay budget.
    pub overlay_bytes: i64,
    pub base_at: String,
    pub published_at: String,
}

/// A provider's status on core (core.md §12 Lookup providers: status, queue).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct LookupProviderStatus {
    pub provider: String,
    pub module: String,
    pub cache_generation: String,
    /// `closed` or `open`.
    pub breaker: String,
    /// Paused after a rejection until about this time, as core last saw it.
    pub paused_until: Option<String>,
    /// Core's calls since it started.
    pub calls: u64,
    /// Calls that ended in an error, timeouts included.
    pub errors: u64,
    /// Of `errors`, the calls that ran out of `async_timeout_ms`.
    pub timeouts: u64,
    pub rejected: u64,
    /// Errors (timeouts included) per call, since core started.
    pub error_rate: Option<f64>,
    pub latency_ms: Option<LookupLatency>,
    /// Items in `lookup_queue`.
    pub queue: i64,
    /// By what drives each item: `retry`, `async`, `recheck`.
    pub queue_by_reason: std::collections::BTreeMap<String, i64>,
    /// Live verdicts, tombstones and Blocks kept for alerts.
    pub verdicts: i64,
    pub tombstones: i64,
    pub blocks: i64,
    pub verdict_set: Option<VerdictSetView>,
    pub last_self_test: Option<Value>,
    /// The module's self-test for this config: name, expected verdict, cron.
    pub self_test: Option<Value>,
}

async fn modules(State(s): State<SharedState>) -> Json<Vec<LookupModuleInfo>> {
    let r = s.lookups.modules();
    Json(
        r.ids()
            .filter_map(|id| r.get(id))
            .map(|m| LookupModuleInfo {
                id: m.id().to_string(),
                config_schema: serde_json::to_value(m.config_schema()).unwrap_or(Value::Null),
                presets: m
                    .presets()
                    .into_iter()
                    .map(|p| LookupPresetInfo {
                        id: p.id.to_string(),
                        title: p.title.to_string(),
                        params_schema: serde_json::to_value(&p.params_schema).unwrap_or(Value::Null),
                    })
                    .collect(),
            })
            .collect(),
    )
}

async fn build_preset(
    State(s): State<SharedState>,
    ApiPath((module, preset)): ApiPath<(String, String)>,
    ApiJson(params): ApiJson<Value>,
) -> ApiResult<Json<LookupPresetBuilt>> {
    let r = s.lookups.modules();
    let m = r
        .get(&module)
        .ok_or_else(|| ApiError::not_found("no such lookup module"))?;
    let p = m
        .presets()
        .into_iter()
        .find(|p| p.id == preset)
        .ok_or_else(|| ApiError::not_found("no such preset"))?;
    if params.to_string().len() > 64 * 1024 {
        return Err(ApiError::unprocessable("preset parameters are limited to 64 KiB"));
    }
    let (config, category) = (p.build)(&params)
        .map_err(|e| ApiError::unprocessable(crate::util::sanitize_for_message(&format!("{e:#}"), 400)))?;
    Ok(Json(LookupPresetBuilt {
        config,
        category: category.map(|c| c.as_str().to_string()),
    }))
}

async fn flush(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(id): ApiPath<String>,
    ApiJson(_): ApiJson<Value>,
) -> ApiResult<Json<LookupFlushed>> {
    let generation = super::flush(&s, &id, actor(peer)).await?;
    Ok(Json(LookupFlushed {
        provider: id,
        cache_generation: generation,
    }))
}

/// How long Test now waits for the lookup runtime to reload a commit (a reload takes
/// milliseconds; the margin covers a busy core). A policy choice.
const TEST_RELOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Waits until the runtime runs provider `id` as core.db holds it (the definition the status
/// shows, api.md §7), at most [`TEST_RELOAD_WAIT`]: `404` when core.db has no such provider,
/// `409` when the runtime hasn't caught up by then (a reload in progress, or one that failed).
async fn committed_in_runtime(s: &SharedState, id: &str) -> ApiResult<()> {
    let end = tokio::time::Instant::now() + TEST_RELOAD_WAIT;
    loop {
        let Some(committed) = s
            .config
            .model_of(crate::config::EntityKind::LookupProvider)
            .await?
            .lookup_providers
            .remove(id)
        else {
            return Err(ApiError::not_found("no such lookup provider"));
        };
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        // Every commit published by now is loaded, and the runtime's definition is core.db's
        // (its last self-test aside: that is the test's own result).
        let caught_up = s.lookups.reloaded(s, left).await
            && s.lookups.model().lookup_providers.get(id).is_some_and(|p| {
                p == &crate::config::model::LookupProviderDef {
                    last_self_test: p.last_self_test.clone(),
                    ..committed.clone()
                }
            })
            && s.lookups.client(id).is_some();
        if caught_up {
            return Ok(());
        }
        if tokio::time::Instant::now() >= end {
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "conflict",
                "provider is being reloaded",
            ));
        }
        // A commit between the two reads: look again shortly.
        tokio::time::sleep(std::time::Duration::from_millis(100).min(left)).await;
    }
}

async fn test_now(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiJson(_): ApiJson<Value>,
) -> ApiResult<Json<super::selftest::SelfTestView>> {
    // The committed config, as the status reads it (api.md §7; providers.md §4 Self-tests): a
    // provider just created or edited is tested once the runtime has it, never in an older form.
    committed_in_runtime(&s, &id).await?;
    let st = s.clone();
    let pid = id.clone();
    let handle = s
        .scheduler
        .light
        .spawn(Some(&super::lane_key(&id)), async move {
            super::selftest::run_one(&st, &pid, "manual").await
        })
        .ok_or_else(|| {
            ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "the light lane is full",
            )
        })?;
    let view = handle
        .await
        .map_err(|e| crate::error::CoreError::Other(anyhow::anyhow!("{e}")))?
        .map_err(crate::error::CoreError::Other)?;
    view.map(Json)
        .ok_or_else(|| ApiError::unprocessable("this provider's module names no self-test for its config"))
}

async fn status(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<LookupProviderStatus>> {
    // The definition as core.db holds it, not the runtime's model, which follows a commit only
    // once the reload after it ran: a provider just created, or a flush that just moved its
    // `cache_generation` on, shows at once (api.md §7). Until the reload the runtime has no
    // client for a new provider: its counters read 0.
    let p = s
        .config
        .model_of(crate::config::EntityKind::LookupProvider)
        .await?
        .lookup_providers
        .remove(&id)
        .ok_or_else(|| ApiError::not_found("no such lookup provider"))?;
    let metrics = s.lookups.client(&id).map(|c| c.metrics());
    let rt = s.lookups.runtime(&id);
    let now = crate::util::now();
    let pid = id.clone();
    type Counts = (
        i64,
        std::collections::BTreeMap<String, i64>,
        i64,
        i64,
        i64,
        Option<VerdictSetView>,
        Option<String>,
    );
    let (queue, by_reason, verdicts, tombstones, blocks, set, last): Counts = s
        .db
        .read(move |c| {
            let mut by = std::collections::BTreeMap::new();
            let mut st = c.prepare("SELECT reason, count(*) FROM lookup_queue WHERE provider_id = ?1 GROUP BY reason")?;
            for r in st.query_map([&pid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
                let (k, n) = r?;
                by.insert(k, n);
            }
            let queue = by.values().sum();
            let (v, t): (i64, i64) = c.query_row(
                "SELECT coalesce(sum(verdict IS NOT NULL), 0), coalesce(sum(verdict IS NULL), 0) FROM lookup_verdicts WHERE provider_id = ?1",
                [&pid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let b: i64 = c.query_row("SELECT count(*) FROM lookup_blocks WHERE provider_id = ?1", [&pid], |r| r.get(0))?;
            let set = super::verdict_sets::states(c)?.remove(&pid).map(|s| VerdictSetView {
                head: s.head_id,
                generation: s.generation,
                seq: s.seq,
                base_records: s.base_records,
                overlay_entries: s.overlay_entries,
                overlay_bytes: s.overlay_bytes,
                base_at: s.base_at,
                published_at: s.published_at,
            });
            let last: Option<String> = c
                .query_row("SELECT last_self_test_json FROM lookup_providers WHERE id = ?1", [&pid], |r| r.get(0))
                .optional()?
                .flatten();
            Ok::<_, anyhow::Error>((queue, by, v, t, b, set, last))
        })
        .await?;
    let (calls, errors, timeouts, rejected, latency, breaker_open) = match &metrics {
        Some(m) => (
            m.calls,
            m.errors,
            m.timeouts,
            m.rejected,
            (m.calls > 0).then(|| LookupLatency {
                p50: m.call_ms.quantile_us(0.5).map(|us| us / 1000.0),
                p99: m.call_ms.quantile_us(0.99).map(|us| us / 1000.0),
            }),
            m.breaker_open != 0,
        ),
        None => (0, 0, 0, 0, None, false),
    };
    let self_test = s.lookups.modules().get(&p.module).and_then(|m| {
        let cfg = picket_lookup::secrets::with_placeholders(&p.config).ok()?;
        m.self_test(&cfg).and_then(|t| serde_json::to_value(t).ok())
    });
    Ok(Json(LookupProviderStatus {
        provider: id,
        module: p.module.clone(),
        cache_generation: p.cache_generation.clone(),
        breaker: if breaker_open { "open" } else { "closed" }.into(),
        paused_until: rt.paused_until.filter(|t| *t > now).map(|t| crate::util::ts(&t)),
        calls,
        errors,
        timeouts,
        rejected,
        // The client's `errors` already counts the calls that timed out (picket-lookup metrics).
        error_rate: (calls > 0).then(|| errors.min(calls) as f64 / calls as f64),
        latency_ms: latency,
        queue,
        queue_by_reason: by_reason,
        verdicts,
        tombstones,
        blocks,
        verdict_set: set,
        last_self_test: last.and_then(|s| serde_json::from_str(&s).ok()),
        self_test,
    }))
}

/// A temporary allow as core knows it from the edges' logs and its revoke requests (core.md §4,
/// §12; storage.md §3 `temp_allows`).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TempAllowView {
    pub edge: String,
    pub allow_id: String,
    pub client: Option<String>,
    pub device: Option<String>,
    /// `dns` or `ip`.
    pub kind: Option<String>,
    pub target: Option<String>,
    pub created_at: Option<String>,
    /// The expiry the edge last reported (the extension can extend an allow core can't see).
    pub expires_at: Option<String>,
    /// When it ended: the edge logged it revoked or expired, or (marked `expired`) its reported
    /// expiry passed with no later news. Null while `active`, and for `revoked` (see
    /// `revoke_acked_at`) until the edge's log reports the end.
    pub ended_at: Option<String>,
    /// `active`, `revoked` (the edge acknowledged the revoke; its log hasn't reported the end
    /// yet), `ended` (the edge logged its end), or `expired` (past its reported expiry, no revoke
    /// pending).
    pub state: AllowState,
    pub revoke_requested_at: Option<String>,
    pub revoke_acked_at: Option<String>,
    /// A revoke is pending: requested, not acknowledged, and the allow hasn't ended.
    pub revoke_pending: bool,
}

/// A temporary allow's state as core knows it (core.md §12 Temporary allows; storage.md §3
/// `temp_allows`). Core learns an allow's end from the edge's log; until then an allow whose
/// revoke the edge acknowledged (`applied.revoked_allows` covered it, api.md §4) is `revoked`:
/// no longer in force on the edge, though core keeps the row open for the log's end record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AllowState {
    Active,
    Revoked,
    Ended,
    Expired,
}

impl AllowState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Ended => "ended",
            Self::Expired => "expired",
        }
    }
}

/// An allow's state and the time it ended (`ended_at`, or its expiry when `expired`), from its
/// `temp_allows` row as of `now` (timestamps in core's fixed format, so they compare as text).
/// A pending revoke (requested, not acknowledged) keeps an allow `active` past its reported
/// expiry: the extension can extend an allow core can't see, and the revoke still reaches it.
pub fn allow_state(
    ended: Option<&str>,
    expires: Option<&str>,
    revoke_requested: Option<&str>,
    revoke_acked: Option<&str>,
    now: &str,
) -> (AllowState, Option<String>) {
    match (ended, revoke_requested, revoke_acked, expires) {
        (Some(e), ..) => (AllowState::Ended, Some(e.to_string())),
        (None, Some(_), Some(_), _) => (AllowState::Revoked, None),
        (None, None, _, Some(x)) if x < now => (AllowState::Expired, Some(x.to_string())),
        _ => (AllowState::Active, None),
    }
}

/// SQL template: a `temp_allows` row whose [`allow_state`] is `active` at `?now`, which the
/// caller replaces with its own parameter.
pub const ACTIVE_ALLOW_SQL: &str = "(ended_at IS NULL AND revoke_acked_at IS NULL
     AND (expires_at IS NULL OR expires_at >= ?now OR revoke_requested_at IS NOT NULL))";

/// SQL template: a `temp_allows` row in force at some time since `?from` (the per-device and
/// per-profile views over a window, core.md §12): active now, or its end (logged, acknowledged
/// revoke, or reported expiry) at or after `?from`, which the caller replaces with its own
/// parameter.
pub const ALLOW_SINCE_SQL: &str = "(coalesce(ended_at, CASE WHEN revoke_acked_at IS NOT NULL
       AND revoke_requested_at IS NOT NULL THEN revoke_acked_at END,
       CASE WHEN revoke_requested_at IS NULL THEN expires_at END) IS NULL
     OR coalesce(ended_at, CASE WHEN revoke_acked_at IS NOT NULL
       AND revoke_requested_at IS NOT NULL THEN revoke_acked_at END,
       CASE WHEN revoke_requested_at IS NULL THEN expires_at END) >= ?from)";

/// `GET temp-allows` filters.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct TempAllowQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    /// `active`, `recent` (`revoked`, `ended` or `expired`) or `all` (default).
    pub state: Option<String>,
    pub edge: Option<String>,
}

async fn temp_allows(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<TempAllowQuery>,
) -> ApiResult<Json<Page<TempAllowView>>> {
    let limit = crate::web::api::limit_param(
        q.limit,
        crate::web::api::DEFAULT_LIMIT,
        crate::web::api::MAX_LIMIT,
    )?;
    let after = match &q.cursor {
        None => None,
        Some(c) => Some(decode_cursor(c).ok_or_else(|| ApiError::bad_request("bad cursor"))?),
    };
    let want = q.state.clone().unwrap_or_else(|| "all".into());
    if !["active", "recent", "all"].contains(&want.as_str()) {
        return Err(ApiError::bad_request("state is active, recent or all"));
    }
    let edge = q.edge.clone();
    let now = crate::util::now_ts();
    let rows: Vec<TempAllowView> =
        s.db.read(move |c| {
            // Newest first, keyed by (created_at, edge, allow id) for the cursor. The state filter
            // is in the query, so every page is full while matching rows remain (api.md §7
            // paging): active is `ACTIVE_ALLOW_SQL`, the state `allow_state` gives.
            let mut st = c.prepare(&format!(
                "SELECT edge_id, allow_id, client, device, kind, target, created_at, expires_at, ended_at,
                        revoke_requested_at, revoke_acked_at,
                        coalesce(created_at, '') || char(31) || edge_id || char(31) || allow_id AS k
                 FROM temp_allows
                 WHERE (?1 IS NULL OR k < ?1) AND (?2 IS NULL OR edge_id = ?2)
                   AND (?5 = 'all' OR (?5 = 'active') = {})
                 ORDER BY k DESC LIMIT ?3",
                ACTIVE_ALLOW_SQL.replace("?now", "?4")
            ))?;
            let mut out = Vec::new();
            let mut rows = st.query(params![after, edge, limit + 1, now, want])?;
            while let Some(r) = rows.next()? {
                let ended: Option<String> = r.get(8)?;
                let expires: Option<String> = r.get(7)?;
                let requested: Option<String> = r.get(9)?;
                let acked: Option<String> = r.get(10)?;
                let on_list = requested.is_some() && acked.is_none() && ended.is_none();
                let (state, ended_at) = allow_state(
                    ended.as_deref(),
                    expires.as_deref(),
                    requested.as_deref(),
                    acked.as_deref(),
                    &now,
                );
                let active = state == AllowState::Active;
                if (want == "active" && !active) || (want == "recent" && active) {
                    continue;
                }
                out.push((
                    r.get::<_, String>(11)?,
                    TempAllowView {
                        edge: r.get(0)?,
                        allow_id: r.get(1)?,
                        client: r.get(2)?,
                        device: r.get(3)?,
                        kind: r.get(4)?,
                        target: r.get(5)?,
                        created_at: r.get(6)?,
                        expires_at: expires,
                        ended_at,
                        state,
                        revoke_pending: on_list,
                        revoke_requested_at: requested,
                        revoke_acked_at: acked,
                    },
                ));
                if out.len() > limit {
                    break;
                }
            }
            Ok::<_, anyhow::Error>(out)
        })
        .await?
        .into_iter()
        .map(|(_, v)| v)
        .collect();
    let more = rows.len() > limit;
    let mut items = rows;
    items.truncate(limit);
    let next_cursor = more.then(|| {
        items.last().map(|v| {
            encode_cursor(&format!(
                "{}\u{1f}{}\u{1f}{}",
                v.created_at.clone().unwrap_or_default(),
                v.edge,
                v.allow_id
            ))
        })
    });
    Ok(Json(Page {
        items,
        next_cursor: next_cursor.flatten(),
    }))
}

/// The routes under `lookup-providers/` beside the generic CRUD (merged into its router).
pub fn item_routes() -> Router<SharedState> {
    Router::new()
        .route("/{id}/flush", post(flush))
        .route("/{id}/test", post(test_now))
        .route("/{id}/status", get(status))
}

/// The top-level lookup routes.
pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/lookup-modules", get(modules))
        .route("/lookup-modules/{module}/presets/{preset}", post(build_preset))
        .route("/temp-allows", get(temp_allows))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C8 (core.md §12 Temporary allows; api.md §4 `revoked_allows`): a revoke the edge
    /// acknowledged makes an allow `revoked` until its log reports the end (then `ended`); a
    /// pending revoke keeps it `active` past its reported expiry; without one it is `expired`.
    #[test]
    fn allow_states() {
        let now = "2026-11-24T10:00:00.000000Z";
        let past = Some("2026-11-24T09:00:00.000000Z");
        let later = Some("2026-11-24T11:00:00.000000Z");
        let at = Some("2026-11-24T09:30:00.000000Z");
        let st = |ended, expires, req, ack| allow_state(ended, expires, req, ack, now);
        assert_eq!(st(None, later, None, None), (AllowState::Active, None));
        assert_eq!(
            st(None, past, None, None),
            (AllowState::Expired, past.map(String::from))
        );
        assert_eq!(
            st(None, past, at, None),
            (AllowState::Active, None),
            "a pending revoke"
        );
        assert_eq!(st(None, later, at, at), (AllowState::Revoked, None));
        assert_eq!(st(None, past, at, at), (AllowState::Revoked, None));
        assert_eq!(st(at, later, at, at), (AllowState::Ended, at.map(String::from)));
        assert_eq!(st(None, None, None, None), (AllowState::Active, None));
    }
}
