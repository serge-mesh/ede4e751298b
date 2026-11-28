//! The UI API, `/api/ui/v1/…` (api.md §7): REST CRUD for every entity of core.md §2, settings,
//! the admin password, edges and pending keys, each edge's live status and requests (Update,
//! flushes, revokes), identity, alerts, the change journal, jobs, metrics charts. The feeds'
//! own routes (status, "Check now", runs, entries, manual files, presets) are
//! [`crate::feeds::api`]'s.
//!
//! Lists use cursor pagination: `?cursor=…&limit=…` → `{items, next_cursor}` (`limit` default
//! 100, at most 500). Errors use `{"error": {"code", "message"}}`.

use std::collections::BTreeMap;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use base64::Engine as _;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use super::protect::PeerAddr;
use crate::alerts::{Alert, AlertFilter, HistoryEntry};
use crate::config::model::{EdgeDef, EntityKind, PendingEdge, SecretMeta};
use crate::config::validate::Issue;
use crate::config::{Actor, Op, Outcome, store};
use crate::edges::StatusSummary;
use crate::state::SharedState;

/// One generically handled entity collection.
#[derive(Clone, Copy, Debug)]
pub struct EntityRoute {
    pub kind: EntityKind,
    /// The collection's path segment.
    pub path: &'static str,
    /// The OpenAPI component of the entity.
    pub schema: &'static str,
    pub title: &'static str,
}

/// Every collection with plain CRUD (edges and secrets have their own routes).
pub const ENTITY_ROUTES: &[EntityRoute] = &[
    EntityRoute {
        kind: EntityKind::Client,
        path: "clients",
        schema: "ClientDef",
        title: "Clients",
    },
    EntityRoute {
        kind: EntityKind::Listener,
        path: "listeners",
        schema: "ListenerDef",
        title: "Listeners",
    },
    EntityRoute {
        kind: EntityKind::Profile,
        path: "profiles",
        schema: "ProfileDef",
        title: "Profiles",
    },
    EntityRoute {
        kind: EntityKind::Upstream,
        path: "upstreams",
        schema: "UpstreamDef",
        title: "Upstreams",
    },
    EntityRoute {
        kind: EntityKind::UpstreamGroup,
        path: "upstream-groups",
        schema: "UpstreamGroupDef",
        title: "Upstream groups",
    },
    EntityRoute {
        kind: EntityKind::ForwardZone,
        path: "forward-zones",
        schema: "ForwardZoneDef",
        title: "Forward zones",
    },
    EntityRoute {
        kind: EntityKind::FeedProvider,
        path: "feed-providers",
        schema: "FeedProviderDef",
        title: "Feed providers",
    },
    EntityRoute {
        kind: EntityKind::Feed,
        path: "feeds",
        schema: "FeedDef",
        title: "Feeds",
    },
    EntityRoute {
        kind: EntityKind::Bundle,
        path: "bundles",
        schema: "BundleDef",
        title: "Bundles",
    },
    EntityRoute {
        kind: EntityKind::LookupProvider,
        path: "lookup-providers",
        schema: "LookupProviderDef",
        title: "Lookup providers",
    },
];

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 500;

/// A `limit` (page size) query parameter (api.md §7 cursor pagination; README §2 Untrusted
/// input: checked for range, and a value out of it refused, not quietly changed): `default` when
/// left out, else 1 to `max`, or `400` (`bad_request`, "limit: 1 to `max`"). Every `limit` the UI
/// API reads is checked so (`GET logs` in `logs::query::search`, the rest here), and the OpenAPI
/// document declares the same bounds (`web::openapi::param_type`).
pub fn limit_param(limit: Option<usize>, default: usize, max: usize) -> ApiResult<usize> {
    match limit {
        None => Ok(default),
        Some(n) if (1..=max).contains(&n) => Ok(n),
        Some(_) => Err(ApiError::bad_request(format!("limit: 1 to {max}"))),
    }
}

/// `?cursor=…&limit=…`
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct PageQuery {
    pub cursor: Option<String>,
    /// Items per page: default [`DEFAULT_LIMIT`], 1 to [`MAX_LIMIT`] ([`limit_param`]).
    pub limit: Option<usize>,
}

impl PageQuery {
    /// The page size ([`limit_param`]: `400` out of range).
    pub fn limit(&self) -> ApiResult<usize> {
        limit_param(self.limit, DEFAULT_LIMIT, MAX_LIMIT)
    }
    fn after(&self) -> ApiResult<Option<String>> {
        match &self.cursor {
            None => Ok(None),
            Some(c) if c.is_empty() => Ok(None),
            Some(c) => decode_cursor(c)
                .map(Some)
                .ok_or_else(|| ApiError::bad_request("bad cursor")),
        }
    }
}

/// A page of items.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Pass as `cursor` for the next page; null on the last page.
    pub next_cursor: Option<String>,
}

pub fn encode_cursor(key: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
}

pub fn decode_cursor(c: &str) -> Option<String> {
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(c).ok()?;
    String::from_utf8(b).ok()
}

/// Pages a list sorted by `key`.
fn page_by_key<T>(items: Vec<(String, T)>, q: &PageQuery) -> ApiResult<Page<T>> {
    let after = q.after()?;
    let limit = q.limit()?;
    let mut it = items
        .into_iter()
        .filter(|(k, _)| after.as_ref().is_none_or(|a| k > a))
        .peekable();
    let mut out = Vec::new();
    let mut last = None;
    while out.len() < limit {
        match it.next() {
            Some((k, v)) => {
                last = Some(k);
                out.push(v);
            }
            None => break,
        }
    }
    let next_cursor = if it.peek().is_some() {
        last.map(|k| encode_cursor(&k))
    } else {
        None
    };
    Ok(Page {
        items: out,
        next_cursor,
    })
}

fn actor(peer: Option<axum::Extension<PeerAddr>>) -> Actor {
    Actor::ui(peer.map(|p| crate::net::canonical_ip(p.0.0.ip()).to_string()))
}

/// The sort key of an entity: its id, or `position:name` for clients.
fn sort_key(kind: EntityKind, id: &str, v: &Value) -> String {
    if kind == EntityKind::Client {
        let pos = v.get("position").and_then(Value::as_u64).unwrap_or(0);
        format!("{pos:010}:{id}")
    } else {
        id.to_string()
    }
}

// ---------------------------------------------------------------------------------------------
// Generic entity handlers

async fn list_entities(state: SharedState, kind: EntityKind, q: PageQuery) -> ApiResult<Json<Page<Value>>> {
    let m = state.config.model_of(kind).await?;
    let items: Vec<(String, Value)> = store::list_values(&m, kind)
        .into_iter()
        .map(|(id, v)| (sort_key(kind, &id, &v), v))
        .collect();
    Ok(Json(page_by_key(items, &q)?))
}

async fn get_entity(state: SharedState, kind: EntityKind, id: String) -> ApiResult<Json<Value>> {
    let m = state.config.model_of(kind).await?;
    store::entity_for_ui(&m, kind, &id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no {} {id:?}", kind.as_str())))
}

/// `?clear_cached_verdicts=` on lookup provider saves (providers.md §4);
/// `?delete_unselected=true` on feed provider saves that stop selecting feeds (feeds.md §1:
/// asked first, then deleted).
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct SaveQuery {
    pub clear_cached_verdicts: Option<bool>,
    pub delete_unselected: Option<bool>,
}

async fn create_entity(
    state: SharedState,
    kind: EntityKind,
    actor: Actor,
    body: Value,
) -> ApiResult<Response> {
    let out = state.config.apply(kind, Op::Create(body), actor, None).await?;
    Ok((StatusCode::CREATED, Json(out)).into_response())
}

async fn update_entity(
    state: SharedState,
    kind: EntityKind,
    actor: Actor,
    id: String,
    q: SaveQuery,
    body: Value,
) -> ApiResult<Json<Outcome>> {
    Ok(Json(
        state
            .config
            .apply_with(
                kind,
                Op::Update(id, body),
                actor,
                crate::config::SaveOpts {
                    clear_cached_verdicts: q.clear_cached_verdicts,
                    delete_unselected: q.delete_unselected.unwrap_or(false),
                },
            )
            .await?,
    ))
}

async fn delete_entity(
    state: SharedState,
    kind: EntityKind,
    actor: Actor,
    id: String,
) -> ApiResult<Json<Outcome>> {
    Ok(Json(state.config.apply(kind, Op::Delete(id), actor, None).await?))
}

fn entity_router(r: EntityRoute) -> Router<SharedState> {
    let kind = r.kind;
    Router::new()
        .route(
            "/",
            get(
                move |State(s): State<SharedState>, ApiQuery(q): ApiQuery<PageQuery>| {
                    list_entities(s, kind, q)
                },
            )
            .post(
                move |State(s): State<SharedState>,
                      peer: Option<axum::Extension<PeerAddr>>,
                      ApiJson(body): ApiJson<Value>| {
                    create_entity(s, kind, actor(peer), body)
                },
            ),
        )
        .route(
            "/{id}",
            get(move |State(s): State<SharedState>, ApiPath(id): ApiPath<String>| get_entity(s, kind, id))
                .put(
                    move |State(s): State<SharedState>,
                          peer: Option<axum::Extension<PeerAddr>>,
                          ApiPath(id): ApiPath<String>,
                          ApiQuery(q): ApiQuery<SaveQuery>,
                          ApiJson(body): ApiJson<Value>| {
                        update_entity(s, kind, actor(peer), id, q, body)
                    },
                )
                .delete(
                    move |State(s): State<SharedState>,
                          peer: Option<axum::Extension<PeerAddr>>,
                          ApiPath(id): ApiPath<String>| {
                        delete_entity(s, kind, actor(peer), id)
                    },
                ),
        )
}

// ---------------------------------------------------------------------------------------------
// Clients order

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct ClientOrder {
    /// Every client's name, in the new order.
    pub names: Vec<String>,
}

async fn reorder_clients(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiJson(body): ApiJson<ClientOrder>,
) -> ApiResult<StatusCode> {
    s.config.reorder_clients(body.names, actor(peer)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Secrets (write-only values)

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct SecretValue {
    /// The value; stored encrypted, never returned.
    pub value: String,
}

async fn list_secrets(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<SecretMeta>>> {
    let m = s.config.model_of(EntityKind::Secret).await?;
    let items = m.secrets.into_iter().collect();
    Ok(Json(page_by_key(items, &q)?))
}

async fn put_secret(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<SecretValue>,
) -> ApiResult<Json<SecretMeta>> {
    s.config.set_secret(name.clone(), body.value, actor(peer)).await?;
    Ok(Json(SecretMeta {
        name,
        has_value: true,
    }))
}

async fn delete_secret(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<StatusCode> {
    s.config.delete_secret(name, actor(peer)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Edges

/// An edge with its status.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EdgeView {
    #[serde(flatten)]
    pub edge: EdgeDef,
    /// Listener ids assigned to this edge.
    pub listeners: Vec<String>,
    pub status: Option<StatusSummary>,
}

async fn edge_views(s: &SharedState) -> ApiResult<Vec<(String, EdgeView)>> {
    let m = s.config.model().await?;
    let statuses: BTreeMap<String, StatusSummary> = crate::edges::statuses(&s.db, crate::util::now())
        .await?
        .into_iter()
        .map(|st| (st.edge.clone(), st))
        .collect();
    Ok(m.edges
        .values()
        .map(|e| {
            let listeners = m
                .listeners
                .values()
                .filter(|l| l.edges.contains(&e.id))
                .map(|l| l.id.clone())
                .collect();
            (
                e.id.clone(),
                EdgeView {
                    edge: e.clone(),
                    listeners,
                    status: statuses.get(&e.id).cloned(),
                },
            )
        })
        .collect())
}

async fn list_edges(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<EdgeView>>> {
    Ok(Json(page_by_key(edge_views(&s).await?, &q)?))
}

async fn get_edge(State(s): State<SharedState>, ApiPath(id): ApiPath<String>) -> ApiResult<Json<EdgeView>> {
    edge_views(&s)
        .await?
        .into_iter()
        .find(|(k, _)| *k == id)
        .map(|(_, v)| Json(v))
        .ok_or_else(|| ApiError::not_found(format!("no edge {id:?}")))
}

async fn add_edge(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Response> {
    let edge: EdgeDef =
        serde_json::from_value(body).map_err(|e| ApiError::unprocessable(format!("invalid edge: {e}")))?;
    let out = crate::edges::add(&s.config, edge, actor(peer)).await?;
    Ok((StatusCode::CREATED, Json(out)).into_response())
}

async fn update_edge(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(id): ApiPath<String>,
    ApiJson(mut body): ApiJson<Value>,
) -> ApiResult<Json<Outcome>> {
    // Keys can be replaced in the UI (core.md §4); keep them canonical.
    if let Some(k) = body.get("key").and_then(Value::as_str) {
        let k = crate::edges::normalize_key(k)?;
        body["key"] = Value::String(k);
    }
    Ok(Json(
        s.config
            .apply(EntityKind::Edge, Op::Update(id, body), actor(peer), None)
            .await?,
    ))
}

async fn delete_edge(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Outcome>> {
    Ok(Json(
        s.config
            .apply(EntityKind::Edge, Op::Delete(id), actor(peer), None)
            .await?,
    ))
}

/// A preview of an edge's config object as core would render it now (secret values blanked).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ConfigPreview {
    /// The config's id: BLAKE3 of its bytes.
    pub id: String,
    pub config: Value,
    /// Bundles its profiles reference that have no head yet.
    pub missing_heads: Vec<String>,
    /// Secrets its sync providers reference that have no value.
    pub missing_secrets: Vec<String>,
}

async fn edge_config(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<ConfigPreview>> {
    let m = s.config.model().await?;
    if !m.edges.contains_key(&id) {
        return Err(ApiError::not_found(format!("no edge {id:?}")));
    }
    // The same inputs the publisher renders with (heads, release offer, the edge's running
    // release, requests, secrets, core's addresses).
    let shared = crate::edges::publish::SharedInputs::load(&s, &m).await?;
    let state = s.edges.publisher.edge_state(&s, &id, &shared).await?;
    let r = crate::edges::render(&m, &id, &state).map_err(|e| ApiError::unprocessable(e.to_string()))?;
    Ok(Json(ConfigPreview {
        id: r.id,
        config: serde_json::from_str(&r.stored_body).unwrap_or(Value::Null),
        missing_heads: r.missing_heads,
        missing_secrets: r.missing_secrets,
    }))
}

/// A request made to an edge (Update, a flush, a revoke): its id, pending until the edge's
/// `applied` carries it (core.md §4).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RequestMade {
    pub request_id: String,
}

/// `POST edges/{id}/flush`: flush the DNS cache, or one lookup provider's RAM tier.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct FlushRequest {
    /// A lookup provider id: flush its RAM tier on this edge; left out: the DNS cache.
    #[serde(default)]
    pub provider: Option<String>,
}

async fn edge_status(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<crate::edges::status::EdgeStatusView>> {
    Ok(Json(crate::edges::status::view(&s, &id).await?))
}

async fn edge_update(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiJson(_): ApiJson<Value>,
) -> ApiResult<Json<RequestMade>> {
    let request_id = crate::edges::requests::install_now(&s, &id).await?;
    Ok(Json(RequestMade { request_id }))
}

async fn edge_flush(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiJson(body): ApiJson<FlushRequest>,
) -> ApiResult<Json<RequestMade>> {
    let request_id = crate::edges::requests::flush(&s, &id, body.provider).await?;
    Ok(Json(RequestMade { request_id }))
}

async fn edge_revoke_allow(
    State(s): State<SharedState>,
    ApiPath((id, allow)): ApiPath<(String, String)>,
    ApiJson(_): ApiJson<Value>,
) -> ApiResult<Json<RequestMade>> {
    let request_id = crate::edges::requests::revoke_allow(&s, &id, &allow).await?;
    Ok(Json(RequestMade { request_id }))
}

/// `GET metrics?series=…&window=…&edge=…` (api.md §7).
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct MetricsQuery {
    /// Series names, comma-separated (`queries`, `by_decision.block`, `upstream.<id>.queries`,
    /// `latency_us.p99`, `convergence_lag_s`, …).
    pub series: Option<String>,
    /// `1h`, `6h`, `24h` or `72h`.
    pub window: Option<String>,
    /// `all` (default), `each`, or an edge id.
    pub edge: Option<String>,
}

async fn metrics_chart(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<MetricsQuery>,
) -> ApiResult<Json<crate::metrics::query::Chart>> {
    let window = q.window.as_deref().unwrap_or("24h");
    let w = crate::metrics::query::Window::parse(window)
        .ok_or_else(|| ApiError::bad_request("window is 1h, 6h, 24h or 72h"))?;
    let series: Vec<String> = q
        .series
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect();
    if series.is_empty() {
        return Err(ApiError::bad_request("name at least one series"));
    }
    let edges = crate::metrics::query::EdgeSel::parse(q.edge.as_deref());
    let retention = crate::util::sat_i64(s.settings().retention.metrics.as_secs());
    let now = jiff::Timestamp::now().as_millisecond();
    let chart = s
        .metrics_db
        .read(move |c| crate::metrics::query::chart(c, &series, w, &edges, now, retention))
        .await?;
    Ok(Json(chart))
}

fn fp_from_path(fp: &str) -> ApiResult<String> {
    let hash = picket_api::ids::parse_fingerprint_path(fp).ok_or_else(|| {
        ApiError::bad_request("the key in the path is the fingerprint's hash as unpadded base64url")
    })?;
    Ok(picket_api::ids::fingerprint_from_hash(&hash))
}

async fn list_pending(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<PendingEdge>>> {
    let items = crate::edges::list_pending(&s.db)
        .await?
        .into_iter()
        .map(|p| (p.key.clone(), p))
        .collect();
    Ok(Json(page_by_key(items, &q)?))
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct ApproveEdge {
    pub name: String,
    #[serde(default)]
    pub platform: Option<picket_api::edge_config::Platform>,
}

async fn approve_pending(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(fp): ApiPath<String>,
    ApiJson(body): ApiJson<ApproveEdge>,
) -> ApiResult<Response> {
    let key = fp_from_path(&fp)?;
    let edge = EdgeDef {
        name: body.name,
        platform: body.platform.unwrap_or_default(),
        ..Default::default()
    };
    let out = crate::edges::approve_pending(&s.config, &key, edge, actor(peer)).await?;
    Ok((StatusCode::CREATED, Json(out)).into_response())
}

async fn delete_pending(State(s): State<SharedState>, ApiPath(fp): ApiPath<String>) -> ApiResult<StatusCode> {
    let key = fp_from_path(&fp)?;
    if crate::edges::delete_pending(&s.db, &key).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("no pending edge with that key"))
    }
}

// ---------------------------------------------------------------------------------------------
// Settings, identity, account

/// Settings with what can't be changed here, and the LAN CA's state.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct SettingsView {
    pub settings: crate::settings::Settings,
    /// The compiled-in release keys (`release_keys`).
    pub release_keys: Vec<String>,
    /// Keys the UI can't change: none now (a `lanca.zones` change rotates the LAN CA root,
    /// core.md §11; see `lanca`).
    pub read_only: Vec<String>,
    /// The LAN CA: its zones, root fingerprint and the state of the last rotation (previous
    /// roots still in use, by which edges).
    pub lanca: crate::lanca::rotation::LancaView,
}

async fn settings_view(state: &SharedState, s: crate::settings::Settings) -> ApiResult<SettingsView> {
    Ok(SettingsView {
        settings: s,
        release_keys: crate::settings::release_keys(),
        read_only: Vec::new(),
        lanca: crate::lanca::rotation::view(state).await?,
    })
}

async fn get_settings(State(s): State<SharedState>) -> ApiResult<Json<SettingsView>> {
    let settings = (*s.settings()).clone();
    Ok(Json(settings_view(&s, settings).await?))
}

/// `PUT settings`. A patch whose `lanca.zones` names other zones than the current root's rotates
/// the LAN CA with the rest of the patch (core.md §11, `lanca::rotation`) when it also names the
/// current root in `lanca.rotate_from`, so a rotation is always asked for explicitly: without it
/// (or with `null`, which counts as left out, as a patch's null sets nothing that isn't a setting)
/// `422`; with a root that is no longer the current one `409` with code `lanca_root_changed`
/// (`lanca::rotation::ROOT_CHANGED`: reload and decide again); `409` with code `conflict` while a
/// previous root is still in use (wait for the edges it names); `503` while the clock isn't
/// synchronised, `422` for names the new zones wouldn't cover or any other problem, and nothing
/// changes on a refusal. The same zones (a UI saving the whole object, an old tab's merged form)
/// pass, and `rotate_from` is ignored then.
async fn put_settings(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiJson(mut patch): ApiJson<Value>,
) -> ApiResult<Json<SettingsView>> {
    let mut take = |key: &str| {
        patch
            .get_mut("lanca")
            .and_then(|l| l.as_object_mut())
            .and_then(|l| l.remove(key))
            .or_else(|| {
                patch
                    .as_object_mut()
                    .and_then(|p| p.remove(&format!("lanca.{key}")))
            })
    };
    let zones = take("zones");
    let rotate_from = take("rotate_from");
    if patch
        .get("lanca")
        .and_then(Value::as_object)
        .is_some_and(|l| l.is_empty())
        && let Some(p) = patch.as_object_mut()
    {
        p.remove("lanca");
    }
    if let Some(z) = zones.filter(|z| !z.is_null()) {
        let z: Vec<String> = serde_json::from_value(z)
            .map_err(|_| ApiError::unprocessable("lanca.zones is a list of DNS names"))?;
        let z = crate::lanca::normalize_zones(&z).map_err(|e| ApiError::unprocessable(format!("{e:#}")))?;
        let current = s.lanca.load_full();
        if !crate::lanca::same_zones(current.zones(), &z) {
            let from = match rotate_from.filter(|f| !f.is_null()) {
                Some(Value::String(f)) => f,
                Some(_) => {
                    return Err(ApiError::unprocessable(
                        "lanca.rotate_from is the current LAN CA root's fingerprint (SHA256:…)",
                    ));
                }
                None => {
                    return Err(ApiError::unprocessable(format!(
                        "lanca.zones {} would replace the LAN CA root (zones {}) with a new one that \
                         every device must trust again (core.md §11). To rotate, send lanca.rotate_from \
                         with the current root's fingerprint (lanca.fingerprint in GET settings) in \
                         the same request; to keep the root, leave lanca.zones out or send its zones. \
                         Nothing changed",
                        z.join(", "),
                        current.zones().join(", ")
                    )));
                }
            };
            let new = crate::lanca::rotation::rotate(&s, z, patch, from, actor(peer)).await?;
            return Ok(Json(settings_view(&s, new).await?));
        }
    }
    let new = if patch.as_object().is_some_and(|p| p.is_empty()) {
        s.config.settings().as_ref().clone()
    } else {
        s.config.patch_settings(patch, actor(peer)).await?
    };
    Ok(Json(settings_view(&s, new).await?))
}

/// Core's identity and LAN CA (Settings → Identity).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct IdentityInfo {
    /// Core's key fingerprint `SHA256:…`, which edges pin.
    pub fingerprint: String,
    pub instance_id: String,
    pub version: String,
    /// The current LAN CA root's zones (`lanca.zones`; a change rotates the root).
    pub lanca_zones: Vec<String>,
    /// The current LAN CA root's fingerprint (`SHA256:` and the hex SHA-256 of its certificate,
    /// as `lanca.fingerprint` in `GET settings`); a rotation replaces it (a `lanca` UI event).
    pub lanca_fingerprint: String,
    /// The current root's download path (also on the plain-HTTP port when set).
    pub lanca_download: String,
    /// False while no UI is embedded in this build.
    pub ui_embedded: bool,
    /// True when this request came over plain HTTP (`web.tls` `off` when core started; a saved
    /// change applies at the next start): credentials cross the network in clear (core.md §12).
    pub plain_http: bool,
}

async fn identity(
    State(s): State<SharedState>,
    conn: Option<axum::Extension<super::ConnTls>>,
) -> Json<IdentityInfo> {
    // The connection's own scheme: a saved `web.tls` changes the port only at the next start.
    let tls = match conn {
        Some(axum::Extension(super::ConnTls(t))) => t,
        None => s.settings().web.tls != crate::settings::WebTls::Off,
    };
    Json(IdentityInfo {
        fingerprint: s.identity.fingerprint.clone(),
        instance_id: s.marker.instance_id.clone(),
        version: crate::VERSION.into(),
        lanca_zones: s.lanca.load().zones().to_vec(),
        lanca_fingerprint: s.lanca.load().fingerprint(),
        lanca_download: "/lanca/ca.crt".into(),
        ui_embedded: super::assets::embedded(),
        plain_http: !tls,
    })
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct PasswordChange {
    pub current: String,
    /// At least 12 characters.
    pub new: String,
}

async fn change_password(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiJson(body): ApiJson<PasswordChange>,
) -> ApiResult<StatusCode> {
    // The current password goes through the failed-login limit like any login (core.md §12).
    let ip = peer
        .map(|p| p.0.0.ip())
        .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
    use crate::web::auth::AuthResult;
    match s
        .auth
        .check_credentials(ip, crate::instance::ADMIN, &body.current)
        .await
        .0
    {
        AuthResult::Ok => {}
        AuthResult::Missing | AuthResult::Failed => {
            return Err(ApiError::forbidden("the current password is wrong"));
        }
        AuthResult::Blocked(_) | AuthResult::Throttled => {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "too many failed logins; try again later",
            ));
        }
        AuthResult::Busy => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "too many password checks at once; try again",
            ));
        }
    }
    s.auth.set_password(&s.data_dir, &body.new).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// Config issues, journal, export

async fn config_issues(State(s): State<SharedState>) -> ApiResult<Json<Page<Issue>>> {
    Ok(Json(Page {
        items: s.config.issues().await?,
        next_cursor: None,
    }))
}

/// One journal row (diffs are redacted).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ConfigChange {
    pub id: i64,
    pub at: String,
    pub source_ip: Option<String>,
    pub entity: String,
    pub entity_id: String,
    pub diff: Value,
}

async fn config_changes(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<ConfigChange>>> {
    let limit = q.limit()?;
    let before: i64 = match q.after()? {
        Some(c) => c.parse().map_err(|_| ApiError::bad_request("bad cursor"))?,
        None => i64::MAX,
    };
    let rows: Vec<ConfigChange> = s
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT id, at, source_ip, entity, entity_id, diff_json FROM config_changes WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
            )?;
            let v = st
                .query_map(rusqlite::params![before, limit + 1], |r| {
                    Ok(ConfigChange {
                        id: r.get(0)?,
                        at: r.get(1)?,
                        source_ip: r.get(2)?,
                        entity: r.get(3)?,
                        entity_id: r.get(4)?,
                        diff: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or(Value::Null),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, crate::error::CoreError>(v)
        })
        .await?;
    let mut items = rows;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|r| encode_cursor(&r.id.to_string()))
    } else {
        None
    };
    Ok(Json(Page { items, next_cursor }))
}

// ---------------------------------------------------------------------------------------------
// Alerts

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct AlertQuery {
    #[serde(flatten)]
    pub filter: AlertFilter,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

async fn list_alerts(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<AlertQuery>,
) -> ApiResult<Json<Page<Alert>>> {
    let page = PageQuery {
        cursor: q.cursor.clone(),
        limit: q.limit,
    };
    let limit = page.limit()?;
    let after = match page.after()? {
        Some(c) => {
            let (ls, id) = c
                .rsplit_once('|')
                .ok_or_else(|| ApiError::bad_request("bad cursor"))?;
            Some((
                ls.to_string(),
                id.parse::<i64>()
                    .map_err(|_| ApiError::bad_request("bad cursor"))?,
            ))
        }
        None => None,
    };
    let mut items = s.alerts.list(q.filter, after, limit + 1).await?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items
            .last()
            .map(|a| encode_cursor(&format!("{}|{}", a.last_seen, a.id)))
    } else {
        None
    };
    Ok(Json(Page { items, next_cursor }))
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct AlertDetail {
    pub alert: Alert,
    /// Every raise and resolve.
    pub history: Vec<HistoryEntry>,
}

async fn get_alert(State(s): State<SharedState>, ApiPath(id): ApiPath<i64>) -> ApiResult<Json<AlertDetail>> {
    let (alert, history) = s.alerts.get(id).await?;
    Ok(Json(AlertDetail { alert, history }))
}

async fn resolve_alert(State(s): State<SharedState>, ApiPath(id): ApiPath<i64>) -> ApiResult<Json<Alert>> {
    Ok(Json(s.alerts.resolve_id(id).await?))
}

async fn delete_alert(State(s): State<SharedState>, ApiPath(id): ApiPath<i64>) -> ApiResult<StatusCode> {
    match s.alerts.delete(vec![id]).await? {
        0 => Err(ApiError::not_found(format!("no alert {id}"))),
        _ => Ok(StatusCode::NO_CONTENT),
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct AlertIds {
    pub ids: Vec<i64>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Deleted {
    pub deleted: usize,
}

async fn delete_alerts(
    State(s): State<SharedState>,
    ApiJson(body): ApiJson<AlertIds>,
) -> ApiResult<Json<Deleted>> {
    Ok(Json(Deleted {
        deleted: s.alerts.delete(body.ids).await?,
    }))
}

// ---------------------------------------------------------------------------------------------
// Jobs

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct JobsView {
    pub light_depth: usize,
    pub light_dropped: u64,
    pub heavy_depth: usize,
    pub heavy_dropped: u64,
    pub heavy_completed: u64,
    pub heavy_failed: u64,
    pub heavy_running: Option<String>,
}

/// The lanes' state now (`GET jobs`, and each `job` event's fields).
pub fn jobs_view(s: &crate::state::AppState) -> JobsView {
    let h = s.scheduler.heavy.stats();
    JobsView {
        light_depth: s.scheduler.light.depth(),
        light_dropped: s.scheduler.light.dropped(),
        heavy_depth: s.scheduler.heavy.depth(),
        heavy_dropped: h.dropped,
        heavy_completed: h.completed,
        heavy_failed: h.failed,
        heavy_running: h.running,
    }
}

async fn jobs(State(s): State<SharedState>) -> Json<JobsView> {
    Json(jobs_view(&s))
}

async fn openapi() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        super::openapi::document_json(),
    )
        .into_response()
}

async fn browser_lists(State(s): State<SharedState>) -> ApiResult<Json<Vec<crate::lists::ListView>>> {
    Ok(Json(crate::lists::views(&s).await?))
}

async fn not_found() -> ApiError {
    ApiError::not_found("no such UI API endpoint")
}

/// A method the route doesn't take: `405` in the API's error shape (api.md §7); axum adds the
/// route's `Allow`.
async fn method_not_allowed(method: axum::http::Method) -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        format!("this UI API endpoint doesn't take {method}"),
    )
}

/// The `/api/ui/v1` router.
pub fn router() -> Router<SharedState> {
    let mut r = Router::new()
        .route("/openapi.json", get(openapi))
        .route("/events", get(super::events::upgrade))
        .route("/identity", get(identity))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/account/password", post(change_password))
        .route("/config/issues", get(config_issues))
        .route(
            "/config/export",
            // The restore streams its body into staging/ with its own bound
            // (`MAX_DOCUMENT_BYTES`, 413 past it).
            get(crate::config::export::api_get)
                .put(crate::config::export::api_put)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/config-changes", get(config_changes))
        .route("/clients/order", put(reorder_clients))
        .route("/secrets", get(list_secrets))
        .route("/secrets/{name}", put(put_secret).delete(delete_secret))
        .route("/edges", get(list_edges).post(add_edge))
        .route("/edges/pending", get(list_pending))
        .route("/edges/pending/{fp}", axum::routing::delete(delete_pending))
        .route("/edges/pending/{fp}/approve", post(approve_pending))
        .route("/edges/{id}", get(get_edge).put(update_edge).delete(delete_edge))
        .route("/edges/{id}/config", get(edge_config))
        .route("/edges/{id}/status", get(edge_status))
        .route("/edges/{id}/update", post(edge_update))
        .route("/edges/{id}/flush", post(edge_flush))
        .route("/edges/{id}/allows/{allow}/revoke", post(edge_revoke_allow))
        .route("/metrics", get(metrics_chart))
        .route("/alerts", get(list_alerts).delete(delete_alerts))
        .route("/alerts/{id}", get(get_alert).delete(delete_alert))
        .route("/alerts/{id}/resolve", post(resolve_alert))
        .route("/jobs", get(jobs));
    for er in ENTITY_ROUTES {
        let mut sub = entity_router(*er);
        if er.kind == EntityKind::Feed {
            sub = sub.merge(crate::feeds::api::item_routes());
        }
        if er.kind == EntityKind::FeedProvider {
            sub = sub.merge(crate::feeds::api::provider_item_routes());
        }
        if er.kind == EntityKind::Bundle {
            sub = sub.merge(crate::compiler::api::item_routes());
        }
        if er.kind == EntityKind::LookupProvider {
            sub = sub.merge(crate::lookups::api::item_routes());
        }
        r = r.nest(&format!("/{}", er.path), sub);
    }
    r = r.merge(crate::feeds::api::routes());
    r = r.merge(crate::compiler::api::routes());
    r = r.merge(crate::logs::api::routes());
    r = r.merge(crate::lookups::api::routes());
    r = r.merge(crate::dnssec::api::routes());
    r = r.route("/browser-extension", get(super::browser_extension::list));
    r = r.route("/browser-lists", get(browser_lists));
    // After every route (nested ones are flattened into this router), so each takes it.
    r.method_not_allowed_fallback(method_not_allowed)
        .fallback(not_found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging() {
        let items: Vec<(String, u32)> = (0..7).map(|i| (format!("k{i}"), i)).collect();
        let q = PageQuery {
            cursor: None,
            limit: Some(3),
        };
        let p1 = page_by_key(items.clone(), &q).unwrap();
        assert_eq!(p1.items, vec![0, 1, 2]);
        let q2 = PageQuery {
            cursor: p1.next_cursor.clone(),
            limit: Some(3),
        };
        let p2 = page_by_key(items.clone(), &q2).unwrap();
        assert_eq!(p2.items, vec![3, 4, 5]);
        let q3 = PageQuery {
            cursor: p2.next_cursor.clone(),
            limit: Some(3),
        };
        let p3 = page_by_key(items, &q3).unwrap();
        assert_eq!(p3.items, vec![6]);
        assert!(p3.next_cursor.is_none());
        assert!(
            page_by_key(
                Vec::<(String, u32)>::new(),
                &PageQuery {
                    cursor: Some("!!".into()),
                    limit: None
                }
            )
            .is_err()
        );
    }
}
