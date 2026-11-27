//! The UI API routes over the query log (core.md §12; api.md §7):
//!
//! | Route | |
//! |---|---|
//! | `GET logs` | search: time range, edge, client, device, qname (exact, suffix, substring), decision, profile, bundle; newest partition first, cursor pagination |
//! | `GET logs/{id}` | one record: the reply the client got, the upstream answer, attribution with roles, lookups, would-blocks, versions |
//! | `GET top?kind=blocked\|allowed\|clients&window&edge&limit` | the dashboard's top panels (api.md §7) |
//! | `GET devices` | the devices in the logged records (Clients page) |
//! | `GET query-summary?device=…\|profile=…&window&edge` | the device and per-profile views |
//! | `GET trial-results?profile&bundle&window&edge` | a trial bundle's would-blocks |
//! | `GET alerts/{id}/evidence` | an alert's evidence copies, counts, answers and `wire_mismatch` examples |
//!
//! A window longer than the query-log retention is refused (`422`, api.md §7).

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use schemars::JsonSchema;
use serde::Deserialize;

use super::query::{self, BadQuery, Scope, Subject};
use crate::state::SharedState;
use crate::web::error::{ApiError, ApiPath, ApiQuery, ApiResult};

fn map_err(e: anyhow::Error) -> ApiError {
    match e.downcast_ref::<BadQuery>() {
        Some(b) => ApiError::bad_request(b.0.clone()),
        None => ApiError::from(e),
    }
}

/// The window and edge of a chart-like call; `422` past the query-log retention.
fn scope(s: &SharedState, window: Option<&str>, edge: Option<&str>) -> ApiResult<Scope> {
    let now = jiff::Timestamp::now();
    let sc = Scope::parse(window, edge, now)
        .ok_or_else(|| ApiError::bad_request("window is 1h, 6h, 24h or 72h"))?;
    let retention = crate::util::sat_i64(s.settings().retention.query_logs.as_secs());
    if sc.secs() > retention {
        return Err(ApiError::unprocessable(format!(
            "the window is longer than the query-log retention ({retention} s)"
        )));
    }
    Ok(sc)
}

async fn search(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<query::LogQuery>,
) -> ApiResult<Json<query::LogPage>> {
    let store = s.logs.writer().store().clone();
    let retention = s.settings().retention.query_logs.as_duration();
    let page =
        tokio::task::spawn_blocking(move || query::search(&store, &q, retention, jiff::Timestamp::now()))
            .await
            .map_err(|e| ApiError::from(anyhow::anyhow!("search task: {e}")))?
            .map_err(map_err)?;
    Ok(Json(page))
}

async fn detail(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<query::LogDetail>> {
    let store = s.logs.writer().store().clone();
    let d =
        s.db.read(move |c| query::detail(&store, c, &id))
            .await
            .map_err(map_err)?
            .ok_or_else(|| ApiError::not_found("no such record (it may have aged out of the log)"))?;
    Ok(Json(d))
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct TopQuery {
    /// `blocked`, `allowed` or `clients`.
    pub kind: String,
    pub window: Option<String>,
    pub edge: Option<String>,
    /// Default 10, at most 100.
    pub limit: Option<usize>,
}

async fn top(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<TopQuery>,
) -> ApiResult<Json<query::TopList>> {
    let sc = scope(&s, q.window.as_deref(), q.edge.as_deref())?;
    let store = s.logs.writer().store().clone();
    let limit = crate::web::api::limit_param(q.limit, query::TOP_DEFAULT, query::TOP_MAX)?;
    let t = tokio::task::spawn_blocking(move || query::top(&store, &q.kind, &sc, limit))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!("top task: {e}")))?
        .map_err(map_err)?;
    Ok(Json(t))
}

async fn devices(State(s): State<SharedState>) -> ApiResult<Json<query::DeviceList>> {
    let model = s.config.model().await?;
    let store = s.logs.writer().store().clone();
    let d = tokio::task::spawn_blocking(move || query::devices(&store, &model.clients))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!("devices task: {e}")))?
        .map_err(map_err)?;
    Ok(Json(d))
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct SummaryQuery {
    /// A device key (its client name, MAC or address); or `profile`.
    pub device: Option<String>,
    pub profile: Option<String>,
    pub window: Option<String>,
    pub edge: Option<String>,
}

async fn summary(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<SummaryQuery>,
) -> ApiResult<Json<query::Summary>> {
    let subject = match (
        q.device.filter(|d| !d.is_empty()),
        q.profile.filter(|p| !p.is_empty()),
    ) {
        (Some(d), None) if d.len() <= 256 => Subject::Device(d),
        (None, Some(p)) if p.len() <= 128 => Subject::Profile(p),
        _ => return Err(ApiError::bad_request("name one device or one profile")),
    };
    let sc = scope(&s, q.window.as_deref(), q.edge.as_deref())?;
    // core.db first, its reader released before the partitions are read (README §2 Bounded: the
    // read pool is small and shared).
    let allows = {
        let (subject, sc) = (subject.clone(), sc.clone());
        s.db.read(move |c| query::summary_allows(c, &subject, &sc))
            .await
            .map_err(map_err)?
    };
    let store = s.logs.writer().store().clone();
    let (sub, sc2) = (subject.clone(), sc.clone());
    let (mut out, devices) = tokio::task::spawn_blocking(move || query::summary(&store, &sub, &sc2, allows))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!("summary task: {e}")))?
        .map_err(map_err)?;
    // A profile's devices are known once the partitions are read: their allows come after, in a
    // read of their own (core.md §12 per-profile view).
    if matches!(subject, Subject::Profile(_)) {
        out.temporary_allows =
            s.db.read(move |c| query::profile_allows(c, &devices, &sc))
                .await
                .map_err(map_err)?;
    }
    Ok(Json(out))
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct TrialQuery {
    pub profile: String,
    pub bundle: String,
    pub window: Option<String>,
    pub edge: Option<String>,
}

async fn trial_results(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<TrialQuery>,
) -> ApiResult<Json<query::TrialResults>> {
    if q.profile.is_empty() || q.profile.len() > 128 || q.bundle.is_empty() || q.bundle.len() > 128 {
        return Err(ApiError::bad_request("profile and bundle: ids"));
    }
    let sc = scope(&s, q.window.as_deref(), q.edge.as_deref())?;
    let store = s.logs.writer().store().clone();
    let out = tokio::task::spawn_blocking(move || query::trial_results(&store, &q.profile, &q.bundle, &sc))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!("trial task: {e}")))?
        .map_err(map_err)?;
    Ok(Json(out))
}

/// `GET alerts/{id}/evidence` paging (api.md §7 cursor pagination).
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct EvidenceQuery {
    pub cursor: Option<String>,
    /// Copies per page: default 100, at most 500.
    pub limit: Option<usize>,
}

async fn evidence(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<i64>,
    ApiQuery(q): ApiQuery<EvidenceQuery>,
) -> ApiResult<Json<query::EvidenceView>> {
    let limit = crate::web::api::limit_param(q.limit, query::EVIDENCE_PAGE, query::EVIDENCE_PAGE_MAX)?;
    let v =
        s.db.read(move |c| query::evidence(c, id, q.cursor.as_deref(), limit))
            .await
            .map_err(map_err)?
            .ok_or_else(|| ApiError::not_found(format!("no alert {id}")))?;
    Ok(Json(v))
}

/// The routes, merged into `/api/ui/v1`.
pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/logs", get(search))
        .route("/logs/{id}", get(detail))
        .route("/top", get(top))
        .route("/devices", get(devices))
        .route("/query-summary", get(summary))
        .route("/trial-results", get(trial_results))
        .route("/alerts/{id}/evidence", get(evidence))
}
