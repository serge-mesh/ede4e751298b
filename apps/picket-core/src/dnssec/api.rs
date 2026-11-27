//! The DNSSEC page's UI API routes (core.md §12 "DNSSEC: queue, recent Bogus results"):
//!
//! | Route | |
//! |---|---|
//! | `GET dnssec/queue?limit` | the validation backlog, earliest due first, with its depth, and the cross-check queue's |
//! | `GET dnssec/results?outcome&cursor&limit` | results in the retention window, newest first; `outcome=bogus` for the recent Bogus ones |

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::queue;
use crate::state::SharedState;
use crate::web::error::{ApiError, ApiQuery, ApiResult};

/// One queued check.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DnssecQueueItem {
    pub qname: String,
    pub qtype: String,
    /// `answer` (a logged answer), `fallback` (core's own query) or `servfail` (an upstream
    /// SERVFAIL's query, never retried).
    pub kind: String,
    /// Failed requests so far (an item waiting for a reachable edge uses none).
    pub attempts: i64,
    pub next_at: Option<String>,
    pub queued_at: String,
    /// The logged answer's `received_at`, the time it is validated as of.
    pub received_at: Option<String>,
    /// The edges, clients and upstream groups of the records sharing the check.
    pub edges: Vec<String>,
    pub clients: Vec<String>,
    pub groups: Vec<String>,
    /// Records sharing the check.
    pub records: u64,
}

/// The DNSSEC and cross-check queues.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DnssecQueue {
    pub items: Vec<DnssecQueueItem>,
    /// Items in `dnssec_queue`.
    pub depth: i64,
    /// Items in `crosscheck_queue`.
    pub crosscheck_depth: i64,
    /// The first `limit` of them, earliest due first.
    pub crosscheck_items: Vec<super::crosscheck::CrosscheckQueueItem>,
}

/// The most items `GET dnssec/queue` lists and `GET dnssec/results` pages at a time (`limit`,
/// default 100; README §2 Bounded).
pub const MAX_LIST: usize = 500;

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct QueueQuery {
    /// Items listed of each queue (default 100, 1 to 500; else `400`).
    pub limit: Option<usize>,
}

async fn get_queue(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<QueueQuery>,
) -> ApiResult<Json<DnssecQueue>> {
    let limit = crate::web::api::limit_param(q.limit, 100, MAX_LIST)?;
    let (items, depth) =
        s.db.read(move |c| Ok::<_, anyhow::Error>(queue::list(c, limit)?))
            .await?;
    let (cc_items, cc_depth) = super::crosscheck::queue_view(&s, limit).await?;
    Ok(Json(DnssecQueue {
        items: items
            .into_iter()
            .map(|it| DnssecQueueItem {
                qname: it.qname,
                qtype: it.qtype,
                kind: it.kind.as_str().into(),
                attempts: it.attempts,
                next_at: Some(it.next_at),
                queued_at: it.first_seen,
                received_at: it.received_at,
                edges: it.ctx.edges,
                clients: it.ctx.clients,
                groups: it.ctx.groups,
                records: it.ctx.n,
            })
            .collect(),
        depth,
        crosscheck_depth: cc_depth,
        crosscheck_items: cc_items,
    }))
}

/// One validation result (core.md §8 "Outcomes").
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DnssecResult {
    pub id: i64,
    /// The name checked.
    pub name: String,
    pub qtype: String,
    pub outcome: String,
    /// `answer`, `fallback` or `servfail`.
    pub kind: Option<String>,
    /// The zone where validation broke (Bogus), else null.
    pub zone: Option<String>,
    /// The RFC 8914 code 1.1.1.1 would return (Bogus).
    pub ede: Option<u16>,
    pub ede_text: Option<String>,
    /// hickory's proof error.
    pub proof: Option<String>,
    /// The validator's upstream group.
    pub group: Option<String>,
    pub edges: Vec<String>,
    pub clients: Vec<String>,
    /// The upstream groups the records were answered by.
    pub groups: Vec<String>,
    /// The logged answer and the time it was validated as of (null for core's own query).
    pub answer_id: Option<String>,
    pub received_at: Option<String>,
    pub at: String,
}

/// A page of results.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DnssecResultPage {
    pub items: Vec<DnssecResult>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct ResultQuery {
    /// `secure`, `insecure`, `bogus` or `indeterminate`.
    pub outcome: Option<String>,
    /// The `next_cursor` of the previous page.
    pub cursor: Option<String>,
    /// Items per page (default 100, at most 500).
    pub limit: Option<usize>,
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

async fn get_results(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<ResultQuery>,
) -> ApiResult<Json<DnssecResultPage>> {
    let limit = crate::web::api::limit_param(q.limit, 100, MAX_LIST)?;
    if let Some(o) = &q.outcome
        && super::validator::Outcome::parse(o).is_none()
    {
        return Err(ApiError::bad_request(
            "outcome is secure, insecure, bogus or indeterminate",
        ));
    }
    let before: i64 = match &q.cursor {
        Some(c) => c
            .parse()
            .map_err(|_| ApiError::bad_request("cursor isn't one this API gave"))?,
        None => i64::MAX,
    };
    let outcome = q.outcome.clone();
    let rows =
        s.db.read(move |c| {
            let mut st = c.prepare(
                "SELECT id, qname, qtype, outcome, detail, answer_id, received_at, at FROM dnssec_results
                 WHERE id < ?1 AND (?2 IS NULL OR outcome = ?2) ORDER BY id DESC LIMIT ?3",
            )?;
            let rows = st.query_map(params![before, outcome, limit + 1], |r| {
                let detail: Value = r
                    .get::<_, Option<String>>(4)?
                    .and_then(|d| serde_json::from_str(&d).ok())
                    .unwrap_or(Value::Null);
                let ede = detail
                    .get("ede")
                    .and_then(Value::as_u64)
                    .and_then(|e| u16::try_from(e).ok());
                Ok(DnssecResult {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    qtype: r.get(2)?,
                    outcome: r.get(3)?,
                    kind: detail.get("kind").and_then(Value::as_str).map(str::to_string),
                    zone: detail.get("zone").and_then(Value::as_str).map(str::to_string),
                    ede,
                    ede_text: ede.map(|e| super::ede_text(e).to_string()),
                    proof: detail.get("proof").and_then(Value::as_str).map(str::to_string),
                    group: detail.get("group").and_then(Value::as_str).map(str::to_string),
                    edges: strings(detail.get("edges")),
                    clients: strings(detail.get("clients")),
                    groups: strings(detail.get("groups")),
                    answer_id: r.get(5)?,
                    received_at: r.get(6)?,
                    at: r.get(7)?,
                })
            })?;
            Ok::<_, anyhow::Error>(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await?;
    let mut items = rows;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|r| r.id.to_string())
    } else {
        None
    };
    Ok(Json(DnssecResultPage { items, next_cursor }))
}

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/dnssec/queue", get(get_queue))
        .route("/dnssec/results", get(get_results))
}
