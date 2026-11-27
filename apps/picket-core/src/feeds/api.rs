//! The feeds' UI API (api.md §7, core.md §12 Feed providers, Feeds and Warninglists pages),
//! under `/api/ui/v1`, beside the generic feed provider and feed CRUD:
//!
//! | Route | What |
//! |---|---|
//! | `GET feed-provider-status`, `GET feed-providers/{id}/status` | providers' trigger, checks, `k`, listing, SQS state |
//! | `POST feed-providers/{id}/check` | "Check now" (checks are per provider, never per feed): bypasses the trigger, not `min_interval` |
//! | `GET feed-providers/{id}/listing` | the stored listing (or declared paths), S3 ListObjectsV2-style (`?prefix=&delimiter=/`: folders and files) or a search of the paths (`?q=`), paged, each file with its feed or none |
//! | `POST feed-providers/{id}/files` | **Add as feed**: appends the file to the provider's `files` |
//! | `GET feed-providers/{id}/checks`, `GET feed-providers/{id}/backtest` | provider check history; a replay with simulated checks |
//! | `GET feed-providers-review` | new feeds awaiting review (an open `feed_added`) |
//! | `POST feed-providers-add-url` | add a feed by URL: picks or creates the provider, adds the file to its `files` |
//! | `GET download-modules` | each download module with its `Config` schema and whether it lists files |
//! | `GET feed-status`, `GET feeds/{id}/status` | every feed's status; one feed's status, metrics and learned schedule |
//! | `GET feeds/{id}/runs`, `GET feeds/{id}/runs/{run}` | run history, a run's result (counts, parse errors, policy drops) |
//! | `GET feeds/{id}/checks` | check history |
//! | `GET feeds/{id}/entries` | the feed's current entries |
//! | `GET feeds/{id}/policy-drops` | rules `rule_policy` dropped |
//! | `GET feeds/{id}/schedule` | the learned pattern |
//! | `GET/PUT feeds/{id}/file`, `POST feeds/{id}/file/lines` | manual feed files |
//! | `GET feeds/{id}/export` (`?as=file`), `GET feeds/{id}/export-size` | export (feeds.md §4) |
//! | `POST feeds/import`, `POST feeds/{id}/import` | import into a new manual feed, an existing manual feed, or a provider feed |
//! | `GET feed-presets`, `POST feed-presets/{id}` | bundled presets |
//! | `GET warninglists` | warn bundles, their member feeds, the feeds whose `warn_on` names each |

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use jiff::Timestamp;
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::store::{self, RunRow};
use super::types::TypeCounts;
use super::{Cause, Triggered, manual, presets};
use crate::config::Actor;
use crate::config::model::{BundleAction, FeedDef, FeedProviderDef};
use crate::state::SharedState;
use crate::web::api::{Page, PageQuery, decode_cursor, encode_cursor};
use crate::web::error::{ApiError, ApiPath, ApiQuery, ApiResult};
use crate::web::protect::PeerAddr;

fn actor(peer: Option<axum::Extension<PeerAddr>>) -> Actor {
    Actor::ui(peer.map(|p| crate::net::canonical_ip(p.0.0.ip()).to_string()))
}

/// The page size (`web::api::limit_param`: `400` out of range).
fn limit(q: &PageQuery) -> ApiResult<usize> {
    q.limit()
}

fn cursor_i64(q: &PageQuery) -> ApiResult<i64> {
    match &q.cursor {
        None => Ok(i64::MAX),
        Some(c) if c.is_empty() => Ok(i64::MAX),
        Some(c) => decode_cursor(c)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ApiError::bad_request("bad cursor")),
    }
}

async fn def_of(s: &SharedState, id: &str) -> ApiResult<FeedDef> {
    s.feeds
        .def_or_reload(s, id)
        .await
        .ok_or_else(|| ApiError::not_found(format!("no feed {id:?}")))
}

/// Hits from attribution in the last 24 h (core.md §6; the series `feed_hits{feed, role}`).
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct Hits {
    pub decisive: f64,
    pub also_matched: f64,
}

/// A feed's status (feeds.md §6, feed-scheduling.md §6 UI).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FeedStatus {
    pub feed: String,
    pub name: String,
    /// Its feed provider (null for a manual feed).
    pub provider: Option<String>,
    /// The provider's file it reads (null for a manual feed).
    pub file: Option<String>,
    pub enabled: bool,
    pub manual: bool,
    /// A check or run is in progress.
    pub busy: bool,
    /// The provider's next check (feeds are checked with their provider).
    pub next_check: Option<String>,
    /// The feed's own ask (feed-scheduling.md §5).
    pub next_ask: Option<String>,
    pub last_check: Option<String>,
    pub last_ok: Option<String>,
    /// Consecutive failed checks.
    pub failures: u32,
    pub failing_since: Option<String>,
    /// The module's rate-limit pause.
    pub paused_until: Option<String>,
    /// The last download (a run's source).
    pub last_download: Option<String>,
    /// The source's update time of the latest applied run.
    pub last_change: Option<String>,
    /// Seconds since that update.
    pub since_last_change_s: Option<i64>,
    pub checks_24h: u64,
    pub failures_24h: u64,
    pub changes_7d: u64,
    /// Entries per rule type, as the latest run that changed them left them.
    pub totals: TypeCounts,
    /// A run waiting for confirmation.
    pub held_run: Option<i64>,
    pub latest_run: Option<RunRow>,
    /// The learned pattern in words.
    pub pattern: Option<String>,
    pub k: Option<f64>,
    pub median_delay_s: Option<f64>,
    pub p90_delay_s: Option<f64>,
    pub hits_24h: Hits,
    /// A manual feed's file version, as `GET feeds/{id}/file` gives it without the content
    /// (null for a provider feed, or before the first save).
    pub version: Option<String>,
    /// When that file was saved: the `updated_at` of the run that reads it (feeds.md §1).
    pub saved_at: Option<String>,
    /// A manual feed's run that couldn't start (a full heavy lane) or failed: when core tries it
    /// again. With `busy`, it tells "a run is coming" from "no run is coming".
    pub manual_retry_at: Option<String>,
}

async fn status_of(s: &SharedState, def: &FeedDef) -> ApiResult<FeedStatus> {
    let id = def.id.clone();
    let now = Timestamp::now();
    let day = crate::util::ts(&(now - jiff::SignedDuration::from_hours(24)));
    let week = crate::util::ts(&(now - jiff::SignedDuration::from_hours(24 * 7)));
    let f = id.clone();
    let manual = def.is_manual();
    let (st, latest, change, newest_dl, counts, delays, file) = s
        .db
        .read(move |c| {
            let file = if manual { store::manual_file(c, &f)? } else { None };
            let st = store::load_state(c, &f)?;
            let latest = c
                .query_row(
                    &format!("SELECT {} FROM feed_runs WHERE feed_id = ?1 ORDER BY id DESC LIMIT 1", store::RUN_COLUMNS),
                    [&f],
                    store::row_to_run,
                )
                .ok();
            let change = store::latest_change(c, &f)?;
            let newest_dl = store::newest_download(c, &f)?;
            let counts: (i64, i64, i64) = c.query_row(
                "SELECT (SELECT count(*) FROM feed_checks WHERE feed_id = ?1 AND t >= ?2 AND method <> 'bootstrap'),
                        (SELECT count(*) FROM feed_checks WHERE feed_id = ?1 AND t >= ?2 AND ok = 0),
                        (SELECT count(*) FROM feed_changes WHERE feed_id = ?1 AND t_seen >= ?3 AND origin = 'check')",
                params![f, day, week],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            let mut st2 = c.prepare(
                "SELECT t_change, t_seen FROM feed_changes WHERE feed_id = ?1 AND exact = 1 AND origin = 'check' AND t_seen >= ?2",
            )?;
            let delays: Vec<f64> = st2
                .query_map(params![f, week], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .filter_map(|r| r.ok())
                .filter_map(|(a, b)| {
                    let (a, b) = (crate::util::parse_ts(&a)?, crate::util::parse_ts(&b)?);
                    Some((b - a).as_millis() as f64 / 1000.0)
                })
                .collect();
            Ok::<_, anyhow::Error>((st, latest, change, newest_dl, counts, delays, file))
        })
        .await?;
    let mut delays = delays;
    delays.sort_by(f64::total_cmp);
    let pct = |q: f64| -> Option<f64> {
        (!delays.is_empty())
            .then(|| delays[crate::util::f64_to_usize(((delays.len() as f64 - 1.0) * q).round())])
    };
    let learner = s.feeds.learner(&id);
    let hits = hits_24h(s, &id).await;
    let last_change = change.as_ref().and_then(|r| r.updated_at.clone());
    let module = def
        .provider
        .as_deref()
        .and_then(|p| s.feeds.provider_def(p))
        .map(|p| p.module);
    Ok(FeedStatus {
        feed: id.clone(),
        name: def.name.clone(),
        provider: def.provider.clone(),
        file: def.file.clone(),
        enabled: def.enabled,
        manual: def.is_manual(),
        busy: s.feeds.is_busy(&id),
        next_check: match (&def.provider, def.enabled) {
            (Some(p), true) => s.feeds.next_due(p).map(|t| crate::util::ts(&t)),
            _ => None,
        },
        next_ask: s.feeds.ask(&id).map(|t| crate::util::ts(&t)),
        last_check: st.last_check_at.map(|t| crate::util::ts(&t)),
        last_ok: st.last_ok_at.map(|t| crate::util::ts(&t)),
        failures: st.failures,
        failing_since: st.failing_since.map(|t| crate::util::ts(&t)),
        paused_until: module
            .and_then(|m| s.feeds.paused_until(&m))
            .map(|t| crate::util::ts(&t)),
        last_download: st.last_download_at.map(|t| crate::util::ts(&t)),
        since_last_change_s: last_change
            .as_deref()
            .and_then(crate::util::parse_ts)
            .map(|t| (now - t).as_secs().max(0)),
        last_change,
        checks_24h: crate::util::nonneg(counts.0),
        failures_24h: crate::util::nonneg(counts.1),
        changes_7d: crate::util::nonneg(counts.2),
        totals: change.map(|r| r.total).unwrap_or_default(),
        held_run: newest_dl
            .filter(|r| r.status == Some(super::types::RunStatus::Held))
            .map(|r| r.id),
        latest_run: latest,
        pattern: learner
            .as_ref()
            .map(|l| l.describe(super::schedule::to_secs(now))),
        k: learner.as_ref().map(|l| l.k),
        median_delay_s: pct(0.5),
        p90_delay_s: pct(0.9),
        hits_24h: hits,
        version: file.as_ref().map(|(_, v, _)| v.clone()),
        saved_at: file.as_ref().map(|(_, _, at)| crate::util::ts(at)),
        manual_retry_at: s.feeds.manual_retry(&id).map(|t| crate::util::ts(&t)),
    })
}

async fn hits_24h(s: &SharedState, feed: &str) -> Hits {
    let since = (Timestamp::now() - jiff::SignedDuration::from_hours(24)).as_millisecond();
    let f = feed.to_string();
    s.metrics_db
        .read(move |c| Ok::<_, anyhow::Error>(hits_in(c, &f, since)?))
        .await
        .unwrap_or_default()
}

/// A feed's `feed_hits` since `since` (Unix ms; core.md §6, §10): its two series found by their
/// exact labels (`series` is unique on name and labels, stored as `metrics::labels` serialise),
/// then their points through `points_series_ts`, so each status reads only its own feed's
/// series, however many feeds there are (core.md §3).
fn hits_in(c: &rusqlite::Connection, feed: &str, since: i64) -> rusqlite::Result<Hits> {
    let mut st = c.prepare_cached(
        "SELECT coalesce(sum(p.value), 0) FROM series s JOIN points p ON p.series_id = s.id
         WHERE s.name = 'feed_hits' AND s.labels_json = ?1 AND p.ts >= ?2",
    )?;
    let mut sum = |role: &str| -> rusqlite::Result<f64> {
        let labels = crate::metrics::labels("", &[("feed", feed), ("role", role)]);
        let labels = serde_json::to_string(&labels).unwrap_or_default();
        st.query_row(rusqlite::params![labels, since], |r| r.get(0))
    };
    Ok(Hits {
        decisive: sum("decisive")?,
        also_matched: sum("also_matched")?,
    })
}

async fn feed_status(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<FeedStatus>> {
    let def = def_of(&s, &id).await?;
    Ok(Json(status_of(&s, &def).await?))
}

async fn all_status(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<FeedStatus>>> {
    let model = s.config.model_of(crate::config::EntityKind::Feed).await?;
    Ok(Json(key_page(&model.feeds, &q, |def| status_of(&s, def)).await?))
}

/// The marker before the key inside [`key_page`]'s cursors, so a page ending at the empty key
/// (a declared path `""`) still gives a cursor that differs from none.
const KEY_CURSOR: char = '\0';

/// The key after which a [`key_page`] cursor continues: what follows [`KEY_CURSOR`]; a cursor
/// without it (given before the marker) is the key as a whole. `400` when it isn't one.
fn cursor_key(c: &str) -> ApiResult<String> {
    let k = decode_cursor(c).ok_or_else(|| ApiError::bad_request("bad cursor"))?;
    Ok(match k.strip_prefix(KEY_CURSOR) {
        Some(key) => key.to_string(),
        None => k,
    })
}

/// One page of a list in key order (api.md §7 cursor pagination): the entries after the query's
/// cursor, each read by `read`; the next cursor names the last key returned (after
/// [`KEY_CURSOR`]), when more follow.
/// `entries` comes in ascending key order, each key once. Each key is its item's own id or path,
/// so an item that exists throughout a walk shows on exactly one page, whatever else is added or
/// removed between pages. The status lists page so by id (`GET feed-status`,
/// `GET feed-provider-status`), a provider's listing by path or common prefix
/// (`GET feed-providers/{id}/listing`).
async fn key_page<'a, K, D, T, Fut>(
    entries: impl IntoIterator<Item = (K, &'a D)>,
    q: &PageQuery,
    mut read: impl FnMut(&'a D) -> Fut,
) -> ApiResult<Page<T>>
where
    K: AsRef<str>,
    D: ?Sized + 'a,
    Fut: std::future::Future<Output = ApiResult<T>>,
{
    let after = q
        .cursor
        .as_deref()
        .filter(|c| !c.is_empty())
        .map(cursor_key)
        .transpose()?;
    let lim = limit(q)?;
    let mut items = Vec::new();
    let mut last: Option<K> = None;
    for (key, item) in entries
        .into_iter()
        .filter(|(key, _)| after.as_deref().is_none_or(|a| key.as_ref() > a))
    {
        if items.len() == lim {
            return Ok(Page {
                items,
                next_cursor: last.map(|k| encode_cursor(&format!("{KEY_CURSOR}{}", k.as_ref()))),
            });
        }
        items.push(read(item).await?);
        last = Some(key);
    }
    Ok(Page {
        items,
        next_cursor: None,
    })
}

async fn runs(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<RunRow>>> {
    def_of(&s, &id).await?;
    let before = cursor_i64(&q)?;
    let lim = limit(&q)?;
    let mut items =
        s.db.read(move |c| {
            let mut st = c.prepare(&format!(
                "SELECT {} FROM feed_runs WHERE feed_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
                store::RUN_COLUMNS
            ))?;
            let v = st
                .query_map(params![id, before, lim + 1], store::row_to_run)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    let next = if items.len() > lim {
        items.truncate(lim);
        items.last().map(|r| encode_cursor(&r.id.to_string()))
    } else {
        None
    };
    Ok(Json(Page {
        items,
        next_cursor: next,
    }))
}

/// A rule `rule_policy` dropped.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct PolicyDrop {
    pub id: i64,
    /// `redirects`, `client_rules`, `browser_changes` (comma-separated when several cover it).
    pub option: String,
    /// The rule as written (shown as text only).
    pub raw: String,
    pub first_run: i64,
    pub last_seen_run: i64,
    /// `open` while the feed has the rule, `resolved` after.
    pub status: String,
}

/// A run with its dropped rules.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RunDetail {
    pub run: RunRow,
    /// Rules this run's `rule_policy` dropped (the first 100).
    pub policy_drops: Vec<PolicyDrop>,
}

fn row_to_drop(r: &rusqlite::Row<'_>) -> rusqlite::Result<PolicyDrop> {
    Ok(PolicyDrop {
        id: r.get(0)?,
        option: r.get(1)?,
        raw: r.get(2)?,
        first_run: r.get(3)?,
        last_seen_run: r.get(4)?,
        status: r.get(5)?,
    })
}

async fn run_detail(
    State(s): State<SharedState>,
    ApiPath((id, run)): ApiPath<(String, i64)>,
) -> ApiResult<Json<RunDetail>> {
    def_of(&s, &id).await?;
    let r =
        s.db.read(move |c| {
            // A held or rejected run that was applied later moved to a newer id (its old one is
            // in `source_run`): the old id still finds it (alerts and events name it).
            let found = match store::run_by_id(c, run)?.filter(|r| r.feed_id == id) {
                Some(r) => Some(r),
                None => c
                    .query_row(
                        &format!(
                            "SELECT {} FROM feed_runs WHERE feed_id = ?1 AND source_run = ?2",
                            store::RUN_COLUMNS
                        ),
                        params![id, run],
                        store::row_to_run,
                    )
                    .optional()?,
            };
            let Some(run) = found else {
                return Ok::<_, anyhow::Error>(None);
            };
            let mut st = c.prepare(
                "SELECT id, option, raw, first_run, last_seen_run, status FROM policy_drops
                 WHERE feed_id = ?1 AND first_run <= ?2 AND last_seen_run >= ?2 ORDER BY id LIMIT 100",
            )?;
            let drops = st
                .query_map(params![id, run.id], row_to_drop)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Some(RunDetail {
                run,
                policy_drops: drops,
            }))
        })
        .await?;
    r.map(Json).ok_or_else(|| ApiError::not_found("no such run"))
}

/// One check.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct CheckView {
    pub id: i64,
    pub t: String,
    pub duration_ms: Option<i64>,
    pub method: Option<String>,
    pub ok: bool,
    pub changed: Option<bool>,
    pub bytes: Option<i64>,
    /// The provider's version at the check.
    pub version: Option<String>,
    pub predicted_rate: Option<f64>,
    pub error: Option<String>,
}

async fn checks(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<CheckView>>> {
    def_of(&s, &id).await?;
    let before = cursor_i64(&q)?;
    let lim = limit(&q)?;
    let mut items = s
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT id, t, duration_ms, method, ok, changed, bytes, ref, predicted_rate, error FROM feed_checks
                 WHERE feed_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
            )?;
            let v = st
                .query_map(params![id, before, lim + 1], |r| {
                    Ok(CheckView {
                        id: r.get(0)?,
                        t: r.get(1)?,
                        duration_ms: r.get(2)?,
                        method: r.get(3)?,
                        ok: r.get::<_, i64>(4)? != 0,
                        changed: r.get::<_, Option<i64>>(5)?.map(|v| v != 0),
                        bytes: r.get(6)?,
                        version: r.get(7)?,
                        predicted_rate: r.get(8)?,
                        error: r.get(9)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    let next = if items.len() > lim {
        items.truncate(lim);
        items.last().map(|r| encode_cursor(&r.id.to_string()))
    } else {
        None
    };
    Ok(Json(Page {
        items,
        next_cursor: next,
    }))
}

/// `?rule_type=&q=&cursor=&limit=` on the entry list.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct EntryQuery {
    pub rule_type: Option<String>,
    /// A substring of the rule as written.
    pub q: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// One current entry (storage.md §3 `feed_entries`).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EntryView {
    pub id: i64,
    pub rule_type: String,
    pub key: String,
    pub kind: String,
    pub flags: i64,
    /// The rule as written, as first seen (shown as text only).
    pub raw: String,
    pub line_no: Option<i64>,
    pub first_run: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
    /// `aggregate` types: when the first applied run without it ran.
    pub dropped_at: Option<String>,
}

async fn entries(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<EntryQuery>,
) -> ApiResult<Json<Page<EntryView>>> {
    def_of(&s, &id).await?;
    let pq = PageQuery {
        cursor: q.cursor.clone(),
        limit: q.limit,
    };
    let after = match cursor_i64(&pq)? {
        i64::MAX => 0,
        v => v,
    };
    let lim = limit(&pq)?;
    let rule_type = q
        .rule_type
        .clone()
        .filter(|t| picket_rules::RuleType::parse(t).is_some());
    let like = q.q.as_ref().filter(|x| !x.is_empty()).map(|x| {
        let esc: String = x
            .chars()
            .take(256)
            .flat_map(|c| match c {
                '%' | '_' | '\\' => vec!['\\', c],
                c => vec![c],
            })
            .collect();
        format!("%{esc}%")
    });
    let mut items = s
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT id, rule_type, key, kind, flags, raw, line_no, first_run, first_seen_at, last_seen_at, dropped_at
                 FROM feed_entries WHERE feed_id = ?1 AND removed_run IS NULL AND id > ?2
                   AND (?3 IS NULL OR rule_type = ?3) AND (?4 IS NULL OR raw LIKE ?4 ESCAPE '\\')
                 ORDER BY id LIMIT ?5",
            )?;
            let v = st
                .query_map(params![id, after, rule_type, like, lim + 1], |r| {
                    Ok(EntryView {
                        id: r.get(0)?,
                        rule_type: r.get(1)?,
                        key: r.get(2)?,
                        kind: r.get(3)?,
                        flags: r.get(4)?,
                        raw: r.get(5)?,
                        line_no: r.get(6)?,
                        first_run: r.get(7)?,
                        first_seen_at: r.get(8)?,
                        last_seen_at: r.get(9)?,
                        dropped_at: r.get(10)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    let next = if items.len() > lim {
        items.truncate(lim);
        items.last().map(|r| encode_cursor(&r.id.to_string()))
    } else {
        None
    };
    Ok(Json(Page {
        items,
        next_cursor: next,
    }))
}

async fn policy_drops(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<PolicyDrop>>> {
    def_of(&s, &id).await?;
    let before = cursor_i64(&q)?;
    let lim = limit(&q)?;
    let mut items =
        s.db.read(move |c| {
            let mut st = c.prepare(
                "SELECT id, option, raw, first_run, last_seen_run, status FROM policy_drops
                 WHERE feed_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
            )?;
            let v = st
                .query_map(params![id, before, lim + 1], row_to_drop)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    let next = if items.len() > lim {
        items.truncate(lim);
        items.last().map(|r| encode_cursor(&r.id.to_string()))
    } else {
        None
    };
    Ok(Json(Page {
        items,
        next_cursor: next,
    }))
}

/// The learned schedule (feed-scheduling.md §6 UI).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ScheduleView {
    pub kind: String,
    pub pattern: Option<String>,
    /// The best candidate's period in seconds (null: no period).
    pub period_s: Option<u64>,
    pub k: Option<f64>,
    pub k_chosen_at: Option<String>,
    pub next_check: Option<String>,
    /// Changes the learner placed in the last 7 days.
    pub changes_7d: usize,
    /// Checks the learner saw in the last 24 h.
    pub checks_24h: usize,
}

async fn schedule_view(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<ScheduleView>> {
    let def = def_of(&s, &id).await?;
    let now = super::schedule::to_secs(Timestamp::now());
    let l = s.feeds.learner(&id);
    let provider = def.provider.as_deref().and_then(|p| s.feeds.provider_def(p));
    Ok(Json(ScheduleView {
        kind: provider
            .as_ref()
            .map_or_else(|| "manual".to_string(), |p| p.trigger.kind().to_string()),
        pattern: l.as_ref().map(|l| l.describe(now)),
        period_s: l
            .as_ref()
            .and_then(|l| l.candidates().get(l.best).and_then(|c| c.period)),
        k: l.as_ref().map(|l| l.k),
        k_chosen_at: l
            .as_ref()
            .and_then(|l| l.k_chosen_at)
            .map(|t| crate::util::ts(&super::schedule::from_unix(t))),
        next_check: def
            .provider
            .as_deref()
            .and_then(|p| s.feeds.next_due(p))
            .map(|t| crate::util::ts(&t)),
        changes_7d: l.as_ref().map_or(0, |l| {
            l.changes.iter().filter(|c| now - **c <= 7.0 * 86_400.0).count()
        }),
        checks_24h: l
            .as_ref()
            .map_or(0, |l| l.checks.iter().filter(|c| now - **c <= 86_400.0).count()),
    }))
}

/// `GET feeds/{id}/file`: `{version, saved_at, size, content}`, streamed from the blob.
async fn get_file(State(s): State<SharedState>, ApiPath(id): ApiPath<String>) -> ApiResult<Response> {
    let def = def_of(&s, &id).await?;
    if !def.is_manual() {
        return Err(ApiError::unprocessable(format!(
            "{id:?} is a provider feed: its file comes from its provider"
        )));
    }
    let info = manual::file_info(&s, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("the feed has no file yet"))?;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    let prefix = format!(
        "{{\"version\":{},\"saved_at\":{},\"size\":{},\"content\":\"",
        serde_json::to_string(&info.version).unwrap_or_default(),
        serde_json::to_string(&crate::util::ts(&info.saved_at)).unwrap_or_default(),
        info.size
    );
    let path = info.path.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        if tx.blocking_send(Ok(Bytes::from(prefix))).is_err() {
            return;
        }
        let mut f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                let _ = tx.blocking_send(Err(e));
                return;
            }
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut carry: Vec<u8> = Vec::new();
        loop {
            let n = match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    return;
                }
            };
            carry.extend_from_slice(&buf[..n]);
            let (text, rest) = utf8_lossy_prefix(&carry);
            let out = escape_json(&text);
            carry = rest;
            if tx.blocking_send(Ok(Bytes::from(out))).is_err() {
                return;
            }
        }
        let mut tail = String::new();
        if !carry.is_empty() {
            tail.push_str(&escape_json(&String::from_utf8_lossy(&carry)));
        }
        tail.push_str("\"}");
        let _ = tx.blocking_send(Ok(Bytes::from(tail)));
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|x| (x, rx)) });
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        axum::body::Body::from_stream(stream),
    )
        .into_response())
}

/// The valid UTF-8 prefix of `b` (invalid sequences as U+FFFD) and an incomplete trailing
/// sequence, kept for the next chunk.
fn utf8_lossy_prefix(b: &[u8]) -> (String, Vec<u8>) {
    let mut out = String::new();
    let mut rest = b;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                return (out, Vec::new());
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(good).unwrap_or_default());
                match e.error_len() {
                    None => return (out, bad.to_vec()),
                    Some(n) => {
                        out.push('\u{fffd}');
                        rest = &bad[n..];
                    }
                }
            }
        }
    }
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn save_error(e: manual::SaveError) -> ApiError {
    use manual::SaveError as E;
    match e {
        E::NotFound(m) => ApiError::not_found(format!("no feed {m:?}")),
        E::Invalid(m) => ApiError::unprocessable(m),
        E::Issues(issues) => ApiError::from(crate::error::CoreError::Validation(issues)),
        E::Syntax(m) => ApiError::bad_request(m),
        e @ E::Conflict { .. } => ApiError::new(StatusCode::CONFLICT, "conflict", e.to_string()),
        e @ E::TooLarge(_) => ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", e.to_string()),
        e @ E::Encoding(_) => ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_encoding",
            e.to_string(),
        ),
        e @ E::Timeout(_) => ApiError::new(StatusCode::REQUEST_TIMEOUT, "timeout", e.to_string()),
        e @ E::Busy(_) => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "busy", e.to_string()),
        E::Other(err) => {
            tracing::error!(error = %format!("{err:#}"), "manual feed write failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
        }
    }
}

fn encoding(h: &HeaderMap) -> Option<String> {
    h.get(axum::http::header::CONTENT_ENCODING)
        .map(|v| v.to_str().unwrap_or("unknown").to_string())
}

async fn put_file(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> ApiResult<Json<manual::SaveResult>> {
    manual::save(&s, &id, body, encoding(&headers).as_deref(), actor(peer))
        .await
        .map(Json)
        .map_err(save_error)
}

async fn append_lines(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> ApiResult<Json<manual::SaveResult>> {
    manual::append(&s, &id, body, encoding(&headers).as_deref(), actor(peer))
        .await
        .map(Json)
        .map_err(save_error)
}

async fn list_presets(State(s): State<SharedState>) -> ApiResult<Json<Vec<presets::PresetView>>> {
    let model = s.config.model_of(crate::config::EntityKind::Feed).await?;
    Ok(Json(
        presets::all()
            .iter()
            .map(|p| presets::PresetView {
                installed: presets::installed(p, &model),
                preset: p.clone(),
            })
            .collect(),
    ))
}

/// `POST feed-presets/{id}`: installs a preset. It reads no body: the JSON body every mutation
/// carries (core.md §12) is ignored, whatever it holds, so an empty or malformed one never gets
/// a reply outside the API's JSON (README §2).
async fn install_preset(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<presets::Installed>> {
    Ok(Json(presets::install(&s, &id, actor(peer)).await?))
}

/// A download module and its config form (api.md §7 `download-modules`).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ModuleInfo {
    pub id: String,
    /// `files` may hold globs: `check()` lists the provider's files.
    pub lists_files: bool,
    /// Each provider's one file, for a module whose providers have exactly one (`http`'s
    /// `response`): a new provider's `files` entry names it with its feed's settings.
    pub fixed_file: Option<String>,
    /// The settings that file's feed takes by default (`alphamountain_threat_1000`'s `plain`).
    pub default_feed: Option<Value>,
    /// The `Config` JSON Schema (the UI renders the provider form from it).
    pub config_schema: Value,
}

async fn download_modules(State(s): State<SharedState>) -> Json<Vec<ModuleInfo>> {
    let r = s.feeds.registry();
    Json(
        r.ids()
            .filter_map(|id| r.get(id))
            .map(|m| ModuleInfo {
                id: m.id().to_string(),
                lists_files: m.lists_files(),
                fixed_file: m.fixed_file().map(str::to_string),
                default_feed: m
                    .fixed_file()
                    .and_then(|_| m.default_files().into_iter().next().map(|(_, t)| t)),
                config_schema: serde_json::to_value(m.config_schema()).unwrap_or(Value::Null),
            })
            .collect(),
    )
}

/// A warn bundle (feeds.md §7, core.md §12 Warninglists page).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Warninglist {
    pub bundle: String,
    pub name: String,
    /// The warninglists: the bundle's member feeds.
    pub feeds: Vec<String>,
    /// The feeds whose `warn_on` names this bundle (checked against it where they block).
    pub checked_feeds: Vec<String>,
    /// Open warnings it found (from the compiler).
    pub open_warnings: i64,
}

async fn warninglists(State(s): State<SharedState>) -> ApiResult<Json<Vec<Warninglist>>> {
    let m = s.config.model().await?;
    let counts: std::collections::BTreeMap<String, i64> = s
        .db
        .read(|c| {
            let mut st = c.prepare(
                "SELECT by_bundle_id, count(*) FROM warnings WHERE kind = 'warn' AND status = 'open' AND by_bundle_id IS NOT NULL GROUP BY by_bundle_id",
            )?;
            let v = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<rusqlite::Result<std::collections::BTreeMap<_, _>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    Ok(Json(
        m.bundles
            .values()
            .filter(|b| b.action == BundleAction::Warn)
            .map(|b| Warninglist {
                bundle: b.id.clone(),
                name: b.name.clone(),
                feeds: b.feeds.iter().map(|f| f.feed.clone()).collect(),
                checked_feeds: m
                    .feeds
                    .values()
                    .filter(|f| f.effective_warn_on().contains(&b.id))
                    .map(|f| f.id.clone())
                    .collect(),
                open_warnings: counts.get(&b.id).copied().unwrap_or(0),
            })
            .collect(),
    ))
}

/// The routes under `feeds/` beside the generic CRUD (merged into its router).
pub fn item_routes() -> Router<SharedState> {
    Router::new()
        .route("/import", post(import_new))
        .route("/{id}/status", get(feed_status))
        .route("/{id}/runs", get(runs))
        .route("/{id}/runs/{run}", get(run_detail))
        .route("/{id}/checks", get(checks))
        .route("/{id}/entries", get(entries))
        .route("/{id}/policy-drops", get(policy_drops))
        .route("/{id}/schedule", get(schedule_view))
        .route("/{id}/file", get(get_file).put(put_file))
        .route("/{id}/file/lines", post(append_lines))
        .route("/{id}/export", get(export))
        .route("/{id}/export-size", get(export_size))
        .route("/{id}/import", post(import_into))
}

/// The routes under `feed-providers/` beside the generic CRUD (merged into its router).
pub fn provider_item_routes() -> Router<SharedState> {
    Router::new()
        .route("/{id}/status", get(provider_status))
        .route("/{id}/check", post(check_now))
        .route("/{id}/listing", get(provider_listing))
        .route("/{id}/files", post(add_as_feed))
        .route("/{id}/checks", get(provider_checks))
        .route("/{id}/backtest", get(backtest))
}

/// The top-level feed routes.
pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/feed-status", get(all_status))
        .route("/feed-provider-status", get(all_provider_status))
        .route("/feed-providers-review", get(review_queue))
        .route("/feed-providers-add-url", post(add_by_url))
        .route("/feed-presets", get(list_presets))
        .route("/feed-presets/{id}", post(install_preset))
        .route("/download-modules", get(download_modules))
        .route("/warninglists", get(warninglists))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`key_page`]'s cursor names the last key after a marker: a page ending at the empty key
    /// continues past it; a cursor given before the marker still reads as its key.
    #[tokio::test]
    async fn key_pages_past_an_empty_key() {
        let entries: std::collections::BTreeMap<String, u8> =
            [(String::new(), 0), ("a.txt".into(), 1), ("b".into(), 2)].into();
        let page = |cursor: Option<String>| {
            let entries = &entries;
            async move {
                let q = PageQuery {
                    cursor,
                    limit: Some(1),
                };
                key_page(entries, &q, |v| std::future::ready(Ok(*v)))
                    .await
                    .unwrap()
            }
        };
        let p1 = page(None).await;
        assert_eq!(p1.items, [0]);
        let c1 = p1.next_cursor.unwrap();
        assert_ne!(c1, "", "differs from no cursor");
        let p2 = page(Some(c1)).await;
        assert_eq!(p2.items, [1]);
        let p3 = page(p2.next_cursor).await;
        assert_eq!((p3.items, p3.next_cursor), (vec![2], None));
        let old = page(Some(encode_cursor("a.txt"))).await;
        assert_eq!(old.items, [2], "a cursor without the marker is the key");
        assert!(cursor_key("!!").is_err());
    }

    #[test]
    fn utf8_chunks_and_escaping() {
        let (s, rest) = utf8_lossy_prefix("aé".as_bytes().split_at(2).0);
        assert_eq!(s, "a");
        assert_eq!(rest, vec![0xc3]);
        let (s, rest) = utf8_lossy_prefix(b"a\xffb");
        assert_eq!(s, "a\u{fffd}b");
        assert!(rest.is_empty());
        assert_eq!(escape_json("a\"b\\c\nd\u{1}"), "a\\\"b\\\\c\\nd\\u0001");
    }

    #[test]
    fn a_feeds_hits_are_its_own_series_only() {
        // core.md §6 `feed_hits{feed, role}`: a feed's 24 h hits sum its own two series within
        // the window, never another feed's (one whose id it starts with included), nor another
        // series carrying its label.
        let d = tempfile::tempdir().unwrap();
        let opts = crate::db::DbOptions::metrics(d.path());
        crate::db::migrate::create_fresh(&opts, &crate::db::migrate::METRICS).unwrap();
        let c = crate::db::open_connection(&opts, 1024).unwrap();
        let since = 1_000_000;
        let series = |name: &str, feed: &str, role: &str, points: &[(i64, f64)]| {
            let l = crate::metrics::labels("", &[("feed", feed), ("role", role)]);
            c.execute(
                "INSERT INTO series(name, labels_json) VALUES (?1, ?2)",
                rusqlite::params![name, serde_json::to_string(&l).unwrap()],
            )
            .unwrap();
            let id = c.last_insert_rowid();
            for (ts, v) in points {
                c.execute(
                    "INSERT INTO points(series_id, ts, value) VALUES (?1, ?2, ?3)",
                    rusqlite::params![id, ts, v],
                )
                .unwrap();
            }
        };
        series(
            "feed_hits",
            "a\"b",
            "decisive",
            &[(since - 1, 7.0), (since, 1.0), (since + 5, 2.0)],
        );
        series("feed_hits", "a\"b", "also_matched", &[(since + 1, 1.0)]);
        series("feed_hits", "a", "decisive", &[(since + 1, 5.0)]);
        series("trial_would_block", "a\"b", "decisive", &[(since + 1, 9.0)]);
        let h = hits_in(&c, "a\"b", since).unwrap();
        assert_eq!((h.decisive, h.also_matched), (3.0, 1.0));
        let h = hits_in(&c, "a", since).unwrap();
        assert_eq!((h.decisive, h.also_matched), (5.0, 0.0));
        let h = hits_in(&c, "none", since).unwrap();
        assert_eq!((h.decisive, h.also_matched), (0.0, 0.0));
    }
}

// ---------------------------------------------------------------------------------------------
// Feed providers (providers.md §2–§3, feed-scheduling.md, core.md §12 Feed providers)

async fn provider_of(s: &SharedState, id: &str) -> ApiResult<FeedProviderDef> {
    s.feeds
        .provider_or_reload(s, id)
        .await
        .ok_or_else(|| ApiError::not_found(format!("no feed provider {id:?}")))
}

/// A provider's latest listing, summarised.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ListingSummary {
    pub files: usize,
    /// False when the module limited the listing to what `files` can select.
    pub whole: bool,
}

/// A feed provider's status (feed-scheduling.md §6 UI).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProviderStatus {
    pub provider: String,
    pub name: String,
    pub module: String,
    pub enabled: bool,
    /// `dynamic`, `cron` or `sqs`.
    pub trigger: String,
    /// A check is in progress.
    pub checking: bool,
    pub next_check: Option<String>,
    pub last_check: Option<String>,
    pub last_ok: Option<String>,
    /// The current streak of checks that failed as a whole or in every file.
    pub failing_since: Option<String>,
    /// The module's rate-limit pause.
    pub paused_until: Option<String>,
    pub checks_24h: u64,
    pub failures_24h: u64,
    /// The aggressiveness chosen weekly (`dynamic`).
    pub k: Option<f64>,
    /// Its feeds.
    pub feeds: Vec<String>,
    pub listing: Option<ListingSummary>,
    /// An open `feed_provider_listing_incomplete`.
    pub listing_incomplete: bool,
    /// An `sqs` trigger: the last receive, message and error; a pending nudge.
    pub sqs: Option<super::sqs::TriggerState>,
    pub nudged_at: Option<String>,
}

async fn provider_status_of(s: &SharedState, p: &FeedProviderDef) -> ApiResult<ProviderStatus> {
    let id = p.id.clone();
    let day = crate::util::ts(&(Timestamp::now() - jiff::SignedDuration::from_hours(24)));
    let (st, counts, incomplete) = {
        let id = id.clone();
        s.db.read(move |c| {
            let st = store::load_provider_state(c, &id)?;
            let counts: (i64, i64) = c.query_row(
                "SELECT (SELECT count(*) FROM feed_provider_checks WHERE provider_id = ?1 AND t >= ?2),
                        (SELECT count(*) FROM feed_provider_checks WHERE provider_id = ?1 AND t >= ?2 AND ok = 0)",
                params![id, day],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let incomplete: bool = c.query_row(
                "SELECT EXISTS (SELECT 1 FROM alerts WHERE dedupe_key = ?1 AND state = 'open')",
                [format!("feed_provider_listing_incomplete:{id}")],
                |r| r.get(0),
            )?;
            Ok::<_, anyhow::Error>((st, counts, incomplete))
        })
        .await?
    };
    let feeds: Vec<String> = s.feeds.provider_feeds(&id).into_iter().map(|f| f.id).collect();
    Ok(ProviderStatus {
        provider: id.clone(),
        name: p.name.clone(),
        module: p.module.clone(),
        enabled: p.enabled,
        trigger: p.trigger.kind().into(),
        checking: s.feeds.is_checking(&id),
        next_check: p
            .enabled
            .then(|| s.feeds.next_due(&id))
            .flatten()
            .map(|t| crate::util::ts(&t)),
        last_check: st.last_check_at.map(|t| crate::util::ts(&t)),
        last_ok: st.last_ok_at.map(|t| crate::util::ts(&t)),
        failing_since: st.failing_since.map(|t| crate::util::ts(&t)),
        paused_until: s.feeds.paused_until(&p.module).map(|t| crate::util::ts(&t)),
        checks_24h: crate::util::nonneg(counts.0),
        failures_24h: crate::util::nonneg(counts.1),
        k: st
            .k
            .or_else(|| feeds.first().and_then(|f| s.feeds.learner(f)).map(|l| l.k)),
        feeds,
        listing: st.listing.as_ref().map(|l| ListingSummary {
            files: l.files.len(),
            whole: l.whole,
        }),
        listing_incomplete: incomplete,
        sqs: matches!(p.trigger, crate::config::model::Trigger::Sqs { .. })
            .then(|| super::sqs::status_of(st.trigger_state.as_ref()).unwrap_or_default()),
        nudged_at: st.nudged_at.map(|t| crate::util::ts(&t)),
    })
}

async fn provider_status(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<ProviderStatus>> {
    let p = provider_of(&s, &id).await?;
    Ok(Json(provider_status_of(&s, &p).await?))
}

async fn all_provider_status(
    State(s): State<SharedState>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<ProviderStatus>>> {
    let model = s.config.model_of(crate::config::EntityKind::FeedProvider).await?;
    Ok(Json(
        key_page(&model.feed_providers, &q, |p| provider_status_of(&s, p)).await?,
    ))
}

/// What "Check now" did.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct CheckNow {
    /// `started`, `queued` (a check of the provider is in progress: another runs when it ends)
    /// or `scheduled` (`min_interval`, or the module's rate-limit pause).
    pub result: String,
    /// When a scheduled check runs.
    pub at: Option<String>,
}

/// `POST feed-providers/{id}/check`: checks the whole provider; bypasses the trigger, not
/// `min_interval` (feed-scheduling.md). It reads no body, as [`install_preset`].
async fn check_now(State(s): State<SharedState>, ApiPath(id): ApiPath<String>) -> ApiResult<Response> {
    provider_of(&s, &id).await?;
    let (result, at) = match s.feeds.trigger_provider(&s, &id, Cause::CheckNow) {
        Triggered::Started => ("started", None),
        Triggered::Queued => ("queued", None),
        Triggered::Scheduled(t) => ("scheduled", Some(crate::util::ts(&t))),
        Triggered::Disabled => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "conflict",
                "the feed provider is disabled",
            ));
        }
        Triggered::Unknown => return Err(ApiError::not_found(format!("no feed provider {id:?}"))),
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(CheckNow {
            result: result.into(),
            at,
        }),
    )
        .into_response())
}

/// One file of a provider (its stored listing, a declared path, or a feed's file) with its feed.
#[derive(Clone, Debug, PartialEq, Serialize, JsonSchema)]
pub struct ProviderFile {
    /// The whole path: what **Add as feed** takes.
    pub file: String,
    /// `files` selects it (minus `exclude`).
    pub selected: bool,
    /// The feed that reads it; none: **Add as feed** adds it to `files`.
    pub feed: Option<String>,
}

/// A common prefix of a provider's listing (a folder, with `delimiter=/`).
#[derive(Clone, Debug, PartialEq, Serialize, JsonSchema)]
pub struct FilePrefix {
    /// The prefix, ending in `/`: `prefix=` lists it.
    pub prefix: String,
    /// The files under it, at any depth.
    pub files: usize,
    /// How many of those a feed reads.
    pub feeds: usize,
}

/// A page of a provider's listing (S3 ListObjectsV2 semantics in the UI API's envelope): the
/// common prefixes and the files of the page, each list in key order; together at most `limit`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ListingPage {
    pub prefixes: Vec<FilePrefix>,
    pub items: Vec<ProviderFile>,
    /// Pass as `cursor` for the next page; null on the last page.
    pub next_cursor: Option<String>,
    /// The stored listing, summarised: none before the first, or for a module that lists none.
    pub listing: Option<ListingSummary>,
}

/// The longest `q` on a provider's listing: longer is refused (`400`, README §2 Untrusted input).
pub const MAX_LISTING_Q: usize = 256;
/// The longest `prefix` (bytes): longer is refused (`400`).
pub const MAX_LISTING_PREFIX: usize = 4096;

/// `?prefix=&delimiter=&q=&cursor=&limit=` on a provider's listing.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct ListingQuery {
    /// The files whose path starts with it; at most [`MAX_LISTING_PREFIX`] bytes.
    pub prefix: Option<String>,
    /// `/` groups the files past the prefix into common prefixes; left out or empty, none are
    /// (as in S3); any other value is refused.
    pub delimiter: Option<String>,
    /// A substring of the path, case-insensitive (each character lowercased, Unicode); at most
    /// [`MAX_LISTING_Q`] characters.
    pub q: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// A row of a listing page: a common prefix or a file.
enum FileRow {
    Prefix(FilePrefix),
    File(ProviderFile),
}

fn file_row(view: &super::select::FilesView<'_>, path: &str) -> FileRow {
    let (selected, feed) = view.row(path);
    FileRow::File(ProviderFile {
        file: path.to_string(),
        selected,
        feed,
    })
}

/// A provider's listing (core.md §12 Feed providers page: every file it lists, or declares, with
/// that file's feed) with S3 ListObjectsV2 semantics over its flat paths, a page at a time ([`key_page`], api.md §7), from its stored listing and the
/// configuration only (no module call, so no GitHub request):
/// - `prefix` (default none: every file) and `delimiter=/`: the files directly under the prefix
///   and the common prefixes (folders) of the rest, with their file and feed counts, merged in
///   key order and returned as two lists; without `delimiter`, every file under the prefix;
/// - `q` (our addition): the files under `prefix` whose path holds it, no grouping.
///
/// The cursor names the last key returned, so an entry present throughout a walk shows exactly
/// once however later checks change the listing; a prefix nothing is under lists empty (`200`).
async fn provider_listing(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<ListingQuery>,
) -> ApiResult<Json<ListingPage>> {
    provider_of(&s, &id).await?;
    let prefix = q.prefix.unwrap_or_default();
    if prefix.len() > MAX_LISTING_PREFIX {
        return Err(ApiError::bad_request(format!(
            "prefix: at most {MAX_LISTING_PREFIX} bytes"
        )));
    }
    let delimiter = match q.delimiter.as_deref() {
        None | Some("") => false,
        Some("/") => true,
        Some(_) => return Err(ApiError::bad_request("delimiter: only /")),
    };
    let needle = match q.q.as_deref() {
        None | Some("") => None,
        Some(n) if n.chars().count() > MAX_LISTING_Q => {
            return Err(ApiError::bad_request(format!(
                "q: at most {MAX_LISTING_Q} characters"
            )));
        }
        Some(n) => Some(n),
    };
    let pq = PageQuery {
        cursor: q.cursor,
        limit: q.limit,
    };
    let model = s.config.model_of(crate::config::EntityKind::Feed).await?;
    let p = model
        .feed_providers
        .get(&id)
        .ok_or_else(|| ApiError::not_found(format!("no feed provider {id:?}")))?;
    let i = id.clone();
    let listing =
        s.db.read(move |c| Ok::<_, anyhow::Error>(super::select::stored_listing(c, &i)?))
            .await?;
    let listing_summary = listing.as_ref().map(|l| ListingSummary {
        files: l.files.len(),
        whole: l.whole,
    });
    let view = super::select::FilesView::new(&model, p, listing);
    let entries = match needle {
        Some(n) => view
            .search(&prefix, n)
            .into_iter()
            .map(super::select::Entry::File)
            .collect(),
        None => view.list(&prefix, delimiter),
    };
    // Keys and entries go in as two zipped lists: a closure pairing them would make the
    // handler's future not `Send` for every lifetime, which axum needs.
    let keys: Vec<&str> = entries.iter().map(super::select::Entry::key).collect();
    let page = key_page(keys.iter().zip(&entries), &pq, |e| {
        std::future::ready(Ok(match e {
            super::select::Entry::Prefix { prefix, files, feeds } => FileRow::Prefix(FilePrefix {
                prefix: prefix.to_string(),
                files: *files,
                feeds: *feeds,
            }),
            super::select::Entry::File(path) => file_row(&view, path),
        }))
    })
    .await?;
    let (mut prefixes, mut items) = (Vec::new(), Vec::new());
    for row in page.items {
        match row {
            FileRow::Prefix(x) => prefixes.push(x),
            FileRow::File(f) => items.push(f),
        }
    }
    Ok(Json(ListingPage {
        prefixes,
        items,
        next_cursor: page.next_cursor,
        listing: listing_summary,
    }))
}

/// **Add as feed**: a file to add to the provider's `files`, with the settings of its feed.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct AddFile {
    pub file: String,
    /// Feed settings (`format` required; default `adblock`).
    #[serde(default)]
    pub feed: Option<Value>,
}

async fn add_file_to(
    s: &SharedState,
    id: &str,
    file: &str,
    feed: Option<Value>,
    actor: Actor,
) -> ApiResult<crate::config::Outcome> {
    let model = s.config.model_of(crate::config::EntityKind::FeedProvider).await?;
    let mut p = model
        .feed_providers
        .get(id)
        .cloned()
        .ok_or_else(|| ApiError::not_found(format!("no feed provider {id:?}")))?;
    let template = feed.unwrap_or_else(|| serde_json::json!({"format": "adblock"}));
    // For a module that lists files, `files` holds globs: the path goes in as a literal, which
    // selects no sibling (feeds.md §1); for one that doesn't, `files` holds paths as they are.
    let lists = s.feeds.registry().get(&p.module).is_some_and(|m| m.lists_files());
    let glob = crate::modules::download::glob::escape(file);
    let pattern = if lists { glob.clone() } else { file.to_string() };
    // The settings given now are the feed's (adding a deleted feed's file again takes them, not
    // the entry's earlier ones).
    match p.files.iter_mut().find(|f| f.pattern == pattern) {
        Some(f) => f.feed = Some(template),
        None => p.files.push(crate::config::model::FileSelect {
            pattern,
            feed: Some(template),
        }),
    }
    // A file `exclude` holds comes back once added explicitly.
    p.exclude.retain(|x| x != file && *x != glob);
    let body = serde_json::to_value(&p).map_err(|e| ApiError::from(anyhow::Error::from(e)))?;
    Ok(s.config
        .apply(
            crate::config::EntityKind::FeedProvider,
            crate::config::Op::Update(id.to_string(), body),
            actor,
            None,
        )
        .await?)
}

async fn add_as_feed(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(id): ApiPath<String>,
    crate::web::error::ApiJson(body): crate::web::error::ApiJson<AddFile>,
) -> ApiResult<Json<crate::config::Outcome>> {
    Ok(Json(
        add_file_to(&s, &id, &body.file, body.feed, actor(peer)).await?,
    ))
}

/// One provider check.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProviderCheckView {
    pub id: i64,
    pub t: String,
    /// `trigger`, `sqs`, `backstop`, `check_now`, `first`, `edit`.
    pub cause: String,
    pub duration_ms: Option<i64>,
    pub ok: bool,
    pub error: Option<String>,
}

async fn provider_checks(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<ProviderCheckView>>> {
    provider_of(&s, &id).await?;
    let before = cursor_i64(&q)?;
    let lim = limit(&q)?;
    let mut items =
        s.db.read(move |c| {
            let mut st = c.prepare(
                "SELECT id, t, cause, duration_ms, ok, error FROM feed_provider_checks
                 WHERE provider_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
            )?;
            let v = st
                .query_map(params![id, before, lim + 1], |r| {
                    Ok(ProviderCheckView {
                        id: r.get(0)?,
                        t: r.get(1)?,
                        cause: r.get(2)?,
                        duration_ms: r.get(3)?,
                        ok: r.get::<_, i64>(4)? != 0,
                        error: r.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    let next = if items.len() > lim {
        items.truncate(lim);
        items.last().map(|r| encode_cursor(&r.id.to_string()))
    } else {
        None
    };
    Ok(Json(Page {
        items,
        next_cursor: next,
    }))
}

/// The backtest's `days`: 1 to 60 (feed check history is kept 60 days, README §2), default 7.
pub const BACKTEST_DAYS: std::ops::RangeInclusive<i64> = 1..=60;
/// The backtest's `k`: 0.1 to 50.
pub const BACKTEST_K: std::ops::RangeInclusive<f64> = 0.1..=50.0;

/// `?days=&k=` on the backtest; a value out of range is refused (`400`), as every `limit` is.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct BacktestQuery {
    /// How far back to replay (1–60 days, default 7).
    pub days: Option<i64>,
    /// One `k`, 0.1 to 50 (default: each of 1, 2, 3, 5).
    pub k: Option<f64>,
}

/// `GET feed-providers/{id}/backtest`: replays the provider's recorded history through the
/// learner with simulated checks (feed-scheduling.md §6).
async fn backtest(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<BacktestQuery>,
) -> ApiResult<Json<Vec<super::schedule::learner::SimResult>>> {
    let p = provider_of(&s, &id).await?;
    if let Some(k) = q.k
        && !BACKTEST_K.contains(&k)
    {
        return Err(ApiError::bad_request("k: 0.1 to 50"));
    }
    let days = q.days.unwrap_or(7);
    if !BACKTEST_DAYS.contains(&days) {
        return Err(ApiError::bad_request("days: 1 to 60"));
    }
    let r = super::check::backtest(&s, &p, days, q.k).await?;
    Ok(Json(r))
}

/// A new feed awaiting review (an open `feed_added`, feeds.md §1).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ReviewItem {
    pub feed: String,
    pub name: String,
    pub provider: Option<String>,
    pub file: Option<String>,
    pub alert: i64,
    pub since: String,
}

async fn review_queue(State(s): State<SharedState>) -> ApiResult<Json<Vec<ReviewItem>>> {
    let v = s
        .db
        .read(|c| {
            let mut st = c.prepare(
                "SELECT a.feed_id, f.name, f.provider_id, f.file, a.id, a.first_seen FROM alerts a JOIN feeds f ON f.id = a.feed_id
                 WHERE a.kind = 'feed_added' AND a.state = 'open' ORDER BY a.first_seen, a.id LIMIT 1000",
            )?;
            let v = st
                .query_map([], |r| {
                    Ok(ReviewItem {
                        feed: r.get(0)?,
                        name: r.get(1)?,
                        provider: r.get(2)?,
                        file: r.get(3)?,
                        alert: r.get(4)?,
                        since: r.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    Ok(Json(v))
}

/// Adding a feed by URL (providers.md §3, core.md §12).
#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct AddUrl {
    pub url: String,
    /// The id of a provider to create when none fits (default: from the URL).
    #[serde(default)]
    pub provider: Option<String>,
    /// Its name (default: the id).
    #[serde(default)]
    pub name: Option<String>,
    /// The feed's settings (`format` required; default `adblock`).
    #[serde(default)]
    pub feed: Option<Value>,
}

/// What adding by URL did.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct AddedUrl {
    pub provider: String,
    /// A new provider was created for the URL.
    pub created_provider: bool,
    /// The file added to the provider's `files` (an http provider's one file, `response`).
    pub file: String,
    /// The feed reading it (an existing one when the URL had a feed already).
    pub feed: Option<String>,
    /// The URL had its feed already: nothing changed.
    #[serde(default)]
    pub existing: bool,
    /// What the UI says about the mapping (jsDelivr's cache).
    pub notice: Option<String>,
    pub outcome: crate::config::Outcome,
}

async fn add_by_url(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    crate::web::error::ApiJson(body): crate::web::error::ApiJson<AddUrl>,
) -> ApiResult<Json<AddedUrl>> {
    let actor = actor(peer);
    let model = s.config.model_of(crate::config::EntityKind::FeedProvider).await?;
    let template = body
        .feed
        .clone()
        .unwrap_or_else(|| serde_json::json!({"format": "adblock"}));
    // A user name or password can't be carried over: refused, not dropped (README §2 Secrets:
    // credentials go in a header with a secret).
    if url::Url::parse(body.url.trim()).is_ok_and(|u| crate::modules::download::http::has_user_info(&u)) {
        return Err(ApiError::unprocessable(
            "the URL can't hold a user name or password; use a header with a secret",
        ));
    }
    // github forms first; then any https URL as http (providers.md §3).
    match crate::modules::download::github::parse_url(&body.url) {
        Ok(u) => {
            // A provider of that repository following the URL's branch; the default branch is
            // resolved with ls-refs when the URL or a provider names none.
            let same_repo: Vec<&FeedProviderDef> = model
                .feed_providers
                .values()
                .filter(|p| p.module == "github")
                .filter(|p| {
                    let o = p.config.get("owner").and_then(Value::as_str).unwrap_or_default();
                    let r = p.config.get("repo").and_then(Value::as_str).unwrap_or_default();
                    o.eq_ignore_ascii_case(&u.owner) && r.eq_ignore_ascii_case(&u.repo)
                })
                .collect();
            let needs_default = same_repo
                .iter()
                .any(|p| p.config.get("branch").and_then(Value::as_str).is_none())
                && u.branch.is_some();
            let default_branch = if needs_default || (u.branch.is_none() && !same_repo.is_empty()) {
                let http = s.feeds.http(&s.settings().resolver)?;
                Some(
                    crate::modules::download::github::default_branch(&http, &u.owner, &u.repo, None)
                        .await
                        .map_err(|e| {
                            ApiError::new(
                                StatusCode::BAD_GATEWAY,
                                "upstream",
                                format!("cannot resolve the repository's default branch: {e}"),
                            )
                        })?,
                )
            } else {
                None
            };
            let want = u.branch.clone().or_else(|| default_branch.clone());
            let found = same_repo.iter().find(|p| {
                let pb = p
                    .config
                    .get("branch")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| default_branch.clone());
                pb == want
            });
            let (pid, created) = match found {
                Some(p) => (p.id.clone(), false),
                None => {
                    let id = body.provider.clone().unwrap_or_else(|| {
                        let base = super::select::slug(&format!("{}-{}", u.owner, u.repo), "provider");
                        let base = match (&u.branch, &default_branch) {
                            (Some(b), Some(d)) if b != d => {
                                super::select::slug(&format!("{base}-{b}"), "provider")
                            }
                            (Some(b), None) if !same_repo.is_empty() => {
                                super::select::slug(&format!("{base}-{b}"), "provider")
                            }
                            _ => base,
                        };
                        let mut id = base.clone();
                        let mut n = 2;
                        while model.feed_providers.contains_key(&id) {
                            id = format!("{base}-{n}");
                            n += 1;
                        }
                        id
                    });
                    let mut cfg = serde_json::json!({"owner": u.owner, "repo": u.repo});
                    if let Some(b) = &u.branch {
                        cfg["branch"] = Value::String(b.clone());
                    }
                    let p = FeedProviderDef {
                        id: id.clone(),
                        name: body
                            .name
                            .clone()
                            .unwrap_or_else(|| format!("{}/{}", u.owner, u.repo)),
                        module: "github".into(),
                        config: cfg,
                        ..Default::default()
                    };
                    let v = serde_json::to_value(&p).map_err(|e| ApiError::from(anyhow::Error::from(e)))?;
                    s.config
                        .apply(
                            crate::config::EntityKind::FeedProvider,
                            crate::config::Op::Create(v),
                            actor.clone(),
                            None,
                        )
                        .await?;
                    (id, true)
                }
            };
            let outcome = add_file_to(&s, &pid, &u.path, Some(template), actor).await?;
            let now = s.config.model_of(crate::config::EntityKind::Feed).await?;
            let feed = now
                .feeds
                .values()
                .find(|f| {
                    f.provider.as_deref() == Some(pid.as_str()) && f.file.as_deref() == Some(u.path.as_str())
                })
                .map(|f| f.id.clone());
            Ok(Json(AddedUrl {
                provider: pid,
                created_provider: created,
                file: u.path,
                feed,
                existing: false,
                notice: u.notice,
                outcome,
            }))
        }
        Err(gh_err) => {
            let url = url::Url::parse(&body.url)
                .ok()
                .filter(|u| u.scheme() == "https" && u.host_str().is_some())
                .ok_or_else(|| ApiError::unprocessable(format!("the URL isn't a feed URL: {gh_err}")))?;
            if url.host_str().is_some_and(|h| {
                let h = h.to_ascii_lowercase();
                h == "raw.githubusercontent.com" || h == "cdn.jsdelivr.net" || h == "github.com"
            }) {
                return Err(ApiError::unprocessable(gh_err));
            }
            // providers.md §3: an http provider is one URL. The one whose url is this URL
            // (scheme and host lowercase, no default port, otherwise exact, the query too), else
            // a new one; its one feed takes the provider's id (feeds.md §1).
            use crate::modules::download::http;
            let url = http::check_feed_url(url.as_str()).map_err(|e| {
                ApiError::unprocessable(format!(
                    "{e}: give the list's https:// URL, without user info or a #fragment"
                ))
            })?;
            let key = http::url_key(&url);
            let same_url = |p: &FeedProviderDef| {
                p.module == "http"
                    && p.config
                        .get("url")
                        .and_then(Value::as_str)
                        .and_then(|u| url::Url::parse(u).ok())
                        .is_some_and(|u| http::url_key(&u) == key)
            };
            let model = s.config.model_of(crate::config::EntityKind::Feed).await?;
            let feed_of = |m: &crate::config::Model, pid: &str| {
                m.feeds
                    .values()
                    .find(|f| f.provider.as_deref() == Some(pid) && f.file.as_deref() == Some(http::FILE))
                    .map(|f| f.id.clone())
            };
            let existing = model.feed_providers.values().find(|p| same_url(p)).cloned();
            let had_feed = existing
                .as_ref()
                .is_some_and(|p| feed_of(&model, &p.id).is_some());
            let (pid, created, outcome) = match existing {
                // Its feed is there: returned as it is (no duplicate), the provider masked as
                // every entity the UI API returns (an older release's literal credential).
                Some(p) if feed_of(&model, &p.id).is_some() => {
                    let outcome = crate::config::Outcome {
                        id: p.id.clone(),
                        entity: serde_json::to_value(&p).ok().map(|v| {
                            crate::config::store::for_ui(crate::config::EntityKind::FeedProvider, v)
                        }),
                        warnings: vec![],
                        feeds_added: vec![],
                        feeds_deleted: vec![],
                    };
                    (p.id, false, outcome)
                }
                // Its feed was deleted: added again.
                Some(p) => {
                    let outcome = add_file_to(&s, &p.id, http::FILE, Some(template), actor).await?;
                    (p.id, false, outcome)
                }
                None => {
                    let (base_id, readable) = super::select::http_identity(&url);
                    let taken = |c: &str| model.feed_providers.contains_key(c) || model.feeds.contains_key(c);
                    let id = body
                        .provider
                        .clone()
                        .unwrap_or_else(|| super::select::unique_id(&base_id, &taken));
                    let p = FeedProviderDef {
                        id: id.clone(),
                        name: body.name.clone().unwrap_or(readable),
                        module: "http".into(),
                        config: serde_json::json!({ "url": key }),
                        files: vec![crate::config::model::FileSelect {
                            pattern: http::FILE.into(),
                            feed: Some(template),
                        }],
                        ..Default::default()
                    };
                    let v = serde_json::to_value(&p).map_err(|e| ApiError::from(anyhow::Error::from(e)))?;
                    let outcome = s
                        .config
                        .apply(
                            crate::config::EntityKind::FeedProvider,
                            crate::config::Op::Create(v),
                            actor,
                            None,
                        )
                        .await?;
                    (id, true, outcome)
                }
            };
            let now = s.config.model_of(crate::config::EntityKind::Feed).await?;
            Ok(Json(AddedUrl {
                feed: feed_of(&now, &pid),
                provider: pid,
                created_provider: created,
                existing: had_feed,
                file: http::FILE.into(),
                notice: None,
                outcome,
            }))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Export and import (feeds.md §4, api.md §7)

/// `?as=file` on the export.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct ExportQuery {
    /// `file`: the file export instead of the JSON export.
    #[serde(rename = "as")]
    pub as_: Option<String>,
}

async fn export(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<ExportQuery>,
) -> ApiResult<Response> {
    let def = def_of(&s, &id).await?;
    let as_file = match q.as_.as_deref() {
        None | Some("json") => false,
        Some("file") => true,
        Some(_) => return Err(ApiError::bad_request("as is file or json")),
    };
    let slot = s.feeds.upload_slot().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy",
            "too many exports and uploads are in progress; try again later",
        )
    })?;
    let e = super::transfer::export(&s, &def, as_file, slot)?;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, e.content_type.to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                super::transfer::disposition(&e.filename),
            ),
        ],
        e.body,
    )
        .into_response())
}

async fn export_size(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<super::transfer::ExportSize>> {
    def_of(&s, &id).await?;
    Ok(Json(super::transfer::export_size(&s, &id).await?))
}

/// The feed settings an import's query may name (feeds.md §4, api.md §7): the admin's picks
/// for a plain list file; an export's own settings win, and one that differs is `422`.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct ImportSettingsQuery {
    /// A plain list file's format (default `adblock`).
    pub format: Option<crate::config::model::FeedFormat>,
    /// A `plain` list's `format_options.domains_as`.
    pub domains_as: Option<crate::config::model::DomainsAs>,
    pub category: Option<crate::config::model::Category>,
    /// The warn bundles to check the feed against, comma-separated (empty: none; left out:
    /// follows the category).
    pub warn_on: Option<String>,
    /// `rule_policy.redirects` (`drop` or `keep`; a manual feed's default `keep`).
    pub redirects: Option<crate::config::model::PolicyOption>,
    /// `rule_policy.client_rules` (`drop` or `keep`; a manual feed's default `keep`).
    pub client_rules: Option<crate::config::model::PolicyOption>,
    /// `rule_policy.browser_changes` (`drop` or `keep`; default `keep`).
    pub browser_changes: Option<crate::config::model::PolicyOption>,
}

impl ImportSettingsQuery {
    fn settings(self) -> super::transfer::QuerySettings {
        super::transfer::QuerySettings {
            format: self.format,
            domains_as: self.domains_as,
            category: self.category,
            warn_on: self.warn_on.map(|w| {
                w.split(',')
                    .map(str::trim)
                    .filter(|b| !b.is_empty())
                    .map(str::to_string)
                    .collect()
            }),
            redirects: self.redirects,
            client_rules: self.client_rules,
            browser_changes: self.browser_changes,
        }
    }
}

/// `POST feeds/import?id=&name=…`: a new manual feed from an export or a plain list file.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct ImportNewQuery {
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(flatten)]
    pub settings: ImportSettingsQuery,
}

async fn import_new(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiQuery(q): ApiQuery<ImportNewQuery>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> ApiResult<Response> {
    let r = super::transfer::import(
        &s,
        super::transfer::Target::NewManual {
            id: q.id,
            name: q.name,
            settings: q.settings.settings(),
        },
        body,
        encoding(&headers).as_deref(),
        actor(peer),
    )
    .await
    .map_err(import_error)?;
    Ok((StatusCode::CREATED, Json(r)).into_response())
}

/// `POST feeds/{id}/import?mode=replace|merge&base_version=…`.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct ImportQuery {
    /// `replace` or `merge` (a provider feed: `merge` only).
    pub mode: Option<String>,
    /// A manual feed's file version the import was made against.
    pub base_version: Option<String>,
    /// Each setting named must be the feed's own (`422` naming the field otherwise).
    #[serde(flatten)]
    pub settings: ImportSettingsQuery,
}

async fn import_into(
    State(s): State<SharedState>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<ImportQuery>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> ApiResult<Json<super::transfer::Imported>> {
    let replace = match q.mode.as_deref() {
        Some("replace") => true,
        Some("merge") | None => false,
        Some(_) => return Err(ApiError::bad_request("mode is replace or merge")),
    };
    super::transfer::import(
        &s,
        super::transfer::Target::Existing {
            feed: id,
            replace,
            base_version: q.base_version,
            settings: q.settings.settings(),
        },
        body,
        encoding(&headers).as_deref(),
        actor(peer),
    )
    .await
    .map(Json)
    .map_err(import_error)
}

/// An import refused: as a save's, with a taken id a `409`.
fn import_error(e: manual::SaveError) -> ApiError {
    match e {
        manual::SaveError::Conflict { current } if current.starts_with("feed ") => {
            ApiError::new(StatusCode::CONFLICT, "conflict", current)
        }
        e => save_error(e),
    }
}
