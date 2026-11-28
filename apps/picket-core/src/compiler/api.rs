//! The UI API routes for bundles (core.md §12 Bundles, Warninglists; api.md §7), beside the
//! generic CRUD of bundle definitions:
//!
//! | Route | |
//! |---|---|
//! | `GET bundle-status` | every bundle's build status |
//! | `GET bundles/{id}/status` | one bundle: status, head, feed runs, stats, shards, the heads edges are named |
//! | `GET bundles/{id}/versions` | its versions, newest first (cursor pagination) |
//! | `GET bundles/{id}/warnings` | its open guardrail alerts and compile-time warnings |
//! | `GET bundles/{id}/public-suffixes?feed=…` | every public suffix the bundle blocks below the top level, per feed, with its rules and lines (the full list behind each grouped warning, #49; cursor pagination) |
//! | `POST bundles/{id}/build` | build now (heavy lane, P0) |
//! | `GET bundles/{id}/explain?name=…&qtype=…&client_ip=…&client=…&tags=…` | how the bundle's current rules decide a name or address, with picket-rules' reference matcher |
//!
//! Text from feeds (rule text) is returned as data; the UI renders it as text only (core.md §12).

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::source::View;
use super::spec::{self, Spec};
use crate::scheduler::Priority;
use crate::state::SharedState;
use crate::web::api::{Page, PageQuery, decode_cursor, encode_cursor};
use crate::web::error::{ApiError, ApiPath, ApiQuery, ApiResult};

/// The most rules an explanation reads (keys at the name's suffixes, patterns, IP rules).
const EXPLAIN_MAX_RULES: usize = 200_000;

/// One bundle's detail.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct BundleDetail {
    #[serde(flatten)]
    pub status: super::BundleStatus,
    /// Per shard: part, shard number, keys, base, chain length, overlay entries, in-memory bytes.
    pub shards: Vec<ShardView>,
    pub ip_shards: Vec<IpShardView>,
    /// The head each edge's current config names for the bundle.
    pub edges: BTreeMap<String, String>,
    /// A block bundle's last tiering dry run: how many blocks of the log window would have
    /// come from cold under its proposed split (bundles.md §2 Tiering).
    pub dry_run: Option<super::tier::DryRun>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ShardView {
    pub part: String,
    pub shard: u32,
    pub keys: u64,
    pub base: Option<String>,
    pub deltas: u64,
    pub overlay_entries: u64,
    pub mem_bytes: u64,
    pub disk_bytes: u64,
    pub created_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct IpShardView {
    pub ip_shard: String,
    pub runs: u64,
    pub base: Option<String>,
    pub deltas: u64,
    pub overlay_entries: u64,
    pub mem_bytes: u64,
}

/// One version.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct VersionView {
    pub head: String,
    pub published_at: String,
    pub feed_runs: BTreeMap<String, i64>,
    pub definition_hash: String,
    pub stats: Option<serde_json::Value>,
    pub current: bool,
    pub last_used_at: Option<String>,
}

/// One compile-time warning (bundles.md §3).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct WarningView {
    pub id: i64,
    /// `warn` (a warn bundle matched) or `allow` (an allow bundle overrides it).
    pub kind: String,
    pub by_bundle: Option<String>,
    pub by_feed: Option<String>,
    pub value: String,
    pub feed: Option<String>,
    /// The block entry's rule text.
    pub raw: Option<String>,
    pub bundle: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct BundleWarnings {
    pub alerts: Vec<crate::alerts::Alert>,
    pub warnings: Page<WarningView>,
}

/// `?feed=…&cursor=…&limit=…`
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct PublicSuffixQuery {
    /// One feed's suffixes (default every feed's).
    pub feed: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// `?feed=…&suffix=…&cursor=…&limit=…`
#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct PublicSuffixRulesQuery {
    pub feed: String,
    pub suffix: String,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// How many of a suffix's rules a [`PublicSuffixView`] lists (issue 115): the rest come a page
/// at a time from `GET bundles/{id}/public-suffixes/rules`, so a page of suffixes stays bounded
/// however many rules name one.
pub const PUBLIC_SUFFIX_RULES: usize = 10;

/// One public suffix a bundle blocks below the top level, from one feed.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct PublicSuffixView {
    pub feed: String,
    pub suffix: String,
    /// The feed's first rules blocking it (more than one when several rules name it), at most
    /// 10; `rules_cursor` pages through the rest.
    pub rules: Vec<PublicSuffixRule>,
    /// How many of the feed's rules block it, over every page.
    pub rule_count: u64,
    /// Pass as `cursor` to `GET bundles/{id}/public-suffixes/rules` for the rules after
    /// `rules`; null when `rules` holds them all.
    pub rules_cursor: Option<String>,
}

/// One rule behind a public-suffix block: its text and source line, as the feed lists it now.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct PublicSuffixRule {
    pub rule: Option<String>,
    pub line: Option<i64>,
}

/// The public suffixes a bundle blocks below the top level, ordered by feed then suffix, with
/// the exact totals behind the grouped warnings.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct PublicSuffixes {
    /// Distinct (feed, suffix) pairs in all, over every page.
    pub total: u64,
    pub items: Vec<PublicSuffixView>,
    /// Pass as `cursor` for the next page; null on the last page.
    pub next_cursor: Option<String>,
}

/// `?name=…&qtype=…&client_ip=…&client=…&tags=…`
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
pub struct ExplainQuery {
    /// A name, or an address (matched as an answer address).
    pub name: String,
    /// The query type (default `A`).
    pub qtype: Option<String>,
    pub client_ip: Option<String>,
    /// The client entry's name (`$client`).
    pub client: Option<String>,
    /// The client entry's tags, comma-separated (`$ctag`).
    pub tags: Option<String>,
}

/// How the bundle's rules decide.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Explanation {
    pub bundle: String,
    pub name: String,
    /// The reference matcher's outcome (`none`, `block`, `exception`, `allow`, `in_scope`, a
    /// rewrite or host mapping).
    pub outcome: serde_json::Value,
    pub step: Option<String>,
    pub matches: Vec<ExplainMatch>,
    /// The feed runs read (the feeds as they stand now; the published head may be older).
    pub feed_runs: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ExplainMatch {
    pub feed: String,
    pub rule: String,
    pub line: Option<i64>,
    /// `decisive`, `also_matched` or `overridden`.
    pub role: serde_json::Value,
    pub level: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct BuildQueued {
    pub bundle: String,
    pub queued: bool,
}

async fn all_status(State(s): State<SharedState>) -> ApiResult<Json<Vec<super::BundleStatus>>> {
    Ok(Json(super::statuses(&s).await?))
}

async fn bundle_status(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<BundleDetail>> {
    let status = super::statuses(&s)
        .await?
        .into_iter()
        .find(|b| b.bundle == id)
        .ok_or_else(|| ApiError::not_found("no such bundle"))?;
    let b = id.clone();
    let (shards, ip_shards, dry_run) = s
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT part, shard, keys, base_blake3, deltas, overlay_entries, mem_bytes, disk_bytes, created_at
                 FROM bundle_shards WHERE bundle_id = ?1 ORDER BY part DESC, shard",
            )?;
            let shards = st
                .query_map([&b], |r| {
                    Ok(ShardView {
                        part: r.get(0)?,
                        shard: u32::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                        keys: crate::util::nonneg(r.get(2)?),
                        base: r.get(3)?,
                        deltas: crate::util::nonneg(r.get(4)?),
                        overlay_entries: crate::util::nonneg(r.get(5)?),
                        mem_bytes: crate::util::nonneg(r.get(6)?),
                        disk_bytes: crate::util::nonneg(r.get(7)?),
                        created_at: r.get(8)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut st = c.prepare(
                "SELECT ip_shard, runs, base_blake3, deltas, overlay_entries, mem_bytes FROM bundle_ip_shards
                 WHERE bundle_id = ?1 ORDER BY ip_shard",
            )?;
            let ips = st
                .query_map([&b], |r| {
                    Ok(IpShardView {
                        ip_shard: r.get(0)?,
                        runs: crate::util::nonneg(r.get(1)?),
                        base: r.get(2)?,
                        deltas: crate::util::nonneg(r.get(3)?),
                        overlay_entries: crate::util::nonneg(r.get(4)?),
                        mem_bytes: crate::util::nonneg(r.get(5)?),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let dry = super::tier::last_dry_run(c, &b)?;
            Ok::<_, anyhow::Error>((shards, ips, dry))
        })
        .await?;
    let mut edges = BTreeMap::new();
    for e in s.edges.hub.edge_ids() {
        if let Some(p) = s.edges.publisher.current(&e)
            && let Some(h) = p.config.bundles.get(&id)
        {
            edges.insert(e.clone(), h.clone());
        }
    }
    Ok(Json(BundleDetail {
        status,
        shards,
        ip_shards,
        edges,
        dry_run,
    }))
}

async fn versions(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<VersionView>>> {
    let limit = q.limit()?;
    let after = match &q.cursor {
        Some(c) if !c.is_empty() => {
            Some(decode_cursor(c).ok_or_else(|| ApiError::bad_request("bad cursor"))?)
        }
        _ => None,
    };
    let b = id.clone();
    let (rows, current) =
        s.db.read(move |c| {
            let current: Option<String> = c
                .query_row(
                    "SELECT head_id FROM bundle_builds WHERE bundle_id = ?1",
                    [&b],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            let mut st = c.prepare(
                "SELECT head_id, published_at, feed_runs_json, definition_hash, stats_json, last_used_at
                 FROM bundle_versions WHERE bundle_id = ?1 AND (?2 IS NULL OR (published_at || head_id) < ?2)
                 ORDER BY published_at DESC, head_id DESC LIMIT ?3",
            )?;
            let rows = st
                .query_map(rusqlite::params![b, after, limit + 1], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>((rows, current))
        })
        .await?;
    let more = rows.len() > limit;
    let items: Vec<VersionView> = rows
        .into_iter()
        .take(limit)
        .map(|(h, p, f, d, st, lu)| VersionView {
            current: current.as_deref() == Some(h.as_str()),
            head: h,
            published_at: p,
            feed_runs: spec::parse_runs(&f),
            definition_hash: d,
            stats: st.and_then(|x| serde_json::from_str(&x).ok()),
            last_used_at: lu,
        })
        .collect();
    let next_cursor = more
        .then(|| {
            items
                .last()
                .map(|v| encode_cursor(&format!("{}{}", v.published_at, v.head)))
        })
        .flatten();
    Ok(Json(Page { items, next_cursor }))
}

async fn warnings(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<BundleWarnings>> {
    let model = s.config.model().await?;
    let def = model
        .bundles
        .get(&id)
        .ok_or_else(|| ApiError::not_found("no such bundle"))?;
    let alerts = s
        .alerts
        .list(
            crate::alerts::AlertFilter {
                bundle: Some(id.clone()),
                state: Some(crate::alerts::AlertState::Open),
                ..Default::default()
            },
            None,
            500,
        )
        .await?;
    let limit = q.limit()?;
    let after: i64 = match &q.cursor {
        Some(c) if !c.is_empty() => decode_cursor(c)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ApiError::bad_request("bad cursor"))?,
        _ => 0,
    };
    // A block bundle lists the warnings on its entries; a warn or allow bundle the ones it raised.
    let by = !matches!(def.action, crate::config::model::BundleAction::Block);
    let b = id.clone();
    let rows = s
        .db
        .read(move |c| {
            let col = if by { "by_bundle_id" } else { "bundle_id" };
            let mut st = c.prepare(&format!(
                "SELECT id, kind, by_bundle_id, by_feed_id, value, feed_id, raw, bundle_id, first_seen, last_seen, status
                 FROM warnings WHERE {col} = ?1 AND status = 'open' AND id > ?2 ORDER BY id LIMIT ?3"
            ))?;
            let v = st
                .query_map(rusqlite::params![b, after, limit + 1], |r| {
                    Ok(WarningView {
                        id: r.get(0)?,
                        kind: r.get(1)?,
                        by_bundle: r.get(2)?,
                        by_feed: r.get(3)?,
                        value: r.get(4)?,
                        feed: r.get(5)?,
                        raw: r.get(6)?,
                        bundle: r.get(7)?,
                        first_seen: r.get(8)?,
                        last_seen: r.get(9)?,
                        status: r.get(10)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>(v)
        })
        .await?;
    let more = rows.len() > limit;
    let items: Vec<WarningView> = rows.into_iter().take(limit).collect();
    let next_cursor = more
        .then(|| items.last().map(|w| encode_cursor(&w.id.to_string())))
        .flatten();
    Ok(Json(BundleWarnings {
        alerts,
        warnings: Page { items, next_cursor },
    }))
}

/// The rule behind a `bundle_psl_hits` row (its stored identity), as its feed lists it now;
/// `None` for an identity that doesn't parse.
fn psl_rule(c: &rusqlite::Connection, identity_json: &str) -> Option<PublicSuffixRule> {
    let i = serde_json::from_str::<super::guard::Identity>(identity_json).ok()?;
    let (rule, line): (Option<String>, Option<i64>) = c
        .query_row(
            "SELECT raw, line_no FROM feed_entries WHERE feed_id = ?1 AND rule_type = ?2 AND key = ?3
               AND kind = ?4 AND flags = ?5 AND value_json = ?6 AND removed_run IS NULL LIMIT 1",
            rusqlite::params![
                i.feed,
                i.rule_type,
                i.key,
                i.kind,
                i64::from(i.flags),
                i.value_json
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or_default();
    Some(PublicSuffixRule { rule, line })
}

/// Up to `limit` of the rules of `bundle`'s (`feed`, `suffix`) after `after` (a rule hash,
/// empty for the first), in rule-hash order, and the cursor past them when more follow.
fn psl_rules(
    c: &rusqlite::Connection,
    bundle: &str,
    feed: &str,
    suffix: &str,
    after: &str,
    limit: usize,
) -> anyhow::Result<(Vec<PublicSuffixRule>, Option<String>)> {
    let mut st = c.prepare_cached(
        "SELECT rule_hash, identity_json FROM bundle_psl_hits
          WHERE bundle_id = ?1 AND feed_id = ?2 AND suffix = ?3 AND rule_hash > ?4
          ORDER BY rule_hash LIMIT ?5",
    )?;
    let mut rows: Vec<(String, String)> = st
        .query_map(rusqlite::params![bundle, feed, suffix, after, limit + 1], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let cursor = more.then(|| rows.last().map(|(h, _)| encode_cursor(h))).flatten();
    let rules = rows.iter().filter_map(|(_, ij)| psl_rule(c, ij)).collect();
    Ok((rules, cursor))
}

async fn public_suffixes(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PublicSuffixQuery>,
) -> ApiResult<Json<PublicSuffixes>> {
    let model = s.config.model().await?;
    if !model.bundles.contains_key(&id) {
        return Err(ApiError::not_found("no such bundle"));
    }
    let limit = crate::web::api::limit_param(
        q.limit,
        crate::web::api::DEFAULT_LIMIT,
        crate::web::api::MAX_LIMIT,
    )?;
    let (after_feed, after_suffix) = match &q.cursor {
        Some(c) if !c.is_empty() => decode_cursor(c)
            .and_then(|s| s.split_once('\n').map(|(f, x)| (f.to_string(), x.to_string())))
            .ok_or_else(|| ApiError::bad_request("bad cursor"))?,
        _ => (String::new(), String::new()),
    };
    let feed = q.feed.clone();
    let (total, more, items) =
        s.db.read(move |c| {
            let total: i64 = c.query_row(
                "SELECT count(*) FROM (SELECT DISTINCT feed_id, suffix FROM bundle_psl_hits
                   WHERE bundle_id = ?1 AND (?2 IS NULL OR feed_id = ?2))",
                rusqlite::params![id, feed],
                |r| r.get(0),
            )?;
            let mut st = c.prepare(
                "SELECT feed_id, suffix, count(*) FROM bundle_psl_hits
                  WHERE bundle_id = ?1 AND (?2 IS NULL OR feed_id = ?2) AND (feed_id, suffix) > (?3, ?4)
                  GROUP BY feed_id, suffix ORDER BY feed_id, suffix LIMIT ?5",
            )?;
            let mut groups: Vec<(String, String, i64)> = st
                .query_map(
                    rusqlite::params![id, feed, after_feed, after_suffix, limit + 1],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?
                .collect::<rusqlite::Result<_>>()?;
            // The group past the page only says another page follows: its rules aren't read.
            let more = groups.len() > limit;
            groups.truncate(limit);
            let mut items = Vec::with_capacity(groups.len());
            for (f, suffix, count) in groups {
                let (rules, rules_cursor) = psl_rules(c, &id, &f, &suffix, "", PUBLIC_SUFFIX_RULES)?;
                items.push(PublicSuffixView {
                    feed: f,
                    suffix,
                    rules,
                    rule_count: u64::try_from(count).unwrap_or(0),
                    rules_cursor,
                });
            }
            Ok::<_, anyhow::Error>((total, more, items))
        })
        .await?;
    let next_cursor = more
        .then(|| {
            items
                .last()
                .map(|v: &PublicSuffixView| encode_cursor(&format!("{}\n{}", v.feed, v.suffix)))
        })
        .flatten();
    Ok(Json(PublicSuffixes {
        total: u64::try_from(total).unwrap_or(0),
        items,
        next_cursor,
    }))
}

/// The rules of one public suffix a bundle blocks from one feed, a page at a time (the rest of a
/// [`PublicSuffixView`]'s `rules`, from its `rules_cursor`).
async fn public_suffix_rules(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PublicSuffixRulesQuery>,
) -> ApiResult<Json<Page<PublicSuffixRule>>> {
    let model = s.config.model().await?;
    if !model.bundles.contains_key(&id) {
        return Err(ApiError::not_found("no such bundle"));
    }
    let limit = crate::web::api::limit_param(
        q.limit,
        crate::web::api::DEFAULT_LIMIT,
        crate::web::api::MAX_LIMIT,
    )?;
    let after = match &q.cursor {
        Some(c) if !c.is_empty() => decode_cursor(c).ok_or_else(|| ApiError::bad_request("bad cursor"))?,
        _ => String::new(),
    };
    let (items, next_cursor) =
        s.db.read(move |c| psl_rules(c, &id, &q.feed, &q.suffix, &after, limit))
            .await?;
    Ok(Json(Page { items, next_cursor }))
}

async fn build_now(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<impl IntoResponse> {
    let model = s.config.model().await?;
    if !model.bundles.contains_key(&id) {
        return Err(ApiError::not_found("no such bundle"));
    }
    s.compiler.request(
        &s,
        &id,
        super::Request {
            reasons: ["build now (UI)".into()].into(),
            force: true,
            ..super::Request::default()
        },
        Priority::P0,
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(BuildQueued {
            bundle: id,
            queued: true,
        }),
    ))
}

async fn explain(
    State(s): State<SharedState>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<ExplainQuery>,
) -> ApiResult<Json<Explanation>> {
    let model = s.config.model().await?;
    let def = model
        .bundles
        .get(&id)
        .ok_or_else(|| ApiError::not_found("no such bundle"))?;
    let spec = Spec::of(def, &model);
    let name = q.name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return Err(ApiError::bad_request("name: a DNS name or an address"));
    }
    let qtype = match &q.qtype {
        Some(t) => picket_rules::rrtype::parse_rr_type(t)
            .ok_or_else(|| ApiError::bad_request("qtype: a record type"))?,
        None => 1,
    };
    let client_ip: Option<IpAddr> = match &q.client_ip {
        Some(ip) => Some(
            ip.parse()
                .map_err(|_| ApiError::bad_request("client_ip: an address"))?,
        ),
        None => None,
    };
    let ip: Option<IpAddr> = name.parse().ok();
    let out =
        s.db.read(move |c| {
            let runs = spec::snapshot(c, &spec)?;
            let view = View::new(&spec, &runs);
            let mut bad = 0u64;
            let mut rows: Vec<super::source::Row> = Vec::new();
            if ip.is_none() {
                let rn = picket_rules::OwnedName::from_dotted(&name);
                let labels: Vec<String> = rn
                    .as_labels()
                    .iter()
                    .map(|l| String::from_utf8_lossy(l).into_owned())
                    .collect();
                // Keys at each suffix of the name, whole wire labels (rules.md §3).
                for i in 0..labels.len() {
                    let suffix: Vec<&str> = labels[i..].iter().rev().map(String::as_str).collect();
                    if suffix.iter().any(|l| l.contains('.')) {
                        continue;
                    }
                    rows.extend(view.key_rules(c, &suffix.join("."), &mut bad)?);
                }
            } else if let Ok(ips) = view.ip_rules(c, EXPLAIN_MAX_RULES, &mut bad)? {
                rows.extend(ips);
            }
            if let Ok(p) = view.patterns(c, EXPLAIN_MAX_RULES, &mut bad)? {
                rows.extend(p);
            }
            rows.sort_by(|a, b| a.order.cmp(&b.order));
            rows.dedup_by(|a, b| a.order == b.order);
            let matcher = picket_rules::BundleMatcher::new(
                spec.rules_action(),
                rows.iter().map(|r| r.rule.clone()).collect(),
            )
            .with_public_suffix_list(crate::psl::rules_list());
            let tags: Vec<String> = q
                .tags
                .as_deref()
                .map(|t| {
                    t.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let tag_refs: Vec<&str> = tags.iter().map(String::as_str).collect();
            let client: Vec<&str> = q.client.as_deref().into_iter().collect();
            let ctx = picket_rules::QueryCtx {
                qtype,
                client_ip,
                client_names: &client,
                client_tags: &tag_refs,
            };
            let r = match ip {
                Some(ip) => matcher.match_ip(ip, &ctx),
                None => matcher.match_dotted(&name, &ctx),
            };
            let mut matches = Vec::new();
            for m in &r.matches {
                let Some(row) = rows.get(m.rule) else { continue };
                let (raw, line) = super::source::raw_of(c, row.entry_id).unwrap_or_default();
                matches.push(ExplainMatch {
                    feed: row.feed.clone(),
                    rule: raw,
                    line,
                    role: serde_json::to_value(m.role).unwrap_or_default(),
                    level: m.level.map(|l| format!("{l:?}")),
                });
            }
            Ok::<_, anyhow::Error>(Explanation {
                bundle: spec.id.clone(),
                name: name.clone(),
                outcome: serde_json::to_value(&r.outcome).unwrap_or_default(),
                step: r.step.map(|s| format!("{s:?}").to_ascii_lowercase()),
                matches,
                feed_runs: runs,
            })
        })
        .await?;
    Ok(Json(out))
}

/// The routes under `bundles/` beside the generic CRUD (merged into its router).
pub fn item_routes() -> Router<SharedState> {
    Router::new()
        .route("/{id}/status", get(bundle_status))
        .route("/{id}/versions", get(versions))
        .route("/{id}/warnings", get(warnings))
        .route("/{id}/public-suffixes", get(public_suffixes))
        .route("/{id}/public-suffixes/rules", get(public_suffix_rules))
        .route("/{id}/build", post(build_now))
        .route("/{id}/explain", get(explain))
}

/// The top-level bundle routes.
pub fn routes() -> Router<SharedState> {
    Router::new().route("/bundle-status", get(all_status))
}
