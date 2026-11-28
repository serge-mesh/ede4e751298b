//! Reading and writing the configuration in `core.db`, and applying changes.
//!
//! A change runs entirely inside one writer transaction: load the model, apply the change in
//! memory, validate the whole model, refuse if the change introduces an error, write the
//! entity's rows, journal a redacted diff (core.md §2, storage.md §3).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::journal;
use super::model::*;
use super::secrets::{self, SecretsKey};
use super::system;
use super::validate::{self, Issue, Severity};
use crate::error::{CoreError, CoreResult};
use crate::settings;

// ---------------------------------------------------------------------------------------------
// Helpers

fn json<T: DeserializeOwned + Default>(what: &str, s: Option<String>) -> T {
    match s {
        None => T::default(),
        Some(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            tracing::warn!(what, error = %e, "unreadable stored JSON; using the default");
            T::default()
        }),
    }
}

fn enum_str<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        _ => String::new(),
    }
}

fn parse_enum<T: DeserializeOwned + Default>(s: &str) -> T {
    serde_json::from_value(Value::String(s.to_string())).unwrap_or_default()
}

fn to_json<T: Serialize>(v: &T) -> Result<String> {
    Ok(serde_json::to_string(v)?)
}

// ---------------------------------------------------------------------------------------------
// Loading

/// Loads the whole model (settings included).
pub fn load_model(conn: &Connection) -> Result<Model> {
    load_parts(conn, None)
}

/// Loads the settings and one kind's entities only (listing and reading one collection needn't
/// materialise the whole model; README §2, Bounded).
pub fn load_kind(conn: &Connection, kind: EntityKind) -> Result<Model> {
    load_parts(conn, Some(kind))
}

fn load_parts(conn: &Connection, only: Option<EntityKind>) -> Result<Model> {
    // Feeds come with their providers (the feeds runtime and the feed pages need both).
    let want = |k: EntityKind| {
        only.is_none_or(|o| o == k || (o == EntityKind::Feed && k == EntityKind::FeedProvider))
    };
    let mut m = Model {
        settings: settings::load(conn)?,
        ..Model::default()
    };

    if want(EntityKind::Edge) {
        let mut st =
            conn.prepare("SELECT id, name, key_sha256, platform, settings_json, created_at FROM edges")?;
        let rows = st.query_map([], |r| {
            Ok(EdgeDef {
                id: r.get(0)?,
                name: r.get(1)?,
                key: r.get(2)?,
                platform: parse_enum(&r.get::<_, String>(3)?),
                settings: json("edge settings", r.get(4)?),
                created_at: r.get(5)?,
            })
        })?;
        for e in rows {
            let e = e?;
            m.edges.insert(e.id.clone(), e);
        }
    }

    if want(EntityKind::Listener) {
        let mut assign: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut st =
            conn.prepare("SELECT listener_id, edge_id FROM listener_edges ORDER BY listener_id, edge_id")?;
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (l, e) = row?;
            assign.entry(l).or_default().push(e);
        }
        let mut st = conn.prepare(
            "SELECT id, name, proto, bind, interfaces_json, tls_json, api, ips_json, limits_json FROM listeners",
        )?;
        let rows = st.query_map([], |r| {
            Ok(ListenerDef {
                id: r.get(0)?,
                name: r.get(1)?,
                proto: parse_enum(&r.get::<_, String>(2)?),
                bind: r.get(3)?,
                interfaces: json("listener interfaces", r.get(4)?),
                tls: r
                    .get::<_, Option<String>>(5)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                api: r.get::<_, i64>(6)? != 0,
                ips: json("listener ips", r.get(7)?),
                limits: json("listener limits", r.get(8)?),
                edges: vec![],
            })
        })?;
        for l in rows {
            let mut l = l?;
            l.edges = assign.remove(&l.id).unwrap_or_default();
            m.listeners.insert(l.id.clone(), l);
        }
    }

    if want(EntityKind::Client) {
        let mut st = conn.prepare(
            "SELECT name, position, macs_json, source_ips_json, profile, tags_json FROM clients ORDER BY position, name",
        )?;
        let rows = st.query_map([], |r| {
            Ok(ClientDef {
                name: r.get(0)?,
                position: u32::try_from(r.get::<_, i64>(1)?).ok(),
                macs: json("client macs", r.get(2)?),
                source_ips: json("client source_ips", r.get(3)?),
                profile: r.get(4)?,
                tags: json("client tags", r.get(5)?),
            })
        })?;
        for c in rows {
            m.clients.push(c?);
        }
    }

    if want(EntityKind::Profile) {
        let mut st = conn.prepare("SELECT id, name, system, body_json FROM profiles")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (id, name, system, body) = row?;
            let mut p: ProfileDef = json("profile body", Some(body));
            p.id = id;
            p.name = name;
            p.system = system != 0;
            m.profiles.insert(p.id.clone(), p);
        }
    }

    if want(EntityKind::Upstream) {
        let mut st = conn.prepare(
            "SELECT id, name, protocol, ip, port, tls_host, path, trust_store_pem, operator FROM upstreams",
        )?;
        let rows = st.query_map([], |r| {
            Ok(UpstreamDef {
                id: r.get(0)?,
                name: r.get(1)?,
                protocol: parse_enum(&r.get::<_, String>(2)?),
                ip: r
                    .get::<_, String>(3)?
                    .parse()
                    .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
                port: u16::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                tls_host: r.get(5)?,
                path: r.get(6)?,
                trust_store: r.get(7)?,
                operator: r.get(8)?,
            })
        })?;
        for u in rows {
            let u = u?;
            m.upstreams.insert(u.id.clone(), u);
        }
    }

    if want(EntityKind::UpstreamGroup) {
        let mut st =
            conn.prepare("SELECT id, name, strategy, optimistic, members_json FROM upstream_groups")?;
        let rows = st.query_map([], |r| {
            Ok(UpstreamGroupDef {
                id: r.get(0)?,
                name: r.get(1)?,
                strategy: parse_enum(&r.get::<_, String>(2)?),
                optimistic: r.get::<_, i64>(3)? != 0,
                upstreams: json("group members", r.get(4)?),
            })
        })?;
        for g in rows {
            let g = g?;
            m.upstream_groups.insert(g.id.clone(), g);
        }
    }

    if want(EntityKind::ForwardZone) {
        let mut st = conn.prepare("SELECT id, zone, group_id, fallback FROM forward_zones")?;
        let rows = st.query_map([], |r| {
            Ok(ForwardZoneDef {
                id: r.get(0)?,
                zone: r.get(1)?,
                group: r.get(2)?,
                fallback: parse_enum(&r.get::<_, String>(3)?),
            })
        })?;
        for z in rows {
            let z = z?;
            m.forward_zones.insert(z.id.clone(), z);
        }
    }

    if want(EntityKind::FeedProvider) {
        let mut st = conn.prepare(
            "SELECT id, name, enabled, system, module, config_json, trigger_json, files_json, exclude_json
             FROM feed_providers",
        )?;
        let rows = st.query_map([], |r| {
            let id: String = r.get(0)?;
            Ok(FeedProviderDef {
                system: r.get::<_, i64>(3)? != 0 || system::is_system(EntityKind::FeedProvider, &id),
                id,
                name: r.get(1)?,
                enabled: r.get::<_, i64>(2)? != 0,
                module: r.get(4)?,
                config: json("feed provider config", r.get(5)?),
                trigger: json("feed provider trigger", r.get(6)?),
                files: json("feed provider files", r.get(7)?),
                exclude: json("feed provider exclude", r.get(8)?),
            })
        })?;
        for p in rows {
            let p = p?;
            m.feed_providers.insert(p.id.clone(), p);
        }
    }

    if want(EntityKind::Feed) {
        let mut st = conn.prepare(
            "SELECT id, name, category, enabled, provider_id, file, format, format_options_json,
                    modes_json, rule_policy_json, sanity_json, warn_on_json FROM feeds",
        )?;
        let rows = st.query_map([], |r| {
            let id: String = r.get(0)?;
            Ok(FeedDef {
                system: system::is_system(EntityKind::Feed, &id),
                id,
                name: r.get(1)?,
                category: parse_enum(&r.get::<_, String>(2)?),
                enabled: r.get::<_, i64>(3)? != 0,
                provider: r.get(4)?,
                file: r.get(5)?,
                format: parse_enum(&r.get::<_, String>(6)?),
                format_options: json("feed format_options", r.get(7)?),
                modes: json("feed modes", r.get(8)?),
                rule_policy: json("feed rule_policy", r.get(9)?),
                sanity: json("feed sanity", r.get(10)?),
                warn_on: r
                    .get::<_, Option<String>>(11)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
            })
        })?;
        for f in rows {
            let f = f?;
            m.feeds.insert(f.id.clone(), f);
        }
    }

    if want(EntityKind::Bundle) {
        let mut feeds: BTreeMap<String, Vec<BundleFeed>> = BTreeMap::new();
        let mut st = conn.prepare(
            "SELECT bundle_id, feed_id, rule_types_json, tier FROM bundle_feeds ORDER BY bundle_id, position, feed_id",
        )?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })? {
            let (b, f, rt, tier) = row?;
            let tier = match tier.as_str() {
                "cold" => Some(Tier::Cold),
                "intelligent-tiering" => Some(Tier::IntelligentTiering),
                _ => None, // `hot` is the default
            };
            feeds.entry(b).or_default().push(BundleFeed {
                feed: f,
                rule_types: rt.and_then(|s| serde_json::from_str(&s).ok()),
                tier,
            });
        }
        let mut st =
            conn.prepare(r#"SELECT id, name, system, "action", max_shard_keys, hot_max_mib FROM bundles"#)?;
        let rows = st.query_map([], |r| {
            Ok(BundleDef {
                id: r.get(0)?,
                name: r.get(1)?,
                system: r.get::<_, i64>(2)? != 0,
                action: parse_enum(&r.get::<_, String>(3)?),
                max_shard_keys: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                hot_max_mib: r.get::<_, Option<i64>>(5)?.and_then(|v| u32::try_from(v).ok()),
                feeds: vec![],
            })
        })?;
        for b in rows {
            let mut b = b?;
            b.feeds = feeds.remove(&b.id).unwrap_or_default();
            m.bundles.insert(b.id.clone(), b);
        }
    }

    if want(EntityKind::LookupProvider) {
        let mut st = conn.prepare(
            "SELECT id, name, module, config_json, sync_timeout_ms, async_timeout_ms, fail_mode, retries,
                    recheck_json, scope_json, cache_json, limits_json, breaker_json, async_max_attempts,
                    category, cache_generation, preset_json, last_self_test_json FROM lookup_providers",
        )?;
        let rows = st.query_map([], |r| {
            let mut settings = picket_api::edge_config::LookupSettings {
                sync_timeout_ms: u32::try_from(r.get::<_, i64>(4)?).unwrap_or(150),
                async_timeout_ms: u32::try_from(r.get::<_, i64>(5)?).unwrap_or(10_000),
                fail_mode: parse_enum(&r.get::<_, String>(6)?),
                retries: r.get::<_, i64>(7)? != 0,
                ..Default::default()
            };
            settings.recheck = json("provider recheck", r.get(8)?);
            settings.scope = json("provider scope", r.get(9)?);
            settings.cache = json("provider cache", r.get(10)?);
            settings.limits = json("provider limits", r.get(11)?);
            settings.breaker = json("provider breaker", r.get(12)?);
            settings.async_max_attempts = u32::try_from(r.get::<_, i64>(13)?).unwrap_or(5);
            Ok(LookupProviderDef {
                id: r.get(0)?,
                name: r.get(1)?,
                module: r.get(2)?,
                config: json("provider config", r.get(3)?),
                settings,
                category: parse_enum(&r.get::<_, String>(14)?),
                cache_generation: r.get(15)?,
                preset: r
                    .get::<_, Option<String>>(16)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
                last_self_test: r
                    .get::<_, Option<String>>(17)?
                    .and_then(|s| serde_json::from_str(&s).ok()),
            })
        })?;
        for p in rows {
            let p = p?;
            m.lookup_providers.insert(p.id.clone(), p);
        }
    }

    if want(EntityKind::Secret) {
        let mut st = conn.prepare("SELECT name, length(value_enc) FROM secrets")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (name, len) = row?;
            m.secrets.insert(
                name.clone(),
                SecretMeta {
                    name,
                    has_value: len > 1,
                },
            );
        }
    }
    Ok(m)
}

/// What [`upgrade_previous`] did beyond the configuration itself: what the provider state
/// follows, and what the owner is told ([`announce_upgrade`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Upgrade {
    /// Each provider split off an older `http` provider, and the one it came from (its stored or
    /// exported provider state follows it).
    pub splits: Vec<(String, String)>,
    /// The older `http` providers converted in place (their stale record of files skipped past
    /// the feed cap, and its alert, go).
    pub converted: Vec<String>,
    /// The `alphamountain_threat_1000` providers whose file `""` was named.
    pub named: Vec<String>,
    /// An `sqs` provider and its split-offs, which take the default trigger: one queue has one
    /// consumer, so it nudges the kept provider only.
    pub sqs: Vec<(String, Vec<String>)>,
    /// The URLs an older provider selected but never added a feed for (past its feed cap):
    /// nothing fetched them, so they get no provider.
    pub dropped: Vec<(String, Vec<String>)>,
}

impl Upgrade {
    /// True when nothing was upgraded.
    pub fn is_empty(&self) -> bool {
        self.splits.is_empty()
            && self.converted.is_empty()
            && self.named.is_empty()
            && self.sqs.is_empty()
            && self.dropped.is_empty()
    }
}

/// Reads what the previous release stored in a since-changed shape (README §2 Compatibility: release
/// N reads everything N−1 stored, the config export included, and it behaves the same). An export
/// being restored goes through this (`export::check_head`, before validation), and the stored rows
/// once at start ([`upgrade_stored`]). Running it again changes nothing.
/// - `alphamountain_threat_1000`'s one file was `""`: a provider's `files` and `exclude` entries
///   `""` and its feeds' `file` `""` become
///   [`FILE`](crate::modules::download::alphamountain_threat_1000::FILE).
/// - An `http` provider was a `base_url` and paths ([`split_http`]): it becomes one provider per
///   feed's URL.
///
/// Feed ids never change, so a feed's runs, entries, state and bundle references stay its own.
/// Any other module's empty name is left: validation refuses it (`empty_file`).
pub fn upgrade_previous(m: &mut Model) -> Upgrade {
    use crate::modules::download::alphamountain_threat_1000::FILE;
    let mut named = BTreeSet::new();
    let mut changed = BTreeSet::new();
    for p in m
        .feed_providers
        .values_mut()
        .filter(|p| p.module == "alphamountain_threat_1000")
    {
        for f in p.files.iter_mut().filter(|f| f.pattern.is_empty()) {
            f.pattern = FILE.into();
            changed.insert(p.id.clone());
        }
        for x in p.exclude.iter_mut().filter(|x| x.is_empty()) {
            *x = FILE.into();
            changed.insert(p.id.clone());
        }
        named.insert(p.id.clone());
    }
    for f in m.feeds.values_mut() {
        if let Some(p) = f.provider.as_ref().filter(|p| named.contains(*p))
            && f.file.as_deref() == Some("")
        {
            changed.insert(p.clone());
            f.file = Some(FILE.into());
        }
    }
    let mut up = split_http(m);
    up.named = changed.into_iter().collect();
    up
}

/// One feed of an older `http` provider ([`split_http`]).
struct HttpUnit {
    url: String,
    /// The path it read, for a split-off provider's name.
    path: String,
    feed: String,
    template: Option<serde_json::Value>,
}

/// An older `http` provider (config `{base_url, headers?, date_line_regex?}`, `files` holding
/// paths under it) becomes one provider per feed's URL (config `{url, headers?,
/// date_line_regex?}`, its one file `response`), behaving as before:
/// - its feeds, in id order, each at its path resolved against `base_url` as the old module did
///   (`""` and `./` are one URL); the first keeps the provider's id; each other one gets a new
///   provider whose id is its feed's (free among providers and the other feeds), with the
///   provider's headers, regex, `enabled` and name (and the path), and its trigger, except `sqs`:
///   one queue has one consumer, so a split-off takes the default trigger;
/// - each feed points at its URL's provider and reads `response`; two feeds of one URL keep a
///   provider each (the same `url`: a save warns of the overlap);
/// - a path selected without a feed (past `feeds.max_per_provider`) was never fetched: it gets no
///   provider, and is reported ([`Upgrade::dropped`]);
/// - a provider without feeds keeps selecting nothing (`exclude: ["response"]`).
fn split_http(m: &mut Model) -> Upgrade {
    use crate::modules::download::http::FILE;
    let old: Vec<FeedProviderDef> = m
        .feed_providers
        .values()
        .filter(|p| p.module == "http" && p.config.get("base_url").is_some() && p.config.get("url").is_none())
        .cloned()
        .collect();
    let mut out = Upgrade::default();
    for p in old {
        let base_text = p
            .config
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let base = url::Url::parse(&base_text).ok();
        // As the old module resolved a path (`""` is base_url itself).
        let url_of = |path: &str| match base.as_ref().and_then(|b| b.join(path).ok()) {
            Some(u) => u.to_string(),
            None => format!("{base_text}{path}"),
        };
        let template_of = |path: &str| {
            p.files
                .iter()
                .find(|f| f.pattern == path)
                .and_then(|f| f.feed.clone())
        };
        let units: Vec<HttpUnit> = m
            .feeds
            .values()
            .filter(|f| f.provider.as_deref() == Some(p.id.as_str()))
            .map(|f| {
                let path = f.file.clone().unwrap_or_default();
                HttpUnit {
                    url: url_of(&path),
                    template: template_of(&path),
                    feed: f.id.clone(),
                    path,
                }
            })
            .collect();
        // Paths the old rules selected (not excluded) that no feed reads: never fetched.
        let mut dropped: Vec<String> = Vec::new();
        for f in p
            .files
            .iter()
            .filter(|f| !crate::feeds::select::excluded(&p, &f.pattern))
        {
            let url = url_of(&f.pattern);
            if units.iter().all(|u| u.url != url) && !dropped.contains(&url) {
                dropped.push(url);
            }
        }
        let config_for = |url: &str| {
            let mut c = p.config.as_object().cloned().unwrap_or_default();
            c.remove("base_url");
            c.insert("url".into(), serde_json::Value::String(url.into()));
            serde_json::Value::Object(c)
        };
        let files_for = |t: Option<serde_json::Value>| {
            t.map(|t| {
                vec![FileSelect {
                    pattern: FILE.into(),
                    feed: Some(t),
                }]
            })
            .unwrap_or_default()
        };
        let mut owner: BTreeMap<String, String> = BTreeMap::new();
        // The provider itself: its first feed's URL; with none, a path's (it fetched nothing,
        // and still doesn't).
        let mut kept = p.clone();
        match units.first() {
            Some(u) => {
                kept.config = config_for(&u.url);
                kept.files = files_for(u.template.clone());
                kept.exclude = vec![];
                owner.insert(u.feed.clone(), p.id.clone());
            }
            None => {
                let first = p.files.first();
                kept.config = config_for(
                    &first
                        .map(|f| url_of(&f.pattern))
                        .unwrap_or_else(|| base_text.clone()),
                );
                kept.files = files_for(first.and_then(|f| f.feed.clone()));
                kept.exclude = vec![FILE.into()];
            }
        }
        m.feed_providers.insert(p.id.clone(), kept);
        let sqs = matches!(p.trigger, crate::config::model::Trigger::Sqs { .. });
        let mut sqs_moved = Vec::new();
        let name = if p.name.trim().is_empty() {
            p.id.clone()
        } else {
            p.name.clone()
        };
        for u in units.into_iter().skip(1) {
            let id = crate::feeds::select::unique_id(&u.feed, &|c: &str| {
                m.feed_providers.contains_key(c) || (c != u.feed && m.feeds.contains_key(c))
            });
            let label = if u.path.trim().is_empty() {
                u.url.clone()
            } else {
                u.path.clone()
            };
            let label = percent_encoding::percent_decode_str(&label)
                .decode_utf8_lossy()
                .into_owned();
            m.feed_providers.insert(
                id.clone(),
                FeedProviderDef {
                    id: id.clone(),
                    name: crate::feeds::select::display_name(&name, Some(&label)),
                    enabled: p.enabled,
                    system: false,
                    module: p.module.clone(),
                    config: config_for(&u.url),
                    trigger: if sqs {
                        Default::default()
                    } else {
                        p.trigger.clone()
                    },
                    files: files_for(u.template),
                    exclude: vec![],
                },
            );
            owner.insert(u.feed, id.clone());
            if sqs {
                sqs_moved.push(id.clone());
            }
            out.splits.push((id, p.id.clone()));
        }
        for (feed, provider) in owner {
            if let Some(f) = m.feeds.get_mut(&feed) {
                f.provider = Some(provider);
                f.file = Some(FILE.into());
            }
        }
        if !sqs_moved.is_empty() {
            out.sqs.push((p.id.clone(), sqs_moved));
        }
        if !dropped.is_empty() {
            out.dropped.push((p.id.clone(), dropped));
        }
        out.converted.push(p.id.clone());
    }
    out
}

/// [`upgrade_previous`] on the stored rows, in the start's transaction (before anything reads
/// them), so every reader sees the new shape: the configuration, and the stored provider and
/// feed sources a check compares with it. A split-off provider gets a copy of the provider state
/// of the one it came from (its scheduler's and `k`; not the listing, a trigger's own state or a
/// check in flight); a feed's own state (the module's validators and method in its last run)
/// stays with the feed. A converted provider's record of files skipped past the feed cap goes
/// (they get no provider). Nothing else of a row changes (no new generation: the URL is the
/// same). The start tells the owner what changed ([`announce_upgrade`]).
pub fn upgrade_stored(tx: &Transaction<'_>) -> Result<Upgrade> {
    let before = load_kind(tx, EntityKind::Feed)?;
    let mut after = before.clone();
    let up = upgrade_previous(&mut after);
    for (new, from) in &up.splits {
        tx.execute(
            "INSERT OR IGNORE INTO feed_provider_state(provider_id, state_json, next_check_at, due_cause, nudged_at, k,
                 source_gen, last_check_at, last_ok_at, failing_since, list_gen)
             SELECT ?1, state_json, next_check_at, due_cause, nudged_at, k, source_gen,
                 last_check_at, last_ok_at, failing_since, list_gen
             FROM feed_provider_state WHERE provider_id = ?2",
            params![new, from],
        )?;
        if let Some(p) = after.feed_providers.get(new) {
            write_feed_provider(tx, p)?;
        }
    }
    for (id, p) in &after.feed_providers {
        if before.feed_providers.get(id).is_some_and(|b| b != p) {
            tx.execute(
                "UPDATE feed_providers SET config_json = ?2, files_json = ?3, exclude_json = ?4 WHERE id = ?1",
                params![id, to_json(&p.config)?, to_json(&p.files)?, to_json(&p.exclude)?],
            )?;
        }
    }
    for id in &up.converted {
        tx.execute(
            "UPDATE feed_provider_state SET skipped_json = NULL, capacity_skipped_json = NULL WHERE provider_id = ?1",
            [id],
        )?;
    }
    // Feeds moving to another provider first, so none meets the (provider, file) index on the
    // way (an older file that was named `response`).
    let mut moves: Vec<(&String, &FeedDef, bool)> = after
        .feeds
        .iter()
        .filter_map(|(id, f)| {
            let b = before.feeds.get(id)?;
            (b.provider != f.provider || b.file != f.file).then_some((id, f, b.provider != f.provider))
        })
        .collect();
    moves.sort_by_key(|(_, _, moved)| !moved);
    for (id, f, _) in moves {
        tx.execute(
            "UPDATE feeds SET provider_id = ?2, file = ?3 WHERE id = ?1",
            params![id, f.provider, f.file],
        )?;
    }
    Ok(up)
}

/// Tells the owner what an upgrade of the previous release's shapes changed ([`Upgrade`]): one
/// `config_upgraded` alert for split-off providers that left an `sqs` trigger behind and one
/// for paths never added past the feed cap (dropped); a converted provider's feed-cap alert is
/// resolved (its files get no provider).
pub async fn announce_upgrade(alerts: &crate::alerts::Alerts, up: &Upgrade) {
    use crate::alerts::{RaiseSpec, Severity};
    for id in &up.converted {
        if let Err(e) = alerts
            .resolve(
                &format!("feed_added:provider:{id}"),
                Some(serde_json::json!({"by": "the upgrade to one http provider per URL"})),
            )
            .await
        {
            tracing::warn!(provider = %id, error = %e, "cannot resolve the feed-cap alert");
        }
    }
    for (kept, moved) in &up.sqs {
        let spec = RaiseSpec::new(
            "config_upgraded",
            Severity::Warning,
            format!("config_upgraded:sqs:{kept}"),
            format!(
                "{} now on the dynamic trigger: the SQS queue nudges only {kept}",
                moved.join(", ")
            ),
            serde_json::json!({"provider": kept, "dynamic": moved}),
        )
        .feed_provider(kept.clone());
        if let Err(e) = alerts.raise(spec).await {
            tracing::warn!(provider = %kept, error = %e, "cannot raise config_upgraded");
        }
    }
    if !up.dropped.is_empty() {
        let urls: Vec<&String> = up.dropped.iter().flat_map(|(_, u)| u).collect();
        let spec = RaiseSpec::new(
            "config_upgraded",
            Severity::Info,
            "config_upgraded:dropped",
            format!(
                "{} selected URL(s) never added past the feed cap: add by URL to fetch them",
                urls.len()
            ),
            serde_json::json!({
                "providers": up.dropped.iter().map(|(p, u)| serde_json::json!({"provider": p, "urls": u})).collect::<Vec<_>>(),
            }),
        );
        if let Err(e) = alerts.raise(spec).await {
            tracing::warn!(error = %e, "cannot raise config_upgraded");
        }
    }
}

/// Reads and decrypts the values of `names` (for rendering; never for the UI).
pub fn read_secret_values(
    conn: &Connection,
    key: Option<&SecretsKey>,
    names: &[String],
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut st = conn.prepare_cached("SELECT value_enc FROM secrets WHERE name = ?1")?;
    for n in names {
        let stored: Option<Vec<u8>> = st.query_row([n], |r| r.get(0)).optional()?;
        if let Some(bytes) = stored {
            match secrets::open(key, n, &bytes) {
                Ok(v) if !v.is_empty() => {
                    out.insert(n.clone(), v);
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(secret = %n, error = %e, "secret unreadable"),
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Writing rows (no validation: callers validate first)

pub fn write_edge(tx: &Transaction<'_>, e: &EdgeDef) -> Result<()> {
    tx.execute(
        "INSERT INTO edges(id, name, key_sha256, platform, settings_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, key_sha256 = excluded.key_sha256,
            platform = excluded.platform, settings_json = excluded.settings_json",
        params![
            e.id,
            e.name,
            e.key,
            enum_str(&e.platform),
            to_json(&e.settings)?,
            e.created_at.clone().unwrap_or_else(crate::util::now_ts)
        ],
    )?;
    Ok(())
}

pub fn write_listener(tx: &Transaction<'_>, l: &ListenerDef) -> Result<()> {
    tx.execute(
        "INSERT INTO listeners(id, name, proto, bind, interfaces_json, tls_json, api, ips_json, limits_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, proto = excluded.proto, bind = excluded.bind,
            interfaces_json = excluded.interfaces_json, tls_json = excluded.tls_json, api = excluded.api,
            ips_json = excluded.ips_json, limits_json = excluded.limits_json",
        params![
            l.id,
            l.name,
            enum_str(&l.proto),
            l.bind,
            to_json(&l.interfaces)?,
            l.tls.as_ref().map(to_json).transpose()?,
            l.api as i64,
            to_json(&l.ips)?,
            to_json(&l.limits)?
        ],
    )?;
    tx.execute("DELETE FROM listener_edges WHERE listener_id = ?1", [&l.id])?;
    for e in &l.edges {
        tx.execute(
            "INSERT OR IGNORE INTO listener_edges(listener_id, edge_id) VALUES (?1, ?2)",
            params![l.id, e],
        )?;
    }
    Ok(())
}

pub fn write_client(tx: &Transaction<'_>, c: &ClientDef) -> Result<()> {
    let macs: Vec<String> = c
        .macs
        .iter()
        .map(|m| crate::net::normalize_mac(m).unwrap_or_else(|| m.clone()))
        .collect();
    tx.execute(
        "INSERT INTO clients(name, position, macs_json, source_ips_json, profile, tags_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(name) DO UPDATE SET position = excluded.position, macs_json = excluded.macs_json,
            source_ips_json = excluded.source_ips_json, profile = excluded.profile, tags_json = excluded.tags_json",
        params![
            c.name,
            i64::from(c.position.unwrap_or(0)),
            to_json(&macs)?,
            to_json(&c.source_ips)?,
            c.profile,
            to_json(&c.tags)?
        ],
    )?;
    Ok(())
}

pub fn write_profile(tx: &Transaction<'_>, p: &ProfileDef) -> Result<()> {
    let mut body = serde_json::to_value(p)?;
    if let Value::Object(m) = &mut body {
        m.remove("id");
        m.remove("name");
        m.remove("system");
    }
    tx.execute(
        "INSERT INTO profiles(id, name, system, body_json) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, body_json = excluded.body_json",
        params![p.id, p.name, p.system as i64, serde_json::to_string(&body)?],
    )?;
    Ok(())
}

pub fn write_upstream(tx: &Transaction<'_>, u: &UpstreamDef) -> Result<()> {
    tx.execute(
        "INSERT INTO upstreams(id, name, protocol, ip, port, tls_host, path, trust_store_pem, operator)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, protocol = excluded.protocol, ip = excluded.ip,
            port = excluded.port, tls_host = excluded.tls_host, path = excluded.path,
            trust_store_pem = excluded.trust_store_pem, operator = excluded.operator",
        params![
            u.id,
            u.name,
            enum_str(&u.protocol),
            u.ip.to_string(),
            i64::from(u.port),
            u.tls_host,
            u.path,
            u.trust_store,
            u.operator
        ],
    )?;
    Ok(())
}

pub fn write_group(tx: &Transaction<'_>, g: &UpstreamGroupDef) -> Result<()> {
    tx.execute(
        "INSERT INTO upstream_groups(id, name, strategy, optimistic, members_json) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, strategy = excluded.strategy,
            optimistic = excluded.optimistic, members_json = excluded.members_json",
        params![g.id, g.name, enum_str(&g.strategy), g.optimistic as i64, to_json(&g.upstreams)?],
    )?;
    Ok(())
}

pub fn write_zone(tx: &Transaction<'_>, z: &ForwardZoneDef) -> Result<()> {
    tx.execute(
        "INSERT INTO forward_zones(id, zone, group_id, fallback) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET zone = excluded.zone, group_id = excluded.group_id, fallback = excluded.fallback",
        params![z.id, z.zone, z.group, enum_str(&z.fallback)],
    )?;
    Ok(())
}

/// Writes a feed's row. A feed's `provider` and `file` never change: an update keeps the stored
/// ones (validation refuses a change before this).
pub fn write_feed(tx: &Transaction<'_>, f: &FeedDef) -> Result<()> {
    tx.execute(
        "INSERT INTO feeds(id, name, category, enabled, provider_id, file, format, format_options_json,
                           modes_json, rule_policy_json, sanity_json, warn_on_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, category = excluded.category, enabled = excluded.enabled,
            format = excluded.format, format_options_json = excluded.format_options_json,
            modes_json = excluded.modes_json, rule_policy_json = excluded.rule_policy_json,
            sanity_json = excluded.sanity_json, warn_on_json = excluded.warn_on_json",
        params![
            f.id,
            f.name,
            f.category.as_str(),
            f.enabled as i64,
            f.provider,
            f.file,
            enum_str(&f.format),
            to_json(&f.format_options)?,
            to_json(&f.modes)?,
            to_json(&f.rule_policy.resolved(f.is_manual()))?,
            to_json(&f.sanity)?,
            f.warn_on.as_ref().map(to_json).transpose()?
        ],
    )?;
    Ok(())
}

pub fn write_feed_provider(tx: &Transaction<'_>, p: &FeedProviderDef) -> Result<()> {
    tx.execute(
        "INSERT INTO feed_providers(id, name, enabled, system, module, config_json, trigger_json, files_json, exclude_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, enabled = excluded.enabled, module = excluded.module,
            config_json = excluded.config_json, trigger_json = excluded.trigger_json, files_json = excluded.files_json,
            exclude_json = excluded.exclude_json",
        params![
            p.id,
            p.name,
            p.enabled as i64,
            p.system as i64,
            p.module,
            to_json(&p.config)?,
            to_json(&p.trigger)?,
            to_json(&p.files)?,
            to_json(&p.exclude)?
        ],
    )?;
    tx.execute(
        "INSERT INTO feed_provider_state(provider_id) VALUES (?1) ON CONFLICT(provider_id) DO NOTHING",
        [&p.id],
    )?;
    Ok(())
}

pub fn write_bundle(tx: &Transaction<'_>, b: &BundleDef) -> Result<()> {
    tx.execute(
        r#"INSERT INTO bundles(id, name, system, "action", max_shard_keys, hot_max_mib) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
           ON CONFLICT(id) DO UPDATE SET name = excluded.name, "action" = excluded."action",
              max_shard_keys = excluded.max_shard_keys, hot_max_mib = excluded.hot_max_mib"#,
        params![
            b.id,
            b.name,
            b.system as i64,
            b.action.as_str(),
            i64::try_from(b.max_shard_keys).unwrap_or(i64::MAX),
            b.hot_max_mib.map(i64::from)
        ],
    )?;
    tx.execute("DELETE FROM bundle_feeds WHERE bundle_id = ?1", [&b.id])?;
    for (i, f) in b.feeds.iter().enumerate() {
        tx.execute(
            "INSERT OR IGNORE INTO bundle_feeds(bundle_id, feed_id, rule_types_json, tier, position) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                b.id,
                f.feed,
                f.rule_types.as_ref().map(to_json).transpose()?,
                f.tier.unwrap_or(Tier::Hot).as_str(),
                i
            ],
        )?;
    }
    Ok(())
}

pub fn write_provider(tx: &Transaction<'_>, p: &LookupProviderDef) -> Result<()> {
    let s = &p.settings;
    tx.execute(
        "INSERT INTO lookup_providers(id, name, module, config_json, sync_timeout_ms, async_timeout_ms, fail_mode,
            retries, recheck_json, scope_json, cache_json, limits_json, breaker_json, async_max_attempts, category,
            cache_generation, preset_json, last_self_test_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, module = excluded.module,
            config_json = excluded.config_json, sync_timeout_ms = excluded.sync_timeout_ms,
            async_timeout_ms = excluded.async_timeout_ms, fail_mode = excluded.fail_mode, retries = excluded.retries,
            recheck_json = excluded.recheck_json, scope_json = excluded.scope_json, cache_json = excluded.cache_json,
            limits_json = excluded.limits_json, breaker_json = excluded.breaker_json,
            async_max_attempts = excluded.async_max_attempts, category = excluded.category,
            cache_generation = excluded.cache_generation, preset_json = excluded.preset_json",
        params![
            p.id,
            p.name,
            p.module,
            to_json(&p.config)?,
            i64::from(s.sync_timeout_ms),
            i64::from(s.async_timeout_ms),
            enum_str(&s.fail_mode),
            s.retries as i64,
            to_json(&s.recheck)?,
            to_json(&s.scope)?,
            to_json(&s.cache)?,
            to_json(&s.limits)?,
            to_json(&s.breaker)?,
            i64::from(s.async_max_attempts),
            p.category.as_str(),
            p.cache_generation,
            p.preset.as_ref().map(to_json).transpose()?,
            p.last_self_test.as_ref().map(to_json).transpose()?
        ],
    )?;
    Ok(())
}

/// Stores a manual feed's file as a blob and points `manual_files` at it. `version` is the
/// first 16 hex characters of the file's BLAKE3, so only a save that changes the file changes
/// it (providers.md §3).
pub fn write_manual_file(
    tx: &Transaction<'_>,
    data_dir: &Path,
    feed_id: &str,
    content: &[u8],
) -> Result<String> {
    let b3 = crate::blobs::put(tx, data_dir, crate::blobs::kind::MANUAL_FILE, content)?;
    let version = picket_api::ids::short_id(&b3).to_string();
    tx.execute(
        "INSERT INTO manual_files(feed_id, blob, version, saved_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(feed_id) DO UPDATE SET blob = excluded.blob, version = excluded.version, saved_at = excluded.saved_at",
        params![feed_id, b3, version, crate::feeds::manual::next_saved_at(tx, feed_id)?],
    )?;
    Ok(version)
}

/// True when the manual feed has a current file.
pub fn has_manual_file(conn: &Connection, feed_id: &str) -> Result<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM manual_files WHERE feed_id = ?1", [feed_id], |_| {
            Ok(())
        })
        .optional()?
        .is_some())
}

/// Reads a manual feed's current file.
pub fn read_manual_file(conn: &Connection, data_dir: &Path, feed_id: &str) -> Result<Option<Vec<u8>>> {
    let blob: Option<String> = conn
        .query_row(
            "SELECT blob FROM manual_files WHERE feed_id = ?1",
            [feed_id],
            |r| r.get(0),
        )
        .optional()?;
    match blob {
        Some(b) => crate::blobs::read(conn, data_dir, &b),
        None => Ok(None),
    }
}

fn delete_rows(tx: &Transaction<'_>, kind: EntityKind, id: &str) -> Result<()> {
    match kind {
        EntityKind::Edge => {
            tx.execute("DELETE FROM edges WHERE id = ?1", [id])?;
            tx.execute("DELETE FROM listener_edges WHERE edge_id = ?1", [id])?;
            tx.execute("DELETE FROM edge_status WHERE edge_id = ?1", [id])?;
            tx.execute("DELETE FROM edge_requests WHERE edge_id = ?1", [id])?;
            // storage.md §4: deleting an edge drops its pins.
            tx.execute("DELETE FROM edge_pins WHERE edge_id = ?1", [id])?;
            tx.execute("DELETE FROM edge_named WHERE edge_id = ?1", [id])?;
        }
        EntityKind::Listener => {
            tx.execute("DELETE FROM listeners WHERE id = ?1", [id])?;
            tx.execute("DELETE FROM listener_edges WHERE listener_id = ?1", [id])?;
        }
        EntityKind::Client => {
            tx.execute("DELETE FROM clients WHERE name = ?1", [id])?;
        }
        EntityKind::Profile => {
            tx.execute("DELETE FROM profiles WHERE id = ?1", [id])?;
        }
        EntityKind::Upstream => {
            tx.execute("DELETE FROM upstreams WHERE id = ?1", [id])?;
        }
        EntityKind::UpstreamGroup => {
            tx.execute("DELETE FROM upstream_groups WHERE id = ?1", [id])?;
        }
        EntityKind::ForwardZone => {
            tx.execute("DELETE FROM forward_zones WHERE id = ?1", [id])?;
        }
        EntityKind::FeedProvider => {
            tx.execute("DELETE FROM feed_providers WHERE id = ?1", [id])?;
            tx.execute("DELETE FROM feed_provider_state WHERE provider_id = ?1", [id])?;
        }
        EntityKind::Feed => {
            tx.execute("DELETE FROM feeds WHERE id = ?1", [id])?;
            tx.execute("DELETE FROM manual_files WHERE feed_id = ?1", [id])?;
            tx.execute("DELETE FROM feed_state WHERE feed_id = ?1", [id])?;
            // Its imports waiting for their runs go with it (feeds.md §4: bound to the feed they
            // were checked against), so nothing pins their blobs for retention (storage.md §4).
            tx.execute("DELETE FROM feed_imports WHERE feed_id = ?1", [id])?;
            // Its entries and runs are retired by a purge recorded with the deletion, so a feed
            // created again with this id starts clean (storage.md §4; `feeds::purge`).
            crate::feeds::purge::schedule_in(tx, id)?;
        }
        EntityKind::Bundle => {
            tx.execute("DELETE FROM bundles WHERE id = ?1", [id])?;
            tx.execute("DELETE FROM bundle_feeds WHERE bundle_id = ?1", [id])?;
        }
        EntityKind::LookupProvider => {
            // providers.md §4: deleting a provider deletes its queue items and verdicts.
            tx.execute("DELETE FROM lookup_providers WHERE id = ?1", [id])?;
            tx.execute("DELETE FROM lookup_queue WHERE provider_id = ?1", [id])?;
            tx.execute("DELETE FROM lookup_verdicts WHERE provider_id = ?1", [id])?;
            tx.execute("DELETE FROM lookup_blocks WHERE provider_id = ?1", [id])?;
        }
        EntityKind::Secret => {
            tx.execute("DELETE FROM secrets WHERE name = ?1", [id])?;
        }
        EntityKind::Settings => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Changes

/// Who made a change (for the journal).
#[derive(Clone, Debug, Default)]
pub struct Actor {
    /// `ui`, `cli`, `system`, …
    pub source: String,
    pub ip: Option<String>,
}

impl Actor {
    pub fn ui(ip: Option<String>) -> Self {
        Self {
            source: "ui".into(),
            ip,
        }
    }
    pub fn cli() -> Self {
        Self {
            source: "cli".into(),
            ip: None,
        }
    }
}

/// A change to one entity.
#[derive(Clone, Debug)]
pub enum Op {
    Create(Value),
    /// Replace the entity with this id by the body (read-only fields are kept).
    Update(String, Value),
    Delete(String),
}

/// What a change produced.
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct Outcome {
    pub id: String,
    /// The entity as stored (null after a delete).
    pub entity: Option<Value>,
    /// Warnings about the configuration after the change.
    pub warnings: Vec<Issue>,
    /// Feed provider saves: the feeds core created for files its `files` now selects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub feeds_added: Vec<String>,
    /// Feed provider saves: the feeds deleted because `files` or `exclude` stopped selecting
    /// them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub feeds_deleted: Vec<String>,
}

fn invalid(msg: impl Into<String>) -> CoreError {
    CoreError::Invalid(msg.into())
}

fn parse<T: DeserializeOwned>(kind: EntityKind, v: Value) -> CoreResult<T> {
    if !v.is_object() {
        return Err(invalid(format!("a {} must be a JSON object", kind.as_str())));
    }
    serde_json::from_value(v).map_err(|e| invalid(format!("invalid {}: {e}", kind.as_str())))
}

/// Takes the id from the path, checks the body doesn't name another.
fn take_id(kind: EntityKind, body_id: &str, path_id: &str) -> CoreResult<String> {
    if !body_id.is_empty() && body_id != path_id {
        return Err(invalid(format!(
            "a {} id never changes ({path_id:?} can't become {body_id:?}); create a new one instead",
            kind.as_str()
        )));
    }
    Ok(path_id.to_string())
}

/// What a save may do beyond the change itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SaveOpts {
    /// Lookup providers: **Clear cached verdicts on save** (providers.md §4).
    pub clear_cached_verdicts: Option<bool>,
    /// Feed providers: the admin confirmed deleting the feeds an edit to `files` or `exclude`
    /// stops selecting (feeds.md §1 "asks first, then deletes them").
    pub delete_unselected: bool,
}

/// Applies a change in `tx` and returns its outcome; the caller commits.
pub fn apply(
    tx: &Transaction<'_>,
    kind: EntityKind,
    op: Op,
    actor: &Actor,
    clear_cached_verdicts: Option<bool>,
) -> CoreResult<Outcome> {
    apply_with(
        tx,
        kind,
        op,
        actor,
        SaveOpts {
            clear_cached_verdicts,
            ..SaveOpts::default()
        },
    )
}

/// [`apply`] with every save option.
pub fn apply_with(
    tx: &Transaction<'_>,
    kind: EntityKind,
    op: Op,
    actor: &Actor,
    opts: SaveOpts,
) -> CoreResult<Outcome> {
    let before = load_model(tx)?;
    // Admission: a create past its kind's cap is refused before any work (README §2, Bounded).
    if matches!(op, Op::Create(_)) && before.count(kind) >= validate::max_entities(kind) {
        return Err(CoreError::Validation(vec![validate::too_many(kind)]));
    }
    let mut after = before.clone();
    let saves = !matches!(op, Op::Delete(_));
    // What a save converted on the way in, for the UI.
    let mut notes: Vec<String> = Vec::new();
    // A provider whose `exclude` a feed deletion extended (feeds.md §1).
    let mut excluded_by: Option<String> = None;
    // Feeds an edit of their provider's `files` or `exclude` stopped selecting, deleted with it.
    let mut unselected: Vec<String> = Vec::new();
    let id = match op {
        Op::Delete(id) => {
            if system::is_system(kind, &id)
                || (kind == EntityKind::FeedProvider
                    && before.feed_providers.get(&id).is_some_and(|p| p.system))
            {
                return Err(CoreError::Forbidden(format!(
                    "{} {id:?} is a system object: it can be edited but not deleted",
                    kind.as_str()
                )));
            }
            if before.entity_value(kind, &id).is_none() {
                return Err(CoreError::NotFound(format!("no {} {id:?}", kind.as_str())));
            }
            if kind == EntityKind::FeedProvider {
                // providers.md §2: a provider can't be deleted while a feed uses it.
                let feeds: Vec<&str> = before
                    .feeds
                    .values()
                    .filter(|f| f.provider.as_deref() == Some(id.as_str()))
                    .map(|f| f.id.as_str())
                    .collect();
                if !feeds.is_empty() {
                    return Err(CoreError::Conflict(format!(
                        "feed provider {id:?} still has feeds ({}); delete them first (Export keeps a feed's entries and dates)",
                        feeds.join(", ")
                    )));
                }
            }
            if kind == EntityKind::Feed
                && let Some(f) = before.feeds.get(&id)
                && let (Some(p), Some(file)) = (&f.provider, &f.file)
                && let Some(pd) = after.feed_providers.get_mut(p)
                && !pd
                    .exclude
                    .iter()
                    .any(|x| crate::modules::download::glob::matches(x, file))
            {
                // Deleting a provider feed adds its file to the provider's `exclude`, so it
                // doesn't come back (feeds.md §1): as a literal, which excludes no sibling.
                pd.exclude.push(crate::modules::download::glob::escape(file));
                excluded_by = Some(p.clone());
            }
            remove(&mut after, kind, &id);
            if kind == EntityKind::Feed {
                // feeds.md §1: deleting a feed that bundles take removes it from them (the UI
                // asks first, naming them).
                for b in after.bundles.values_mut() {
                    b.feeds.retain(|f| f.feed != id);
                }
            }
            if kind == EntityKind::Edge {
                // The listener assignment is a relation: deleting the edge drops it.
                for l in after.listeners.values_mut() {
                    l.edges.retain(|e| e != &id);
                }
            }
            id
        }
        Op::Create(body) => insert(
            &mut after,
            kind,
            body,
            None,
            opts.clear_cached_verdicts,
            &mut notes,
        )?,
        Op::Update(id, body) => {
            if before.entity_value(kind, &id).is_none() {
                return Err(CoreError::NotFound(format!("no {} {id:?}", kind.as_str())));
            }
            insert(
                &mut after,
                kind,
                body,
                Some(&id),
                opts.clear_cached_verdicts,
                &mut notes,
            )?
        }
    };
    if kind == EntityKind::FeedProvider && saves {
        unselected = crate::feeds::select::unselected(&after, &id);
        if !unselected.is_empty() {
            if !opts.delete_unselected {
                return Err(CoreError::Conflict(format!(
                    "this edit stops selecting feeds {}; they will be deleted: save again with delete_unselected=true to confirm",
                    unselected.join(", ")
                )));
            }
            for f in &unselected {
                if system::is_system(EntityKind::Feed, f) {
                    return Err(CoreError::Forbidden(format!("feed {f:?} is a system feed")));
                }
                after.feeds.remove(f);
                for b in after.bundles.values_mut() {
                    b.feeds.retain(|x| &x.feed != f);
                }
            }
        }
    }
    let mut errors = validate::new_errors(&validate::validate(&before), &validate::validate(&after));
    if saves {
        // A save of a provider that still holds a credential in clear is refused even when an
        // older release stored it (README §2 Secrets): it can't keep it or swap it for another.
        for i in validate::credential_issues(&after, kind, &id) {
            if !errors.contains(&i) {
                errors.push(i);
            }
        }
    }
    if !errors.is_empty() {
        return Err(CoreError::Validation(errors));
    }
    persist(tx, &before, &after, kind, &id)?;
    // Bundles a deleted feed left (feeds.md §1), journaled each.
    if matches!(kind, EntityKind::Feed | EntityKind::FeedProvider) {
        for (bid, b) in &after.bundles {
            if before.bundles.get(bid) != Some(b) {
                write_bundle(tx, b)?;
                journal::record(
                    tx,
                    actor.ip.as_deref(),
                    &actor.source,
                    EntityKind::Bundle,
                    bid,
                    &journal::diff(
                        before.entity_value(EntityKind::Bundle, bid).as_ref(),
                        after.entity_value(EntityKind::Bundle, bid).as_ref(),
                    ),
                )?;
            }
        }
    }
    for f in &unselected {
        delete_rows(tx, EntityKind::Feed, f)?;
        journal::record(
            tx,
            actor.ip.as_deref(),
            &actor.source,
            EntityKind::Feed,
            f,
            &serde_json::json!({"op": "delete", "by": "provider files no longer select it", "provider": id}),
        )?;
    }
    if let Some(p) = &excluded_by {
        write_feed_provider(tx, &after.feed_providers[p])?;
        journal::record(
            tx,
            actor.ip.as_deref(),
            &actor.source,
            EntityKind::FeedProvider,
            p,
            &journal::diff(
                before.entity_value(EntityKind::FeedProvider, p).as_ref(),
                after.entity_value(EntityKind::FeedProvider, p).as_ref(),
            ),
        )?;
    }
    let b = before.entity_value(kind, &id);
    let a = after.entity_value(kind, &id);
    journal::record(
        tx,
        actor.ip.as_deref(),
        &actor.source,
        kind,
        &id,
        &journal::diff(b.as_ref(), a.as_ref()),
    )?;
    // A provider save creates the feeds its `files` now select (feeds.md §1), journaled each.
    let mut feeds_added = Vec::new();
    let mut feeds_skipped = Vec::new();
    let mut feeds_over_limit = Vec::new();
    if kind == EntityKind::FeedProvider && saves {
        let applied = crate::feeds::select::apply_in(tx, &mut after, &id, None).map_err(CoreError::Other)?;
        feeds_added = applied.created;
        feeds_skipped = applied.skipped;
        feeds_over_limit = applied.capacity_skipped;
    }
    // A change that left fewer feeds makes room for files skipped for lack of it (feeds.md §1).
    crate::feeds::select::retry_capacity_in(tx, &mut after, before.count(EntityKind::Feed))
        .map_err(CoreError::Other)?;
    let mut warnings = warnings_for(&after, kind, &id);
    for n in notes {
        warnings.push(Issue {
            severity: Severity::Warning,
            entity: kind.as_str().into(),
            id: id.clone(),
            field: Some("config".into()),
            code: "converted".into(),
            message: n,
        });
    }
    if !feeds_skipped.is_empty() {
        warnings.push(Issue {
            severity: Severity::Warning,
            entity: kind.as_str().into(),
            id: id.clone(),
            field: Some("files".into()),
            code: "feed_cap".into(),
            message: format!(
                "the provider reached feeds.max_per_provider ({}); {} selected files got no feed",
                after.settings.feeds.max_per_provider,
                feeds_skipped.len()
            ),
        });
    }
    if !feeds_over_limit.is_empty() {
        warnings.push(Issue {
            severity: Severity::Warning,
            entity: kind.as_str().into(),
            id: id.clone(),
            field: Some("files".into()),
            code: "feed_limit".into(),
            message: format!(
                "the configuration holds as many feeds as it may ({}); {} selected files got no feed: delete feeds you don't use or select fewer files",
                validate::max_entities(EntityKind::Feed),
                feeds_over_limit.len()
            ),
        });
    }
    Ok(Outcome {
        warnings,
        entity: a.map(|v| for_ui(kind, v)),
        id,
        feeds_added,
        feeds_deleted: unselected,
    })
}

/// An entity as the UI API returns it: a credential written in clear in a provider config (an
/// older release's save; saves refuse them now) is masked (README §2 Secrets; security.md §4).
pub fn for_ui(kind: EntityKind, mut v: Value) -> Value {
    let fields: &[&str] = match kind {
        EntityKind::FeedProvider => &["config", "trigger"],
        EntityKind::LookupProvider => &["config", "preset"],
        _ => &[],
    };
    for f in fields {
        if let Some(x) = v.get_mut(*f) {
            *x = super::credentials::mask(x);
        }
    }
    v
}

/// One entity as the UI API returns it ([`for_ui`]).
pub fn entity_for_ui(m: &Model, kind: EntityKind, id: &str) -> Option<Value> {
    m.entity_value(kind, id).map(|v| for_ui(kind, v))
}

/// Refuses a model change that introduces errors.
pub fn check(before: &Model, after: &Model) -> CoreResult<()> {
    let new = validate::new_errors(&validate::validate(before), &validate::validate(after));
    if new.is_empty() {
        Ok(())
    } else {
        Err(CoreError::Validation(new))
    }
}

fn warnings_for(m: &Model, kind: EntityKind, id: &str) -> Vec<Issue> {
    validate::validate(m)
        .into_iter()
        .filter(|i| i.severity == Severity::Warning && i.entity == kind.as_str() && i.id == id)
        .collect()
}

fn remove(m: &mut Model, kind: EntityKind, id: &str) {
    match kind {
        EntityKind::Edge => drop(m.edges.remove(id)),
        EntityKind::Listener => drop(m.listeners.remove(id)),
        EntityKind::Client => m.clients.retain(|c| c.name != id),
        EntityKind::Profile => drop(m.profiles.remove(id)),
        EntityKind::Upstream => drop(m.upstreams.remove(id)),
        EntityKind::UpstreamGroup => drop(m.upstream_groups.remove(id)),
        EntityKind::ForwardZone => drop(m.forward_zones.remove(id)),
        EntityKind::FeedProvider => drop(m.feed_providers.remove(id)),
        EntityKind::Feed => drop(m.feeds.remove(id)),
        EntityKind::Bundle => drop(m.bundles.remove(id)),
        EntityKind::LookupProvider => drop(m.lookup_providers.remove(id)),
        EntityKind::Secret => drop(m.secrets.remove(id)),
        EntityKind::Settings => {}
    }
}

/// Creates (`path_id` None) or replaces an entity in the model; returns its id.
fn insert(
    m: &mut Model,
    kind: EntityKind,
    body: Value,
    path_id: Option<&str>,
    clear: Option<bool>,
    notes: &mut Vec<String>,
) -> CoreResult<String> {
    let creating = path_id.is_none();
    let exists = |m: &Model, id: &str| m.entity_value(kind, id).is_some();
    macro_rules! resolve_id {
        ($e:expr, $field:ident) => {{
            match path_id {
                Some(p) => $e.$field = take_id(kind, &$e.$field, p)?,
                None => {
                    if $e.$field.is_empty() {
                        return Err(invalid(format!("a new {} needs an id", kind.as_str())));
                    }
                    if exists(m, &$e.$field) {
                        return Err(CoreError::Conflict(format!(
                            "{} {:?} already exists",
                            kind.as_str(),
                            $e.$field
                        )));
                    }
                }
            }
            $e.$field.clone()
        }};
    }
    let id = match kind {
        EntityKind::Edge => {
            let mut e: EdgeDef = parse(kind, body)?;
            if creating && e.id.is_empty() {
                e.id = format!("e-{}", crate::util::random_hex(4));
            }
            let id = resolve_id!(e, id);
            e.created_at = match m.edges.get(&id) {
                Some(old) => old.created_at.clone(),
                None => Some(crate::util::now_ts()),
            };
            m.edges.insert(id.clone(), e);
            id
        }
        EntityKind::Listener => {
            let mut l: ListenerDef = parse(kind, body)?;
            let id = resolve_id!(l, id);
            l.edges.sort();
            l.edges.dedup();
            m.listeners.insert(id.clone(), l);
            id
        }
        EntityKind::Client => {
            let mut c: ClientDef = parse(kind, body)?;
            let id = resolve_id!(c, name);
            c.macs = c
                .macs
                .iter()
                .map(|x| crate::net::normalize_mac(x).unwrap_or_else(|| x.clone()))
                .collect();
            let old_pos = m.clients.iter().find(|x| x.name == id).and_then(|x| x.position);
            let next = m
                .clients
                .iter()
                .filter_map(|x| x.position)
                .max()
                .map_or(0, |p| p.saturating_add(1));
            c.position = Some(c.position.or(old_pos).unwrap_or(next));
            m.clients.retain(|x| x.name != id);
            m.clients.push(c);
            m.clients
                .sort_by(|a, b| a.position.cmp(&b.position).then(a.name.cmp(&b.name)));
            id
        }
        EntityKind::Profile => {
            let mut p: ProfileDef = parse(kind, body)?;
            let id = resolve_id!(p, id);
            p.system = system::is_system(kind, &id);
            m.profiles.insert(id.clone(), p);
            id
        }
        EntityKind::Upstream => {
            let mut u: UpstreamDef = parse(kind, body)?;
            let id = resolve_id!(u, id);
            m.upstreams.insert(id.clone(), u);
            id
        }
        EntityKind::UpstreamGroup => {
            let mut g: UpstreamGroupDef = parse(kind, body)?;
            let id = resolve_id!(g, id);
            m.upstream_groups.insert(id.clone(), g);
            id
        }
        EntityKind::ForwardZone => {
            let mut z: ForwardZoneDef = parse(kind, body)?;
            let id = resolve_id!(z, id);
            z.zone = z.zone.trim_end_matches('.').to_string();
            m.forward_zones.insert(id.clone(), z);
            id
        }
        EntityKind::FeedProvider => {
            let mut p: FeedProviderDef = parse(kind, body)?;
            let id = resolve_id!(p, id);
            p.system = system::is_system(kind, &id) || m.feed_providers.get(&id).is_some_and(|o| o.system);
            // The module's stored form of the config; a config it refuses is reported by
            // validation.
            if let Ok(n) = crate::modules::download::normalize(&p.module, &p.config)
                && n.config != p.config
            {
                p.config = n.config;
                notes.extend(n.notice);
            }
            m.feed_providers.insert(id.clone(), p);
            id
        }
        EntityKind::Feed => {
            let mut f: FeedDef = parse(kind, body)?;
            let id = resolve_id!(f, id);
            match m.feeds.get(&id) {
                None => {
                    // feeds.md §1: nobody adds a provider feed but its provider's `files`.
                    if f.provider.is_some() || f.file.is_some() {
                        return Err(invalid(
                            "a provider feed is added by its provider's files: add the file to the provider's files (or add it by URL); POST feeds creates manual feeds",
                        ));
                    }
                }
                Some(old) => {
                    // A feed's provider and file never change (feeds.md §1): kept as stored.
                    let other_provider = f.provider.is_some() && f.provider != old.provider;
                    let other_file = f.file.is_some() && f.file != old.file;
                    if other_provider || other_file {
                        return Err(invalid(
                            "a feed's provider and file never change; Export and Import carry its entries to another feed",
                        ));
                    }
                    f.provider = old.provider.clone();
                    f.file = old.file.clone();
                }
            }
            f.system = system::is_system(kind, &id);
            f.rule_policy = f.rule_policy.resolved(f.is_manual());
            m.feeds.insert(id.clone(), f);
            id
        }
        EntityKind::Bundle => {
            let mut b: BundleDef = parse(kind, body)?;
            let id = resolve_id!(b, id);
            b.system = system::is_system(kind, &id);
            // `hot` is the default tier; store it as unset so non-block bundles stay clean.
            for f in &mut b.feeds {
                if f.tier == Some(Tier::Hot) && b.action == BundleAction::Block {
                    f.tier = None;
                }
            }
            m.bundles.insert(id.clone(), b);
            id
        }
        EntityKind::LookupProvider => {
            let mut p: LookupProviderDef = parse(kind, body)?;
            let id = resolve_id!(p, id);
            match m.lookup_providers.get(&id) {
                None => p.cache_generation = picket_api::ids::new_id64(),
                Some(old) => {
                    // providers.md §4: **Clear cached verdicts on save**, ticked by default when
                    // the config changed; settings and secret edits keep the verdicts.
                    let clear = clear.unwrap_or(old.config != p.config);
                    p.cache_generation = if clear {
                        picket_api::ids::new_id64()
                    } else {
                        old.cache_generation.clone()
                    };
                    p.last_self_test = old.last_self_test.clone();
                }
            }
            m.lookup_providers.insert(id.clone(), p);
            id
        }
        EntityKind::Secret | EntityKind::Settings => {
            return Err(invalid("use the secrets or settings endpoints"));
        }
    };
    Ok(id)
}

/// Writes the rows of the changed entity (and of listeners an edge delete touched).
fn persist(tx: &Transaction<'_>, before: &Model, after: &Model, kind: EntityKind, id: &str) -> Result<()> {
    let gone = after.entity_value(kind, id).is_none();
    if gone {
        delete_rows(tx, kind, id)?;
        return Ok(());
    }
    match kind {
        EntityKind::Edge => {
            let e = &after.edges[id];
            write_edge(tx, e)?;
            // A registered (or replaced) key is no longer pending (core.md §4), in the same
            // transaction as the registration.
            tx.execute("DELETE FROM edge_pending WHERE key_sha256 = ?1", [&e.key])?;
        }
        EntityKind::Listener => write_listener(tx, &after.listeners[id])?,
        EntityKind::Client => {
            if let Some(c) = after.clients.iter().find(|c| c.name == id) {
                write_client(tx, c)?;
            }
        }
        EntityKind::Profile => write_profile(tx, &after.profiles[id])?,
        EntityKind::Upstream => write_upstream(tx, &after.upstreams[id])?,
        EntityKind::UpstreamGroup => write_group(tx, &after.upstream_groups[id])?,
        EntityKind::ForwardZone => write_zone(tx, &after.forward_zones[id])?,
        EntityKind::FeedProvider => persist_provider(tx, before, after, id)?,
        EntityKind::Feed => {
            write_feed(tx, &after.feeds[id])?;
            let created = !before.feeds.contains_key(id);
            if after.feeds[id].is_manual() && created {
                tx.execute("DELETE FROM manual_files WHERE feed_id = ?1", [id])?;
            }
            // A new source generation and model epoch for a new feed (one created again with a
            // deleted feed's id too), in this transaction: a check or run that started before
            // stores nothing it observed (`feeds::store::source_current`).
            if created {
                crate::feeds::store::new_source_gen(tx, id)?;
                tx.execute(
                    "UPDATE feed_state SET epoch_at = ?2 WHERE feed_id = ?1",
                    params![id, crate::util::now_ts()],
                )?;
            }
        }
        EntityKind::Bundle => write_bundle(tx, &after.bundles[id])?,
        EntityKind::LookupProvider => {
            let p = &after.lookup_providers[id];
            write_provider(tx, p)?;
            if let Some(old) = before.lookup_providers.get(id)
                && old.cache_generation != p.cache_generation
            {
                // A generation change deletes verdicts and tombstones alike (core.md §7), and the
                // Blocks kept for alerts (providers.md §4: an old generation is never used).
                tx.execute("DELETE FROM lookup_verdicts WHERE provider_id = ?1", [id])?;
                tx.execute("DELETE FROM lookup_blocks WHERE provider_id = ?1", [id])?;
            }
        }
        EntityKind::Secret | EntityKind::Settings => {}
    }
    Ok(())
}

/// Writes a feed provider and what its edit changes (feeds.md §3 "Editing a feed provider"): a
/// new `module` or `config` clears the `last` of the provider and of each of its feeds, gives
/// them new source generations and makes the provider due at once; one that points elsewhere
/// (the module's `epoch_key`) also starts a new model epoch for each feed and drops the listing.
/// An edit of `files` or `exclude` of a module that lists files, with no whole listing to apply
/// it to (one limited to the patterns, or none), resets the provider's state, so it lists again;
/// with one, any wait before listing again ends unless that listing is current
/// ([`crate::modules::download::DownloadModule::state_for_selection_edit`]).
fn persist_provider(tx: &Transaction<'_>, before: &Model, after: &Model, id: &str) -> Result<()> {
    let p = &after.feed_providers[id];
    write_feed_provider(tx, p)?;
    let old = before.feed_providers.get(id);
    let reg = crate::modules::download::builtin();
    let key = |d: &FeedProviderDef| {
        reg.get(&d.module)
            .map(|m| format!("{}|{}", d.module, m.epoch_key(&d.config)))
            .unwrap_or_default()
    };
    let created = old.is_none();
    let source_changed = old.is_some_and(|o| o.module != p.module || o.config != p.config);
    let elsewhere = old.is_some_and(|o| key(o) != key(p));
    if created || source_changed {
        crate::feeds::store::new_provider_source_gen(tx, id)?;
        tx.execute(
            "UPDATE feed_provider_state SET state_json = NULL, next_check_at = NULL, due_cause = ?2 WHERE provider_id = ?1",
            params![id, if created { "first" } else { "edit" }],
        )?;
        if elsewhere {
            // What the old source's listing selected and skipped goes with it: the new source's
            // first listing (or, for a provider that never lists, the selection right after)
            // decides them again, so no warning keeps the old source's files. The last `k` choice
            // replayed the old source's history.
            tx.execute(
                "UPDATE feed_provider_state SET listing_json = NULL, skipped_json = NULL,
                     capacity_skipped_json = NULL, k_choice_json = NULL
                 WHERE provider_id = ?1",
                [id],
            )?;
        }
        let now = crate::util::now_ts();
        for f in after.feeds.values().filter(|f| f.provider.as_deref() == Some(id)) {
            tx.execute(
                "UPDATE feed_state SET last_json = NULL, next_check_at = NULL WHERE feed_id = ?1",
                [&f.id],
            )?;
            crate::feeds::store::new_source_gen(tx, &f.id)?;
            if elsewhere {
                // A new model epoch (feed-scheduling.md §4): a fresh model, warm start and
                // seen_blake3; the staleness reference is dropped (§8).
                tx.execute(
                    "UPDATE feed_state SET epoch_at = ?2, seen_blake3 = NULL, stale_ref_json = NULL,
                        warm_started_at = NULL, warm_span_at = NULL, learner_json = NULL, next_ask_at = NULL
                     WHERE feed_id = ?1",
                    params![f.id, now],
                )?;
            }
        }
    }
    let selection_changed = old.is_some_and(|o| o.files != p.files || o.exclude != p.exclude);
    if created || source_changed || selection_changed {
        // A check listing for the old selection or source stores no provider state or listing
        // and adds no feeds (`feeds::store::provider_list_current`).
        crate::feeds::store::new_provider_list_gen(tx, id)?;
    }
    let module = reg.get(&p.module).filter(|m| m.lists_files());
    if selection_changed && let Some(m) = module {
        if crate::feeds::select::stored_listing(tx, id)?.is_none_or(|l| !l.whole) {
            // Without a whole listing to apply the new patterns to (one limited to the old ones,
            // or none: a walk that couldn't finish, whose retry delay lives in the state), list
            // again at once (feeds.md §3: `files` and `exclude` edits apply at once; providers.md
            // §2).
            tx.execute(
                "UPDATE feed_provider_state SET state_json = NULL, next_check_at = NULL, due_cause = 'edit' WHERE provider_id = ?1",
                [id],
            )?;
        } else {
            // A whole listing is kept, but a newer one that couldn't finish may be waiting for
            // its retry (an older head's listing beside a failed walk at the current head): the
            // module ends that wait, and the provider lists again at once, so the edit isn't
            // applied to an obsolete listing alone.
            let state: Option<String> = tx
                .query_row(
                    "SELECT state_json FROM feed_provider_state WHERE provider_id = ?1",
                    [id],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            let cleared = state
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|s| m.state_for_selection_edit(&s));
            if let Some(new) = cleared {
                tx.execute(
                    "UPDATE feed_provider_state SET state_json = ?2, next_check_at = NULL, due_cause = 'edit' WHERE provider_id = ?1",
                    params![id, serde_json::to_string(&new)?],
                )?;
            }
        }
    }
    Ok(())
}

/// Moves clients into the given order (every client named once).
pub fn reorder_clients(tx: &Transaction<'_>, names: &[String], actor: &Actor) -> CoreResult<()> {
    let before = load_model(tx)?;
    let mut current: Vec<&str> = before.clients.iter().map(|c| c.name.as_str()).collect();
    let mut wanted: Vec<&str> = names.iter().map(String::as_str).collect();
    current.sort_unstable();
    wanted.sort_unstable();
    if current != wanted {
        return Err(invalid("the order must name every client exactly once"));
    }
    for (i, n) in names.iter().enumerate() {
        tx.execute("UPDATE clients SET position = ?1 WHERE name = ?2", params![i, n])?;
    }
    journal::record(
        tx,
        actor.ip.as_deref(),
        &actor.source,
        EntityKind::Client,
        "*",
        &serde_json::json!({"op": "reorder", "order": names}),
    )?;
    Ok(())
}

/// Applies a settings patch (partial nested object; `null` resets a key).
pub fn apply_settings(
    tx: &Transaction<'_>,
    patch: &Value,
    actor: &Actor,
    allow_read_only: bool,
) -> CoreResult<crate::settings::Settings> {
    let before = load_model(tx)?;
    let (new, rows) = settings::apply_patch(&before.settings, patch, allow_read_only)
        .map_err(|e| invalid(format!("{e:#}")))?;
    let mut after = before.clone();
    after.settings = new.clone();
    check(&before, &after)?;
    settings::write_rows(tx, &rows).map_err(CoreError::Other)?;
    let b = serde_json::to_value(settings::flat(&before.settings)).ok();
    let a = serde_json::to_value(settings::flat(&new)).ok();
    journal::record(
        tx,
        actor.ip.as_deref(),
        &actor.source,
        EntityKind::Settings,
        "settings",
        &journal::diff(b.as_ref(), a.as_ref()),
    )?;
    Ok(new)
}

/// Sets a secret's value (write-only). The journal records that it changed, never the value.
pub fn set_secret(
    tx: &Transaction<'_>,
    key: Option<&SecretsKey>,
    name: &str,
    value: &str,
    actor: &Actor,
) -> CoreResult<()> {
    if !validate::is_slug(name) {
        return Err(invalid(format!(
            "{name:?} is not a valid secret name (1–64 of a-z, 0-9, - and _)"
        )));
    }
    if value.is_empty() {
        return Err(invalid(
            "a secret value can't be empty; delete the secret instead",
        ));
    }
    let sealed = secrets::seal(key, name, value).map_err(|e| invalid(format!("{e:#}")))?;
    let existed: bool = tx
        .query_row("SELECT 1 FROM secrets WHERE name = ?1", [name], |_| Ok(()))
        .optional()?
        .is_some();
    if !existed {
        let n: i64 = tx.query_row("SELECT count(*) FROM secrets", [], |r| r.get(0))?;
        if usize::try_from(n).unwrap_or(usize::MAX) >= validate::max_entities(EntityKind::Secret) {
            return Err(CoreError::Validation(vec![validate::too_many(
                EntityKind::Secret,
            )]));
        }
    }
    tx.execute(
        "INSERT INTO secrets(name, value_enc) VALUES (?1, ?2) ON CONFLICT(name) DO UPDATE SET value_enc = excluded.value_enc",
        params![name, sealed],
    )?;
    journal::record(
        tx,
        actor.ip.as_deref(),
        &actor.source,
        EntityKind::Secret,
        name,
        &serde_json::json!({"op": if existed { "update" } else { "create" }, "value": "<redacted>"}),
    )?;
    Ok(())
}

/// Deletes a secret; refused while a lookup provider or a feed references it.
pub fn delete_secret(tx: &Transaction<'_>, name: &str, actor: &Actor) -> CoreResult<()> {
    let m = load_model(tx)?;
    if !m.secrets.contains_key(name) {
        return Err(CoreError::NotFound(format!("no secret {name:?}")));
    }
    if let Some(p) = m
        .lookup_providers
        .values()
        .find(|p| p.secret_refs().iter().any(|r| r == name))
    {
        return Err(CoreError::Conflict(format!(
            "lookup provider {:?} references secret {name:?}",
            p.id
        )));
    }
    if let Some(p) = m
        .feed_providers
        .values()
        .find(|p| p.secret_refs().iter().any(|r| r == name))
    {
        return Err(CoreError::Conflict(format!(
            "feed provider {:?} references secret {name:?}",
            p.id
        )));
    }
    delete_rows(tx, EntityKind::Secret, name)?;
    journal::record(
        tx,
        actor.ip.as_deref(),
        &actor.source,
        EntityKind::Secret,
        name,
        &serde_json::json!({"op": "delete"}),
    )?;
    Ok(())
}

/// Lists entity values of `kind` as the UI API returns them ([`for_ui`]), in id order (clients
/// in position order).
pub fn list_values(m: &Model, kind: EntityKind) -> Vec<(String, Value)> {
    entity_values(m, kind)
        .into_iter()
        .map(|(id, v)| (id, for_ui(kind, v)))
        .collect()
}

fn entity_values(m: &Model, kind: EntityKind) -> Vec<(String, Value)> {
    fn vals<T: Serialize>(map: &BTreeMap<String, T>) -> Vec<(String, Value)> {
        map.iter()
            .filter_map(|(k, v)| serde_json::to_value(v).ok().map(|v| (k.clone(), v)))
            .collect()
    }
    match kind {
        EntityKind::Edge => vals(&m.edges),
        EntityKind::Listener => vals(&m.listeners),
        EntityKind::Client => m
            .clients
            .iter()
            .filter_map(|c| serde_json::to_value(c).ok().map(|v| (c.name.clone(), v)))
            .collect(),
        EntityKind::Profile => vals(&m.profiles),
        EntityKind::Upstream => vals(&m.upstreams),
        EntityKind::UpstreamGroup => vals(&m.upstream_groups),
        EntityKind::ForwardZone => vals(&m.forward_zones),
        EntityKind::FeedProvider => vals(&m.feed_providers),
        EntityKind::Feed => vals(&m.feeds),
        EntityKind::Bundle => vals(&m.bundles),
        EntityKind::LookupProvider => vals(&m.lookup_providers),
        EntityKind::Secret => vals(&m.secrets),
        EntityKind::Settings => vec![],
    }
}

/// Opens a connection and runs `f` in a transaction (CLI tools, tests).
pub fn with_tx<T>(conn: &mut Connection, f: impl FnOnce(&Transaction<'_>) -> CoreResult<T>) -> CoreResult<T> {
    let tx = conn.transaction().context("begin").map_err(CoreError::Other)?;
    let v = f(&tx)?;
    tx.commit()?;
    Ok(v)
}
