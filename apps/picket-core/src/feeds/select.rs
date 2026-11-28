//! Provider feeds (feeds.md §1 "Provider feeds"): which files a feed provider's `files` and
//! `exclude` select, the feeds core creates for selected files that have none, and the
//! `feed_added` review alerts.
//!
//! - **Selection:** for a module that lists files, each file of the provider's latest listing
//!   that matches a `files` glob and no `exclude` glob; for one that doesn't, each `files` path
//!   not excluded (the module's [`DownloadModule::default_files`] when `files` is empty).
//! - **New feeds** ([`apply_in`], in the caller's transaction: a provider save, or a check that
//!   listed files): id `<provider id>-<file>` ([`feed_id`]), name = the file, settings from the
//!   first matching entry's `feed`, enabled and in no bundle, a new source generation and model
//!   epoch. At most `feeds.max_per_provider` feeds per provider; the files skipped past the cap
//!   are kept in `feed_provider_state.skipped_json`. Never more feeds in all than the
//!   configuration's limit ([`validate::max_entities`] of feeds, the limit a restore enforces):
//!   the files skipped for lack of room are counted, with a bounded sample, in
//!   `feed_provider_state.capacity_skipped_json`, checked in the same transaction that creates
//!   the feeds, so concurrent provider saves and listings can't overshoot it together.
//! - **Capacity:** [`announce`] raises one `feed_limit_reached` warning per provider whose
//!   selected files got no feed for lack of room (the limit, the feeds in use, how many files
//!   were skipped and a sample), updates its details as they change without raising it again,
//!   and resolves it once none are skipped. Skipped files are reconsidered whenever the provider
//!   is saved or lists its files, and, for every provider with skipped files, as soon as a
//!   configuration change leaves fewer feeds ([`retry_capacity_in`], in that change's
//!   transaction).
//! - **Review:** each new feed is marked (`feed_state.added_pending`) in the same transaction,
//!   and [`announce`] raises its `feed_added` (and the provider's "skipped past the cap" alert)
//!   and clears the mark in one transaction, so a crash between the two loses no alert.
//!   [`resolve_reviewed`] resolves `feed_added` once the feed joins a bundle, is disabled or is
//!   deleted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::Result;
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::{Value, json};

use crate::alerts::{Changes as AlertChanges, RaiseSpec, Severity};
use crate::config::model::{EntityKind, FeedDef, FeedProviderDef, Model};
use crate::config::validate;
use crate::modules::download::{DownloadModule, Listing, glob};
use crate::state::SharedState;

/// The longest feed id (`config::validate::is_slug`).
const MAX_ID: usize = 64;

/// A selected file and the template of the `files` entry that selected it.
#[derive(Clone, Debug, PartialEq)]
pub struct Selected {
    pub file: String,
    pub template: Option<Value>,
}

/// The `files` entries in force: the provider's, or the module's defaults when it has none.
pub fn entries(p: &FeedProviderDef, m: &dyn DownloadModule) -> Vec<(String, Option<Value>)> {
    if p.files.is_empty() {
        m.default_files().into_iter().map(|(f, t)| (f, Some(t))).collect()
    } else {
        p.files
            .iter()
            .map(|f| (f.pattern.clone(), f.feed.clone()))
            .collect()
    }
}

/// True when an `exclude` glob matches `file`.
pub fn excluded(p: &FeedProviderDef, file: &str) -> bool {
    p.exclude.iter().any(|x| glob::matches(x, file))
}

/// The first entry whose pattern matches `file` (globs for a module that lists files, exact
/// paths otherwise), unless `file` is excluded.
pub fn selects(p: &FeedProviderDef, m: &dyn DownloadModule, file: &str) -> Option<Option<Value>> {
    if excluded(p, file) {
        return None;
    }
    entries(p, m).into_iter().find_map(|(pat, t)| {
        let hit = if m.lists_files() {
            glob::matches(&pat, file)
        } else {
            pat == file
        };
        hit.then_some(t)
    })
}

/// The files a provider selects now: from `listing` for a module that lists files (`None`
/// without one), from the declared paths otherwise.
pub fn selected(
    p: &FeedProviderDef,
    m: &dyn DownloadModule,
    listing: Option<&Listing>,
) -> Option<Vec<Selected>> {
    let files: Vec<String> = if m.lists_files() {
        // No file name is blank: a listing's blank path selects nothing.
        let mut v: Vec<String> = listing?
            .files
            .iter()
            .filter(|f| !f.trim().is_empty())
            .cloned()
            .collect();
        v.sort();
        v.dedup();
        v
    } else {
        let mut seen = BTreeSet::new();
        entries(p, m)
            .into_iter()
            .map(|(f, _)| f)
            .filter(|f| seen.insert(f.clone()))
            .collect()
    };
    Some(
        files
            .into_iter()
            .filter_map(|f| selects(p, m, &f).map(|template| Selected { file: f, template }))
            .collect(),
    )
}

/// An id from free text: lowercased, characters outside `a-z0-9` turned into `-` (one at a
/// time), at most 48 bytes; `fallback` when nothing is left.
pub fn slug(s: &str, fallback: &str) -> String {
    let mut out = String::new();
    for c in s.to_ascii_lowercase().chars() {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }
    let mut out = out.trim_matches('-').to_string();
    out.truncate(48);
    let out = out.trim_end_matches('-');
    if out.is_empty() {
        fallback.into()
    } else {
        out.into()
    }
}

/// The id and name of a new `http` provider for `url` (adding a feed by URL): from its host and
/// last path segment (percent-decoded for the name), e.g.
/// `iplists-firehol-org-firehol-level1-netset` and `firehol_level1.netset (iplists.firehol.org)`.
pub fn http_identity(url: &url::Url) -> (String, String) {
    let host = url.host_str().unwrap_or("http");
    let seg = url
        .path_segments()
        .and_then(|mut s| s.rfind(|x| !x.is_empty()))
        .unwrap_or_default();
    let shown = percent_encoding::percent_decode_str(seg).decode_utf8_lossy();
    let id = slug(&format!("{host}-{shown}"), "http");
    let name = if seg.is_empty() {
        display_name(host, None)
    } else {
        display_name(&shown, Some(host))
    };
    (id, name)
}

/// A display name (`config::validate::is_display_name`: 1–128 characters, no control
/// characters) of `base` and, in parentheses, `detail`: the base's head and the detail's tail
/// kept when it would be longer, cut on character boundaries; control characters dropped.
pub fn display_name(base: &str, detail: Option<&str>) -> String {
    const MAX: usize = crate::config::validate::MAX_NAME;
    let clean = |s: &str| -> Vec<char> { s.chars().filter(|c| !c.is_control()).collect() };
    let mut b = clean(base);
    if b.iter().all(|c| c.is_whitespace()) {
        b = "feed".chars().collect();
    }
    let Some(detail) = detail.map(clean).filter(|d| !d.is_empty()) else {
        b.truncate(MAX);
        return b.into_iter().collect();
    };
    if b.len() + 3 + detail.len() <= MAX {
        return format!(
            "{} ({})",
            b.into_iter().collect::<String>(),
            detail.into_iter().collect::<String>()
        );
    }
    // The base's head (at most half), the detail's tail in the rest: `base (…tail)`.
    let head = b.len().min(MAX / 2);
    if b.len() > head {
        b.truncate(head - 1);
        b.push('…');
    }
    let room = MAX - b.len() - 3;
    let d: String = if detail.len() <= room {
        detail.into_iter().collect()
    } else {
        std::iter::once('…')
            .chain(detail[detail.len() - (room - 1)..].iter().copied())
            .collect()
    };
    format!("{} ({d})", b.into_iter().collect::<String>())
}

/// `base`, or `base-2`, `base-3` … when taken; the base shortened first so the result stays an id
/// (`config::validate::is_slug`: at most 64 characters).
pub fn unique_id(base: &str, taken: &dyn Fn(&str) -> bool) -> String {
    let fit = |suffix: &str| {
        let b: String = base.chars().take(MAX_ID - suffix.len()).collect();
        format!("{}{suffix}", b.trim_end_matches('-'))
    };
    let first = fit("");
    if !taken(&first) {
        return first;
    }
    (2..10_000)
        .map(|n| fit(&format!("-{n}")))
        .find(|c| !taken(c))
        .unwrap_or_else(|| fit(&format!("-{}", crate::util::random_hex(4))))
}

/// The id and default name of a new feed of provider `p` for `file` (feeds.md §1): for a module
/// whose providers have one fixed file ([`DownloadModule::fixed_file`]), the provider's id and
/// name, or `None` when another feed has that id (validation refuses that, `id_taken`); else
/// `<provider id>-<file>` ([`feed_id`]) and the file.
pub fn new_feed_identity(
    p: &FeedProviderDef,
    m: &dyn DownloadModule,
    file: &str,
    taken: &dyn Fn(&str) -> bool,
) -> Option<(String, String)> {
    if m.fixed_file().is_some() {
        let name = if p.name.trim().is_empty() {
            p.id.clone()
        } else {
            p.name.clone()
        };
        (!taken(&p.id)).then_some((p.id.clone(), name))
    } else {
        Some((feed_id(&p.id, file, taken), file.to_string()))
    }
}

/// The id of a new feed for `file` (feeds.md §1): `<provider id>-<file>`, lowercased, the
/// extension dropped and other characters outside `a-z0-9` turned into `-`, with `-2`, `-3` …
/// when taken.
pub fn feed_id(provider: &str, file: &str, taken: &dyn Fn(&str) -> bool) -> String {
    let stem = match file.rsplit_once('/') {
        Some((dir, last)) => match last.rsplit_once('.') {
            Some((s, _)) if !s.is_empty() => format!("{dir}/{s}"),
            _ => file.to_string(),
        },
        None => match file.rsplit_once('.') {
            Some((s, _)) if !s.is_empty() => s.to_string(),
            _ => file.to_string(),
        },
    };
    let stem = stem.split('?').next().unwrap_or_default().to_string();
    let mut raw = format!("{provider}-{stem}").to_ascii_lowercase();
    raw = raw
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    let mut base = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c == '-' && base.ends_with('-') {
            continue;
        }
        base.push(c);
    }
    let mut base = base.trim_matches('-').to_string();
    if base.is_empty() {
        base = "feed".into();
    }
    // Room for a `-NNNN` suffix.
    base.truncate(MAX_ID - 6);
    unique_id(base.trim_end_matches('-'), taken)
}

/// The feed core creates for a selected file: defaults, then the template's settings; the
/// identity fields and `enabled` are core's. Its name is the template's `name` when the files
/// entry sets one (a preset names its feeds so, whenever a listing creates them), else `name`
/// ([`new_feed_identity`]: the provider's for a provider of one fixed file, else the file).
pub fn new_feed(
    id: &str,
    provider: &str,
    file: &str,
    name: &str,
    template: Option<&Value>,
) -> Result<FeedDef, String> {
    let mut v = serde_json::to_value(FeedDef::default()).map_err(|e| e.to_string())?;
    if let (Some(obj), Some(t)) = (v.as_object_mut(), template.and_then(Value::as_object)) {
        for (k, x) in t {
            obj.insert(k.clone(), x.clone());
        }
    }
    let mut f: FeedDef =
        serde_json::from_value(v).map_err(|e| format!("the files entry's feed settings are invalid: {e}"))?;
    f.id = id.to_string();
    let named = template
        .and_then(|t| t.get("name"))
        .and_then(Value::as_str)
        .is_some_and(|n| !n.trim().is_empty());
    if !named {
        f.name = name.to_string();
    }
    f.provider = Some(provider.to_string());
    f.file = Some(file.to_string());
    f.enabled = true;
    f.system = false;
    f.rule_policy = f.rule_policy.resolved(false);
    Ok(f)
}

/// Checks a `files` entry's `feed` template at save time (feeds.md §1: any feed setting;
/// `format` is required).
pub fn check_template(t: Option<&Value>) -> Result<(), String> {
    let Some(t) = t else {
        return Err("a files entry needs feed settings with at least a format".into());
    };
    let Some(o) = t.as_object() else {
        return Err("a files entry's feed must be an object of feed settings".into());
    };
    if !o.contains_key("format") {
        return Err("a files entry's feed settings need a format".into());
    }
    for k in ["id", "provider", "file", "system"] {
        if o.contains_key(k) {
            return Err(format!("a files entry's feed can't set {k} (core sets it)"));
        }
    }
    if let Some(n) = o.get("name")
        && !n.as_str().is_some_and(crate::config::validate::is_display_name)
    {
        return Err("a files entry's feed name must be 1–128 characters without control characters".into());
    }
    new_feed("x-y", "x", "y", "y", Some(t)).map(|_| ())
}

/// What applying the selection did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Applied {
    pub created: Vec<String>,
    /// Selected files left without a feed past `feeds.max_per_provider`.
    pub skipped: Vec<String>,
    /// Selected files left without a feed because the configuration holds as many feeds as it
    /// may ([`validate::max_entities`]).
    pub capacity_skipped: Vec<String>,
}

/// How many skipped file names `capacity_skipped_json` and the `feed_limit_reached` alert keep.
pub const CAPACITY_SAMPLE: usize = 20;

/// The files of a provider skipped for lack of room, as stored (`capacity_skipped_json`): how
/// many, and the first [`CAPACITY_SAMPLE`] of them.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CapacitySkipped {
    pub count: usize,
    pub sample: Vec<String>,
}

impl CapacitySkipped {
    fn of(files: &[String]) -> Self {
        Self {
            count: files.len(),
            sample: files.iter().take(CAPACITY_SAMPLE).cloned().collect(),
        }
    }
}

/// The provider's stored listing, without any empty or blank path (no file name is either).
pub fn stored_listing(tx: &rusqlite::Connection, provider: &str) -> rusqlite::Result<Option<Listing>> {
    let j: Option<Option<String>> = tx
        .query_row(
            "SELECT listing_json FROM feed_provider_state WHERE provider_id = ?1",
            [provider],
            |r| r.get(0),
        )
        .optional()?;
    Ok(j.flatten().and_then(|s| super::store::parse_listing(&s)))
}

/// Creates a feed for each selected file of `provider` that has none (feeds.md §1), within the
/// provider's cap and the configuration's feed limit, in `tx`, and journals each. `model` is the configuration after the save in progress
/// (or as stored, for a check's listing); `listing` the listing to apply (`None`: the stored one,
/// for a module that lists files). Returns what it created and skipped.
pub fn apply_in(
    tx: &Transaction<'_>,
    model: &mut Model,
    provider: &str,
    listing: Option<&Listing>,
) -> Result<Applied> {
    let Some(p) = model.feed_providers.get(provider).cloned() else {
        return Ok(Applied::default());
    };
    let Some(m) = crate::modules::download::builtin().get(&p.module) else {
        return Ok(Applied::default());
    };
    let stored;
    let listing = match listing {
        Some(l) => Some(l),
        None => {
            stored = stored_listing(tx, provider)?;
            stored.as_ref()
        }
    };
    let Some(sel) = selected(&p, m.as_ref(), listing) else {
        return Ok(Applied::default());
    };
    let have: BTreeSet<String> = model
        .feeds
        .values()
        .filter(|f| f.provider.as_deref() == Some(provider))
        .filter_map(|f| f.file.clone())
        .collect();
    let mut count = have.len();
    let cap = model.settings.feeds.max_per_provider as usize;
    // Every feed counts, manual ones and other providers' (the limit validation and a restore
    // enforce), counted in this transaction.
    let limit = validate::max_entities(EntityKind::Feed);
    let mut out = Applied::default();
    let now = crate::util::now_ts();
    for s in sel {
        if have.contains(&s.file) {
            continue;
        }
        if count >= cap {
            out.skipped.push(s.file);
            continue;
        }
        if model.count(EntityKind::Feed) >= limit {
            out.capacity_skipped.push(s.file);
            continue;
        }
        // A deleted feed's id is free again: its purge runs before the new feed's first check.
        let Some((id, name)) =
            new_feed_identity(&p, m.as_ref(), &s.file, &|c: &str| model.feeds.contains_key(c))
        else {
            tracing::warn!(provider = %provider, "no feed for the provider's one file: another feed has its id");
            continue;
        };
        let f = match new_feed(&id, provider, &s.file, &name, s.template.as_ref()) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(provider = %provider, file = %s.file, error = %e, "no feed for a selected file: its files entry's settings are invalid");
                continue;
            }
        };
        crate::config::store::write_feed(tx, &f)?;
        crate::feeds::store::new_source_gen(tx, &id)?;
        tx.execute(
            "UPDATE feed_state SET epoch_at = ?2, added_pending = 1 WHERE feed_id = ?1",
            params![id, now],
        )?;
        crate::config::journal::record(
            tx,
            None,
            "system",
            crate::config::EntityKind::Feed,
            &id,
            &json!({"op": "create", "by": "provider files", "provider": provider, "file": s.file}),
        )?;
        model.feeds.insert(id.clone(), f);
        out.created.push(id);
        count += 1;
    }
    tx.execute(
        "INSERT INTO feed_provider_state(provider_id) VALUES (?1) ON CONFLICT(provider_id) DO NOTHING",
        [provider],
    )?;
    tx.execute(
        "UPDATE feed_provider_state SET skipped_json = ?2, capacity_skipped_json = ?3 WHERE provider_id = ?1",
        params![
            provider,
            if out.skipped.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&out.skipped)?)
            },
            if out.capacity_skipped.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&CapacitySkipped::of(
                    &out.capacity_skipped,
                ))?)
            }
        ],
    )?;
    Ok(out)
}

/// The providers with selected files skipped for lack of room, in id order.
fn capacity_skipped_providers(tx: &rusqlite::Connection) -> rusqlite::Result<Vec<String>> {
    let mut st = tx.prepare(
        "SELECT provider_id FROM feed_provider_state WHERE capacity_skipped_json IS NOT NULL ORDER BY provider_id",
    )?;
    st.query_map([], |r| r.get(0))?.collect()
}

/// Reconsiders the files skipped for lack of room (feeds.md §1) once a change in `tx` left fewer
/// feeds than `before` had: each provider with skipped files, in id order, applies its selection
/// again ([`apply_in`]) with `model`, the configuration after the change, so the room goes to
/// them first come first served and the `feed_limit_reached` warning follows (resolved, or
/// updated, by the next [`announce`]). Returns the feeds it created.
pub fn retry_capacity_in(tx: &Transaction<'_>, model: &mut Model, before: usize) -> Result<Vec<String>> {
    if model.count(EntityKind::Feed) >= before {
        return Ok(Vec::new());
    }
    let mut created = Vec::new();
    for p in capacity_skipped_providers(tx)? {
        if model.count(EntityKind::Feed) >= validate::max_entities(EntityKind::Feed) {
            break;
        }
        created.extend(apply_in(tx, model, &p, None)?.created);
    }
    Ok(created)
}

/// The provider feeds a provider no longer selects (an edit to `files` or `exclude`): asked
/// about, then deleted (feeds.md §1).
pub fn unselected(model: &Model, provider: &str) -> Vec<String> {
    let Some(p) = model.feed_providers.get(provider) else {
        return vec![];
    };
    let Some(m) = crate::modules::download::builtin().get(&p.module) else {
        return vec![];
    };
    model
        .feeds
        .values()
        .filter(|f| f.provider.as_deref() == Some(provider))
        .filter(|f| {
            f.file
                .as_deref()
                .is_none_or(|file| selects(p, m.as_ref(), file).is_none())
        })
        .map(|f| f.id.clone())
        .collect()
}

/// Raises `feed_added` for each feed marked new and the provider alerts for files skipped past
/// the cap, clearing the marks in the same transaction.
pub async fn announce(state: &SharedState) {
    let alerts = state.alerts.clone();
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let pending: Vec<(String, String, Option<String>, Option<String>)> = {
                let mut st = tx.prepare(
                    "SELECT s.feed_id, f.name, f.provider_id, f.file FROM feed_state s JOIN feeds f ON f.id = s.feed_id
                     WHERE s.added_pending = 1 LIMIT 1000",
                )?;
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let mut ch = AlertChanges::default();
            for (feed, name, provider, file) in &pending {
                let spec = RaiseSpec::new(
                    "feed_added",
                    Severity::Info,
                    format!("feed_added:{feed}"),
                    format!("New feed {name}: review it for bundles"),
                    json!({"provider": provider, "file": file}),
                )
                .feed(feed.clone());
                let spec = match provider {
                    Some(p) => spec.feed_provider(p.clone()),
                    None => spec,
                };
                alerts.raise_in(&tx, &spec, &mut ch)?;
                tx.execute("UPDATE feed_state SET added_pending = 0 WHERE feed_id = ?1", [feed])?;
            }
            // Files skipped past the cap: one alert per provider, resolved once none are.
            let skipped: Vec<(String, Option<String>)> = {
                let mut st = tx.prepare("SELECT provider_id, skipped_json FROM feed_provider_state")?;
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for (p, s) in skipped {
                let key = format!("feed_added:provider:{p}");
                let files: Vec<String> = s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
                if files.is_empty() {
                    alerts.resolve_in(&tx, &key, Some(&json!({"by": "no file skipped"})), &mut ch)?;
                    continue;
                }
                // Raised again only when the skipped files change.
                let open: Option<String> = tx
                    .query_row(
                        "SELECT details_json FROM alerts WHERE dedupe_key = ?1 AND state = 'open'",
                        [&key],
                        |r| r.get(0),
                    )
                    .optional()?;
                let detail = json!({"skipped": files.iter().take(100).collect::<Vec<_>>(), "count": files.len()});
                if open.is_some_and(|d| serde_json::from_str::<Value>(&d).ok().as_ref() == Some(&detail)) {
                    continue;
                }
                let spec = RaiseSpec::new(
                    "feed_added",
                    Severity::Info,
                    key,
                    format!("Feed provider {p}: files not added past its feed cap"),
                    detail,
                )
                .feed_provider(p.clone());
                alerts.raise_in(&tx, &spec, &mut ch)?;
            }
            capacity_alerts(&alerts, &tx, &mut ch)?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await;
    match r {
        Ok(ch) => state.alerts.announce(ch),
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "cannot raise the new feeds' alerts"),
    }
}

/// The dedupe key of a provider's `feed_limit_reached` warning.
pub fn capacity_key(provider: &str) -> String {
    format!("feed_limit_reached:{provider}")
}

/// Raises, updates or resolves each provider's `feed_limit_reached` warning in `tx` (module
/// docs): raised when its files are first skipped for lack of room (or again after it was
/// resolved), its details replaced in place while they change (no new raise, so no repeated
/// notification), resolved once none are skipped or the provider is gone.
fn capacity_alerts(
    alerts: &crate::alerts::Alerts,
    tx: &Transaction<'_>,
    ch: &mut AlertChanges,
) -> Result<()> {
    let limit = validate::max_entities(EntityKind::Feed);
    let in_use: i64 = tx.query_row("SELECT count(*) FROM feeds", [], |r| r.get(0))?;
    let rows: Vec<(String, String)> = {
        let mut st = tx.prepare(
            "SELECT provider_id, capacity_skipped_json FROM feed_provider_state
             WHERE capacity_skipped_json IS NOT NULL ORDER BY provider_id",
        )?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut skipping = BTreeSet::new();
    for (p, j) in rows {
        let Some(s) = serde_json::from_str::<CapacitySkipped>(&j)
            .ok()
            .filter(|s| s.count > 0)
        else {
            continue;
        };
        let key = capacity_key(&p);
        skipping.insert(key.clone());
        let detail = json!({
            "provider": p,
            "limit": limit,
            "feeds": in_use,
            "skipped": s.count,
            "files": s.sample,
            "guidance": "Every feed counts toward the limit, manual ones and other providers' too. Delete feeds you don't use, or narrow this provider's files or exclude; its skipped files get feeds as soon as there is room.",
        });
        let open: Option<String> = tx
            .query_row(
                "SELECT details_json FROM alerts WHERE dedupe_key = ?1 AND state = 'open'",
                [&key],
                |r| r.get(0),
            )
            .optional()?;
        match open {
            Some(d) if serde_json::from_str::<Value>(&d).ok().as_ref() == Some(&detail) => {}
            Some(_) => {
                alerts.update_details_in(tx, &key, &detail, &[], ch)?;
            }
            None => {
                let spec = RaiseSpec::new(
                    "feed_limit_reached",
                    Severity::Warning,
                    key,
                    format!(
                        "Feed provider {p}: {} selected files got no feed, the configuration's feed limit ({limit}) is reached",
                        s.count
                    ),
                    detail,
                )
                .feed_provider(p.clone());
                alerts.raise_in(tx, &spec, ch)?;
            }
        }
    }
    let open: Vec<String> = {
        let mut st =
            tx.prepare("SELECT dedupe_key FROM alerts WHERE kind = 'feed_limit_reached' AND state = 'open'")?;
        st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
    };
    for key in open.into_iter().filter(|k| !skipping.contains(k)) {
        alerts.resolve_in(
            tx,
            &key,
            Some(&json!({"by": "no selected file skipped for lack of room"})),
            ch,
        )?;
    }
    Ok(())
}

/// Resolves `feed_added` for feeds that joined a bundle, were disabled or deleted (core.md §9).
pub async fn resolve_reviewed(state: &SharedState) {
    let alerts = state.alerts.clone();
    let r = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            let open: Vec<(String, String)> = {
                let mut st = tx.prepare(
                    "SELECT a.dedupe_key, a.feed_id FROM alerts a WHERE a.kind = 'feed_added' AND a.state = 'open'
                       AND a.feed_id IS NOT NULL",
                )?;
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let mut ch = AlertChanges::default();
            for (key, feed) in open {
                let row: Option<(i64, i64)> = tx
                    .query_row(
                        "SELECT f.enabled, EXISTS (SELECT 1 FROM bundle_feeds b WHERE b.feed_id = f.id) FROM feeds f WHERE f.id = ?1",
                        [&feed],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let by = match row {
                    None => Some("feed deleted"),
                    Some((0, _)) => Some("feed disabled"),
                    Some((_, 1)) => Some("feed joined a bundle"),
                    _ => None,
                };
                if let Some(by) = by {
                    alerts.resolve_in(&tx, &key, Some(&json!({"by": by})), &mut ch)?;
                }
            }
            tx.commit()?;
            alerts.committed(&ch);
            Ok::<_, anyhow::Error>(ch)
        })
        .await;
    match r {
        Ok(ch) => state.alerts.announce(ch),
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "cannot resolve reviewed feeds' alerts"),
    }
}

/// Each provider's location (its module's `location()`), worked out once for a whole model, so
/// the save warning for providers that cover the same files (providers.md §2) costs one
/// location per provider, not one per pair (an `http` location parses and normalises a URL).
pub struct Overlaps<'a> {
    /// Providers of a module with one fixed file (one URL each), by module and exact location:
    /// they overlap another of the same URL only.
    exact: BTreeMap<(&'a str, String), Vec<&'a str>>,
    /// The others, by module: id and location, lowercase, for [`covers`].
    prefix: BTreeMap<&'a str, Vec<(&'a str, String)>>,
    /// Each provider's location as kept above, and whether it is in `exact`.
    by_id: BTreeMap<&'a str, (String, bool)>,
}

impl<'a> Overlaps<'a> {
    /// The locations of `model`'s providers of the built-in modules.
    pub fn new(model: &'a Model) -> Self {
        let reg = crate::modules::download::builtin();
        Self::with(model, |p| {
            reg.get(&p.module)
                .map(|m| (m.location(&p.config), m.fixed_file().is_some()))
        })
    }

    /// [`Overlaps::new`] with the location (and whether the module has one fixed file) of each
    /// provider from `locate`, called once per provider; `None` for a module core doesn't have.
    pub fn with(
        model: &'a Model,
        mut locate: impl FnMut(&FeedProviderDef) -> Option<(String, bool)>,
    ) -> Self {
        let mut out = Self {
            exact: BTreeMap::new(),
            prefix: BTreeMap::new(),
            by_id: BTreeMap::new(),
        };
        // In id order (the model's), so each warning names the others in id order.
        for p in model.feed_providers.values() {
            let Some((loc, exact)) = locate(p) else { continue };
            if loc.is_empty() {
                continue;
            }
            let loc = if exact { loc } else { loc.to_ascii_lowercase() };
            out.by_id.insert(p.id.as_str(), (loc.clone(), exact));
            if exact {
                out.exact
                    .entry((p.module.as_str(), loc))
                    .or_default()
                    .push(p.id.as_str());
            } else {
                out.prefix
                    .entry(p.module.as_str())
                    .or_default()
                    .push((p.id.as_str(), loc));
            }
        }
        out
    }

    /// The providers of `p`'s module that cover the same files as `p` (equal locations, or one
    /// directory-like location inside the other), in id order, without `p`.
    pub fn of(&self, p: &FeedProviderDef) -> Vec<&'a str> {
        let others =
            |ids: &[&'a str]| -> Vec<&'a str> { ids.iter().copied().filter(|id| *id != p.id).collect() };
        match self.by_id.get(p.id.as_str()) {
            None => vec![],
            Some((loc, true)) => self
                .exact
                .get(&(p.module.as_str(), loc.clone()))
                .map(|ids| others(ids.as_slice()))
                .unwrap_or_default(),
            Some((loc, false)) => self
                .prefix
                .get(p.module.as_str())
                .map(|peers| {
                    peers
                        .iter()
                        .filter(|(id, ol)| *id != p.id && covers(loc, ol))
                        .map(|(id, _)| *id)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// `a` and `b` (lowercase) are equal, or one ends in `/` and holds the other.
fn covers(a: &str, b: &str) -> bool {
    a == b || (a.ends_with('/') && b.starts_with(a)) || (b.ends_with('/') && a.starts_with(b))
}

/// A provider's files as the UI shows them (`GET feed-providers/{id}/listing`, core.md §12 Feed
/// providers page): each file of its stored listing (without one, for a module that lists no
/// files, each declared path) and each file a feed of the provider reads, once each. Built from
/// the stored listing and the configuration only (no module call): every entry, up to the
/// listing's own bound (`github::MAX_WALK_ENTRIES`), with no cap here; the endpoint's paging
/// bounds each answer (api.md §7). Listed with S3 ListObjectsV2 semantics over the flat paths
/// ([`FilesView::list`]); whether `files` selects a file, and its feed, are worked out per row
/// ([`FilesView::row`]), for one page's rows only.
pub struct FilesView<'a> {
    p: &'a FeedProviderDef,
    module: Option<Arc<dyn DownloadModule>>,
    by_file: BTreeMap<&'a str, &'a str>,
    /// Every file, once, in key (byte) order.
    files: Vec<String>,
}

/// An entry of a listing ([`FilesView::list`]).
#[derive(Clone, Debug, PartialEq)]
pub enum Entry<'v> {
    /// A common prefix (a folder, ending in `/`): the files under it at any depth, and how many
    /// of those a feed reads.
    Prefix {
        prefix: &'v str,
        files: usize,
        feeds: usize,
    },
    /// A file, by its whole path.
    File(&'v str),
}

impl Entry<'_> {
    /// Its key: the prefix or the path, the order a listing comes and pages in.
    pub fn key(&self) -> &str {
        match self {
            Self::Prefix { prefix, .. } => prefix,
            Self::File(path) => path,
        }
    }
}

impl<'a> FilesView<'a> {
    /// The files of `p` (none for a module core doesn't have).
    pub fn new(model: &'a Model, p: &'a FeedProviderDef, listing: Option<Listing>) -> Self {
        let module = crate::modules::download::builtin().get(&p.module);
        let by_file: BTreeMap<&str, &str> = model
            .feeds
            .values()
            .filter(|f| f.provider.as_deref() == Some(p.id.as_str()))
            .filter_map(|f| f.file.as_deref().map(|file| (file, f.id.as_str())))
            .collect();
        let mut files: Vec<String> = match (&module, listing) {
            (None, _) => Vec::new(),
            (Some(_), Some(l)) => l.files,
            (Some(m), None) if !m.lists_files() => {
                entries(p, m.as_ref()).into_iter().map(|(f, _)| f).collect()
            }
            (Some(_), None) => Vec::new(),
        };
        if module.is_some() {
            files.extend(by_file.keys().map(|f| f.to_string()));
        }
        files.sort_unstable();
        files.dedup();
        Self {
            p,
            module,
            by_file,
            files,
        }
    }

    /// The files whose path starts with `prefix`, in key order. With `delimiter` (`/`), as S3
    /// ListObjectsV2 groups them: a file with a `/` after the prefix rolls up into its common
    /// prefix (the prefix up to and including that `/`), which stands once, at its own key's
    /// place, with the files under it and how many of those are feeds. A file's keys sort
    /// together, so each common prefix's files are one run of the sorted paths: one pass, no
    /// copies.
    pub fn list(&self, prefix: &str, delimiter: bool) -> Vec<Entry<'_>> {
        let mut out: Vec<Entry<'_>> = Vec::new();
        let start = self.files.partition_point(|f| f.as_str() < prefix);
        for path in self.files[start..].iter().take_while(|f| f.starts_with(prefix)) {
            let common = delimiter
                .then(|| path[prefix.len()..].find('/'))
                .flatten()
                .map(|i| &path[..prefix.len() + i + 1]);
            let Some(common) = common else {
                out.push(Entry::File(path));
                continue;
            };
            let feed = usize::from(self.by_file.contains_key(path.as_str()));
            match out.last_mut() {
                Some(Entry::Prefix {
                    prefix: p,
                    files,
                    feeds,
                }) if *p == common => {
                    *files += 1;
                    *feeds += feed;
                }
                _ => out.push(Entry::Prefix {
                    prefix: common,
                    files: 1,
                    feeds: feed,
                }),
            }
        }
        out
    }

    /// The files whose path starts with `prefix` and holds `needle`, case-insensitively, in key
    /// order (no grouping). Both sides are lowercased a character at a time (Unicode's mapping,
    /// [`char::to_lowercase`]), the same for either, so `éCOLE` finds `École.txt`.
    pub fn search(&self, prefix: &str, needle: &str) -> Vec<&str> {
        let needle: String = needle.chars().flat_map(char::to_lowercase).collect();
        // One buffer for every path's lowercase copy; `contains` is linear in both.
        let mut lower = String::new();
        let start = self.files.partition_point(|f| f.as_str() < prefix);
        self.files[start..]
            .iter()
            .take_while(|f| f.starts_with(prefix))
            .filter(|path| {
                lower.clear();
                lower.extend(path.chars().flat_map(char::to_lowercase));
                lower.contains(needle.as_str())
            })
            .map(String::as_str)
            .collect()
    }

    /// Whether `files` selects `file` (minus `exclude`), and the feed that reads it: none means
    /// **Add as feed**.
    pub fn row(&self, file: &str) -> (bool, Option<String>) {
        let selected = self
            .module
            .as_ref()
            .is_some_and(|m| selects(self.p, m.as_ref(), file).is_some());
        (selected, self.by_file.get(file).map(|f| f.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::FileSelect;

    #[test]
    fn feed_ids() {
        let none = |_: &str| false;
        assert_eq!(feed_id("hagezi", "adblock/tif.txt", &none), "hagezi-adblock-tif");
        assert_eq!(feed_id("p", "list.txt", &none), "p-list");
        assert_eq!(feed_id("p", "Weird Name!!.TXT", &none), "p-weird-name");
        assert_eq!(
            feed_id("am", "community-threat-1000", &none),
            "am-community-threat-1000"
        );
        assert_eq!(feed_id("p", "a.b/c", &none), "p-a-b-c");
        assert_eq!(feed_id("p", "list.txt?x=1", &none), "p-list");
        let taken = |c: &str| c == "p-list" || c == "p-list-2";
        assert_eq!(feed_id("p", "list.txt", &taken), "p-list-3");
        let long = "x".repeat(200);
        let id = feed_id("p", &long, &none);
        assert!(id.len() <= 64 && crate::config::validate::is_slug(&id), "{id}");
    }

    #[test]
    fn selection_globs_paths_and_exclude() {
        let gh = crate::modules::download::builtin().get("github").unwrap();
        let p = FeedProviderDef {
            id: "hagezi".into(),
            module: "github".into(),
            files: vec![FileSelect {
                pattern: "adblock/*.txt".into(),
                feed: Some(json!({"format": "adblock"})),
            }],
            exclude: vec!["adblock/*-onlydomains.txt".into()],
            ..Default::default()
        };
        let l = Listing {
            files: vec![
                "adblock/tif.txt".into(),
                "adblock/pro-onlydomains.txt".into(),
                "hosts/tif.txt".into(),
                "adblock/ultimate.txt".into(),
            ],
            whole: true,
        };
        let s = selected(&p, gh.as_ref(), Some(&l)).unwrap();
        let files: Vec<&str> = s.iter().map(|x| x.file.as_str()).collect();
        assert_eq!(files, vec!["adblock/tif.txt", "adblock/ultimate.txt"]);
        // A listing's blank path is no file: `**` selects it not.
        let all = FeedProviderDef {
            files: vec![FileSelect {
                pattern: "**".into(),
                feed: Some(json!({"format": "plain"})),
            }],
            exclude: vec![],
            ..p.clone()
        };
        let blank = Listing {
            files: vec![" ".into(), "".into(), "a.txt".into()],
            whole: true,
        };
        let s = selected(&all, gh.as_ref(), Some(&blank)).unwrap();
        assert_eq!(s.iter().map(|x| x.file.as_str()).collect::<Vec<_>>(), ["a.txt"]);
        assert!(selected(&p, gh.as_ref(), None).is_none(), "globs need a listing");

        // An http provider is one URL: its one file, `response` (by default, or as `files` names
        // it), unless excluded.
        let http = crate::modules::download::builtin().get("http").unwrap();
        let mut h = FeedProviderDef {
            id: "lists".into(),
            module: "http".into(),
            config: json!({"url": "https://x.example/a.txt"}),
            ..Default::default()
        };
        let s = selected(&h, http.as_ref(), None).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].file, "response");
        assert_eq!(s[0].template, Some(json!({"format": "adblock"})));
        h.files = vec![FileSelect {
            pattern: "response".into(),
            feed: Some(json!({"format": "hosts"})),
        }];
        let s = selected(&h, http.as_ref(), None).unwrap();
        assert_eq!(s[0].template, Some(json!({"format": "hosts"})));
        h.exclude = vec!["response".into()];
        assert!(selected(&h, http.as_ref(), None).unwrap().is_empty());

        let am = crate::modules::download::builtin()
            .get("alphamountain_threat_1000")
            .unwrap();
        let a = FeedProviderDef {
            id: "am".into(),
            module: "alphamountain_threat_1000".into(),
            ..Default::default()
        };
        let s = selected(&a, am.as_ref(), None).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].file, "community-threat-1000");
        assert_eq!(s[0].template, Some(json!({"format": "plain"})));
    }

    #[test]
    fn templates_and_new_feeds() {
        assert!(check_template(Some(&json!({"format": "adblock", "category": "security"}))).is_ok());
        // A template's name is a display name.
        assert!(check_template(Some(&json!({"format": "plain", "name": "Readable"}))).is_ok());
        for bad in [json!("x".repeat(129)), json!("a\u{1}b"), json!(" "), json!(7)] {
            assert!(
                check_template(Some(&json!({"format": "plain", "name": bad}))).is_err(),
                "{bad}"
            );
        }
        assert!(check_template(Some(&json!({"category": "security"}))).is_err());
        assert!(check_template(Some(&json!({"format": "nope"}))).is_err());
        assert!(check_template(Some(&json!({"format": "plain", "id": "x"}))).is_err());
        assert!(check_template(None).is_err());
        let f = new_feed(
            "p-a",
            "p",
            "a.txt",
            "a.txt",
            Some(&json!({"format": "plain", "enabled": false, "category": "security"})),
        )
        .unwrap();
        assert!(f.enabled, "a new feed is enabled");
        assert_eq!(f.name, "a.txt");
        // A files entry may name its feeds (a preset's do).
        let named = new_feed(
            "p-a",
            "p",
            "a.txt",
            "a.txt",
            Some(&json!({"format": "plain", "name": "Readable"})),
        )
        .unwrap();
        assert_eq!(named.name, "Readable");
        let blank = new_feed(
            "p-a",
            "p",
            "a.txt",
            "a.txt",
            Some(&json!({"format": "plain", "name": " "})),
        )
        .unwrap();
        assert_eq!(blank.name, "a.txt");
        assert_eq!(f.provider.as_deref(), Some("p"));
        assert_eq!(f.category, crate::config::model::Category::Security);
    }

    /// The listing page (`GET feed-providers/{id}/listing`): the listing and the provider's feeds'
    /// files, once each, listed like S3 ListObjectsV2 (common prefixes with file and feed counts,
    /// merged with the files in key order), or searched case-insensitively (Unicode).
    #[test]
    fn files_view_lists_like_s3_and_searches() {
        let mut model = Model::default();
        for (id, provider, file) in [
            ("hz-x", "hz", "z/feed-only.txt"),
            ("hz-b", "hz", "b/B.txt"),
            ("hz-deep", "hz", "a/x/deep.txt"),
            ("other-a", "other", "a/1.txt"),
        ] {
            let f = new_feed(id, provider, file, file, Some(&json!({"format": "plain"}))).unwrap();
            model.feeds.insert(id.into(), f);
        }
        let p = FeedProviderDef {
            id: "hz".into(),
            module: "github".into(),
            files: vec![FileSelect {
                pattern: "b/*.txt".into(),
                feed: Some(json!({"format": "plain"})),
            }],
            exclude: vec!["b/skip.txt".into()],
            ..Default::default()
        };
        let listing = || Listing {
            files: [
                "b/B.txt",
                "a/1.txt",
                "b/skip.txt",
                "b/B.txt",
                "Hosts/x.txt",
                "a/x/deep.txt",
                "a/x/y/z.txt",
                "root.txt",
                "a.txt",
            ]
            .map(String::from)
            .to_vec(),
            whole: true,
        };
        let pre = |prefix, files, feeds| Entry::Prefix { prefix, files, feeds };
        let v = FilesView::new(&model, &p, Some(listing()));
        assert_eq!(
            v.list("", true),
            [
                pre("Hosts/", 1, 0),
                Entry::File("a.txt"),
                pre("a/", 3, 1),
                pre("b/", 2, 1),
                Entry::File("root.txt"),
                pre("z/", 1, 1),
            ],
            "key order: `a.txt` before `a/`"
        );
        assert_eq!(v.list("a/", true), [Entry::File("a/1.txt"), pre("a/x/", 2, 1)]);
        assert_eq!(
            v.list("a/x/", true),
            [Entry::File("a/x/deep.txt"), pre("a/x/y/", 1, 0)]
        );
        assert_eq!(
            v.list("a/", false),
            [
                Entry::File("a/1.txt"),
                Entry::File("a/x/deep.txt"),
                Entry::File("a/x/y/z.txt")
            ],
            "no delimiter: every file under the prefix"
        );
        assert_eq!(
            v.list("a", true),
            [Entry::File("a.txt"), pre("a/", 3, 1)],
            "any prefix, as S3"
        );
        assert!(v.list("nope/", true).is_empty());
        assert_eq!(v.search("", "B.TXT"), ["b/B.txt"]);
        let mut accents = model.clone();
        let f = new_feed(
            "hz-e",
            "hz",
            "docs/École.txt",
            "docs/École.txt",
            Some(&json!({"format": "plain"})),
        )
        .unwrap();
        accents.feeds.insert("hz-e".into(), f);
        let e = FilesView::new(&accents, &p, Some(listing()));
        assert_eq!(e.search("", "éCOLE"), ["docs/École.txt"], "Unicode lowercase");
        assert_eq!(e.search("docs/", "ÉCOLE.TXT"), ["docs/École.txt"]);
        assert_eq!(v.search("a/", "TXT"), ["a/1.txt", "a/x/deep.txt", "a/x/y/z.txt"]);
        assert!(v.search("b/", "z").is_empty());
        assert_eq!(v.row("b/B.txt"), (true, Some("hz-b".into())));
        assert_eq!(v.row("b/skip.txt"), (false, None), "excluded");
        assert_eq!(v.row("a/1.txt"), (false, None), "another provider's feed");
        assert_eq!(v.row("z/feed-only.txt"), (false, Some("hz-x".into())));
        let v = FilesView::new(&model, &p, None);
        assert_eq!(
            v.list("", false),
            [
                Entry::File("a/x/deep.txt"),
                Entry::File("b/B.txt"),
                Entry::File("z/feed-only.txt")
            ],
            "no listing yet: the feeds' files"
        );
        let gone = FeedProviderDef {
            module: "nope".into(),
            ..p.clone()
        };
        assert!(
            FilesView::new(&model, &gone, Some(listing()))
                .list("", true)
                .is_empty()
        );
        let h = FeedProviderDef {
            id: "lists".into(),
            module: "http".into(),
            config: json!({"url": "https://x.example/a.txt"}),
            ..Default::default()
        };
        let v = FilesView::new(&model, &h, None);
        assert_eq!(v.list("", true), [Entry::File("response")], "declared files: one");
        assert_eq!(v.row("response"), (true, None));
    }

    /// feeds.md §1: a module whose providers have one fixed file gives its feed the provider's
    /// id and name; others `<provider id>-<file>` and the file.
    #[test]
    fn single_file_feeds_take_the_providers_id_and_name() {
        let reg = crate::modules::download::builtin();
        let p = |module: &str| FeedProviderDef {
            id: "fh".into(),
            name: "FireHOL level 1".into(),
            module: module.into(),
            ..Default::default()
        };
        let none = |_: &str| false;
        for module in ["http", "alphamountain_threat_1000"] {
            let m = reg.get(module).unwrap();
            let file = m.fixed_file().unwrap();
            assert_eq!(
                new_feed_identity(&p(module), m.as_ref(), file, &none),
                Some(("fh".to_string(), "FireHOL level 1".to_string())),
                "{module}"
            );
        }
        let gh = reg.get("github").unwrap();
        assert_eq!(
            new_feed_identity(&p("github"), gh.as_ref(), "a/b.txt", &none),
            Some(("fh-a-b".to_string(), "a/b.txt".to_string()))
        );
        // Another feed with the provider's id: none (validation refuses it, `id_taken`); never a
        // `-2` that would leave the feed's id and the provider's apart.
        let taken = |c: &str| c == "fh";
        let http = reg.get("http").unwrap();
        assert_eq!(
            new_feed_identity(&p("http"), http.as_ref(), "response", &taken),
            None
        );
        let unnamed = FeedProviderDef {
            name: String::new(),
            ..p("http")
        };
        assert_eq!(
            new_feed_identity(&unnamed, http.as_ref(), "response", &none)
                .unwrap()
                .1,
            "fh"
        );
        // unique_id stays an id: the base shortened before its suffix.
        let long = "a".repeat(64);
        let id = unique_id(&long, &|c: &str| c == long);
        assert!(
            id.len() <= 64 && id.ends_with("-2") && crate::config::validate::is_slug(&id),
            "{id}"
        );
        assert_eq!(unique_id("x-", &none), "x");
        // Derived names: percent-decoded, at most 128 characters, no control characters.
        let enc = url::Url::parse("https://x.example/lists/My%20List%C3%A9.txt").unwrap();
        assert_eq!(
            http_identity(&enc),
            (
                "x-example-my-list-txt".to_string(),
                "My Listé.txt (x.example)".to_string()
            )
        );
        let name = display_name(&"N".repeat(120), Some(&format!("dir/{}", "p".repeat(300))));
        assert!(
            name.chars().count() <= 128 && crate::config::validate::is_display_name(&name),
            "{name}"
        );
        assert!(
            name.starts_with("NNN") && name.ends_with("ppp)") && name.contains('…'),
            "{name}"
        );
        assert_eq!(display_name("Lists", Some("a.txt")), "Lists (a.txt)");
        assert_eq!(display_name("A\u{7}B", None), "AB");
        assert_eq!(display_name(" ", Some("x")), "feed (x)");
        let u = url::Url::parse("https://iplists.firehol.org/files/firehol_level1.netset?x=1").unwrap();
        assert_eq!(
            http_identity(&u),
            (
                "iplists-firehol-org-firehol-level1-netset".to_string(),
                "firehol_level1.netset (iplists.firehol.org)".to_string()
            )
        );
        let root = url::Url::parse("https://big.oisd.nl/").unwrap();
        assert_eq!(
            http_identity(&root),
            ("big-oisd-nl".to_string(), "big.oisd.nl".to_string())
        );
        assert_eq!(slug("!!", "x"), "x");
    }

    #[test]
    fn overlap_by_location() {
        assert!(covers("https://github.com/a/b/", "https://github.com/a/b/"));
        assert!(covers("https://x.example/lists/", "https://x.example/lists/sub/"));
        assert!(!covers("https://x.example/lists/", "https://x.example/other/"));
        assert!(!covers("https://x.example/a.csv", "https://x.example/a.csv2"));
    }

    fn provider(id: &str, module: &str, config: Value) -> FeedProviderDef {
        FeedProviderDef {
            id: id.into(),
            name: id.into(),
            module: module.into(),
            config,
            ..Default::default()
        }
    }

    fn model_of(ps: Vec<FeedProviderDef>) -> Model {
        let mut m = Model::default();
        for p in ps {
            m.feed_providers.insert(p.id.clone(), p);
        }
        m
    }

    /// The overlap check as it was: each provider's peers located again for every provider.
    fn overlapping_pairwise<'a>(model: &'a Model, p: &FeedProviderDef) -> Vec<&'a str> {
        let reg = crate::modules::download::builtin();
        let Some(m) = reg.get(&p.module) else {
            return vec![];
        };
        let loc = m.location(&p.config);
        if loc.is_empty() {
            return vec![];
        }
        let exact = m.fixed_file().is_some();
        model
            .feed_providers
            .values()
            .filter(|o| o.id != p.id && o.module == p.module)
            .filter(|o| {
                let ol = m.location(&o.config);
                let (a, b) = (loc.to_ascii_lowercase(), ol.to_ascii_lowercase());
                !ol.is_empty() && if exact { ol == loc } else { covers(&a, &b) }
            })
            .map(|o| o.id.as_str())
            .collect()
    }

    /// Issue 75: the same warnings as the pairwise check, for every provider: canonical URL
    /// equality for `http` (one URL each; the query counts), case-insensitive repositories for
    /// `github`, modules kept apart, empty or invalid locations overlapping nothing, the other
    /// providers named in id order.
    #[test]
    fn overlaps_match_the_pairwise_check() {
        let http = |id: &str, url: &str| provider(id, "http", json!({ "url": url }));
        let gh =
            |id: &str, owner: &str, repo: &str| provider(id, "github", json!({"owner": owner, "repo": repo}));
        let m = model_of(vec![
            http("h1", "https://lists.example/a.txt"),
            http("h2", "HTTPS://Lists.Example:443/a.txt"),
            http("h0", "https://lists.example/a.txt"),
            http("h3", "https://lists.example/a.txt?v=1"),
            http("h4", "https://lists.example/A.txt"),
            http("h5", "not a url"),
            http("h6", "https://lists.example/"),
            provider("h7", "http", json!({})),
            gh("g1", "Hagezi", "dns-blocklists"),
            gh("g2", "hagezi", "DNS-Blocklists.git"),
            gh("g3", "other", "list"),
            provider("g4", "github", json!({})),
            provider(
                "x1",
                "no_such_module",
                json!({"url": "https://lists.example/a.txt"}),
            ),
            provider("a1", "alphamountain_threat_1000", json!({})),
            provider("a2", "alphamountain_threat_1000", json!({})),
        ]);
        let overlaps = Overlaps::new(&m);
        for p in m.feed_providers.values() {
            assert_eq!(overlaps.of(p), overlapping_pairwise(&m, p), "{}", p.id);
        }
        let of = |id: &str| overlaps.of(&m.feed_providers[id]);
        assert_eq!(of("h1"), vec!["h0", "h2"]);
        assert_eq!(of("h0"), vec!["h1", "h2"]);
        assert!(of("h3").is_empty() && of("h4").is_empty() && of("h5").is_empty());
        assert!(of("h6").is_empty(), "an http provider is one URL, never a prefix");
        assert_eq!(of("g1"), vec!["g2"]);
        assert!(of("g3").is_empty() && of("x1").is_empty());
    }

    /// Prefix coverage: equal locations, or one ending in `/` holding the other, case-insensitive.
    #[test]
    fn overlaps_by_prefix() {
        let p = |id: &str, loc: &str| provider(id, "m", json!({ "loc": loc }));
        let m = model_of(vec![
            p("root", "https://s.example/"),
            p("sub", "https://S.example/lists/"),
            p("file", "https://s.example/lists/a.txt"),
            p("other", "https://t.example/"),
            p("sibling", "https://s.example/listsx/"),
            p("empty", ""),
        ]);
        let overlaps = Overlaps::with(&m, |p| {
            Some((p.config["loc"].as_str().unwrap().to_string(), false))
        });
        let of = |id: &str| overlaps.of(&m.feed_providers[id]);
        assert_eq!(of("root"), vec!["file", "sibling", "sub"]);
        assert_eq!(of("sub"), vec!["file", "root"]);
        assert_eq!(of("file"), vec!["root", "sub"]);
        assert_eq!(of("sibling"), vec!["root"]);
        assert!(of("other").is_empty() && of("empty").is_empty());
    }

    /// Each provider is located once however many providers' warnings are asked for (the
    /// pairwise check located N² times).
    #[test]
    fn overlaps_locate_each_provider_once() {
        let n = 1_280;
        let m = model_of(
            (0..n)
                .map(|i| {
                    provider(
                        &format!("p{i:04}"),
                        "http",
                        json!({ "url": format!("https://lists.example/{}.txt", i % 640) }),
                    )
                })
                .collect(),
        );
        let reg = crate::modules::download::builtin();
        let http = reg.get("http").unwrap();
        let mut calls = 0usize;
        let overlaps = Overlaps::with(&m, |p| {
            calls += 1;
            Some((http.location(&p.config), true))
        });
        let warned = m
            .feed_providers
            .values()
            .filter(|p| !overlaps.of(p).is_empty())
            .count();
        assert_eq!(calls, n);
        assert_eq!(warned, n, "each URL is two providers'");
        assert_eq!(overlaps.of(&m.feed_providers["p0000"]), vec!["p0640"]);
    }
}
