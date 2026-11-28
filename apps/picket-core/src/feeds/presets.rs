//! Bundled feed presets (feeds.md §9), shipped in `data/feed-presets.json` and compiled in:
//! each a feed provider with its feeds (HaGeZi TIF and Ultimate as two feeds of one `hagezi`
//! provider; OISD big and the AdGuard DNS filter, `github` providers; the alphaMountain community threat 1000 list with
//! `dns: aggregate`; FireHOL level 1), each provider's `files` selecting just its own feeds,
//! and the two rebinding presets, `plain` manual feeds with the private IPv4 and IPv6 ranges.
//! Every preset goes in `block-common`.
//!
//! The UI offers them as editable starting points. Installing one creates its provider (whose
//! `files` create its feeds) or manual feed (and its file) when missing, and adds the feeds to
//! the bundle; a preset feed the admin deleted is restored by installing it again (its file
//! leaves the provider's `exclude`), as is a preset manual feed whose file is gone. An existing
//! provider or feed is otherwise never changed: the admin's edits stay.
//!
//! A provider with a preset's id is that preset only when it reads the preset's source
//! ([`same_source`]): the same module and the same normalized source (the module's
//! [`epoch_key`](crate::modules::download::DownloadModule::epoch_key): a GitHub repository's
//! owner and name, case-insensitively, and its branch, the default branch when none is set; an
//! `http` provider's canonical URL). Any other provider with the id (the admin's own, of another
//! module or another source) isn't shown installed, and installing the preset is refused with
//! `409 Conflict` before anything changes: ids never change, so the admin keeps theirs or
//! deletes it first. The decision and the provider's update are one config transaction, so a
//! concurrent edit of the provider's source can't slip between them.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::model::{BundleFeed, EntityKind, FeedProviderDef};
use crate::config::{Actor, Op};
use crate::error::{CoreError, CoreResult};
use crate::state::SharedState;

const PRESETS_JSON: &str = include_str!("../../data/feed-presets.json");

/// One preset.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Preset {
    pub id: String,
    pub title: String,
    pub description: String,
    /// The feed provider it creates (editable), whose `files` select its feeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Value>,
    /// A manual preset's feed definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed: Option<Value>,
    /// A manual preset's file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The bundle the feeds go in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

/// Every preset.
pub fn all() -> &'static [Preset] {
    static P: OnceLock<Vec<Preset>> = OnceLock::new();
    P.get_or_init(|| match serde_json::from_str(PRESETS_JSON) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "the bundled feed presets don't parse");
            vec![]
        }
    })
}

pub fn get(id: &str) -> Option<&'static Preset> {
    all().iter().find(|p| p.id == id)
}

/// A preset with whether it is installed (its provider or manual feed exists).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct PresetView {
    #[serde(flatten)]
    pub preset: Preset,
    pub installed: bool,
}

/// What an install did.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct Installed {
    /// The provider it installed (null for a manual preset).
    pub provider: Option<String>,
    /// Its feeds.
    pub feeds: Vec<String>,
    /// The provider or manual feed was created.
    pub created: bool,
    pub bundle_added: bool,
    pub file_restored: bool,
}

fn id_of(v: &Value) -> CoreResult<String> {
    v.get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| CoreError::Other(anyhow::anyhow!("a preset has no id")))
}

/// True when `cur` (a provider with a preset provider's id) reads the preset's source: the same
/// module and the same normalized source identity, the module's `epoch_key` (GitHub: owner and
/// repository, case-insensitively, and the branch: the default branch when none is set, which no
/// explicit branch matches, not even `HEAD`; `http`: the canonical URL). Names, credentials,
/// headers and the selection are the admin's and never count.
pub fn same_source(preset: &FeedProviderDef, cur: &FeedProviderDef) -> bool {
    cur.module == preset.module
        && crate::modules::download::builtin()
            .get(&preset.module)
            .is_some_and(|m| {
                let key = m.epoch_key(&preset.config);
                !key.is_empty() && m.epoch_key(&cur.config) == key
            })
}

/// A provider's source, for a conflict message: the module's location, and for a provider that
/// follows a branch, which.
fn source_label(p: &FeedProviderDef) -> String {
    let loc = crate::modules::download::builtin()
        .get(&p.module)
        .map(|m| m.location(&p.config))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "an unknown source".into());
    match (p.module.as_str(), p.config.get("branch").and_then(Value::as_str)) {
        (_, Some(b)) => format!("{loc} (branch {b})"),
        ("github", None) => format!("{loc} (default branch)"),
        _ => loc,
    }
}

/// The preset's provider definition.
fn provider_def(p: &Preset, pv: &Value) -> CoreResult<FeedProviderDef> {
    serde_json::from_value(pv.clone()).map_err(|e| CoreError::Other(anyhow::anyhow!("preset {}: {e}", p.id)))
}

/// True when the preset's provider (of its module and source, [`same_source`]: another provider
/// with its id is no install of it) or manual feed exists.
pub fn installed(p: &Preset, m: &crate::config::Model) -> bool {
    match (&p.provider, &p.feed) {
        (Some(pv), _) => {
            let Ok(def) = provider_def(p, pv) else {
                return false;
            };
            m.feed_providers
                .get(&def.id)
                .is_some_and(|cur| same_source(&def, cur))
        }
        (None, Some(f)) => f
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| m.feeds.contains_key(id)),
        _ => false,
    }
}

/// What the provider step of an install found and did (in one config transaction).
enum ProviderStep {
    Created,
    /// The preset's provider exists (possibly updated to select the preset's files again).
    Present,
}

/// Creates the preset's provider, or brings back the preset's files on the existing provider of
/// the same source, in `tx`; refuses a provider with the id that reads another source.
fn provider_step(
    tx: &rusqlite::Transaction<'_>,
    pv: &Value,
    def: &FeedProviderDef,
    actor: &Actor,
) -> CoreResult<(ProviderStep, bool)> {
    let model = crate::config::store::load_model(tx).map_err(CoreError::Other)?;
    let pid = &def.id;
    let Some(cur) = model.feed_providers.get(pid) else {
        crate::config::store::apply(tx, EntityKind::FeedProvider, Op::Create(pv.clone()), actor, None)?;
        return Ok((ProviderStep::Created, true));
    };
    // Another module's or another source's provider with the preset's id (the admin's) isn't
    // merged into: the install is refused and says so (ids never change).
    if cur.module != def.module {
        return Err(CoreError::Conflict(format!(
            "a feed provider {pid:?} exists with another module ({:?}, not this preset's {:?}): delete it first to install the preset, or keep it",
            cur.module, def.module
        )));
    }
    if !same_source(def, cur) {
        return Err(CoreError::Conflict(format!(
            "a feed provider {pid:?} exists with another source ({}, not this preset's {}): delete it first to install the preset, or keep it",
            source_label(cur),
            source_label(def)
        )));
    }
    // A preset feed the admin deleted comes back: its files leave `exclude`, and a files entry
    // the admin removed is added again.
    let mut next = cur.clone();
    for f in &def.files {
        next.exclude.retain(|x| x != &f.pattern);
        if !next.files.iter().any(|x| x.pattern == f.pattern) {
            next.files.push(f.clone());
        }
    }
    if next == *cur {
        return Ok((ProviderStep::Present, false));
    }
    let body = serde_json::to_value(&next).map_err(|e| CoreError::Other(e.into()))?;
    crate::config::store::apply(
        tx,
        EntityKind::FeedProvider,
        Op::Update(pid.clone(), body),
        actor,
        None,
    )?;
    Ok((ProviderStep::Present, true))
}

/// Installs (or restores) a preset.
pub async fn install(state: &SharedState, id: &str, actor: Actor) -> CoreResult<Installed> {
    let p = get(id).ok_or_else(|| CoreError::NotFound(format!("no feed preset {id:?}")))?;
    let mut out = Installed::default();
    let model = state.config.model().await?;
    if let Some(pv) = &p.provider {
        let def = provider_def(p, pv)?;
        let pid = def.id.clone();
        let (pv, a) = (pv.clone(), actor.clone());
        let def2 = def.clone();
        let (step, _) = state
            .config
            .change_when(
                move |tx| provider_step(tx, &pv, &def2, &a),
                |(_, changed)| *changed,
            )
            .await?;
        match step {
            ProviderStep::Created => out.created = true,
            ProviderStep::Present => {}
        }
        // Its feeds (a module that lists files adds them with its first listing, named by the
        // files entries' templates then). A feed still on its default name (its file's, or its
        // provider's) takes the preset's; a name the admin gave stays.
        let model = state.config.model().await?;
        let pname = model
            .feed_providers
            .get(&pid)
            .map(|x| x.name.clone())
            .unwrap_or_default();
        let mut feeds = Vec::new();
        for f in model
            .feeds
            .values()
            .filter(|f| f.provider.as_deref() == Some(pid.as_str()))
        {
            let Some(entry) = def
                .files
                .iter()
                .find(|x| f.file.as_deref() == Some(x.pattern.as_str()))
            else {
                continue;
            };
            feeds.push(f.id.clone());
            let preset_name = entry
                .feed
                .as_ref()
                .and_then(|t| t.get("name"))
                .and_then(Value::as_str);
            let default = f.file.as_deref() == Some(f.name.as_str()) || f.name == pname;
            if let Some(name) = preset_name.filter(|n| default && *n != f.name) {
                let mut next = f.clone();
                next.name = name.to_string();
                let body = serde_json::to_value(&next).map_err(|e| CoreError::Other(e.into()))?;
                state
                    .config
                    .apply(
                        EntityKind::Feed,
                        Op::Update(f.id.clone(), body),
                        actor.clone(),
                        None,
                    )
                    .await?;
            }
        }
        out.feeds = feeds;
        out.provider = Some(pid);
    }
    if let Some(fv) = &p.feed {
        let feed_id = id_of(fv)?;
        if !model.feeds.contains_key(&feed_id) {
            state
                .config
                .apply(EntityKind::Feed, Op::Create(fv.clone()), actor.clone(), None)
                .await?;
            out.created = true;
        }
        if let Some(text) = &p.file {
            let has = super::manual::file_info(state, &feed_id).await?.is_some();
            if !has {
                // The runtime learns of the new feed from the config watcher; make sure it has.
                state.feeds.reload(state).await;
                write_text(state, &feed_id, text, actor.clone()).await?;
                out.file_restored = true;
            }
        }
        out.feeds = vec![feed_id];
    }
    bundle_feeds(state, p, out, actor).await
}

/// Adds an install's feeds to the preset's bundle.
async fn bundle_feeds(
    state: &SharedState,
    p: &Preset,
    mut out: Installed,
    actor: Actor,
) -> CoreResult<Installed> {
    if let Some(b) = &p.bundle {
        let model = state.config.model().await?;
        if let Some(bundle) = model.bundles.get(b) {
            let mut bundle = bundle.clone();
            let mut added = false;
            for f in &out.feeds {
                if !bundle.feeds.iter().any(|x| &x.feed == f) {
                    bundle.feeds.push(BundleFeed {
                        feed: f.clone(),
                        rule_types: None,
                        tier: None,
                    });
                    added = true;
                }
            }
            if added {
                let body = serde_json::to_value(&bundle).map_err(|e| CoreError::Other(e.into()))?;
                state
                    .config
                    .apply(EntityKind::Bundle, Op::Update(b.clone(), body), actor, None)
                    .await?;
                out.bundle_added = true;
            }
        }
    }
    Ok(out)
}

/// Saves a small text as a manual feed's file through the normal save path.
async fn write_text(state: &SharedState, feed: &str, text: &str, actor: Actor) -> CoreResult<()> {
    let body = serde_json::json!({"content": text, "base_version": null}).to_string();
    match super::manual::save(state, feed, axum::body::Body::from(body), None, actor).await {
        Ok(_) => Ok(()),
        Err(super::manual::SaveError::Conflict { .. }) => Ok(()), // saved meanwhile
        Err(e) => Err(CoreError::Other(anyhow::anyhow!("{e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::FeedDef;

    fn provider(module: &str, config: Value) -> FeedProviderDef {
        serde_json::from_value(
            serde_json::json!({"id": "x", "name": "Mine", "module": module, "config": config}),
        )
        .unwrap()
    }

    #[test]
    fn same_source_compares_the_normalized_source_only() {
        let gh = |c: Value| provider("github", c);
        let preset = gh(serde_json::json!({"owner": "hagezi", "repo": "dns-blocklists"}));
        // GitHub names are case-insensitive; names, tokens and selections never count.
        let mut mine =
            gh(serde_json::json!({"owner": "HaGeZi", "repo": "DNS-Blocklists", "token": "${secret:gh}"}));
        mine.name = "Something else".into();
        mine.exclude = vec!["adblock/*".into()];
        assert!(same_source(&preset, &mine));
        // Another owner or repository is another source.
        assert!(!same_source(
            &preset,
            &gh(serde_json::json!({"owner": "someone", "repo": "dns-blocklists"}))
        ));
        assert!(!same_source(
            &preset,
            &gh(serde_json::json!({"owner": "hagezi", "repo": "other"}))
        ));
        // The default branch (none set) is not an explicit branch, which could be any other.
        assert!(!same_source(
            &preset,
            &gh(serde_json::json!({"owner": "hagezi", "repo": "dns-blocklists", "branch": "main"}))
        ));
        let on_main = gh(serde_json::json!({"owner": "o", "repo": "r", "branch": "main"}));
        assert!(same_source(
            &on_main,
            &gh(serde_json::json!({"owner": "O", "repo": "R", "branch": "main"}))
        ));
        assert!(!same_source(
            &on_main,
            &gh(serde_json::json!({"owner": "o", "repo": "r", "branch": "dev"}))
        ));
        assert!(!same_source(
            &on_main,
            &gh(serde_json::json!({"owner": "o", "repo": "r"}))
        ));
        // An explicit `HEAD` is a branch of that name, not the default branch.
        assert!(!same_source(
            &gh(serde_json::json!({"owner": "hagezi", "repo": "dns-blocklists"})),
            &gh(serde_json::json!({"owner": "hagezi", "repo": "dns-blocklists", "branch": "HEAD"}))
        ));
        // alphamountain: its URL keyed as http keys one.
        let am = |c: Value| provider("alphamountain_threat_1000", c);
        assert!(same_source(
            &am(serde_json::json!({})),
            &am(
                serde_json::json!({"url": "https://FILES.ALPHAMOUNTAIN.AI:443/alphaMountain-community-threat-1000.csv"})
            )
        ));
        // http: the canonical URL (host case and the default port don't count, the path does).
        let http = |u: &str| provider("http", serde_json::json!({"url": u}));
        let preset = http("https://iplists.firehol.org/files/firehol_level1.netset");
        assert!(same_source(
            &preset,
            &http("https://IPLISTS.firehol.org:443/files/firehol_level1.netset")
        ));
        assert!(!same_source(
            &preset,
            &http("https://iplists.firehol.org/files/firehol_level2.netset")
        ));
        // Another module is never the same source.
        assert!(!same_source(
            &preset,
            &gh(serde_json::json!({"owner": "o", "repo": "r"}))
        ));
    }

    #[test]
    fn installed_needs_the_presets_source() {
        let p = get("hagezi").unwrap();
        let mut m = crate::config::Model::default();
        assert!(!installed(p, &m));
        let mut cur = provider("github", serde_json::json!({"owner": "someone", "repo": "lists"}));
        cur.id = "hagezi".into();
        m.feed_providers.insert("hagezi".into(), cur.clone());
        assert!(!installed(p, &m), "same id and module, another repository");
        cur.config = serde_json::json!({"owner": "hagezi", "repo": "dns-blocklists"});
        m.feed_providers.insert("hagezi".into(), cur);
        assert!(installed(p, &m));
    }

    #[test]
    fn presets_parse_and_validate() {
        let p = all();
        assert_eq!(p.len(), 7);
        let mut m = crate::config::Model::default();
        let reg = crate::modules::download::builtin();
        let mut cats: Vec<(String, String)> = Vec::new();
        for x in p {
            assert_eq!(x.bundle.as_deref(), Some("block-common"));
            match (&x.provider, &x.feed) {
                (Some(pv), None) => {
                    let d: FeedProviderDef = serde_json::from_value(pv.clone()).unwrap();
                    let n = crate::modules::download::normalize(&d.module, &d.config);
                    assert!(n.is_ok(), "{}: {n:?}", x.id);
                    let module = reg.get(&d.module).unwrap();
                    for f in &d.files {
                        assert!(
                            module.check_file(&d.config, &f.pattern, true).is_ok(),
                            "{}: {}",
                            x.id,
                            f.pattern
                        );
                        assert!(
                            crate::feeds::select::check_template(f.feed.as_ref()).is_ok(),
                            "{}",
                            x.id
                        );
                        let cat = f.feed.as_ref().unwrap()["category"].as_str().unwrap().to_string();
                        cats.push((format!("{}:{}", d.id, f.pattern), cat));
                        // Each preset feed has a readable name: its files entry's, or (a provider
                        // of one fixed file) its provider's.
                        let name = match module.fixed_file() {
                            Some(_) => Some(d.name.as_str()),
                            None => f.feed.as_ref().and_then(|t| t["name"].as_str()),
                        };
                        assert!(
                            name.is_some_and(|n| !n.trim().is_empty() && n != f.pattern && n != d.id),
                            "{}: {}",
                            x.id,
                            f.pattern
                        );
                    }
                    assert!(x.file.is_none());
                    m.feed_providers.insert(d.id.clone(), d);
                }
                (None, Some(fv)) => {
                    let f: FeedDef = serde_json::from_value(fv.clone()).unwrap();
                    assert!(f.is_manual() && x.file.is_some(), "{}", x.id);
                    cats.push((f.id.clone(), f.category.as_str().into()));
                }
                _ => panic!("{}: a provider or a manual feed", x.id),
            }
        }
        for (k, cat) in [
            ("hagezi:adblock/tif.txt", "security"),
            ("alphamountain:community-threat-1000", "security"),
            ("firehol:response", "security"),
            ("private-ipv4", "security"),
            ("private-ipv6", "security"),
            ("adguard:Filters/filter.txt", "privacy"),
            ("hagezi:adblock/ultimate.txt", "mixed"),
            ("oisd-big:abp_big.txt", "mixed"),
        ] {
            assert!(cats.contains(&(k.to_string(), cat.to_string())), "{k} {cat}");
        }
        // Each preset's files select just its own feeds: no glob.
        for d in m.feed_providers.values() {
            assert!(!d.has_globs(), "{}", d.id);
        }
        assert!(
            get("private-ipv4")
                .unwrap()
                .file
                .as_deref()
                .unwrap()
                .contains("100.64.0.0/10")
        );
        assert!(
            get("private-ipv6")
                .unwrap()
                .file
                .as_deref()
                .unwrap()
                .contains("fc00::/7")
        );
    }
}
