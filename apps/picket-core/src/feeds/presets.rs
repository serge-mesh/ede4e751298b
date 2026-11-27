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
    /// Providers of the same list an older release's preset made under its provider id (OISD big
    /// was an `http` provider of `https://big.oisd.nl/`): such a provider is this preset,
    /// installed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy: Vec<LegacyProvider>,
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

/// A provider an older release's preset made (a preset's `legacy`): its module and its `url` (as
/// providers are matched by URL).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LegacyProvider {
    pub module: String,
    pub url: String,
}

impl LegacyProvider {
    fn is(&self, p: &FeedProviderDef) -> bool {
        let key = |u: &str| {
            url::Url::parse(u)
                .ok()
                .map(|u| crate::modules::download::http::url_key(&u))
        };
        p.module == self.module
            && key(&self.url)
                .is_some_and(|k| p.config.get("url").and_then(Value::as_str).and_then(key) == Some(k))
    }
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

/// True when the preset's provider (of its module, or a [`Preset::legacy`] one: another
/// provider with its id is no install of it) or manual feed exists.
pub fn installed(p: &Preset, m: &crate::config::Model) -> bool {
    match (&p.provider, &p.feed) {
        (Some(pv), _) => pv.get("id").and_then(Value::as_str).is_some_and(|id| {
            m.feed_providers.get(id).is_some_and(|cur| {
                Some(cur.module.as_str()) == pv.get("module").and_then(Value::as_str)
                    || p.legacy.iter().any(|l| l.is(cur))
            })
        }),
        (None, Some(f)) => f
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| m.feeds.contains_key(id)),
        _ => false,
    }
}

/// Installs (or restores) a preset.
pub async fn install(state: &SharedState, id: &str, actor: Actor) -> CoreResult<Installed> {
    let p = get(id).ok_or_else(|| CoreError::NotFound(format!("no feed preset {id:?}")))?;
    let mut out = Installed::default();
    let model = state.config.model().await?;
    if let Some(pv) = &p.provider {
        let pid = id_of(pv)?;
        let def: FeedProviderDef = serde_json::from_value(pv.clone())
            .map_err(|e| CoreError::Other(anyhow::anyhow!("preset {id}: {e}")))?;
        match model.feed_providers.get(&pid) {
            None => {
                state
                    .config
                    .apply(
                        EntityKind::FeedProvider,
                        Op::Create(pv.clone()),
                        actor.clone(),
                        None,
                    )
                    .await?;
                out.created = true;
            }
            // An older release's provider of the same list is this preset, installed: left as
            // it is, its feeds go in the bundle.
            Some(cur) if p.legacy.iter().any(|l| l.is(cur)) => {
                out.provider = Some(pid.clone());
                out.feeds = model
                    .feeds
                    .values()
                    .filter(|f| f.provider.as_deref() == Some(pid.as_str()))
                    .map(|f| f.id.clone())
                    .collect();
                return bundle_feeds(state, p, out, actor).await;
            }
            // Another module's provider with the preset's id (the admin's) isn't merged into:
            // the install is refused and says so (ids never change).
            Some(cur) if cur.module != def.module => {
                return Err(CoreError::Conflict(format!(
                    "a feed provider {pid:?} exists with another module ({:?}, not this preset's {:?}): delete it first to install the preset, or keep it",
                    cur.module, def.module
                )));
            }
            Some(cur) => {
                // A preset feed the admin deleted comes back: its files leave `exclude`, and a
                // files entry the admin removed is added again.
                let mut next = cur.clone();
                for f in &def.files {
                    next.exclude.retain(|x| x != &f.pattern);
                    if !next.files.iter().any(|x| x.pattern == f.pattern) {
                        next.files.push(f.clone());
                    }
                }
                if next != *cur {
                    let body = serde_json::to_value(&next).map_err(|e| CoreError::Other(e.into()))?;
                    state
                        .config
                        .apply(
                            EntityKind::FeedProvider,
                            Op::Update(pid.clone(), body),
                            actor.clone(),
                            None,
                        )
                        .await?;
                }
            }
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
