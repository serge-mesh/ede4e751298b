//! Download modules (providers.md §1–§3): compile-time code, one directory each under
//! `src/modules/download/<id>/`, found by `build.rs` (no linker tricks, no `unsafe`). A **feed
//! provider** is a configured instance of one ([`crate::config::model::FeedProviderDef`]): its
//! `module` names the directory, its `config` is the module's `Config`.
//!
//! - [`DownloadModule`]: the trait as providers.md §2 writes it (`id`, `config_schema`,
//!   `location`, `lists_files`, `check`, `history`), plus default methods core needs around it:
//!   [`DownloadModule::normalize_config`] (the save-time check and the stored form of a config),
//!   [`DownloadModule::check_file`] (a feed's `file` in the module's terms, e.g. a `github` path),
//!   [`DownloadModule::epoch_key`] (what "pointing elsewhere" compares, feed-scheduling.md §4),
//!   [`DownloadModule::default_files`] (the files a provider with an empty `files` selects),
//!   [`DownloadModule::fixed_file`] (the one file of a module whose providers have exactly one:
//!   `http`'s `response`, `alphamountain_threat_1000`'s `community-threat-1000`),
//!   [`DownloadModule::pause_scope`] (what a rate-limit pause covers) and
//!   [`DownloadModule::max_concurrent`] (the module's share of the light lane).
//! - One `check()` covers a provider: one [`FileCheck`] per enabled feed, each judged against
//!   its own `last`; the answer is a [`ProviderCheck`] with one result per file and, for a module
//!   that lists files, the provider's [`Listing`] when it may have changed.
//! - [`Ctx`] ([`ctx`]): the HTTP client ([`client`]: HTTPS only, at most 5 redirects, all HTTPS,
//!   gzip and brotli, `User-Agent: picket/<ver>`, core's resolver, deadlines, the decoded size
//!   cap), `stage_file()` for streaming bodies into `staging/` with BLAKE3 hashing, cancellation,
//!   [`Ctx::listing_incomplete`], how a module tells core a listing walk couldn't finish
//!   (`feed_provider_listing_incomplete`, providers.md §3) without changing the trait's types,
//!   and [`Ctx::cooldown`] / [`Ctx::note_cooldown`], how a module keeps every request of a check
//!   behind a server cooldown.
//! - [`Registry`]: the modules by id, one instance each per running core. A module keeps no
//!   per-provider state: `cfg` and `state` come with every call.
//!
//! **Convention** (providers.md §1): each directory has `mod.rs` with `pub struct Module`
//! (`Default`, implementing the trait), a `Config` (`serde` + `schemars::JsonSchema`), a
//! `README.md` and `tests/` with recorded fixtures. The directory name is the id providers name
//! in `module`.

pub mod client;
pub mod ctx;
pub mod dates;
pub mod glob;
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit;

use std::collections::BTreeMap;
use std::sync::Arc;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use ctx::{Ctx, StageWriter, StagedFile};

// The generated module declarations (`pub mod <id>`), `MODULE_IDS` and `all_modules()`.
include!(concat!(env!("OUT_DIR"), "/download_registry.rs"));

/// The module's own notion of one file's version, as its previous run left it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LastRun {
    /// chrono's default serde form, as `feed_state.last_json` has always held it (README §2).
    #[serde(with = "picket_api::time::autosi")]
    pub updated_at: Timestamp,
    pub version: String,
    #[serde(default)]
    pub state: Value,
}

/// One file a check asks about: an enabled feed's `file` and its last run (`None` on the
/// file's first check).
#[derive(Clone, Debug, PartialEq)]
pub struct FileCheck {
    pub file: String,
    pub last: Option<LastRun>,
}

/// The files a provider offers, when a check listed them. `whole: false` when the module
/// limited a costly walk to what the `select` patterns reach; such a listing still holds every
/// file `files` can select.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub files: Vec<String>,
    pub whole: bool,
}

/// What one check of a provider found (providers.md §2).
#[derive(Debug)]
pub struct ProviderCheck {
    /// The provider's own state, e.g. `github`'s listed head.
    pub state: Value,
    /// One result per file asked about.
    pub files: Vec<(String, Result<CheckOutcome, CheckError>)>,
    /// The files the provider offers, when this check listed them.
    pub listing: Option<Listing>,
}

/// When a change happened (feed-scheduling.md §3). Stored as `feed_changes` columns, never as
/// JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeTime {
    /// A known time: a git commit time, `Last-Modified`, a date line in the list header.
    Exact(Timestamp),
    /// Somewhere in `(lo, hi]`: the previous successful check and this one.
    Interval { lo: Timestamp, hi: Timestamp },
}

/// What a check found for one file.
#[derive(Debug)]
pub enum CheckOutcome {
    Unchanged {
        /// New file state to keep (a moved `github` head with the same blob).
        state: Option<Value>,
        /// Change times seen without a new file.
        observed: Vec<ChangeTime>,
        bytes: u64,
        method: &'static str,
    },
    Changed {
        updated_at: Timestamp,
        version: String,
        state: Value,
        change_times: Vec<ChangeTime>,
        file: StagedFile,
        bytes: u64,
        method: &'static str,
    },
}

/// Why a check (of the provider, or of one file) failed.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// The server refused the request under its rate limit or asked for a cooldown (`github`'s
    /// rate-limit replies; `http`'s `429`/`503` with a valid `Retry-After`): no check in the
    /// provider's pause scope ([`DownloadModule::pause_scope`]) starts until `until`. The text
    /// carries `until` in the storage form (api.md §5), as a feed's own rate-limit error does.
    #[error("rate limited until {}", picket_api::time::format_micros(.until))]
    RateLimited { until: Timestamp },
    /// The provider no longer has this file.
    #[error("the provider no longer has this file")]
    Missing,
    #[error("{0:#}")]
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for CheckError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e)
    }
}

impl From<client::HttpError> for CheckError {
    fn from(e: client::HttpError) -> Self {
        Self::Failed(anyhow::Error::new(e))
    }
}

/// A config as it is stored, with what the UI should say about the conversion.
#[derive(Clone, Debug, PartialEq)]
pub struct Normalized {
    pub config: Value,
    /// Shown after the save.
    pub notice: Option<String>,
}

/// A download module (providers.md §2).
#[async_trait::async_trait]
pub trait DownloadModule: Send + Sync {
    fn id(&self) -> &'static str;
    /// Schema of a feed provider's `config`.
    fn config_schema(&self) -> schemars::Schema;
    /// The URL prefix all files of a provider with this config are under, so the UI can warn
    /// about two providers covering the same files.
    fn location(&self, cfg: &Value) -> String;
    /// Whether `check()` can list a provider's files, so `files` can hold globs.
    fn lists_files(&self) -> bool {
        false
    }
    /// Called when the provider is due, with its state from its previous check (None on its
    /// first), one entry per enabled feed, and the `match` patterns of the provider's `files`
    /// (a hint for limiting a listing).
    async fn check(
        &self,
        ctx: &Ctx,
        cfg: &Value,
        state: Option<&Value>,
        feeds: &[FileCheck],
        select: &[String],
    ) -> Result<ProviderCheck, CheckError>;
    /// Optional: past change times of one file, for the scheduler's warm start
    /// (feed-scheduling.md §6).
    async fn history(&self, _ctx: &Ctx, _cfg: &Value, _file: &str) -> anyhow::Result<Vec<ChangeTime>> {
        Ok(vec![])
    }

    // Core's additions (default methods):

    /// Checks a config at save time (secret references in place) and returns the form to store.
    /// The message names the field at fault; it never quotes a secret value (there is none yet).
    fn normalize_config(&self, cfg: &Value) -> Result<Normalized, String>;
    /// Checks a feed's `file` (or a `files` entry's `match`) in the module's terms. `pattern`:
    /// a `files` entry, which may be a glob for a module that lists files.
    fn check_file(&self, _cfg: &Value, file: &str, _pattern: bool) -> Result<(), String> {
        if file.chars().any(char::is_control) || file.len() > 1024 {
            Err("a file is at most 1024 bytes, without control characters".into())
        } else {
            Ok(())
        }
    }
    /// What a config points at: an edit that changes it points the provider's feeds at other
    /// files and starts new model epochs (feeds.md §3, feed-scheduling.md §4).
    fn epoch_key(&self, cfg: &Value) -> String {
        self.location(cfg)
    }
    /// A `files` or `exclude` edit while the provider keeps a whole listing (feeds.md §3: the
    /// edit applies at once): the provider's state with any wait before listing again removed,
    /// when that listing may be out of date (a newer listing that couldn't finish waits for its
    /// retry); `None` when nothing waits. Only a module that lists files has such a wait.
    fn state_for_selection_edit(&self, _state: &Value) -> Option<Value> {
        None
    }
    /// The one file every provider of this module has, when it has exactly one with a fixed
    /// name (`http`'s `response`, `alphamountain_threat_1000`'s `community-threat-1000`): the
    /// feed reading it takes the provider's id, and by default its name (feeds.md §1).
    fn fixed_file(&self) -> Option<&'static str> {
        None
    }
    /// The `files` entries a provider with an empty `files` selects: `(match, feed template)`.
    fn default_files(&self) -> Vec<(String, Value)> {
        vec![]
    }
    /// The pause scope of a provider with this config (providers.md §2): the endpoint whose
    /// quota a `RateLimited` reply speaks for. After one, no check of any provider in the same
    /// scope starts until it ends, and providers in other scopes are untouched. By default the
    /// module (GitHub's API quota covers every `github` provider); `http` keys it by the URL's
    /// origin, so a cooling-down list server never pauses a list on another host.
    fn pause_scope(&self, _cfg: &Value) -> String {
        self.id().to_string()
    }
    /// The most checks through this module that run at once (its share of the feed checks'
    /// part of the light lane, core.md §3): two, so two modules can fill the feed checks' share
    /// ([`FEED_SHARE`]) and none holds it alone.
    fn max_concurrent(&self) -> usize {
        2
    }
}

/// The light-lane key of all feed provider checks together, and its share: half the lane, so
/// feed checks and downloads never hold every light slot and async lookups, DNSSEC validations
/// and the other light work always have the other half (core.md §3; README §2 capped shares).
pub const FEED_SHARE_KEY: &str = "feeds";
pub const FEED_SHARE: usize = crate::scheduler::LightLane::CONCURRENCY / 2;

/// True when a check `method` transferred the whole file (feeds.md §5: `! Expires:` spaces full
/// downloads). Modules label full downloads `full`, `probe` (an `http` first check) or
/// `download`; a `Changed` outcome is always one.
pub fn is_full_download(method: &str) -> bool {
    matches!(method, "full" | "probe" | "download")
}

/// A provider's pause scope ([`DownloadModule::pause_scope`]), with the module id for a module
/// this build doesn't have.
pub fn pause_scope(module: &str, cfg: &Value) -> String {
    builtin()
        .get(module)
        .map_or_else(|| module.to_string(), |m| m.pause_scope(cfg))
}

/// The download modules by id.
#[derive(Clone)]
pub struct Registry {
    modules: BTreeMap<&'static str, Arc<dyn DownloadModule>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.modules.keys()).finish()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Registry {
    /// Fresh instances of every compiled-in module.
    pub fn builtin() -> Self {
        let mut modules = BTreeMap::new();
        for m in all_modules() {
            modules.insert(m.id(), Arc::from(m));
        }
        Self { modules }
    }

    /// Adds or replaces a module (tests).
    pub fn insert(&mut self, m: Arc<dyn DownloadModule>) {
        self.modules.insert(m.id(), m);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn DownloadModule>> {
        self.modules.get(id).cloned()
    }

    /// Module ids, sorted.
    pub fn ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.modules.keys().copied()
    }
}

/// The shared registry for save-time checks (validation needs no running core).
pub fn builtin() -> &'static Registry {
    static REG: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
    REG.get_or_init(Registry::builtin)
}

/// The compiled-in module ids (validation needs no instance).
pub fn known_ids() -> &'static [&'static str] {
    MODULE_IDS
}

/// The save-time check of a feed provider's config (config validation, providers.md §1–§3):
/// `Err` names what is wrong; `Ok` gives the config to store.
pub fn normalize(module: &str, cfg: &Value) -> Result<Normalized, String> {
    match builtin().get(module) {
        Some(m) => m.normalize_config(cfg),
        None => Err(format!(
            "{module:?} is not a download module ({})",
            known_ids().join(", ")
        )),
    }
}

/// Parses a stored config into a module's `Config`, with `${secret:name}` references replaced
/// by placeholders first (save-time checks never see secret values). The error names the field.
pub fn parse_config<T: serde::de::DeserializeOwned>(cfg: &Value) -> Result<T, String> {
    let cfg = picket_lookup::secrets::with_placeholders(cfg).map_err(|e| e.to_string())?;
    serde_json::from_value(cfg).map_err(|e| format!("invalid config: {e}"))
}

/// Parses a config whose secrets are resolved (in a check).
pub fn config_of<T: serde::de::DeserializeOwned>(cfg: &Value) -> Result<T, CheckError> {
    serde_json::from_value(cfg.clone())
        .map_err(|e| CheckError::Failed(anyhow::anyhow!("invalid config: {e}")))
}

/// The JSON Schema of a module `Config` (the UI's form, providers.md §1).
pub fn schema_of<T: schemars::JsonSchema>() -> schemars::Schema {
    schemars::schema_for!(T)
}

/// True when `v` is exactly one `${secret:name}` reference (a field that takes only secrets).
pub fn is_secret_ref(v: &str) -> bool {
    let t = v.trim();
    t.starts_with(picket_lookup::secrets::SECRET_PREFIX) && t.ends_with('}') && t.matches("${").count() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// providers.md §1: the directory name is the module id, and ids are unique; the `manual`
    /// module is gone (manual feeds have no provider).
    #[test]
    fn ids_match_directories() {
        let r = Registry::builtin();
        let ids: Vec<&str> = r.ids().collect();
        assert_eq!(ids, MODULE_IDS);
        assert_eq!(ids, vec!["alphamountain_threat_1000", "github", "http"]);
        for id in &ids {
            assert_eq!(r.get(id).unwrap().id(), *id);
        }
        for m in all_modules() {
            assert!(m.config_schema().as_object().is_some(), "{}", m.id());
        }
        assert!(r.get("github").unwrap().lists_files());
        assert!(!r.get("http").unwrap().lists_files());
        assert!(!r.get("alphamountain_threat_1000").unwrap().lists_files());
        assert!(r.get("manual").is_none());
    }

    /// Golden (F2: the default serde form of the states in `feed_state.last_json`; plan §5 step
    /// 1, unchanged after the move to jiff): 0, 3, 6 or 9 fractional digits, and read back
    /// exactly.
    #[test]
    fn golden_stored_states() {
        use picket_api::time::golden::{ROWS, ts_from_nanos};
        for r in ROWS {
            let t = ts_from_nanos(r.nanos);
            let last = LastRun {
                updated_at: t,
                version: "v1".into(),
                state: serde_json::json!({"k": 1}),
            };
            let json = serde_json::to_string(&last).unwrap();
            let want = format!(
                r#"{{"updated_at":"{}","version":"v1","state":{{"k":1}}}}"#,
                r.autosi
            );
            assert_eq!(json, want, "{}", r.name);
            assert_eq!(
                serde_json::from_str::<LastRun>(&json).unwrap(),
                last,
                "{}",
                r.name
            );

            let http = http::State {
                date_line: Some(t),
                last_full: Some(t),
                ..Default::default()
            };
            let json = serde_json::to_string(&http).unwrap();
            assert_eq!(
                json,
                format!(r#"{{"date_line":"{0}","last_full":"{0}"}}"#, r.autosi),
                "{}",
                r.name
            );
            assert_eq!(
                serde_json::from_str::<http::State>(&json).unwrap(),
                http,
                "{}",
                r.name
            );

            let gh = github::ProviderState {
                listed_head: Some("abc".into()),
                walk_failed: Some(github::WalkFailed {
                    head: "def".into(),
                    at: t,
                }),
            };
            let json = serde_json::to_string(&gh).unwrap();
            let want = format!(
                r#"{{"listed_head":"abc","walk_failed":{{"head":"def","at":"{}"}}}}"#,
                r.autosi
            );
            assert_eq!(json, want, "{}", r.name);
            assert_eq!(
                serde_json::from_str::<github::ProviderState>(&json).unwrap(),
                gh,
                "{}",
                r.name
            );
        }
    }

    /// Golden (F12, jiff plan choice D3): a provider-wide rate limit's error text carries `until`
    /// in the storage form.
    #[test]
    fn golden_rate_limited_text() {
        use picket_api::time::golden::{ROWS, ts_from_nanos};
        for r in ROWS {
            let e = CheckError::RateLimited {
                until: ts_from_nanos(r.nanos),
            };
            assert_eq!(
                e.to_string(),
                format!("rate limited until {}", r.micros),
                "{}",
                r.name
            );
        }
    }
}
