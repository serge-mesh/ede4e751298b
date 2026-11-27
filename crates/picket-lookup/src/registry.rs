//! The module registry (providers.md §1). `build.rs` scans `src/modules/*/` and generates
//! [`modules`]: one `pub mod <id>` per directory and `all()`, a boxed `Module::default()`
//! each. [`Registry`] holds them by id, shared by every lookup provider of a module.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::module::{LookupModule, Preset};
use crate::secrets;

/// The generated module declarations and lists.
pub mod modules {
    include!(concat!(env!("OUT_DIR"), "/registry.rs"));
}

/// Why a stored config doesn't fit its module. The message names the field or rule at fault;
/// secret values are replaced by placeholders before checking, so none can appear in it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("unknown lookup module {0:?}")]
    UnknownModule(String),
    #[error("{0}")]
    Secret(#[from] secrets::SecretError),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Lookup modules by id.
#[derive(Clone)]
pub struct Registry {
    modules: BTreeMap<&'static str, Arc<dyn LookupModule>>,
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
    /// Every compiled-in module.
    pub fn builtin() -> Self {
        let mut by_id = BTreeMap::new();
        for m in modules::all() {
            by_id.insert(m.id(), Arc::from(m));
        }
        Self { modules: by_id }
    }

    /// An empty registry (tests add their own modules).
    pub fn empty() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }

    /// Adds or replaces a module (tests, or a side that wraps a module).
    pub fn insert(&mut self, module: Arc<dyn LookupModule>) {
        self.modules.insert(module.id(), module);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn LookupModule>> {
        self.modules.get(id).cloned()
    }

    /// Module ids, sorted.
    pub fn ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.modules.keys().copied()
    }

    /// The module's presets (empty for an unknown module).
    pub fn presets(&self, id: &str) -> Vec<Preset> {
        self.get(id).map(|m| m.presets()).unwrap_or_default()
    }

    /// Checks a stored config (with `${secret:name}` references) against its module's `Config`,
    /// for core's save path: references must be well formed, and the config must parse with
    /// placeholder values in their place. A module added with [`Self::insert`] that isn't
    /// compiled in is only checked for its references.
    pub fn validate_config(&self, id: &str, cfg: &serde_json::Value) -> Result<(), ConfigError> {
        if !self.modules.contains_key(id) {
            return Err(ConfigError::UnknownModule(id.to_owned()));
        }
        let cfg = secrets::with_placeholders(cfg)?;
        match modules::check_config(id, &cfg) {
            Some(Err(e)) => Err(ConfigError::Invalid(e.to_string())),
            Some(Ok(())) | None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// providers.md §1: the directory name is the module id, and ids are unique.
    #[test]
    fn ids_match_directories() {
        let all = modules::all();
        let ids: Vec<&str> = all.iter().map(|m| m.id()).collect();
        assert_eq!(ids, modules::IDS);
        assert!(ids.contains(&"http_json"));
        assert!(ids.contains(&"dns"));
        let r = Registry::builtin();
        assert_eq!(r.ids().collect::<Vec<_>>(), modules::IDS);
    }

    #[test]
    fn config_schemas_are_objects() {
        for m in modules::all() {
            let s = m.config_schema();
            assert!(s.as_object().is_some(), "{}", m.id());
        }
    }

    #[test]
    fn validate_with_secret_refs() {
        let r = Registry::builtin();
        let cfg = serde_json::json!({
            "url": "https://api.example.net/v1/domain/{domain}?key=${secret:k}",
            "headers": {"Authorization": "Bearer ${secret:am_rt}"},
            "verdict": {"pointer": "/risk_score", "block_if": ">= 7.0", "clean_if": "< 4.0"}
        });
        r.validate_config("http_json", &cfg).unwrap();
        let bad = serde_json::json!({"url": "https://x/{domain}", "verdict": {"pointer": "x"}});
        assert!(matches!(
            r.validate_config("http_json", &bad),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            r.validate_config("nope", &cfg),
            Err(ConfigError::UnknownModule(_))
        ));
    }
}
