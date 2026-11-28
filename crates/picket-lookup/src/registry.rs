//! The module registry (providers.md §1). `build.rs` scans `src/modules/*/` and generates
//! [`modules`]: one `pub mod <id>` per directory, `all()` (a boxed `Module::default()` each) and
//! one constructor per module. [`Registry`] holds the constructors by id and builds a module only
//! when something asks for it (#44).
//!
//! **Sharing and release.** Every lookup provider of a module shares one instance: the registry
//! keeps a [`Weak`] to it and hands out that instance while any holder (a provider's settings, a
//! call still running) keeps it alive. Once the last one lets go the module is dropped, and the
//! next request builds a new one. What the registry itself keeps is bookkeeping: the id, the
//! constructor, and the weak pointer, which holds the module struct's own allocation (not what
//! the module owns on the heap) until the slot is used again. A module added with
//! [`Registry::insert`] is held for the registry's lifetime, as before.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

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

/// Builds a module.
pub type ModuleFactory = Arc<dyn Fn() -> Arc<dyn LookupModule> + Send + Sync>;

enum Source {
    /// Built on demand and shared while in use.
    Make(ModuleFactory),
    /// Held for the registry's lifetime.
    Fixed(Arc<dyn LookupModule>),
}

struct Slot {
    source: Source,
    live: Mutex<Option<Weak<dyn LookupModule>>>,
}

impl Slot {
    fn get(&self) -> Arc<dyn LookupModule> {
        match &self.source {
            Source::Fixed(m) => Arc::clone(m),
            Source::Make(make) => {
                let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(m) = live.as_ref().and_then(Weak::upgrade) {
                    return m;
                }
                let m = make();
                *live = Some(Arc::downgrade(&m));
                m
            }
        }
    }

    fn is_live(&self) -> bool {
        match &self.source {
            Source::Fixed(_) => true,
            Source::Make(_) => self
                .live
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .is_some_and(|w| w.strong_count() > 0),
        }
    }
}

/// Lookup modules by id. Clones share their slots, and so their live instances.
#[derive(Clone)]
pub struct Registry {
    modules: BTreeMap<&'static str, Arc<Slot>>,
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
    /// Every compiled-in module, none of them built yet.
    pub fn builtin() -> Self {
        let mut r = Self::empty();
        for (id, make) in modules::FACTORIES {
            r.insert_factory(id, Arc::new(*make));
        }
        r
    }

    /// An empty registry (tests add their own modules).
    pub fn empty() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }

    /// Adds or replaces a module held for the registry's lifetime (tests, or a side that wraps
    /// a module).
    pub fn insert(&mut self, module: Arc<dyn LookupModule>) {
        self.put(module.id(), Source::Fixed(module));
    }

    /// Adds or replaces a module built by `make` when first asked for and shared while in use
    /// (tests with an instrumented module). `make` must build a module whose `id()` is `id`.
    pub fn insert_factory(&mut self, id: &'static str, make: ModuleFactory) {
        self.put(id, Source::Make(make));
    }

    fn put(&mut self, id: &'static str, source: Source) {
        self.modules.insert(
            id,
            Arc::new(Slot {
                source,
                live: Mutex::new(None),
            }),
        );
    }

    /// The module, built if no one holds it now.
    pub fn get(&self, id: &str) -> Option<Arc<dyn LookupModule>> {
        self.modules.get(id).map(|s| s.get())
    }

    /// Whether `id` is a known module (builds nothing).
    pub fn contains(&self, id: &str) -> bool {
        self.modules.contains_key(id)
    }

    /// Whether an instance of `id` exists now (always for one added with [`Self::insert`]).
    pub fn is_live(&self, id: &str) -> bool {
        self.modules.get(id).is_some_and(|s| s.is_live())
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

    /// #44: a module is built when first asked for, shared while held, dropped after its last
    /// holder, and built again on the next request.
    #[test]
    fn modules_are_built_on_demand_shared_and_released() {
        let r = Registry::builtin();
        for id in modules::IDS {
            assert!(!r.is_live(id), "{id} built at startup");
            assert!(r.contains(id));
        }
        let a = r.get("dns").unwrap();
        let b = r.clone().get("dns").unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "one instance per module, also through a clone"
        );
        assert!(r.is_live("dns") && !r.is_live("http_json"));
        drop((a, b));
        assert!(!r.is_live("dns"), "released after its last holder");

        let counters = Arc::new(crate::testkit::ModuleCounters::default());
        let mut r = Registry::empty();
        r.insert_factory(
            "counted",
            crate::testkit::CountedModule::factory(1 << 20, Arc::clone(&counters)),
        );
        assert!(r.contains("counted") && !r.is_live("counted"));
        assert_eq!(counters.get(), (0, 0));
        let one = r.get("counted").unwrap();
        let two = r.get("counted").unwrap();
        assert_eq!(counters.get(), (1, 0));
        drop(one);
        assert_eq!(counters.get(), (1, 0), "still held");
        drop(two);
        assert_eq!(counters.get(), (1, 1));
        let again = r.get("counted").unwrap();
        assert_eq!(counters.get(), (2, 1), "built again after release");
        drop(again);
        assert_eq!(counters.get(), (2, 2));
        r.validate_config("counted", &serde_json::json!({})).unwrap();
        assert_eq!(counters.get(), (2, 2), "validation builds nothing");
    }
}
