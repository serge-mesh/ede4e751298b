//! Scope checks on core (core.md §7; edge.md §10 "Scope"): whether a name is in a bundle (a
//! profile's allow bundles, a provider's or attachment's scope bundles), in one of a profile's
//! forward zones, and in a provider's and attachment's scope.
//!
//! A bundle's current rules decide, read from `feed_entries` at the member feeds' current runs and
//! matched by picket-rules' reference matcher, the semantics the edge's matcher is tested against
//! (bundles.md §6): the key rules at each suffix of the name, plus the bundle's patterns. The
//! patterns and a matcher built from them alone are cached per bundle and runs (a few bundles at
//! a time), so a name without key rules (most names) costs the key lookups and one match; only a
//! name with key rules builds a matcher of its own. A name is in a bundle when it would be
//! blocked by a block bundle, allowed by an allow bundle, or in scope of a scope bundle.
//!
//! Scope, as on the edge: the provider's and the attachment's `exclude_bundles` first (exclude
//! wins), then their `include_bundles` (each list, when set, must hold the name).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use picket_api::edge_config::LookupAttachment;
use picket_rules::{BundleMatcher, Outcome, QueryCtx, Rule};

use crate::compiler::source::View;
use crate::compiler::spec::{self, Spec};
use crate::config::Model;
use crate::config::model::{LookupProviderDef, ProfileDef};

/// Pattern rules read per bundle at most (README §2 Bounded).
const MAX_PATTERNS: usize = 200_000;
/// Bundles whose patterns stay cached (allow bundles, scope bundles of providers and attachments).
const CACHED: usize = 16;

/// A bundle's patterns at its current runs, and the matcher of the patterns alone.
struct Patterns {
    rules: Arc<[Rule]>,
    matcher: Option<Arc<BundleMatcher>>,
}

type PatternCache = Mutex<VecDeque<(String, Arc<Patterns>)>>;

fn cache() -> &'static PatternCache {
    static C: std::sync::OnceLock<PatternCache> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// True when `name` (log text) is under one of the profile's forward zones.
pub fn in_forward_zone(model: &Model, profile: &ProfileDef, name: &str) -> bool {
    profile.edge.forward_zones.iter().any(|z| {
        model.forward_zones.get(z).is_some_and(|d| {
            let zone = d.zone.trim_end_matches('.').to_ascii_lowercase();
            !zone.is_empty() && (name == zone || name.ends_with(&format!(".{zone}")))
        })
    })
}

/// True when `name` is in `bundle` (module docs). An unknown bundle holds nothing.
pub fn in_bundle(
    c: &rusqlite::Connection,
    model: &Model,
    bundle: &str,
    name: &str,
) -> rusqlite::Result<bool> {
    let Some(def) = model.bundles.get(bundle) else {
        return Ok(false);
    };
    let spec = Spec::of(def, model);
    let runs = spec::snapshot(c, &spec)?;
    let view = View::new(&spec, &runs);
    let mut bad = 0u64;
    let mut rules: Vec<Rule> = Vec::new();
    let rn = picket_rules::OwnedName::from_dotted(name);
    let labels: Vec<String> = rn
        .as_labels()
        .iter()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    for i in 0..labels.len() {
        let suffix: Vec<&str> = labels[i..].iter().rev().map(String::as_str).collect();
        if suffix.iter().any(|l| l.contains('.')) {
            continue;
        }
        rules.extend(
            view.key_rules(c, &suffix.join("."), &mut bad)?
                .into_iter()
                .map(|r| r.rule),
        );
    }
    let key = format!("{bundle}|{runs:?}");
    let cached = cache()
        .lock()
        .ok()
        .and_then(|q| q.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()));
    let patterns = match cached {
        Some(p) => p,
        None => {
            let p: Vec<Rule> = match view.patterns(c, MAX_PATTERNS, &mut bad)? {
                Ok(rows) => rows.into_iter().map(|r| r.rule).collect(),
                Err(_) => Vec::new(),
            };
            let matcher = (!p.is_empty()).then(|| {
                Arc::new(
                    BundleMatcher::new(spec.rules_action(), p.clone())
                        .with_public_suffix_list(crate::psl::rules_list()),
                )
            });
            let p = Arc::new(Patterns {
                rules: p.into(),
                matcher,
            });
            if let Ok(mut q) = cache().lock() {
                q.retain(|(k, _)| !k.starts_with(&format!("{bundle}|")));
                if q.len() >= CACHED {
                    q.pop_front();
                }
                q.push_back((key, p.clone()));
            }
            p
        }
    };
    let ctx = QueryCtx {
        qtype: 1,
        client_ip: None,
        client_names: &[],
        client_tags: &[],
    };
    // No key rule at any suffix of the name: the patterns alone decide (the cached matcher).
    let r = if rules.is_empty() {
        let Some(m) = &patterns.matcher else {
            return Ok(false);
        };
        m.match_dotted(name, &ctx)
    } else {
        rules.extend(patterns.rules.iter().cloned());
        BundleMatcher::new(spec.rules_action(), rules)
            .with_public_suffix_list(crate::psl::rules_list())
            .match_dotted(name, &ctx)
    };
    Ok(matches!(
        r.outcome,
        Outcome::Block | Outcome::Rewrite(_) | Outcome::HostMapping(_) | Outcome::Allow | Outcome::InScope
    ))
}

/// True when `name` is in the provider's and the attachment's scope (module docs).
pub fn in_scope(
    c: &rusqlite::Connection,
    model: &Model,
    p: &LookupProviderDef,
    att: &LookupAttachment,
    name: &str,
) -> rusqlite::Result<bool> {
    for b in p
        .settings
        .scope
        .exclude_bundles
        .iter()
        .chain(att.exclude_bundles.iter())
    {
        if in_bundle(c, model, b, name)? {
            return Ok(false);
        }
    }
    for list in [&p.settings.scope.include_bundles, &att.include_bundles] {
        if list.is_empty() {
            continue;
        }
        let mut any = false;
        for b in list {
            if in_bundle(c, model, b, name)? {
                any = true;
                break;
            }
        }
        if !any {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Why no call is made for `name` on behalf of `profiles` (core.md §7 Sources (b): "within the
/// attachment's and the provider's scope"; edge.md §10 Scope): `not_attached` when none of them
/// attaches the provider any more, `out_of_scope` when every attachment's or the provider's scope
/// keeps the name out. `None`: one of them attaches it and the name is in scope.
pub fn call_skip(
    c: &rusqlite::Connection,
    model: &Model,
    provider: &str,
    p: &LookupProviderDef,
    profiles: &[String],
    name: &str,
) -> rusqlite::Result<Option<&'static str>> {
    let mut why = "not_attached";
    for pid in profiles {
        let Some(att) = model
            .profiles
            .get(pid)
            .and_then(|prof| prof.edge.lookups.iter().find(|a| a.provider == provider))
        else {
            continue;
        };
        if in_scope(c, model, p, att, name)? {
            return Ok(None);
        }
        why = "out_of_scope";
    }
    Ok(Some(why))
}

/// True when the provider calls for a query of `qtype` (`scope.qtypes`; edge.md §10: an empty list
/// calls for none).
pub fn calls_for(p: &LookupProviderDef, qtype: &str) -> bool {
    p.settings
        .scope
        .qtypes
        .iter()
        .any(|t| t.eq_ignore_ascii_case(qtype))
}
