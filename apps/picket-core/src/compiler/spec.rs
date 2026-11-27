//! What a build compiles (bundles.md §1–§2): the bundle definition as the compiler reads it, its
//! definition hash, and the feed runs a build snapshots.
//!
//! **Members:** each feed entry of the definition, in definition order (its `position` is the
//! bundle order's first key, bundles.md §2 "Determinism"), with the rule types the bundle takes
//! from it (`rule_types`, default every type the feed stores) and its tier.
//!
//! **Definition hash:** the BLAKE3 of the canonical JSON of what changes compiled output: the
//! action, the members (feed, rule types, tier), `max_shard_keys`, `hot_max_mib`, the bundle file
//! format and [`COMPILER_VERSION`]. A changed hash makes the next build recompute every key
//! (bundles.md §2 "After a definition change"); a changed format rebuilds every shard (§4).
//!
//! **Snapshot:** a build reads each member feed as it stood at that feed's newest run that
//! changed entries (`applied` or `expired`, tombstoned `#` ids never match a member), through the
//! replay predicate `first_run ≤ r < removed_run` (storage.md §3). Reads between heavy steps then
//! see one consistent state even when a feed run lands in between: its additions have a newer
//! `first_run`, and the rows it closes a newer `removed_run`.

use std::collections::BTreeMap;

use picket_rules::RuleType;
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;

use crate::config::model::{BundleAction, BundleDef, Model, Tier};

/// Bumped when the compiler's output for the same inputs changes: it is in every definition hash,
/// so each bundle's next build after an upgrade is a full one (bundles.md §2 "After a definition
/// change"). 2: rules whose pattern is empty with a restriction (`$client=…`, `$dnstype=A`) read
/// back from storage, which version 1 skipped.
pub const COMPILER_VERSION: u32 = 2;

/// One feed of a bundle, as the compiler reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub feed: String,
    /// The feed's place in the definition (bundle order).
    pub position: u32,
    /// The rule types the bundle takes from it.
    pub types: Vec<RuleType>,
    pub tier: Tier,
    /// A downloaded (not manual) feed: its allows raise `broad_allow`, and it counts for allow
    /// overrides (bundles.md §2–§3).
    pub downloaded: bool,
    /// The feed's category is `security` etc. (alerts name it).
    pub warn_on: Vec<String>,
}

impl Member {
    pub fn takes(&self, t: RuleType) -> bool {
        self.types.contains(&t)
    }
}

/// A bundle as one build compiles it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub id: String,
    pub action: BundleAction,
    pub members: Vec<Member>,
    pub max_shard_keys: u64,
    pub hot_max_mib: Option<u32>,
    pub def_hash: String,
}

impl Spec {
    /// The compiler's view of `def` within `model` (feeds the model doesn't hold are left out: a
    /// definition naming a deleted feed is refused on save, and a stale snapshot just skips it).
    pub fn of(def: &BundleDef, model: &Model) -> Spec {
        let mut members = Vec::new();
        for (i, f) in def.feeds.iter().enumerate() {
            let feed = model.feeds.get(&f.feed);
            let types: Vec<RuleType> = match &f.rule_types {
                Some(ts) => {
                    let mut v: Vec<RuleType> = ts.iter().map(|t| rule_type(*t)).collect();
                    v.sort();
                    v.dedup();
                    v
                }
                None => RuleType::ALL.to_vec(),
            };
            members.push(Member {
                feed: f.feed.clone(),
                position: u32::try_from(i).unwrap_or(u32::MAX),
                types,
                tier: if def.action == BundleAction::Block {
                    f.tier.unwrap_or(Tier::Hot)
                } else {
                    Tier::Hot
                },
                downloaded: feed.is_some_and(|f| !f.is_manual()),
                warn_on: feed.map(|f| f.effective_warn_on()).unwrap_or_default(),
            });
        }
        let mut s = Spec {
            id: def.id.clone(),
            action: def.action,
            members,
            max_shard_keys: def.max_shard_keys,
            hot_max_mib: if def.action == BundleAction::Block {
                def.hot_max_mib
            } else {
                None
            },
            def_hash: String::new(),
        };
        s.def_hash = s.hash();
        s
    }

    fn hash(&self) -> String {
        self.hash_with(COMPILER_VERSION)
    }

    /// The definition hash as compiler version `compiler` computes it.
    fn hash_with(&self, compiler: u32) -> String {
        let feeds: Vec<serde_json::Value> = self
            .members
            .iter()
            .map(|m| {
                json!({
                    "feed": m.feed,
                    "types": m.types.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                    "tier": m.tier.as_str(),
                })
            })
            .collect();
        let v = json!({
            "action": self.action.as_str(),
            "feeds": feeds,
            "max_shard_keys": self.max_shard_keys,
            "hot_max_mib": self.hot_max_mib,
            "format": picket_bundle::FORMAT,
            "compiler": compiler,
        });
        picket_api::ids::object_id(&picket_api::ids::canonical_json(&v))
    }

    /// This spec with each member's tier from `tier_of` and `hot_max_mib` replaced, its
    /// definition hash recomputed: the split a build applies while a proposed one waits for its
    /// dry run (bundles.md §2 Tiering, [`super::tier::effective_spec`]).
    pub fn with_tiering(&self, tier_of: impl Fn(&str) -> Tier, hot_max_mib: Option<u32>) -> Spec {
        let mut s = self.clone();
        if s.action == BundleAction::Block {
            for m in &mut s.members {
                m.tier = tier_of(&m.feed);
            }
            s.hot_max_mib = hot_max_mib;
        }
        s.def_hash = s.hash();
        s
    }

    /// The member for a feed id.
    pub fn member(&self, feed: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.feed == feed)
    }

    /// The rule types this bundle's edge (or core-only) compiled form takes: `scope` bundles count
    /// only `dns` rules (bundles.md §1), browser rules never reach a compiled bundle.
    pub fn compiled_types(&self, m: &Member) -> Vec<RuleType> {
        m.types
            .iter()
            .copied()
            .filter(|t| *t != RuleType::Browser)
            .filter(|t| self.action != BundleAction::Scope || *t == RuleType::Dns)
            .collect()
    }

    /// True when the bundle has an edge bundle (bundles.md §1): not a warn bundle, and at least
    /// one member takes `dns` or `ip` rules.
    pub fn has_edge_bundle(&self) -> bool {
        self.action != BundleAction::Warn && self.members.iter().any(|m| !self.compiled_types(m).is_empty())
    }

    /// True when the bundle compiles keys at all (warn bundles do, for warning checks, but
    /// publish no head).
    pub fn compiles(&self) -> bool {
        self.members.iter().any(|m| !self.compiled_types(m).is_empty())
    }

    /// True when some member's `browser` rules make a browser list (bundles.md §8).
    pub fn has_browser_list(&self) -> bool {
        self.action != BundleAction::Warn
            && self.action != BundleAction::Scope
            && self.members.iter().any(|m| m.takes(RuleType::Browser))
    }

    /// A block bundle with a cold part possible (bundles.md §1 Tiers).
    pub fn cold_capable(&self) -> bool {
        self.action == BundleAction::Block
            && self.members.iter().any(|m| match m.tier {
                Tier::Cold => true,
                Tier::IntelligentTiering => self.hot_max_mib.is_some(),
                Tier::Hot => false,
            })
    }

    /// picket-rules' action for the reference semantics.
    pub fn rules_action(&self) -> picket_rules::BundleAction {
        rules_action(self.action)
    }
}

/// picket-rules' bundle action for a config action (warn and scope bundles match like block ones:
/// a name is "in" them when a rule would block it).
pub fn rules_action(a: BundleAction) -> picket_rules::BundleAction {
    match a {
        BundleAction::Allow => picket_rules::BundleAction::Allow,
        BundleAction::Scope => picket_rules::BundleAction::Scope,
        BundleAction::Block | BundleAction::Warn => picket_rules::BundleAction::Block,
    }
}

fn rule_type(t: crate::config::model::RuleType) -> RuleType {
    match t {
        crate::config::model::RuleType::Dns => RuleType::Dns,
        crate::config::model::RuleType::Ip => RuleType::Ip,
        crate::config::model::RuleType::Browser => RuleType::Browser,
    }
}

/// Feed id → the run a build reads it at.
pub type Runs = BTreeMap<String, i64>;

/// Each member feed's newest run that changed entries (0 for a feed with none yet), or the
/// purge of a deleted feed with its id when that is newer: the purge closed the deleted feed's
/// entries under its run id *D* and moved its runs to `<id>#<D>` (`feeds::purge`), so reading the
/// feed at *D* sees none of them, and a feed created again with the id, even before its first
/// run, never inherits the deleted feed's keys.
pub fn snapshot(c: &Connection, spec: &Spec) -> rusqlite::Result<Runs> {
    let mut out = Runs::new();
    let mut st = c.prepare_cached(
        "SELECT max(id) FROM feed_runs WHERE feed_id = ?1 AND status IN ('applied', 'expired')",
    )?;
    // Tombstoned runs of finished purges: `<id>#<D>` sorts within [`<id>#`, `<id>$`).
    let mut purged = c.prepare_cached(
        "SELECT DISTINCT feed_id FROM feed_runs WHERE feed_id >= ?1 || '#' AND feed_id < ?1 || '$'",
    )?;
    for m in &spec.members {
        let r: Option<i64> = st.query_row([&m.feed], |r| r.get(0)).optional()?.flatten();
        let mut run = r.unwrap_or(0);
        let tombs = purged.query_map([&m.feed], |r| r.get::<_, String>(0))?;
        for t in tombs {
            if let Some(d) = t?
                .strip_prefix(&format!("{}#", m.feed))
                .and_then(|d| d.parse::<i64>().ok())
            {
                run = run.max(d);
            }
        }
        out.insert(m.feed.clone(), run);
    }
    Ok(out)
}

/// Parses a stored `{feed: run}` object (`feed_runs_json`).
pub fn parse_runs(s: &str) -> Runs {
    serde_json::from_str::<BTreeMap<String, serde_json::Value>>(s)
        .map(|m| {
            m.into_iter()
                .filter_map(|(k, v)| v.as_i64().map(|r| (k, r)))
                .collect()
        })
        .unwrap_or_default()
}

/// The `{feed: run}` JSON stored with a build and a version.
pub fn runs_json(r: &Runs) -> String {
    serde_json::to_string(r).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{BundleFeed, FeedDef, RuleType as CRuleType};

    fn model() -> Model {
        let mut m = Model::default();
        for f in ["a", "b"] {
            m.feeds.insert(
                f.into(),
                FeedDef {
                    id: f.into(),
                    provider: Some("lists".into()),
                    file: Some(format!("{f}.txt")),
                    ..Default::default()
                },
            );
        }
        m
    }

    #[test]
    fn hash_follows_what_changes_output() {
        let m = model();
        let mut def = BundleDef {
            id: "b".into(),
            name: "B".into(),
            feeds: vec![
                BundleFeed {
                    feed: "a".into(),
                    ..Default::default()
                },
                BundleFeed {
                    feed: "b".into(),
                    rule_types: Some(vec![CRuleType::Ip, CRuleType::Dns]),
                    tier: Some(Tier::Cold),
                },
            ],
            ..Default::default()
        };
        let s1 = Spec::of(&def, &m);
        assert_eq!(s1.members[1].types, vec![RuleType::Dns, RuleType::Ip]);
        assert!(s1.cold_capable());
        def.name = "renamed".into();
        assert_eq!(
            Spec::of(&def, &m).def_hash,
            s1.def_hash,
            "a name changes no output"
        );
        def.feeds.swap(0, 1);
        assert_ne!(
            Spec::of(&def, &m).def_hash,
            s1.def_hash,
            "feed order is bundle order"
        );
        def.feeds.swap(0, 1);
        def.max_shard_keys = 5;
        assert_ne!(Spec::of(&def, &m).def_hash, s1.def_hash);
        // A bundle built by compiler 1, which skipped restricted rules with an empty pattern, is
        // behind: its next build is a full one.
        assert_ne!(s1.hash_with(1), s1.def_hash);
    }

    #[test]
    fn scope_takes_dns_only_and_warn_has_no_edge_bundle() {
        let m = model();
        let mut def = BundleDef {
            id: "s".into(),
            action: BundleAction::Scope,
            feeds: vec![BundleFeed {
                feed: "a".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let s = Spec::of(&def, &m);
        assert_eq!(s.compiled_types(&s.members[0]), vec![RuleType::Dns]);
        assert!(s.has_edge_bundle() && !s.has_browser_list());
        def.action = BundleAction::Warn;
        let w = Spec::of(&def, &m);
        assert!(!w.has_edge_bundle() && w.compiles());
        assert_eq!(
            parse_runs(&runs_json(&Runs::from([("a".into(), 7)]))),
            Runs::from([("a".into(), 7)])
        );
    }
}
