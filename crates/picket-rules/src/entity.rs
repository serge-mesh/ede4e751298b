//! `$denyallow` entities (`tracker.*`; review round 1, R3).
//!
//! urlfilter (`matchWildcard`) exempts a name from a rule with `$denyallow=tracker.*` when its text
//! starts with `tracker.` or holds `.tracker.`, its public suffix is in the ICANN section, and it
//! ends with `tracker.` + that suffix. So `tracker.co.uk`, `a.tracker.net` and `tracker.co.ck`
//! (`*.ck`) are exempt; `tracker.blogspot.com` (a private suffix) and `tracker.zzz` (no rule) are
//! not; and, as a quirk of that text test, `a.tracker.xtracker.com` is exempt too: it holds
//! `.tracker.` and ends with `tracker.com`.
//!
//! - [`entity_covers`] is that test given a [`PublicSuffixList`]: on the text form for patterns and
//!   for ordinary names (rules.md §3), by whole labels for keyed rules on names with unusual bytes.
//! - [`EntityExpansion`] is what the compiler ships in `rich.json` so the edge, which has no public
//!   suffix list, decides the same: the entity's `prefix.S` domains for every ICANN suffix `S`
//!   (its ICANN rules), plus the few other rules that can change a covered name's suffix (wildcards,
//!   exceptions, private rules on a label of the entity, rules under a TLD with no ICANN rule). The
//!   suffix computed from those rules equals the full list's wherever the result can matter, so
//!   matching the expansion equals matching with the full list (tested on every rule of the
//!   bundled list).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::modifiers::NameSemantics;
use crate::psl::{PublicSuffixList, SuffixRule};

/// True when the entity `prefix` (`tracker` for `tracker.*`, normalised) covers the name, by
/// urlfilter's `matchWildcard` (see the module docs). `labels` are the wire labels (most specific
/// first), `text` the name's AdGuard text form.
pub fn entity_covers(
    prefix: &str,
    labels: &[&[u8]],
    text: &str,
    sem: NameSemantics,
    list: &PublicSuffixList,
) -> bool {
    let ordinary = labels.iter().all(|l| picket_api::names::is_ordinary_label(l));
    if sem == NameSemantics::Text || ordinary {
        return covers_text(prefix, text, list);
    }
    covers_labels(prefix, labels, list)
}

/// urlfilter `matchWildcard(domain, prefix + ".*")` on the text form.
fn covers_text(prefix: &str, text: &str, list: &PublicSuffixList) -> bool {
    let w = format!("{prefix}.");
    if !(text.starts_with(&w) || text.contains(&format!(".{w}"))) {
        return false;
    }
    let (ps, icann) = list.public_suffix(text);
    icann && !ps.is_empty() && text.ends_with(&format!("{w}{ps}"))
}

/// Whole labels: the name ends with the entity's labels followed by its ICANN public suffix
/// (computed on the labels; a label holding a `.` byte is never a suffix label).
fn covers_labels(prefix: &str, labels: &[&[u8]], list: &PublicSuffixList) -> bool {
    // The public suffix of the trailing labels that hold no `.` byte (the wire's boundaries).
    let tail_start = labels
        .iter()
        .rposition(|l| l.contains(&b'.'))
        .map_or(0, |j| j.saturating_add(1));
    let tail: Vec<String> = labels
        .get(tail_start..)
        .unwrap_or(&[])
        .iter()
        .map(|l| String::from_utf8_lossy(&l.to_ascii_lowercase()).into_owned())
        .collect();
    if tail.is_empty() {
        return false;
    }
    let dotted = tail.join(".");
    let (ps, icann) = list.public_suffix(&dotted);
    if !icann || ps.is_empty() {
        return false;
    }
    let ps_labels = ps.split('.').count();
    let p: Vec<&str> = prefix.split('.').collect();
    let need = ps_labels.saturating_add(p.len());
    if labels.len() < need || tail.len() < ps_labels {
        return false;
    }
    let start = labels.len().saturating_sub(need);
    labels
        .get(start..start.saturating_add(p.len()))
        .unwrap_or(&[])
        .iter()
        .zip(&p)
        .all(|(l, q)| l.eq_ignore_ascii_case(q.as_bytes()))
}

/// An entity expanded for the edge: the part of the public suffix list that decides it, as a
/// lookup structure shared by every rule naming the entity (review round 2, CC4: a copy per rule
/// cost 255 KB of JSON and ~0.5 MB of RAM each). In a rich rule it serialises as its prefix only,
/// a reference into the bundle's [`EntityTable`], which carries each expansion once; read back, it
/// is unexpanded until [`EntityTable::link`] fills it in. An unexpanded entity fails safe: a block
/// or rewrite rule naming one doesn't apply ([`crate::rule::RichRule::conditions_match`]), an
/// exception applies as if the entity covered nothing (it only allows more), and a `$badfilter`
/// suppressor removes its target everywhere.
#[derive(Clone, Debug)]
pub struct EntityExpansion {
    /// The entity's prefix (`tracker` for `tracker.*`).
    pub prefix: String,
    /// The suffix rules that decide it (see the module docs), in list order, ready to look up;
    /// `None` until expanded or linked.
    list: Option<Arc<PublicSuffixList>>,
}

impl PartialEq for EntityExpansion {
    fn eq(&self, other: &Self) -> bool {
        self.prefix == other.prefix && self.rules() == other.rules()
    }
}

impl Eq for EntityExpansion {}

impl std::hash::Hash for EntityExpansion {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.prefix.hash(state);
        self.rules().hash(state);
    }
}

/// An entity reference in a rich rule: `{"prefix": "tracker"}`.
#[derive(Serialize, Deserialize)]
struct EntityRef {
    prefix: String,
}

impl Serialize for EntityExpansion {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        EntityRef {
            prefix: self.prefix.clone(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for EntityExpansion {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = EntityRef::deserialize(d)?;
        Ok(EntityExpansion::unexpanded(&r.prefix))
    }
}

impl EntityExpansion {
    /// Expands the entity `prefix` against the full list.
    pub fn expand(prefix: &str, full: &PublicSuffixList) -> EntityExpansion {
        let p: Vec<&str> = prefix.split('.').collect();
        let first = p.first().copied().unwrap_or("");
        // TLDs that an ICANN rule lists outright.
        let icann_tlds: std::collections::HashSet<&str> = full
            .rules()
            .iter()
            .filter(|r| r.icann && !r.rule.starts_with(['*', '!']))
            .filter_map(|r| r.rule.rsplit('.').next())
            .collect();
        let rules: Vec<SuffixRule> = full
            .rules()
            .iter()
            .filter(|r| {
                if r.icann || r.rule.starts_with(['*', '!']) {
                    return true;
                }
                let body = r.rule.as_str();
                let touches = body
                    .split('.')
                    .any(|l| p.contains(&l) || (!first.is_empty() && l.ends_with(first)));
                let tld = body.rsplit('.').next().unwrap_or("");
                touches || !icann_tlds.contains(tld)
            })
            .cloned()
            .collect();
        EntityExpansion::from_parts(prefix.to_string(), rules)
    }

    /// Builds an expansion from its suffix rules (an [`EntityTable`] entry read back).
    pub fn from_parts(prefix: String, rules: Vec<SuffixRule>) -> EntityExpansion {
        EntityExpansion {
            prefix,
            list: Some(Arc::new(PublicSuffixList::from_rules(rules))),
        }
    }

    /// True once expanded (or linked to an [`EntityTable`]).
    pub fn is_expanded(&self) -> bool {
        self.list.is_some()
    }

    /// True when both share one expansion (no copy).
    pub fn shares_expansion_with(&self, other: &EntityExpansion) -> bool {
        match (&self.list, &other.list) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    /// The suffix rules it carries, in list order (none when unexpanded).
    pub fn rules(&self) -> &[SuffixRule] {
        self.list.as_deref().map_or(&[], PublicSuffixList::rules)
    }

    /// The entity before expansion: it covers no name (a rule built without the public suffix
    /// list applies everywhere; core passes the list, [`crate::matcher::BundleMatcher`]).
    pub fn unexpanded(prefix: &str) -> EntityExpansion {
        EntityExpansion {
            prefix: prefix.to_string(),
            list: None,
        }
    }

    /// Number of suffix rules it carries (what bounds its size).
    pub fn len(&self) -> usize {
        self.rules().len()
    }

    /// Heap bytes the expansion's shared lookup structure holds (its `Arc`, the suffix rules and
    /// their trie; [`PublicSuffixList::memory_usage`]), 0 when unexpanded. Rules linked to it
    /// share it, so a table counts it once.
    pub fn memory_usage(&self) -> usize {
        self.list.as_deref().map_or(0, |l| {
            crate::mem::alloc_bytes(16usize.saturating_add(std::mem::size_of::<PublicSuffixList>()))
                .saturating_add(l.memory_usage())
        })
    }

    /// True when it carries no rule.
    pub fn is_empty(&self) -> bool {
        self.rules().is_empty()
    }

    /// The concrete domains it covers by subdomain semantics: `prefix.S` for each ICANN suffix
    /// rule `S` listed outright.
    pub fn domains(&self) -> Vec<String> {
        self.rules()
            .iter()
            .filter(|r| r.icann && !r.rule.starts_with(['*', '!']))
            .map(|r| format!("{}.{}", self.prefix, r.rule))
            .collect()
    }

    /// True when the entity covers the name ([`entity_covers`] with the expansion's rules); an
    /// unexpanded entity covers none (callers fail safe on [`EntityExpansion::is_expanded`]).
    pub fn covers(&self, labels: &[&[u8]], text: &str, sem: NameSemantics) -> bool {
        match &self.list {
            Some(l) => entity_covers(&self.prefix, labels, text, sem, l),
            None => false,
        }
    }
}

/// Most suffix rules one stored expansion may carry (the bundled list has about 9,700 rules in
/// all; `tracker.*` takes about 7,300). A larger one is refused when the table is read.
pub const MAX_EXPANSION_RULES: usize = 16_384;

/// An expansion as the table stores it.
#[derive(Serialize, Deserialize)]
struct StoredExpansion {
    prefix: String,
    rules: Vec<SuffixRule>,
}

/// The expansions of a bundle's `$denyallow` entities (bundles.md §4 `rich.json`), each stored
/// once: rich rules reference an entity by its prefix ([`EntityExpansion`]). Reading the table
/// builds each lookup structure once; [`EntityTable::link`] shares it with every rich rule naming
/// the entity. Bounded on read: at most [`MAX_ENTITIES_PER_BUNDLE`] entities of at most
/// [`MAX_EXPANSION_RULES`] rules, distinct prefixes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntityTable {
    entities: std::collections::BTreeMap<String, EntityExpansion>,
}

impl EntityTable {
    /// Adds an expanded entity (an unexpanded one is ignored).
    pub fn insert(&mut self, e: &EntityExpansion) {
        if e.is_expanded() {
            self.entities.insert(e.prefix.clone(), e.clone());
        }
    }

    /// The entity with this prefix.
    pub fn get(&self, prefix: &str) -> Option<&EntityExpansion> {
        self.entities.get(prefix)
    }

    pub fn len(&self) -> usize {
        self.entities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Fills in the expansions `rich` (and its `$badfilter` suppressors) reference. False when one
    /// isn't in the table: that entity stays unexpanded, so the rule fails safe (see
    /// [`EntityExpansion`]); the reader counts it.
    pub fn link(&self, rich: &mut crate::rule::RichRule) -> bool {
        let mut all = true;
        let mut fill = |ents: &mut Vec<EntityExpansion>| {
            for e in ents.iter_mut() {
                match self.entities.get(&e.prefix) {
                    Some(x) => *e = x.clone(),
                    None => all = false,
                }
            }
        };
        fill(&mut rich.denyallow_entities);
        for s in rich.unless.iter_mut() {
            fill(&mut s.denyallow_entities);
        }
        all
    }
}

impl Serialize for EntityTable {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(self.entities.len()))?;
        for e in self.entities.values() {
            seq.serialize_element(&StoredExpansion {
                prefix: e.prefix.clone(),
                rules: e.rules().to_vec(),
            })?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for EntityTable {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let stored = Vec::<StoredExpansion>::deserialize(d)?;
        if stored.len() > MAX_ENTITIES_PER_BUNDLE {
            return Err(D::Error::custom(format!(
                "{} entities, at most {MAX_ENTITIES_PER_BUNDLE}",
                stored.len()
            )));
        }
        let mut t = EntityTable::default();
        for x in stored {
            if x.rules.len() > MAX_EXPANSION_RULES {
                return Err(D::Error::custom(format!(
                    "entity {:?} carries {} suffix rules, at most {MAX_EXPANSION_RULES}",
                    x.prefix,
                    x.rules.len()
                )));
            }
            if t.entities.contains_key(&x.prefix) {
                return Err(D::Error::custom(format!("entity {:?} listed twice", x.prefix)));
            }
            let e = EntityExpansion::from_parts(x.prefix.clone(), x.rules);
            t.entities.insert(x.prefix, e);
        }
        Ok(t)
    }
}

/// Distinct entities a bundle expands by default: each carries about 7,300 suffix rules from the
/// bundled list (its ICANN rules, wildcards and exceptions), so the cap bounds `rich.json` and the
/// edge's memory (README §2 "Bounded").
pub const MAX_ENTITIES_PER_BUNDLE: usize = 8;

/// Expands the `$denyallow` entities of a bundle's rich rules for `rich.json`, one expansion per
/// distinct entity (shared by every rule naming it), at most `max_entities` of them; the
/// compiler writes [`EntityExpander::table`] into `rich.json` once. A rule needing an entity past the cap can't be
/// written exactly: the compiler drops it, counts it against its feed and raises
/// `bundle_warning`, as for an unbuildable regex.
pub struct EntityExpander<'a> {
    list: &'a PublicSuffixList,
    max_entities: usize,
    cache: std::collections::HashMap<String, EntityExpansion>,
    /// Rules refused because their entities didn't fit.
    pub refused: u64,
}

impl<'a> EntityExpander<'a> {
    pub fn new(list: &'a PublicSuffixList, max_entities: usize) -> EntityExpander<'a> {
        EntityExpander {
            list,
            max_entities,
            cache: std::collections::HashMap::new(),
            refused: 0,
        }
    }

    /// Fills in the expansions of `rich`'s entities (its own and its `$badfilter` suppressors').
    /// False when one doesn't fit: the rule must be dropped (and was counted in `refused`).
    pub fn expand(&mut self, rich: &mut crate::rule::RichRule) -> bool {
        let mut needed: Vec<String> = rich.denyallow_entities.iter().map(|e| e.prefix.clone()).collect();
        for s in &rich.unless {
            needed.extend(s.denyallow_entities.iter().map(|e| e.prefix.clone()));
        }
        needed.sort();
        needed.dedup();
        let new = needed.iter().filter(|p| !self.cache.contains_key(*p)).count();
        if self.cache.len().saturating_add(new) > self.max_entities {
            self.refused = self.refused.saturating_add(1);
            return false;
        }
        for p in needed {
            let list = self.list;
            self.cache
                .entry(p.clone())
                .or_insert_with(|| EntityExpansion::expand(&p, list));
        }
        let fill = |ents: &mut Vec<EntityExpansion>,
                    cache: &std::collections::HashMap<String, EntityExpansion>| {
            for e in ents.iter_mut() {
                if let Some(x) = cache.get(&e.prefix) {
                    *e = x.clone();
                }
            }
        };
        fill(&mut rich.denyallow_entities, &self.cache);
        for s in rich.unless.iter_mut() {
            fill(&mut s.denyallow_entities, &self.cache);
        }
        true
    }

    /// The distinct entities expanded so far.
    pub fn entities(&self) -> usize {
        self.cache.len()
    }

    /// The table `rich.json` carries: each expansion once (rich rules reference them by prefix).
    pub fn table(&self) -> EntityTable {
        let mut t = EntityTable::default();
        for e in self.cache.values() {
            t.insert(e);
        }
        t
    }

    /// The suffix rules all expansions carry (what they cost in `rich.json` and on the edge).
    pub fn suffix_rules(&self) -> usize {
        self.cache.values().map(EntityExpansion::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundled() -> PublicSuffixList {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/picket-core/data/public_suffix_list.dat"
        );
        PublicSuffixList::parse(&std::fs::read_to_string(path).expect("bundled PSL"))
    }

    fn cov(prefix: &str, name: &str, l: &PublicSuffixList) -> bool {
        let labels: Vec<&[u8]> = name.split('.').map(str::as_bytes).collect();
        entity_covers(prefix, &labels, name, NameSemantics::Text, l)
    }

    #[test]
    fn expander_is_bounded() {
        let full = bundled();
        let rule = |l: &str| match crate::classify::classify_adblock_line(l, false) {
            crate::classify::Line::Items(v) => match v.into_iter().next() {
                Some(crate::classify::Item::Rule(r)) => r,
                o => panic!("{o:?}"),
            },
            o => panic!("{o:?}"),
        };
        let mut x = EntityExpander::new(&full, 2);
        let mut a = rule("*$denyallow=tracker.*|example.*,dnstype=A").rich().unwrap();
        assert!(x.expand(&mut a));
        assert!(a.denyallow_entities.iter().all(|e| !e.is_empty()));
        let names: Vec<&[u8]> = vec![b"tracker", b"de"];
        let ctx = crate::modifiers::QueryCtx {
            qtype: 1,
            ..Default::default()
        };
        assert!(!a.conditions_match(&names, "tracker.de", &ctx, NameSemantics::Labels));
        let mut b = rule("||x.example^$denyallow=example.*").rich().unwrap();
        assert!(x.expand(&mut b), "already expanded");
        let mut c = rule("||y.example^$denyallow=other.*").rich().unwrap();
        assert!(!x.expand(&mut c), "a third entity is past the cap");
        assert_eq!((x.refused, x.entities()), (1, 2));
        assert!(x.suffix_rules() > 10_000);
    }

    #[test]
    fn rich_json_stores_each_expansion_once() {
        // CC4: 1,000 rules naming one entity carry one expansion in the table and a reference
        // each (255 MB of JSON before); reading the table back builds the lookup once, and a
        // rich rule linked to it decides as the expanded one without rebuilding per call.
        let full = bundled();
        let rule = |l: &str| match crate::classify::classify_adblock_line(l, false) {
            crate::classify::Line::Items(v) => match v.into_iter().next() {
                Some(crate::classify::Item::Rule(r)) => r,
                o => panic!("{o:?}"),
            },
            o => panic!("{o:?}"),
        };
        let mut x = EntityExpander::new(&full, MAX_ENTITIES_PER_BUNDLE);
        let mut rich = Vec::new();
        for i in 0..1000 {
            let mut r = rule(&format!("||a{i}.com^$denyallow=tracker.*")).rich().unwrap();
            assert!(x.expand(&mut r));
            rich.push(r);
        }
        let table = x.table();
        let rules_json = serde_json::to_string(&rich).unwrap();
        let table_json = serde_json::to_string(&table).unwrap();
        eprintln!(
            "1,000 rich rules: {} bytes, entity table: {} bytes",
            rules_json.len(),
            table_json.len()
        );
        assert!(rules_json.len() < 200_000, "{}", rules_json.len());
        assert!(table_json.len() < 400_000, "{}", table_json.len());
        let table: EntityTable = serde_json::from_str(&table_json).unwrap();
        let mut back: Vec<crate::rule::RichRule> = serde_json::from_str(&rules_json).unwrap();
        let ctx = crate::modifiers::QueryCtx {
            qtype: 1,
            ..Default::default()
        };
        let exempt: Vec<&[u8]> = vec![b"a", b"tracker", b"co", b"uk"];
        let other: Vec<&[u8]> = vec![b"a", b"example", b"com"];
        // Unlinked: the block rule doesn't apply (fail safe), whatever the name.
        assert!(!back[0].conditions_match(&other, "a.example.com", &ctx, NameSemantics::Labels));
        for r in back.iter_mut() {
            assert!(table.link(r));
        }
        let t = std::time::Instant::now();
        for r in &back {
            assert!(!r.conditions_match(&exempt, "a.tracker.co.uk", &ctx, NameSemantics::Labels));
            assert!(r.conditions_match(&other, "a.example.com", &ctx, NameSemantics::Labels));
        }
        assert!(
            t.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            t.elapsed()
        );
        assert!(back[0].denyallow_entities[0].shares_expansion_with(&back[999].denyallow_entities[0]));
        assert_eq!(back, rich);
        // A table with an entity not in it leaves the rule unlinked.
        let mut stray = rule("||b.com^$denyallow=other.*").rich().unwrap();
        assert!(!table.link(&mut stray));
        // An exception rule with an unexpanded entity still applies (it only allows more).
        let exc = rule("@@||c.com^$denyallow=tracker.*").rich().unwrap();
        assert!(exc.conditions_match(&other, "a.example.com", &ctx, NameSemantics::Labels));
    }

    #[test]
    fn as_urlfilter() {
        let l = bundled();
        assert!(cov("tracker", "tracker.com", &l));
        assert!(cov("tracker", "tracker.co.uk", &l));
        assert!(cov("tracker", "a.b.tracker.net", &l));
        assert!(cov("tracker", "tracker.co.ck", &l), "*.ck");
        assert!(!cov("tracker", "tracker.blogspot.com", &l), "private suffix");
        assert!(!cov("tracker", "tracker.zzz", &l), "no rule");
        assert!(!cov("tracker", "x.tracker.example.com", &l));
        assert!(!cov("tracker", "mytracker.com", &l));
        assert!(
            cov("tracker", "a.tracker.xtracker.com", &l),
            "urlfilter's text quirk"
        );
        assert!(cov("ads.tracker", "x.ads.tracker.de", &l));
        assert!(!cov("ads.tracker", "x.tracker.de", &l));
        // Unusual names keep whole labels for keyed rules.
        let n: Vec<&[u8]> = vec![b"a!b", b"tracker", b"com"];
        assert!(entity_covers(
            "tracker",
            &n,
            "a!b.tracker.com",
            NameSemantics::Labels,
            &l
        ));
        let n: Vec<&[u8]> = vec![b"x.tracker", b"com"];
        assert!(!entity_covers(
            "tracker",
            &n,
            "x\\.tracker.com",
            NameSemantics::Labels,
            &l
        ));
        assert!(entity_covers(
            "tracker",
            &n,
            "x\\.tracker.com",
            NameSemantics::Text,
            &l
        ));
    }

    #[test]
    fn expansion_equals_the_full_list() {
        // For every rule of the bundled list, and names built around it, the expansion decides as
        // the full list does.
        let full = bundled();
        for prefix in ["tracker", "google", "blogspot", "ads.tracker", "co", "s3"] {
            let e = EntityExpansion::expand(prefix, &full);
            assert!(e.len() < full.len());
            let mut checked = 0usize;
            for r in full.rules() {
                let body = r.rule.trim_start_matches("*.").trim_start_matches('!');
                for name in [
                    format!("{prefix}.{body}"),
                    format!("x.{prefix}.{body}"),
                    format!("{prefix}.x.{body}"),
                    format!("x{prefix}.{body}"),
                    format!("{prefix}.x{prefix}.{body}"),
                    format!("a.{prefix}.b.x{prefix}.{body}"),
                    body.to_string(),
                ] {
                    let labels: Vec<&[u8]> = name.split('.').map(str::as_bytes).collect();
                    let want = entity_covers(prefix, &labels, &name, NameSemantics::Text, &full);
                    assert_eq!(
                        e.covers(&labels, &name, NameSemantics::Text),
                        want,
                        "{prefix} {name}"
                    );
                    checked += 1;
                }
            }
            assert!(checked > 50_000);
        }
        let e = EntityExpansion::expand("tracker", &full);
        assert!(e.domains().contains(&"tracker.co.uk".to_string()));
        // Its size (reported to the owner with the cap).
        eprintln!(
            "tracker.* expands to {} suffix rules ({} concrete domains), {} bytes as JSON",
            e.len(),
            e.domains().len(),
            serde_json::to_string(e.rules()).map(|j| j.len()).unwrap_or(0)
        );
        assert!(e.len() < 8_000);
        // In a rich rule it is a reference; the table carries the rules and builds the lookup.
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"prefix":"tracker"}"#);
        let mut t = EntityTable::default();
        t.insert(&e);
        let json = serde_json::to_string(&t).unwrap();
        let back: EntityTable = serde_json::from_str(&json).unwrap();
        let back = back.get("tracker").unwrap();
        assert!(back.covers(&[b"a", b"tracker", b"de"], "a.tracker.de", NameSemantics::Text));
        assert_eq!(back, &e);
        let back = EntityExpansion::from_parts(back.prefix.clone(), back.rules().to_vec());
        assert_eq!(back, e);
        assert!(!EntityExpansion::unexpanded("tracker").covers(
            &[b"tracker", b"de"],
            "tracker.de",
            NameSemantics::Text
        ));
    }
}
