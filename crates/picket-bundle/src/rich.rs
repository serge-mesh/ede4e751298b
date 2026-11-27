//! `rich.json` (bundles.md §4): the bundle's modifier rules (`$dnstype`, `$client`, `$ctag`,
//! `$denyallow`, `$dnsrewrite`, conditionally `$badfilter`ed rules) and host-IP mappings.
//!
//! ```jsonc
//! {"format": 1,
//!  "entities": [{"prefix": "tracker", "rules": [...]}],   // EntityExpander::table(), once
//!  "rules": [RichRule, ...],                               // distinct rules
//!  "sets": [[0, 3], [1], ...]}                             // a key's, run's or pattern's rules
//! ```
//!
//! A key, IP run or pattern with `HAS_RICH` carries a `rich_idx` naming one set. Each
//! `$dnsrewrite` rule carries `order`, urlfilter's matched-rule order, which orders a query's
//! rewrites ([`picket_rules::order::sequence`]). `$denyallow` entities are written once, in
//! `entities`; rules reference them by prefix and the reader links them ([`EntityTable::link`]).
//! A rule whose entity isn't in the table stays unexpanded: a block or rewrite naming it applies
//! to nothing (fail safe), and the reader counts it ([`RichSegment::unlinked`]).
//!
//! **Indices are stable** (bundles.md §6 "Each active part reads rich rules from the `rich.json` of
//! its own head"; edge.md §13; review round 1, B6). A head moves the parts it leaves unchanged to
//! itself, and they then read the new head's `rich.json` with the indices they were written with.
//! So every build but a whole-bundle one (every shard, IP shard and segment rebuilt in the same
//! head: a new bundle or a format change) starts from the previous head's segment
//! ([`RichBuilder::from_previous`]): incremental builds and per-shard compaction alike. A live
//! rule or set keeps its index for as long as anything references it; dead ones are reclaimed by
//! [`RichBuilder::retain_sets`], which empties them, and later builds reuse their slots (lowest
//! first). That is safe because a part only moves to a head unchanged, so everything it references
//! is live there; parts still from an older head read that head's segment. Each part checks at
//! load, and when it moves to a head, that every index it holds names a set of the segment it reads
//! (`LoadError`, never a silent "no rules").
//!
//! **Limits** (README §2 "Bounded", "Untrusted input"; edge.md §17; B8; review round 2, CR1):
//! the reader parses under a memory budget ([`MAX_RICH_MEMORY`]) that every allocation of the
//! parsed segment is charged to as it is made, however deeply nested: each rule's `$denyallow`
//! names, entities, `$client` and `$ctag` lists, `unless` suppressors and rewrite values, every
//! array's growth, every string's buffer, each as the allocator takes it ([`crate::charge`]). It
//! also counts rules, sets, set elements, entities and each entity's suffix rules while parsing,
//! and an entity's lookup trie is charged at an upper bound before it is built, then at what it
//! holds. So a file of millions of tiny items is refused once the budget or a count is spent,
//! before it costs more, and [`RichSegment::memory_usage`] reports the memory the parsed segment
//! really holds, not the JSON's length. The writer refuses to write a segment the reader would
//! refuse ([`RichBuilder::to_bytes`] parses its output as the reader does).

use std::collections::{BTreeSet, HashMap};

use picket_rules::entity::{EntityExpansion, EntityTable, MAX_ENTITIES_PER_BUNDLE, MAX_EXPANSION_RULES};
use picket_rules::mem::{alloc_bytes, vec_bytes};
use picket_rules::psl::SuffixRule;
use picket_rules::rule::RichRule;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::FORMAT;
use crate::charge::{Budget, Charge, LIMITS};

/// Largest `rich.json` the reader accepts.
pub const MAX_RICH_BYTES: usize = 64 * 1024 * 1024;
/// Most memory a parsed `rich.json` may hold: 96 MiB, a quarter of the default
/// `bundle_budget_mib` (edge.md §17), room for [`MAX_RULES`] typical rules (~0.4 KiB each with
/// their sets) and the entity table. Policy bound (owner to confirm).
pub const MAX_RICH_MEMORY: usize = 96 * 1024 * 1024;
/// Most rules: 128 Ki, about 50 MiB parsed (a rule is ~384 bytes plus its strings). bundles.md §2
/// warns from 10k host-IP mappings. Policy bound (owner to confirm).
pub const MAX_RULES: usize = 128 * 1024;
/// Most sets.
pub const MAX_SETS: usize = 256 * 1024;
/// Most rules in one set.
pub const MAX_SET_LEN: usize = 65_536;
/// Most set elements in all.
pub const MAX_SET_ELEMENTS: usize = 1024 * 1024;
/// Longest suffix rule an entity may carry: a name of at most 253 bytes with its `*.` or `!`.
pub const MAX_SUFFIX_RULE: usize = 256;
/// What one label of a suffix rule can cost in an entity's lookup trie, at most: its node (with
/// the node array's spare capacity), its slot in its parent's child map (a map of one child takes
/// a 160-byte table) and its own buffer past 24 bytes, which is charged by length on top.
const TRIE_LABEL_BYTES: usize = 320;

/// Why a `rich.json` is refused.
#[derive(Debug, thiserror::Error)]
pub enum RichError {
    #[error("rich.json is larger than {MAX_RICH_BYTES} bytes")]
    TooLarge,
    #[error("rich.json: {0}")]
    Json(serde_json::Error),
    #[error("rich.json format {0} is not supported")]
    Format(u32),
    #[error("{LIMITS}")]
    Limits,
    #[error("set {0} names a rule that doesn't exist")]
    Index(usize),
}

impl From<serde_json::Error> for RichError {
    fn from(e: serde_json::Error) -> Self {
        if e.is_data() && e.to_string().starts_with(LIMITS) {
            RichError::Limits
        } else {
            RichError::Json(e)
        }
    }
}

#[derive(Serialize)]
struct RichFileOut<'a> {
    format: u32,
    entities: &'a EntityTable,
    rules: &'a [RichRule],
    sets: &'a [Vec<u32>],
}

/// A parsed `rich.json`, before its indices are checked and its rules linked.
struct Parsed {
    format: u32,
    entities: EntityTable,
    rules: Vec<RichRule>,
    sets: Vec<Vec<u32>>,
    /// Bytes the parsed structures hold (what the budget was charged).
    memory: usize,
    /// Of `memory`, the bytes of the entity table's entries ([`entity_entry_bytes`]).
    table_memory: usize,
}

/// What one entity table entry holds: the expansion (its `Arc`, suffix rules and trie), its prefix
/// twice (the expansion's and the table's key) and its share of the table's node.
fn entity_entry_bytes(e: &EntityExpansion) -> usize {
    e.memory_usage()
        .saturating_add(alloc_bytes(e.prefix.len()).saturating_mul(2))
        .saturating_add(std::mem::size_of::<(String, EntityExpansion)>())
        .saturating_add(16)
}

/// Parses a `rich.json` under the budget (see the module docs).
fn parse(data: &[u8]) -> Result<Parsed, RichError> {
    if data.len() > MAX_RICH_BYTES {
        return Err(RichError::TooLarge);
    }
    let budget = Budget::new(MAX_RICH_MEMORY);
    let mut de = serde_json::Deserializer::from_slice(data);
    let table = std::cell::Cell::new(0usize);
    let (format, entities, rules, sets) = FileSeed(&budget, &table).deserialize(&mut de)?;
    de.end()?;
    Ok(Parsed {
        format,
        entities,
        rules,
        sets,
        memory: budget.used(),
        table_memory: table.get(),
    })
}

fn limits<E: de::Error>() -> E {
    E::custom(LIMITS)
}

/// Pushes onto a vector, charging the growth of its buffer as it happens.
fn push_charged<T, E: de::Error>(v: &mut Vec<T>, x: T, b: &Budget) -> Result<(), E> {
    let before = vec_bytes::<T>(v.capacity());
    v.push(x);
    b.charge(vec_bytes::<T>(v.capacity()).saturating_sub(before))
}

/// Shrinks a vector to fit, giving back its spare capacity.
fn shrink_charged<T>(v: &mut Vec<T>, b: &Budget) {
    let before = vec_bytes::<T>(v.capacity());
    v.shrink_to_fit();
    b.refund(before.saturating_sub(vec_bytes::<T>(v.capacity())));
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "lowercase")]
enum FileField {
    Format,
    Entities,
    Rules,
    Sets,
    #[serde(other)]
    Other,
}

/// The whole file: `{format, entities, rules, sets}` (unknown fields ignored); the cell gets the
/// entity table's share of the budget.
struct FileSeed<'b>(&'b Budget, &'b std::cell::Cell<usize>);

type FileParts = (u32, EntityTable, Vec<RichRule>, Vec<Vec<u32>>);

impl<'de> DeserializeSeed<'de> for FileSeed<'_> {
    type Value = FileParts;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<FileParts, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for FileSeed<'_> {
    type Value = FileParts;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a rich.json object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<FileParts, A::Error> {
        let b = self.0;
        let (mut format, mut entities, mut rules, mut sets) = (None, None, None, None);
        while let Some(k) = map.next_key::<FileField>()? {
            match k {
                FileField::Format if format.is_none() => format = Some(map.next_value::<u32>()?),
                FileField::Entities if entities.is_none() => {
                    entities = Some(map.next_value_seed(EntitiesSeed(b, self.1))?)
                }
                FileField::Rules if rules.is_none() => rules = Some(map.next_value_seed(RulesSeed(b))?),
                FileField::Sets if sets.is_none() => sets = Some(map.next_value_seed(SetsSeed(b))?),
                FileField::Other => {
                    map.next_value::<de::IgnoredAny>()?;
                }
                _ => return Err(de::Error::custom("rich.json repeats a field")),
            }
        }
        let format = format.ok_or_else(|| de::Error::missing_field("format"))?;
        Ok((
            format,
            entities.unwrap_or_default(),
            rules.unwrap_or_default(),
            sets.unwrap_or_default(),
        ))
    }
}

/// `rules`: at most [`MAX_RULES`], each charged as it is parsed.
struct RulesSeed<'b>(&'b Budget);

impl<'de> DeserializeSeed<'de> for RulesSeed<'_> {
    type Value = Vec<RichRule>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Vec<RichRule>, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for RulesSeed<'_> {
    type Value = Vec<RichRule>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a list of rules")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<RichRule>, A::Error> {
        let b = self.0;
        let mut out: Vec<RichRule> = Vec::new();
        while let Some(r) = seq.next_element_seed(Charge::<RichRule>::new(b))? {
            if out.len() >= MAX_RULES {
                return Err(limits());
            }
            push_charged(&mut out, r, b)?;
        }
        shrink_charged(&mut out, b);
        Ok(out)
    }
}

/// `sets`: at most [`MAX_SETS`], [`MAX_SET_LEN`] each and [`MAX_SET_ELEMENTS`] in all.
struct SetsSeed<'b>(&'b Budget);

impl<'de> DeserializeSeed<'de> for SetsSeed<'_> {
    type Value = Vec<Vec<u32>>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Vec<Vec<u32>>, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for SetsSeed<'_> {
    type Value = Vec<Vec<u32>>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a list of sets")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<Vec<u32>>, A::Error> {
        let b = self.0;
        let mut left = MAX_SET_ELEMENTS;
        let mut out: Vec<Vec<u32>> = Vec::new();
        while let Some(s) = seq.next_element_seed(SetSeed {
            left: &mut left,
            budget: b,
        })? {
            if out.len() >= MAX_SETS {
                return Err(limits());
            }
            push_charged(&mut out, s, b)?;
        }
        shrink_charged(&mut out, b);
        Ok(out)
    }
}

/// One set of rule indices.
struct SetSeed<'a, 'b> {
    left: &'a mut usize,
    budget: &'b Budget,
}

impl<'de> DeserializeSeed<'de> for SetSeed<'_, '_> {
    type Value = Vec<u32>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Vec<u32>, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for SetSeed<'_, '_> {
    type Value = Vec<u32>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a set of rule indices")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u32>, A::Error> {
        let mut out: Vec<u32> = Vec::new();
        while let Some(x) = seq.next_element::<u32>()? {
            if out.len() >= MAX_SET_LEN || *self.left == 0 {
                return Err(limits());
            }
            *self.left = self.left.saturating_sub(1);
            push_charged(&mut out, x, self.budget)?;
        }
        shrink_charged(&mut out, self.budget);
        Ok(out)
    }
}

/// `entities`: at most [`MAX_ENTITIES_PER_BUNDLE`] of at most [`MAX_EXPANSION_RULES`] suffix rules
/// each, distinct prefixes, counted while parsing (review round 2, CR1: the whole table used to be
/// parsed before its caps were checked). The cell gets what the entries hold.
struct EntitiesSeed<'b>(&'b Budget, &'b std::cell::Cell<usize>);

impl<'de> DeserializeSeed<'de> for EntitiesSeed<'_> {
    type Value = EntityTable;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<EntityTable, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for EntitiesSeed<'_> {
    type Value = EntityTable;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a list of entities")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<EntityTable, A::Error> {
        let b = self.0;
        let mut table = EntityTable::default();
        loop {
            let start = b.used();
            let Some((prefix, rules)) = seq.next_element_seed(EntitySeed(b))? else {
                break;
            };
            if table.len() >= MAX_ENTITIES_PER_BUNDLE {
                return Err(de::Error::custom(format!(
                    "more than {MAX_ENTITIES_PER_BUNDLE} entities"
                )));
            }
            if table.get(&prefix).is_some() {
                return Err(de::Error::custom(format!("entity {prefix:?} listed twice")));
            }
            // The trie, at most TRIE_LABEL_BYTES and its text per label, before it is built ...
            let trie = rules.iter().fold(0usize, |a, r| {
                r.rule.split('.').fold(a, |a, l| {
                    a.saturating_add(TRIE_LABEL_BYTES).saturating_add(l.len())
                })
            });
            b.charge::<A::Error>(trie)?;
            let e = EntityExpansion::from_parts(prefix.clone(), rules);
            // ... then what the entry holds.
            let held = entity_entry_bytes(&e);
            b.refund(b.used().saturating_sub(start));
            b.charge::<A::Error>(held)?;
            self.1.set(self.1.get().saturating_add(held));
            table.insert(&e);
        }
        Ok(table)
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "lowercase")]
enum EntityField {
    Prefix,
    Rules,
    #[serde(other)]
    Other,
}

/// One stored entity: `{prefix, rules}`.
struct EntitySeed<'b>(&'b Budget);

impl<'de> DeserializeSeed<'de> for EntitySeed<'_> {
    type Value = (String, Vec<SuffixRule>);
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for EntitySeed<'_> {
    type Value = (String, Vec<SuffixRule>);
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an entity")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let b = self.0;
        let (mut prefix, mut rules) = (None, None);
        while let Some(k) = map.next_key::<EntityField>()? {
            match k {
                EntityField::Prefix if prefix.is_none() => {
                    prefix = Some(map.next_value_seed(Charge::<String>::new(b))?)
                }
                EntityField::Rules if rules.is_none() => {
                    rules = Some(map.next_value_seed(SuffixRulesSeed(b))?)
                }
                EntityField::Other => {
                    map.next_value::<de::IgnoredAny>()?;
                }
                _ => return Err(de::Error::custom("an entity repeats a field")),
            }
        }
        let prefix = prefix.ok_or_else(|| de::Error::missing_field("prefix"))?;
        let rules = rules.ok_or_else(|| de::Error::missing_field("rules"))?;
        Ok((prefix, rules))
    }
}

/// An entity's suffix rules: at most [`MAX_EXPANSION_RULES`], each at most [`MAX_SUFFIX_RULE`]
/// bytes.
struct SuffixRulesSeed<'b>(&'b Budget);

impl<'de> DeserializeSeed<'de> for SuffixRulesSeed<'_> {
    type Value = Vec<SuffixRule>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Vec<SuffixRule>, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for SuffixRulesSeed<'_> {
    type Value = Vec<SuffixRule>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a list of suffix rules")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<SuffixRule>, A::Error> {
        let b = self.0;
        let mut out: Vec<SuffixRule> = Vec::new();
        while let Some(r) = seq.next_element_seed(Charge::<SuffixRule>::new(b))? {
            if out.len() >= MAX_EXPANSION_RULES {
                return Err(de::Error::custom(format!(
                    "an entity carries more than {MAX_EXPANSION_RULES} suffix rules"
                )));
            }
            if r.rule.is_empty() || r.rule.len() > MAX_SUFFIX_RULE {
                return Err(de::Error::custom("a suffix rule is empty or too long"));
            }
            push_charged(&mut out, r, b)?;
        }
        shrink_charged(&mut out, b);
        Ok(out)
    }
}

/// Builds a `rich.json`: interns rules and sets so each is written once, keeping every index it
/// was seeded with (see the module docs).
#[derive(Default)]
pub struct RichBuilder {
    rules: Vec<RichRule>,
    rule_index: HashMap<RichRule, u32>,
    sets: Vec<Vec<u32>>,
    set_index: HashMap<Vec<u32>, u32>,
    entities: EntityTable,
    /// Reclaimed slots, reused lowest first.
    free_rules: BTreeSet<u32>,
    free_sets: BTreeSet<u32>,
}

impl RichBuilder {
    /// A builder for a whole-bundle build, where every part is rebuilt in the same head (a new
    /// bundle, or a format change): indices start from zero.
    pub fn new() -> RichBuilder {
        RichBuilder::default()
    }

    /// A builder seeded with the previous head's `rich.json`, for every other build (incremental,
    /// or a per-shard compaction): every rule and set keeps its index, so the `rich_idx` of keys
    /// and runs the build doesn't touch stays valid against the new segment. Empty slots (from
    /// [`RichBuilder::retain_sets`]) are reused before the arrays grow.
    pub fn from_previous(data: &[u8]) -> Result<RichBuilder, RichError> {
        let (seg, entities) = RichSegment::load(data)?;
        let mut b = RichBuilder {
            entities,
            ..RichBuilder::default()
        };
        // A reclaimed rule slot is an empty rule no set names (an empty rule a set does name keeps
        // its slot, so reuse can't change that set).
        let named: BTreeSet<u32> = seg.sets.iter().flatten().copied().collect();
        // Linked rules, so a rule the compiler interns again (entities expanded) compares equal.
        for (i, r) in seg.rules.into_iter().enumerate() {
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            if r == RichRule::default() && !named.contains(&i) {
                b.free_rules.insert(i);
            } else {
                b.rule_index.entry(r.clone()).or_insert(i);
            }
            b.rules.push(r);
        }
        for (i, s) in seg.sets.into_iter().enumerate() {
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            if s.is_empty() {
                b.free_sets.insert(i);
            } else {
                b.set_index.entry(s.clone()).or_insert(i);
            }
            b.sets.push(s);
        }
        Ok(b)
    }

    /// Sets the entity table: the compiler's [`picket_rules::entity::EntityExpander::table`] for
    /// the bundle's current rules. For an incremental build too: a rule an unchanged key still
    /// references is a current rule, so its entities are in the table, and entities no current rule
    /// names are dropped, so churn never piles up past the entity cap (bundles.md §2 incremental
    /// equivalence; review round 1, B5).
    pub fn set_entities(&mut self, table: EntityTable) {
        self.entities = table;
    }

    /// Interns one rule.
    pub fn rule(&mut self, r: &RichRule) -> u32 {
        if let Some(&i) = self.rule_index.get(r) {
            return i;
        }
        let i = match self.free_rules.pop_first() {
            Some(i) => {
                if let Some(slot) = usize::try_from(i).ok().and_then(|i| self.rules.get_mut(i)) {
                    *slot = r.clone();
                }
                i
            }
            None => {
                let i = u32::try_from(self.rules.len()).unwrap_or(u32::MAX);
                self.rules.push(r.clone());
                i
            }
        };
        self.rule_index.insert(r.clone(), i);
        i
    }

    /// Interns a set of rules (order doesn't matter: rewrites are ordered by their `order`).
    pub fn set(&mut self, rules: &[RichRule]) -> u32 {
        let mut ids: Vec<u32> = rules.iter().map(|r| self.rule(r)).collect();
        ids.sort_unstable();
        ids.dedup();
        if let Some(&i) = self.set_index.get(&ids) {
            return i;
        }
        let i = match self.free_sets.pop_first() {
            Some(i) => {
                if let Some(slot) = usize::try_from(i).ok().and_then(|i| self.sets.get_mut(i)) {
                    *slot = ids.clone();
                }
                i
            }
            None => {
                let i = u32::try_from(self.sets.len()).unwrap_or(u32::MAX);
                self.sets.push(ids.clone());
                i
            }
        };
        self.set_index.insert(ids, i);
        i
    }

    /// Reclaims every set not in `live` (the sets the new head's keys, runs and patterns
    /// reference, unchanged ones included) and every rule no live set names: they are written
    /// empty, keep their index, and later interning reuses their slots. Live indices never change.
    pub fn retain_sets(&mut self, live: &BTreeSet<u32>) {
        let mut live_rules: BTreeSet<u32> = BTreeSet::new();
        for (i, s) in self.sets.iter_mut().enumerate() {
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            if live.contains(&i) {
                live_rules.extend(s.iter().copied());
            } else if !s.is_empty() {
                self.set_index.remove(s);
                s.clear();
                self.free_sets.insert(i);
            }
        }
        for (i, r) in self.rules.iter_mut().enumerate() {
            let i = u32::try_from(i).unwrap_or(u32::MAX);
            if !live_rules.contains(&i) && !self.free_rules.contains(&i) {
                self.rule_index.remove(r);
                *r = RichRule::default();
                self.free_rules.insert(i);
            }
        }
    }

    /// Rules interned (live ones; reclaimed slots don't count).
    pub fn rule_count(&self) -> usize {
        self.rules.len().saturating_sub(self.free_rules.len())
    }

    /// Slots in the rule and set arrays (live and reclaimed).
    pub fn slots(&self) -> (usize, usize) {
        (self.rules.len(), self.sets.len())
    }

    /// The `rich.json` bytes, or [`RichError::Limits`] when the reader would refuse them.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RichError> {
        let elements: usize = self.sets.iter().map(Vec::len).sum();
        if self.rules.len() > MAX_RULES
            || self.sets.len() > MAX_SETS
            || elements > MAX_SET_ELEMENTS
            || self.sets.iter().any(|s| s.len() > MAX_SET_LEN)
        {
            return Err(RichError::Limits);
        }
        let b = serde_json::to_vec(&RichFileOut {
            format: FORMAT,
            entities: &self.entities,
            rules: &self.rules,
            sets: &self.sets,
        })?;
        if b.len() > MAX_RICH_BYTES {
            return Err(RichError::TooLarge);
        }
        // Parsed as the reader parses it, under the same budget, so a segment whose parsed form
        // the edge would refuse is never written (review round 2, CR1).
        parse(&b)?;
        Ok(b)
    }
}

/// A loaded `rich.json`.
#[derive(Debug, Default)]
pub struct RichSegment {
    rules: Vec<RichRule>,
    sets: Vec<Vec<u32>>,
    unlinked: usize,
    memory: usize,
}

impl RichSegment {
    /// An empty segment (a bundle without rich rules).
    pub fn empty() -> RichSegment {
        RichSegment::default()
    }

    /// Parses, checks and links a `rich.json` (within the module docs' limits).
    pub fn from_bytes(data: &[u8]) -> Result<RichSegment, RichError> {
        Self::load(data).map(|(seg, _)| seg)
    }

    /// [`RichSegment::from_bytes`], also giving back the entity table.
    fn load(data: &[u8]) -> Result<(RichSegment, EntityTable), RichError> {
        let p = parse(data)?;
        if p.format != FORMAT {
            return Err(RichError::Format(p.format));
        }
        for (i, s) in p.sets.iter().enumerate() {
            if s.iter()
                .any(|&r| usize::try_from(r).map_or(true, |r| r >= p.rules.len()))
            {
                return Err(RichError::Index(i));
            }
        }
        let mut rules = p.rules;
        let mut unlinked = 0usize;
        // Linking swaps each entity reference for the table's (an equal prefix and a shared
        // `Arc`), so what the rules were charged stays what they hold.
        for r in rules.iter_mut() {
            if !p.entities.link(r) {
                unlinked = unlinked.saturating_add(1);
            }
        }
        // The table itself goes; an expansion stays (once) while a linked rule shares it.
        let mut kept: BTreeSet<&str> = BTreeSet::new();
        for r in &rules {
            let refs = r
                .denyallow_entities
                .iter()
                .chain(r.unless.iter().flat_map(|u| u.denyallow_entities.iter()));
            kept.extend(refs.filter(|e| e.is_expanded()).map(|e| e.prefix.as_str()));
        }
        let shared = kept
            .iter()
            .filter_map(|k| p.entities.get(k))
            .fold(0usize, |a, e| a.saturating_add(e.memory_usage()));
        let memory = p.memory.saturating_sub(p.table_memory).saturating_add(shared);
        Ok((
            RichSegment {
                rules,
                sets: p.sets,
                unlinked,
                memory,
            },
            p.entities,
        ))
    }

    /// The rules of set `idx` (empty for an unknown set; parts check their indices against
    /// [`RichSegment::set_count`] when they load or move, so a lookup never meets one).
    pub fn set(&self, idx: u32) -> &[u32] {
        usize::try_from(idx)
            .ok()
            .and_then(|i| self.sets.get(i))
            .map_or(&[], Vec::as_slice)
    }

    /// True when `idx` names a set.
    pub fn has_set(&self, idx: u32) -> bool {
        usize::try_from(idx).is_ok_and(|i| i < self.sets.len())
    }

    /// Rule `idx`.
    pub fn rule(&self, idx: u32) -> Option<&RichRule> {
        usize::try_from(idx).ok().and_then(|i| self.rules.get(i))
    }

    /// Rules naming an entity the table doesn't carry (they fail safe).
    pub fn unlinked(&self) -> usize {
        self.unlinked
    }

    /// Rules held.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Sets held.
    pub fn set_count(&self) -> usize {
        self.sets.len()
    }

    /// Bytes held by the parsed segment: every allocation of its rules, sets and entity table, as
    /// charged while parsing (see the module docs).
    pub fn memory_usage(&self) -> usize {
        self.memory
    }
}

/// Checks that a part's largest rich index names a set of `rich` (review round 1, B6).
pub fn check_rich_idx(max: Option<u32>, rich: &RichSegment) -> Result<(), String> {
    match max {
        Some(i) if !rich.has_set(i) => Err(format!(
            "rich_idx {i} is out of range for a rich.json of {} sets",
            rich.set_count()
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_rules::Flags;
    use picket_rules::modifiers::DnsTypeCond;

    fn rr(t: &str) -> RichRule {
        RichRule {
            flags: Flags::B_EXACT,
            dnstype: DnsTypeCond::parse(t),
            ..RichRule::default()
        }
    }

    #[test]
    fn interning_and_roundtrip() {
        let mut b = RichBuilder::new();
        let s1 = b.set(&[rr("A"), rr("AAAA")]);
        let s2 = b.set(&[rr("AAAA"), rr("A"), rr("A")]);
        assert_eq!(s1, s2);
        let s3 = b.set(&[rr("MX")]);
        assert_ne!(s1, s3);
        assert_eq!(b.rule_count(), 3);
        let seg = RichSegment::from_bytes(&b.to_bytes().unwrap()).unwrap();
        assert_eq!(seg.set(s1).len(), 2);
        assert_eq!(seg.rule(seg.set(s3)[0]), Some(&rr("MX")));
        assert!(seg.set(99).is_empty());
        assert_eq!(seg.unlinked(), 0);
    }

    #[test]
    fn refusals() {
        assert!(RichSegment::from_bytes(b"{\"format\":2}").is_err());
        assert!(matches!(
            RichSegment::from_bytes(b"{\"format\":1,\"rules\":[],\"sets\":[[0]]}"),
            Err(RichError::Index(0))
        ));
        assert!(RichSegment::from_bytes(b"[").is_err());
        // An entity missing from the table: counted, and the rule fails safe.
        let seg = RichSegment::from_bytes(
            br#"{"format":1,"rules":[{"flags":3,"denyallow_entities":[{"prefix":"tracker"}]}],"sets":[[0]]}"#,
        )
        .unwrap();
        assert_eq!(seg.unlinked(), 1);
        assert!(seg.rule(0).unwrap().has_unexpanded_entity());
    }

    /// Review round 1, B8 (a): counts are checked while parsing, and the reported memory is the
    /// parsed structures', not the JSON's (a `{"flags":1}` rule is 12 bytes of JSON and ~384 in
    /// RAM).
    #[test]
    fn limits_while_parsing_and_true_memory() {
        let doc = |rules: usize, sets: &str| {
            let mut s = String::from("{\"format\":1,\"rules\":[");
            for i in 0..rules {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("{\"flags\":1}");
            }
            s.push_str("],\"sets\":");
            s.push_str(sets);
            s.push('}');
            s.into_bytes()
        };
        let ok = RichSegment::from_bytes(&doc(1000, "[[0],[1,2]]")).unwrap();
        assert!(
            ok.memory_usage() >= 1000 * std::mem::size_of::<RichRule>(),
            "{}",
            ok.memory_usage()
        );
        assert!(matches!(
            RichSegment::from_bytes(&doc(MAX_RULES + 1, "[]")),
            Err(RichError::Limits)
        ));
        let big_set = format!("[[{}]]", vec!["0"; MAX_SET_LEN + 1].join(","));
        assert!(matches!(
            RichSegment::from_bytes(&doc(1, &big_set)),
            Err(RichError::Limits)
        ));
        let many = format!("[{}]", vec!["[0]"; MAX_SETS + 1].join(","));
        assert!(matches!(
            RichSegment::from_bytes(&doc(1, &many)),
            Err(RichError::Limits)
        ));
        let elems = format!(
            "[{}]",
            vec![vec!["0"; 60_000].join(","); 18]
                .iter()
                .map(|s| format!("[{s}]"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(matches!(
            RichSegment::from_bytes(&doc(1, &elems)),
            Err(RichError::Limits)
        ));
        // The writer refuses what the reader would.
        let mut b = RichBuilder::new();
        for i in 0..=MAX_RULES {
            b.rule(&RichRule {
                flags: Flags(1),
                order: Some(picket_rules::order::MatchOrder {
                    gram: None,
                    seq: i as u32,
                }),
                ..RichRule::default()
            });
        }
        assert!(matches!(b.to_bytes(), Err(RichError::Limits)));
    }

    /// Review round 2, CR1: the writer parses its output as the reader does, so it refuses a
    /// segment the reader would (here an entity whose suffix rule is longer than any name); and
    /// the reader stops an entity past its rule cap while parsing.
    #[test]
    fn writer_refuses_what_the_reader_refuses() {
        use picket_rules::psl::SuffixRule;
        let mut t = EntityTable::default();
        t.insert(&EntityExpansion::from_parts(
            "tracker".into(),
            vec![SuffixRule {
                rule: "a".repeat(MAX_SUFFIX_RULE + 1),
                icann: true,
            }],
        ));
        let mut b = RichBuilder::new();
        b.set(&[rr("A")]);
        b.set_entities(t);
        assert!(b.to_bytes().is_err());
        let rules = vec!["{\"rule\":\"a\"}"; MAX_EXPANSION_RULES + 1].join(",");
        let doc = format!("{{\"format\":1,\"entities\":[{{\"prefix\":\"x\",\"rules\":[{rules}]}}]}}");
        let e = RichSegment::from_bytes(doc.as_bytes()).unwrap_err();
        assert!(e.to_string().contains("suffix rules"), "{e}");
    }

    /// Review round 1, B6: reclaimed slots keep every live index and are reused, so a long run of
    /// incremental builds doesn't grow the segment.
    #[test]
    fn retain_keeps_live_indices_and_reuses_slots() {
        let mut b = RichBuilder::new();
        let keep = b.set(&[rr("A")]);
        let dead = b.set(&[rr("MX"), rr("TXT")]);
        let both = b.set(&[rr("A"), rr("AAAA")]);
        let bytes = b.to_bytes().unwrap();
        let mut b = RichBuilder::from_previous(&bytes).unwrap();
        b.retain_sets(&[keep, both].into_iter().collect());
        assert_eq!(b.rule_count(), 2, "MX and TXT are reclaimed");
        let seg = RichSegment::from_bytes(&b.to_bytes().unwrap()).unwrap();
        assert!(seg.set(dead).is_empty());
        assert_eq!(seg.rule(seg.set(keep)[0]), Some(&rr("A")));
        // Next build: the indices hold, reclaimed slots are reused before the arrays grow.
        let mut b = RichBuilder::from_previous(&b.to_bytes().unwrap()).unwrap();
        assert_eq!(b.set(&[rr("A")]), keep);
        assert_eq!(b.set(&[rr("A"), rr("AAAA")]), both);
        let new = b.set(&[rr("CNAME"), rr("HTTPS")]);
        assert_eq!(new, dead, "the reclaimed set slot");
        assert_eq!(b.slots(), (4, 3), "no growth");
        let seg = RichSegment::from_bytes(&b.to_bytes().unwrap()).unwrap();
        let mut got: Vec<&RichRule> = seg.set(new).iter().map(|&i| seg.rule(i).unwrap()).collect();
        got.sort_by_key(|r| format!("{r:?}"));
        let mut want = [rr("CNAME"), rr("HTTPS")];
        want.sort_by_key(|r| format!("{r:?}"));
        assert_eq!(got, want.iter().collect::<Vec<_>>());
        assert_eq!(seg.rule(seg.set(keep)[0]), Some(&rr("A")));
        // Range checks.
        assert!(check_rich_idx(Some(2), &seg).is_ok());
        assert!(check_rich_idx(Some(3), &seg).is_err());
        assert!(check_rich_idx(None, &RichSegment::empty()).is_ok());
    }
}
