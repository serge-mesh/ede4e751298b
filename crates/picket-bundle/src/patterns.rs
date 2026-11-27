//! `patterns.bin` (bundles.md §4): wildcard and regex rules with a pre-built sparse DFA each.
//!
//! Layout, little-endian: a 16-byte header (magic `PKTPATS\0`, format `u32`, entry count `u32`),
//! then per entry, in bundle order: its length `u32`, then kind `u8` (1 sparse DFA, 2 lazy DFA,
//! 3 matches every text), target `u8` (0 the text form, 1 `http://` + it), flags `u16`, rich set
//! `u32` (`u32::MAX` none), cost `u32` (the pattern's admission cost, below; 0 for kind 3), the
//! source (`u16` length + bytes), the shortcut (`u8` present, `u16` length + bytes), the regex
//! (`u32` length + bytes; lazy entries only) and the DFA (`u32` length + bytes; sparse entries
//! only, `regex-automata`'s little-endian serialisation with `u32` state ids).
//!
//! The DFA runs on the name's AdGuard text form, or `http://` + it (rules.md §3), unanchored,
//! asking only whether it matches. A rule's urlfilter shortcut is part of AdGuard's semantics:
//! the rule matches only when its shortcut occurs in `http://` + text, whatever its regex says. The
//! reader rebuilds an Aho-Corasick automaton over the shortcuts, so only rules whose shortcut
//! occurs (plus rules without one) run. Every regex is built with picket-rules' syntax
//! ([`picket_rules::analysis::syntax_config`]) and NFA limit
//! ([`picket_rules::analysis::NFA_SIZE_LIMIT`]), as on core.
//!
//! Haystacks are always printable ASCII (the text form escapes every other byte), so a DFA's
//! Unicode word-boundary heuristic never quits.
//!
//! **Admission: one cost model** (README §2 "Bounded"; bundles.md §2 "Determinism", §6;
//! rules.md §3; review round 1, B3). A pattern's cost is the reference matcher's
//! ([`picket_rules::matcher::pattern_cost`]: its regex heap plus a fresh cache), and admission is
//! the reference's rule ([`picket_rules::matcher::pattern_admission`]): in bundle order, patterns
//! are kept while their costs fit [`picket_rules::matcher::pattern_admission_limit`] of the budget;
//! at the first that doesn't, it and every later one are dropped (patterns matching every text, and
//! those without a regex, cost nothing). The compiler takes the reference's decisions as they are
//! ([`PatternInput::admit`]), so it drops exactly what the reference drops (listing them in
//! [`BuiltPatterns::fates`] for core's `bundle_warning`), and writes each kept entry's cost. The
//! reader admits by the written costs with the same rule, so under the same budget it keeps every
//! entry, and the edge never holds a different set than core's reference.
//!
//! **Edge memory.** Each pattern gets the smaller automaton the cost allows: a sparse DFA when its
//! bytes fit [`DFA_CAP`] and either the cost or the lazy alternative, otherwise a lazy (hybrid)
//! DFA whose fixed cache is the cost less its NFA (at most [`LAZY_CACHE`], at least the lazy DFA's
//! minimum). The reference's cost holds two NFAs and fresh caches, so an automaton is usually well
//! under it; the exceptions are near-literal regexes the reference runs as a bare prefilter
//! (`/[!]/` costs 0 there), which need about a kilobyte here. So the writer adds up the automata
//! with the reader's own measure ([`BuiltPatterns::edge_memory`]) and refuses to write a segment
//! whose automata pass the budget (core then keeps the previous version and raises an alert,
//! rather than publish a set the edge would cut), and the reader refuses, never cuts, a segment
//! whose automata pass the budget (a crafted file understating its costs). Either way the edge
//! runs exactly the reference's set or keeps its current head. [`PatternSegment::memory_usage`]
//! reports everything held: automata, records, strings and the Aho-Corasick automaton.
//!
//! **Lazy DFAs** keep their cache behind a `Mutex` shared by the query threads. Only regexes whose
//! DFA passes the per-rule cap or their cost run lazily (rare in real lists), each search holds the
//! lock for one scan of a name of at most ~1 KB, and splitting a cache per thread would multiply
//! its memory past the pattern's cost; so the lock stays (documented trade-off).

use std::sync::Mutex;

use aho_corasick::{AhoCorasick, MatchKind as AcMatchKind};
use picket_rules::Flags;
use picket_rules::adguard::MatchTarget;
use picket_rules::analysis::{NFA_SIZE_LIMIT, syntax_config};
use picket_rules::matcher::pattern_admission_limit;
use picket_rules::rule::PatternSpec;
use regex_automata::dfa::{Automaton, StartKind, dense, sparse};
use regex_automata::nfa::thompson;
use regex_automata::{Input, hybrid};

use crate::FORMAT;
use crate::bytes::ByteReader;

/// The file magic.
pub const MAGIC: [u8; 8] = *b"PKTPATS\0";
/// Per-rule cap on a sparse DFA's size; larger ones ship as a lazy DFA.
pub const DFA_CAP: usize = 256 * 1024;
/// Determinisation memory for one DFA build.
const DETERMINIZE_CAP: usize = 4 * DFA_CAP;
/// The largest fixed cache a lazy DFA gets.
pub const LAZY_CACHE: usize = 256 * 1024;
/// The default budget for a segment's automata: the reference matcher's regex budget
/// ([`picket_rules::matcher::REGEX_CACHE_BUDGET`]), so both admit the same patterns.
pub const DEFAULT_BUDGET: usize = picket_rules::matcher::REGEX_CACHE_BUDGET;
/// Most entries in one file: 64 Ki, six times the count at which bundles.md §2 warns (10k
/// patterns). Each costs a record and its strings (~150 bytes) whatever its automaton, and those
/// without a shortcut run on every query, so the cap bounds both RAM and per-query work. The
/// writer refuses to write more (core then raises an alert for the bundle) rather than drop some
/// the reference would run. Policy bound (owner to confirm).
pub const MAX_ENTRIES: usize = 64 * 1024;
/// No rich set.
pub const NO_RICH: u32 = u32::MAX;

/// Distinct shortcuts a lookup remembers having run (a 1 KiB stack array).
const SEEN_CAP: usize = 256;

const KIND_DFA: u8 = 1;
const KIND_LAZY: u8 = 2;
const KIND_ALL: u8 = 3;

/// Why `patterns.bin` is refused, or can't be written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PatternsError {
    #[error("not a patterns file")]
    Magic,
    #[error("patterns format {0} is not supported")]
    Format(u32),
    #[error("patterns entry {0} is malformed: {1}")]
    Entry(usize, &'static str),
    #[error("patterns file is over its limits")]
    Limits,
    #[error("patterns entry {0}: DFA refused: {1}")]
    Dfa(usize, String),
}

/// What the writer did with one input pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternFate {
    /// Written as a sparse DFA.
    Dfa,
    /// Written as a regex for a lazy DFA (its DFA is over [`DFA_CAP`] or its cost).
    Lazy,
    /// Matches every text holding its shortcut (no automaton).
    All,
    /// Matches nothing (`matches_nothing`, or a regex Go refuses): left out.
    Nothing,
    /// Too large to build even as a lazy DFA: dropped (rules.md §3; core raises `bundle_warning`).
    TooLarge,
    /// Past the memory budget: dropped (core raises `bundle_warning`).
    OverBudget,
}

/// The reference matcher's admission decision for one pattern
/// ([`picket_rules::matcher::pattern_admission`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternAdmit {
    /// Resident, at this cost ([`picket_rules::matcher::pattern_cost`]).
    Resident { cost: usize },
    /// Past the budget: dropped.
    OverBudget,
    /// Its regex doesn't build: dropped.
    TooLarge,
    /// Not decided by an admission (patterns matching every text, regex-less ones, and callers
    /// without a budget): the writer costs a regex itself and admits it by the reference's rule,
    /// like every written entry ([`build`]).
    Free,
}

/// One input to [`build`]: a pattern, the rich set its rule's conditions are in, and its
/// admission.
#[derive(Clone, Debug)]
pub struct PatternInput {
    pub spec: PatternSpec,
    /// The `rich.json` set (when the spec has `HAS_RICH`).
    pub rich_set: Option<u32>,
    pub admit: PatternAdmit,
}

enum Built {
    Dfa(Vec<u8>),
    Lazy(String),
    All,
}

fn nfa_config() -> thompson::Config {
    thompson::Config::new()
        .nfa_size_limit(Some(NFA_SIZE_LIMIT))
        .which_captures(thompson::WhichCaptures::None)
}

/// The automaton for a resident regex (see the module docs) and the bytes it holds.
fn build_one(regex: &str, cost: usize) -> Result<(Built, usize), PatternFate> {
    let dfa = dense::Builder::new()
        .syntax(syntax_config())
        .thompson(nfa_config())
        .configure(
            dense::Config::new()
                .start_kind(StartKind::Unanchored)
                .unicode_word_boundary(true)
                .minimize(false)
                .dfa_size_limit(Some(DFA_CAP))
                .determinize_size_limit(Some(DETERMINIZE_CAP)),
        )
        .build(regex);
    let dfa = match dfa {
        Ok(d) => d
            .to_sparse()
            .ok()
            .map(|s| s.to_bytes_little_endian())
            .filter(|b| b.len() <= DFA_CAP),
        Err(_) => None,
    };
    if let Some(b) = &dfa
        && b.len() <= cost
    {
        let n = b.len();
        return Ok((Built::Dfa(dfa.unwrap_or_default()), n));
    }
    match (build_lazy(regex, cost), dfa) {
        (Ok((_, lazy)), Some(b)) if b.len() <= lazy => {
            let n = b.len();
            Ok((Built::Dfa(b), n))
        }
        (Ok((_, lazy)), _) => Ok((Built::Lazy(regex.to_string()), lazy)),
        (Err(_), Some(b)) => {
            let n = b.len();
            Ok((Built::Dfa(b), n))
        }
        (Err(_), None) => Err(PatternFate::TooLarge),
    }
}

/// A lazy DFA for `regex` whose fixed cache is `cost` less its NFA (at most [`LAZY_CACHE`], at
/// least the lazy DFA's minimum), and the bytes it can hold: the NFA plus that cache.
fn build_lazy(regex: &str, cost: usize) -> Result<(hybrid::dfa::DFA, usize), String> {
    let nfa = thompson::Compiler::new()
        .syntax(syntax_config())
        .configure(nfa_config())
        .build(regex)
        .map_err(|e| e.to_string())?;
    let heap = nfa.memory_usage();
    let capacity = cost.saturating_sub(heap).min(LAZY_CACHE);
    let cfg = hybrid::dfa::Config::new()
        .unicode_word_boundary(true)
        .cache_capacity(capacity)
        .skip_cache_capacity_check(true);
    let min = cfg.get_minimum_cache_capacity(&nfa).map_err(|e| e.to_string())?;
    let dfa = hybrid::dfa::Builder::new()
        .configure(cfg)
        .build_from_nfa(nfa)
        .map_err(|e| e.to_string())?;
    Ok((dfa, heap.saturating_add(capacity.max(min))))
}

/// What [`build`] produced.
#[derive(Clone, Debug)]
pub struct BuiltPatterns {
    pub bytes: Vec<u8>,
    /// Index-aligned with the inputs.
    pub fates: Vec<PatternFate>,
    /// The bytes the written automata take on the edge (the reader's measure), for core's
    /// `bundle_budget_mib` count.
    pub edge_memory: usize,
}

/// Writes `patterns.bin` from patterns in bundle order, keeping what their admission keeps (see
/// the module docs). Every written cost goes through the reference's admission rule, as the
/// reader applies it: once an entry's cost doesn't fit [`pattern_admission_limit`] of `budget`,
/// it and every later regex entry are [`PatternFate::OverBudget`] and left out (never the case for
/// the compiler's [`PatternAdmit::Resident`] costs, which the reference admitted under the same
/// budget; a [`PatternAdmit::Free`] regex from a direct caller can hit it), so the reader keeps
/// every entry written (review round 2, nit). Refused past [`MAX_ENTRIES`] written entries, or
/// when the automata would take more than `budget` on the edge (the reader would refuse the
/// segment).
pub fn build(inputs: &[PatternInput], budget: usize) -> Result<BuiltPatterns, PatternsError> {
    let mut fates = Vec::with_capacity(inputs.len());
    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut edge_memory = 0usize;
    let limit = pattern_admission_limit(budget);
    let mut used = 0usize;
    let mut full = false;
    for p in inputs {
        let regex = p.spec.regex.as_deref();
        // The reference's rule ([`picket_rules::matcher::pattern_admission`]) over written costs.
        let admit = |re: &str, cost: usize, used: &mut usize, full: &mut bool| {
            if used.saturating_add(cost) > limit {
                *full = true;
                return Err(PatternFate::OverBudget);
            }
            let built = build_one(re, cost)?;
            *used = used.saturating_add(cost);
            Ok((built, cost))
        };
        let decided: Result<((Built, usize), usize), PatternFate> = if p.spec.matches_all {
            Ok(((Built::All, 0), 0))
        } else {
            match (p.admit, regex) {
                (PatternAdmit::OverBudget, _) => Err(PatternFate::OverBudget),
                (PatternAdmit::TooLarge, _) => Err(PatternFate::TooLarge),
                (_, None) => Err(PatternFate::Nothing),
                (_, Some(_)) if full => Err(PatternFate::OverBudget),
                (PatternAdmit::Resident { cost }, Some(re)) => admit(re, cost, &mut used, &mut full),
                (PatternAdmit::Free, Some(re)) => match picket_rules::matcher::pattern_cost(re) {
                    Some(cost) => admit(re, cost, &mut used, &mut full),
                    None => Err(PatternFate::TooLarge),
                },
            }
        };
        let ((built, real), cost) = match decided {
            Ok(x) => x,
            Err(f) => {
                fates.push(f);
                continue;
            }
        };
        edge_memory = edge_memory.saturating_add(real);
        let cost = u32::try_from(cost).map_err(|_| PatternsError::Limits)?;
        let (kind, regex, dfa, fate) = match built {
            Built::Dfa(b) => (KIND_DFA, String::new(), b, PatternFate::Dfa),
            Built::Lazy(regex) => (KIND_LAZY, regex, Vec::new(), PatternFate::Lazy),
            Built::All => (KIND_ALL, String::new(), Vec::new(), PatternFate::All),
        };
        let mut e = Vec::new();
        e.push(kind);
        e.push(match p.spec.target {
            MatchTarget::Host => 0,
            MatchTarget::HttpHost => 1,
        });
        let flags = if p.spec.flags.contains(Flags::HAS_RICH) && p.rich_set.is_none() {
            p.spec.flags.without(Flags::HAS_RICH)
        } else {
            p.spec.flags
        };
        e.extend_from_slice(&flags.bits().to_le_bytes());
        let rich = if flags.contains(Flags::HAS_RICH) {
            p.rich_set.unwrap_or(NO_RICH)
        } else {
            NO_RICH
        };
        e.extend_from_slice(&rich.to_le_bytes());
        e.extend_from_slice(&cost.to_le_bytes());
        let src = p.spec.source.as_bytes();
        let src = src.get(..src.len().min(usize::from(u16::MAX))).unwrap_or(&[]);
        e.extend_from_slice(&u16::try_from(src.len()).unwrap_or(0).to_le_bytes());
        e.extend_from_slice(src);
        match &p.spec.shortcut {
            Some(s) => {
                e.push(1);
                let s = s.as_bytes();
                let s = s.get(..s.len().min(usize::from(u16::MAX))).unwrap_or(&[]);
                e.extend_from_slice(&u16::try_from(s.len()).unwrap_or(0).to_le_bytes());
                e.extend_from_slice(s);
            }
            None => {
                e.push(0);
                e.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        e.extend_from_slice(&u32::try_from(regex.len()).unwrap_or(0).to_le_bytes());
        e.extend_from_slice(regex.as_bytes());
        e.extend_from_slice(&u32::try_from(dfa.len()).unwrap_or(0).to_le_bytes());
        e.extend_from_slice(&dfa);
        entries.push(e);
        fates.push(fate);
    }
    if entries.len() > MAX_ENTRIES || edge_memory > budget {
        return Err(PatternsError::Limits);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT.to_le_bytes());
    out.extend_from_slice(&u32::try_from(entries.len()).unwrap_or(0).to_le_bytes());
    for e in &entries {
        out.extend_from_slice(&u32::try_from(e.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(e);
    }
    Ok(BuiltPatterns {
        bytes: out,
        fates,
        edge_memory,
    })
}

struct LazyDfa {
    dfa: hybrid::dfa::DFA,
    cache: Mutex<hybrid::dfa::Cache>,
}

enum Automaton_ {
    Dfa(Box<sparse::DFA<Vec<u8>>>),
    Lazy(Box<LazyDfa>),
    All,
}

/// One loaded pattern.
pub struct Pattern {
    automaton: Automaton_,
    target: MatchTarget,
    flags: Flags,
    rich: Option<u32>,
    /// The admission cost written for it.
    cost: usize,
    /// The bytes its automaton can hold (a DFA's own, a lazy DFA's NFA plus its full cache).
    automaton_bytes: usize,
    source: String,
    shortcut: Option<String>,
}

impl std::fmt::Debug for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pattern")
            .field("source", &self.source)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl Pattern {
    /// The AdGuard pattern (`||ads*.example^`, `/regex/`).
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Plain `_EXACT` level bits, or `HAS_RICH` with [`Pattern::rich_set`].
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// The rich set, with `HAS_RICH`.
    pub fn rich_set(&self) -> Option<u32> {
        self.rich
    }

    /// True when it runs as a lazy DFA.
    pub fn is_lazy(&self) -> bool {
        matches!(self.automaton, Automaton_::Lazy(_))
    }

    /// Runs the automaton (the shortcut must already be known to occur).
    fn run(&self, text: &[u8], url: &[u8]) -> bool {
        let hay = match self.target {
            MatchTarget::Host => text,
            MatchTarget::HttpHost => url,
        };
        let input = Input::new(hay).earliest(true);
        match &self.automaton {
            Automaton_::All => true,
            Automaton_::Dfa(d) => matches!(d.try_search_fwd(&input), Ok(Some(_))),
            Automaton_::Lazy(l) => match l.cache.lock() {
                Ok(mut c) => matches!(l.dfa.try_search_fwd(&mut c, &input), Ok(Some(_))),
                // A poisoned lock: search with a fresh cache rather than miss.
                Err(_) => {
                    let mut c = l.dfa.create_cache();
                    matches!(l.dfa.try_search_fwd(&mut c, &input), Ok(Some(_)))
                }
            },
        }
    }

    /// Bytes held: the record, its strings and its automaton.
    fn memory_usage(&self) -> usize {
        std::mem::size_of::<Pattern>()
            .saturating_add(self.automaton_bytes)
            .saturating_add(self.source.capacity())
            .saturating_add(self.shortcut.as_ref().map_or(0, String::capacity))
    }
}

/// A loaded `patterns.bin`.
pub struct PatternSegment {
    patterns: Vec<Pattern>,
    ac: Option<AhoCorasick>,
    /// Aho-Corasick pattern id → the patterns with that shortcut.
    ac_targets: Vec<Vec<u32>>,
    /// Patterns without a shortcut: they run on every query.
    unshortcut: Vec<u32>,
    over_budget: usize,
    memory: usize,
}

impl std::fmt::Debug for PatternSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternSegment")
            .field("patterns", &self.patterns.len())
            .field("over_budget", &self.over_budget)
            .finish_non_exhaustive()
    }
}

impl PatternSegment {
    /// A segment with no patterns.
    pub fn empty() -> PatternSegment {
        PatternSegment {
            patterns: Vec::new(),
            ac: None,
            ac_targets: Vec::new(),
            unshortcut: Vec::new(),
            over_budget: 0,
            memory: 0,
        }
    }

    /// Parses `patterns.bin`, validating every DFA (`sparse::DFA::from_bytes`, the safe,
    /// validating constructor), admitting entries by their written costs within `budget` (see the
    /// module docs).
    pub fn from_bytes(data: &[u8], budget: usize) -> Result<PatternSegment, PatternsError> {
        let mut r = ByteReader::new(data);
        let magic: [u8; 8] = r.array().map_err(|_| PatternsError::Magic)?;
        if magic != MAGIC {
            return Err(PatternsError::Magic);
        }
        let format = r.u32().map_err(|_| PatternsError::Magic)?;
        if format != FORMAT {
            return Err(PatternsError::Format(format));
        }
        let count =
            usize::try_from(r.u32().map_err(|_| PatternsError::Magic)?).map_err(|_| PatternsError::Limits)?;
        // Each entry takes at least its length field and fixed fields.
        if count > MAX_ENTRIES || count > r.remaining() / 20 {
            return Err(PatternsError::Limits);
        }
        let limit = pattern_admission_limit(budget);
        let mut patterns = Vec::with_capacity(count);
        let mut used = 0usize;
        let mut real = 0usize;
        let mut over_budget = 0usize;
        for i in 0..count {
            let len = usize::try_from(r.u32().map_err(|_| PatternsError::Entry(i, "length"))?)
                .map_err(|_| PatternsError::Entry(i, "length"))?;
            let body = r.bytes(len).map_err(|_| PatternsError::Entry(i, "length"))?;
            if over_budget > 0 {
                over_budget = over_budget.saturating_add(1);
                continue;
            }
            // The cost is in the fixed fields, before anything is built.
            let cost = entry_cost(i, body)?;
            if used.saturating_add(cost) > limit {
                over_budget = over_budget.saturating_add(1);
                continue;
            }
            let p = parse_entry(i, body)?;
            used = used.saturating_add(p.cost);
            real = real.saturating_add(p.automaton_bytes);
            if real > budget {
                // Automata past the whole budget: costs that understate them (a crafted file).
                return Err(PatternsError::Limits);
            }
            patterns.push(p);
        }
        if r.remaining() != 0 {
            return Err(PatternsError::Entry(count, "trailing bytes"));
        }
        let mut shortcuts: Vec<&str> = patterns.iter().filter_map(|p| p.shortcut.as_deref()).collect();
        shortcuts.sort_unstable();
        shortcuts.dedup();
        let mut ac_targets: Vec<Vec<u32>> = vec![Vec::new(); shortcuts.len()];
        let mut unshortcut = Vec::new();
        for (pi, p) in patterns.iter().enumerate() {
            let pi = u32::try_from(pi).unwrap_or(u32::MAX);
            match p.shortcut.as_deref() {
                Some(s) => {
                    if let Ok(k) = shortcuts.binary_search(&s)
                        && let Some(t) = ac_targets.get_mut(k)
                    {
                        t.push(pi);
                    }
                }
                None => unshortcut.push(pi),
            }
        }
        let ac = if shortcuts.is_empty() {
            None
        } else {
            match AhoCorasick::builder()
                .match_kind(AcMatchKind::Standard)
                .build(&shortcuts)
            {
                Ok(ac) => Some(ac),
                Err(_) => {
                    // Without the automaton every pattern is checked directly (their shortcuts too).
                    unshortcut = (0..patterns.len())
                        .filter_map(|i| u32::try_from(i).ok())
                        .collect();
                    ac_targets.clear();
                    None
                }
            }
        };
        let memory = patterns
            .iter()
            .map(Pattern::memory_usage)
            .sum::<usize>()
            .saturating_add(
                patterns
                    .capacity()
                    .saturating_sub(patterns.len())
                    .saturating_mul(std::mem::size_of::<Pattern>()),
            )
            .saturating_add(ac.as_ref().map_or(0, AhoCorasick::memory_usage))
            .saturating_add(
                ac_targets
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Vec<u32>>()),
            )
            .saturating_add(
                ac_targets
                    .iter()
                    .map(|t| t.capacity().saturating_mul(4))
                    .sum::<usize>(),
            )
            .saturating_add(unshortcut.capacity().saturating_mul(4));
        Ok(PatternSegment {
            patterns,
            ac,
            ac_targets,
            unshortcut,
            over_budget,
            memory,
        })
    }

    /// Patterns left out for want of memory (they match nothing; the edge counts them).
    pub fn over_budget(&self) -> usize {
        self.over_budget
    }

    /// Patterns held.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// True with no patterns.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Pattern `i`.
    pub fn get(&self, i: u32) -> Option<&Pattern> {
        usize::try_from(i).ok().and_then(|i| self.patterns.get(i))
    }

    /// Bytes held (see the module docs).
    pub fn memory_usage(&self) -> usize {
        self.memory
    }

    /// The largest rich set a pattern names (checked against the part's `rich.json`).
    pub fn max_rich_idx(&self) -> Option<u32> {
        self.patterns.iter().filter_map(|p| p.rich).max()
    }

    /// Calls `hit` with each pattern matching `text` (the AdGuard text form) given `url`
    /// (`http://` + text), in pattern order within each group, each pattern at most once.
    pub fn for_each_match(&self, text: &[u8], url: &[u8], mut hit: impl FnMut(u32, &Pattern)) {
        if self.patterns.is_empty() {
            return;
        }
        // Shortcuts already run, on the stack (build-and-test.md §4: no allocation; review round
        // 1, B9). Past `SEEN_CAP` distinct shortcuts in one name a later repeat runs its patterns
        // again: a repeated hit changes no decision, so that only costs time, and only on a name
        // holding that many shortcuts.
        let mut seen = [0u32; SEEN_CAP];
        let mut n_seen = 0usize;
        if let Some(ac) = &self.ac {
            for m in ac.find_overlapping_iter(url) {
                let id = u32::try_from(m.pattern().as_usize()).unwrap_or(u32::MAX);
                if seen.get(..n_seen).unwrap_or(&[]).contains(&id) {
                    continue;
                }
                if let Some(slot) = seen.get_mut(n_seen) {
                    *slot = id;
                    n_seen = n_seen.saturating_add(1);
                }
                for &pi in self
                    .ac_targets
                    .get(m.pattern().as_usize())
                    .map_or(&[][..], Vec::as_slice)
                {
                    if let Some(p) = self.get(pi)
                        && p.run(text, url)
                    {
                        hit(pi, p);
                    }
                }
            }
        }
        for &pi in &self.unshortcut {
            let Some(p) = self.get(pi) else { continue };
            // Without an automaton (build failure) shortcuts are checked here.
            if let Some(sc) = p.shortcut.as_deref()
                && !contains(url, sc.as_bytes())
            {
                continue;
            }
            if p.run(text, url) {
                hit(pi, p);
            }
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

/// An entry's admission cost (0 for an entry matching every text), from its fixed fields.
fn entry_cost(i: usize, body: &[u8]) -> Result<usize, PatternsError> {
    let e = |m| PatternsError::Entry(i, m);
    let mut r = ByteReader::new(body);
    let kind = r.u8().map_err(|_| e("kind"))?;
    let _target = r.u8().map_err(|_| e("target"))?;
    let _flags = r.u16().map_err(|_| e("flags"))?;
    let _rich = r.u32().map_err(|_| e("rich"))?;
    let cost = r.u32().map_err(|_| e("cost"))?;
    Ok(if kind == KIND_ALL {
        0
    } else {
        usize::try_from(cost).map_err(|_| e("cost"))?
    })
}

fn parse_entry(i: usize, body: &[u8]) -> Result<Pattern, PatternsError> {
    let e = |m| PatternsError::Entry(i, m);
    let mut r = ByteReader::new(body);
    let kind = r.u8().map_err(|_| e("kind"))?;
    let target = match r.u8().map_err(|_| e("target"))? {
        0 => MatchTarget::Host,
        1 => MatchTarget::HttpHost,
        _ => return Err(e("target")),
    };
    let flags = Flags(r.u16().map_err(|_| e("flags"))?);
    let rich = r.u32().map_err(|_| e("rich"))?;
    let cost = usize::try_from(r.u32().map_err(|_| e("cost"))?).map_err(|_| e("cost"))?;
    let has_rich = flags.contains(Flags::HAS_RICH);
    if flags.without(Flags::HAS_RICH).without(Flags::ALL_EXACT) != Flags::NONE
        || (has_rich && (rich == NO_RICH || flags != Flags::HAS_RICH))
        || (!has_rich && (rich != NO_RICH || flags.is_empty()))
    {
        return Err(e("flags"));
    }
    let slen = usize::from(r.u16().map_err(|_| e("source"))?);
    let source = std::str::from_utf8(r.bytes(slen).map_err(|_| e("source"))?)
        .map_err(|_| e("source"))?
        .to_string();
    let has_sc = r.u8().map_err(|_| e("shortcut"))?;
    let sclen = usize::from(r.u16().map_err(|_| e("shortcut"))?);
    let sc = r.bytes(sclen).map_err(|_| e("shortcut"))?;
    let shortcut = match has_sc {
        0 if sclen == 0 => None,
        1 => Some(std::str::from_utf8(sc).map_err(|_| e("shortcut"))?.to_string()),
        _ => return Err(e("shortcut")),
    };
    let rlen = usize::try_from(r.u32().map_err(|_| e("regex"))?).map_err(|_| e("regex"))?;
    let regex = std::str::from_utf8(r.bytes(rlen).map_err(|_| e("regex"))?).map_err(|_| e("regex"))?;
    let dlen = usize::try_from(r.u32().map_err(|_| e("dfa"))?).map_err(|_| e("dfa"))?;
    let dfa_bytes = r.bytes(dlen).map_err(|_| e("dfa"))?;
    if r.remaining() != 0 {
        return Err(e("trailing bytes"));
    }
    let (automaton, automaton_bytes, cost) = match kind {
        KIND_DFA => {
            if !regex.is_empty() || dlen > DFA_CAP {
                return Err(e("dfa"));
            }
            let (d, n) =
                sparse::DFA::from_bytes(dfa_bytes).map_err(|x| PatternsError::Dfa(i, x.to_string()))?;
            if n != dfa_bytes.len() {
                return Err(e("dfa length"));
            }
            if d.start_kind() == StartKind::Anchored {
                return Err(e("dfa start"));
            }
            // Measured as the writer measures it: its serialised size (what the owned copy holds).
            (Automaton_::Dfa(Box::new(d.to_owned())), dlen, cost)
        }
        KIND_LAZY => {
            if !dfa_bytes.is_empty() {
                return Err(e("lazy"));
            }
            let (dfa, bytes) = build_lazy(regex, cost).map_err(|x| PatternsError::Dfa(i, x))?;
            let cache = Mutex::new(dfa.create_cache());
            (Automaton_::Lazy(Box::new(LazyDfa { dfa, cache })), bytes, cost)
        }
        KIND_ALL => {
            if !regex.is_empty() || !dfa_bytes.is_empty() {
                return Err(e("all"));
            }
            (Automaton_::All, 0, 0)
        }
        _ => return Err(e("kind")),
    };
    Ok(Pattern {
        automaton,
        target,
        flags,
        rich: has_rich.then_some(rich),
        cost,
        automaton_bytes,
        source,
        shortcut,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_rules::classify::{Item, Line, classify_adblock_line};

    fn spec(line: &str) -> PatternSpec {
        match classify_adblock_line(line, false) {
            Line::Items(v) => match v.into_iter().next() {
                Some(Item::Rule(r)) => r.pattern_spec().unwrap(),
                o => panic!("{o:?}"),
            },
            o => panic!("{o:?}"),
        }
    }

    fn input(line: &str) -> PatternInput {
        PatternInput {
            spec: spec(line),
            rich_set: None,
            admit: PatternAdmit::Free,
        }
    }

    fn cost(p: &PatternInput) -> usize {
        picket_rules::matcher::pattern_cost(p.spec.regex.as_deref().unwrap()).unwrap()
    }

    /// The smallest budget whose admission limit holds `need`.
    fn budget_for(need: usize) -> usize {
        (need..need * 2)
            .find(|&b| pattern_admission_limit(b) >= need)
            .unwrap()
    }

    fn matches(seg: &PatternSegment, text: &str) -> Vec<u32> {
        let url = format!("http://{text}");
        let mut v = Vec::new();
        seg.for_each_match(text.as_bytes(), url.as_bytes(), |i, _| v.push(i));
        v.sort_unstable();
        v
    }

    #[test]
    fn dfa_lazy_all() {
        let mut inputs: Vec<PatternInput> = ["||ads*.example^", "/^track[0-9]+\\./", "||*^", "/[!]/"]
            .iter()
            .map(|l| input(l))
            .collect();
        inputs[2].spec.matches_all = true;
        let built = build(&inputs, DEFAULT_BUDGET).unwrap();
        assert_eq!(
            built.fates,
            vec![
                PatternFate::Dfa,
                PatternFate::Dfa,
                PatternFate::All,
                PatternFate::Dfa
            ]
        );
        let seg = PatternSegment::from_bytes(&built.bytes, DEFAULT_BUDGET).unwrap();
        assert_eq!(matches(&seg, "ads1.example"), vec![0, 2]);
        assert_eq!(matches(&seg, "track12.net"), vec![1, 2]);
        assert_eq!(matches(&seg, "a!b.example"), vec![2, 3]);
        assert_eq!(seg.get(0).unwrap().source(), "||ads*.example^");
    }

    #[test]
    fn big_regex_goes_lazy_and_budget_cuts_in_order() {
        // A DFA far past its cost and the per-rule cap: lazy, with a cache sized from the cost.
        let big = input("/(?:a|b)*a(?:a|b){12}/");
        let built = build(std::slice::from_ref(&big), DEFAULT_BUDGET).unwrap();
        assert_eq!(built.fates[0], PatternFate::Lazy);
        let seg = PatternSegment::from_bytes(&built.bytes, DEFAULT_BUDGET).unwrap();
        assert!(seg.get(0).unwrap().is_lazy());
        assert_eq!(matches(&seg, "abbbbbbbbbbbb.example"), vec![0]);
        assert!(matches(&seg, "bbbbbbbbbbbbb.example").is_empty());
        let p = seg.get(0).unwrap();
        assert!(p.automaton_bytes <= p.cost, "{} > {}", p.automaton_bytes, p.cost);
        assert_eq!(
            built.edge_memory, p.automaton_bytes,
            "the writer measures as the reader"
        );
        // The reader cuts by the written costs, in order, as the reference would at that budget.
        let small = input("||ads*.example^");
        let all = vec![small.clone(), big.clone(), small.clone()];
        let built = build(&all, DEFAULT_BUDGET).unwrap();
        let seg = PatternSegment::from_bytes(&built.bytes, 1).unwrap();
        assert_eq!(seg.over_budget(), 3);
        assert!(seg.is_empty());
        let first = budget_for(cost(&small));
        let seg = PatternSegment::from_bytes(&built.bytes, first).unwrap();
        assert_eq!(
            (seg.len(), seg.over_budget()),
            (1, 2),
            "everything after the first miss"
        );
        // Admission decisions from the inputs: dropped ones aren't written.
        let mut dropped = all.clone();
        dropped[1].admit = PatternAdmit::OverBudget;
        dropped[2].admit = PatternAdmit::OverBudget;
        let built = build(&dropped, DEFAULT_BUDGET).unwrap();
        assert_eq!(
            built.fates,
            vec![PatternFate::Dfa, PatternFate::OverBudget, PatternFate::OverBudget]
        );
        assert_eq!(
            PatternSegment::from_bytes(&built.bytes, DEFAULT_BUDGET)
                .unwrap()
                .len(),
            1
        );
    }

    /// Review round 1, B3 (b): the writer and reader share one cost, so a segment written within a
    /// budget is read whole with that budget, DFA and lazy entries alike (the reader once counted
    /// a DFA's in-memory size plus the source and shortcut bytes, and dropped the tail).
    #[test]
    fn written_within_a_budget_reads_whole_with_it() {
        for lines in [
            vec!["/(?:ab|ab|ab|ab|ab|ab|ab|ab|ab|ab)+c/"],
            vec![
                "/(?:a|b)*a(?:a|b){12}/",
                "/(?:a|b)*b(?:a|b){12}/",
                "/(?:a|c)*a(?:a|c){12}/",
            ],
            vec!["/^ad0[a-z]+\\./", "/(?:a|b)*a(?:a|b){12}/", "/^ad1[a-z]+\\./"],
        ] {
            let mut inputs: Vec<PatternInput> = lines.iter().map(|l| input(l)).collect();
            let total: usize = inputs.iter().map(cost).sum();
            let budget = budget_for(total);
            for p in inputs.iter_mut() {
                p.admit = PatternAdmit::Resident { cost: cost(p) };
            }
            let built = build(&inputs, DEFAULT_BUDGET).unwrap();
            let seg = PatternSegment::from_bytes(&built.bytes, budget).unwrap();
            assert_eq!((seg.len(), seg.over_budget()), (lines.len(), 0), "{lines:?}");
        }
    }

    /// The reader trusts no cost: a segment whose automata take more than the whole budget is
    /// refused (not cut), whatever costs it claims; the writer refuses to write one.
    #[test]
    fn crafted_costs_are_refused() {
        let dfas: Vec<PatternInput> = (0..8)
            .map(|i| input(&format!("/^track{i}[0-9]+\\.example\\.(?:com|net|org)/")))
            .collect();
        let built = build(&dfas, DEFAULT_BUDGET).unwrap();
        assert!(built.edge_memory > 0);
        // A budget below the automata, with costs that fit its admission limit (a caller's
        // understated costs; real ones would be over the budget, the reference's rule): the writer
        // won't write the segment ...
        let understated: Vec<PatternInput> = dfas
            .iter()
            .cloned()
            .map(|mut p| {
                p.admit = PatternAdmit::Resident { cost: 1 };
                p
            })
            .collect();
        let u = build(&understated, DEFAULT_BUDGET).unwrap();
        assert_eq!(
            build(&understated, u.edge_memory - 1).unwrap_err(),
            PatternsError::Limits
        );
        // ... and a reader given costs of 1 for it refuses it rather than admit by cost.
        let mut b = built.bytes.clone();
        let mut off = 16;
        for _ in 0..8 {
            let len = u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize;
            b[off + 4 + 8..off + 4 + 12].copy_from_slice(&1u32.to_le_bytes());
            off += 4 + len;
        }
        assert_eq!(
            PatternSegment::from_bytes(&b, built.edge_memory - 1).unwrap_err(),
            PatternsError::Limits
        );
        assert_eq!(
            PatternSegment::from_bytes(&b, built.edge_memory).unwrap().len(),
            8
        );
        // A lazy entry's cache comes from its cost, so understating the cost shrinks it (to the
        // lazy DFA's minimum); the real sizes still bound the segment.
        let lazy = input("/(?:a|b)*a(?:a|b){12}/");
        let many: Vec<PatternInput> = (0..8).map(|_| lazy.clone()).collect();
        let built = build(&many, DEFAULT_BUDGET).unwrap();
        let mut b = built.bytes.clone();
        let mut off = 16;
        for _ in 0..8 {
            let len = u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize;
            b[off + 4 + 8..off + 4 + 12].copy_from_slice(&1u32.to_le_bytes());
            off += 4 + len;
        }
        let shrunk = PatternSegment::from_bytes(&b, DEFAULT_BUDGET).unwrap();
        let real: usize = (0..8).map(|i| shrunk.get(i).unwrap().automaton_bytes).sum();
        assert!(real < built.edge_memory, "{real} vs {}", built.edge_memory);
        assert_eq!(
            PatternSegment::from_bytes(&b, real - 1).unwrap_err(),
            PatternsError::Limits
        );
        assert_eq!(
            matches(&shrunk, "abbbbbbbbbbbb.example").len(),
            8,
            "a small cache still matches"
        );
    }

    #[test]
    fn shortcut_is_enforced() {
        // A pattern matches only when its shortcut occurs, whatever its regex says.
        let mut s = spec("||ads*^$dnstype=A");
        assert_eq!(s.shortcut.as_deref(), Some("ads"));
        s.matches_all = true;
        let built = build(
            &[PatternInput {
                spec: s.clone(),
                rich_set: Some(0),
                admit: PatternAdmit::Free,
            }],
            DEFAULT_BUDGET,
        )
        .unwrap();
        let seg = PatternSegment::from_bytes(&built.bytes, DEFAULT_BUDGET).unwrap();
        assert_eq!(seg.get(0).unwrap().rich_set(), Some(0));
        assert_eq!(matches(&seg, "xads.example"), vec![0]);
        assert!(matches(&seg, "adx.example").is_empty(), "no shortcut, no match");
    }

    /// Review round 2, nit: `Free` regex entries (direct callers; the compiler never writes one)
    /// are admitted by the reference's rule too: once one doesn't fit the admission limit, it and
    /// every later regex entry are dropped as over the budget (patterns matching every text stay),
    /// so the reader keeps every entry the writer wrote.
    #[test]
    fn free_entries_follow_the_admission_rule() {
        let regexes: Vec<PatternInput> = (0..6).map(|i| input(&format!("/^ad{i}[a-z]+x\\./"))).collect();
        let need: usize = regexes.iter().take(3).map(cost).sum();
        let budget = budget_for(need);
        let mut all = input("||*^");
        all.spec.matches_all = true;
        let mut inputs = regexes.clone();
        inputs.insert(4, all);
        let built = build(&inputs, budget).unwrap();
        use PatternFate::*;
        let written = |f: &PatternFate| matches!(f, Dfa | Lazy | All);
        assert!(built.fates[..3].iter().all(written), "{:?}", built.fates);
        assert_eq!(built.fates[3], OverBudget, "{:?}", built.fates);
        assert_eq!(built.fates[4], All, "matches every text: kept");
        assert!(
            built.fates[5..].iter().all(|f| *f == OverBudget),
            "{:?}",
            built.fates
        );
        let seg = PatternSegment::from_bytes(&built.bytes, budget).unwrap();
        assert_eq!(seg.over_budget(), 0, "the reader keeps every written entry");
        assert_eq!(seg.len(), built.fates.iter().filter(|f| written(f)).count());
    }

    #[test]
    fn refusals() {
        let built = build(&[input("||ads*.example^")], DEFAULT_BUDGET).unwrap();
        for cut in [0, 5, 16, 20, built.bytes.len() - 1] {
            assert!(PatternSegment::from_bytes(&built.bytes[..cut], DEFAULT_BUDGET).is_err());
        }
        let mut bad = built.bytes.clone();
        let n = bad.len();
        bad[n - 30] ^= 0xff;
        let _ = PatternSegment::from_bytes(&bad, DEFAULT_BUDGET);
        // The writer refuses more entries than the reader takes.
        let mut all = input("||*^");
        all.spec.matches_all = true;
        let many = vec![all; MAX_ENTRIES + 1];
        assert_eq!(build(&many, DEFAULT_BUDGET).unwrap_err(), PatternsError::Limits);
    }
}
