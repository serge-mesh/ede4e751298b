//! Proofs about pattern regexes (rules.md §3 "Dropped only when it can't change a decision").
//!
//! [`can_match`] decides whether a regex can match any string over an alphabet. It first walks the
//! regex's NFA restricted to that alphabet, taking look-around assertions as always true: linear
//! in the NFA's size, and exact when the regex has no look-around. Only a regex with look-around
//! that this walk can't rule out is then decided on its dense DFA, within [`PROOF_DFA_LIMIT`]. It
//! is sound: it answers `Some(false)` only when no such string exists, and `None` (callers keep
//! the rule) when it can't decide within those limits. The limits are sizes, not times, so a build
//! decides the same way every time (bundles.md §2 "Determinism"); they bound a proof's CPU (review
//! round 1, R7: a 2,000-pattern feed of `/(?:\w|-){900}N/` took 0.5 s per pattern on dense DFAs).

use regex_automata::dfa::{Automaton, StartKind, dense};
use regex_automata::hybrid::{self, LazyStateID};
use regex_automata::util::start;
use regex_automata::{Anchored, nfa::thompson, util::syntax};

use crate::adguard::{MatchTarget, URL_PREFIX};
use crate::rule::PatternSpec;

/// The NFA size limit for every pattern regex, the same on core and edge (bundles.md §4).
pub const NFA_SIZE_LIMIT: usize = 2 * 1024 * 1024;
/// The dense-DFA size limit for the proofs here (only regexes with look-around get that far).
pub const PROOF_DFA_LIMIT: usize = 1024 * 1024;

/// Rust's nesting limit for pattern regexes: Go accepts parse trees up to 1000 high (`maxHeight`),
/// and the translation adds at most one group level per Go level (regex-syntax's default is 250).
pub const NEST_LIMIT: u32 = 2_100;

/// The regex syntax every pattern regex is built with, on core and edge alike (picket-bundle must
/// use it too, or a deep regex Go accepts would fail to build there).
pub fn syntax_config() -> syntax::Config {
    syntax::Config::new()
        .unicode(true)
        .utf8(true)
        .nest_limit(NEST_LIMIT)
}

/// Bytes of ordinary names and IP text: `a-z0-9-_.` plus `:` for IPv6 (used to tell DNS rules
/// from URL-path rules, rules.md §2).
pub const ORDINARY_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-_.:";

/// Bytes a name's text form can hold: printable ASCII except `A`–`Z` (rules.md §3); IP text is a
/// subset.
pub fn text_alphabet() -> Vec<u8> {
    (0x20u8..=0x7e).filter(|b| !b.is_ascii_uppercase()).collect()
}

/// Can `regex` (Rust syntax, unanchored search) match some string made only of `alphabet` bytes?
/// `None` when undecided (the DFA is over the limits).
pub fn can_match(regex: &str, alphabet: &[u8]) -> Option<bool> {
    can_match_after(regex, b"", alphabet)
}

/// Can `regex` match some string `prefix` + (bytes of `alphabet`)*?
pub fn can_match_after(regex: &str, prefix: &[u8], alphabet: &[u8]) -> Option<bool> {
    let nfa = thompson::Compiler::new()
        .syntax(syntax_config())
        .configure(thompson::Config::new().nfa_size_limit(Some(NFA_SIZE_LIMIT)))
        .build(regex)
        .ok()?;
    if !nfa_reachable(&nfa, prefix, alphabet) {
        return Some(false);
    }
    if nfa.look_set_any().is_empty() {
        return Some(true);
    }
    dfa_can_match_after(regex, prefix, alphabet)
}

/// The epsilon closure of `from` (look-around taken as true): adds byte-consuming states to `out`;
/// true when a match state is reached.
fn closure(
    nfa: &thompson::NFA,
    from: regex_automata::util::primitives::StateID,
    seen: &mut std::collections::HashSet<regex_automata::util::primitives::StateID>,
    out: &mut Vec<regex_automata::util::primitives::StateID>,
) -> bool {
    use regex_automata::nfa::thompson::State;
    let mut stack = vec![from];
    let mut matched = false;
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        match nfa.state(id) {
            State::ByteRange { .. } | State::Sparse(_) | State::Dense(_) => out.push(id),
            State::Look { next, .. } | State::Capture { next, .. } => stack.push(*next),
            State::Union { alternates } => stack.extend(alternates.iter().copied()),
            State::BinaryUnion { alt1, alt2 } => {
                stack.push(*alt1);
                stack.push(*alt2);
            }
            State::Fail => {}
            State::Match { .. } => matched = true,
        }
    }
    matched
}

/// The states a byte-consuming NFA state moves to on `b`.
fn step(
    nfa: &thompson::NFA,
    id: regex_automata::util::primitives::StateID,
    b: u8,
    out: &mut Vec<regex_automata::util::primitives::StateID>,
) {
    use regex_automata::nfa::thompson::State;
    match nfa.state(id) {
        State::ByteRange { trans } => {
            if trans.start <= b && b <= trans.end {
                out.push(trans.next);
            }
        }
        State::Sparse(sp) => out.extend(
            sp.transitions
                .iter()
                .filter(|t| t.start <= b && b <= t.end)
                .map(|t| t.next),
        ),
        State::Dense(d) => {
            if let Some(&n) = d.transitions.get(usize::from(b))
                && n != regex_automata::util::primitives::StateID::ZERO
            {
                out.push(n);
            }
        }
        _ => {}
    }
}

/// Can the NFA reach a match on some `prefix` + alphabet* (look-around taken as true)?
fn nfa_reachable(nfa: &thompson::NFA, prefix: &[u8], alphabet: &[u8]) -> bool {
    // After the prefix: a set simulation.
    let mut cur = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if closure(nfa, nfa.start_unanchored(), &mut seen, &mut cur) {
        return true;
    }
    for &b in prefix {
        let mut moved = Vec::new();
        for &id in &cur {
            step(nfa, id, b, &mut moved);
        }
        let mut next = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for id in moved {
            if closure(nfa, id, &mut seen, &mut next) {
                return true;
            }
        }
        if next.is_empty() {
            return false;
        }
        cur = next;
    }
    // Then any alphabet bytes: plain reachability.
    let mut seen = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<_> = cur.iter().copied().collect();
    let mut visited: std::collections::HashSet<_> = cur.iter().copied().collect();
    while let Some(id) = queue.pop_front() {
        let mut moved = Vec::new();
        for &b in alphabet {
            step(nfa, id, b, &mut moved);
        }
        for t in moved {
            let mut out = Vec::new();
            if closure(nfa, t, &mut seen, &mut out) {
                return true;
            }
            for o in out {
                if visited.insert(o) {
                    queue.push_back(o);
                }
            }
        }
    }
    false
}

/// The dense-DFA proof (exact for look-around), within the proof limits.
fn dfa_can_match_after(regex: &str, prefix: &[u8], alphabet: &[u8]) -> Option<bool> {
    let dfa = dense::Builder::new()
        .configure(
            dense::Config::new()
                .start_kind(StartKind::Unanchored)
                .dfa_size_limit(Some(PROOF_DFA_LIMIT))
                .determinize_size_limit(Some(PROOF_DFA_LIMIT)),
        )
        .syntax(syntax_config())
        .thompson(thompson::Config::new().nfa_size_limit(Some(NFA_SIZE_LIMIT)))
        .build(regex)
        .ok()?;
    let cfg = start::Config::new().anchored(Anchored::No).look_behind(None);
    let mut state = dfa.start_state(&cfg).ok()?;
    for &b in prefix {
        state = dfa.next_state(state, b);
        if dfa.is_match_state(state) {
            return Some(true);
        }
        if dfa.is_dead_state(state) {
            return Some(false);
        }
        if dfa.is_quit_state(state) {
            return None;
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    seen.insert(state);
    queue.push_back(state);
    while let Some(s) = queue.pop_front() {
        if dfa.is_match_state(s) || dfa.is_match_state(dfa.next_eoi_state(s)) {
            return Some(true);
        }
        for &b in alphabet {
            let t = dfa.next_state(s, b);
            if dfa.is_quit_state(t) {
                return None;
            }
            if dfa.is_dead_state(t) {
                continue;
            }
            if dfa.is_match_state(t) {
                return Some(true);
            }
            if seen.insert(t) {
                queue.push_back(t);
            }
        }
        if seen.len() > 1_000_000 {
            return None;
        }
    }
    Some(false)
}

/// The compiler's drop test (rules.md §3): false only when the pattern provably can't match any
/// name's text form, IP text, or `http://` plus either, according to its match target. A regex Go
/// refuses matches nothing. Undecided → true (kept).
pub fn pattern_can_match(spec: &PatternSpec) -> bool {
    if spec.matches_all {
        return true;
    }
    let Some(re) = &spec.regex else { return false };
    let alphabet = text_alphabet();
    let prefix: &[u8] = match spec.target {
        MatchTarget::Host => b"",
        MatchTarget::HttpHost => URL_PREFIX.as_bytes(),
    };
    can_match_after(re, prefix, &alphabet).unwrap_or(true)
}

/// Bounds for one overlap proof (states explored); past them the proof answers "overlaps".
const OVERLAP_STATE_LIMIT: usize = 200_000;

/// The lazy-DFA cache of one overlap automaton. A proof that would need more states (the cache
/// would be cleared) answers "overlaps" (sound), so an automaton never holds more.
pub const OVERLAP_CACHE_BYTES: usize = 256 * 1024;

/// Work a bounded scan may still spend (README §2 "Bounded"): one unit per automaton transition,
/// key or rule pair visited, and per NFA state built.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    left: u64,
    spent: u64,
}

/// The budget ran out: the proof didn't finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exhausted;

impl Budget {
    pub fn new(units: u64) -> Budget {
        Budget {
            left: units,
            spent: 0,
        }
    }

    /// Spends `n` units, or fails when fewer are left.
    pub fn spend(&mut self, n: u64) -> Result<(), Exhausted> {
        if self.left < n {
            self.spent = self.spent.saturating_add(self.left);
            self.left = 0;
            return Err(Exhausted);
        }
        self.left = self.left.saturating_sub(n);
        self.spent = self.spent.saturating_add(n);
        Ok(())
    }

    /// Units spent so far.
    pub fn spent(&self) -> u64 {
        self.spent
    }
}

/// What an overlap proof can say about a pattern (bundles.md §2 cross-feed guardrail). Proofs run
/// over [`ORDINARY_ALPHABET`]: names with other bytes are rules.md §3's listed exception, and a
/// pattern only names with `#` or `/` bytes can trigger (`@@/\.(gif|png)#…/`) cancels nothing a
/// resolver sees (review round 2, CC3).
pub enum Overlap {
    /// The pattern matches no ordinary text (Go refuses its regex, or a bare `^`).
    Never,
    /// Taken as matching any text: it matches everything, or its automaton is over the limits.
    Always,
    /// Its lazy search automaton.
    Lazy(Box<LazyPattern>),
}

/// A pattern's lazy DFA over its match target, for overlap proofs: states are built only as a
/// proof reaches them, within [`OVERLAP_CACHE_BYTES`] (no dense DFA: building one cost up to
/// 0.1 s per pattern; review round 2, CC3). A search automaton (unanchored, for
/// [`patterns_overlap`]) or an anchored one, for the subtree proofs ([`Overlap::subtree_entry`]):
/// an anchored automaton dies once a match can't continue, so a walk over a key stops after a few
/// bytes instead of reading every key to its end.
pub struct LazyPattern {
    dfa: hybrid::dfa::DFA,
    cache: hybrid::dfa::Cache,
    /// A search automaton: the state after the match target's fixed prefix.
    start: LazyStateID,
    /// A search automaton: a match ended inside the prefix.
    matched: bool,
    anchored: bool,
    target: MatchTarget,
    /// Bytes it holds (its NFA and cache bound).
    bytes: usize,
    /// Its NFA's states: what building one new DFA state can cost, charged per state a proof
    /// expands (cached transitions cost one unit).
    nfa_states: u64,
}

/// Where a pattern's anchored automaton can be once a match has started before a key (in the
/// match target's prefix, in the labels before the key, or at the `.` before it) and read up to
/// the key: the entry into a key's subtree. Matches starting inside the key are another proof
/// ([`KeyMatcher`]).
pub enum SubtreeEntry {
    /// It can match before reaching the key: it overlaps every subtree.
    Always,
    States(Vec<LazyStateID>),
}

/// One transition: `None` when the automaton can't decide (its cache is full, or a quit byte),
/// which proofs take as "overlaps".
fn next(
    p: &mut LazyPattern,
    s: LazyStateID,
    b: u8,
    budget: &mut Budget,
) -> Result<Option<LazyStateID>, Exhausted> {
    budget.spend(1)?;
    match p.dfa.next_state(&mut p.cache, s, b) {
        Ok(t) if t.is_quit() || t.is_unknown() => Ok(None),
        Ok(t) => Ok(Some(t)),
        Err(_) => Ok(None),
    }
}

fn eoi(p: &mut LazyPattern, s: LazyStateID, budget: &mut Budget) -> Result<Option<LazyStateID>, Exhausted> {
    budget.spend(1)?;
    match p.dfa.next_eoi_state(&mut p.cache, s) {
        Ok(t) if t.is_quit() || t.is_unknown() => Ok(None),
        Ok(t) => Ok(Some(t)),
        Err(_) => Ok(None),
    }
}

fn prefix_of(target: MatchTarget) -> &'static [u8] {
    match target {
        MatchTarget::Host => b"",
        MatchTarget::HttpHost => URL_PREFIX.as_bytes(),
    }
}

impl Overlap {
    /// The search-automaton view of a pattern rule ([`patterns_overlap`]).
    pub fn of(spec: &PatternSpec, budget: &mut Budget) -> Result<Overlap, Exhausted> {
        Self::build(spec, false, budget)
    }

    /// The anchored view, for the subtree proofs ([`Overlap::subtree_entry`]).
    pub fn anchored(spec: &PatternSpec, budget: &mut Budget) -> Result<Overlap, Exhausted> {
        Self::build(spec, true, budget)
    }

    /// Building it spends one unit per NFA state.
    fn build(spec: &PatternSpec, anchored: bool, budget: &mut Budget) -> Result<Overlap, Exhausted> {
        if spec.matches_all {
            return Ok(Overlap::Always);
        }
        let Some(re) = &spec.regex else {
            return Ok(Overlap::Never);
        };
        let Ok(nfa) = thompson::Compiler::new()
            .syntax(syntax_config())
            .configure(thompson::Config::new().nfa_size_limit(Some(NFA_SIZE_LIMIT)))
            .build(re)
        else {
            return Ok(Overlap::Always);
        };
        let nfa_states = u64::try_from(nfa.states().len()).unwrap_or(u64::MAX);
        budget.spend(nfa_states)?;
        let nfa_bytes = nfa.memory_usage();
        let Ok(dfa) = hybrid::dfa::DFA::builder()
            .configure(
                hybrid::dfa::Config::new()
                    .cache_capacity(OVERLAP_CACHE_BYTES)
                    .minimum_cache_clear_count(Some(0))
                    .unicode_word_boundary(true),
            )
            .build_from_nfa(nfa)
        else {
            return Ok(Overlap::Always);
        };
        let mut cache = dfa.create_cache();
        let cfg = start::Config::new().anchored(Anchored::No).look_behind(None);
        let Ok(start) = dfa.start_state(&mut cache, &cfg) else {
            return Ok(Overlap::Always);
        };
        let mut p = LazyPattern {
            dfa,
            cache,
            start,
            matched: false,
            anchored,
            target: spec.target,
            bytes: nfa_bytes.saturating_add(OVERLAP_CACHE_BYTES),
            nfa_states,
        };
        if !anchored {
            let mut state = p.start;
            for &b in prefix_of(spec.target) {
                match next(&mut p, state, b, budget)? {
                    None => return Ok(Overlap::Always),
                    Some(t) => {
                        p.matched |= t.is_match();
                        state = t;
                    }
                }
            }
            p.start = state;
        }
        Ok(Overlap::Lazy(Box::new(p)))
    }

    /// Bytes its automaton may hold.
    pub fn bytes(&self) -> usize {
        match self {
            Overlap::Lazy(p) => p.bytes,
            _ => 0,
        }
    }

    /// Its NFA's states (0 without an automaton): the work unit of building or searching with it.
    pub fn nfa_states(&self) -> u64 {
        match self {
            Overlap::Lazy(p) => p.nfa_states,
            _ => 0,
        }
    }

    /// Its entry into a key's subtree ([`LazyPattern::subtree_entry`]); `Always` for a search
    /// automaton (build it with [`Overlap::anchored`]).
    pub fn subtree_entry(&mut self, budget: &mut Budget) -> Result<SubtreeEntry, Exhausted> {
        match self {
            Overlap::Never => Ok(SubtreeEntry::States(Vec::new())),
            Overlap::Always => Ok(SubtreeEntry::Always),
            Overlap::Lazy(p) if !p.anchored => Ok(SubtreeEntry::Always),
            Overlap::Lazy(p) => p.subtree_entry(budget),
        }
    }

    /// True when a match that started before `key` continues into it and ends in it or at its end
    /// ([`LazyPattern::matches_below`]).
    pub fn matches_below(
        &mut self,
        entry: &SubtreeEntry,
        key: &[u8],
        budget: &mut Budget,
    ) -> Result<bool, Exhausted> {
        match self {
            Overlap::Never => Ok(false),
            Overlap::Always => Ok(true),
            Overlap::Lazy(p) => p.matches_below(entry, key, budget),
        }
    }

    /// The bytes a key can start with and still be matched from `entry` (a prefilter for
    /// [`Overlap::matches_below`]); every byte for [`SubtreeEntry::Always`].
    pub fn live_first_bytes(
        &mut self,
        entry: &SubtreeEntry,
        budget: &mut Budget,
    ) -> Result<Vec<u8>, Exhausted> {
        let (Overlap::Lazy(p), SubtreeEntry::States(states)) = (self, entry) else {
            return Ok(match entry {
                SubtreeEntry::Always => ORDINARY_ALPHABET.to_vec(),
                SubtreeEntry::States(_) => Vec::new(),
            });
        };
        let mut out = Vec::new();
        for &b in ORDINARY_ALPHABET {
            for &s in states {
                match next(p, s, b, budget)? {
                    Some(t) if t.is_dead() && !t.is_match() => {}
                    _ => {
                        out.push(b);
                        break;
                    }
                }
            }
        }
        Ok(out)
    }
}

impl LazyPattern {
    /// The anchored automaton's states once a match has started before a key and read up to it:
    /// started anywhere in the match target's prefix (`http://`), in the labels before the key
    /// (any ordinary text, with any ordinary byte, the prefix's last byte or the start of text
    /// before it), or at the `.`; then read the rest of that text and the `.`. Sound: every
    /// ordinary name's leading labels are covered. A match on the way means every subtree.
    pub fn subtree_entry(&mut self, budget: &mut Budget) -> Result<SubtreeEntry, Exhausted> {
        let prefix = prefix_of(self.target);
        let mut seeds: Vec<LazyStateID> = Vec::new();
        let start_at = |p: &mut LazyPattern, lb: Option<u8>| -> Option<LazyStateID> {
            let cfg = start::Config::new().anchored(Anchored::Yes).look_behind(lb);
            p.dfa.start_state(&mut p.cache, &cfg).ok()
        };
        // Starts inside the prefix, reading its rest.
        for i in 0..prefix.len() {
            let lb = i.checked_sub(1).and_then(|j| prefix.get(j).copied());
            let Some(mut s) = start_at(self, lb) else {
                return Ok(SubtreeEntry::Always);
            };
            for &b in prefix.get(i..).unwrap_or(&[]) {
                match next(self, s, b, budget)? {
                    None => return Ok(SubtreeEntry::Always),
                    Some(t) if t.is_match() => return Ok(SubtreeEntry::Always),
                    Some(t) => s = t,
                }
            }
            if !s.is_dead() {
                seeds.push(s);
            }
        }
        // Starts in the labels before the key, or at its `.`.
        let first_lb = prefix.last().copied();
        let lbs = std::iter::once(first_lb).chain(ORDINARY_ALPHABET.iter().map(|b| Some(*b)));
        for lb in lbs {
            let Some(s) = start_at(self, lb) else {
                return Ok(SubtreeEntry::Always);
            };
            if !s.is_dead() && !seeds.contains(&s) {
                seeds.push(s);
            }
        }
        let mut seen: std::collections::HashSet<LazyStateID> = seeds.iter().copied().collect();
        let mut queue: std::collections::VecDeque<LazyStateID> = seeds.into_iter().collect();
        let mut entry: Vec<LazyStateID> = Vec::new();
        while let Some(s) = queue.pop_front() {
            if s.is_match() {
                return Ok(SubtreeEntry::Always);
            }
            // Expanding a new state determinises its transitions.
            budget.spend(self.nfa_states)?;
            for &b in ORDINARY_ALPHABET {
                let t = match next(self, s, b, budget)? {
                    None => return Ok(SubtreeEntry::Always),
                    Some(t) if t.is_match() => return Ok(SubtreeEntry::Always),
                    Some(t) => t,
                };
                if t.is_dead() {
                    continue;
                }
                if b == b'.' && !entry.contains(&t) {
                    entry.push(t);
                }
                if seen.insert(t) {
                    queue.push_back(t);
                }
            }
            if seen.len() > OVERLAP_STATE_LIMIT {
                return Ok(SubtreeEntry::Always);
            }
        }
        Ok(SubtreeEntry::States(entry))
    }

    /// True when a match from [`LazyPattern::subtree_entry`] continues through `key` (dotted,
    /// ordinary labels) and ends in it or at its end.
    pub fn matches_below(
        &mut self,
        entry: &SubtreeEntry,
        key: &[u8],
        budget: &mut Budget,
    ) -> Result<bool, Exhausted> {
        let SubtreeEntry::States(states) = entry else {
            return Ok(true);
        };
        let mut cur: Vec<LazyStateID> = states.clone();
        for &b in key {
            let mut nx = Vec::with_capacity(cur.len());
            for &s in &cur {
                match next(self, s, b, budget)? {
                    None => return Ok(true),
                    Some(t) if t.is_match() => return Ok(true),
                    Some(t) if !t.is_dead() && !nx.contains(&t) => nx.push(t),
                    Some(_) => {}
                }
            }
            if nx.is_empty() {
                return Ok(false);
            }
            cur = nx;
        }
        for s in cur {
            match eoi(self, s, budget)? {
                None => return Ok(true),
                Some(t) if t.is_match() => return Ok(true),
                Some(_) => {}
            }
        }
        Ok(false)
    }
}

/// The patterns of a chunk whose match can start inside a key (preceded by its `.`): one
/// multi-pattern search over `.K` per key, so a key costs one scan whatever the number of
/// patterns. The other half of the subtree proof ([`SubtreeEntry`] covers matches starting before
/// the key).
pub struct KeyMatcher {
    re: Option<regex_automata::meta::Regex>,
    /// Pattern ids → chunk positions; positions it can't run (no regex built) are in `always`.
    ids: Vec<usize>,
    /// Chunk positions taken as matching inside every key (a regex that wouldn't build).
    pub always: Vec<usize>,
    set: regex_automata::PatternSet,
}

impl KeyMatcher {
    /// For the chunk's specs (`None`: not a pattern, never matches); `cost` is what building it
    /// is charged (the chunk's NFA states).
    pub fn new(
        specs: &[Option<PatternSpec>],
        cost: u64,
        budget: &mut Budget,
    ) -> Result<KeyMatcher, Exhausted> {
        budget.spend(cost)?;
        let mut ids = Vec::new();
        let mut srcs: Vec<&str> = Vec::new();
        let mut always = Vec::new();
        for (ci, spec) in specs.iter().enumerate() {
            let Some(spec) = spec else { continue };
            if spec.matches_all {
                always.push(ci);
                continue;
            }
            if let Some(re) = &spec.regex {
                budget.spend(u64::try_from(re.len()).unwrap_or(u64::MAX))?;
                ids.push(ci);
                srcs.push(re);
            }
        }
        let re = if srcs.is_empty() {
            None
        } else {
            let built = regex_automata::meta::Regex::builder()
                .syntax(syntax_config())
                .configure(
                    regex_automata::meta::Config::new()
                        .match_kind(regex_automata::MatchKind::All)
                        .nfa_size_limit(Some(NFA_SIZE_LIMIT.saturating_mul(8)))
                        .hybrid_cache_capacity(OVERLAP_CACHE_BYTES.saturating_mul(8)),
                )
                .build_many(&srcs);
            match built {
                Ok(r) => Some(r),
                Err(_) => {
                    // Too large together: every one is taken as matching (sound).
                    always.append(&mut ids);
                    None
                }
            }
        };
        let set = regex_automata::PatternSet::new(re.as_ref().map_or(0, |r| r.pattern_len()));
        Ok(KeyMatcher { re, ids, always, set })
    }

    /// The chunk positions of the patterns with a match starting inside `key` (`text` is `.` and
    /// the key's text). Spends one unit per byte.
    pub fn starting_inside(&mut self, text: &str, budget: &mut Budget) -> Result<Vec<usize>, Exhausted> {
        budget.spend(u64::try_from(text.len()).unwrap_or(u64::MAX))?;
        let mut out = self.always.clone();
        let Some(re) = &self.re else {
            return Ok(out);
        };
        if text.len() < 2 {
            return Ok(out);
        }
        self.set.clear();
        re.which_overlapping_matches(&regex_automata::Input::new(text).range(1..), &mut self.set);
        out.extend(
            self.set
                .iter()
                .filter_map(|pid| self.ids.get(pid.as_usize()).copied()),
        );
        Ok(out)
    }
}

/// True when two patterns can both match one ordinary name's text (an over-approximation: any
/// ordinary text stands for a name's text form). Over the proof limits: true.
pub fn patterns_overlap(a: &mut Overlap, b: &mut Overlap, budget: &mut Budget) -> Result<bool, Exhausted> {
    let (a, b) = match (a, b) {
        (Overlap::Never, _) | (_, Overlap::Never) => return Ok(false),
        (Overlap::Always, _) | (_, Overlap::Always) => return Ok(true),
        (Overlap::Lazy(a), Overlap::Lazy(b)) => (a, b),
    };
    let start = (a.start, a.matched, b.start, b.matched);
    let mut seen = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    seen.insert(start);
    queue.push_back((start, false));
    let expand = a.nfa_states.saturating_add(b.nfa_states);
    while let Some(((sa, ma, sb, mb), nonempty)) = queue.pop_front() {
        budget.spend(expand)?;
        if nonempty {
            let fa = ma || eoi(a, sa, budget)?.is_none_or(|t| t.is_match());
            let fb = mb || eoi(b, sb, budget)?.is_none_or(|t| t.is_match());
            if fa && fb {
                return Ok(true);
            }
        }
        for &byte in ORDINARY_ALPHABET {
            let (Some(ta), Some(tb)) = (next(a, sa, byte, budget)?, next(b, sb, byte, budget)?) else {
                return Ok(true);
            };
            let na = ma || ta.is_match();
            let nb = mb || tb.is_match();
            if na && nb {
                return Ok(true);
            }
            if (ta.is_dead() && !na) || (tb.is_dead() && !nb) {
                continue;
            }
            let st = (ta, na, tb, nb);
            if seen.insert(st) {
                queue.push_back((st, true));
            }
        }
        if seen.len() > OVERLAP_STATE_LIMIT {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Builds a pattern's regex for matching, with the shared NFA limit. `Err` for a regex too large
/// to build (the compiler drops it and raises `bundle_warning`, bundles.md §2).
pub fn build_regex(
    regex: &str,
) -> Result<regex_automata::meta::Regex, Box<regex_automata::meta::BuildError>> {
    regex_automata::meta::Regex::builder()
        .syntax(syntax_config())
        .configure(
            regex_automata::meta::Config::new()
                .nfa_size_limit(Some(NFA_SIZE_LIMIT))
                .hybrid_cache_capacity(2 * 1024 * 1024),
        )
        .build(regex)
        .map_err(Box::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adguard::pattern_rust_regex;

    fn cm(go_pattern: &str, alphabet: &[u8]) -> Option<bool> {
        can_match(&pattern_rust_regex(go_pattern).unwrap(), alphabet)
    }

    #[test]
    fn proofs() {
        let t = text_alphabet();
        assert_eq!(cm("/[A-Z]{3}/", &t), Some(true), "case-insensitive");
        assert_eq!(
            cm("/\\p{L}+\\.example/", &t),
            Some(true),
            "unicode class with ASCII letters"
        );
        assert_eq!(cm("/\\p{Greek}/", &t), Some(false));
        assert_eq!(cm("/[^\\x00-\\x7f]/", &t), Some(false));
        assert_eq!(cm("/a\\nb/", &t), Some(false));
        assert_eq!(cm("/[!]/", &t), Some(true));
        assert_eq!(cm("/[!]/", ORDINARY_ALPHABET), Some(false));
        assert_eq!(cm("/^ads\\./", ORDINARY_ALPHABET), Some(true));
        assert_eq!(cm("/^https?:\\/\\//", ORDINARY_ALPHABET), Some(false));
        assert_eq!(
            can_match_after("^http://x", b"http://", ORDINARY_ALPHABET),
            Some(true)
        );
        assert_eq!(can_match_after("(?i)^https://", b"http://", &t), Some(false));
    }

    #[test]
    fn drop_test_on_specs() {
        use crate::classify::{Item, Line, classify_adblock_line};
        let spec = |l: &str| match classify_adblock_line(l, false) {
            Line::Items(v) => match &v[0] {
                Item::Rule(r) => r.pattern_spec().unwrap(),
                o => panic!("{o:?}"),
            },
            o => panic!("{o:?}"),
        };
        assert!(pattern_can_match(&spec("/\\p{L}{2,}\\.ex/")));
        assert!(!pattern_can_match(&spec("/\\p{Cyrillic}/")));
        assert!(pattern_can_match(&spec("||ads*.example^")));
        assert!(
            !pattern_can_match(&spec("/(?=x)/")),
            "Go refuses lookahead: matches nothing"
        );
    }
}
