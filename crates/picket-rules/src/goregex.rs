//! Go RE2 syntax → Rust `regex-syntax` (rules.md §3: patterns keep AdGuard's regex).
//!
//! urlfilter compiles every pattern with Go's `regexp` package (Go 1.27, `regexp/syntax`). Rust's
//! syntax differs in what it accepts and what some forms mean: `\<`/`\>` are word boundaries in Rust
//! but literals in Go; `[a&&b]`, `[a--b]`, `[a~~b]` and nested `[[…]]` are class operators in Rust
//! but literals in Go; Go has octal escapes and `\Q…\E`; Go's `\d \w \s \b` are ASCII while Rust's
//! are Unicode; Go's `\p{…}` names (categories and scripts, matched loosely) aren't Rust's.
//!
//! So [`translate`] is a port of Go's parser: it builds the parse tree Go builds, node for node
//! (literal strings, alternation factoring, character-class merging), applies Go's checks on it
//! (syntax, repeat counts over 1000, nested repeats whose product passes 1000 — `repeatIsValid` —,
//! tree height over 1000, and the instruction-size limit), and writes the tree as Rust syntax.
//! Writing the factored tree reproduces Go's matching exactly, quirks of factoring included. A
//! regex Go refuses is refused here (such a rule matches nothing in AdGuard, so here too).
//!
//! Approximations, none of which can change what matches:
//! - Case folding is computed exactly for ASCII (and `ſ`, `K`, the two non-ASCII runes that fold to
//!   ASCII). Other runes are taken as unfolded when deciding the tree's shape (whether two
//!   branches share a prefix, whether a class is one rune), so for non-ASCII case variants the tree
//!   can be less factored than Go's; the Rust text still folds them, under `(?i)`, as Go does.
//! - Go's rune limit (`maxRunes`, 33.5 M runes in classes) isn't checked: it can't be reached in a
//!   64 KiB rule (the densest input, `\pL` × 21,845, is 29.9 M), and a regex over it is far over
//!   the NFA limit (bundles.md §4), so it is dropped as too large: it matches nothing either way.
//!   Input over [`MAX_GO_REGEX_LEN`] is refused as too large outright, to bound the work.
//! - Go keeps the computed sizes and heights of nodes in maps keyed by pointer and doesn't always
//!   refresh them when factoring edits a node; here they are recomputed.
//!
//! Every name a match target can hold is ASCII (rules.md §3 text form, IP text, `http://`), so
//! Unicode tables Rust lacks (`Cs`, scripts newer than its tables) are written as their (empty)
//! ASCII part.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::OnceLock;

/// Go's limit on repetition counts (`{n,m}`), also applied to nested repeats' product.
const MAX_REPEAT: i32 = 1000;
/// Go's parse-tree height limit (`maxHeight`).
const MAX_HEIGHT: usize = 1000;
/// Go's compiled-size limit in instructions (`maxSize`: 128 MiB / 40 bytes).
const MAX_SIZE: i64 = (128 << 20) / 40;
/// The longest Go regex translated (1 MiB, well over any rule line).
pub const MAX_GO_REGEX_LEN: usize = 1024 * 1024;
/// The largest rune.
const MAX_RUNE: u32 = 0x10_FFFF;

/// Why a Go pattern can't be translated: Go refuses it (`regexp/syntax` error codes).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GoRegexError {
    #[error("trailing backslash at end of expression")]
    TrailingBackslash,
    #[error("invalid escape sequence")]
    InvalidEscape,
    #[error("missing closing ]")]
    MissingBracket,
    #[error("missing closing )")]
    MissingParen,
    #[error("unexpected )")]
    UnexpectedParen,
    #[error("invalid character class range")]
    InvalidCharRange,
    #[error("invalid named capture")]
    InvalidNamedCapture,
    #[error("invalid or unsupported Perl syntax")]
    InvalidPerlOp,
    #[error("invalid nested repetition operator")]
    InvalidRepeatOp,
    #[error("invalid repeat count")]
    InvalidRepeatSize,
    #[error("missing argument to repetition operator")]
    MissingRepeatArgument,
    #[error("expression too large")]
    Large,
    #[error("expression nests too deeply")]
    NestingDepth,
}

// Parse flags (Go `syntax.Flags`); urlfilter compiles with `syntax.Perl`.
const FOLD_CASE: u16 = 1;
const CLASS_NL: u16 = 4;
const DOT_NL: u16 = 8;
const ONE_LINE: u16 = 16;
const NON_GREEDY: u16 = 32;
const PERL_X: u16 = 64;
const UNICODE_GROUPS: u16 = 128;
const WAS_DOLLAR: u16 = 256;
const PERL: u16 = CLASS_NL | ONE_LINE | PERL_X | UNICODE_GROUPS;

/// Go's `syntax.Op`, in Go's order (the parser compares them).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    NoMatch = 1,
    EmptyMatch,
    Literal,
    CharClass,
    AnyCharNotNl,
    AnyChar,
    BeginLine,
    EndLine,
    BeginText,
    EndText,
    WordBoundary,
    NoWordBoundary,
    Capture,
    Star,
    Plus,
    Quest,
    Repeat,
    Concat,
    Alternate,
    // Pseudo-ops for the parse stack (`opPseudo` and above).
    LeftParen = 128,
    VerticalBar,
}

/// One union member of a class as Rust writes it: a bracketed class (`[a-z]`, `[^\p{gc=L}]`) and
/// whether it is case-folded.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Atom {
    text: String,
    fold: bool,
}

/// A character class: its runes as Go holds them (for the tree's shape), and what Rust matches.
#[derive(Clone, Debug, Default)]
struct Class {
    /// Go's rune ranges (folded under `(?i)`, negated for `[^…]`), sorted and merged. Meaningless
    /// when `opaque`.
    ranges: Vec<(u32, u32)>,
    /// The runes aren't known exactly (a Unicode table, or non-ASCII runes under `(?i)`): the class
    /// compares by its atoms and never becomes a literal.
    opaque: bool,
    /// The union Rust matches.
    atoms: Vec<Atom>,
}

impl Class {
    fn shape_eq(&self, other: &Class) -> bool {
        if self.opaque || other.opaque {
            let mut a = self.atoms.clone();
            let mut b = other.atoms.clone();
            a.sort();
            b.sort();
            a.dedup();
            b.dedup();
            return self.opaque == other.opaque && a == b;
        }
        self.ranges == other.ranges
    }
}

#[derive(Clone, Debug)]
struct Node {
    op: Op,
    flags: u16,
    /// Literal runes as Go stores them (the smallest of each fold orbit under `(?i)`).
    runes: Vec<char>,
    class: Class,
    sub: Vec<usize>,
    min: i32,
    max: i32,
    cap: u32,
    name: Option<String>,
    /// Go's `calcSize` and `calcHeight` of the node as last computed.
    size: i64,
    height: usize,
}

impl Node {
    fn new(op: Op) -> Node {
        Node {
            op,
            flags: 0,
            runes: Vec::new(),
            class: Class::default(),
            sub: Vec::new(),
            min: 0,
            max: 0,
            cap: 0,
            name: None,
            size: 1,
            height: 1,
        }
    }
}

/// Translates a Go RE2 pattern into Rust regex syntax with the same matches on any ASCII text, or
/// returns the error Go gives.
pub fn translate(go: &str) -> Result<String, GoRegexError> {
    if go.len() > MAX_GO_REGEX_LEN {
        return Err(GoRegexError::Large);
    }
    let mut p = Parser {
        flags: PERL,
        ..Parser::default()
    };
    let root = p.parse(go)?;
    let mut out = String::with_capacity(go.len().saturating_mul(2).saturating_add(8));
    out.push_str("(?i)");
    p.emit(root, Need::Alt, true, &mut out);
    Ok(out)
}

#[derive(Default)]
struct Parser {
    flags: u16,
    nodes: Vec<Node>,
    stack: Vec<usize>,
    num_cap: u32,
    /// Go's `numRegexp` (nodes allocated, not reused) and the free list's length.
    num_regexp: usize,
    free: usize,
    /// Go's `repeats`: the product of the repeat counts seen while size isn't tracked yet.
    repeats: i64,
    size_tracked: bool,
    height_tracked: bool,
}

type PResult<T> = Result<T, GoRegexError>;

impl Parser {
    // ---- Nodes and limits ----------------------------------------------------------------

    fn new_node(&mut self, op: Op) -> usize {
        if self.free > 0 {
            self.free = self.free.saturating_sub(1);
        } else {
            self.num_regexp = self.num_regexp.saturating_add(1);
        }
        self.nodes.push(Node::new(op));
        self.nodes.len().saturating_sub(1)
    }

    fn reuse(&mut self, _id: usize) {
        self.free = self.free.saturating_add(1);
    }

    fn n(&self, id: usize) -> &Node {
        self.nodes.get(id).unwrap_or(&NO_NODE)
    }

    fn nm(&mut self, id: usize) -> Option<&mut Node> {
        self.nodes.get_mut(id)
    }

    fn op(&self, id: usize) -> Op {
        self.n(id).op
    }

    /// Go `calcSize` for one node from its subs' stored sizes.
    fn calc_size(&mut self, id: usize) -> i64 {
        let node = self.n(id);
        let sub = |k: usize| node.sub.get(k).map_or(1, |&s| self.n(s).size);
        let sum = || {
            node.sub
                .iter()
                .fold(0i64, |a, &s| a.saturating_add(self.n(s).size))
        };
        let size = match node.op {
            Op::Literal => i64::try_from(node.runes.len()).unwrap_or(i64::MAX),
            Op::Capture | Op::Star => sub(0).saturating_add(2),
            Op::Plus | Op::Quest => sub(0).saturating_add(1),
            Op::Concat => sum(),
            Op::Alternate => {
                let n = i64::try_from(node.sub.len()).unwrap_or(i64::MAX);
                sum().saturating_add(if n > 1 { n.saturating_sub(1) } else { 0 })
            }
            Op::Repeat => {
                let s = sub(0);
                if node.max == -1 {
                    if node.min == 0 {
                        s.saturating_add(2)
                    } else {
                        s.saturating_mul(i64::from(node.min)).saturating_add(1)
                    }
                } else {
                    s.saturating_mul(i64::from(node.max))
                        .saturating_add(i64::from(node.max.saturating_sub(node.min)))
                }
            }
            _ => 0,
        };
        let size = size.max(1);
        if let Some(n) = self.nm(id) {
            n.size = size;
        }
        size
    }

    fn calc_height(&mut self, id: usize) -> usize {
        let h = self
            .n(id)
            .sub
            .iter()
            .map(|&s| self.n(s).height)
            .max()
            .map_or(1, |m| m.saturating_add(1));
        if let Some(n) = self.nm(id) {
            n.height = h;
        }
        h
    }

    /// Go `checkLimits` (without the rune count: see the module docs).
    fn check_limits(&mut self, id: usize) -> PResult<()> {
        // Sizes and heights are kept for every node; Go's gating decides when they are checked.
        let size = self.calc_size(id);
        let height = self.calc_height(id);
        if !self.size_tracked {
            if self.repeats == 0 {
                self.repeats = 1;
            }
            let node = self.n(id);
            if node.op == Op::Repeat {
                let mut n = node.max;
                if n == -1 {
                    n = node.min;
                }
                let n = i64::from(n.max(1));
                if n > MAX_SIZE.checked_div(self.repeats).unwrap_or(0) {
                    self.repeats = MAX_SIZE;
                } else {
                    self.repeats = self.repeats.saturating_mul(n);
                }
            }
            let budget = MAX_SIZE.checked_div(self.repeats.max(1)).unwrap_or(0);
            if i64::try_from(self.num_regexp).unwrap_or(i64::MAX) >= budget {
                self.size_tracked = true;
                for &s in &self.stack {
                    if self.n(s).size > MAX_SIZE {
                        return Err(GoRegexError::Large);
                    }
                }
            }
        }
        if self.size_tracked && size > MAX_SIZE {
            return Err(GoRegexError::Large);
        }
        if self.num_regexp >= MAX_HEIGHT {
            if !self.height_tracked {
                self.height_tracked = true;
                if self.stack.iter().any(|&s| self.n(s).height > MAX_HEIGHT) {
                    return Err(GoRegexError::NestingDepth);
                }
            }
            if height > MAX_HEIGHT {
                return Err(GoRegexError::NestingDepth);
            }
        }
        Ok(())
    }

    // ---- The parse stack (Go `push`, `maybeConcat`, `literal`, `op`) -----------------------

    fn push(&mut self, id: usize) -> PResult<Option<usize>> {
        let node = self.n(id).clone();
        if node.op == Op::CharClass && !node.class.opaque {
            let r = &node.class.ranges;
            if let [(lo, hi)] = r.as_slice()
                && lo == hi
            {
                // A single rune: a literal.
                let c = char::from_u32(*lo).unwrap_or('\u{0}');
                if self.maybe_concat(Some((c, self.flags & !FOLD_CASE))) {
                    return Ok(None);
                }
                let flags = self.flags & !FOLD_CASE;
                if let Some(n) = self.nm(id) {
                    n.op = Op::Literal;
                    n.runes = vec![c];
                    n.flags = flags;
                }
                return self.push_node(id);
            }
            if let [(a, b), (c, d)] = r.as_slice()
                && a == b
                && c == d
                && fold_pair(*a, *c)
            {
                // A case-insensitive rune like `[Aa]`: a folded literal.
                let ch = char::from_u32(*a).unwrap_or('\u{0}');
                if self.maybe_concat(Some((ch, self.flags | FOLD_CASE))) {
                    return Ok(None);
                }
                let flags = self.flags | FOLD_CASE;
                if let Some(n) = self.nm(id) {
                    n.op = Op::Literal;
                    n.runes = vec![ch];
                    n.flags = flags;
                }
                return self.push_node(id);
            }
        }
        self.maybe_concat(None);
        self.push_node(id)
    }

    fn push_node(&mut self, id: usize) -> PResult<Option<usize>> {
        self.stack.push(id);
        self.check_limits(id)?;
        Ok(Some(id))
    }

    /// Go `maybeConcat`: merges the top two literals; with `r`, reuses the merged node for it.
    fn maybe_concat(&mut self, r: Option<(char, u16)>) -> bool {
        let n = self.stack.len();
        if n < 2 {
            return false;
        }
        let (Some(&re1), Some(&re2)) = (
            self.stack.get(n.saturating_sub(1)),
            self.stack.get(n.saturating_sub(2)),
        ) else {
            return false;
        };
        let (a, b) = (self.n(re1), self.n(re2));
        if a.op != Op::Literal || b.op != Op::Literal || (a.flags & FOLD_CASE) != (b.flags & FOLD_CASE) {
            return false;
        }
        let moved = a.runes.clone();
        if let Some(n2) = self.nm(re2) {
            n2.runes.extend(moved);
        }
        self.calc_size(re2);
        if let Some((c, flags)) = r {
            if let Some(n1) = self.nm(re1) {
                n1.runes = vec![c];
                n1.flags = flags;
            }
            self.calc_size(re1);
            return true;
        }
        self.stack.truncate(n.saturating_sub(1));
        self.reuse(re1);
        false
    }

    fn literal(&mut self, c: char) -> PResult<()> {
        let id = self.new_node(Op::Literal);
        let flags = self.flags;
        let c = if flags & FOLD_CASE != 0 { min_fold(c) } else { c };
        if let Some(n) = self.nm(id) {
            n.flags = flags;
            n.runes = vec![c];
        }
        self.push(id)?;
        Ok(())
    }

    fn push_op(&mut self, op: Op) -> PResult<usize> {
        let id = self.new_node(op);
        let flags = self.flags;
        if let Some(n) = self.nm(id) {
            n.flags = flags;
        }
        self.push(id)?;
        Ok(id)
    }

    // ---- Main loop (Go `parse`) -------------------------------------------------------------

    fn parse(&mut self, s: &str) -> PResult<usize> {
        let mut t = s;
        let mut last_repeat = false;
        while let Some(c) = t.chars().next() {
            let mut repeat = false;
            match c {
                '(' => {
                    if t.as_bytes().get(1) == Some(&b'?') {
                        t = self.parse_perl_flags(t)?;
                    } else {
                        self.num_cap = self.num_cap.saturating_add(1);
                        let id = self.push_op(Op::LeftParen)?;
                        let cap = self.num_cap;
                        if let Some(n) = self.nm(id) {
                            n.cap = cap;
                        }
                        t = rest_after(t, 1);
                    }
                }
                '|' => {
                    self.parse_vertical_bar()?;
                    t = rest_after(t, 1);
                }
                ')' => {
                    self.parse_right_paren()?;
                    t = rest_after(t, 1);
                }
                '^' => {
                    self.push_op(if self.flags & ONE_LINE != 0 {
                        Op::BeginText
                    } else {
                        Op::BeginLine
                    })?;
                    t = rest_after(t, 1);
                }
                '$' => {
                    if self.flags & ONE_LINE != 0 {
                        let id = self.push_op(Op::EndText)?;
                        if let Some(n) = self.nm(id) {
                            n.flags |= WAS_DOLLAR;
                        }
                    } else {
                        self.push_op(Op::EndLine)?;
                    }
                    t = rest_after(t, 1);
                }
                '.' => {
                    self.push_op(if self.flags & DOT_NL != 0 {
                        Op::AnyChar
                    } else {
                        Op::AnyCharNotNl
                    })?;
                    t = rest_after(t, 1);
                }
                '[' => t = self.parse_class(t)?,
                '*' | '+' | '?' => {
                    let op = match c {
                        '*' => Op::Star,
                        '+' => Op::Plus,
                        _ => Op::Quest,
                    };
                    t = self.repeat(op, 0, 0, rest_after(t, 1), last_repeat)?;
                    repeat = true;
                }
                '{' => match parse_repeat(t) {
                    None => {
                        self.literal('{')?;
                        t = rest_after(t, 1);
                    }
                    Some((min, max, after)) => {
                        if !(0..=MAX_REPEAT).contains(&min) || max > MAX_REPEAT || (max >= 0 && min > max) {
                            return Err(GoRegexError::InvalidRepeatSize);
                        }
                        t = self.repeat(Op::Repeat, min, max, after, last_repeat)?;
                        repeat = true;
                    }
                },
                '\\' => t = self.parse_backslash(t)?,
                _ => {
                    self.literal(c)?;
                    t = rest_after(t, c.len_utf8());
                }
            }
            last_repeat = repeat;
        }
        self.concat()?;
        if self.swap_vertical_bar() {
            self.stack.pop();
        }
        self.alternate()?;
        if self.stack.len() != 1 {
            return Err(GoRegexError::MissingParen);
        }
        Ok(self.stack.first().copied().unwrap_or(0))
    }

    fn parse_backslash<'a>(&mut self, t: &'a str) -> PResult<&'a str> {
        let next = t.as_bytes().get(1).copied();
        match next {
            Some(b'A') => {
                self.push_op(Op::BeginText)?;
                return Ok(rest_after(t, 2));
            }
            Some(b'b') => {
                self.push_op(Op::WordBoundary)?;
                return Ok(rest_after(t, 2));
            }
            Some(b'B') => {
                self.push_op(Op::NoWordBoundary)?;
                return Ok(rest_after(t, 2));
            }
            // Any byte: Go doesn't support it.
            Some(b'C') => return Err(GoRegexError::InvalidEscape),
            Some(b'Q') => {
                let body = rest_after(t, 2);
                let (lit, rest) = match body.find("\\E") {
                    Some(i) => (body.get(..i).unwrap_or(""), rest_after(body, i.saturating_add(2))),
                    None => (body, ""),
                };
                for c in lit.chars() {
                    self.literal(c)?;
                }
                return Ok(rest);
            }
            Some(b'z') => {
                self.push_op(Op::EndText)?;
                return Ok(rest_after(t, 2));
            }
            _ => {}
        }
        if let Some(b'p' | b'P') = next {
            let (class, rest) = parse_unicode_class(t, self.flags)?;
            let id = self.new_node(Op::CharClass);
            let flags = self.flags;
            if let Some(n) = self.nm(id) {
                n.flags = flags;
                n.class = class;
            }
            self.push(id)?;
            return Ok(rest);
        }
        if let Some(g) = next.and_then(perl_group) {
            let class = group_class(&g, self.flags & FOLD_CASE != 0);
            let id = self.new_node(Op::CharClass);
            let flags = self.flags;
            if let Some(n) = self.nm(id) {
                n.flags = flags;
                n.class = class;
            }
            self.push(id)?;
            return Ok(rest_after(t, 2));
        }
        // Go allocates a class node, finds no class, and reuses it.
        let id = self.new_node(Op::CharClass);
        self.reuse(id);
        let (c, rest) = parse_escape(t)?;
        self.literal(c)?;
        Ok(rest)
    }

    /// Go `parsePerlFlags`: `(?flags)`, `(?flags:`, `(?P<name>`, `(?<name>`.
    fn parse_perl_flags<'a>(&mut self, s: &'a str) -> PResult<&'a str> {
        let b = s.as_bytes();
        let starts_with_p = b.len() > 4 && b.get(2) == Some(&b'P') && b.get(3) == Some(&b'<');
        let starts_with_name = b.len() > 3 && b.get(2) == Some(&b'<');
        if starts_with_p || starts_with_name {
            let expr_start = if starts_with_name { 3 } else { 4 };
            let end = s.find('>').ok_or(GoRegexError::InvalidNamedCapture)?;
            let name = s.get(expr_start..end).unwrap_or("");
            if name.is_empty() || !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()) {
                return Err(GoRegexError::InvalidNamedCapture);
            }
            self.num_cap = self.num_cap.saturating_add(1);
            let id = self.push_op(Op::LeftParen)?;
            let cap = self.num_cap;
            if let Some(n) = self.nm(id) {
                n.cap = cap;
                n.name = Some(name.to_string());
            }
            return Ok(rest_after(s, end.saturating_add(1)));
        }
        let mut t = rest_after(s, 2);
        let mut flags = self.flags;
        let mut negated = false;
        let mut saw_flag = false;
        while let Some(c) = t.chars().next() {
            t = rest_after(t, c.len_utf8());
            match c {
                'i' | 'm' | 's' | 'U' => {
                    let bit = match c {
                        'i' => FOLD_CASE,
                        'm' => ONE_LINE,
                        's' => DOT_NL,
                        _ => NON_GREEDY,
                    };
                    // `m` clears OneLine; the others set their bit (inverted after `-`).
                    let set = (c != 'm') != negated;
                    if set {
                        flags |= bit;
                    } else {
                        flags &= !bit;
                    }
                    saw_flag = true;
                }
                '-' => {
                    if negated {
                        break;
                    }
                    negated = true;
                    saw_flag = false;
                }
                ':' | ')' => {
                    if negated && !saw_flag {
                        break;
                    }
                    if c == ':' {
                        self.push_op(Op::LeftParen)?;
                    }
                    self.flags = flags;
                    return Ok(t);
                }
                _ => break,
            }
        }
        Err(GoRegexError::InvalidPerlOp)
    }

    /// Go `repeat`.
    fn repeat<'a>(
        &mut self,
        op: Op,
        min: i32,
        max: i32,
        after: &'a str,
        last_repeat: bool,
    ) -> PResult<&'a str> {
        let mut flags = self.flags;
        let mut after = after;
        if let Some(rest) = after.strip_prefix('?') {
            after = rest;
            flags ^= NON_GREEDY;
        }
        if last_repeat {
            return Err(GoRegexError::InvalidRepeatOp);
        }
        let Some(&sub) = self.stack.last() else {
            return Err(GoRegexError::MissingRepeatArgument);
        };
        if self.op(sub) >= Op::LeftParen {
            return Err(GoRegexError::MissingRepeatArgument);
        }
        let id = self.new_node(op);
        if let Some(n) = self.nm(id) {
            n.min = min;
            n.max = max;
            n.flags = flags;
            n.sub = vec![sub];
        }
        if let Some(top) = self.stack.last_mut() {
            *top = id;
        }
        self.check_limits(id)?;
        if op == Op::Repeat && (min >= 2 || max >= 2) && !self.repeat_is_valid(id, MAX_REPEAT) {
            return Err(GoRegexError::InvalidRepeatSize);
        }
        Ok(after)
    }

    /// Go `repeatIsValid`: the repetition and those nested in it don't make more than `n` copies.
    fn repeat_is_valid(&self, id: usize, n: i32) -> bool {
        let node = self.n(id);
        let mut n = n;
        if node.op == Op::Repeat {
            let mut m = node.max;
            if m == 0 {
                return true;
            }
            if m < 0 {
                m = node.min;
            }
            if m > n {
                return false;
            }
            if m > 0 {
                n = n.checked_div(m).unwrap_or(0);
            }
        }
        node.sub.iter().all(|&s| self.repeat_is_valid(s, n))
    }

    // ---- Concatenation and alternation ----------------------------------------------------

    fn concat(&mut self) -> PResult<usize> {
        self.maybe_concat(None);
        let i = self.pseudo_floor();
        let subs: Vec<usize> = self.stack.split_off(i);
        if subs.is_empty() {
            let id = self.new_node(Op::EmptyMatch);
            self.push(id)?;
            return Ok(id);
        }
        let id = self.collapse(subs, Op::Concat)?;
        self.push(id)?;
        Ok(id)
    }

    fn alternate(&mut self) -> PResult<usize> {
        let i = self.pseudo_floor();
        let subs: Vec<usize> = self.stack.split_off(i);
        if let Some(&last) = subs.last() {
            self.clean_alt(last);
        }
        if subs.is_empty() {
            let id = self.new_node(Op::NoMatch);
            self.push(id)?;
            return Ok(id);
        }
        let id = self.collapse(subs, Op::Alternate)?;
        self.push(id)?;
        Ok(id)
    }

    /// Index of the first stack entry above the topmost pseudo-op.
    fn pseudo_floor(&self) -> usize {
        let mut i = self.stack.len();
        while i > 0
            && self
                .stack
                .get(i.saturating_sub(1))
                .is_some_and(|&s| self.op(s) < Op::LeftParen)
        {
            i = i.saturating_sub(1);
        }
        i
    }

    fn collapse(&mut self, subs: Vec<usize>, op: Op) -> PResult<usize> {
        if subs.len() == 1 {
            return Ok(subs.first().copied().unwrap_or(0));
        }
        let id = self.new_node(op);
        let mut all = Vec::with_capacity(subs.len());
        for s in subs {
            if self.op(s) == op {
                all.extend(self.n(s).sub.clone());
                self.reuse(s);
            } else {
                all.push(s);
            }
        }
        if op == Op::Alternate {
            all = self.factor(all)?;
            if all.len() == 1 {
                self.reuse(id);
                return Ok(all.first().copied().unwrap_or(0));
            }
        }
        if let Some(n) = self.nm(id) {
            n.sub = all;
        }
        self.calc_size(id);
        self.calc_height(id);
        Ok(id)
    }

    /// Go `factor`: common literal prefixes, common leading classes, runs of single runes and
    /// classes into one class, runs of empty matches.
    fn factor(&mut self, sub: Vec<usize>) -> PResult<Vec<usize>> {
        if sub.len() < 2 {
            return Ok(sub);
        }
        // Round 1: common literal prefixes.
        let mut sub = sub;
        let mut out: Vec<usize> = Vec::with_capacity(sub.len());
        let mut start = 0usize;
        let mut str_: Vec<char> = Vec::new();
        let mut strflags: u16 = 0;
        let mut i = 0usize;
        while i <= sub.len() {
            let mut istr: Vec<char> = Vec::new();
            let mut iflags: u16 = 0;
            if let Some(&si) = sub.get(i) {
                (istr, iflags) = self.leading_string(si);
                if iflags == strflags {
                    let same = str_.iter().zip(&istr).take_while(|(a, b)| a == b).count();
                    if same > 0 {
                        str_.truncate(same);
                        i = i.saturating_add(1);
                        continue;
                    }
                }
            }
            if i == start {
            } else if i == start.saturating_add(1) {
                out.extend(sub.get(start).copied());
            } else {
                let prefix = self.new_node(Op::Literal);
                if let Some(n) = self.nm(prefix) {
                    n.flags = strflags;
                    n.runes = str_.clone();
                }
                self.calc_size(prefix);
                for j in start..i {
                    if let Some(&sj) = sub.get(j) {
                        let r = self.remove_leading_string(sj, str_.len());
                        if let Some(slot) = sub.get_mut(j) {
                            *slot = r;
                        }
                        self.check_limits(r)?;
                    }
                }
                let suffix = self.collapse(sub.get(start..i).unwrap_or(&[]).to_vec(), Op::Alternate)?;
                let re = self.new_node(Op::Concat);
                if let Some(n) = self.nm(re) {
                    n.sub = vec![prefix, suffix];
                }
                self.calc_size(re);
                self.calc_height(re);
                out.push(re);
            }
            start = i;
            str_ = istr;
            strflags = iflags;
            i = i.saturating_add(1);
        }
        sub = out;

        // Round 2: common leading single-rune regexps (a class, or a fixed repeat of one).
        let mut out: Vec<usize> = Vec::with_capacity(sub.len());
        let mut start = 0usize;
        let mut first: Option<usize> = None;
        let mut i = 0usize;
        while i <= sub.len() {
            let mut ifirst: Option<usize> = None;
            if let Some(&si) = sub.get(i) {
                ifirst = self.leading_regexp(si);
                if let (Some(f), Some(fi)) = (first, ifirst)
                    && self.equal(f, fi)
                    && (self.is_char_class(f)
                        || (self.op(f) == Op::Repeat
                            && self.n(f).min == self.n(f).max
                            && self.n(f).sub.first().is_some_and(|&s| self.is_char_class(s))))
                {
                    i = i.saturating_add(1);
                    continue;
                }
            }
            if i == start {
            } else if i == start.saturating_add(1) {
                out.extend(sub.get(start).copied());
            } else if let Some(prefix) = first {
                for j in start..i {
                    let reuse = j != start;
                    if let Some(&sj) = sub.get(j) {
                        let r = self.remove_leading_regexp(sj, reuse);
                        if let Some(slot) = sub.get_mut(j) {
                            *slot = r;
                        }
                        self.check_limits(r)?;
                    }
                }
                let suffix = self.collapse(sub.get(start..i).unwrap_or(&[]).to_vec(), Op::Alternate)?;
                let re = self.new_node(Op::Concat);
                if let Some(n) = self.nm(re) {
                    n.sub = vec![prefix, suffix];
                }
                self.calc_size(re);
                self.calc_height(re);
                out.push(re);
            }
            start = i;
            first = ifirst;
            i = i.saturating_add(1);
        }
        sub = out;

        // Round 3: runs of single runes and classes into one class.
        let mut out: Vec<usize> = Vec::with_capacity(sub.len());
        let mut start = 0usize;
        let mut i = 0usize;
        while i <= sub.len() {
            if sub.get(i).is_some_and(|&s| self.is_char_class(s)) {
                i = i.saturating_add(1);
                continue;
            }
            if i == start {
            } else if i == start.saturating_add(1) {
                out.extend(sub.get(start).copied());
            } else {
                // Start with the most complex node.
                let mut max = start;
                for j in start.saturating_add(1)..i {
                    let (a, b) = (
                        sub.get(max).copied().unwrap_or(0),
                        sub.get(j).copied().unwrap_or(0),
                    );
                    let (na, nb) = (self.n(a), self.n(b));
                    if na.op < nb.op || (na.op == nb.op && na.class.ranges.len() < nb.class.ranges.len()) {
                        max = j;
                    }
                }
                sub.swap(start, max);
                let dst = sub.get(start).copied().unwrap_or(0);
                for j in start.saturating_add(1)..i {
                    let src = sub.get(j).copied().unwrap_or(0);
                    self.merge_char_class(dst, src);
                    self.reuse(src);
                }
                self.clean_alt(dst);
                out.push(dst);
            }
            if let Some(&si) = sub.get(i) {
                out.push(si);
            }
            start = i.saturating_add(1);
            i = i.saturating_add(1);
        }
        sub = out;

        // Round 4: runs of empty matches into one.
        let mut out: Vec<usize> = Vec::with_capacity(sub.len());
        for (k, &s) in sub.iter().enumerate() {
            if sub
                .get(k.saturating_add(1))
                .is_some_and(|&t| self.op(t) == Op::EmptyMatch)
                && self.op(s) == Op::EmptyMatch
            {
                continue;
            }
            out.push(s);
        }
        Ok(out)
    }

    fn leading_string(&self, id: usize) -> (Vec<char>, u16) {
        let mut re = self.n(id);
        if re.op == Op::Concat
            && let Some(&f) = re.sub.first()
        {
            re = self.n(f);
        }
        if re.op != Op::Literal {
            return (Vec::new(), 0);
        }
        (re.runes.clone(), re.flags & FOLD_CASE)
    }

    fn remove_leading_string(&mut self, id: usize, n: usize) -> usize {
        if self.op(id) == Op::Concat && !self.n(id).sub.is_empty() {
            let first = self.n(id).sub.first().copied().unwrap_or(0);
            let s = self.remove_leading_string(first, n);
            if let Some(node) = self.nm(id)
                && let Some(slot) = node.sub.first_mut()
            {
                *slot = s;
            }
            if self.op(s) == Op::EmptyMatch {
                self.reuse(s);
                let len = self.n(id).sub.len();
                match len {
                    0 | 1 => {
                        if let Some(node) = self.nm(id) {
                            node.op = Op::EmptyMatch;
                            node.sub.clear();
                        }
                    }
                    2 => {
                        let second = self.n(id).sub.get(1).copied().unwrap_or(0);
                        self.reuse(id);
                        return second;
                    }
                    _ => {
                        if let Some(node) = self.nm(id) {
                            node.sub.remove(0);
                        }
                    }
                }
            }
            self.calc_size(id);
            self.calc_height(id);
            return id;
        }
        if self.op(id) == Op::Literal
            && let Some(node) = self.nm(id)
        {
            let k = n.min(node.runes.len());
            node.runes.drain(..k);
            if node.runes.is_empty() {
                node.op = Op::EmptyMatch;
            }
        }
        self.calc_size(id);
        id
    }

    fn leading_regexp(&self, id: usize) -> Option<usize> {
        let re = self.n(id);
        if re.op == Op::EmptyMatch {
            return None;
        }
        if re.op == Op::Concat
            && let Some(&f) = re.sub.first()
        {
            if self.op(f) == Op::EmptyMatch {
                return None;
            }
            return Some(f);
        }
        Some(id)
    }

    fn remove_leading_regexp(&mut self, id: usize, reuse: bool) -> usize {
        if self.op(id) == Op::Concat && !self.n(id).sub.is_empty() {
            if reuse && let Some(&f) = self.n(id).sub.first() {
                self.reuse(f);
            }
            if let Some(node) = self.nm(id) {
                node.sub.remove(0);
            }
            match self.n(id).sub.len() {
                0 => {
                    if let Some(node) = self.nm(id) {
                        node.op = Op::EmptyMatch;
                    }
                }
                1 => {
                    let only = self.n(id).sub.first().copied().unwrap_or(0);
                    self.reuse(id);
                    return only;
                }
                _ => {}
            }
            self.calc_size(id);
            self.calc_height(id);
            return id;
        }
        if reuse {
            self.reuse(id);
        }
        self.new_node(Op::EmptyMatch)
    }

    /// Go `Regexp.Equal`.
    fn equal(&self, x: usize, y: usize) -> bool {
        let (a, b) = (self.n(x), self.n(y));
        if a.op != b.op {
            return false;
        }
        let same_fold = (a.flags & FOLD_CASE) == (b.flags & FOLD_CASE);
        match a.op {
            Op::EndText => (a.flags & WAS_DOLLAR) == (b.flags & WAS_DOLLAR),
            Op::Literal => same_fold && a.runes == b.runes,
            Op::CharClass => same_fold && a.class.shape_eq(&b.class),
            Op::Alternate | Op::Concat => {
                a.sub.len() == b.sub.len() && a.sub.iter().zip(&b.sub).all(|(&p, &q)| self.equal(p, q))
            }
            Op::Star | Op::Plus | Op::Quest => {
                (a.flags & NON_GREEDY) == (b.flags & NON_GREEDY) && self.equal_first_sub(a, b)
            }
            Op::Repeat => {
                (a.flags & NON_GREEDY) == (b.flags & NON_GREEDY)
                    && a.min == b.min
                    && a.max == b.max
                    && self.equal_first_sub(a, b)
            }
            Op::Capture => a.cap == b.cap && a.name == b.name && self.equal_first_sub(a, b),
            _ => true,
        }
    }

    fn equal_first_sub(&self, a: &Node, b: &Node) -> bool {
        match (a.sub.first(), b.sub.first()) {
            (Some(&p), Some(&q)) => self.equal(p, q),
            _ => false,
        }
    }

    /// Go `isCharClass`: a one-rune literal, a class, `.` or `(?s:.)`.
    fn is_char_class(&self, id: usize) -> bool {
        let n = self.n(id);
        (n.op == Op::Literal && n.runes.len() == 1)
            || matches!(n.op, Op::CharClass | Op::AnyCharNotNl | Op::AnyChar)
    }

    /// Go `mergeCharClass` (`dst |= src`; `dst` is at least as complex). The Rust atoms keep the
    /// exact union whatever Go's op becomes.
    fn merge_char_class(&mut self, dst: usize, src: usize) {
        let s = self.n(src).clone();
        let src_atoms = node_atoms(&s);
        let d = self.n(dst).clone();
        let mut atoms = node_atoms(&d);
        atoms.extend(src_atoms);
        let mut class = d.class.clone();
        let op = match d.op {
            Op::AnyChar => Op::AnyChar,
            Op::AnyCharNotNl => {
                if match_rune(&s, '\n') {
                    Op::AnyChar
                } else {
                    Op::AnyCharNotNl
                }
            }
            Op::CharClass => {
                if s.op == Op::Literal {
                    let c = s.runes.first().copied().unwrap_or('\u{0}');
                    append_literal(&mut class.ranges, c, s.flags & FOLD_CASE != 0);
                    class.opaque |= literal_fold_unknown(c, s.flags);
                } else {
                    class.ranges.extend(s.class.ranges.iter().copied());
                    class.opaque |= s.class.opaque;
                }
                Op::CharClass
            }
            Op::Literal => {
                let (dc, sc) = (d.runes.first().copied(), s.runes.first().copied());
                if dc == sc && d.flags == s.flags {
                    Op::Literal
                } else {
                    class.ranges.clear();
                    let dc = dc.unwrap_or('\u{0}');
                    let sc = sc.unwrap_or('\u{0}');
                    append_literal(&mut class.ranges, dc, d.flags & FOLD_CASE != 0);
                    append_literal(&mut class.ranges, sc, s.flags & FOLD_CASE != 0);
                    class.opaque = literal_fold_unknown(dc, d.flags) || literal_fold_unknown(sc, s.flags);
                    Op::CharClass
                }
            }
            _ => d.op,
        };
        clean_class(&mut class.ranges);
        class.atoms = atoms;
        if let Some(n) = self.nm(dst) {
            n.op = op;
            n.class = class;
        }
    }

    /// Go `cleanAlt`: a class covering everything becomes `(?s:.)`, one covering all but `\n`
    /// becomes `.`.
    fn clean_alt(&mut self, id: usize) {
        let Some(n) = self.nm(id) else { return };
        if n.op != Op::CharClass {
            return;
        }
        clean_class(&mut n.class.ranges);
        if n.class.opaque {
            return;
        }
        if n.class.ranges == [(0, MAX_RUNE)] {
            n.op = Op::AnyChar;
        } else if n.class.ranges == [(0, 9), (11, MAX_RUNE)] {
            n.op = Op::AnyCharNotNl;
        }
    }

    /// Go `parseVerticalBar`.
    fn parse_vertical_bar(&mut self) -> PResult<()> {
        self.concat()?;
        if !self.swap_vertical_bar() {
            self.push_op(Op::VerticalBar)?;
        }
        Ok(())
    }

    /// Go `swapVerticalBar`.
    fn swap_vertical_bar(&mut self) -> bool {
        let n = self.stack.len();
        if n >= 3 {
            let (s1, s2, s3) = (
                self.stack.get(n.saturating_sub(1)).copied().unwrap_or(0),
                self.stack.get(n.saturating_sub(2)).copied().unwrap_or(0),
                self.stack.get(n.saturating_sub(3)).copied().unwrap_or(0),
            );
            if self.op(s2) == Op::VerticalBar && self.is_char_class(s1) && self.is_char_class(s3) {
                let (mut re1, mut re3) = (s1, s3);
                if self.op(re1) > self.op(re3) {
                    std::mem::swap(&mut re1, &mut re3);
                    if let Some(slot) = self.stack.get_mut(n.saturating_sub(3)) {
                        *slot = re3;
                    }
                }
                self.merge_char_class(re3, re1);
                self.reuse(re1);
                self.stack.truncate(n.saturating_sub(1));
                return true;
            }
        }
        if n >= 2 {
            let (re1, re2) = (
                self.stack.get(n.saturating_sub(1)).copied().unwrap_or(0),
                self.stack.get(n.saturating_sub(2)).copied().unwrap_or(0),
            );
            if self.op(re2) == Op::VerticalBar {
                if n >= 3
                    && let Some(&s3) = self.stack.get(n.saturating_sub(3))
                {
                    self.clean_alt(s3);
                }
                if let Some(slot) = self.stack.get_mut(n.saturating_sub(2)) {
                    *slot = re1;
                }
                if let Some(slot) = self.stack.get_mut(n.saturating_sub(1)) {
                    *slot = re2;
                }
                return true;
            }
        }
        false
    }

    /// Go `parseRightParen`.
    fn parse_right_paren(&mut self) -> PResult<()> {
        self.concat()?;
        if self.swap_vertical_bar() {
            self.stack.pop();
        }
        self.alternate()?;
        let n = self.stack.len();
        if n < 2 {
            return Err(GoRegexError::UnexpectedParen);
        }
        let re1 = self.stack.get(n.saturating_sub(1)).copied().unwrap_or(0);
        let re2 = self.stack.get(n.saturating_sub(2)).copied().unwrap_or(0);
        self.stack.truncate(n.saturating_sub(2));
        if self.op(re2) != Op::LeftParen {
            return Err(GoRegexError::UnexpectedParen);
        }
        self.flags = self.n(re2).flags;
        if self.n(re2).cap == 0 {
            self.push(re1)?;
        } else {
            if let Some(node) = self.nm(re2) {
                node.op = Op::Capture;
                node.sub = vec![re1];
            }
            self.push(re2)?;
        }
        Ok(())
    }

    /// Go `parseClass`.
    fn parse_class<'a>(&mut self, s: &'a str) -> PResult<&'a str> {
        let mut t = rest_after(s, 1);
        let fold = self.flags & FOLD_CASE != 0;
        let id = self.new_node(Op::CharClass);
        let mut negated = false;
        if t.starts_with('^') {
            negated = true;
            t = rest_after(t, 1);
            // Perl flags include ClassNL: `[^a]` matches `\n`.
        }
        let mut shape: Vec<(u32, u32)> = Vec::new();
        let mut opaque = false;
        let mut body = String::new();
        let mut first = true;
        loop {
            if t.is_empty() {
                return Err(GoRegexError::MissingBracket);
            }
            if t.starts_with(']') && !first {
                break;
            }
            first = false;
            // POSIX class `[:alpha:]`.
            if t.len() > 2
                && t.starts_with("[:")
                && let Some(i) = t.get(2..).and_then(|r| r.find(":]"))
            {
                let name = t.get(..i.saturating_add(4)).unwrap_or("");
                let g = posix_group(name).ok_or(GoRegexError::InvalidCharRange)?;
                add_group(&g, fold, &mut shape, &mut body);
                t = rest_after(t, name.len());
                continue;
            }
            if t.starts_with("\\p") || t.starts_with("\\P") {
                let (c, rest) = parse_unicode_class(t, self.flags)?;
                for a in &c.atoms {
                    // Unicode items (opaque) or ASCII (explicit).
                    body.push_str(a.text.as_str());
                }
                if c.opaque {
                    opaque = true;
                } else {
                    shape.extend(c.ranges.iter().copied());
                }
                t = rest;
                continue;
            }
            if let Some(g) = t
                .strip_prefix('\\')
                .and_then(|r| r.as_bytes().first().copied())
                .and_then(perl_group)
            {
                add_group(&g, fold, &mut shape, &mut body);
                t = rest_after(t, 2);
                continue;
            }
            let (lo, rest) = parse_class_char(t)?;
            t = rest;
            let mut hi = lo;
            if t.len() >= 2 && t.starts_with('-') && !t.starts_with("-]") {
                let (h, rest) = parse_class_char(rest_after(t, 1))?;
                if h < lo {
                    return Err(GoRegexError::InvalidCharRange);
                }
                hi = h;
                t = rest;
            }
            push_class_char(&mut body, lo);
            if hi != lo {
                body.push('-');
                push_class_char(&mut body, hi);
            }
            if fold {
                opaque |= range_fold_unknown(u32::from(lo), u32::from(hi));
                append_folded_range(&mut shape, u32::from(lo), u32::from(hi));
            } else {
                shape.push((u32::from(lo), u32::from(hi)));
            }
        }
        t = rest_after(t, 1);
        clean_class(&mut shape);
        if negated {
            shape = negate_class(&shape);
        }
        let text = format!("[{}{}]", if negated { "^" } else { "" }, body);
        let flags = self.flags;
        if let Some(n) = self.nm(id) {
            n.flags = flags;
            n.class = Class {
                ranges: shape,
                opaque,
                atoms: vec![Atom { text, fold }],
            };
        }
        self.push(id)?;
        Ok(t)
    }

    // ---- Writing Rust syntax ------------------------------------------------------------------

    fn emit(&self, id: usize, need: Need, fold_ctx: bool, out: &mut String) {
        let node = self.n(id);
        match node.op {
            Op::NoMatch => out.push_str(EMPTY_CLASS),
            Op::EmptyMatch => out.push_str("(?:)"),
            Op::Literal => {
                let fold = node.flags & FOLD_CASE != 0;
                let wrap_flag = fold != fold_ctx;
                if wrap_flag {
                    out.push_str(if fold { "(?i:" } else { "(?-i:" });
                } else if node.runes.len() > 1 && need == Need::Atom {
                    out.push_str("(?:");
                }
                for &c in &node.runes {
                    push_literal(out, c);
                }
                if wrap_flag || (node.runes.len() > 1 && need == Need::Atom) {
                    out.push(')');
                }
            }
            Op::CharClass | Op::AnyChar | Op::AnyCharNotNl => {
                let atoms = node_atoms(node);
                emit_atoms(&atoms, fold_ctx, out);
            }
            Op::BeginLine => out.push_str("(?m:^)"),
            Op::EndLine => out.push_str("(?m:$)"),
            Op::BeginText => out.push_str("\\A"),
            Op::EndText => out.push_str("\\z"),
            Op::WordBoundary => out.push_str("(?-u:\\b)"),
            Op::NoWordBoundary => out.push_str("(?-u:\\B)"),
            Op::Capture => {
                if let Some(&s) = node.sub.first() {
                    self.emit(s, need, fold_ctx, out);
                } else {
                    out.push_str("(?:)");
                }
            }
            Op::Star | Op::Plus | Op::Quest | Op::Repeat => {
                let group = need == Need::Atom;
                if group {
                    out.push_str("(?:");
                }
                match node.sub.first() {
                    Some(&s) => self.emit(s, Need::Atom, fold_ctx, out),
                    None => out.push_str("(?:)"),
                }
                match node.op {
                    Op::Star => out.push('*'),
                    Op::Plus => out.push('+'),
                    Op::Quest => out.push('?'),
                    _ => {
                        if node.max == -1 {
                            let _ = write!(out, "{{{},}}", node.min);
                        } else if node.min == node.max {
                            let _ = write!(out, "{{{}}}", node.min);
                        } else {
                            let _ = write!(out, "{{{},{}}}", node.min, node.max);
                        }
                    }
                }
                if node.flags & NON_GREEDY != 0 {
                    out.push('?');
                }
                if group {
                    out.push(')');
                }
            }
            Op::Concat => {
                let group = need == Need::Atom;
                if group {
                    out.push_str("(?:");
                }
                for &s in &node.sub {
                    self.emit(s, Need::Concat, fold_ctx, out);
                }
                if group {
                    out.push(')');
                }
            }
            Op::Alternate => {
                let group = need != Need::Alt;
                if group {
                    out.push_str("(?:");
                }
                for (k, &s) in node.sub.iter().enumerate() {
                    if k > 0 {
                        out.push('|');
                    }
                    self.emit(s, Need::Alt, fold_ctx, out);
                }
                if group {
                    out.push(')');
                }
            }
            Op::LeftParen | Op::VerticalBar => {}
        }
    }
}

static NO_NODE: Node = Node {
    op: Op::NoMatch,
    flags: 0,
    runes: Vec::new(),
    class: Class {
        ranges: Vec::new(),
        opaque: false,
        atoms: Vec::new(),
    },
    sub: Vec::new(),
    min: 0,
    max: 0,
    cap: 0,
    name: None,
    size: 1,
    height: 1,
};

/// The context a node is written in: an alternation branch, a concatenation element, or the operand
/// of a repetition.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Alt,
    Concat,
    Atom,
}

/// A class that matches nothing.
const EMPTY_CLASS: &str = "[^\\x{0}-\\x{10FFFF}]";

fn rest_after(s: &str, n: usize) -> &str {
    s.get(n..).unwrap_or("")
}

/// The Rust atoms a class-like node matches.
fn node_atoms(n: &Node) -> Vec<Atom> {
    match n.op {
        Op::Literal => n
            .runes
            .first()
            .map(|&c| {
                let mut text = String::from("[");
                push_class_char(&mut text, c);
                text.push(']');
                vec![Atom {
                    text,
                    fold: n.flags & FOLD_CASE != 0,
                }]
            })
            .unwrap_or_default(),
        Op::AnyChar if n.class.atoms.is_empty() => vec![Atom {
            text: "[\\x{0}-\\x{10FFFF}]".into(),
            fold: false,
        }],
        Op::AnyCharNotNl if n.class.atoms.is_empty() => vec![Atom {
            text: "[^\\n]".into(),
            fold: false,
        }],
        _ => n.class.atoms.clone(),
    }
}

/// Writes a union of atoms: one bracket per fold flag, alternated when both occur.
fn emit_atoms(atoms: &[Atom], fold_ctx: bool, out: &mut String) {
    let group = |fold: bool| -> Option<String> {
        let parts: Vec<&str> = atoms
            .iter()
            .filter(|a| a.fold == fold)
            .map(|a| a.text.as_str())
            .collect();
        match parts.as_slice() {
            [] => None,
            [one] => Some((*one).to_string()),
            many => Some(format!("[{}]", many.concat())),
        }
    };
    let flagged = |fold: bool, text: String| -> String {
        if fold == fold_ctx {
            text
        } else if fold {
            format!("(?i:{text})")
        } else {
            format!("(?-i:{text})")
        }
    };
    match (group(true), group(false)) {
        (None, None) => out.push_str(EMPTY_CLASS),
        (Some(a), None) => out.push_str(&flagged(true, a)),
        (None, Some(b)) => out.push_str(&flagged(false, b)),
        (Some(a), Some(b)) => {
            let _ = write!(out, "(?:{}|{})", flagged(true, a), flagged(false, b));
        }
    }
}

/// Writes one literal character outside a class.
fn push_literal(out: &mut String, c: char) {
    if c.is_ascii_alphanumeric() || !c.is_ascii() {
        out.push(c);
    } else if c.is_ascii_graphic() && c != '<' && c != '>' {
        out.push('\\');
        out.push(c);
    } else {
        let _ = write!(out, "\\x{{{:X}}}", u32::from(c));
    }
}

/// Writes one literal character inside a class.
fn push_class_char(out: &mut String, c: char) {
    if c.is_ascii_alphanumeric() || !c.is_ascii() {
        out.push(c);
    } else {
        let _ = write!(out, "\\x{{{:X}}}", u32::from(c));
    }
}

// ---- Case folding (exact for ASCII; see the module docs) --------------------------------------

/// Go `minFoldRune` for the runes whose fold orbit holds ASCII; others are left as they are.
fn min_fold(c: char) -> char {
    match c {
        'a'..='z' => c.to_ascii_uppercase(),
        '\u{17F}' => 'S',
        '\u{212A}' => 'K',
        _ => c,
    }
}

/// The ASCII-reaching fold orbit of `c` (Go `unicode.SimpleFold` cycle), `None` when unknown.
fn ascii_orbit(c: u32) -> Option<&'static [u32]> {
    const K: &[u32] = &[0x4B, 0x6B, 0x212A];
    const S: &[u32] = &[0x53, 0x73, 0x17F];
    match c {
        0x4B | 0x6B | 0x212A => Some(K),
        0x53 | 0x73 | 0x17F => Some(S),
        _ => None,
    }
}

/// True for an ASCII letter pair `[Aa]` Go reads as one folded rune.
fn fold_pair(a: u32, b: u32) -> bool {
    let (Some(x), Some(y)) = (char::from_u32(a), char::from_u32(b)) else {
        return false;
    };
    x.is_ascii_uppercase() && y.is_ascii_lowercase() && x.to_ascii_lowercase() == y && !matches!(y, 'k' | 's')
}

/// True when folding the range under `(?i)` reaches runes this module doesn't fold exactly: a
/// non-ASCII rune up to Go's `maxFold` other than `ſ` and `K`.
fn range_fold_unknown(lo: u32, hi: u32) -> bool {
    let (l, h) = (lo.max(0x80), hi.min(0x1_E943));
    if l > h {
        return false;
    }
    let known = [0x17Fu32, 0x212A]
        .iter()
        .filter(|&&c| (l..=h).contains(&c))
        .count();
    u64::from(h.saturating_sub(l)).saturating_add(1) > known as u64
}

fn literal_fold_unknown(c: char, flags: u16) -> bool {
    flags & FOLD_CASE != 0 && range_fold_unknown(u32::from(c), u32::from(c))
}

/// Go `appendFoldedRange`, exact for ASCII.
fn append_folded_range(r: &mut Vec<(u32, u32)>, lo: u32, hi: u32) {
    r.push((lo, hi));
    for (a, b, delta) in [(0x41u32, 0x5Au32, 0x20u32), (0x61, 0x7A, 0)] {
        let (l, h) = (lo.max(a), hi.min(b));
        if l <= h {
            if delta == 0x20 {
                r.push((l.saturating_add(0x20), h.saturating_add(0x20)));
            } else {
                r.push((l.saturating_sub(0x20), h.saturating_sub(0x20)));
            }
        }
    }
    for c in [0x4Bu32, 0x6B, 0x212A, 0x53, 0x73, 0x17F] {
        if (lo..=hi).contains(&c)
            && let Some(orbit) = ascii_orbit(c)
        {
            r.extend(orbit.iter().map(|&o| (o, o)));
        }
    }
}

/// Go `appendLiteral`.
fn append_literal(r: &mut Vec<(u32, u32)>, c: char, fold: bool) {
    let c = u32::from(c);
    if fold {
        append_folded_range(r, c, c);
    } else {
        r.push((c, c));
    }
}

/// Go `cleanClass`: sort and merge.
fn clean_class(r: &mut Vec<(u32, u32)>) {
    r.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(r.len());
    for &(lo, hi) in r.iter() {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => {
                if hi > last.1 {
                    last.1 = hi;
                }
            }
            _ => out.push((lo, hi)),
        }
    }
    *r = out;
}

/// Go `negateClass` over a clean class.
fn negate_class(r: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut out = Vec::with_capacity(r.len().saturating_add(1));
    let mut next = 0u32;
    for &(lo, hi) in r {
        if lo > next {
            out.push((next, lo.saturating_sub(1)));
        }
        next = hi.saturating_add(1);
    }
    if next <= MAX_RUNE {
        out.push((next, MAX_RUNE));
    }
    out
}

/// Go `matchRune` for a class-like node (an opaque class is taken as matching).
fn match_rune(n: &Node, c: char) -> bool {
    let c = u32::from(c);
    match n.op {
        Op::Literal => n.runes.len() == 1 && n.runes.first().map(|&r| u32::from(r)) == Some(c),
        Op::CharClass => n.class.opaque || n.class.ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi),
        Op::AnyCharNotNl => c != u32::from('\n'),
        Op::AnyChar => true,
        _ => false,
    }
}

// ---- Escapes and classes ------------------------------------------------------------------------

/// Go `parseEscape`: the escaped rune at the start of `s` (which begins with `\`).
fn parse_escape(s: &str) -> PResult<(char, &str)> {
    let t = rest_after(s, 1);
    let c = t.chars().next().ok_or(GoRegexError::TrailingBackslash)?;
    let mut t = rest_after(t, c.len_utf8());
    let digit = |t: &str| {
        t.as_bytes()
            .first()
            .filter(|b| (b'0'..=b'7').contains(b))
            .copied()
    };
    match c {
        '1'..='7' if digit(t).is_none() => Err(GoRegexError::InvalidEscape),
        '0'..='7' => {
            let mut r = u32::from(c).saturating_sub(u32::from('0'));
            for _ in 1..3 {
                let Some(d) = digit(t) else { break };
                r = r
                    .saturating_mul(8)
                    .saturating_add(u32::from(d.saturating_sub(b'0')));
                t = rest_after(t, 1);
            }
            Ok((char::from_u32(r).unwrap_or('\u{0}'), t))
        }
        'x' => {
            let c = t.chars().next().ok_or(GoRegexError::InvalidEscape)?;
            t = rest_after(t, c.len_utf8());
            if c == '{' {
                let mut r: u32 = 0;
                let mut nhex = 0usize;
                loop {
                    let d = t.chars().next().ok_or(GoRegexError::InvalidEscape)?;
                    t = rest_after(t, d.len_utf8());
                    if d == '}' {
                        break;
                    }
                    let v = d.to_digit(16).ok_or(GoRegexError::InvalidEscape)?;
                    r = r.saturating_mul(16).saturating_add(v);
                    if r > MAX_RUNE {
                        return Err(GoRegexError::InvalidEscape);
                    }
                    nhex = nhex.saturating_add(1);
                }
                if nhex == 0 {
                    return Err(GoRegexError::InvalidEscape);
                }
                // Go accepts a surrogate code point here; no decoded text holds one, so it matches
                // nothing. U+FFFF stands in for it (match targets are ASCII).
                return Ok((char::from_u32(r).unwrap_or('\u{FFFF}'), t));
            }
            let x = c.to_digit(16);
            let d = t.chars().next().ok_or(GoRegexError::InvalidEscape)?;
            t = rest_after(t, d.len_utf8());
            match (x, d.to_digit(16)) {
                (Some(x), Some(y)) => Ok((
                    char::from_u32(x.saturating_mul(16).saturating_add(y)).unwrap_or('\u{0}'),
                    t,
                )),
                _ => Err(GoRegexError::InvalidEscape),
            }
        }
        'a' => Ok(('\u{7}', t)),
        'f' => Ok(('\u{c}', t)),
        'n' => Ok(('\n', t)),
        'r' => Ok(('\r', t)),
        't' => Ok(('\t', t)),
        'v' => Ok(('\u{b}', t)),
        c if c.is_ascii() && !c.is_ascii_alphanumeric() => Ok((c, t)),
        _ => Err(GoRegexError::InvalidEscape),
    }
}

/// Go `parseClassChar`.
fn parse_class_char(s: &str) -> PResult<(char, &str)> {
    if s.starts_with('\\') {
        return parse_escape(s);
    }
    let c = s.chars().next().ok_or(GoRegexError::MissingBracket)?;
    Ok((c, rest_after(s, c.len_utf8())))
}

/// `{min}`, `{min,}` (max -1) or `{min,max}`, Go `parseRepeat`: `None` when `s` isn't one (the `{`
/// is then a literal); a number over 10^8 gives min -1.
fn parse_repeat(s: &str) -> Option<(i32, i32, &str)> {
    let t = s.strip_prefix('{')?;
    let (mut min, t) = parse_int(t)?;
    let (max, t) = if let Some(t) = t.strip_prefix(',') {
        if t.starts_with('}') {
            (-1, t)
        } else {
            let (max, t) = parse_int(t)?;
            if max < 0 {
                min = -1;
            }
            (max, t)
        }
    } else {
        (min, t)
    };
    let t = t.strip_prefix('}')?;
    Some((min, max, t))
}

/// Go `parseInt`: digits without a leading zero; -1 when too big.
fn parse_int(s: &str) -> Option<(i32, &str)> {
    let b = s.as_bytes();
    if !b.first().is_some_and(u8::is_ascii_digit) {
        return None;
    }
    if b.len() >= 2 && b.first() == Some(&b'0') && b.get(1).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let end = b.iter().position(|c| !c.is_ascii_digit()).unwrap_or(b.len());
    let mut n: i64 = 0;
    for &d in b.get(..end).unwrap_or(&[]) {
        if n >= 100_000_000 {
            n = -1;
            break;
        }
        n = n
            .saturating_mul(10)
            .saturating_add(i64::from(d.saturating_sub(b'0')));
    }
    Some((i32::try_from(n).unwrap_or(-1), rest_after(s, end)))
}

/// A Perl or POSIX group: its ASCII ranges and whether it is negated.
struct Group {
    ranges: &'static [(u32, u32)],
    negated: bool,
}

const DIGIT: &[(u32, u32)] = &[(0x30, 0x39)];
const SPACE: &[(u32, u32)] = &[(0x9, 0xA), (0xC, 0xD), (0x20, 0x20)];
const WORD: &[(u32, u32)] = &[(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)];

/// Go `perlGroup` (`\d \D \s \S \w \W`, ASCII).
fn perl_group(c: u8) -> Option<Group> {
    let (ranges, negated) = match c {
        b'd' => (DIGIT, false),
        b'D' => (DIGIT, true),
        b's' => (SPACE, false),
        b'S' => (SPACE, true),
        b'w' => (WORD, false),
        b'W' => (WORD, true),
        _ => return None,
    };
    Some(Group { ranges, negated })
}

/// Go `posixGroup` (`[:alpha:]`, `[:^alpha:]`, …).
fn posix_group(name: &str) -> Option<Group> {
    let (negated, bare) = match name.strip_prefix("[:^") {
        Some(rest) => (true, rest.strip_suffix(":]")?),
        None => (false, name.strip_prefix("[:")?.strip_suffix(":]")?),
    };
    let ranges: &'static [(u32, u32)] = match bare {
        "alnum" => &[(0x30, 0x39), (0x41, 0x5A), (0x61, 0x7A)],
        "alpha" => &[(0x41, 0x5A), (0x61, 0x7A)],
        "ascii" => &[(0x0, 0x7F)],
        "blank" => &[(0x9, 0x9), (0x20, 0x20)],
        "cntrl" => &[(0x0, 0x1F), (0x7F, 0x7F)],
        "digit" => DIGIT,
        "graph" => &[(0x21, 0x7E)],
        "lower" => &[(0x61, 0x7A)],
        "print" => &[(0x20, 0x7E)],
        "punct" => &[(0x21, 0x2F), (0x3A, 0x40), (0x5B, 0x60), (0x7B, 0x7E)],
        "space" => &[(0x9, 0xD), (0x20, 0x20)],
        "upper" => &[(0x41, 0x5A)],
        "word" => WORD,
        "xdigit" => &[(0x30, 0x39), (0x41, 0x46), (0x61, 0x66)],
        _ => return None,
    };
    Some(Group { ranges, negated })
}

/// The Rust text of a group's ranges (a bracket, negated for a negated group).
fn group_text(g: &Group) -> String {
    let mut s = String::from(if g.negated { "[^" } else { "[" });
    for &(lo, hi) in g.ranges {
        push_class_char(&mut s, char::from_u32(lo).unwrap_or('\u{0}'));
        if hi != lo {
            s.push('-');
            push_class_char(&mut s, char::from_u32(hi).unwrap_or('\u{0}'));
        }
    }
    s.push(']');
    s
}

/// Go `appendGroup` into a class being built: fold, then negate.
fn add_group(g: &Group, fold: bool, shape: &mut Vec<(u32, u32)>, body: &mut String) {
    let mut set: Vec<(u32, u32)> = Vec::new();
    for &(lo, hi) in g.ranges {
        if fold {
            append_folded_range(&mut set, lo, hi);
        } else {
            set.push((lo, hi));
        }
    }
    clean_class(&mut set);
    if g.negated {
        set = negate_class(&set);
    }
    shape.extend(set);
    body.push_str(&group_text(g));
}

/// A class node's class for a group written alone (`\d`, `\W`).
fn group_class(g: &Group, fold: bool) -> Class {
    let mut shape = Vec::new();
    let mut body = String::new();
    add_group(g, fold, &mut shape, &mut body);
    clean_class(&mut shape);
    Class {
        ranges: shape,
        opaque: false,
        atoms: vec![Atom {
            // `body` is one bracket already.
            text: body,
            fold,
        }],
    }
}

/// Go `parseUnicodeClass`: `\pL`, `\p{Greek}`, `\p{^Greek}`, `\PL`, at the start of `s`.
fn parse_unicode_class(s: &str, flags: u16) -> PResult<(Class, &str)> {
    let fold = flags & FOLD_CASE != 0;
    let mut negated = s.as_bytes().get(1) == Some(&b'P');
    let t = rest_after(s, 2);
    let c = t.chars().next().ok_or(GoRegexError::InvalidCharRange)?;
    let (mut name, rest) = if c != '{' {
        (t.get(..c.len_utf8()).unwrap_or(""), rest_after(t, c.len_utf8()))
    } else {
        let end = t.find('}').ok_or(GoRegexError::InvalidCharRange)?;
        (t.get(1..end).unwrap_or(""), rest_after(t, end.saturating_add(1)))
    };
    if let Some(n) = name.strip_prefix('^') {
        negated = !negated;
        name = n;
    }
    let table = unicode_table(name).ok_or(GoRegexError::InvalidCharRange)?;
    let class = match table {
        Table::Ascii => {
            // ASCII is explicit (its fold table adds `ſ` and `K`).
            let mut shape = Vec::new();
            if fold {
                append_folded_range(&mut shape, 0, 0x7F);
            } else {
                shape.push((0, 0x7F));
            }
            clean_class(&mut shape);
            if negated {
                shape = negate_class(&shape);
            }
            let text = if negated {
                "[^\\x{0}-\\x{7F}]"
            } else {
                "[\\x{0}-\\x{7F}]"
            };
            Class {
                ranges: shape,
                opaque: false,
                atoms: vec![Atom {
                    text: text.into(),
                    fold,
                }],
            }
        }
        Table::Rust { text, negate } => {
            let neg = negated != negate;
            let atom = if rust_knows(&text) {
                format!("[{}{}]", if neg { "^" } else { "" }, text)
            } else if neg {
                // A table Rust lacks has no ASCII runes (module docs): its complement is all of ASCII.
                "[\\x{0}-\\x{10FFFF}]".to_string()
            } else {
                EMPTY_CLASS.to_string()
            };
            Class {
                ranges: Vec::new(),
                opaque: true,
                atoms: vec![Atom { text: atom, fold }],
            }
        }
    };
    Ok((class, rest))
}

/// A Go Unicode table as Rust writes it.
enum Table {
    Ascii,
    /// A Rust property (`\p{gc=Lu}`, `\p{sc=Greek}`, `\p{Any}`), negated for `Assigned`.
    Rust {
        text: String,
        negate: bool,
    },
}

/// Go 1.27's `unicode.Categories` keys.
const CATEGORIES: &[&str] = &[
    "C", "Cc", "Cf", "Cn", "Co", "Cs", "L", "LC", "Ll", "Lm", "Lo", "Lt", "Lu", "M", "Mc", "Me", "Mn", "N",
    "Nd", "Nl", "No", "P", "Pc", "Pd", "Pe", "Pf", "Pi", "Po", "Ps", "S", "Sc", "Sk", "Sm", "So", "Z", "Zl",
    "Zp", "Zs",
];

/// Go 1.27's `unicode.CategoryAliases`.
const CATEGORY_ALIASES: &[(&str, &str)] = &[
    ("Cased_Letter", "LC"),
    ("Close_Punctuation", "Pe"),
    ("Combining_Mark", "M"),
    ("Connector_Punctuation", "Pc"),
    ("Control", "Cc"),
    ("Currency_Symbol", "Sc"),
    ("Dash_Punctuation", "Pd"),
    ("Decimal_Number", "Nd"),
    ("Enclosing_Mark", "Me"),
    ("Final_Punctuation", "Pf"),
    ("Format", "Cf"),
    ("Initial_Punctuation", "Pi"),
    ("Letter", "L"),
    ("Letter_Number", "Nl"),
    ("Line_Separator", "Zl"),
    ("Lowercase_Letter", "Ll"),
    ("Mark", "M"),
    ("Math_Symbol", "Sm"),
    ("Modifier_Letter", "Lm"),
    ("Modifier_Symbol", "Sk"),
    ("Nonspacing_Mark", "Mn"),
    ("Number", "N"),
    ("Open_Punctuation", "Ps"),
    ("Other", "C"),
    ("Other_Letter", "Lo"),
    ("Other_Number", "No"),
    ("Other_Punctuation", "Po"),
    ("Other_Symbol", "So"),
    ("Paragraph_Separator", "Zp"),
    ("Private_Use", "Co"),
    ("Punctuation", "P"),
    ("Separator", "Z"),
    ("Space_Separator", "Zs"),
    ("Spacing_Mark", "Mc"),
    ("Surrogate", "Cs"),
    ("Symbol", "S"),
    ("Titlecase_Letter", "Lt"),
    ("Unassigned", "Cn"),
    ("Uppercase_Letter", "Lu"),
    ("cntrl", "Cc"),
    ("digit", "Nd"),
    ("punct", "P"),
];

/// Go 1.27's `unicode.Scripts` keys (Unicode 17.0.0).
const SCRIPTS: &[&str] = &[
    "Adlam",
    "Ahom",
    "Anatolian_Hieroglyphs",
    "Arabic",
    "Armenian",
    "Avestan",
    "Balinese",
    "Bamum",
    "Bassa_Vah",
    "Batak",
    "Bengali",
    "Beria_Erfe",
    "Bhaiksuki",
    "Bopomofo",
    "Brahmi",
    "Braille",
    "Buginese",
    "Buhid",
    "Canadian_Aboriginal",
    "Carian",
    "Caucasian_Albanian",
    "Chakma",
    "Cham",
    "Cherokee",
    "Chorasmian",
    "Common",
    "Coptic",
    "Cuneiform",
    "Cypriot",
    "Cypro_Minoan",
    "Cyrillic",
    "Deseret",
    "Devanagari",
    "Dives_Akuru",
    "Dogra",
    "Duployan",
    "Egyptian_Hieroglyphs",
    "Elbasan",
    "Elymaic",
    "Ethiopic",
    "Garay",
    "Georgian",
    "Glagolitic",
    "Gothic",
    "Grantha",
    "Greek",
    "Gujarati",
    "Gunjala_Gondi",
    "Gurmukhi",
    "Gurung_Khema",
    "Han",
    "Hangul",
    "Hanifi_Rohingya",
    "Hanunoo",
    "Hatran",
    "Hebrew",
    "Hiragana",
    "Imperial_Aramaic",
    "Inherited",
    "Inscriptional_Pahlavi",
    "Inscriptional_Parthian",
    "Javanese",
    "Kaithi",
    "Kannada",
    "Katakana",
    "Kawi",
    "Kayah_Li",
    "Kharoshthi",
    "Khitan_Small_Script",
    "Khmer",
    "Khojki",
    "Khudawadi",
    "Kirat_Rai",
    "Lao",
    "Latin",
    "Lepcha",
    "Limbu",
    "Linear_A",
    "Linear_B",
    "Lisu",
    "Lycian",
    "Lydian",
    "Mahajani",
    "Makasar",
    "Malayalam",
    "Mandaic",
    "Manichaean",
    "Marchen",
    "Masaram_Gondi",
    "Medefaidrin",
    "Meetei_Mayek",
    "Mende_Kikakui",
    "Meroitic_Cursive",
    "Meroitic_Hieroglyphs",
    "Miao",
    "Modi",
    "Mongolian",
    "Mro",
    "Multani",
    "Myanmar",
    "Nabataean",
    "Nag_Mundari",
    "Nandinagari",
    "New_Tai_Lue",
    "Newa",
    "Nko",
    "Nushu",
    "Nyiakeng_Puachue_Hmong",
    "Ogham",
    "Ol_Chiki",
    "Ol_Onal",
    "Old_Hungarian",
    "Old_Italic",
    "Old_North_Arabian",
    "Old_Permic",
    "Old_Persian",
    "Old_Sogdian",
    "Old_South_Arabian",
    "Old_Turkic",
    "Old_Uyghur",
    "Oriya",
    "Osage",
    "Osmanya",
    "Pahawh_Hmong",
    "Palmyrene",
    "Pau_Cin_Hau",
    "Phags_Pa",
    "Phoenician",
    "Psalter_Pahlavi",
    "Rejang",
    "Runic",
    "Samaritan",
    "Saurashtra",
    "Sharada",
    "Shavian",
    "Siddham",
    "Sidetic",
    "SignWriting",
    "Sinhala",
    "Sogdian",
    "Sora_Sompeng",
    "Soyombo",
    "Sundanese",
    "Sunuwar",
    "Syloti_Nagri",
    "Syriac",
    "Tagalog",
    "Tagbanwa",
    "Tai_Le",
    "Tai_Tham",
    "Tai_Viet",
    "Tai_Yo",
    "Takri",
    "Tamil",
    "Tangsa",
    "Tangut",
    "Telugu",
    "Thaana",
    "Thai",
    "Tibetan",
    "Tifinagh",
    "Tirhuta",
    "Todhri",
    "Tolong_Siki",
    "Toto",
    "Tulu_Tigalari",
    "Ugaritic",
    "Vai",
    "Vithkuqi",
    "Wancho",
    "Warang_Citi",
    "Yezidi",
    "Yi",
    "Zanabazar_Square",
];

/// Go `canonicalName`: first letter upper, the rest lower, `_`, `-` and spaces dropped.
fn canonical_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut first = true;
    for c in name.chars() {
        if matches!(c, '_' | '-' | ' ') {
            continue;
        }
        if first {
            out.push(c.to_ascii_uppercase());
            first = false;
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// Go `unicodeTable`.
fn unicode_table(name: &str) -> Option<Table> {
    let canon = canonical_name(name);
    let cat = |c: &str| Table::Rust {
        text: format!("\\p{{gc={c}}}"),
        negate: false,
    };
    match canon.as_str() {
        "Any" => {
            return Some(Table::Rust {
                text: "\\p{Any}".into(),
                negate: false,
            });
        }
        "Assigned" => {
            return Some(Table::Rust {
                text: "\\p{gc=Cn}".into(),
                negate: true,
            });
        }
        "Ascii" => return Some(Table::Ascii),
        "Lc" => return Some(cat("LC")),
        _ => {}
    }
    if let Some(c) = CATEGORIES.iter().find(|c| **c == canon) {
        return Some(cat(c));
    }
    if let Some(s) = SCRIPTS.iter().find(|s| **s == canon) {
        return Some(Table::Rust {
            text: format!("\\p{{sc={s}}}"),
            negate: false,
        });
    }
    if let Some((_, c)) = CATEGORY_ALIASES.iter().find(|(a, _)| canonical_name(a) == canon) {
        return Some(cat(c));
    }
    if let Some(s) = SCRIPTS.iter().find(|s| canonical_name(s) == canon) {
        return Some(Table::Rust {
            text: format!("\\p{{sc={s}}}"),
            negate: false,
        });
    }
    None
}

/// True when Rust's Unicode tables know the property.
fn rust_knows(text: &str) -> bool {
    static KNOWN: OnceLock<std::sync::Mutex<HashSet<String>>> = OnceLock::new();
    static UNKNOWN: OnceLock<std::sync::Mutex<HashSet<String>>> = OnceLock::new();
    let known = KNOWN.get_or_init(Default::default);
    let unknown = UNKNOWN.get_or_init(Default::default);
    if known.lock().map(|k| k.contains(text)).unwrap_or(false) {
        return true;
    }
    if unknown.lock().map(|k| k.contains(text)).unwrap_or(false) {
        return false;
    }
    let ok = regex_automata::util::syntax::parse(text).is_ok();
    let set = if ok { known } else { unknown };
    if let Ok(mut s) = set.lock() {
        s.insert(text.to_string());
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(go: &str, hay: &str) -> bool {
        let t = translate(go).unwrap_or_else(|e| panic!("{go}: {e}"));
        crate::analysis::build_regex(&t)
            .unwrap_or_else(|e| panic!("{go} -> {t}: {e}"))
            .is_match(hay)
    }

    #[test]
    fn go_specific_syntax() {
        assert!(m(r"a\<b\>", "a<b>"));
        assert!(m(r"[a&&b]", "&"));
        assert!(translate(r"[a--]").is_err(), "Go reads a range a..'-'");
        assert!(m(r"[--/]", "."));
        assert!(m(r"[[a]", "["));
        assert!(m(r"\101", "A"));
        assert!(m(r"\0", "\0"));
        assert!(translate(r"\1").is_err());
        assert!(m(r"\Qa.b\E", "a.b"));
        assert!(!m(r"\Qa.b\E", "axb"));
        assert!(m(r"[\d]x", "5x"));
        assert!(!m(r"\d", "٣"));
        assert!(m(r"\bads\b", "x.ads.y"));
        assert!(m(r"[[:alpha:]]+", "abc"));
        assert!(m(r"\p{Greek}", "α"));
        assert!(m(r"\p{^Greek}", "a"));
        assert!(m(r"\pL", "a"));
        assert!(m(r"a{2}", "aa"));
        assert!(m(r"a{,2}", "a{,2}"));
        assert!(m(r"x{", "x{"));
        assert!(translate("a{1001}").is_err());
        assert!(translate("a**").is_err());
        assert!(translate("*a").is_err());
        assert!(m("a*?", "a"));
        assert!(translate("(?x)a").is_err());
        // Go reads `(?:…)` as a plain group and `(?)` as an empty flag group.
        assert!(m("(?:ads|track)\\.", "track.y.org"));
        assert!(m("^(?:ads|track)\\.$", "ads."));
        assert!(m("(?)ads", "xads"));
        assert!(m("x(?:)y", "xy"));
        assert!(translate("(?-)a").is_err());
        assert!(translate("(?i-)a").is_err());
        assert!(translate("(?=a)").is_err());
        assert!(m("(?i)ABC", "abc"));
        assert!(m("(?i:A)b", "ab"));
        assert!(m("(?P<n>a)", "a"));
        assert!(m("(?<n>a)", "a"));
        assert!(translate("(a").is_err());
        assert!(translate("a)").is_err());
        assert!(translate("[a").is_err());
        assert!(translate("[b-a]").is_err());
        assert!(m("[]a]", "]"));
        assert!(m("[^]a]", "b"));
        assert!(m(r"a\-b", "a-b"));
        assert!(m(r"a#b", "a#b"));
        assert!(m(r"\x41\x{42}", "AB"));
        assert!(m(r"[a-c-e]", "-"));
        assert!(translate("\\").is_err());
        assert!(translate(r"\y").is_err());
    }

    #[test]
    fn go_acceptance() {
        // R2 (review round 1): Go refuses `\C`, accepts numeric and repeated capture names, and
        // refuses nested repeats whose product passes 1000 (`repeatIsValid`).
        assert_eq!(translate(r"\C"), Err(GoRegexError::InvalidEscape));
        assert!(m(r"(?P<x>ads)|(?P<x>tracker)", "tracker"));
        assert!(m(r"(?P<1>example)", "example"));
        assert!(m(r"(?<x>a)(?<x>b)", "ab"));
        assert_eq!(translate(r"(a{1000}){2}"), Err(GoRegexError::InvalidRepeatSize));
        assert!(translate(r"(a{500}){2}").is_ok());
        assert_eq!(
            translate(r"(?:(a{11}){10}){10}"),
            Err(GoRegexError::InvalidRepeatSize)
        );
        assert!(translate(r"(?:(a{10}){10}){10}").is_ok());
        assert!(
            translate(r"((a{600}){0}){2}").is_ok(),
            "a zero-count repeat hides its body"
        );
        assert_eq!(
            translate(r"((a{600}){1}){2}"),
            Err(GoRegexError::InvalidRepeatSize)
        );
        assert!(translate(r"(a{1000})*").is_ok(), "only counted repeats count");
        // `\Q\E` between an operand and `*` doesn't make `*` a nested repeat.
        assert!(m(r"a\Q\E*", "aaa"));
        assert!(m(r"x*\Q\E*", "x"));
        // Leading zeros make `{` a literal.
        assert!(m(r"x{01}", "x{01}"));
        // Loose Unicode names, as Go 1.27 reads them.
        assert!(m(r"\pl", "a"));
        assert!(m(r"\p{Letter}", "a"));
        assert!(m(r"\p{greek}", "α"));
        assert!(m(r"\p{OLD_ITALIC}", "\u{10300}"));
        assert!(!m(r"\p{Greek}", "\u{342}"), "Script, not Script_Extensions");
        assert!(m(r"\p{ascii}", "a"));
        assert!(m(r"\P{Any}|x", "x"));
        assert!(translate(r"\p{Alphabetic}").is_err(), "not a Go table");
        assert!(translate(r"\p{sc=Greek}").is_err());
        assert!(m(r"\p{Sidetic}|ok", "ok"), "a table Rust lacks still builds");
        assert!(!m(r"\p{Cs}", "a"));
        assert!(m(r"\P{Cs}", "a"));
        // Height over 1000 (Go `maxHeight`); non-capturing groups add no level.
        let deep = format!("{}a{}", "(".repeat(1001), ")".repeat(1001));
        assert_eq!(translate(&deep), Err(GoRegexError::NestingDepth));
        let ok = format!("{}a{}", "(".repeat(990), ")".repeat(990));
        assert!(translate(&ok).is_ok());
        let flat = format!("{}a{}", "(?:".repeat(3000), ")".repeat(3000));
        assert!(m(&flat, "a"));
        // A tall tree Go accepts builds in Rust too (nesting limit, no stack overflow).
        let mut tall = String::from("a");
        for _ in 0..450 {
            tall = format!("(?:{tall})*b");
        }
        assert!(m(&tall, "ab"));
        // Size over Go's limit once its gate is open.
        let big = format!("(?:{}){{1000}}", "[a-z]x".repeat(1700));
        assert_eq!(translate(&big), Err(GoRegexError::Large));
    }

    #[test]
    fn case_folding_as_go() {
        assert!(m(r"(?i)[k]", "\u{212A}"));
        assert!(!m(r"(?i)\W", "s"), "fold, then negate");
        assert!(m(r"(?i)[^k]", "x"));
        assert!(!m(r"(?i)[^k]", "K"));
        assert!(m(r"(?i)Ab|aC", "ac"));
        assert!(m(r"(?i:a)x|Ay", "Ay"));
        assert!(!m(r"(?i:a)x|Ay", "ay"));
        assert!(!m(r"(?i:a)x|A", "a"), "Go's Equal compares the fold flag");
        assert!(m(r"(?i)x(?-i:A)|xa", "example"));
        assert!(!m(r"(?i)x(?-i:A)|xa", "xb"));
        assert!(m(r"(?i)abc(?-i)D", "ABCD"));
        assert!(!m(r"(?i)abc(?-i)D", "ABCd"));
    }

    #[test]
    fn linear_output() {
        let input = "a".repeat(10_000) + &"\\.".repeat(10_000);
        let t = translate(&input).unwrap();
        assert!(t.len() <= input.len() * 3);
    }
}
