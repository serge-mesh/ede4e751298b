//! A model of one iptables table, parsed from `iptables-save [-c]` or `iptables -S [-v]` output.
//!
//! The text comes from the kernel's tables, which UniFi writes, so it is untrusted input (README
//! "Untrusted input"): the parser is bounded (total size, line length, rule count) and never
//! panics (fuzzed in `fuzz/helper`). A line over [`MAX_LINE`] bytes is not parsed but still
//! takes its place in its chain as an opaque rule, so rule positions — which jump placement
//! depends on — never shift (edge-firewall.md §4 "Jump placement").

use std::collections::HashMap;

/// Longest line parsed; longer `-A` lines become [`RuleKind::Opaque`].
pub const MAX_LINE: usize = 16 * 1024;
/// Most rules kept per table; a table beyond this fails to parse.
pub const MAX_RULES: usize = 250_000;
/// Most chains per table.
pub const MAX_CHAINS: usize = 20_000;
/// Longest chain name iptables allows (`XT_EXTENSION_MAXNAMELEN` - 1).
pub const MAX_CHAIN_NAME: usize = 28;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("too many rules")]
    TooManyRules,
    #[error("too many chains")]
    TooManyChains,
}

/// One token of a rule, as iptables-save printed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tok {
    pub text: String,
    /// Printed in double quotes (always an argument, never an option).
    pub quoted: bool,
}

/// An option with its arguments, e.g. `! --ctstate NEW`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Opt {
    pub name: String,
    pub neg: bool,
    pub args: Vec<String>,
}

/// A match module (`-m name`) and its options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    pub opts: Vec<Opt>,
}

impl Module {
    pub fn opt(&self, name: &str) -> Option<&Opt> {
        self.opts.iter().find(|o| o.name == name)
    }
}

/// A rule's target (`-j` or `-g`) and its options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub goto: bool,
    pub opts: Vec<Opt>,
}

impl Target {
    pub fn opt(&self, name: &str) -> Option<&Opt> {
        self.opts.iter().find(|o| o.name == name)
    }
}

/// A possibly negated value (`! -i br0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neg {
    pub neg: bool,
    pub val: String,
}

/// The parsed parts of a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Spec {
    pub in_if: Option<Neg>,
    pub out_if: Option<Neg>,
    pub proto: Option<Neg>,
    pub src: Option<Neg>,
    pub dst: Option<Neg>,
    pub fragment: Option<bool>,
    pub modules: Vec<Module>,
    pub target: Option<Target>,
    /// Tokens the parser didn't understand (a rule with any is never trusted as a catch-all,
    /// and only "maybe" matches in the redirect check).
    pub unknown: usize,
}

impl Spec {
    pub fn target_name(&self) -> Option<&str> {
        self.target.as_ref().map(|t| t.name.as_str())
    }
    pub fn module(&self, name: &str) -> Option<&Module> {
        self.modules.iter().find(|m| m.name == name)
    }
    /// The `-m comment --comment` text, if any.
    pub fn comment(&self) -> Option<&str> {
        self.modules.iter().filter(|m| m.name == "comment").find_map(|m| {
            m.opt("--comment")
                .and_then(|o| o.args.first())
                .map(String::as_str)
        })
    }
    /// No match at all except comments: the rule applies to every packet.
    pub fn matches_everything(&self) -> bool {
        self.in_if.is_none()
            && self.out_if.is_none()
            && self.proto.is_none()
            && self.src.is_none()
            && self.dst.is_none()
            && self.fragment.is_none()
            && self.unknown == 0
            && self.modules.iter().all(|m| m.name == "comment")
    }
}

// `Opaque` is the rare over-long line; boxing the common variant would cost an allocation per rule.
#[expect(
    clippy::large_enum_variant,
    reason = "`Opaque` is the rare over-long line; boxing the common variant would allocate per rule"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleKind {
    Parsed {
        toks: Vec<Tok>,
        spec: Spec,
    },
    /// Over-long line: holds its position, never interpreted.
    Opaque,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// `[packets, bytes]` from `iptables-save -c` or `-S -v`.
    pub counters: Option<(u64, u64)>,
    pub kind: RuleKind,
}

impl Rule {
    pub fn spec(&self) -> Option<&Spec> {
        match &self.kind {
            RuleKind::Parsed { spec, .. } => Some(spec),
            RuleKind::Opaque => None,
        }
    }
    pub fn toks(&self) -> Option<&[Tok]> {
        match &self.kind {
            RuleKind::Parsed { toks, .. } => Some(toks),
            RuleKind::Opaque => None,
        }
    }
    pub fn target_name(&self) -> Option<&str> {
        self.spec().and_then(Spec::target_name)
    }
    /// The rule as an argument string for `-D <chain> …` / `-I <chain> N …`, quoted the way
    /// iptables-restore reads it back.
    pub fn args_text(&self) -> Option<String> {
        self.toks().map(join_toks)
    }
    /// A normalised form for comparisons: tokens joined, with comma lists of conntrack states
    /// sorted (iptables prints `RELATED,ESTABLISHED` whatever order it was given).
    pub fn norm(&self) -> Option<String> {
        self.toks().map(norm_toks)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub name: String,
    /// Built-in chain policy (`ACCEPT`, `DROP`); `None` for user chains.
    pub policy: Option<String>,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    pub chains: Vec<Chain>,
    index: HashMap<String, usize>,
}

impl Table {
    pub fn chain(&self, name: &str) -> Option<&Chain> {
        self.index.get(name).map(|&i| &self.chains[i])
    }
    pub fn has_chain(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }
    fn chain_mut(&mut self, name: &str) -> Result<&mut Chain, ParseError> {
        if let Some(&i) = self.index.get(name) {
            return Ok(&mut self.chains[i]);
        }
        if self.chains.len() >= MAX_CHAINS {
            return Err(ParseError::TooManyChains);
        }
        self.index.insert(name.to_string(), self.chains.len());
        Ok(self.chains.push_mut(Chain {
            name: name.to_string(),
            policy: None,
            rules: Vec::new(),
        }))
    }

    /// Parses `iptables-save [-c] -t <table>` or `iptables -S [-v]` output for one table. Lines
    /// of other tables in a full `iptables-save` are kept too (callers pass one table).
    pub fn parse(text: &str) -> Result<Table, ParseError> {
        let mut t = Table::default();
        let mut rules = 0usize;
        for raw in text.split('\n') {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if line.len() > MAX_LINE {
                // Keep an `-A` line's position; anything else that long is ignored.
                if let Some(chain) = append_chain_prefix(line) {
                    rules += 1;
                    if rules > MAX_RULES {
                        return Err(ParseError::TooManyRules);
                    }
                    let c = t.chain_mut(&chain)?;
                    c.rules.push(Rule {
                        counters: None,
                        kind: RuleKind::Opaque,
                    });
                }
                continue;
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('*') || line == "COMMIT" {
                continue;
            }
            if let Some(rest) = line.strip_prefix(':') {
                // `:NAME POLICY [p:b]`
                let mut it = rest.split_whitespace();
                if let Some(name) = it.next().filter(|n| valid_chain_name(n)) {
                    let policy = it.next().filter(|p| *p != "-").map(str::to_string);
                    let c = t.chain_mut(name)?;
                    c.policy = policy;
                }
                continue;
            }
            let (counters, body) = split_counters(line);
            let toks = tokenize(body);
            if toks.len() < 2 || toks[0].quoted {
                continue;
            }
            match toks[0].text.as_str() {
                "-P" => {
                    if let (Some(n), Some(p)) = (toks.get(1), toks.get(2))
                        && valid_chain_name(&n.text)
                    {
                        t.chain_mut(&n.text)?.policy = Some(p.text.clone());
                    }
                }
                "-N" => {
                    if valid_chain_name(&toks[1].text) {
                        t.chain_mut(&toks[1].text)?;
                    }
                }
                "-A" => {
                    let name = toks[1].text.clone();
                    if !valid_chain_name(&name) {
                        continue;
                    }
                    rules += 1;
                    if rules > MAX_RULES {
                        return Err(ParseError::TooManyRules);
                    }
                    let mut rest: Vec<Tok> = toks[2..].to_vec();
                    // `iptables -S -v` prints `-c <packets> <bytes>` after the matches, before
                    // the target (no match option is `-c`).
                    let mut counters = counters;
                    let at = rest.windows(3).position(|w| {
                        !w[0].quoted
                            && w[0].text == "-c"
                            && w[1].text.parse::<u64>().is_ok()
                            && w[2].text.parse::<u64>().is_ok()
                    });
                    if let Some(i) = at {
                        let c: Vec<Tok> = rest.drain(i..i + 3).collect();
                        counters = c[1].text.parse().ok().zip(c[2].text.parse().ok());
                    }
                    let spec = parse_spec(&rest);
                    t.chain_mut(&name)?.rules.push(Rule {
                        counters,
                        kind: RuleKind::Parsed { toks: rest, spec },
                    });
                }
                _ => {}
            }
        }
        Ok(t)
    }
}

fn valid_chain_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_CHAIN_NAME
        && !n.starts_with('-')
        && n.bytes().all(|b| b.is_ascii_graphic())
}

/// The chain name of an over-long `-A CHAIN …` or `[p:b] -A CHAIN …` line, read from its prefix.
fn append_chain_prefix(line: &str) -> Option<String> {
    let head = &line.as_bytes()[..line.len().min(128)];
    let head = String::from_utf8_lossy(head);
    let mut it = head.split_whitespace();
    let mut first = it.next()?;
    if first.starts_with('[') {
        first = it.next()?;
    }
    if first != "-A" {
        return None;
    }
    let name = it.next()?;
    valid_chain_name(name).then(|| name.to_string())
}

/// Splits a leading `[packets:bytes]` off an iptables-save line.
fn split_counters(line: &str) -> (Option<(u64, u64)>, &str) {
    if let Some(rest) = line.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let inner = &rest[..end];
        let body = rest[end + 1..].trim_start();
        if let Some((p, b)) = inner.split_once(':')
            && let (Ok(p), Ok(b)) = (p.parse(), b.parse())
        {
            return (Some((p, b)), body);
        }
        return (None, body);
    }
    (None, line)
}

/// Splits a line into tokens: whitespace-separated, with `"…"` quoting and `\"` / `\\` escapes
/// inside quotes, as iptables-save writes (xtables `save_string`) and iptables-restore reads.
pub fn tokenize(s: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&c) = chars.peek() else { break };
        if c == '"' {
            chars.next();
            let mut text = String::new();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(n) = chars.next() {
                            text.push(n);
                        }
                    }
                    '"' => break,
                    c => text.push(c),
                }
            }
            out.push(Tok { text, quoted: true });
        } else {
            let mut text = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                text.push(c);
                chars.next();
            }
            out.push(Tok { text, quoted: false });
        }
    }
    out
}

/// Joins tokens back into iptables-restore syntax.
pub fn join_toks(toks: &[Tok]) -> String {
    let mut s = String::new();
    for (i, t) in toks.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let needs_quotes = t.quoted
            || t.text.is_empty()
            || t.text.chars().any(|c| c.is_whitespace() || c == '"' || c == '\\');
        if needs_quotes {
            s.push('"');
            for c in t.text.chars() {
                if c == '"' || c == '\\' {
                    s.push('\\');
                }
                s.push(c);
            }
            s.push('"');
        } else {
            s.push_str(&t.text);
        }
    }
    s
}

fn norm_toks(toks: &[Tok]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(toks.len());
    let mut sort_next = false;
    for t in toks {
        if sort_next {
            let mut v: Vec<&str> = t.text.split(',').collect();
            v.sort_unstable();
            parts.push(v.join(","));
            sort_next = false;
            continue;
        }
        sort_next = !t.quoted && (t.text == "--ctstate" || t.text == "--state");
        parts.push(if t.quoted {
            format!("\"{}\"", t.text)
        } else {
            t.text.clone()
        });
    }
    parts.join(" ")
}

/// Normalised form of a rule given as text (tokens after `-A CHAIN`).
pub fn norm_text(args: &str) -> String {
    norm_toks(&tokenize(args))
}

fn is_option(t: &Tok) -> bool {
    !t.quoted && t.text.len() > 1 && t.text.starts_with('-')
}

fn is_bang(t: &Tok) -> bool {
    !t.quoted && t.text == "!"
}

enum Ctx {
    Base,
    Module(usize),
    Target,
}

/// Parses rule tokens (after `-A CHAIN`) into a [`Spec`].
pub fn parse_spec(toks: &[Tok]) -> Spec {
    let mut s = Spec::default();
    let mut ctx = Ctx::Base;
    let mut neg = false;
    let mut i = 0;
    // The argument after an option, if any.
    let arg = |i: usize| {
        toks.get(i + 1)
            .filter(|t| t.quoted || !(is_option(t) || is_bang(t)))
            .map(|t| t.text.clone())
    };
    while i < toks.len() {
        let t = &toks[i];
        if is_bang(t) {
            neg = true;
            i += 1;
            continue;
        }
        if !is_option(t) {
            s.unknown += 1;
            i += 1;
            neg = false;
            continue;
        }
        let name = t.text.as_str();
        let take_one = |field: &mut Option<Neg>, s_unknown: &mut usize| match arg(i) {
            Some(v) => {
                *field = Some(Neg { neg, val: v });
                2
            }
            None => {
                *s_unknown += 1;
                1
            }
        };
        let step = match name {
            "-i" | "--in-interface" => {
                ctx = Ctx::Base;
                take_one(&mut s.in_if, &mut s.unknown)
            }
            "-o" | "--out-interface" => {
                ctx = Ctx::Base;
                take_one(&mut s.out_if, &mut s.unknown)
            }
            "-p" | "--protocol" => {
                ctx = Ctx::Base;
                take_one(&mut s.proto, &mut s.unknown)
            }
            "-s" | "--source" | "--src" => {
                ctx = Ctx::Base;
                take_one(&mut s.src, &mut s.unknown)
            }
            "-d" | "--destination" | "--dst" => {
                ctx = Ctx::Base;
                take_one(&mut s.dst, &mut s.unknown)
            }
            "-f" | "--fragment" => {
                ctx = Ctx::Base;
                s.fragment = Some(!neg);
                1
            }
            "-4" | "-6" | "--ipv4" | "--ipv6" => 1,
            "-m" | "--match" => match arg(i) {
                Some(m) => {
                    s.modules.push(Module {
                        name: m,
                        opts: Vec::new(),
                    });
                    ctx = Ctx::Module(s.modules.len() - 1);
                    2
                }
                None => {
                    s.unknown += 1;
                    1
                }
            },
            "-j" | "--jump" | "-g" | "--goto" => match arg(i) {
                Some(n) => {
                    s.target = Some(Target {
                        name: n,
                        goto: name == "-g" || name == "--goto",
                        opts: Vec::new(),
                    });
                    ctx = Ctx::Target;
                    2
                }
                None => {
                    s.unknown += 1;
                    1
                }
            },
            _ if name.starts_with("--") => {
                let mut args = Vec::new();
                let mut j = i + 1;
                while let Some(a) = toks.get(j) {
                    if !a.quoted && (is_option(a) || is_bang(a)) {
                        break;
                    }
                    args.push(a.text.clone());
                    j += 1;
                }
                let opt = Opt {
                    name: name.to_string(),
                    neg,
                    args,
                };
                match ctx {
                    Ctx::Module(m) => s.modules[m].opts.push(opt),
                    Ctx::Target => {
                        if let Some(t) = s.target.as_mut() {
                            t.opts.push(opt)
                        }
                    }
                    // An option outside any module (e.g. `--dport` without `-m tcp`): unknown.
                    Ctx::Base => s.unknown += 1,
                }
                j - i
            }
            _ => {
                s.unknown += 1;
                1
            }
        };
        neg = false;
        i += step;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAVE: &str = r#"# Generated by iptables-save v1.8.7 on Thu Nov 20 10:00:00 2026
*filter
:INPUT ACCEPT [10:1000]
:FORWARD DROP [0:0]
:UBIOS_LAN_WAN_USER - [0:0]
[5:300] -A UBIOS_LAN_WAN_USER -m comment --comment "FIREWALL_POLICY \"quoted\" name" -j NFLOG --nflog-prefix "[FW-R-30000]" --nflog-group 1
[7:420] -A UBIOS_LAN_WAN_USER -m set ! --match-set UBIOS_local_zoned_subnets dst -m conntrack ! --ctstate NEW -j RETURN
-A UBIOS_LAN_WAN_USER -i br0 -j PICKET-FWD
COMMIT
"#;

    #[test]
    fn parses_save_with_counters_quotes_and_negation() {
        let t = Table::parse(SAVE).unwrap();
        assert_eq!(t.chain("FORWARD").unwrap().policy.as_deref(), Some("DROP"));
        let c = t.chain("UBIOS_LAN_WAN_USER").unwrap();
        assert_eq!(c.policy, None);
        assert_eq!(c.rules.len(), 3);
        assert_eq!(c.rules[0].counters, Some((5, 300)));
        let s0 = c.rules[0].spec().unwrap();
        assert_eq!(s0.comment(), Some("FIREWALL_POLICY \"quoted\" name"));
        assert_eq!(s0.target_name(), Some("NFLOG"));
        assert_eq!(
            s0.target.as_ref().unwrap().opt("--nflog-prefix").unwrap().args,
            vec!["[FW-R-30000]"]
        );
        let s1 = c.rules[1].spec().unwrap();
        let set = s1.module("set").unwrap().opt("--match-set").unwrap();
        assert!(set.neg);
        assert_eq!(set.args, vec!["UBIOS_local_zoned_subnets", "dst"]);
        assert!(s1.module("conntrack").unwrap().opt("--ctstate").unwrap().neg);
        let s2 = c.rules[2].spec().unwrap();
        assert_eq!(
            s2.in_if,
            Some(Neg {
                neg: false,
                val: "br0".into()
            })
        );
        assert_eq!(s2.target_name(), Some("PICKET-FWD"));
        // Round trip of a quoted comment.
        let txt = c.rules[0].args_text().unwrap();
        assert_eq!(tokenize(&txt), c.rules[0].toks().unwrap());
    }

    #[test]
    fn parses_dash_s_format_with_v_counters() {
        let s = "-P FORWARD ACCEPT\n-N PICKET-FWD\n-A PICKET-FWD -j RETURN -c 12 345\n";
        let t = Table::parse(s).unwrap();
        let c = t.chain("PICKET-FWD").unwrap();
        assert_eq!(c.rules[0].counters, Some((12, 345)));
        assert_eq!(c.rules[0].norm().unwrap(), "-j RETURN");
        assert_eq!(t.chain("FORWARD").unwrap().policy.as_deref(), Some("ACCEPT"));
    }

    #[test]
    fn dash_s_v_counters_before_the_target() {
        // `iptables -S -v` prints the counters after the matches, before `-j`.
        let t = Table::parse(
            "-N C\n-A C -i br0 -p udp -m udp --dport 53 -c 3 120 -j PICKET-DNS6\n-A C -m comment --comment \"FIREWALL_POLICY 1\" -c 0 0 -j REJECT --reject-with icmp-port-unreachable\n",
        )
        .unwrap();
        let c = t.chain("C").unwrap();
        assert_eq!(c.rules[0].counters, Some((3, 120)));
        let s = c.rules[0].spec().unwrap();
        assert_eq!(s.unknown, 0);
        assert_eq!(s.target_name(), Some("PICKET-DNS6"));
        assert_eq!(
            c.rules[0].norm().unwrap(),
            "-i br0 -p udp -m udp --dport 53 -j PICKET-DNS6"
        );
        assert!(c.rules[1].spec().unwrap().matches_everything());
        assert_eq!(c.rules[1].counters, Some((0, 0)));
    }

    #[test]
    fn over_long_line_keeps_its_position() {
        let long = format!(
            "-A X -m comment --comment \"{}\" -j ACCEPT",
            "a".repeat(MAX_LINE + 10)
        );
        let text = format!("-N X\n-A X -j LOG\n{long}\n[1:2] {long}\n-A X -j REJECT\n");
        let t = Table::parse(&text).unwrap();
        let c = t.chain("X").unwrap();
        assert_eq!(c.rules.len(), 4);
        assert_eq!(c.rules[1].kind, RuleKind::Opaque);
        assert_eq!(c.rules[2].kind, RuleKind::Opaque);
        assert_eq!(c.rules[3].target_name(), Some("REJECT"));
    }

    #[test]
    fn norm_sorts_ctstate_lists() {
        assert_eq!(
            norm_text("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
            norm_text("-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        );
    }

    #[test]
    fn bounded_rule_count() {
        let mut s = String::new();
        for _ in 0..=MAX_RULES {
            s.push_str("-A X -j ACCEPT\n");
        }
        assert_eq!(Table::parse(&s), Err(ParseError::TooManyRules));
    }

    #[test]
    fn junk_never_panics() {
        for s in [
            "-A",
            "-A \"",
            "[1:2",
            "[:] -A X",
            "-A X ! ! !",
            "-A X -m",
            "-A X -j",
            ":\n:X",
            "-P X",
        ] {
            let _ = Table::parse(s);
        }
    }
}
