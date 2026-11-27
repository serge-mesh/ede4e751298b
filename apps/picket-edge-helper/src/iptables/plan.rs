//! Compares one family's filter table with what Picket wants and writes the
//! `iptables-restore --noflush` text that repairs it (edge-firewall.md §2, §4).
//!
//! Picket only ever writes its own chains (`PICKET-FWD`, `PICKET-MON`, `PICKET-DNS6`) and its
//! own jump rules into UniFi's chains; it never declares a UniFi chain (in `--noflush` mode a
//! declaration would flush it). Jumps are inserted by position computed from the table just
//! read and deleted by rule spec, all in one atomic restore; the caller reads the table again
//! afterwards to verify, since UniFi may have changed it in between.

use std::collections::HashMap;

use picket_api::edge_config::FwMode;
use picket_api::helper::sets;

use super::layout::{self, CatchAll, DNS6, FWD, Found, MON, OUR_CHAINS, Platform, is_ours};
use super::model::{Chain, Table, norm_text};

/// Address family of an iptables table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const BOTH: [Family; 2] = [Family::V4, Family::V6];
    pub fn label(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }
    pub fn digit(self) -> char {
        match self {
            Family::V4 => '4',
            Family::V6 => '6',
        }
    }
    /// `(exempt, static, per_client_ip, global)` set names.
    pub fn sets(self) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            Family::V4 => (sets::EXEMPT4, sets::STATIC4, sets::PICKET4, sets::PICKET_G4),
            Family::V6 => (sets::EXEMPT6, sets::STATIC6, sets::PICKET6, sets::PICKET_G6),
        }
    }
}

/// The rules of one of Picket's chains, as iptables-save prints them (edge-firewall.md §2).
pub fn chain_rules(family: Family, chain: &str) -> Vec<String> {
    let (ex, st, pn, g) = family.sets();
    let six = |verdict: &str| {
        vec![
            format!("-m conntrack --ctstate RELATED,ESTABLISHED -j {verdict}"),
            // INVALID or untracked: left to the Block All, as without Picket.
            "-m conntrack ! --ctstate NEW -j RETURN".to_string(),
            format!("-m set --match-set {ex} src -j {verdict}"),
            format!("-m set --match-set {st} dst -j {verdict}"),
            format!("-m set --match-set {pn} src,dst -j {verdict}"),
            format!("-m set --match-set {g} dst -j {verdict}"),
        ]
    };
    match chain {
        FWD => {
            let mut v = six("ACCEPT");
            // Counted (`rejects`); the Block All below refuses it.
            v.push("-j RETURN".into());
            v
        }
        MON => {
            let mut v = six("RETURN");
            // Its counter is the would-be-reject count (`mon_rejects`).
            v.push("-j RETURN".into());
            v
        }
        DNS6 => vec![
            format!("-m set --match-set {} src -j RETURN", sets::EXEMPT6),
            "-p tcp -j REJECT --reject-with tcp-reset".into(),
            "-j REJECT --reject-with icmp6-adm-prohibited".into(),
        ],
        _ => Vec::new(),
    }
}

/// The jump rule for one protected interface.
pub fn jump_rule(iface: &str, mode: FwMode) -> Option<String> {
    match mode {
        FwMode::Enforce => Some(format!("-i {iface} -j {FWD}")),
        FwMode::Monitor => Some(format!("-i {iface} -j {MON}")),
        FwMode::Off => None,
    }
}

/// The `PICKET-DNS6` jumps for one redirect interface: port 53 to the gateway (INPUT hook), port
/// 53 and 853/tcp to anything else (FORWARD hook).
pub fn dns6_rules(iface: &str, forward: bool) -> Vec<String> {
    let mut v = vec![
        format!("-i {iface} -p udp -m udp --dport 53 -j {DNS6}"),
        format!("-i {iface} -p tcp -m tcp --dport 53 -j {DNS6}"),
    ];
    if forward {
        v.push(format!("-i {iface} -p tcp -m tcp --dport 853 -j {DNS6}"));
    }
    v
}

/// What the plan is asked for.
#[derive(Clone, Copy, Debug)]
pub struct Want<'a> {
    pub family: Family,
    pub platform: Platform,
    pub interfaces: &'a [(String, FwMode)],
    /// Redirect interfaces that get the IPv6 DNS reject (IPv6 with `redirect.ipv6: false`).
    pub dns6: &'a [String],
    /// `disable` in force: remove every jump, change nothing else.
    pub disabled: bool,
}

/// A kernel object the plan tracks, for `rules_ok` and `rules_repaired`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Obj {
    Chain(&'static str),
    Jump(String),
    Dns6(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjState {
    Ok,
    Missing,
    /// Present, but not where it belongs (e.g. a UniFi rule landed between a jump and its
    /// catch-all).
    Misplaced,
    /// The interface has no place for a jump (`fw_layout_unknown` or `partial`).
    NoPlace,
}

/// One protected interface's finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfFinding {
    pub iface: String,
    pub mode: FwMode,
    pub catch_all: CatchAll,
}

impl IfFinding {
    /// The `fw_layout_unknown` finding: the interface's jump has no place. A state-limited last
    /// policy is reported as `fw_catch_all: partial` for an `enforce` interface; a `monitor`
    /// one, which has no `fw_catch_all`, is reported here.
    pub fn layout_unknown(&self) -> bool {
        match self.catch_all {
            CatchAll::Unknown(_) => true,
            CatchAll::Partial { .. } => self.mode != FwMode::Enforce,
            CatchAll::At { .. } => false,
        }
    }
    /// The `fw_catch_all` finding: only for `enforce` interfaces.
    pub fn found(&self) -> Option<Found> {
        if self.mode != FwMode::Enforce {
            return None;
        }
        match &self.catch_all {
            CatchAll::At { found, .. } => *found,
            CatchAll::Partial { .. } => Some(Found::Partial),
            CatchAll::Unknown(_) => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// Restore text, or `None` if the table is already as wanted.
    pub restore: Option<String>,
    pub findings: Vec<IfFinding>,
    pub shadowed: bool,
    pub states: Vec<(Obj, ObjState)>,
    /// Things that can't be fixed from here (e.g. a missing UniFi hook chain).
    pub problems: Vec<String>,
}

impl Plan {
    pub fn all_ok(&self) -> bool {
        self.states.iter().all(|(_, s)| *s == ObjState::Ok) && self.problems.is_empty()
    }
}

#[derive(Default)]
struct ChainWant {
    top: Vec<String>,
    block: Option<(usize, Vec<String>)>,
}

fn chain_content_ok(c: &Chain, expected: &[String]) -> bool {
    c.rules.len() == expected.len()
        && c.rules
            .iter()
            .zip(expected)
            .all(|(r, e)| r.norm().is_some_and(|n| n == norm_text(e)))
}

/// One of Picket's rules in a chain, for [`chain_shape_ok`]: whether it is a `PICKET-DNS6` jump
/// (the top block) or a firewall jump (the block above the catch-all), and its normalised text.
type Ours = Option<(bool, String)>;

/// Sort each run of Picket rules of the same kind, so blocks compare as sets. Jumps of different
/// kinds are never interchangeable: a `PICKET-FWD` jump above the `PICKET-DNS6` ones would accept
/// DNS to a granted or static destination before the IPv6 DNS reject (edge-firewall.md §2).
fn sort_runs(v: &mut [Ours]) {
    let mut i = 0;
    while i < v.len() {
        let Some((kind, _)) = &v[i] else {
            i += 1;
            continue;
        };
        let kind = *kind;
        let mut j = i;
        while j < v.len() && v[j].as_ref().is_some_and(|(k, _)| *k == kind) {
            j += 1;
        }
        v[i..j].sort();
        i = j;
    }
}

fn is_dns6_jump(r: &super::model::Rule) -> bool {
    r.target_name() == Some(DNS6)
}

/// Does `c` hold exactly `want` (top block first, then the base rules with the block at its
/// index)? Base rules are compared by position only; they are never moved.
fn chain_shape_ok(c: &Chain, want: Option<&ChainWant>) -> bool {
    let mut obs: Vec<Ours> = c
        .rules
        .iter()
        .map(|r| {
            if is_ours(r) {
                r.norm().map(|n| (is_dns6_jump(r), n))
            } else {
                None
            }
        })
        .collect();
    let base_len = c.rules.iter().filter(|r| !is_ours(r)).count();
    let mut des: Vec<Ours> = Vec::with_capacity(obs.len());
    if let Some(w) = want {
        des.extend(w.top.iter().map(|s| Some((true, norm_text(s)))));
    }
    let block = want.and_then(|w| w.block.as_ref());
    for i in 0..=base_len {
        if let Some((idx, rules)) = block
            && *idx == i
        {
            des.extend(rules.iter().map(|s| Some((false, norm_text(s)))));
        }
        if i < base_len {
            des.push(None);
        }
    }
    sort_runs(&mut obs);
    sort_runs(&mut des);
    obs == des
}

/// Builds the plan for one family's filter table.
pub fn plan(t: &Table, w: &Want<'_>) -> Plan {
    let mut p = Plan::default();
    let mut body = String::new();
    let mut tail = String::new();

    // 1. Picket's chains (left alone while disabled: "sets and chains stay").
    if !w.disabled {
        let dns6_needed = w.family == Family::V6 && !w.dns6.is_empty();
        for name in OUR_CHAINS {
            let needed = name != DNS6 || dns6_needed;
            let expected = chain_rules(w.family, name);
            match t.chain(name) {
                Some(c) if needed => {
                    if chain_content_ok(c, &expected) {
                        p.states.push((Obj::Chain(name), ObjState::Ok));
                        continue;
                    }
                    p.states.push((Obj::Chain(name), ObjState::Misplaced));
                }
                None if needed => p.states.push((Obj::Chain(name), ObjState::Missing)),
                Some(_) => {
                    // An unneeded PICKET-DNS6: removed after its jumps (below).
                    tail.push_str(&format!("-F {name}\n-X {name}\n"));
                    continue;
                }
                None => continue,
            }
            // Declaring a user chain in --noflush mode creates it or flushes it; the explicit
            // -F makes the flush independent of the iptables variant.
            body.push_str(&format!(":{name} - [0:0]\n-F {name}\n"));
            for r in &expected {
                body.push_str(&format!("-A {name} {r}\n"));
            }
        }
    }

    // 2. Where each jump goes. The findings are reported while disabled too (they describe the
    //    layout); only the jumps themselves wait for `enable`.
    let mut wants: HashMap<String, ChainWant> = HashMap::new();
    let mut jump_place: Vec<(String, String, String)> = Vec::new(); // (iface, chain, rule)
    for (iface, mode) in w.interfaces {
        let Some(rule) = jump_rule(iface, *mode) else {
            continue;
        };
        let (ca, shadowed) = layout::place(t, w.platform, iface);
        p.shadowed |= shadowed;
        if !w.disabled {
            match &ca {
                CatchAll::At { chain, index, .. } => {
                    let cw = wants.entry(chain.clone()).or_default();
                    let block = cw.block.get_or_insert_with(|| (*index, Vec::new()));
                    if block.0 == *index {
                        block.1.push(rule.clone());
                        jump_place.push((iface.clone(), chain.clone(), rule));
                    } else {
                        // Cannot happen (one chain has one catch-all); fail closed if it does.
                        p.states.push((Obj::Jump(iface.clone()), ObjState::NoPlace));
                    }
                }
                CatchAll::Partial { .. } | CatchAll::Unknown(_) => {
                    p.states.push((Obj::Jump(iface.clone()), ObjState::NoPlace));
                }
            }
        }
        p.findings.push(IfFinding {
            iface: iface.clone(),
            mode: *mode,
            catch_all: ca,
        });
    }
    if !w.disabled && w.family == Family::V6 {
        let (input, forward) = layout::dns6_hooks(w.platform);
        for iface in w.dns6 {
            for (hook, fwd) in [(input, false), (forward, true)] {
                if t.has_chain(hook) {
                    wants
                        .entry(hook.to_string())
                        .or_default()
                        .top
                        .extend(dns6_rules(iface, fwd));
                } else {
                    p.problems.push(format!("dns6_hook_missing:{hook}"));
                }
            }
        }
    }

    // 3. Compare each chain and write deletions and insertions.
    for c in &t.chains {
        if OUR_CHAINS.contains(&c.name.as_str()) {
            continue;
        }
        let want = wants.get(&c.name);
        if want.is_none() && !c.rules.iter().any(is_ours) {
            continue;
        }
        let ok = chain_shape_ok(c, want);
        if ok {
            continue;
        }
        for r in c.rules.iter().filter(|r| is_ours(r)) {
            if let Some(a) = r.args_text() {
                body.push_str(&format!("-D {} {a}\n", c.name));
            }
        }
        if let Some(w) = want {
            for r in w.top.iter().rev() {
                body.push_str(&format!("-I {} 1 {r}\n", c.name));
            }
            if let Some((idx, rules)) = &w.block {
                let pos = w.top.len() + idx + 1;
                for r in rules.iter().rev() {
                    body.push_str(&format!("-I {} {pos} {r}\n", c.name));
                }
            }
        }
    }

    // 4. Object states, each jump judged by its own position: in place when exactly as many base
    //    rules sit above it as the catch-all's index (so a neighbour going missing doesn't make
    //    it "moved", and a UniFi rule landing between it and the catch-all does).
    let present = |chain: &str, rule: &str| {
        let n = norm_text(rule);
        t.chain(chain)
            .is_some_and(|c| c.rules.iter().any(|r| r.norm().is_some_and(|x| x == n)))
    };
    let in_place = |chain: &str, rule: &str, base_before: usize| {
        let n = norm_text(rule);
        let Some(c) = t.chain(chain) else { return false };
        let mut base = 0;
        for r in &c.rules {
            if is_ours(r) {
                if base == base_before && r.norm().is_some_and(|x| x == n) {
                    return true;
                }
            } else {
                base += 1;
            }
        }
        false
    };
    // A `PICKET-DNS6` jump is in place only within the run of them that opens its hook chain.
    let first_in = |chain: &str, rule: &str| {
        let n = norm_text(rule);
        let Some(c) = t.chain(chain) else { return false };
        c.rules
            .iter()
            .take_while(|r| is_dns6_jump(r))
            .any(|r| r.norm().is_some_and(|x| x == n))
    };
    for (iface, chain, rule) in &jump_place {
        let idx = wants
            .get(chain)
            .and_then(|w| w.block.as_ref())
            .map_or(usize::MAX, |b| b.0);
        let state = if in_place(chain, rule, idx) {
            ObjState::Ok
        } else if present(chain, rule) {
            ObjState::Misplaced
        } else {
            ObjState::Missing
        };
        p.states.push((Obj::Jump(iface.clone()), state));
    }
    if !w.disabled && w.family == Family::V6 {
        let (input, forward) = layout::dns6_hooks(w.platform);
        for iface in w.dns6 {
            let hooks = [(input, false), (forward, true)];
            let all_ok = hooks
                .iter()
                .all(|(h, f)| dns6_rules(iface, *f).iter().all(|r| first_in(h, r)));
            let any_present = hooks
                .iter()
                .any(|(h, f)| dns6_rules(iface, *f).iter().any(|r| present(h, r)));
            let state = if all_ok {
                ObjState::Ok
            } else if any_present {
                ObjState::Misplaced
            } else {
                ObjState::Missing
            };
            p.states.push((Obj::Dns6(iface.clone()), state));
        }
    }

    body.push_str(&tail);
    if !body.is_empty() {
        p.restore = Some(format!("*filter\n{body}COMMIT\n"));
    }
    p
}

/// The packet counter of the final `RETURN` of one of Picket's chains, if the chain is intact
/// (edge-firewall.md §4 `status`).
pub fn final_return_packets(t: &Table, family: Family, chain: &str) -> Option<u64> {
    let c = t.chain(chain)?;
    if !chain_content_ok(c, &chain_rules(family, chain)) {
        return None;
    }
    c.rules.last()?.counters.map(|(p, _)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn picket_chains(f: Family) -> String {
        let mut s = String::new();
        for c in [FWD, MON] {
            s.push_str(&format!("-N {c}\n"));
            for r in chain_rules(f, c) {
                s.push_str(&format!("-A {c} {r}\n"));
            }
        }
        s
    }

    #[test]
    fn debian_places_above_final_reject_and_is_idempotent() {
        let base = "-P FORWARD ACCEPT\n-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A FORWARD -j REJECT --reject-with icmp-port-unreachable\n";
        let t = Table::parse(&format!("{base}{}", picket_chains(Family::V4))).unwrap();
        let ifs = vec![("eth1".to_string(), FwMode::Enforce)];
        let w = Want {
            family: Family::V4,
            platform: Platform::Debian,
            interfaces: &ifs,
            dns6: &[],
            disabled: false,
        };
        let p = plan(&t, &w);
        assert_eq!(
            p.restore.as_deref(),
            Some("*filter\n-I FORWARD 2 -i eth1 -j PICKET-FWD\nCOMMIT\n")
        );
        assert_eq!(p.findings[0].found(), None);
        // Already in place: nothing to do.
        let placed = "-P FORWARD ACCEPT\n-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A FORWARD -i eth1 -j PICKET-FWD\n-A FORWARD -j REJECT --reject-with icmp-port-unreachable\n";
        let t = Table::parse(&format!("{placed}{}", picket_chains(Family::V4))).unwrap();
        let p = plan(&t, &w);
        assert_eq!(p.restore, None);
        assert!(p.all_ok());
    }

    #[test]
    fn disabled_only_deletes_jumps() {
        let placed = "-P FORWARD ACCEPT\n-A FORWARD -i eth1 -j PICKET-MON\n-A FORWARD -j REJECT\n";
        let t = Table::parse(&format!("{placed}{}", picket_chains(Family::V4))).unwrap();
        let ifs = vec![("eth1".to_string(), FwMode::Monitor)];
        let w = Want {
            family: Family::V4,
            platform: Platform::Debian,
            interfaces: &ifs,
            dns6: &[],
            disabled: true,
        };
        let p = plan(&t, &w);
        assert_eq!(
            p.restore.as_deref(),
            Some("*filter\n-D FORWARD -i eth1 -j PICKET-MON\nCOMMIT\n")
        );
    }

    #[test]
    fn missing_chain_is_declared_flushed_and_filled() {
        let t = Table::parse("-P FORWARD ACCEPT\n-A FORWARD -j REJECT\n").unwrap();
        let w = Want {
            family: Family::V6,
            platform: Platform::Debian,
            interfaces: &[],
            dns6: &[],
            disabled: false,
        };
        let p = plan(&t, &w);
        let r = p.restore.unwrap();
        assert!(r.contains(":PICKET-FWD - [0:0]\n-F PICKET-FWD\n-A PICKET-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"));
        assert!(r.contains("-A PICKET-FWD -m set --match-set picket6 src,dst -j ACCEPT\n"));
        assert!(r.contains("-A PICKET-MON -m set --match-set picket-g6 dst -j RETURN\n"));
        assert!(!r.contains("PICKET-DNS6"));
    }

    #[test]
    fn firewall_jump_above_the_dns6_jumps_is_misplaced() {
        // edge-firewall.md §2: the IPv6 DNS reject goes first in FORWARD; a PICKET-FWD jump above
        // it would accept DNS to a granted or static destination before the reject.
        let mut chains = picket_chains(Family::V6);
        chains.push_str(&format!("-N {DNS6}\n"));
        for r in chain_rules(Family::V6, DNS6) {
            chains.push_str(&format!("-A {DNS6} {r}\n"));
        }
        let ifs = vec![("eth1".to_string(), FwMode::Enforce)];
        let dns6 = vec!["eth1".to_string()];
        let w = Want {
            family: Family::V6,
            platform: Platform::Debian,
            interfaces: &ifs,
            dns6: &dns6,
            disabled: false,
        };
        let jump = "-i eth1 -j PICKET-FWD".to_string();
        let input: String = dns6_rules("eth1", false)
            .iter()
            .map(|r| format!("-A INPUT {r}\n"))
            .collect();
        let table = |fwd: &[String]| {
            let mut s = format!("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n{input}");
            for r in fwd {
                s.push_str(&format!("-A FORWARD {r}\n"));
            }
            s.push_str("-A FORWARD -j REJECT\n");
            Table::parse(&format!("{s}{chains}")).unwrap()
        };
        let mut good = dns6_rules("eth1", true);
        good.push(jump.clone());
        let p = plan(&table(&good), &w);
        assert!(p.all_ok() && p.restore.is_none(), "{p:?}");
        // The same rules with the firewall jump first, or between the DNS6 jumps.
        let mut first = vec![jump.clone()];
        first.extend(dns6_rules("eth1", true));
        let mut between = dns6_rules("eth1", true);
        between.insert(1, jump.clone());
        for bad in [first, between] {
            let p = plan(&table(&bad), &w);
            assert!(!p.all_ok(), "{bad:?}");
            assert!(
                p.states
                    .contains(&(Obj::Dns6("eth1".into()), ObjState::Misplaced)),
                "{:?}",
                p.states
            );
            let r = p.restore.expect("repaired");
            assert!(
                r.contains(&format!("-I FORWARD 1 {}", dns6_rules("eth1", true)[0])),
                "{r}"
            );
            assert!(r.contains(&format!("-I FORWARD 4 {jump}")), "{r}");
        }
    }

    #[test]
    fn counters_of_final_return() {
        let mut s = String::from("*filter\n:PICKET-FWD - [0:0]\n:PICKET-MON - [0:0]\n");
        for c in [FWD, MON] {
            let rules = chain_rules(Family::V4, c);
            for (i, r) in rules.iter().enumerate() {
                let n = if i + 1 == rules.len() {
                    if c == FWD { 42 } else { 7 }
                } else {
                    0
                };
                s.push_str(&format!("[{n}:{}] -A {c} {r}\n", n * 60));
            }
        }
        s.push_str("COMMIT\n");
        let t = Table::parse(&s).unwrap();
        assert_eq!(final_return_packets(&t, Family::V4, FWD), Some(42));
        assert_eq!(final_return_packets(&t, Family::V4, MON), Some(7));
        assert_eq!(final_return_packets(&t, Family::V6, FWD), None); // wrong family's sets
    }
}
