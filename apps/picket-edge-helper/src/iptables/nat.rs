//! The port-53 redirect check (edge-firewall.md §4 "Redirect check", edge-unifi.md §3).
//!
//! Per family, interface and protocol (UDP and TCP), the helper walks the nat table from
//! `PREROUTING` the way the kernel would for a packet arriving on the interface from any of its
//! clients to any destination on port 53. The redirect counts as present only if **every** such
//! packet is proven to end in a DNAT to one of the gateway's own addresses at the `dns`
//! listener's port. The walk is conservative:
//!
//! - each match is `Always`, `Never` or `Maybe` for the whole class of packets; an option the
//!   walk doesn't understand is `Maybe`;
//! - `-s` is honoured: a source match is `Always` only if it covers every on-link subnet of the
//!   interface, link-local ones included (a client querying the gateway's link-local address
//!   sends from its own), so a DNAT limited to some clients proves nothing;
//! - a correct DNAT that only maybe matches lets the rest of the packets continue; a wrong
//!   outcome (a DNAT elsewhere, another port, `ACCEPT`, an unknown target) that even maybe
//!   matches breaks the proof: an earlier rule that shadows the redirect is caught, and a later
//!   wrong rule shadowed by a correct one doesn't count.
//!
//! The nat table is untrusted input (README "Untrusted input", "Bounded"), and the check runs in
//! every 2 s re-assert and in the start-up pass before `READY=1`: a run of conditional `RETURN`s
//! is walked in a loop, not by recursion; each chain is walked once per packet class and its
//! outcome reused wherever it is reached from; jumps nest at most [`MAX_DEPTH`] deep, a cycle is
//! never covered, and the whole check looks at no more than [`MAX_WALK_STEPS`] rules per family.
//! Running out of any of these counts as not covered (`redirect_missing`), never as present.

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

use super::model::{Neg, Rule, Spec, Table};
use super::plan::Family;

/// One address the gateway holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub ifname: String,
    pub addr: IpAddr,
    pub prefix: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    fn name(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        }
    }
    fn number(self) -> &'static str {
        match self {
            Proto::Udp => "17",
            Proto::Tcp => "6",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tri {
    Never,
    Maybe,
    Always,
}

impl Tri {
    fn and(self, o: Tri) -> Tri {
        match (self, o) {
            (Tri::Never, _) | (_, Tri::Never) => Tri::Never,
            (Tri::Always, Tri::Always) => Tri::Always,
            _ => Tri::Maybe,
        }
    }
    fn not_if(self, neg: bool) -> Tri {
        if !neg {
            return self;
        }
        match self {
            Tri::Never => Tri::Always,
            Tri::Always => Tri::Never,
            Tri::Maybe => Tri::Maybe,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// Every packet reaching this point ends in a correct DNAT.
    Covered,
    /// Some packet may end elsewhere.
    NotCovered,
    /// Some packets fall out of the chain (back to the caller) undecided; the rest are covered.
    Falls,
}

/// The class of packets being checked.
struct Class<'a> {
    family: Family,
    iface: &'a str,
    proto: Proto,
    port: u16,
    /// The interface's on-link subnets in this family (clients' sources).
    subnets: Vec<IpNet>,
    /// The gateway's own addresses (DNAT targets that count), loopback excluded.
    own: Vec<IpAddr>,
}

/// Deepest jump nesting followed.
pub const MAX_DEPTH: usize = 16;
/// Most rules one walk (one redirect interface and protocol) looks at. Chain outcomes are
/// memoised, so a walk looks at each rule at most once and this covers any table that parses
/// ([`super::model::MAX_RULES`]): the budget bounds the cost (at most 2 × interfaces × this per
/// family and pass) without ever failing a table it could prove (edge-firewall.md §4 redirect
/// check; README §2 Bounded).
pub const MAX_WALK_STEPS: usize = super::model::MAX_RULES;
const DNS_PORT: u16 = 53;

fn parse_net(s: &str, family: Family) -> Option<IpNet> {
    let n = s
        .parse::<IpNet>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))?;
    match (family, n) {
        (Family::V4, IpNet::V4(_)) | (Family::V6, IpNet::V6(_)) => Some(n),
        _ => None,
    }
}

impl Class<'_> {
    fn iface_match(&self, n: &Neg) -> Tri {
        let hit = match n.val.strip_suffix('+') {
            Some(prefix) => self.iface.starts_with(prefix),
            None => n.val == self.iface,
        };
        (if hit { Tri::Always } else { Tri::Never }).not_if(n.neg)
    }

    fn proto_match(&self, n: &Neg) -> Tri {
        let v = n.val.to_ascii_lowercase();
        let hit = if v == "all" || v == "0" {
            true
        } else {
            v == self.proto.name() || v == self.proto.number()
        };
        (if hit { Tri::Always } else { Tri::Never }).not_if(n.neg)
    }

    fn src_match(&self, n: &Neg) -> Tri {
        let Some(net) = parse_net(&n.val, self.family) else {
            return Tri::Maybe;
        };
        let t = if net.prefix_len() == 0 {
            Tri::Always
        } else if self.subnets.is_empty() {
            Tri::Maybe
        } else if self.subnets.iter().all(|s| net.contains(s)) {
            Tri::Always
        } else if self.subnets.iter().all(|s| !net.contains(s) && !s.contains(&net)) {
            Tri::Never
        } else {
            Tri::Maybe
        };
        t.not_if(n.neg)
    }

    fn dst_match(&self, n: &Neg) -> Tri {
        // Any destination: only a match on everything is certain.
        match parse_net(&n.val, self.family) {
            Some(net) if net.prefix_len() == 0 => Tri::Always.not_if(n.neg),
            _ => Tri::Maybe,
        }
    }

    fn port_in(&self, list: &str) -> Option<bool> {
        let mut any = false;
        for part in list.split(',') {
            let (a, b) = match part.split_once(':') {
                Some((a, b)) => (
                    if a.is_empty() { 0 } else { a.parse::<u16>().ok()? },
                    if b.is_empty() {
                        u16::MAX
                    } else {
                        b.parse::<u16>().ok()?
                    },
                ),
                None => {
                    let p = part.parse::<u16>().ok()?;
                    (p, p)
                }
            };
            any |= a <= DNS_PORT && DNS_PORT <= b;
        }
        Some(any)
    }

    fn module_match(&self, m: &super::model::Module, proto_fixed: bool) -> Tri {
        let mut t = Tri::Always;
        match m.name.as_str() {
            "comment" => {}
            "udp" | "tcp" => {
                if m.name != self.proto.name() {
                    return Tri::Never;
                }
                for o in &m.opts {
                    let ot = match o.name.as_str() {
                        "--dport" | "--destination-port" => {
                            match o.args.first().and_then(|a| self.port_in(a)) {
                                Some(true) => Tri::Always,
                                Some(false) => Tri::Never,
                                None => Tri::Maybe,
                            }
                        }
                        "--sport" | "--source-port" => match o.args.first().map(String::as_str) {
                            Some("0:65535") | Some(":") => Tri::Always,
                            _ => Tri::Maybe,
                        },
                        _ => Tri::Maybe,
                    };
                    t = t.and(ot.not_if(o.neg));
                }
            }
            "multiport" => {
                if !proto_fixed {
                    return Tri::Maybe;
                }
                for o in &m.opts {
                    let ot = match o.name.as_str() {
                        "--dports" | "--destination-ports" => {
                            match o.args.first().and_then(|a| self.port_in(a)) {
                                Some(true) => Tri::Always,
                                Some(false) => Tri::Never,
                                None => Tri::Maybe,
                            }
                        }
                        "--ports" => match o.args.first().and_then(|a| self.port_in(a)) {
                            Some(true) => Tri::Always,
                            _ => Tri::Maybe,
                        },
                        _ => Tri::Maybe,
                    };
                    t = t.and(ot.not_if(o.neg));
                }
            }
            "conntrack" | "state" => {
                for o in &m.opts {
                    let ot = match o.name.as_str() {
                        // The nat table sees a connection's first packet: NEW.
                        "--ctstate" | "--state" => {
                            let has_new = o.args.first().is_some_and(|a| a.split(',').any(|s| s == "NEW"));
                            if has_new { Tri::Always } else { Tri::Never }
                        }
                        _ => Tri::Maybe,
                    };
                    t = t.and(ot.not_if(o.neg));
                }
            }
            _ => t = Tri::Maybe,
        }
        t
    }

    fn rule_match(&self, s: &Spec) -> Tri {
        let mut t = if s.unknown > 0 { Tri::Maybe } else { Tri::Always };
        if let Some(n) = &s.in_if {
            t = t.and(self.iface_match(n));
        }
        if s.out_if.is_some() || s.fragment.is_some() {
            t = t.and(Tri::Maybe);
        }
        if let Some(n) = &s.proto {
            t = t.and(self.proto_match(n));
        }
        if let Some(n) = &s.src {
            t = t.and(self.src_match(n));
        }
        if let Some(n) = &s.dst {
            t = t.and(self.dst_match(n));
        }
        let proto_fixed = s
            .proto
            .as_ref()
            .is_some_and(|p| !p.neg && self.proto_match(p) == Tri::Always);
        for m in &s.modules {
            t = t.and(self.module_match(m, proto_fixed));
        }
        t
    }

    /// Is this DNAT target one of the gateway's own addresses at the listener's port?
    fn dnat_ok(&self, s: &Spec) -> bool {
        let Some(tg) = &s.target else { return false };
        let dests: Vec<&String> = tg
            .opts
            .iter()
            .filter(|o| o.name == "--to-destination" || o.name == "--to")
            .flat_map(|o| o.args.iter())
            .collect();
        if dests.is_empty() || tg.opts.iter().any(|o| o.neg) {
            return false;
        }
        dests.iter().all(|d| self.dest_ok(d))
    }

    fn dest_ok(&self, d: &str) -> bool {
        // [addr]:port, addr:port (IPv4), with optional ranges a-b and p1-p2.
        let (addr, port) = if let Some(rest) = d.strip_prefix('[') {
            let Some((a, p)) = rest.split_once(']') else {
                return false;
            };
            (a, p.strip_prefix(':'))
        } else if self.family == Family::V4 {
            match d.split_once(':') {
                Some((a, p)) => (a, Some(p)),
                None => (d, None),
            }
        } else {
            (d, None)
        };
        let single = |s: &str| -> Option<String> {
            match s.split_once('-') {
                Some((a, b)) if a == b => Some(a.to_string()),
                Some(_) => None,
                None => Some(s.to_string()),
            }
        };
        let Some(addr) = single(addr) else { return false };
        let Ok(ip) = addr.parse::<IpAddr>() else {
            return false;
        };
        let port_ok = match port {
            Some(p) => single(p).and_then(|p| p.parse::<u16>().ok()) == Some(self.port),
            None => self.port == DNS_PORT,
        };
        port_ok && self.own.contains(&ip)
    }

    fn redirect_ok(&self, s: &Spec) -> bool {
        // REDIRECT is a DNAT to the incoming interface's own primary address.
        let Some(tg) = &s.target else { return false };
        if tg.opts.iter().any(|o| o.neg) {
            return false;
        }
        match tg.opt("--to-ports").and_then(|o| o.args.first()) {
            Some(p) => {
                let p = match p.split_once('-') {
                    Some((a, b)) if a == b => a,
                    Some(_) => return false,
                    None => p.as_str(),
                };
                p.parse::<u16>().ok() == Some(self.port) && !self.subnets.is_empty()
            }
            None => self.port == DNS_PORT && !self.subnets.is_empty(),
        }
    }

    /// The outcome of `chain` for this class, walked once and then reused.
    fn walk<'t>(&self, t: &'t Table, chain: &'t str, w: &mut Walk<'t>) -> Outcome {
        if let Some(&o) = w.memo.get(chain) {
            return o;
        }
        if w.stack.len() > MAX_DEPTH || w.stack.contains(&chain) {
            return Outcome::NotCovered;
        }
        let Some(c) = t.chain(chain) else {
            return Outcome::NotCovered;
        };
        w.stack.push(chain);
        let out = self.walk_rules(t, &c.rules, w);
        w.stack.pop();
        w.memo.insert(chain, out);
        out
    }

    fn walk_rules<'t>(&self, t: &'t Table, rules: &'t [Rule], w: &mut Walk<'t>) -> Outcome {
        // Some packets already left this chain undecided (a RETURN or a goto that only maybe
        // matched): the rest can at best be covered, so the chain as a whole falls.
        let mut some_fell = false;
        let covered = |some_fell: bool| {
            if some_fell {
                Outcome::Falls
            } else {
                Outcome::Covered
            }
        };
        for r in rules {
            if w.steps == 0 {
                return Outcome::NotCovered;
            }
            w.steps -= 1;
            let Some(s) = r.spec() else {
                // Opaque: unknown match and target.
                return Outcome::NotCovered;
            };
            let m = self.rule_match(s);
            if m == Tri::Never {
                continue;
            }
            let Some(target) = s.target_name() else { continue };
            match target {
                "DNAT" if self.dnat_ok(s) => {
                    if m == Tri::Always {
                        return covered(some_fell);
                    }
                }
                "REDIRECT" if self.redirect_ok(s) => {
                    if m == Tri::Always {
                        return covered(some_fell);
                    }
                }
                "LOG" | "NFLOG" | "MARK" | "CONNMARK" | "TRACE" | "AUDIT" => {}
                "RETURN" => {
                    if m == Tri::Always {
                        return Outcome::Falls;
                    }
                    // Some packets return, the rest go on here.
                    some_fell = true;
                }
                name if t.has_chain(name) => {
                    let sub = self.walk(t, name, w);
                    let goto = s.target.as_ref().is_some_and(|tg| tg.goto);
                    match (sub, m) {
                        (Outcome::NotCovered, _) => return Outcome::NotCovered,
                        (Outcome::Covered, Tri::Always) => return covered(some_fell),
                        // A goto doesn't come back here: falling out of it returns from this
                        // chain.
                        (Outcome::Falls, Tri::Always) if goto => return Outcome::Falls,
                        (Outcome::Falls, _) if goto => some_fell = true,
                        _ => {} // the rest continue here
                    }
                }
                // DNAT elsewhere, ACCEPT, DROP, an unknown target: wrong for whatever matches.
                _ => return Outcome::NotCovered,
            }
        }
        Outcome::Falls
    }
}

/// One class's walk: outcomes of the chains walked so far, the chains being walked, and the
/// steps left of its budget.
struct Walk<'t> {
    memo: HashMap<&'t str, Outcome>,
    stack: Vec<&'t str>,
    steps: usize,
}

/// Is the redirect present for one family? `interfaces` are `redirect.interfaces`, `port` the
/// listener's port.
pub fn redirect_present(
    nat: &Table,
    family: Family,
    interfaces: &[String],
    port: u16,
    addrs: &[IfAddr],
) -> bool {
    redirect_present_within(nat, family, interfaces, port, addrs, MAX_WALK_STEPS)
}

/// [`redirect_present`] with `steps` per walk.
fn redirect_present_within(
    nat: &Table,
    family: Family,
    interfaces: &[String],
    port: u16,
    addrs: &[IfAddr],
    steps: usize,
) -> bool {
    if interfaces.is_empty() {
        return true;
    }
    let fam_ok = |a: &IpAddr| {
        matches!(
            (family, a),
            (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_))
        )
    };
    let own: Vec<IpAddr> = addrs
        .iter()
        .map(|a| a.addr)
        .filter(|a| fam_ok(a) && !a.is_loopback())
        .collect();
    for iface in interfaces {
        let subnets: Vec<IpNet> = addrs
            .iter()
            .filter(|a| &a.ifname == iface && fam_ok(&a.addr))
            .filter_map(|a| IpNet::new(a.addr, a.prefix).ok().map(|n| n.trunc()))
            .collect();
        for proto in [Proto::Udp, Proto::Tcp] {
            let class = Class {
                family,
                iface,
                proto,
                port,
                subnets: subnets.clone(),
                own: own.clone(),
            };
            let mut w = Walk {
                memo: HashMap::new(),
                stack: Vec::new(),
                steps,
            };
            if class.walk(nat, "PREROUTING", &mut w) != Outcome::Covered {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nat(rules: &str) -> Table {
        Table::parse(&format!(
            "-P PREROUTING ACCEPT\n-N HOOK\n-A PREROUTING -j HOOK\n{rules}"
        ))
        .unwrap()
    }

    fn addrs() -> Vec<IfAddr> {
        let a = |i: &str, ip: &str, p| IfAddr {
            ifname: i.into(),
            addr: ip.parse().unwrap(),
            prefix: p,
        };
        vec![
            a("lo", "127.0.0.1", 8),
            a("br0", "192.168.1.1", 24),
            a("br0", "fd00::1", 64),
            a("br10", "192.168.10.1", 24),
        ]
    }

    fn present(t: &Table, f: Family, ifs: &[&str], port: u16) -> bool {
        let ifs: Vec<String> = ifs.iter().map(|s| s.to_string()).collect();
        redirect_present(t, f, &ifs, port, &addrs())
    }

    const OK: &str = "-A HOOK -i br0 -p udp -m udp --dport 53 -j DNAT --to-destination 192.168.1.1:5335\n\
-A HOOK -i br0 -p tcp -m tcp --dport 53 -j DNAT --to-destination 192.168.1.1:5335\n";

    #[test]
    fn both_protocols_and_every_interface() {
        assert!(present(&nat(OK), Family::V4, &["br0"], 5335));
        let udp_only = OK.lines().next().unwrap().to_string() + "\n";
        assert!(!present(&nat(&udp_only), Family::V4, &["br0"], 5335));
        assert!(!present(&nat(OK), Family::V4, &["br0", "br10"], 5335));
    }

    #[test]
    fn wrong_port_host_or_range_is_missing() {
        assert!(!present(&nat(OK), Family::V4, &["br0"], 5353));
        let elsewhere = OK.replace("192.168.1.1:5335", "1.1.1.1:5335");
        assert!(!present(&nat(&elsewhere), Family::V4, &["br0"], 5335));
        // Without a port the packet keeps port 53: right only for a listener on 53.
        let no_port = OK.replace("192.168.1.1:5335", "192.168.1.1");
        assert!(!present(&nat(&no_port), Family::V4, &["br0"], 5335));
        assert!(present(&nat(&no_port), Family::V4, &["br0"], 53));
        // Loopback doesn't count as one of the gateway's addresses for LAN clients.
        let lo = OK.replace("192.168.1.1:5335", "127.0.0.1:5335");
        assert!(!present(&nat(&lo), Family::V4, &["br0"], 5335));
        // A range could send some queries elsewhere.
        let range = OK.replace("192.168.1.1:5335", "192.168.1.1-192.168.1.2:5335");
        assert!(!present(&nat(&range), Family::V4, &["br0"], 5335));
        let ports = OK.replace("192.168.1.1:5335", "192.168.1.1:5335-5336");
        assert!(!present(&nat(&ports), Family::V4, &["br0"], 5335));
    }

    #[test]
    fn multiport_and_interface_wildcards() {
        let mp = "-A HOOK -i br+ -p udp -m multiport --dports 53,853 -j DNAT --to-destination 192.168.10.1:5335\n\
-A HOOK -i br+ -p tcp -m multiport --dports 1:100 -j DNAT --to-destination 192.168.10.1:5335\n";
        assert!(present(&nat(mp), Family::V4, &["br0", "br10"], 5335));
        // A multiport list that leaves out 53 doesn't match.
        let not53 = mp.replace("1:100", "54:100");
        assert!(!present(&nat(&not53), Family::V4, &["br0"], 5335));
    }

    #[test]
    fn ipv6_targets() {
        let v6 = "-A HOOK -i br0 -p udp -m udp --dport 53 -j DNAT --to-destination [fd00::1]:5335\n\
-A HOOK -i br0 -p tcp -m tcp --dport 53 -j DNAT --to-destination [fd00::1]:5335\n";
        assert!(present(&nat(v6), Family::V6, &["br0"], 5335));
        // A bare IPv6 address has no port: port 53 is kept.
        let bare = v6.replace("[fd00::1]:5335", "fd00::1");
        assert!(!present(&nat(&bare), Family::V6, &["br0"], 5335));
        assert!(present(&nat(&bare), Family::V6, &["br0"], 53));
        // An IPv4 address of the gateway doesn't count in ip6tables.
        assert!(!present(&nat(OK), Family::V6, &["br0"], 5335));
    }

    #[test]
    fn an_earlier_accept_or_destination_limited_dnat_breaks_the_proof() {
        let t = Table::parse(&format!(
            "-P PREROUTING ACCEPT\n-N HOOK\n-A PREROUTING -i br0 -j ACCEPT\n-A PREROUTING -j HOOK\n{OK}"
        ))
        .unwrap();
        assert!(!present(&t, Family::V4, &["br0"], 5335));
        // Queries to 8.8.8.8 would go to 1.1.1.1 unfiltered: the redirect doesn't cover them.
        let limited = format!(
            "-A HOOK -i br0 -d 8.8.8.8/32 -p udp -m udp --dport 53 -j DNAT --to-destination 1.1.1.1\n{OK}"
        );
        assert!(!present(&nat(&limited), Family::V4, &["br0"], 5335));
        // A rule for another interface doesn't matter.
        let other =
            format!("-A HOOK -i br10 -p udp -m udp --dport 53 -j DNAT --to-destination 1.1.1.1\n{OK}");
        assert!(present(&nat(&other), Family::V4, &["br0"], 5335));
    }

    /// Runs `f` on a thread with a 2 MiB stack (a tokio worker's default) and fails if it
    /// overflows or takes longer than `limit`.
    fn bounded<T: Send + 'static>(limit: std::time::Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || {
                let _ = tx.send(f());
            })
            .unwrap();
        rx.recv_timeout(limit)
            .expect("the walk overflowed its stack or ran too long")
    }

    #[test]
    fn long_runs_of_conditional_returns_do_not_overflow_the_stack() {
        // README "Untrusted input": a valid 10,000-rule chain mustn't crash the helper.
        let mut rules = String::new();
        for i in 0..10_000u32 {
            rules.push_str(&format!("-A HOOK -d 10.{}.{}.1/32 -j RETURN\n", i / 256, i % 256));
        }
        rules.push_str(OK);
        let t = nat(&rules);
        let ok = bounded(std::time::Duration::from_secs(20), move || {
            present(&t, Family::V4, &["br0"], 5335)
        });
        // Packets to those destinations return to PREROUTING undecided: not covered.
        assert!(!ok);
    }

    #[test]
    fn jump_fan_out_is_walked_once_per_chain() {
        // 14 chains, each jumping 6 times to the next: without memoisation 6^14 sub-walks.
        let mut text = String::from("-P PREROUTING ACCEPT\n");
        for i in 0..=14 {
            text.push_str(&format!("-N C{i}\n"));
        }
        text.push_str("-A PREROUTING -j C0\n");
        for i in 0..14 {
            for _ in 0..6 {
                text.push_str(&format!("-A C{i} -j C{}\n", i + 1));
            }
        }
        text.push_str("-A C14 -p udp -j LOG\n");
        text.push_str(&OK.replace("-A HOOK", "-A PREROUTING"));
        let t = Table::parse(&text).unwrap();
        let start = std::time::Instant::now();
        let ok = bounded(std::time::Duration::from_secs(20), move || {
            present(&t, Family::V4, &["br0"], 5335)
        });
        assert!(ok, "every packet falls back to PREROUTING's DNAT rules");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn every_walk_has_its_own_step_budget() {
        // One walk per redirect interface and protocol: a table that one walk covers within the
        // budget is proven however many interfaces share it (4 walks here, each over more than a
        // quarter of the budget).
        let mut rules = String::new();
        for i in 0..(MAX_WALK_STEPS as u32 / 3) {
            rules.push_str(&format!("-A HOOK -i br99 -j LOG --log-prefix p{i}\n"));
        }
        rules.push_str(OK);
        rules.push_str(&OK.replace("br0", "br10").replace("192.168.1.1", "192.168.10.1"));
        let t = nat(&rules);
        assert!(present(&t, Family::V4, &["br0", "br10"], 5335));
    }

    #[test]
    fn a_walk_over_its_budget_is_not_proven() {
        // More reachable rules than one walk's budget: not proven, so `redirect_missing`.
        let mut rules = String::new();
        for i in 0..1_000 {
            rules.push_str(&format!("-A HOOK -i br99 -j LOG --log-prefix p{i}\n"));
        }
        rules.push_str(OK);
        let t = nat(&rules);
        let ifs = ["br0".to_string()];
        assert!(!redirect_present_within(
            &t,
            Family::V4,
            &ifs,
            5335,
            &addrs(),
            1_000
        ));
        // Within it, the same table is proven.
        assert!(redirect_present_within(
            &t,
            Family::V4,
            &ifs,
            5335,
            &addrs(),
            1_010
        ));
    }

    #[test]
    fn a_jump_cycle_is_never_covered() {
        let t = Table::parse(&format!(
            "-P PREROUTING ACCEPT\n-N A\n-N B\n-A PREROUTING -j A\n-A A -p udp -j B\n-A B -j A\n{}",
            OK.replace("-A HOOK", "-A PREROUTING")
        ))
        .unwrap();
        assert!(!present(&t, Family::V4, &["br0"], 5335));
    }

    #[test]
    fn link_local_clients_count_for_source_matches() {
        // edge-unifi.md §3: a client querying the gateway's link-local address from its own
        // link-local address must be redirected too.
        let mut a = addrs();
        a.push(IfAddr {
            ifname: "br0".into(),
            addr: "fe80::1".parse().unwrap(),
            prefix: 64,
        });
        let ifs = vec!["br0".to_string()];
        let v6 = "-A HOOK -i br0 -p udp -m udp --dport 53 -j DNAT --to-destination [fd00::1]:5335\n\
-A HOOK -i br0 -p tcp -m tcp --dport 53 -j DNAT --to-destination [fd00::1]:5335\n";
        assert!(redirect_present(&nat(v6), Family::V6, &ifs, 5335, &a));
        let scoped = v6.replace("-i br0", "-s fd00::/64 -i br0");
        assert!(!redirect_present(&nat(&scoped), Family::V6, &ifs, 5335, &a));
        // A rule for every source after the scoped one proves it again.
        assert!(redirect_present(
            &nat(&format!("{scoped}{v6}")),
            Family::V6,
            &ifs,
            5335,
            &a
        ));
    }

    #[test]
    fn redirect_target_to_the_listener_port_counts() {
        // REDIRECT is a DNAT to the incoming interface's own address.
        let r = "-A HOOK -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 5335\n\
-A HOOK -i br0 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 5335\n";
        assert!(present(&nat(r), Family::V4, &["br0"], 5335));
        assert!(!present(&nat(r), Family::V4, &["br0"], 5353));
    }
}
