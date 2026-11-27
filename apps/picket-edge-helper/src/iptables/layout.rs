//! Where Picket's jumps go, and what the catch-all below them is (edge-unifi.md §4,
//! edge-firewall.md §4 "Jump placement").
//!
//! UniFi: `UBIOS_FORWARD_IN_USER` → `-i <if> -j UBIOS_<ZONE>_IN_USER` → the rule with
//! `! --match-set UBIOS_local_zoned_subnets dst` → the zone→External chain. Its catch-all is
//! the last Firewall Policy (log tag `FIREWALL_POLICY`) when that is a REJECT or DROP with no
//! match but a comment (the Block All), else UniFi's default, the chain's last rule. The jumps go
//! directly above the catch-all and its NFLOG rule.
//!
//! Debian: the end of `FORWARD`, directly above the final rule that matches everything.
//!
//! Fail closed: whatever this module can't prove gets no jump ([`CatchAll::Unknown`]). In
//! particular a chain ending in `RETURN` is never an allow catch-all — the packet goes back to
//! UniFi's earlier chains, and an `ACCEPT` in `PICKET-FWD` would then override whatever UniFi
//! decides after the return.

use super::model::{Chain, Neg, Rule, Spec, Table};

pub const FWD: &str = "PICKET-FWD";
pub const MON: &str = "PICKET-MON";
pub const DNS6: &str = "PICKET-DNS6";
/// Picket's chains: every rule jumping to one of them is Picket's own.
pub const OUR_CHAINS: [&str; 3] = [FWD, MON, DNS6];
/// UniFi's log tag on Firewall Policies.
pub const POLICY_TAG: &str = "FIREWALL_POLICY";
/// UniFi's Object rules (edge-unifi.md §4).
pub const OBJECT_TAGS: [&str; 2] = ["GEN_BLK_FP", "GEN_ALW_FP"];
pub const UNIFI_FORWARD_IN: &str = "UBIOS_FORWARD_IN_USER";
pub const LOCAL_ZONED_SUFFIX: &str = "local_zoned_subnets";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Platform {
    Unifi,
    Debian,
}

/// What an `enforce` interface's catch-all is when it isn't a Block All with action Reject
/// (`fw_catch_all.found`). Ordered worst first, for when IPv4 and IPv6 differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Found {
    /// No Block All: UniFi's default (or the chain policy) accepts, nothing is refused.
    Allow,
    /// The last policy denies only some connection states: no jump in that chain.
    Partial,
    /// Action Block: refusals are silent.
    Drop,
}

impl Found {
    pub fn as_str(self) -> &'static str {
        match self {
            Found::Allow => "allow",
            Found::Partial => "partial",
            Found::Drop => "drop",
        }
    }
}

/// The result of looking for an interface's place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatchAll {
    /// The jumps go into `chain` at `index` of its base rules (the rules without Picket's
    /// own), i.e. directly above the catch-all's log rules and the catch-all.
    At {
        chain: String,
        index: usize,
        found: Option<Found>,
    },
    /// A state-limited last policy: no jump.
    Partial { chain: String },
    /// No recognisable place (`fw_layout_unknown`).
    Unknown(String),
}

/// Is this one of Picket's own rules (a jump to a `PICKET-*` chain)?
pub fn is_ours(r: &Rule) -> bool {
    r.target_name().is_some_and(|t| OUR_CHAINS.contains(&t))
}

fn is_log(s: &Spec) -> bool {
    matches!(s.target_name(), Some("NFLOG" | "LOG"))
}

fn is_deny(s: &Spec) -> bool {
    matches!(s.target_name(), Some("REJECT" | "DROP"))
}

fn nflog_prefix(s: &Spec) -> Option<&str> {
    let t = s.target.as_ref()?;
    t.opt("--nflog-prefix")
        .or_else(|| t.opt("--log-prefix"))
        .and_then(|o| o.args.first())
        .map(String::as_str)
}

fn tagged(s: &Spec) -> bool {
    s.comment().is_some_and(|c| c.contains(POLICY_TAG))
        || nflog_prefix(s).is_some_and(|p| p.contains(POLICY_TAG))
}

/// Is `specs[i]` part of a Firewall Policy? Its comment or log prefix carries the tag, or it is
/// the action rule directly after its tagged log rule with the same comment.
fn is_policy(specs: &[&Spec], i: usize) -> bool {
    if tagged(specs[i]) {
        return true;
    }
    i > 0
        && is_log(specs[i - 1])
        && tagged(specs[i - 1])
        && specs[i].comment().is_some()
        && specs[i].comment() == specs[i - 1].comment()
}

fn is_object(r: &Rule) -> bool {
    r.toks()
        .is_some_and(|ts| ts.iter().any(|t| OBJECT_TAGS.iter().any(|o| t.text.contains(o))))
}

/// The state match of a rule whose only matches are comments and one conntrack/state match:
/// whether it is negated, and the states it lists.
fn state_only(s: &Spec) -> Option<(bool, Vec<String>)> {
    if s.in_if.is_some()
        || s.out_if.is_some()
        || s.proto.is_some()
        || s.src.is_some()
        || s.dst.is_some()
        || s.fragment.is_some()
        || s.unknown > 0
    {
        return None;
    }
    let mut states = None;
    for m in &s.modules {
        match m.name.as_str() {
            "comment" => {}
            "conntrack" | "state" if states.is_none() && m.opts.len() == 1 => {
                let o = &m.opts[0];
                if o.name != "--ctstate" && o.name != "--state" {
                    return None;
                }
                let listed: Vec<String> = o
                    .args
                    .first()
                    .map(|a| a.split(',').map(str::to_string).collect())
                    .unwrap_or_default();
                states = Some((o.neg, listed));
            }
            _ => return None,
        }
    }
    states
}

/// A deny that leaves Picket nothing to accept below it: no match but a comment, or only a
/// state match that every NEW connection matches ([`matches_every_new`]).
fn broad_deny(s: &Spec) -> bool {
    is_deny(s)
        && (s.matches_everything() || state_only(s).is_some_and(|(neg, st)| matches_every_new(neg, &st)))
}

/// Does `[!] --ctstate <listed>` match every NEW connection? A positive list naming NEW does. A
/// negated list does only when it names no state a NEW connection can be in: not NEW, and none of
/// the virtual `SNAT` and `DNAT` (a NEW connection can be in them too, so `! --ctstate DNAT`
/// lets DNAT'd new connections through) nor anything unknown, the same rule [`excludes_new`]
/// follows.
fn matches_every_new(neg: bool, listed: &[String]) -> bool {
    if neg {
        !listed.is_empty()
            && listed
                .iter()
                .all(|x| NEVER_NEW.iter().any(|n| x.eq_ignore_ascii_case(n)))
    } else {
        listed.iter().any(|x| x.eq_ignore_ascii_case("NEW"))
    }
}

/// Start of the catch-all's own log rules directly above it (`specs[idx]`): log rules with no
/// interface, protocol, address or fragment match (rate limits and state matches are fine)
/// and, when the catch-all has a comment, the same one. Another rule's log rule above them
/// stays above Picket's jumps, so it keeps logging what it did.
fn log_run_start(specs: &[&Spec], idx: usize) -> usize {
    let comment = specs[idx].comment();
    let own = |s: &Spec| {
        is_log(s)
            && s.in_if.is_none()
            && s.out_if.is_none()
            && s.proto.is_none()
            && s.src.is_none()
            && s.dst.is_none()
            && s.fragment.is_none()
            && s.unknown == 0
            && (comment.is_none() || s.comment() == comment)
    };
    let mut i = idx;
    while i > 0 && own(specs[i - 1]) {
        i -= 1;
    }
    i
}

/// Stand-in for an over-long (opaque) rule: unknown match, no target, never a policy or a log
/// rule, so it keeps its position without being interpreted.
static OPAQUE: Spec = Spec {
    in_if: None,
    out_if: None,
    proto: None,
    src: None,
    dst: None,
    fragment: None,
    modules: Vec::new(),
    target: None,
    unknown: 1,
};

/// The chain's base rules (without Picket's own), each with its spec (the stand-in for an opaque
/// rule) and whether it is opaque.
struct Base<'a> {
    rules: Vec<&'a Rule>,
    specs: Vec<&'a Spec>,
    opaque: Vec<bool>,
}

impl<'a> Base<'a> {
    fn of(c: &'a Chain) -> Self {
        let rules: Vec<&Rule> = c.rules.iter().filter(|r| !is_ours(r)).collect();
        let specs = rules.iter().map(|r| r.spec().unwrap_or(&OPAQUE)).collect();
        let opaque = rules.iter().map(|r| r.spec().is_none()).collect();
        Self { rules, specs, opaque }
    }
    fn opaque_from(&self, start: usize) -> bool {
        self.opaque.iter().skip(start).any(|o| *o)
    }
}

/// The connection states a NEW connection is never also in. `SNAT` and `DNAT` are virtual
/// states a NEW connection can be in too, so a list naming them (or anything unknown) can match
/// NEW connections.
const NEVER_NEW: [&str; 4] = ["INVALID", "ESTABLISHED", "RELATED", "UNTRACKED"];

/// Does a state match on this rule leave NEW connections out (`--ctstate RELATED,ESTABLISHED`,
/// `! --ctstate NEW`)? Such a rule can't let a new connection skip Picket.
fn excludes_new(s: &Spec) -> bool {
    s.modules
        .iter()
        .filter(|m| m.name == "conntrack" || m.name == "state")
        .flat_map(|m| m.opts.iter())
        .filter(|o| o.name == "--ctstate" || o.name == "--state")
        .any(|o| {
            let states: Vec<&str> = o.args.first().map(|a| a.split(',').collect()).unwrap_or_default();
            if o.neg {
                // A negated list naming NEW never matches a NEW connection.
                states.iter().any(|x| x.eq_ignore_ascii_case("NEW"))
            } else {
                // A positive list only of states a NEW connection can't be in.
                !states.is_empty()
                    && states
                        .iter()
                        .all(|x| NEVER_NEW.iter().any(|n| x.eq_ignore_ascii_case(n)))
            }
        })
}

/// A rule that ends the dispatch for (some of) the packets it matches without sending them to a
/// zone chain: `ACCEPT` decides them at once, `RETURN` sends them back to UniFi's earlier chains.
/// Either way they never reach Picket's jump, so above the dispatch it fails open unless it can
/// only match connections that aren't NEW.
fn skips_dispatch(s: &Spec) -> bool {
    matches!(s.target_name(), Some("ACCEPT" | "RETURN")) && !excludes_new(s)
}

/// No match but `-i` (and comments).
fn only_in_if(s: &Spec) -> bool {
    s.out_if.is_none()
        && s.proto.is_none()
        && s.src.is_none()
        && s.dst.is_none()
        && s.fragment.is_none()
        && s.unknown == 0
        && s.modules.iter().all(|m| m.name == "comment")
}

/// Can a rule with this `-i` (or none) see `iface`'s packets? A negated match sees them unless
/// it names `iface`.
fn may_see(n: Option<&Neg>, iface: &str) -> bool {
    n.is_none_or(|n| {
        let hit = match n.val.strip_suffix('+') {
            Some(prefix) => iface.starts_with(prefix),
            None => n.val == iface,
        };
        hit != n.neg
    })
}

/// `! --match-set <…local_zoned_subnets> dst`: destinations outside UniFi's own networks.
fn non_local_dst(s: &Spec) -> bool {
    s.modules.iter().filter(|m| m.name == "set").any(|m| {
        m.opts.iter().any(|o| {
            o.name == "--match-set"
                && o.neg
                && o.args.len() == 2
                && o.args[0].ends_with(LOCAL_ZONED_SUFFIX)
                && o.args[1] == "dst"
        })
    })
}

/// A positive `--match-set <set> dst` on one of UniFi's own networks: the rule sees no external
/// destination. Those sets are `…local_zoned_subnets` and the zones' address sets
/// (`UBIOS_ADDRv4_<zone>`, `UBIOS_ADDRv6_<zone>`) other than the External zone's. Only a set
/// module with that one option counts (no `--return-nomatch` or the like).
fn local_dst_only(s: &Spec) -> bool {
    s.modules.iter().filter(|m| m.name == "set").any(|m| {
        let [o] = &m.opts[..] else { return false };
        let local = |set: &str| {
            set.ends_with(LOCAL_ZONED_SUFFIX)
                || ["UBIOS_ADDRv4_", "UBIOS_ADDRv6_"].iter().any(|p| {
                    set.strip_prefix(p)
                        .is_some_and(|z| !z.is_empty() && z != "External")
                })
        };
        o.name == "--match-set" && !o.neg && o.args.len() == 2 && o.args[1] == "dst" && local(&o.args[0])
    })
}

/// The one user chain that `candidates` jump to, if every one of them jumps to the same chain
/// and at least one does so for all of the traffic (`whole`).
fn one_chain<'a>(t: &Table, candidates: impl Iterator<Item = (&'a Spec, bool)>) -> Result<String, usize> {
    let mut chains: Vec<&str> = Vec::new();
    let mut whole = false;
    for (s, all) in candidates {
        let Some(tg) = &s.target else { continue };
        if !t.has_chain(&tg.name) || OUR_CHAINS.contains(&tg.name.as_str()) {
            continue;
        }
        if !chains.contains(&tg.name.as_str()) {
            chains.push(&tg.name);
        }
        whole |= all;
    }
    match chains.as_slice() {
        [one] if whole => Ok((*one).to_string()),
        other => Err(other.len()),
    }
}

/// UniFi: the zone→External chain of `iface`. Fails closed: `UBIOS_FORWARD_IN_USER` must send
/// all of the interface's traffic to one zone chain (a jump on `-i <if>` alone, and no jump
/// for some of it to another), and that zone chain must send what leaves UniFi's networks to
/// one zone→External chain; otherwise part of the traffic would pass a chain without the jump
/// (edge-unifi.md §4 "Unrecognised layout"). Every dispatch rule that can see the interface's
/// packets counts, not only those naming it: one without `-i`, or with a negated `-i` that
/// doesn't exclude it, may send some of them to another zone. Likewise in the zone chain every
/// jump that can see external destinations counts, not only those matching
/// `! --match-set …local_zoned_subnets dst`: `-s <host> -j <chain>` takes that host's external
/// traffic too. Exempt are rules only on UniFi's own networks ([`local_dst_only`]) and rules
/// below the jump that takes all external traffic: none of it comes back (the zone→External
/// chain's catch-all decides every packet, or [`unifi_catch_all`] finds no place).
pub fn unifi_external_chain(t: &Table, iface: &str) -> Result<String, String> {
    let fwd = t
        .chain(UNIFI_FORWARD_IN)
        .ok_or_else(|| format!("no {UNIFI_FORWARD_IN} chain"))?;
    if fwd.rules.iter().any(|r| r.spec().is_none()) {
        return Err(format!("unparseable rule in {UNIFI_FORWARD_IN}"));
    }
    // Fail closed (edge-unifi.md §4 "Unrecognised layout"): a plain `ACCEPT` or `RETURN` that can
    // see the interface's new connections above its dispatch lets them skip the zone chains, and
    // with them Picket's jump. Rules below the first jump that takes all of its traffic never
    // see it.
    let fwd_specs: Vec<&Spec> = fwd.rules.iter().filter_map(Rule::spec).collect();
    let dispatch_at = fwd_specs
        .iter()
        .position(|s| {
            may_see(s.in_if.as_ref(), iface)
                && only_in_if(s)
                && s.target_name()
                    .is_some_and(|n| t.has_chain(n) && !OUR_CHAINS.contains(&n))
        })
        .unwrap_or(fwd_specs.len());
    if fwd_specs[..dispatch_at]
        .iter()
        .any(|s| may_see(s.in_if.as_ref(), iface) && skips_dispatch(s))
    {
        return Err(format!(
            "an ACCEPT or RETURN rule above {iface}'s zone dispatch in {UNIFI_FORWARD_IN}"
        ));
    }
    let zone = one_chain(
        t,
        fwd.rules
            .iter()
            .filter_map(Rule::spec)
            .filter(|s| may_see(s.in_if.as_ref(), iface))
            .map(|s| (s, only_in_if(s))),
    )
    .map_err(|n| match n {
        0 => format!("no jump for {iface} in {UNIFI_FORWARD_IN}"),
        1 => format!("{UNIFI_FORWARD_IN} sends only some of {iface}'s traffic to its zone"),
        _ => format!("{UNIFI_FORWARD_IN} sends {iface} to {n} zone chains"),
    })?;
    let zc = t.chain(&zone).ok_or_else(|| format!("no chain {zone}"))?;
    if zc.rules.iter().any(|r| r.spec().is_none()) {
        return Err(format!("unparseable rule in {zone}"));
    }
    // All of the external traffic: `! --match-set …local_zoned_subnets dst` alone (and
    // comments).
    let whole = |s: &Spec| {
        non_local_dst(s)
            && s.in_if.is_none()
            && s.out_if.is_none()
            && s.proto.is_none()
            && s.src.is_none()
            && s.dst.is_none()
            && s.fragment.is_none()
            && s.unknown == 0
            && s.modules.iter().filter(|m| m.name == "set").count() == 1
            && s.modules
                .iter()
                .all(|m| m.name == "comment" || (m.name == "set" && m.opts.len() == 1))
    };
    // Rules after the first jump for all of it to a user chain never see external traffic.
    let specs: Vec<&Spec> = zc.rules.iter().filter_map(Rule::spec).collect();
    let seen = specs
        .iter()
        .position(|s| {
            whole(s)
                && s.target_name()
                    .is_some_and(|n| t.has_chain(n) && !OUR_CHAINS.contains(&n))
        })
        .map_or(specs.len(), |i| i + 1);
    // The second stage likewise: an `ACCEPT` or `RETURN` that can see external destinations above
    // the zone→External dispatch takes those connections past Picket's jump.
    let ext_at = seen.saturating_sub(1);
    if specs[..ext_at.min(specs.len())]
        .iter()
        .any(|s| !local_dst_only(s) && skips_dispatch(s))
    {
        return Err(format!(
            "an ACCEPT or RETURN rule above the zone→External dispatch in {zone}"
        ));
    }
    one_chain(
        t,
        specs[..seen]
            .iter()
            .filter(|s| !local_dst_only(s))
            .map(|s| (*s, whole(s))),
    )
    .map_err(|n| match n {
        0 => format!("no zone→External jump in {zone}"),
        1 => format!("{zone} sends only some external traffic to its zone→External chain"),
        _ => format!("{zone} sends external traffic to {n} chains"),
    })
}

/// Catch-all of a UniFi zone→External chain, and whether it shadows rules
/// (`unifi_conflict: shadowed_rules`).
pub fn unifi_catch_all(c: &Chain) -> (CatchAll, bool) {
    let base = Base::of(c);
    let specs = &base.specs;
    // An unparseable rule below the catch-all could be a later policy: no place can be proven.
    let unknown_below = || {
        (
            CatchAll::Unknown(format!(
                "unparseable rule at or below the catch-all of {}",
                c.name
            )),
            false,
        )
    };
    let policy: Vec<bool> = (0..specs.len()).map(|i| is_policy(specs, i)).collect();
    let broad_above = |end: usize| (0..end).any(|i| policy[i] && !is_log(specs[i]) && broad_deny(specs[i]));

    if let Some(p) = (0..specs.len()).rev().find(|&i| policy[i] && !is_log(specs[i])) {
        let s = specs[p];
        if is_deny(s) && s.matches_everything() {
            if base.opaque_from(p + 1) {
                return unknown_below();
            }
            // The Block All. Policies or Object rules below it never run.
            let below = (p + 1..specs.len()).any(|i| policy[i] || is_object(base.rules[i]));
            let found = (s.target_name() == Some("DROP")).then_some(Found::Drop);
            let index = log_run_start(specs, p);
            return (
                CatchAll::At {
                    chain: c.name.clone(),
                    index,
                    found,
                },
                below || broad_above(p),
            );
        }
        if is_deny(s) && state_only(s).is_some() {
            if base.opaque_from(p + 1) {
                return unknown_below();
            }
            return (
                CatchAll::Partial {
                    chain: c.name.clone(),
                },
                broad_above(p),
            );
        }
    }
    // UniFi's default: the chain's last rule, which must decide every packet. An unparseable
    // rule anywhere could be the real last policy (a Block All we can't see).
    if base.opaque_from(0) {
        return (
            CatchAll::Unknown(format!("unparseable rule in {}", c.name)),
            false,
        );
    }
    let Some(&last) = specs.last() else {
        return (CatchAll::Unknown(format!("{} is empty", c.name)), false);
    };
    let d = specs.len() - 1;
    if !last.matches_everything() {
        return (
            CatchAll::Unknown(format!(
                "{} does not end in a rule that matches everything",
                c.name
            )),
            false,
        );
    }
    let found = match last.target_name() {
        Some("ACCEPT") => Some(Found::Allow),
        Some("DROP") => Some(Found::Drop),
        Some("REJECT") => None,
        other => {
            return (
                CatchAll::Unknown(format!(
                    "{} ends in {} instead of ACCEPT, DROP or REJECT",
                    c.name,
                    other.unwrap_or("no target")
                )),
                false,
            );
        }
    };
    (
        CatchAll::At {
            chain: c.name.clone(),
            index: log_run_start(specs, d),
            found,
        },
        broad_above(d),
    )
}

/// Debian: the end of `FORWARD`, directly above its final match-everything rule; without one the
/// jumps go last and the chain policy is the catch-all.
pub fn debian_catch_all(t: &Table) -> CatchAll {
    let Some(c) = t.chain("FORWARD") else {
        return CatchAll::Unknown("no FORWARD chain".into());
    };
    let base = Base::of(c);
    if base.opaque.last().copied().unwrap_or(false) {
        // The final rule can't be read: whether it matches everything is unknown.
        return CatchAll::Unknown("unparseable final rule in FORWARD".into());
    }
    let specs = &base.specs;
    let policy_found = match c.policy.as_deref() {
        Some("DROP") => Some(Found::Drop),
        _ => Some(Found::Allow),
    };
    let chain = c.name.clone();
    match specs.last() {
        Some(&last) if last.matches_everything() && last.target.is_some() => {
            let d = specs.len() - 1;
            let found = match last.target_name() {
                Some("ACCEPT") => Some(Found::Allow),
                Some("DROP") => Some(Found::Drop),
                Some("REJECT") => None,
                Some(other) => return CatchAll::Unknown(format!("FORWARD ends in an unconditional {other}")),
                None => unreachable!("checked target.is_some()"),
            };
            CatchAll::At {
                chain,
                index: log_run_start(specs, d),
                found,
            }
        }
        _ => CatchAll::At {
            chain,
            index: specs.len(),
            found: policy_found,
        },
    }
}

/// Where `iface`'s jump goes on this platform, and whether its chain shadows rules.
pub fn place(t: &Table, platform: Platform, iface: &str) -> (CatchAll, bool) {
    match platform {
        Platform::Debian => (debian_catch_all(t), false),
        Platform::Unifi => match unifi_external_chain(t, iface) {
            Ok(name) => match t.chain(&name) {
                Some(c) => unifi_catch_all(c),
                None => (CatchAll::Unknown(format!("no chain {name}")), false),
            },
            Err(e) => (CatchAll::Unknown(e), false),
        },
    }
}

/// The chains `PICKET-DNS6` jumps go first in: UniFi's hooks, or Debian's `INPUT`/`FORWARD`
/// (edge-firewall.md §2 "IPv6 DNS reject", §4 "Jump placement").
pub fn dns6_hooks(platform: Platform) -> (&'static str, &'static str) {
    match platform {
        Platform::Unifi => ("UBIOS_INPUT_USER_HOOK", "UBIOS_FORWARD_USER_HOOK"),
        Platform::Debian => ("INPUT", "FORWARD"),
    }
}

/// Is there a non-empty `DNSFILTER` chain (UniFi's Ad Blocking / Content Filtering,
/// edge-unifi.md §7)?
pub fn dnsfilter_active(t: &Table) -> bool {
    t.chains
        .iter()
        .any(|c| c.name.contains("DNSFILTER") && !c.rules.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(text: &str) -> Table {
        Table::parse(text).unwrap()
    }

    #[test]
    fn chain_ending_in_return_is_never_an_allow_catch_all() {
        let t = chain(
            "-N C\n-A C -m conntrack --ctstate INVALID -j DROP\n-A C -m comment --comment \"x\" -j RETURN\n",
        );
        let (ca, _) = unifi_catch_all(t.chain("C").unwrap());
        assert!(matches!(ca, CatchAll::Unknown(_)), "{ca:?}");
    }

    #[test]
    fn conditional_last_rule_is_unknown() {
        let t = chain("-N C\n-A C -s 10.0.0.0/8 -j ACCEPT\n");
        assert!(matches!(
            unifi_catch_all(t.chain("C").unwrap()).0,
            CatchAll::Unknown(_)
        ));
    }

    #[test]
    fn opaque_rules_keep_positions_but_never_hide_a_catch_all() {
        let long = format!("-A C -m comment --comment \"{}\" -j ACCEPT", "x".repeat(20_000));
        // Above a Block All: tolerated, and counted for the position.
        let block_all = "-A C -m comment --comment \"FIREWALL_POLICY 1 Block All\" -j REJECT";
        let t = chain(&format!(
            "-N C\n-A C -j LOG\n{long}\n{block_all}\n-A C -j ACCEPT\n"
        ));
        assert_eq!(
            unifi_catch_all(t.chain("C").unwrap()).0,
            CatchAll::At {
                chain: "C".into(),
                index: 2,
                found: None
            }
        );
        // Below the Block All, or with only UniFi's default to go by: unknown.
        let t = chain(&format!("-N C\n{block_all}\n{long}\n-A C -j ACCEPT\n"));
        assert!(matches!(
            unifi_catch_all(t.chain("C").unwrap()).0,
            CatchAll::Unknown(_)
        ));
        let t = chain(&format!("-N C\n{long}\n-A C -j ACCEPT\n"));
        assert!(matches!(
            unifi_catch_all(t.chain("C").unwrap()).0,
            CatchAll::Unknown(_)
        ));
    }

    #[test]
    fn only_states_a_new_connection_cant_be_in_leave_new_out() {
        let ex = |m: &str| {
            let t = chain(&format!("-N C\n-A C {m} -j ACCEPT\n"));
            excludes_new(t.chain("C").unwrap().rules[0].spec().unwrap())
        };
        for m in [
            "-m conntrack --ctstate RELATED,ESTABLISHED",
            "-m conntrack --ctstate INVALID",
            "-m conntrack --ctstate UNTRACKED",
            "-m state --state ESTABLISHED",
            "-m conntrack ! --ctstate NEW",
            "-m conntrack ! --ctstate NEW,DNAT",
        ] {
            assert!(ex(m), "{m}");
        }
        for m in [
            "-m conntrack --ctstate DNAT",
            "-m conntrack --ctstate SNAT",
            "-m conntrack --ctstate ESTABLISHED,DNAT",
            "-m conntrack --ctstate NEW",
            "-m conntrack ! --ctstate DNAT",
            "-m conntrack --ctstate SOMETHING",
            "",
        ] {
            assert!(!ex(m), "{m}");
        }
    }

    #[test]
    fn only_state_denies_every_new_connection_meets_are_broad() {
        let broad = |m: &str| {
            let t = chain(&format!("-N C\n-A C {m} -j REJECT\n"));
            broad_deny(t.chain("C").unwrap().rules[0].spec().unwrap())
        };
        for m in [
            "",
            "-m conntrack --ctstate NEW",
            "-m conntrack --ctstate NEW,DNAT",
            "-m conntrack ! --ctstate RELATED,ESTABLISHED",
            "-m conntrack ! --ctstate INVALID",
        ] {
            assert!(broad(m), "{m}");
        }
        // DNAT'd (or SNAT'd) new connections don't match a negated list naming those states.
        for m in [
            "-m conntrack ! --ctstate DNAT",
            "-m conntrack ! --ctstate SNAT",
            "-m conntrack ! --ctstate ESTABLISHED,DNAT",
            "-m conntrack ! --ctstate NEW",
            "-m conntrack ! --ctstate SOMETHING",
            "-m conntrack --ctstate DNAT",
            "-m conntrack --ctstate ESTABLISHED",
        ] {
            assert!(!broad(m), "{m}");
        }
    }

    #[test]
    fn negated_state_partial() {
        let t = chain(
            "-N C\n-A C -m comment --comment \"FIREWALL_POLICY 1\" -m conntrack ! --ctstate RELATED,ESTABLISHED -j REJECT\n-A C -j ACCEPT\n",
        );
        assert_eq!(
            unifi_catch_all(t.chain("C").unwrap()).0,
            CatchAll::Partial { chain: "C".into() }
        );
    }

    const DISPATCH: &str = "-N UBIOS_FORWARD_IN_USER\n-N Z\n-N G\n-N ZW\n-N GW\n\
-A UBIOS_FORWARD_IN_USER -i br0 -m comment --comment zone -j Z\n\
-A UBIOS_FORWARD_IN_USER -i br20 -j G\n\
-A Z -m set ! --match-set UBIOS_local_zoned_subnets dst -m comment --comment ext -j ZW\n\
-A G -m set ! --match-set UBIOS_local_zoned_subnets dst -j GW\n-A ZW -j ACCEPT\n-A GW -j ACCEPT\n";

    #[test]
    fn zone_dispatch_must_be_unambiguous() {
        assert_eq!(unifi_external_chain(&chain(DISPATCH), "br0"), Ok("ZW".into()));
        // An extra jump for the same zone changes nothing; a wildcard on `-i` alone is whole.
        let t = chain(&format!(
            "{DISPATCH}-A UBIOS_FORWARD_IN_USER -i br0 -o eth4 -j Z\n"
        ));
        assert_eq!(unifi_external_chain(&t, "br0"), Ok("ZW".into()));
        let t = chain(&DISPATCH.replace("-i br20 -j G", "-i br2+ -j G"));
        assert_eq!(unifi_external_chain(&t, "br20"), Ok("GW".into()));
        // Some of br0's traffic to another zone, by a condition or a wildcard.
        let t = chain(&DISPATCH.replace(
            "-i br0 -m",
            "-i br0 -s 10.0.0.0/8 -j G\n-A UBIOS_FORWARD_IN_USER -i br0 -m",
        ));
        assert!(unifi_external_chain(&t, "br0").is_err());
        let t = chain(&format!("{DISPATCH}-A UBIOS_FORWARD_IN_USER -i br+ -j G\n"));
        assert!(unifi_external_chain(&t, "br0").is_err());
        // Only a conditional jump: the rest of br0's traffic never reaches the zone.
        let t = chain(&DISPATCH.replace("-i br0 -m", "-i br0 -p tcp -m"));
        assert!(unifi_external_chain(&t, "br0").is_err());
        // A zone chain with a second zone→External jump for some of its traffic.
        let t = chain(&DISPATCH.replace(
            "-A Z -m set",
            "-A Z -m set ! --match-set UBIOS_local_zoned_subnets dst -m set --match-set K src -j GW\n-A Z -m set",
        ));
        assert!(unifi_external_chain(&t, "br0").is_err());
        assert_eq!(unifi_external_chain(&t, "br20"), Ok("GW".into()));
        // An unparseable dispatch rule could send br0 anywhere.
        let long = format!(
            "-A UBIOS_FORWARD_IN_USER -m comment --comment \"{}\" -j G\n",
            "x".repeat(20_000)
        );
        assert!(unifi_external_chain(&chain(&format!("{DISPATCH}{long}")), "br0").is_err());
    }

    #[test]
    fn dispatch_without_a_positive_interface_match_counts() {
        // A jump to another zone with no `-i`, or with a negated one that doesn't exclude br0,
        // sends some of br0's traffic past its zone chain: no place can be proven.
        for extra in [
            "-A UBIOS_FORWARD_IN_USER -m set --match-set UBIOS_GRP_iot src -j G\n",
            "-A UBIOS_FORWARD_IN_USER ! -i eth4 -m conntrack --ctstate NEW -j G\n",
            "-A UBIOS_FORWARD_IN_USER ! -i eth+ -j G\n",
            "-A UBIOS_FORWARD_IN_USER -j G\n",
        ] {
            let t = chain(&format!("{DISPATCH}{extra}"));
            assert!(unifi_external_chain(&t, "br0").is_err(), "{extra}");
        }
        // A negated match that excludes br0 doesn't concern it.
        for extra in [
            "-A UBIOS_FORWARD_IN_USER ! -i br0 -m set --match-set K src -j G\n",
            "-A UBIOS_FORWARD_IN_USER ! -i br+ -j G\n",
        ] {
            let t = chain(&format!("{DISPATCH}{extra}"));
            assert_eq!(unifi_external_chain(&t, "br0"), Ok("ZW".into()), "{extra}");
        }
        // A jump with no `-i` to br0's own zone, for all of the traffic, is its dispatch.
        let t = chain(&DISPATCH.replace("-i br0 -m comment --comment zone -j Z", "-j Z"));
        assert_eq!(unifi_external_chain(&t, "br0"), Ok("ZW".into()));
    }

    #[test]
    fn zone_chain_rules_that_could_take_external_traffic_count() {
        // edge-unifi.md §4 "Unrecognised layout": any jump in the zone chain that could see some
        // of the external traffic before its zone→External dispatch may send it elsewhere.
        let above = |rule: &str| {
            chain(&DISPATCH.replace(
                "-A Z -m set ! --match-set",
                &format!("-A Z {rule}\n-A Z -m set ! --match-set"),
            ))
        };
        for rule in [
            "-s 192.0.2.7/32 -j G",
            "-p tcp -m tcp --dport 443 -j G",
            "-d 10.0.0.0/8 -j G",
            "-m set --match-set UBIOS_GRP_telemetry dst -j G",
            "-m set ! --match-set UBIOS_ADDRv4_Internal dst -j G",
            "-m set --match-set UBIOS_ADDRv4_External dst -j G",
            "-m set --match-set UBIOS_local_zoned_subnets src -j G",
            "-j G",
            "-s 192.0.2.7/32 -g G",
        ] {
            assert!(unifi_external_chain(&above(rule), "br0").is_err(), "{rule}");
        }
        // Rules that only see UniFi's own networks, jumps to the same chain, and targets that
        // aren't user chains don't concern it.
        for rule in [
            "-m set --match-set UBIOS_ADDRv4_Internal dst -m comment --comment \"UBIOS Internal-Internal\" -j G",
            "-m set --match-set UBIOS_ADDRv6_Internal dst -j G",
            "-m set --match-set UBIOS_local_zoned_subnets dst -j G",
            "-s 192.0.2.7/32 -j ZW",
            "-m conntrack --ctstate INVALID -j DROP",
            "-j PICKET-FWD",
        ] {
            assert_eq!(
                unifi_external_chain(&above(rule), "br0"),
                Ok("ZW".into()),
                "{rule}"
            );
        }
        // Below the dispatch for all external traffic, a rule never sees any of it.
        let t = chain(&format!("{DISPATCH}-A Z -j G\n"));
        assert_eq!(unifi_external_chain(&t, "br0"), Ok("ZW".into()));
    }

    #[test]
    fn only_the_catch_alls_own_log_rules_sit_below_the_jump() {
        // Debian: a LOG rule for one interface above the final LOG + REJECT pair.
        let t = chain(
            "-P FORWARD ACCEPT\n-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\
-A FORWARD -i eth0 -j LOG --log-prefix \"lan \"\n-A FORWARD -m limit --limit 5/min -j LOG --log-prefix \"drop \"\n-A FORWARD -j REJECT\n",
        );
        assert_eq!(
            debian_catch_all(&t),
            CatchAll::At {
                chain: "FORWARD".into(),
                index: 2,
                found: None
            }
        );
        // UniFi: a log rule with another comment directly above the Block All's own.
        let t = chain(
            "-N C\n-A C -m comment --comment \"FIREWALL_POLICY 5 Log\" -j NFLOG --nflog-prefix \"[FIREWALL_POLICY-A-5]\"\n\
-A C -m conntrack --ctstate NEW -m comment --comment \"FIREWALL_POLICY 9 Block All\" -j NFLOG --nflog-prefix \"[FIREWALL_POLICY-R-9]\"\n\
-A C -m comment --comment \"FIREWALL_POLICY 9 Block All\" -j REJECT\n-A C -j ACCEPT\n",
        );
        assert_eq!(
            unifi_catch_all(t.chain("C").unwrap()).0,
            CatchAll::At {
                chain: "C".into(),
                index: 1,
                found: None
            }
        );
    }

    #[test]
    fn dnsfilter_detected_only_when_non_empty() {
        assert!(!dnsfilter_active(&chain("-N DNSFILTER\n")));
        assert!(dnsfilter_active(&chain(
            "-N DNSFILTER\n-A DNSFILTER -p udp -m udp --dport 53 -j DNAT --to-destination 127.0.0.1:1053\n"
        )));
    }
}
