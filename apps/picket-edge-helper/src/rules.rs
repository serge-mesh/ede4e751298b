//! The rules the helper keeps (edge-firewall.md §4 `apply`, `disable`/`enable`): validation of an
//! `apply` request into [`Desired`], and `<helper_dir>/rules.json`.
//!
//! The edge is untrusted as seen by the helper (README "Untrusted input"), so everything that
//! reaches `iptables-restore` or a set is checked here: interface names are plain kernel names
//! (no `+` wildcard, quotes or spaces), CIDRs parse, and the static and exempt sets fit their
//! size after normalisation. `rules.json` goes through the same validation when it is read
//! back, so a file that a bug or a full disk left oversized can't bypass the limits.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use picket_api::edge_config::FwMode;
use picket_api::helper::{ApplyRequest, InterfaceMode, RedirectCheck};
use serde::{Deserialize, Serialize};

/// Most protected or redirect interfaces in one `apply`.
pub const MAX_INTERFACES: usize = 64;
/// `maxelem` of the static and exempt sets, and the most entries each may hold after
/// normalisation (a `/0` counts as the two halves it is stored as).
pub const STATIC_MAX: u32 = 65_536;
/// Most raw entries in each static/exempt input list, before normalisation.
pub const MAX_INPUT_NETS: usize = 2 * STATIC_MAX as usize;
/// `IFNAMSIZ` - 1.
pub const MAX_IFNAME: usize = 15;
/// Longest CIDR string accepted.
const MAX_CIDR_LEN: usize = 64;
pub const RULES_FILE: &str = "rules.json";
/// Largest `rules.json` read back (a full `apply` fits a 1 MiB frame).
pub const RULES_MAX: u64 = 4 << 20;

/// A validated `apply`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Desired {
    /// Protected interfaces, sorted by name.
    pub interfaces: Vec<(String, FwMode)>,
    pub static4: Vec<IpNet>,
    pub static6: Vec<IpNet>,
    pub exempt4: Vec<IpNet>,
    pub exempt6: Vec<IpNet>,
    pub redirect: Option<RedirectCheck>,
}

/// A kernel interface name, safe to put in an iptables rule.
pub fn valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_IFNAME
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parses a CIDR or a bare address, with host bits cleared.
pub fn parse_cidr(s: &str) -> Option<IpNet> {
    let s = s.trim();
    if s.is_empty() || s.len() > MAX_CIDR_LEN {
        return None;
    }
    let n = match s.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => IpNet::from(s.parse::<IpAddr>().ok()?),
    };
    Some(n.trunc())
}

/// `hash:net` rejects a zero prefix (kernel `IPSET_ERR_INVALID_CIDR`), so a `/0` is stored as
/// its two halves.
pub(crate) fn expand(n: IpNet) -> impl Iterator<Item = IpNet> {
    if n.prefix_len() > 0 {
        return [Some(n), None].into_iter().flatten();
    }
    // Checked at compile time: `new_assert` in a const panics in the build, never at run time.
    const V4: [Ipv4Net; 2] = [
        Ipv4Net::new_assert(std::net::Ipv4Addr::new(0, 0, 0, 0), 1),
        Ipv4Net::new_assert(std::net::Ipv4Addr::new(128, 0, 0, 0), 1),
    ];
    const V6: [Ipv6Net; 2] = [
        Ipv6Net::new_assert(std::net::Ipv6Addr::from_bits(0), 1),
        Ipv6Net::new_assert(std::net::Ipv6Addr::from_bits(1 << 127), 1),
    ];
    let pair = match n {
        IpNet::V4(_) => V4.map(IpNet::V4),
        IpNet::V6(_) => V6.map(IpNet::V6),
    };
    pair.map(Some).into_iter().flatten()
}

/// Splits CIDR strings into IPv4 and IPv6 lists: normalised, expanded, deduplicated, sorted,
/// each at most [`STATIC_MAX`].
fn split_nets(what: &str, list: &[String]) -> Result<(Vec<IpNet>, Vec<IpNet>), String> {
    // A list longer than twice the limit can't fit even if every entry were a duplicate pair.
    if list.len() > MAX_INPUT_NETS {
        return Err(format!("{what}: too many entries"));
    }
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for s in list {
        let n = parse_cidr(s).ok_or_else(|| format!("{what}: invalid CIDR {:?}", truncate(s)))?;
        for e in expand(n) {
            match e {
                IpNet::V4(_) => v4.insert(e),
                IpNet::V6(_) => v6.insert(e),
            };
        }
        if v4.len() > STATIC_MAX as usize || v6.len() > STATIC_MAX as usize {
            return Err(format!("{what}: more than {STATIC_MAX} entries per family"));
        }
    }
    Ok((v4.into_iter().collect(), v6.into_iter().collect()))
}

fn truncate(s: &str) -> String {
    s.chars().take(40).collect()
}

impl Desired {
    pub fn from_request(r: &ApplyRequest) -> Result<Self, String> {
        if r.interfaces.len() > MAX_INTERFACES {
            return Err(format!("more than {MAX_INTERFACES} interfaces"));
        }
        let mut ifs: Vec<(String, FwMode)> = Vec::with_capacity(r.interfaces.len());
        for i in &r.interfaces {
            if !valid_ifname(&i.name) {
                return Err(format!("invalid interface name {:?}", truncate(&i.name)));
            }
            match ifs.iter().find(|(n, _)| n == &i.name) {
                Some((_, m)) if *m != i.mode => return Err(format!("interface {} listed twice", i.name)),
                Some(_) => {}
                None => ifs.push((i.name.clone(), i.mode)),
            }
        }
        ifs.sort_by(|a, b| a.0.cmp(&b.0));
        let (static4, static6) = split_nets("static", &r.static_allow)?;
        let (exempt4, exempt6) = split_nets("exempt", &r.exempt)?;
        let redirect = match &r.redirect {
            None => None,
            Some(rd) => {
                if rd.interfaces.len() > MAX_INTERFACES {
                    return Err(format!("redirect: more than {MAX_INTERFACES} interfaces"));
                }
                if rd.port == 0 {
                    return Err("redirect: port 0".into());
                }
                let mut names = BTreeSet::new();
                for n in &rd.interfaces {
                    if !valid_ifname(n) {
                        return Err(format!("redirect: invalid interface name {:?}", truncate(n)));
                    }
                    names.insert(n.clone());
                }
                Some(RedirectCheck {
                    interfaces: names.into_iter().collect(),
                    port: rd.port,
                    ipv6: rd.ipv6,
                })
            }
        };
        Ok(Self {
            interfaces: ifs,
            static4,
            static6,
            exempt4,
            exempt6,
            redirect,
        })
    }

    /// The normalised request, as persisted in `rules.json`.
    pub fn to_request(&self) -> ApplyRequest {
        let s = |a: &[IpNet], b: &[IpNet]| a.iter().chain(b).map(|n| n.to_string()).collect();
        ApplyRequest {
            interfaces: self
                .interfaces
                .iter()
                .map(|(n, m)| InterfaceMode {
                    name: n.clone(),
                    mode: *m,
                })
                .collect(),
            static_allow: s(&self.static4, &self.static6),
            exempt: s(&self.exempt4, &self.exempt6),
            redirect: self.redirect.clone(),
        }
    }

    /// Redirect interfaces that get the IPv6 DNS reject (`redirect.ipv6: false`).
    pub fn dns6_interfaces(&self) -> Vec<String> {
        match &self.redirect {
            Some(r) if !r.ipv6 => r.interfaces.clone(),
            _ => Vec::new(),
        }
    }

    /// The desired members of a static or exempt set.
    pub fn members(&self, set: &str) -> &[IpNet] {
        use picket_api::helper::sets::*;
        match set {
            s if s == STATIC4 => &self.static4,
            s if s == STATIC6 => &self.static6,
            s if s == EXEMPT4 => &self.exempt4,
            s if s == EXEMPT6 => &self.exempt6,
            _ => &[],
        }
    }

    pub fn interface_modes(&self) -> Vec<InterfaceMode> {
        self.interfaces
            .iter()
            .map(|(n, m)| InterfaceMode {
                name: n.clone(),
                mode: *m,
            })
            .collect()
    }
}

/// `<helper_dir>/rules.json`: the last `apply` and the `disable` flag.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesFile {
    pub version: u32,
    pub disabled: bool,
    pub apply: Option<ApplyRequest>,
}

impl RulesFile {
    pub const VERSION: u32 = 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(statics: &[&str]) -> ApplyRequest {
        ApplyRequest {
            interfaces: vec![InterfaceMode {
                name: "br0".into(),
                mode: FwMode::Enforce,
            }],
            static_allow: statics.iter().map(|s| s.to_string()).collect(),
            exempt: vec![],
            redirect: None,
        }
    }

    #[test]
    fn interface_names_are_checked() {
        for bad in [
            "",
            "br+",
            "a b",
            "br0\"",
            "-x",
            "verylonginterface0",
            "br0;",
            "..",
            "eth\n0",
        ] {
            assert!(!valid_ifname(bad), "{bad:?}");
        }
        for good in ["br0", "eth4", "br10", "switch0.10", "wg_0", "vlan-1"] {
            assert!(valid_ifname(good), "{good}");
        }
    }

    #[test]
    fn cidrs_normalise_and_zero_prefix_expands() {
        let d = Desired::from_request(&req(&[
            "10.1.2.3/8",
            "10.0.0.0/8",
            "0.0.0.0/0",
            "::/0",
            "192.0.2.1",
        ]))
        .unwrap();
        let s4: Vec<String> = d.static4.iter().map(|n| n.to_string()).collect();
        assert_eq!(s4, vec!["0.0.0.0/1", "10.0.0.0/8", "128.0.0.0/1", "192.0.2.1/32"]);
        let s6: Vec<String> = d.static6.iter().map(|n| n.to_string()).collect();
        assert_eq!(s6, vec!["::/1", "8000::/1"]);
        assert!(Desired::from_request(&req(&["nonsense"])).is_err());
    }

    #[test]
    fn size_limit_counts_after_expansion_and_survives_round_trip() {
        // STATIC_MAX - 1 distinct /32s plus a /0 (two entries) is one over the limit.
        let mut v: Vec<String> = (0..STATIC_MAX - 1)
            .map(|i| format!("10.{}.{}.{}/32", i >> 16, (i >> 8) & 255, i & 255))
            .collect();
        v.push("0.0.0.0/0".into());
        let r = ApplyRequest {
            static_allow: v.clone(),
            ..req(&[])
        };
        assert!(Desired::from_request(&r).unwrap_err().contains("more than"));
        // Exactly at the limit is fine, and the persisted form validates again.
        v.pop();
        v.pop();
        v.push("0.0.0.0/0".into());
        let d = Desired::from_request(&ApplyRequest {
            static_allow: v,
            ..req(&[])
        })
        .unwrap();
        assert_eq!(d.static4.len(), STATIC_MAX as usize);
        let again = Desired::from_request(&d.to_request()).unwrap();
        assert_eq!(again, d);
    }

    #[test]
    fn conflicting_duplicate_interface_rejected() {
        let mut r = req(&[]);
        r.interfaces.push(InterfaceMode {
            name: "br0".into(),
            mode: FwMode::Monitor,
        });
        assert!(Desired::from_request(&r).is_err());
    }
}
