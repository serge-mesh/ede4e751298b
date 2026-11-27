//! Clients, devices and profile choice (edge.md §5), built once per config activation.
//!
//! - A MAC table, one longest-prefix trie per family over every client's `source_ips`, and a
//!   profile-id table, all immutable; the neighbour map (rtnetlink) supplies each source
//!   address's MAC.
//! - **Device:** one MAC with every address the neighbour table holds for it; an address with no
//!   MAC belongs to the client whose `source_ips` hold it (most specific range first, ties to the
//!   first listed), else is a device of its own. Rate limits, temporary allows and the log's
//!   `device` are per device.
//! - **Profile choice,** first match wins: (1) the profile named in the DoH path or DoT name,
//!   which must exist and admit the client (else DoH 403, DoT REFUSED with EDE 18); (2) the
//!   client listing the device's MAC, then the clients whose `source_ips` hold the source address,
//!   most specific first; (3) `default_profile`. In 2 and 3 a profile that doesn't admit the
//!   client is skipped; none left → REFUSED with EDE 18.
//! - **`allowed_sources`:** address ranges admit the source address, MACs that device, client
//!   names that client's devices (its MACs and its source ranges).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use picket_api::edge_config::{Client, EdgeConfig};

use crate::neighbours::{Mac, format_mac, parse_mac};

/// Most clients and allowed-source entries read from a config (README §2 Bounded).
pub const MAX_CLIENTS: usize = 4096;
pub const MAX_SOURCES: usize = 4096;

/// One client entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRt {
    pub name: Arc<str>,
    pub profile: Option<Arc<str>>,
    pub tags: Vec<Arc<str>>,
}

/// Parses an address range: CIDR, or a bare address (a /32 or /128). IPv4-mapped IPv6 ranges
/// fold to IPv4, as sources do.
pub fn parse_range(s: &str) -> Option<IpNet> {
    let s = s.trim();
    if let Ok(n) = s.parse::<IpNet>() {
        return Some(canonical_net(n.trunc()));
    }
    s.parse::<IpAddr>().ok().map(|ip| IpNet::from(ip.to_canonical()))
}

fn canonical_net(n: IpNet) -> IpNet {
    match n {
        IpNet::V6(v6) if v6.prefix_len() >= 96 => match v6.addr().to_ipv4_mapped() {
            Some(v4) => Ipv4Net::new(v4, v6.prefix_len() - 96).map(IpNet::V4).unwrap_or(n),
            None => n,
        },
        _ => n,
    }
}

fn host_net(ip: IpAddr) -> IpNet {
    IpNet::from(ip.to_canonical())
}

/// A set of address ranges with containment checks.
#[derive(Clone, Default)]
pub struct RangeSet {
    v4: PrefixMap<Ipv4Net, ()>,
    v6: PrefixMap<Ipv6Net, ()>,
    len: usize,
}

impl std::fmt::Debug for RangeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeSet").field("len", &self.len).finish()
    }
}

impl RangeSet {
    pub fn insert(&mut self, n: IpNet) {
        match n {
            IpNet::V4(n) => {
                self.v4.insert(n, ());
            }
            IpNet::V6(n) => {
                self.v6.insert(n, ());
            }
        }
        self.len += 1;
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match host_net(ip) {
            IpNet::V4(h) => self.v4.get_lpm(&h).is_some(),
            IpNet::V6(h) => self.v6.get_lpm(&h).is_some(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A profile's `allowed_sources`, compiled.
#[derive(Clone, Debug, Default)]
pub struct Admission {
    ranges: RangeSet,
    macs: HashSet<Mac>,
}

impl Admission {
    pub fn admits(&self, dev: &Device) -> bool {
        self.ranges.contains(dev.ip) || dev.mac.is_some_and(|m| self.macs.contains(&m))
    }
}

/// The device a query comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// The source address (IPv4-mapped IPv6 as IPv4).
    pub ip: IpAddr,
    pub mac: Option<Mac>,
    /// The client listing the MAC.
    pub mac_client: Option<u32>,
    /// The client whose `source_ips` hold the address most specifically.
    pub range_client: Option<u32>,
}

/// What rate limits, temporary allows and the recent-blocks ring key a device by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DeviceKey {
    Mac(Mac),
    Client(Arc<str>),
    Addr(IpAddr),
}

impl DeviceKey {
    /// The form `allows.json` stores (`StoredAllow::device`): the MAC, the client name or the
    /// address.
    pub fn text(&self) -> String {
        match self {
            Self::Mac(m) => format_mac(m),
            Self::Client(c) => c.to_string(),
            Self::Addr(ip) => ip.to_string(),
        }
    }

    /// Calls `f` with [`Self::text`] written into a stack buffer: no allocation on the query
    /// path (build-and-test.md §4).
    pub fn with_text<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        use std::fmt::Write as _;
        match self {
            Self::Client(c) => f(c),
            Self::Mac(m) => {
                let mut b = StackText::default();
                let _ = write!(
                    b,
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                );
                f(b.as_str())
            }
            Self::Addr(ip) => {
                let mut b = StackText::default();
                let _ = write!(b, "{ip}");
                f(b.as_str())
            }
        }
    }
}

/// A short text written on the stack (an address or a MAC: at most 45 bytes).
struct StackText {
    buf: [u8; 64],
    len: usize,
}

impl Default for StackText {
    fn default() -> Self {
        Self { buf: [0; 64], len: 0 }
    }
}

impl StackText {
    fn as_str(&self) -> &str {
        // Only `write_str` fills the buffer, with whole `str`s.
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl std::fmt::Write for StackText {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(std::fmt::Error)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The result of profile choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    /// The profile id.
    Profile(Arc<str>),
    /// No profile admits the client (REFUSED, EDE 18).
    Refused,
    /// The profile named in the DoH path or DoT name doesn't exist or doesn't admit the client
    /// (DoH 403; DoT REFUSED, EDE 18).
    NamedRefused,
}

/// Clients and devices, compiled from a config.
#[derive(Clone, Default)]
pub struct Clients {
    pub list: Vec<ClientRt>,
    by_mac: HashMap<Mac, u32>,
    /// Prefix → the first client listing it.
    v4: PrefixMap<Ipv4Net, u32>,
    v6: PrefixMap<Ipv6Net, u32>,
    /// Per client name: its MACs and ranges (for `allowed_sources` naming a client).
    members: HashMap<Arc<str>, (Vec<Mac>, Vec<IpNet>)>,
}

impl std::fmt::Debug for Clients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clients")
            .field("list", &self.list)
            .finish_non_exhaustive()
    }
}

impl Clients {
    /// Builds the tables. Malformed MACs and ranges are skipped and counted in `skipped`.
    pub fn build(clients: &[Client], skipped: &mut usize) -> Self {
        let mut out = Clients::default();
        for (idx, c) in (0u32..).zip(clients.iter().take(MAX_CLIENTS)) {
            let name: Arc<str> = c.name.as_str().into();
            out.list.push(ClientRt {
                name: Arc::clone(&name),
                profile: c.profile.as_deref().map(Into::into),
                tags: c.tags.iter().take(64).map(|t| t.as_str().into()).collect(),
            });
            let mut macs = vec![];
            let mut nets = vec![];
            for m in c.macs.iter().take(MAX_SOURCES) {
                match parse_mac(m) {
                    Some(mac) => {
                        out.by_mac.entry(mac).or_insert(idx);
                        macs.push(mac);
                    }
                    None => *skipped += 1,
                }
            }
            for r in c.source_ips.iter().take(MAX_SOURCES) {
                match parse_range(r) {
                    Some(IpNet::V4(n)) => {
                        if out.v4.get(&n).is_none() {
                            out.v4.insert(n, idx);
                        }
                        nets.push(IpNet::V4(n));
                    }
                    Some(IpNet::V6(n)) => {
                        if out.v6.get(&n).is_none() {
                            out.v6.insert(n, idx);
                        }
                        nets.push(IpNet::V6(n));
                    }
                    None => *skipped += 1,
                }
            }
            let e = out.members.entry(name).or_default();
            e.0.extend(macs);
            e.1.extend(nets);
        }
        out
    }

    /// The device for a source address and its MAC (if the neighbour table has one).
    pub fn device(&self, ip: IpAddr, mac: Option<Mac>) -> Device {
        let ip = ip.to_canonical();
        let mac_client = mac.and_then(|m| self.by_mac.get(&m).copied());
        let range_client = match host_net(ip) {
            IpNet::V4(h) => self.v4.get_lpm(&h).map(|(_, i)| *i),
            IpNet::V6(h) => self.v6.get_lpm(&h).map(|(_, i)| *i),
        };
        Device {
            ip,
            mac,
            mac_client,
            range_client,
        }
    }

    /// Every client whose `source_ips` hold `ip`, most specific first (ties: first listed).
    pub fn range_clients(&self, ip: IpAddr) -> smallvec::SmallVec<[u32; 4]> {
        let mut v: smallvec::SmallVec<[(u8, u32); 4]> = match host_net(ip.to_canonical()) {
            IpNet::V4(h) => self.v4.cover(&h).map(|(p, i)| (p.prefix_len(), *i)).collect(),
            IpNet::V6(h) => self.v6.cover(&h).map(|(p, i)| (p.prefix_len(), *i)).collect(),
        };
        v.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        v.into_iter().map(|(_, i)| i).collect()
    }

    pub fn get(&self, i: u32) -> Option<&ClientRt> {
        self.list.get(i as usize)
    }

    /// The client that names a device: the one listing its MAC, else the most specific range.
    pub fn naming_client(&self, d: &Device) -> Option<&ClientRt> {
        d.mac_client.or(d.range_client).and_then(|i| self.get(i))
    }

    /// The device's key (edge.md §5): its MAC; with none, the client whose `source_ips` hold the
    /// address; else the address.
    pub fn key(&self, d: &Device) -> DeviceKey {
        if let Some(m) = d.mac {
            return DeviceKey::Mac(m);
        }
        match d.range_client.and_then(|i| self.get(i)) {
            Some(c) => DeviceKey::Client(Arc::clone(&c.name)),
            None => DeviceKey::Addr(d.ip),
        }
    }

    /// The log's `device` (api.md §5): the client's name, else the MAC, else none.
    pub fn log_name(&self, d: &Device) -> Option<String> {
        if let Some(c) = self.naming_client(d) {
            return Some(c.name.to_string());
        }
        d.mac.map(|m| format_mac(&m))
    }

    /// Compiles `allowed_sources`.
    pub fn admission(&self, sources: &[String], skipped: &mut usize) -> Admission {
        let mut a = Admission::default();
        for s in sources.iter().take(MAX_SOURCES) {
            if let Some(n) = parse_range(s) {
                a.ranges.insert(n);
            } else if let Some(m) = parse_mac(s) {
                a.macs.insert(m);
            } else if let Some((macs, nets)) = self.members.get(s.as_str()) {
                a.macs.extend(macs.iter().copied());
                for n in nets {
                    a.ranges.insert(*n);
                }
            } else {
                // An unknown client name admits nobody (the client may have been removed).
                *skipped += 1;
            }
        }
        a
    }
}

/// Whether a profile admits a device: `Some((admitted, the profile's shared id))` for a known
/// profile, `None` for an unknown one.
pub type Admits<'a> = dyn Fn(&str, &Device) -> Option<(bool, Arc<str>)> + 'a;

/// Profile choice over compiled tables.
pub struct Chooser<'a> {
    pub clients: &'a Clients,
    pub admits: &'a Admits<'a>,
    pub default_profile: Option<&'a str>,
}

impl Chooser<'_> {
    /// Chooses the profile for `d` (edge.md §5 "Profile choice"). Allocates nothing.
    pub fn choose(&self, named: Option<&str>, d: &Device) -> Choice {
        if let Some(p) = named {
            return match (self.admits)(p, d) {
                Some((true, id)) => Choice::Profile(id),
                _ => Choice::NamedRefused,
            };
        }
        let try_profile = |p: &str| match (self.admits)(p, d) {
            Some((true, id)) => Some(id),
            _ => None,
        };
        if let Some(c) = d.mac_client.and_then(|i| self.clients.get(i))
            && let Some(p) = &c.profile
            && let Some(id) = try_profile(p)
        {
            return Choice::Profile(id);
        }
        if d.range_client.is_some() {
            for i in self.clients.range_clients(d.ip) {
                if let Some(c) = self.clients.get(i)
                    && let Some(p) = &c.profile
                    && let Some(id) = try_profile(p)
                {
                    return Choice::Profile(id);
                }
            }
        }
        if let Some(p) = self.default_profile
            && let Some(id) = try_profile(p)
        {
            return Choice::Profile(id);
        }
        Choice::Refused
    }
}

/// Ids every profile, client and default profile of `cfg` refer to that don't exist, for a
/// warning (the config still runs: those steps are skipped).
pub fn dangling_profiles(cfg: &EdgeConfig) -> Vec<String> {
    let mut out = vec![];
    if let Some(d) = &cfg.default_profile
        && !cfg.profiles.contains_key(d)
    {
        out.push(d.clone());
    }
    for c in &cfg.clients {
        if let Some(p) = &c.profile
            && !cfg.profiles.contains_key(p)
            && !out.contains(p)
        {
            out.push(p.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn device_text_on_the_stack_equals_text() {
        for k in [
            DeviceKey::Mac([0xaa, 0x0b, 0, 0xff, 1, 2]),
            DeviceKey::Client("Kids tablet".into()),
            DeviceKey::Addr("192.168.1.140".parse().unwrap()),
            DeviceKey::Addr("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255".parse().unwrap()),
            DeviceKey::Addr("2001:db8::1".parse().unwrap()),
        ] {
            assert_eq!(k.with_text(str::to_owned), k.text());
        }
    }

    fn client(name: &str, macs: &[&str], ips: &[&str], profile: Option<&str>) -> Client {
        Client {
            name: name.into(),
            macs: macs.iter().map(|s| s.to_string()).collect(),
            source_ips: ips.iter().map(|s| s.to_string()).collect(),
            profile: profile.map(Into::into),
            tags: vec![],
        }
    }

    struct Fixture {
        clients: Clients,
        adm: BTreeMap<String, Admission>,
        default: Option<String>,
    }

    impl Fixture {
        fn new(list: Vec<Client>, profiles: &[(&str, &[&str])], default: Option<&str>) -> Self {
            let mut skipped = 0;
            let clients = Clients::build(&list, &mut skipped);
            let adm = profiles
                .iter()
                .map(|(p, src)| {
                    let s: Vec<String> = src.iter().map(|x| x.to_string()).collect();
                    (p.to_string(), clients.admission(&s, &mut skipped))
                })
                .collect();
            Fixture {
                clients,
                adm,
                default: default.map(Into::into),
            }
        }

        fn choose(&self, named: Option<&str>, ip: &str, mac: Option<&str>) -> Choice {
            let d = self.clients.device(ip.parse().unwrap(), mac.and_then(parse_mac));
            let admits = |p: &str, d: &Device| self.adm.get(p).map(|a| (a.admits(d), Arc::<str>::from(p)));
            Chooser {
                clients: &self.clients,
                admits: &admits,
                default_profile: self.default.as_deref(),
            }
            .choose(named, &d)
        }
    }

    const ALL: &[&str] = &["0.0.0.0/0", "::/0"];

    #[test]
    fn each_step_with_allowed_sources() {
        let f = Fixture::new(
            vec![
                client("office-pc", &["aa:bb:cc:dd:ee:01"], &[], Some("adults")),
                client("emma-tablet", &["aa:bb:cc:dd:ee:02"], &[], Some("kids")),
                client("kids-network", &[], &["192.168.1.128/25"], Some("kids")),
                client("tv-room", &[], &["192.168.1.192/26"], Some("tv")),
                client("named-only", &["aa:bb:cc:dd:ee:09"], &[], None),
            ],
            &[
                ("adults", &["office-pc", "aa:bb:cc:dd:ee:03"]),
                ("kids", ALL),
                ("tv", &["10.0.0.0/8"]),
                ("strict", ALL),
            ],
            Some("strict"),
        );
        let p = |s: &str| Choice::Profile(s.into());
        // Step 2 by MAC.
        assert_eq!(
            f.choose(None, "192.168.1.10", Some("aa:bb:cc:dd:ee:01")),
            p("adults")
        );
        assert_eq!(
            f.choose(None, "192.168.1.10", Some("aa:bb:cc:dd:ee:02")),
            p("kids")
        );
        // By source range, most specific first; a profile that doesn't admit is skipped (tv
        // admits only 10/8), so the less specific kids-network decides.
        assert_eq!(f.choose(None, "192.168.1.200", None), p("kids"));
        // A client without a profile only names the device: default profile.
        assert_eq!(
            f.choose(None, "192.168.1.10", Some("aa:bb:cc:dd:ee:09")),
            p("strict")
        );
        // A changed (private) MAC is a new device: falls to source_ips or the default.
        assert_eq!(
            f.choose(None, "192.168.1.10", Some("02:00:00:00:00:01")),
            p("strict")
        );
        // Step 1: another profile named in the URL, admitted (by MAC) and refused.
        assert_eq!(
            f.choose(Some("adults"), "192.168.1.11", Some("aa:bb:cc:dd:ee:03")),
            p("adults")
        );
        assert_eq!(
            f.choose(Some("adults"), "192.168.1.11", None),
            Choice::NamedRefused
        );
        assert_eq!(f.choose(Some("nope"), "192.168.1.11", None), Choice::NamedRefused);
        // By client name: office-pc's MAC is admitted to adults.
        assert_eq!(
            f.choose(Some("adults"), "192.168.1.12", Some("aa:bb:cc:dd:ee:01")),
            p("adults")
        );
    }

    #[test]
    fn nobody_admitted_is_refused() {
        let f = Fixture::new(
            vec![client("lan", &[], &["192.168.1.0/24"], Some("lan"))],
            &[("lan", &["192.168.1.0/24"]), ("strict", &["10.0.0.0/8"])],
            Some("strict"),
        );
        assert_eq!(f.choose(None, "192.168.1.5", None), Choice::Profile("lan".into()));
        assert_eq!(f.choose(None, "172.16.0.5", None), Choice::Refused);
        // IPv4-mapped IPv6 sources count as IPv4.
        assert_eq!(
            f.choose(None, "::ffff:192.168.1.5", None),
            Choice::Profile("lan".into())
        );
    }

    #[test]
    fn devices_keys_and_names() {
        let mut skipped = 0;
        let c = Clients::build(
            &[
                client("pc", &["aa:bb:cc:dd:ee:01", "not-a-mac"], &[], None),
                client("wide", &[], &["192.168.0.0/16"], None),
                client("narrow", &[], &["192.168.1.0/24", "192.168.1.0/24"], None),
                client("dup", &[], &["192.168.1.0/24"], None),
            ],
            &mut skipped,
        );
        assert_eq!(skipped, 1);
        let d = c.device("192.168.1.9".parse().unwrap(), None);
        assert_eq!(
            c.key(&d),
            DeviceKey::Client("narrow".into()),
            "ties go to the first listed"
        );
        assert_eq!(c.log_name(&d).as_deref(), Some("narrow"));
        let d = c.device("10.1.1.1".parse().unwrap(), None);
        assert_eq!(c.key(&d), DeviceKey::Addr("10.1.1.1".parse().unwrap()));
        assert_eq!(c.log_name(&d), None);
        let mac = parse_mac("aa:bb:cc:dd:ee:01").unwrap();
        let d = c.device("192.168.1.9".parse().unwrap(), Some(mac));
        assert_eq!(c.key(&d), DeviceKey::Mac(mac));
        assert_eq!(c.log_name(&d).as_deref(), Some("pc"));
        let unknown = parse_mac("aa:bb:cc:dd:ee:77").unwrap();
        let d = c.device("10.0.0.1".parse().unwrap(), Some(unknown));
        assert_eq!(c.log_name(&d).as_deref(), Some("aa:bb:cc:dd:ee:77"));
        assert_eq!(
            c.range_clients("192.168.1.3".parse().unwrap()).as_slice(),
            &[2, 1]
        );
    }

    #[test]
    fn ranges_parse() {
        assert_eq!(parse_range("10.0.0.1"), Some("10.0.0.1/32".parse().unwrap()));
        assert_eq!(parse_range("10.1.2.3/8"), Some("10.0.0.0/8".parse().unwrap()));
        assert_eq!(
            parse_range("::ffff:10.0.0.0/104"),
            Some("10.0.0.0/8".parse().unwrap())
        );
        assert_eq!(parse_range("fd00::/8"), Some("fd00::/8".parse().unwrap()));
        assert_eq!(parse_range("office-pc"), None);
    }
}
