//! The deterministic rules × names corpus shared by the parity tests (PARITY.md).

#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

use std::fmt::Write as _;
use std::net::IpAddr;

use jiff::Timestamp;
use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};
use picket_rules::ip::{go_ip_string, netip_string};
use picket_rules::matcher::{BundleMatcher, MatchResult, Outcome};
use picket_rules::rewrite::RewriteAnswer;
use picket_rules::{QueryCtx, Rule};

/// Which tally a case counts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    /// The parity metric: every decision counts but those rules.md §3's exceptions make.
    Main,
    /// Rule text that rules.md §1 normalises (uppercase host rules, IDN, trailing dots), where
    /// AdGuard compares the text as written. Owner decision pending: asserted against an explicit
    /// list of expected deviations.
    Normalisation,
    /// Several `$badfilter` rules matching one request (urlfilter keeps a rule unless every one of
    /// them negates it; Picket resolves each on its own, rules.md §4). Owner decision pending:
    /// asserted against an explicit list of expected deviations.
    MultiBadfilter,
}

#[derive(Clone, Debug)]
pub enum Target {
    Name(Vec<Vec<u8>>),
    Ip(IpAddr),
}

#[derive(Clone, Debug)]
pub struct Query {
    pub target: Target,
    pub qtype: u16,
    pub client_ip: Option<IpAddr>,
    pub client_name: Option<String>,
    pub tags: Vec<String>,
}

impl Query {
    /// The hostname text AdGuard Home matches.
    pub fn host_text(&self) -> String {
        match &self.target {
            Target::Name(l) => picket_api::names::adguard_text(l.iter().map(Vec::as_slice)),
            Target::Ip(ip) => go_ip_string(*ip),
        }
    }

    /// True for a name with a label holding a byte other than `a-z0-9-_` (rules.md §3).
    pub fn unusual(&self) -> bool {
        match &self.target {
            Target::Name(l) => !l.iter().all(|l| picket_api::names::is_ordinary_label(l)),
            Target::Ip(_) => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Case {
    pub id: String,
    pub group: Group,
    pub rules: Vec<String>,
    pub queries: Vec<Query>,
}

const A: u16 = 1;
const AAAA: u16 = 28;
const CNAME: u16 = 5;
const MX: u16 = 15;
const SVCB: u16 = 64;
const HTTPS: u16 = 65;

/// (qtype, client ip, client name, tags): plain query, a client with every attribute, a named
/// client with a quote and a space, a CNAME target, an SVCB target and a tagged admin.
type Ctx = (
    u16,
    Option<&'static str>,
    Option<&'static str>,
    &'static [&'static str],
);

fn contexts() -> Vec<Ctx> {
    vec![
        (A, None, None, &[]),
        (AAAA, Some("192.168.1.5"), Some("kid"), &["device_phone"]),
        (HTTPS, Some("10.1.2.3"), Some("Frank's laptop"), &[]),
        (CNAME, None, None, &[]),
        (SVCB, Some("::1"), None, &["device_tv"]),
        (MX, Some("192.168.1.200"), None, &["user_admin"]),
    ]
}

pub const ORDINARY_NAMES: &[&str] = &[
    "example.com",
    "www.example.com",
    "ads.example.com",
    "sub.ads.example.com",
    "a.b.c.d.example.com",
    "notexample.com",
    "example.com.evil.net",
    "example.net",
    "tracker.net",
    "x.tracker.net",
    "com",
    "target.example",
    "banner.example.org",
    "ads1.example",
    "ads.example",
    "foo-ads-bar.example",
    "ad-server.example.net",
    "evil.example",
    "_dmarc.example.com",
    "xn--e1afmkfd.xn--p1ai",
    "1.2.3.4",
    "x.1.2.3.4",
    "1.10.0.0",
    "10.0.0.1",
    "adsrvr.example",
    "allowed.adsrvr.example",
    "cdn.metrics.example.net",
    "exact.example.org",
    "w.exact.example.org",
    "scheme.example",
    "a.wild.example",
    "wild.example",
    "x.dot.example",
    "ad-1.example.net",
    "ad5.example.org",
    "pixel.example",
    "ipv6only.example",
    "kids-block.example",
    "guest-only.example",
    "everything-but.example",
    "good.everything-but.example",
    "rewritten.example",
    "cname.example",
    "nx.example",
    "example-host.example",
    "hosts-in-adblock.example",
    "malware-c2.example",
    "sub.domain.malware-c2.example",
    "upper-case.example",
    "news.example",
    "adserver.example",
    "mobile-ads.example",
    "x-728x90-y.example",
    "mapped.example",
    "loopback-block.example",
    "multi-b.example",
    "port.example",
    "scheme-bare.example",
    "http-only.example",
];

/// Names with unusual bytes: as query names, CNAME targets (qtype CNAME) and HTTPS/SVCB targets.
pub fn unusual_names() -> Vec<Vec<Vec<u8>>> {
    let l = |v: &[&[u8]]| v.iter().map(|x| x.to_vec()).collect::<Vec<_>>();
    vec![
        l(&[b"a!b", b"example", b"com"]),
        l(&[b"example", b"com!x"]),
        l(&[b"evil", b"example!x", b"attacker", b"net"]),
        l(&[b"a.b", b"example", b"com"]),
        l(&[b"example.com"]),
        l(&[b"x y", b"example", b"com"]),
        l(&[b"\x00", b"example", b"com"]),
        l(&[b"ads", b"example", b"com\xff"]),
        l(&[b"a!b", b"example"]),
        l(&[b"ads", b"Example", b"COM"]),
        l(&[b"1", b"2", b"3", b"4!"]),
        // `/` bytes: only browser path rules and some patterns reach these (review round 1, R10).
        l(&[b"x/ads/banner", b"example"]),
        l(&[b"example", b"com/ads/x"]),
    ]
}

pub const IP_CHECKS: &[&str] = &[
    "1.2.3.4",
    "1.10.0.0",
    "10.0.0.5",
    "192.0.2.10",
    "2001:db8::1",
    "::ffff:1.2.3.4",
    "2001:db8::10",
    "5.6.7.8",
    "2001:db8::bad",
    "198.51.100.7",
];

fn dotted(n: &str) -> Vec<Vec<u8>> {
    n.split('.').map(|l| l.as_bytes().to_vec()).collect()
}

fn name_queries(names: &[Vec<Vec<u8>>], all_ctx: bool) -> Vec<Query> {
    let ctxs = contexts();
    let ctxs: Vec<_> = if all_ctx {
        ctxs
    } else {
        ctxs.into_iter().take(2).collect()
    };
    let mut out = Vec::new();
    for n in names {
        for (qtype, ip, name, tags) in &ctxs {
            out.push(Query {
                target: Target::Name(n.clone()),
                qtype: *qtype,
                client_ip: ip.map(|s| s.parse().unwrap()),
                client_name: name.map(str::to_string),
                tags: tags.iter().map(|s| s.to_string()).collect(),
            });
        }
    }
    out
}

fn ip_queries() -> Vec<Query> {
    let mut out = Vec::new();
    for s in IP_CHECKS {
        let ip: IpAddr = s.parse().unwrap();
        let qtype = if ip.is_ipv4() || s.starts_with("::ffff:") {
            A
        } else {
            AAAA
        };
        out.push(Query {
            target: Target::Ip(ip),
            qtype,
            client_ip: None,
            client_name: None,
            tags: vec![],
        });
        out.push(Query {
            target: Target::Ip(ip),
            qtype: HTTPS,
            client_ip: Some("192.168.1.5".parse().unwrap()),
            client_name: Some("kid".into()),
            tags: vec!["device_phone".into()],
        });
    }
    out
}

/// Every rule form and modifier the corpus covers, one per single-rule case.
pub const SINGLE_RULES: &[&str] = &[
    // Host rules and hosts lines.
    "example.com",
    "ads.example.com",
    "0.0.0.0 example.com",
    "127.0.0.1 ads.example.com",
    ":: tracker.net",
    "192.0.2.10 example.com",
    "2001:db8::10 example.com",
    // A mapping whose name is IPv6 text (review round 2, CC8).
    "192.0.2.1 2001:db8::1",
    "::ffff:192.0.2.9 example.com",
    "0.0.0.0 example.com tracker.net",
    "0.0.0.0 1.2.3.4",
    "0.0.0.0 example.com#comment",
    "0.0.0.0 tracker.net # comment",
    "localhost",
    "com",
    "ab",
    // Keyed network forms.
    "||example.com^",
    "|example.com^",
    "://example.com^",
    "*.example.com^",
    ".example.com^",
    "||ads.example.com^",
    "||com^",
    "||example.com/*",
    "||Example.COM^",
    "@@||example.com^",
    "@@|ads.example.com^",
    "||example.com^$important",
    "@@||example.com^$important",
    "|ads.example.com^$important",
    "||10.0.0^",
    "||_dmarc.example.com^",
    // Patterns.
    "example.com^",
    "||example.com",
    "|example.com|",
    "||example.com|",
    "||ads*.example.com^",
    "||*.example.com^",
    "*ads*",
    "-ads-",
    "/banner.",
    "||*^",
    "ad*.example.com^",
    "||tracker.net^|",
    "http://example.com^",
    "http://example.com",
    "|http://example.com^",
    "_dmarc.example.com",
    "example.com.evil.net",
    "x-728x90-",
    "^example.com",
    "example.com^^",
    "|example",
    "||example.c",
    "*.com|",
    "/^ads?\\./",
    "/example\\.(com|net)$/",
    "/[!]/",
    "/\\bads\\b/",
    "/ads|tracker/",
    "/^[a-z]+\\.example\\.com$/",
    "/\\p{L}+\\.tracker\\.net/",
    "/a\\\\\\.b/",
    "/(?i)EXAMPLE\\.COM$/",
    "/x{2,1001}/",
    "/(?=ads)/",
    "/[a-z]{3}\\.example/",
    "/^1\\.2\\.3\\.4$/",
    "/^2001:db8::/",
    "/(?:ads|tracker)\\./",
    "/^(?)ads/",
    "ads.",
    "example.com.",
    // IP literals.
    "||1.2.3.4^",
    "|1.2.3.4^",
    "@@||1.2.3.4^",
    "||1.2.3.4^$important",
    "1.2.3.4",
    "||2001:db8::1^",
    "|2001:db8::1^",
    "2001:db8::1",
    "||192.0.2.10^$dnstype=A",
    // Modifiers.
    "||example.com^$dnstype=A",
    "||example.com^$dnstype=~A",
    "||example.com^$dnstype=A|AAAA",
    "||example.com^$dnstype=HTTPS",
    "||example.com^$dnstype=cname",
    "||example.com^$dnstype=",
    "||example.com^$client=192.168.1.0/24",
    "||example.com^$client=~192.168.1.5",
    "||example.com^$client=kid",
    "||example.com^$client='Frank\\'s laptop'",
    "||example.com^$client=~kid|10.0.0.0/8",
    "||example.com^$client=::1",
    "||example.com^$ctag=device_phone",
    "||example.com^$ctag=~user_admin",
    "||example.com^$ctag=device_tv|device_phone",
    "||example.com^$ctag=Bad",
    "||example.com^$denyallow=ads.example.com",
    "||example.com^$denyallow=example.com",
    "*$denyallow=com|net",
    "*$denyallow=example.com",
    "||*^$dnstype=AAAA",
    "||example.com^$~image",
    "||example.com^$~image,~script",
    "||example.com^$important,dnstype=A",
    "@@||example.com^$client=kid",
    "@@||example.com^$dnstype=AAAA",
    "||1.2.3.4^$denyallow=example.com",
    "/ads/$denyallow=ads.example.com",
    "ex*$dnstype=A",
    // Rewrites.
    "||example.com^$dnsrewrite=1.2.3.4",
    "||example.com^$dnsrewrite=2001:db8::5",
    "||example.com^$dnsrewrite=::ffff:1.2.3.4",
    "||example.com^$dnsrewrite=target.example",
    "||example.com^$dnsrewrite=NXDOMAIN;;",
    "||example.com^$dnsrewrite=REFUSED;;",
    "||example.com^$dnsrewrite=SERVFAIL;;",
    "||example.com^$dnsrewrite=NOERROR;;",
    "||example.com^$dnsrewrite",
    "||example.com^$dnsrewrite=NOERROR;A;1.2.3.4",
    "||example.com^$dnsrewrite=NOERROR;AAAA;::1",
    "||example.com^$dnsrewrite=NOERROR;CNAME;target.example",
    "||example.com^$dnsrewrite=NOERROR;MX;10 mail.example.com",
    "||example.com^$dnsrewrite=NOERROR;TXT;hello world",
    "||example.com^$dnsrewrite=NOERROR;HTTPS;1 . alpn=h2",
    "||example.com^$dnsrewrite=NOERROR;SVCB;1 svc.example.com port=8443",
    "||example.com^$dnsrewrite=NOERROR;PTR;host.example.com.",
    "||example.com^$dnsrewrite=NOERROR;SRV;10 60 5060 sip.example.com",
    "||example.com^$dnsrewrite=NOERROR;NS;ns.example.com",
    "||example.com^$dnsrewrite=NXDOMAIN",
    "||example.com^$dnsrewrite=nxdomain",
    "||example.com^$dnsrewrite=example.com",
    "||example.com^$dnsrewrite=1.2.3.4,important",
    "||example.com^$dnsrewrite=1.2.3.4,dnstype=AAAA",
    "||example.com^$dnsrewrite=1.2.3.4,client=kid",
    "@@||example.com^$dnsrewrite",
    "||example.com^$dnsrewrite=1.2.3.4,badfilter",
    "|1.2.3.4^$dnsrewrite=5.6.7.8",
    "/ads/$dnsrewrite=1.2.3.4",
    "||example.com^$dnsrewrite=NOERROR;A;bogus",
    // $badfilter alone (no target).
    "||example.com^$badfilter",
    // Browser rules: AdGuard's DNS engine never applies them.
    "example.com##.ad",
    "||example.com^$third-party",
    "||example.com/ads/*",
    "||example.com^$image",
    "||example.com^$domain=news.example",
    "@@||example.com^$document",
    "||example.com^$popup",
    "||example.com^$document",
    "/ads/banner.gif",
    "/ads/banner",
    // Protocol/port extension (excluded from the metric where it decides).
    "https://example.com",
    "||example.com:443^",
    "|https://example.com^",
    "wss://tracker.net^",
    "|https://[2001:db8::1]^",
    "||[2001:db8::10]:8443^",
    // Dropped.
    "$image",
    "*$third-party",
    "||example.com^$bogus",
    "a*",
    "||example.com^$replace=/a/b/",
];

/// Pairs: each ordered pair of these, on the example.com family.
pub const PAIR_RULES: &[&str] = &[
    "||example.com^",
    "|example.com^",
    "||example.com^$important",
    "|example.com^$important",
    "@@||example.com^",
    "@@|example.com^",
    "@@||example.com^$important",
    "@@|www.example.com^",
    "example.com",
    "0.0.0.0 www.example.com",
    "192.0.2.10 example.com",
    "192.0.2.11 www.example.com",
    "||example.com^$dnsrewrite=1.2.3.4",
    "||example.com^$dnsrewrite=1.2.3.5",
    "||example.com^$dnsrewrite=target.example",
    "||example.com^$dnsrewrite=NXDOMAIN;;",
    "||example.com^$dnsrewrite=1.2.3.4,important",
    "@@||example.com^$dnsrewrite",
    "@@||example.com^$dnsrewrite=1.2.3.4",
    "@@||example.com^$dnsrewrite,important",
    "||example.com^$badfilter",
    "||example.com^$badfilter,dnstype=AAAA",
    "|example.com^$badfilter",
    "||example.com^$dnstype=A",
    "@@||example.com^$client=kid",
    "||ads*.example.com^",
    "@@||ads*.example.com^",
    "/example/",
    "@@/example/",
    "||www.example.com^",
    "*.example.com^",
];

/// Rule text that rules.md §1 normalises where AdGuard compares as written.
pub const NORMALISATION_RULES: &[&str] = &[
    "Example.com",
    "0.0.0.0 Example.COM",
    "пример.рф",
    "example.com.",
    "||example.com.^",
    "||пример.рф^",
    "||example.com^$denyallow=Ads.Example.com",
    "*$denyallow=Tracker.*",
];

/// Several `$badfilter` rules on one request (Group::MultiBadfilter).
pub const MULTI_BADFILTER_CASES: &[&[&str]] = &[
    &[
        "||example.com^",
        "||example.com^$badfilter",
        "||www.example.com^$badfilter",
    ],
    &["||example.com^", "||example.com^$badfilter", "||com^$badfilter"],
];

/// Rewrites whose answer depends on urlfilter's matched-rule order (rules.md §4, crate::order).
pub const ORDER_CASES: &[&[&str]] = &[
    // An unindexed rule (shortcut "ex") lists after a shortcut-indexed one.
    &[
        "||ex*^$dnsrewrite=NXDOMAIN;;",
        "||example.com^$dnsrewrite=target.example",
    ],
    // Slices list by their place in "http://example.com": "examp" before "ample".
    &[
        "ample.com^$dnsrewrite=NXDOMAIN;;",
        "example.com^$dnsrewrite=cname.example",
    ],
    &[
        "example.com^$dnsrewrite=cname.example",
        "ample.com^$dnsrewrite=NXDOMAIN;;",
    ],
    // A filled slice sends the next rule to its next slice; browser rules take slots too.
    &[
        "||example.com/ads/*",
        "||example.com^$dnsrewrite=REFUSED;;",
        "||www.example.com^$dnsrewrite=target.example",
    ],
    // urlfilter skips the exception after one that removed an earlier rule; the skipped one then
    // merges as a value.
    &[
        "||example.com^$dnsrewrite=1.2.3.4",
        "@@||example.com^$dnsrewrite=1.2.3.4",
        "@@||example.com^$dnsrewrite=1.2.3.5",
        "||example.com^$dnsrewrite=1.2.3.5",
    ],
    &[
        "||ex*^$dnsrewrite=1.2.3.4",
        "@@||example.com^$dnsrewrite=1.2.3.4",
        "||example.com^$dnsrewrite=NXDOMAIN;;",
        "@@||ex*^$dnsrewrite",
    ],
];

/// `$denyallow` entities (`tracker.*`), decided with the public suffix list.
pub const ENTITY_RULES: &[&str] = &[
    "||example.com^$denyallow=example.*",
    "*$denyallow=tracker.*",
    "*$denyallow=tracker.*|example.*,dnstype=A",
    "||co.uk^$denyallow=tracker.*",
    "/tracker/$denyallow=tracker.*",
    "@@||net^$denyallow=tracker.*",
    "||example.com^$badfilter,denyallow=www.*",
];

pub const PAIR_NAMES: &[&str] = &[
    "example.com",
    "www.example.com",
    "ads.example.com",
    "sub.ads.example.com",
    "notexample.com",
    "example.com.evil.net",
    "x.www.example.com",
    "target.example",
    "com",
    "example.net",
];

/// Fixture lists in AdGuard-readable syntax.
pub fn fixture_lists() -> Vec<(&'static str, String)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/rules/");
    [
        "adguard-dns-sample.txt",
        "easylist-sample.txt",
        "hagezi-adblock-sample.txt",
        "hagezi-hosts-sample.txt",
        "protocol-port.txt",
    ]
    .iter()
    .map(|f| (*f, std::fs::read_to_string(format!("{dir}{f}")).unwrap()))
    .collect()
}

/// Builds the corpus deterministically.
pub fn build() -> Vec<Case> {
    let mut ordinary: Vec<Vec<Vec<u8>>> = ORDINARY_NAMES.iter().map(|n| dotted(n)).collect();
    ordinary.extend(unusual_names());
    let mut cases = Vec::new();
    let single_queries = {
        let mut q = name_queries(&ordinary, true);
        q.extend(ip_queries());
        q
    };
    for (i, r) in SINGLE_RULES.iter().enumerate() {
        cases.push(Case {
            id: format!("s{i}"),
            group: Group::Main,
            rules: vec![r.to_string()],
            queries: single_queries.clone(),
        });
    }
    let pair_names: Vec<Vec<Vec<u8>>> = PAIR_NAMES.iter().map(|n| dotted(n)).collect();
    let pair_queries = name_queries(&pair_names, false);
    for (i, a) in PAIR_RULES.iter().enumerate() {
        for (j, b) in PAIR_RULES.iter().enumerate() {
            if i != j {
                cases.push(Case {
                    id: format!("p{i}_{j}"),
                    group: Group::Main,
                    rules: vec![a.to_string(), b.to_string()],
                    queries: pair_queries.clone(),
                });
            }
        }
    }
    // The parity examples of build-and-test.md §5.
    for (k, rules) in [
        vec!["||d.example^", "|d.example^$important", "@@||d.example^"],
        vec!["||d.example^$important", "|d.example^", "@@||d.example^"],
        vec!["192.0.2.10 d.example", "@@||d.example^"],
    ]
    .into_iter()
    .enumerate()
    {
        let names: Vec<Vec<Vec<u8>>> = ["d.example", "sub.d.example"].iter().map(|n| dotted(n)).collect();
        cases.push(Case {
            id: format!("x{k}"),
            group: Group::Main,
            rules: rules.into_iter().map(String::from).collect(),
            queries: name_queries(&names, true),
        });
    }
    for (name, text) in fixture_lists() {
        let mut q = name_queries(&ordinary, false);
        q.extend(ip_queries());
        cases.push(Case {
            id: format!("f-{name}"),
            group: Group::Main,
            rules: text.lines().map(String::from).collect(),
            queries: q,
        });
    }
    let norm_names: Vec<Vec<Vec<u8>>> = [
        "example.com",
        "xn--e1afmkfd.xn--p1ai",
        "ads.example.com",
        "sub.xn--e1afmkfd.xn--p1ai",
        "tracker.de",
    ]
    .iter()
    .map(|n| dotted(n))
    .collect();
    for (i, r) in NORMALISATION_RULES.iter().enumerate() {
        cases.push(Case {
            id: format!("n{i}"),
            group: Group::Normalisation,
            rules: vec![r.to_string()],
            queries: name_queries(&norm_names, false),
        });
    }
    let dev_names: Vec<Vec<Vec<u8>>> = ["example.com", "www.example.com", "a.www.example.com"]
        .iter()
        .map(|n| dotted(n))
        .collect();
    for (i, rules) in MULTI_BADFILTER_CASES.iter().enumerate() {
        cases.push(Case {
            id: format!("b{i}"),
            group: Group::MultiBadfilter,
            rules: rules.iter().map(|r| r.to_string()).collect(),
            queries: name_queries(&dev_names, false),
        });
    }
    for (i, rules) in ORDER_CASES.iter().enumerate() {
        cases.push(Case {
            id: format!("o{i}"),
            group: Group::Main,
            rules: rules.iter().map(|r| r.to_string()).collect(),
            queries: name_queries(&dev_names, true),
        });
    }
    let entity_names: Vec<Vec<Vec<u8>>> = [
        "example.com",
        "example.co.uk",
        "www.example.com",
        "x.www.example.de",
        "tracker.net",
        "tracker.co.uk",
        "a.tracker.co.uk",
        "x.example.de",
        "tracker.blogspot.com",
        "tracker.github.io",
        "tracker.co.ck",
        "tracker.zzz",
        "a.tracker.xtracker.com",
        "tracker.xtracker.com",
        "mytracker.net",
        "notexample.com",
        "co.uk",
        "x.co.uk",
        "1.2.3.4",
    ]
    .iter()
    .map(|n| dotted(n))
    .collect();
    let mut entity_queries = name_queries(&entity_names, false);
    entity_queries.extend(name_queries(&unusual_names(), false));
    for (i, r) in ENTITY_RULES.iter().enumerate() {
        cases.push(Case {
            id: format!("e{i}"),
            group: Group::Main,
            rules: vec![r.to_string(), "||example.com^".to_string()]
                .into_iter()
                .take(if r.contains("badfilter") { 2 } else { 1 })
                .collect(),
            queries: entity_queries.clone(),
        });
    }
    cases.extend(corpus().into_iter().map(|c| c.case));
    cases
}

/// One written expectation of `fixtures/rules/parity-corpus.txt`, for the query of the same index.
#[derive(Clone, Debug)]
pub struct Expect {
    /// The outcome in the corpus syntax (`block`, `exception`, `hostmap=…`, `a=…`, …).
    pub want: String,
    /// The rule text that must decide, if given.
    pub decisive: Option<String>,
    /// The fixture line.
    pub line: usize,
}

/// A corpus group: a case (its rules and queries) and the written expectations.
#[derive(Clone, Debug)]
pub struct CorpusCase {
    pub title: String,
    /// Checks a deviation the spec names (rules.md §1–§3) rather than AdGuard's decision.
    pub picket: bool,
    pub case: Case,
    pub expects: Vec<Expect>,
}

/// Splits `opts` like `qtype=AAAA client="Frank's laptop"` (double quotes group).
fn corpus_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn corpus_query(target: &str, is_ip: bool, opts: &[(String, String)], line: usize) -> Query {
    let mut q = Query {
        target: if is_ip {
            Target::Ip(target.parse().unwrap_or_else(|_| panic!("line {line}: {target}")))
        } else {
            Target::Name(dotted(target))
        },
        qtype: A,
        client_ip: None,
        client_name: None,
        tags: vec![],
    };
    for (k, v) in opts {
        match k.as_str() {
            "qtype" => {
                q.qtype = picket_rules::rrtype::parse_rr_type(v).unwrap_or_else(|| panic!("line {line}: {v}"))
            }
            "ip" => q.client_ip = Some(v.parse().unwrap_or_else(|_| panic!("line {line}: {v}"))),
            "client" => q.client_name = Some(v.clone()),
            "tags" => q.tags = v.split(',').map(String::from).collect(),
            "decisive" => {}
            other => panic!("line {line}: unknown option {other}"),
        }
    }
    q
}

/// The hand-written parity corpus (`fixtures/rules/parity-corpus.txt`): rules × names with the
/// decision urlfilter v0.23 and AdGuard Home's `matchHost` give, one case per group.
pub fn corpus() -> Vec<CorpusCase> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/rules/parity-corpus.txt"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut out: Vec<CorpusCase> = Vec::new();
    let new_case = |title: &str, n: usize| CorpusCase {
        title: title.to_string(),
        picket: title.contains("(picket)"),
        case: Case {
            id: format!("c{n}"),
            group: if title.contains("(picket)") && !title.contains("protocol/port") {
                Group::Normalisation
            } else {
                Group::Main
            },
            rules: vec![],
            queries: vec![],
        },
        expects: vec![],
    };
    for (n, raw) in text.lines().enumerate() {
        let line = n + 1;
        if raw.trim().is_empty() || raw.starts_with('#') {
            continue;
        }
        if let Some(t) = raw.strip_prefix("= ") {
            let c = new_case(t, out.len());
            out.push(c);
            continue;
        }
        if let Some(m) = raw.strip_prefix("m ") {
            let parts: Vec<&str> = m.split(" ~~").collect();
            assert_eq!(parts.len(), 3, "line {line}: {raw}");
            let rule = parts[0].trim();
            let hit = if rule.starts_with("@@") {
                "exception"
            } else {
                "block"
            };
            let mut c = new_case(&format!("matrix {rule}"), out.len());
            c.case.rules.push(rule.to_string());
            for (names, want) in [(parts[1], hit), (parts[2], "none")] {
                for t in names.split_whitespace() {
                    let is_ip = t.parse::<IpAddr>().is_ok();
                    c.case.queries.push(corpus_query(t, is_ip, &[], line));
                    c.expects.push(Expect {
                        want: want.to_string(),
                        decisive: None,
                        line,
                    });
                }
            }
            out.push(c);
            continue;
        }
        let c = out.last_mut().unwrap_or_else(|| panic!("line {line}: no group"));
        if let Some(r) = raw.strip_prefix("r ") {
            c.case.rules.push(r.to_string());
            continue;
        }
        let (is_ip, rest) = match (raw.strip_prefix("e "), raw.strip_prefix("i ")) {
            (Some(r), _) => (false, r),
            (_, Some(r)) => (true, r),
            _ => panic!("line {line}: unknown line {raw:?}"),
        };
        let toks = corpus_tokens(rest);
        let opts: Vec<(String, String)> = toks
            .get(2..)
            .unwrap_or(&[])
            .iter()
            .map(|t| {
                let (k, v) = t
                    .split_once('=')
                    .unwrap_or_else(|| panic!("line {line}: bad option {t}"));
                (k.to_string(), v.to_string())
            })
            .collect();
        c.case.queries.push(corpus_query(&toks[0], is_ip, &opts, line));
        c.expects.push(Expect {
            want: toks[1].clone(),
            decisive: opts.iter().find(|(k, _)| k == "decisive").map(|(_, v)| v.clone()),
            line,
        });
    }
    out
}

/// True when a decision (in the oracle's syntax, [`decision`]) meets a corpus outcome for a query
/// of type `qtype`. `a=`/`aaaa=`/`nodata` look at the records of the query's type only.
pub fn meets(decision: &str, want: &str, qtype: u16) -> bool {
    let (kind, value) = want.split_once('=').unwrap_or((want, ""));
    let ips = |v: &str| -> Vec<String> {
        let mut out: Vec<String> = v
            .split(',')
            .map(|s| netip_string(s.parse::<IpAddr>().unwrap()))
            .collect();
        out.sort();
        out.dedup();
        out
    };
    let records = |d: &str| -> Option<Vec<String>> {
        let rest = d.strip_prefix("rewrite records")?.trim();
        let mut out: Vec<String> = rest
            .split('|')
            .filter(|r| !r.is_empty())
            .filter_map(|r| r.split_once('='))
            .filter(|(t, _)| t.parse::<u16>().ok() == Some(qtype))
            .map(|(_, v)| v.to_string())
            .collect();
        out.sort();
        out.dedup();
        Some(out)
    };
    match kind {
        "block" => decision == "block",
        "exception" => decision == "allow",
        "none" => decision == "none",
        "hostmap" if value.is_empty() => decision.starts_with("hosts "),
        "hostmap" => decision == format!("hosts {}", ips(value).join(",")),
        "a" | "aaaa" => records(decision).is_some_and(|r| r == ips(value)),
        "nodata" => records(decision).is_some_and(|r| r.is_empty()),
        "cname" => decision == format!("rewrite cname {value}"),
        "rcode" => {
            let code = picket_rules::rrtype::parse_rcode(value).unwrap_or_else(|| panic!("rcode {value}"));
            decision == format!("rewrite rcode {code}")
        }
        other => panic!("unknown corpus outcome {other}"),
    }
}

/// Parses rule lines as an `adblock` feed, keeping each rule's line text.
pub fn parse_rules_raw(lines: &[String]) -> Vec<(Rule, String)> {
    let text = lines.join("\n");
    let cfg = ParseConfig::new(Format::Adblock, DomainsAs::Exact, Timestamp::now());
    let mut rules = Vec::new();
    parse_lines(text.as_bytes(), &cfg, |e| rules.push((e.rule, e.raw))).unwrap();
    rules
}

fn escape_field(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.:'".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The oracle's input for the corpus.
pub fn oracle_input(cases: &[Case]) -> String {
    let mut s = String::new();
    for c in cases {
        let _ = writeln!(s, "case {}", c.id);
        for r in &c.rules {
            let _ = writeln!(s, "rule {r}");
        }
        for q in &c.queries {
            let ip = q.client_ip.map_or("-".to_string(), go_ip_string);
            let name = q.client_name.as_deref().map_or("-".to_string(), escape_field);
            let tags = if q.tags.is_empty() {
                "-".to_string()
            } else {
                q.tags.join(",")
            };
            let _ = writeln!(s, "query {} {} {} {} {}", q.qtype, ip, name, tags, q.host_text());
        }
        let _ = writeln!(s, "end");
    }
    s
}

/// The bundled public suffix list (core's `apps/picket-core/data/public_suffix_list.dat`).
pub fn psl() -> &'static picket_rules::psl::PublicSuffixList {
    static PSL: std::sync::OnceLock<picket_rules::psl::PublicSuffixList> = std::sync::OnceLock::new();
    PSL.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/picket-core/data/public_suffix_list.dat"
        );
        picket_rules::psl::PublicSuffixList::parse(&std::fs::read_to_string(path).expect("bundled PSL"))
    })
}

/// A block-bundle matcher over `rules`, with the public suffix list (as core builds it).
pub fn block_matcher(rules: Vec<Rule>) -> BundleMatcher {
    BundleMatcher::new(picket_rules::matcher::BundleAction::Block, rules).with_public_suffix_list(psl())
}

/// Parses a case's rules as an `adblock` feed (every `rule_policy` option at `keep`).
pub fn parse_rules(lines: &[String]) -> Vec<Rule> {
    let text = lines.join("\n");
    let cfg = ParseConfig::new(Format::Adblock, DomainsAs::Exact, Timestamp::now());
    let mut rules = Vec::new();
    parse_lines(text.as_bytes(), &cfg, |e| rules.push(e.rule)).unwrap();
    rules
}

/// Evaluates a query with the reference matcher.
pub fn evaluate(m: &BundleMatcher, q: &Query) -> MatchResult {
    let names: Vec<&str> = q.client_name.iter().map(String::as_str).collect();
    let tags: Vec<&str> = q.tags.iter().map(String::as_str).collect();
    let ctx = QueryCtx {
        qtype: q.qtype,
        client_ip: q.client_ip,
        client_names: &names,
        client_tags: &tags,
    };
    match &q.target {
        Target::Name(l) => {
            let labels: Vec<&[u8]> = l.iter().map(Vec::as_slice).collect();
            m.match_name(&labels, &ctx)
        }
        Target::Ip(ip) => m.match_ip(*ip, &ctx),
    }
}

/// Picket's outcome in the oracle's decision syntax.
pub fn decision(o: &Outcome) -> String {
    match o {
        Outcome::None | Outcome::Allow | Outcome::InScope => "none".into(),
        Outcome::Exception => "allow".into(),
        Outcome::Block => "block".into(),
        Outcome::HostMapping(ips) => {
            let mut v: Vec<String> = ips.iter().map(|ip| netip_string(*ip)).collect();
            v.sort();
            format!("hosts {}", v.join(","))
        }
        Outcome::Rewrite(RewriteAnswer::Cname(c)) => format!("rewrite cname {c}"),
        Outcome::Rewrite(RewriteAnswer::Rcode(r)) => format!("rewrite rcode {r}"),
        Outcome::Rewrite(RewriteAnswer::Records(recs)) => {
            let mut v: Vec<String> = recs
                .iter()
                .map(|(t, val)| format!("{t}={}", val.to_text()))
                .collect();
            v.sort();
            v.dedup();
            format!("rewrite records {}", v.join("|")).trim().to_string()
        }
    }
}

/// The oracle's decision with hosts lines folded as Picket reads them: any block address
/// (`0.0.0.0`, `127.0.0.1`, `::`) among the matched hosts lines makes it a block (feeds.md §4).
pub fn normalise_oracle(d: &str) -> String {
    if let Some(ips) = d.strip_prefix("hosts ")
        && ips
            .split(',')
            .any(|ip| matches!(ip, "0.0.0.0" | "127.0.0.1" | "::"))
    {
        return "block".into();
    }
    d.to_string()
}

/// Runs the oracle binary on the corpus.
pub fn run_oracle(bin: &str, cases: &[Case]) -> Vec<Vec<String>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let input = oracle_input(cases);
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("run the oracle");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let out = child.wait_with_output().expect("oracle output");
    writer.join().unwrap().unwrap();
    assert!(out.status.success(), "oracle failed");
    let text = String::from_utf8(out.stdout).unwrap();
    let mut index = std::collections::HashMap::new();
    for (i, c) in cases.iter().enumerate() {
        index.insert(c.id.clone(), i);
    }
    let mut res: Vec<Vec<String>> = cases
        .iter()
        .map(|c| vec![String::new(); c.queries.len()])
        .collect();
    for line in text.lines() {
        let mut f = line.splitn(3, '\t');
        let (Some(id), Some(q), Some(d)) = (f.next(), f.next(), f.next()) else {
            panic!("bad oracle line {line}")
        };
        let ci = index[id];
        let qi: usize = q.parse().unwrap();
        res[ci][qi] = d.to_string();
    }
    res
}

/// A rule folded into a key, read as AdGuard reads it: its pattern over the text form (rules.md
/// §3), for the unusual-bytes exclusion. Host rules and hosts lines match exact text in AdGuard,
/// which whole labels already equal.
pub fn keyed_as_pattern(r: &Rule) -> Rule {
    use picket_rules::Kind;
    let keyed = matches!(r.key_kind(), Kind::Name | Kind::IpLiteral);
    let Some(pattern) = r.spec.pattern.clone().filter(|_| keyed && !r.spec.extension) else {
        return r.clone();
    };
    let mut out = r.clone();
    out.key = pattern;
    out.spec.pattern = None;
    if out.kind == Kind::Badfilter {
        out.spec.target = Some(Kind::Pattern);
        out.spec.pattern = Some(out.key.clone());
    } else {
        out.kind = Kind::Pattern;
    }
    out.flags = picket_rules::Flags(r.flags.exact().union(r.flags.subs_as_exact()).bits());
    out
}

/// How a disagreement is explained (urlfilter_parity.rs, top_lists.rs): by rules.md §3's
/// exceptions, by the R10 owner decision, or not at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Explained {
    Extension,
    UnusualBytes,
    PathNames,
    No,
}

/// The case's rules read the ways the exclusions need, built on demand.
pub struct Alternatives {
    has_extension: bool,
    without_extension: BundleMatcher,
    keyed_as_text: BundleMatcher,
    paths_as_patterns: BundleMatcher,
}

impl Alternatives {
    pub fn new(rule_lines: &[String]) -> Alternatives {
        let rules = parse_rules(rule_lines);
        let has_extension = rules.iter().any(|r| r.spec.extension);
        let without_extension = block_matcher(rules.iter().filter(|r| !r.spec.extension).cloned().collect());
        let keyed_as_text = block_matcher(rules.iter().map(keyed_as_pattern).collect());
        let mut with_paths = rules;
        with_paths.extend(
            rule_lines
                .iter()
                .filter_map(|l| picket_rules::classify::path_rule_as_pattern(l.trim())),
        );
        Alternatives {
            has_extension,
            without_extension,
            keyed_as_text,
            paths_as_patterns: block_matcher(with_paths),
        }
    }

    /// Why Picket's decision on `q` isn't AdGuard's `theirs`.
    pub fn explain(&self, q: &Query, theirs: &str) -> Explained {
        let agrees = |m: &BundleMatcher| decision(&evaluate(m, q).outcome) == theirs;
        if self.has_extension && agrees(&self.without_extension) {
            Explained::Extension
        } else if q.unusual() && agrees(&self.keyed_as_text) {
            Explained::UnusualBytes
        } else if q.host_text().contains('/') && agrees(&self.paths_as_patterns) {
            Explained::PathNames
        } else {
            Explained::No
        }
    }
}
