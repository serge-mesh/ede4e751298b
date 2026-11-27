//! Fixture suites (build-and-test.md §5): Rule types, Formats, Feed modes (parse side), Rule
//! policy, Warn bundles (matching) and Browser lists (helpers), over the samples in
//! `fixtures/rules/`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "integration test code: a failed unwrap or expect is the test's report, and it may cast freely"
)]

use std::collections::BTreeMap;
use std::fs;
use std::io::BufReader;

use jiff::{Timestamp, civil, tz::Offset};
use picket_rules::browser::{AllowConversion, allow_conversion, parse_browser, redirect_rule_to_redirect};
use picket_rules::formats::{DomainsAs, Format, ParseConfig, ParseStats, parse_feed};
use picket_rules::ip::IpRange;
use picket_rules::matcher::{BundleAction, BundleMatcher, Outcome};
use picket_rules::policy::{Choice, PolicyOption, RulePolicy};
use picket_rules::{Entry, Flags, Kind, QueryCtx, Rule, RuleName, RuleType};

/// The instant at a UTC date and time.
fn utc(y: i16, mo: i8, d: i8, h: i8, mi: i8, s: i8) -> Timestamp {
    Offset::UTC
        .to_timestamp(civil::datetime(y, mo, d, h, mi, s, 0))
        .unwrap()
}

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/rules/");

fn parse(file: &str, format: Format, domains_as: DomainsAs) -> (Vec<Entry>, ParseStats) {
    let path = format!("{DIR}{file}");
    let cfg = ParseConfig::new(format, domains_as, utc(2026, 11, 21, 0, 0, 0));
    let mut out = Vec::new();
    let stats = parse_feed(
        || fs::File::open(&path).map(BufReader::new),
        &cfg,
        |e| out.push(e),
    )
    .unwrap();
    (out, stats)
}

fn find<'a>(entries: &'a [Entry], raw: &str) -> &'a Entry {
    entries
        .iter()
        .find(|e| e.raw == raw)
        .unwrap_or_else(|| panic!("no entry for {raw}"))
}

const A: QueryCtx<'static> = QueryCtx {
    qtype: 1,
    client_ip: None,
    client_names: &[],
    client_tags: &[],
};

#[test]
fn rule_types_easylist() {
    let (e, s) = parse("easylist-sample.txt", Format::Adblock, DomainsAs::Exact);
    let ty = |raw: &str| {
        let x = find(&e, raw);
        (x.rule.rule_type, x.rule.kind)
    };
    // dns: wildcard patterns with no path, as AdGuard Home applies EasyList.
    assert_eq!(ty("-ad-banner."), (RuleType::Dns, Kind::Pattern));
    assert_eq!(ty("-728x90-"), (RuleType::Dns, Kind::Pattern));
    assert_eq!(ty("/banner."), (RuleType::Dns, Kind::Pattern));
    assert_eq!(ty("&ad_type="), (RuleType::Dns, Kind::Pattern));
    assert_eq!(ty("||adserver.example^"), (RuleType::Dns, Kind::Name));
    // browser: paths, page-level modifiers, cosmetic, exceptions with modifiers.
    assert_eq!(ty(".com/ads/$image,script"), (RuleType::Browser, Kind::Network));
    assert_eq!(ty("/ads/banner/*"), (RuleType::Browser, Kind::Network));
    assert_eq!(
        ty("||ads.example-cdn.com^$third-party"),
        (RuleType::Browser, Kind::Network)
    );
    assert_eq!(
        ty("||doubleclick.example^$popup"),
        (RuleType::Browser, Kind::Network)
    );
    assert_eq!(
        ty("||tracker.example^$script,domain=news.example|~blog.news.example"),
        (RuleType::Browser, Kind::Network)
    );
    assert_eq!(
        ty("@@||pagead.example/allowed.js$script"),
        (RuleType::Browser, Kind::Network)
    );
    assert_eq!(
        ty("@@||cdn.example^$generichide"),
        (RuleType::Browser, Kind::Network)
    );
    assert_eq!(ty("##.ad-banner"), (RuleType::Browser, Kind::Cosmetic));
    assert_eq!(ty("example.*##.promo"), (RuleType::Browser, Kind::Cosmetic));
    assert_eq!(
        ty("news.example#@#.ad-banner"),
        (RuleType::Browser, Kind::Cosmetic)
    );
    assert_eq!(
        ty("news.example#?#div:has(> .label:has-text(Sponsored))"),
        (RuleType::Browser, Kind::Procedural)
    );
    assert_eq!(
        ty("news.example##+js(set-constant, ads.enabled, false)"),
        (RuleType::Browser, Kind::Scriptlet)
    );
    assert_eq!(
        ty("news.example##^script:has-text(adblock)"),
        (RuleType::Browser, Kind::HtmlFilter)
    );
    assert_eq!(
        ty("news.example#$#body { overflow: auto !important; }"),
        (RuleType::Browser, Kind::CssInject)
    );
    assert_eq!(
        ty("||video.example^$redirect=noopmp4-1s"),
        (RuleType::Browser, Kind::Network)
    );
    // `|https://…/*` is the protocol extension: AdGuard never matches it, Picket blocks the host.
    let x = find(&e, "|https://pagead.example/*");
    assert_eq!(
        (x.rule.rule_type, x.rule.kind, x.rule.spec.extension),
        (RuleType::Dns, Kind::Name, true)
    );
    // Inside `!#if`, the dns rule stays and the browser rule is dropped.
    assert_eq!(ty("||mobile-ads.example^"), (RuleType::Dns, Kind::Name));
    assert!(!e.iter().any(|x| x.raw == "mobile.example##.app-banner"));
    // Dropped and counted: `#%#`, `$$`, `$replace`, the `!#if` browser rule, an unknown modifier.
    assert!(!e.iter().any(|x| x.raw.contains("#%#")
        || x.raw.contains("$$")
        || x.raw.contains("replace=")
        || x.raw.contains("bogus")));
    assert_eq!(s.warnings.browser, 4);
    assert_eq!(s.warnings.unknown, 1);
    assert_eq!(s.errors, 0);
    assert!(s.skipped >= 8, "{s:?}");
    // feeds.md §5: the list's `! Expires:` header, for cron schedules.
    assert_eq!(s.expires_secs, Some(4 * 86_400));
}

#[test]
fn stored_rules_round_trip() {
    // storage.md §3: every fixture entry reads back from its `feed_entries` identity columns, and
    // IP rules store an ordered range.
    for (file, format) in [
        ("easylist-sample.txt", Format::Adblock),
        ("adguard-dns-sample.txt", Format::Adblock),
        ("hagezi-adblock-sample.txt", Format::Adblock),
        ("hagezi-hosts-sample.txt", Format::Hosts),
        ("firehol-level1-sample.netset", Format::Plain),
        ("protocol-port.txt", Format::Adblock),
        ("plain-mixed.txt", Format::Plain),
        ("misp-list.json", Format::MispWarninglist),
        ("misp-cidr.json", Format::MispWarninglist),
    ] {
        let (e, _) = parse(file, format, DomainsAs::Exact);
        assert!(!e.is_empty(), "{file}");
        for x in &e {
            let r = &x.rule;
            let back = Rule::from_stored(
                r.rule_type.as_str(),
                r.kind.as_str(),
                &r.key,
                r.flags.bits(),
                &r.value_json(),
            )
            .unwrap_or_else(|err| panic!("{file}: {}: {err}", x.raw));
            assert_eq!(&back, r, "{file}: {}", x.raw);
            if let Some(range) = r.ip_range() {
                assert!(range.first_bytes() <= range.last_bytes(), "{file}: {}", x.raw);
            }
        }
    }
}

#[test]
fn rule_types_adguard_dns_filter() {
    let (e, s) = parse("adguard-dns-sample.txt", Format::Adblock, DomainsAs::Exact);
    assert_eq!(s.errors, 0);
    assert_eq!(s.entries.browser, 0);
    let r = |raw: &str| find(&e, raw).rule.clone();
    assert_eq!(r("||adsrvr.example^").flags, Flags::B_EXACT | Flags::B_SUBS);
    assert_eq!(
        r("||telemetry.example.com^$important").flags,
        Flags::B_EXACT | Flags::B_SUBS | Flags::IMP_B_EXACT | Flags::IMP_B_SUBS
    );
    assert_eq!(
        r("@@||allowed.adsrvr.example^").flags,
        Flags::A_EXACT | Flags::A_SUBS
    );
    assert_eq!(r("@@||cdn.metrics.example.net^|").kind, Kind::Pattern);
    assert_eq!(r("|exact.example.org^").flags, Flags::B_EXACT);
    assert_eq!(r("://scheme.example^").flags, Flags::B_EXACT);
    assert_eq!(r("*.wild.example^").flags, Flags::B_SUBS);
    assert_eq!(r(".dot.example^").flags, Flags::B_SUBS);
    assert_eq!(r("||ad-*.example.net^").kind, Kind::Pattern);
    assert_eq!(r("/^ad[0-9]+\\.example\\.org$/").kind, Kind::Regex);
    assert!(r("||pixel.example^$dnstype=A|AAAA").spec.dnstype.is_some());
    assert!(
        r("||kids-block.example^$client=192.168.1.0/24")
            .spec
            .client
            .is_some()
    );
    assert!(r("||guest-only.example^$ctag=device_tv").spec.ctag.is_some());
    assert_eq!(
        r("||everything-but.example^$denyallow=good.everything-but.example")
            .spec
            .denyallow
            .len(),
        1
    );
    assert!(
        r("||rewritten.example^$dnsrewrite=192.0.2.55")
            .spec
            .dnsrewrite
            .is_some()
    );
    assert_eq!(r("||adsrvr.example^$badfilter").kind, Kind::Badfilter);
    assert_eq!(
        (r("||1.2.3.4^").rule_type, r("||1.2.3.4^").kind),
        (RuleType::Ip, Kind::IpLiteral)
    );
    assert_eq!(
        (r("|5.6.7.8^").rule_type, r("|5.6.7.8^").kind),
        (RuleType::Ip, Kind::IpLiteral)
    );
    assert_eq!(
        (r("||2001:db8::bad^").rule_type, r("||2001:db8::bad^").kind),
        (RuleType::Ip, Kind::Pattern)
    );
    assert_eq!(r("example-host.example").kind, Kind::Name);
    assert_eq!(r("0.0.0.0 hosts-in-adblock.example").kind, Kind::Name);
    // The list decides as AdGuard Home would.
    let rules: Vec<_> = e.iter().map(|x| x.rule.clone()).collect();
    let m = BundleMatcher::new(BundleAction::Block, rules);
    assert_eq!(
        m.match_dotted("adsrvr.example", &A).outcome,
        Outcome::None,
        "$badfilter removed ||adsrvr.example^"
    );
    assert_eq!(
        m.match_dotted("allowed.adsrvr.example", &A).outcome,
        Outcome::Exception
    );
    assert_eq!(
        m.match_dotted("x.metrics.example.net", &A).outcome,
        Outcome::Block
    );
    assert_eq!(
        m.match_dotted("cdn.metrics.example.net", &A).outcome,
        Outcome::Exception
    );
    assert_eq!(m.match_dotted("ad5.example.org", &A).outcome, Outcome::Block);
    assert_eq!(
        m.match_dotted("x.everything-but.example", &A).outcome,
        Outcome::Block
    );
    assert_eq!(
        m.match_dotted("good.everything-but.example", &A).outcome,
        Outcome::None
    );
    assert!(matches!(
        m.match_dotted("cname.example", &A).outcome,
        Outcome::Rewrite(_)
    ));
    assert_eq!(m.match_ip("5.6.7.8".parse().unwrap(), &A).outcome, Outcome::Block);
}

#[test]
fn rule_types_hagezi() {
    let (e, s) = parse("hagezi-adblock-sample.txt", Format::Adblock, DomainsAs::Exact);
    assert_eq!(s.errors, 0);
    assert_eq!(e.len(), 12);
    assert!(
        e.iter()
            .all(|x| x.rule.rule_type == RuleType::Dns && x.rule.kind == Kind::Name)
    );
    assert_eq!(find(&e, "||Upper-Case.Example^").rule.key, "example.upper-case");
    let d = |y, m, dd| utc(y, m, dd, 0, 0, 0);
    assert_eq!(find(&e, "||malware-c2.example^").first_seen, Some(d(2021, 6, 1)));
    assert_eq!(
        find(&e, "||cryptojack.example^").first_seen,
        Some(utc(2023, 2, 14, 9, 30, 0))
    );
    assert_eq!(find(&e, "||new-threat.example^").first_seen, None);
    let (h, hs) = parse("hagezi-hosts-sample.txt", Format::Hosts, DomainsAs::Exact);
    assert_eq!(hs.errors, 0);
    let keys: Vec<(&str, Kind)> = h.iter().map(|x| (x.rule.key.as_str(), x.rule.kind)).collect();
    assert!(
        keys.contains(&("example.multi-a", Kind::Name)) && keys.contains(&("example.multi-b", Kind::Name))
    );
    assert!(keys.contains(&("example.loopback-block", Kind::Name)));
    assert!(keys.contains(&("example.v6-block", Kind::Name)));
    assert!(keys.contains(&("example.mapped", Kind::HostMapping)));
    assert_eq!(
        h.iter()
            .find(|x| x.rule.key == "example.malware-c2")
            .unwrap()
            .first_seen,
        Some(d(2022, 3, 1))
    );
    assert_eq!(
        h.iter()
            .find(|x| x.rule.key == "example.new-threat")
            .unwrap()
            .first_seen,
        None
    );
}

#[test]
fn rule_types_firehol_and_compile_alerts() {
    let (e, s) = parse("firehol-level1-sample.netset", Format::Plain, DomainsAs::Exact);
    assert_eq!(s.errors, 0);
    assert_eq!(s.entries.ip, 18);
    assert!(
        e.iter()
            .all(|x| x.rule.rule_type == RuleType::Ip && x.rule.kind == Kind::IpRange)
    );
    let r = &find(&e, "45.12.32.0/21").rule;
    let range = r.ip_range().unwrap();
    assert_eq!(range.first_bytes()[12..], [45, 12, 32, 0]);
    assert_eq!(range.last_bytes()[12..], [45, 12, 39, 255]);
    // A recorded FireHOL level 1 file raises no broad_block (bundles.md §2).
    assert!(!e.iter().any(|x| picket_rules::compile::is_broad(&x.rule)));
}

#[test]
fn protocol_port_forms() {
    let (e, _) = parse("protocol-port.txt", Format::Adblock, DomainsAs::Exact);
    let ext = |raw: &str| {
        let x = find(&e, raw);
        (x.rule.kind, x.rule.flags, x.rule.spec.extension)
    };
    let exact = (Kind::Name, Flags::B_EXACT, true);
    let subs = (Kind::Name, Flags::B_EXACT | Flags::B_SUBS, true);
    assert_eq!(ext("https://scheme-bare.example"), exact);
    assert_eq!(ext("|https://scheme-anchored.example^"), exact);
    assert_eq!(ext("https://scheme-star.example/*"), exact);
    assert_eq!(ext("wss://scheme-ws.example^"), exact);
    assert_eq!(ext("https://scheme-slash.example/"), exact);
    assert_eq!(ext("||port.example:8443^"), subs);
    assert_eq!(ext("||port-bare.example:8443"), subs);
    assert_eq!(ext("http://http-port.example:8080^"), exact);
    assert_eq!(ext("|ftp://scheme-ftp.example^"), exact);
    assert_eq!(ext("|https://scheme-tlsport.example:8443^"), exact);
    assert_eq!(ext("ws://scheme-plainws.example^"), exact);
    let v6 = &find(&e, "|https://[2001:db8::7]^").rule;
    assert_eq!(
        (v6.rule_type, v6.kind, v6.key.as_str(), v6.spec.extension),
        (RuleType::Ip, Kind::IpRange, "2001:db8::7", true)
    );
    assert_eq!(find(&e, "http://http-only.example^").rule.kind, Kind::Pattern);
    for raw in [
        "https://scheme-path.example/ads",
        "@@https://exception-scheme.example^",
        "@@||exception-port.example:443^",
    ] {
        assert_eq!(find(&e, raw).rule.rule_type, RuleType::Browser, "{raw}");
    }
    let rules: Vec<_> = e.iter().map(|x| x.rule.clone()).collect();
    let m = BundleMatcher::new(BundleAction::Block, rules);
    assert_eq!(m.match_dotted("scheme-bare.example", &A).outcome, Outcome::Block);
    assert_eq!(m.match_dotted("x.scheme-bare.example", &A).outcome, Outcome::None);
    assert_eq!(m.match_dotted("x.port.example", &A).outcome, Outcome::Block);
    assert_eq!(
        m.match_ip("2001:db8::7".parse().unwrap(), &A).outcome,
        Outcome::Block
    );
}

#[test]
fn formats_plain_and_misp() {
    let (e, s) = parse("plain-mixed.txt", Format::Plain, DomainsAs::Exact);
    let got: Vec<(&str, Flags, RuleType)> = e
        .iter()
        .map(|x| (x.rule.key.as_str(), x.rule.flags, x.rule.rule_type))
        .collect();
    assert_eq!(
        got,
        vec![
            ("example.plain-name", Flags::B_EXACT, RuleType::Dns),
            ("example.plain-wild", Flags::B_SUBS, RuleType::Dns),
            ("203.0.113.7", Flags::B_EXACT, RuleType::Ip),
            ("198.51.100.0/24", Flags::B_EXACT, RuleType::Ip),
            ("2001:db8:dead::/48", Flags::B_EXACT, RuleType::Ip),
            ("example.plain-other", Flags::B_EXACT, RuleType::Dns),
            ("example.plain-dot", Flags::B_SUBS, RuleType::Dns),
            ("net.example.plain-upper", Flags::B_EXACT, RuleType::Dns),
            ("example.xn--bcher-kva", Flags::B_EXACT, RuleType::Dns),
            ("2001:db8::1", Flags::B_EXACT, RuleType::Ip),
            ("10.0.0.0/8", Flags::B_EXACT, RuleType::Ip),
            ("example.plain-semi", Flags::B_EXACT, RuleType::Dns),
        ]
    );
    // "not a valid line" and a URL.
    assert_eq!(s.errors, 2);
    assert!(e.iter().all(|x| x.first_seen == Some(utc(2024, 1, 1, 0, 0, 0))));
    let (e, _) = parse("plain-mixed.txt", Format::Plain, DomainsAs::Subdomains);
    assert_eq!(e[0].rule.flags, Flags::B_EXACT | Flags::B_SUBS);
    assert_eq!(
        e[1].rule.flags,
        Flags::B_SUBS,
        "an explicit *. stays subdomains-only"
    );
    let (m, ms) = parse("misp-list.json", Format::MispWarninglist, DomainsAs::Exact);
    assert_eq!(
        m.iter().map(|x| x.rule.key.as_str()).collect::<Vec<_>>(),
        vec!["google.dns", "one.one.one.one", "net.quad9", "io.nextdns"]
    );
    assert!(m.iter().all(|x| x.rule.flags == Flags::B_EXACT | Flags::B_SUBS));
    assert_eq!(ms.errors, 1);
    let (c, cs) = parse("misp-cidr.json", Format::MispWarninglist, DomainsAs::Exact);
    assert_eq!(c.len(), 3);
    assert!(c.iter().all(|x| x.rule.rule_type == RuleType::Ip));
    assert_eq!(cs.errors, 1);
}

#[test]
fn feed_modes_parse_side_counts_per_type() {
    // A mode applies per rule type; the parser counts each type, including dropped ones.
    let (e, s) = parse("adguard-dns-sample.txt", Format::Adblock, DomainsAs::Exact);
    let mut by_type: BTreeMap<RuleType, u64> = BTreeMap::new();
    for x in &e {
        *by_type.entry(x.rule.rule_type).or_default() += 1;
    }
    assert_eq!(by_type.get(&RuleType::Dns).copied().unwrap_or(0), s.entries.dns);
    assert_eq!(by_type.get(&RuleType::Ip).copied().unwrap_or(0), s.entries.ip);
    assert_eq!(s.entries.ip, 3);
    let (_, s) = parse("easylist-sample.txt", Format::Adblock, DomainsAs::Exact);
    assert!(s.entries.browser > 15 && s.entries.dns > 3, "{s:?}");
    assert_eq!(s.error_ratio(), 0.0);
}

#[test]
fn rule_policy_each_option() {
    let (e, _) = parse("adguard-dns-sample.txt", Format::Adblock, DomainsAs::Exact);
    let (b, _) = parse("easylist-sample.txt", Format::Adblock, DomainsAs::Exact);
    let (h, _) = parse("hagezi-hosts-sample.txt", Format::Hosts, DomainsAs::Exact);
    let all: Vec<_> = e.iter().chain(&b).chain(&h).map(|x| x.rule.clone()).collect();
    let count = |p: RulePolicy, o: PolicyOption| all.iter().filter(|r| p.dropping(r).contains(&o)).count();
    let drop_all = RulePolicy {
        redirects: Choice::Drop,
        client_rules: Choice::Drop,
        browser_changes: Choice::Drop,
    };
    // redirects: the values rewrite, the CNAME rewrite and the hosts mapping; not NXDOMAIN;;.
    assert_eq!(count(drop_all, PolicyOption::Redirects), 3);
    assert_eq!(count(drop_all, PolicyOption::ClientRules), 2);
    assert!(count(drop_all, PolicyOption::BrowserChanges) >= 8);
    assert_eq!(count(RulePolicy::KEEP_ALL, PolicyOption::Redirects), 0);
    let kept = all.iter().filter(|r| RulePolicy::DOWNLOADED.keeps(r)).count();
    assert_eq!(
        kept,
        all.len() - 5,
        "downloaded default drops redirects and client rules only"
    );
}

#[test]
fn warn_bundle_matching() {
    // A warn bundle matches a key as a query for the key's name, and an IP rule by overlap.
    let (m, _) = parse("misp-list.json", Format::MispWarninglist, DomainsAs::Exact);
    let (c, _) = parse("misp-cidr.json", Format::MispWarninglist, DomainsAs::Exact);
    let rules: Vec<_> = m.iter().chain(&c).map(|x| x.rule.clone()).collect();
    let warn = BundleMatcher::new(BundleAction::Allow, rules);
    let key = |n: &str| warn.match_key(&RuleName::parse(n).unwrap(), &A).outcome;
    assert_eq!(key("dns.google"), Outcome::Allow);
    assert_eq!(key("x.dns.quad9.net"), Outcome::Allow);
    assert_eq!(key("google"), Outcome::None);
    assert_eq!(
        warn.overlapping_ip_rules(&IpRange::parse("8.8.0.0/16").unwrap())
            .len(),
        2
    );
    assert!(
        warn.overlapping_ip_rules(&IpRange::parse("9.9.9.9").unwrap())
            .is_empty()
    );
    // "As it would a query for the key's name": any type, any client (bundles.md §3).
    let (d, _) = parse("adguard-dns-sample.txt", Format::Adblock, DomainsAs::Exact);
    let allow = BundleMatcher::new(BundleAction::Allow, d.iter().map(|x| x.rule.clone()).collect());
    let any = |n: &str| allow.match_key_any(&RuleName::parse(n).unwrap()).outcome;
    assert_eq!(any("kids-block.example"), Outcome::Allow, "$client rule");
    assert_eq!(any("guest-only.example"), Outcome::Allow, "$ctag rule");
    assert_eq!(
        allow
            .match_key(&RuleName::parse("kids-block.example").unwrap(), &A)
            .outcome,
        Outcome::None
    );
}

#[test]
fn browser_allow_conversion_rows() {
    let text = fs::read_to_string(format!("{DIR}browser-allow-conversion.tsv")).unwrap();
    let mut n = 0;
    for line in text.lines().filter(|l| !l.starts_with("//") && !l.is_empty()) {
        let (input, want) = line.split_once('\t').unwrap();
        let got = allow_conversion(&parse_browser(input));
        let got = match got {
            AllowConversion::Written(s) | AllowConversion::Unchanged(s) => s,
            AllowConversion::Dropped => "DROPPED".to_string(),
        };
        assert_eq!(got, want, "{input}");
        n += 1;
    }
    assert_eq!(n, 13);
    // DNS-blocked names: `$redirect-rule` rewritten as `$redirect`; `$popup` never pruned.
    let picket_rules::browser::BrowserRule::Network(r) =
        parse_browser("||video.example^$redirect-rule=noopjs")
    else {
        panic!()
    };
    assert_eq!(
        redirect_rule_to_redirect(&r).unwrap(),
        "||video.example^$redirect=noopjs"
    );
    assert_eq!(r.host_anchor().as_deref(), Some("video.example"));
    let picket_rules::browser::BrowserRule::Network(p) = parse_browser("||doubleclick.example^$popup") else {
        panic!()
    };
    assert!(p.is_popup_or_all());
}
