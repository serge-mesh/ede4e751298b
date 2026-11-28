//! The compiled matcher on arbitrary names (client input) decides as picket-rules' reference
//! matcher: labels with any bytes, `.` bytes inside labels, uppercase, long names; and addresses.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use picket_bundle::Bundle;
use picket_bundle::compile::{BuildOptions, CompileOptions, build, compile_rules, load_bundle};
use picket_bundle::page::MemPages;
use picket_rules::compile::Part;
use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};
use picket_rules::matcher::{BundleAction, BundleMatcher};
use picket_rules::{Flags, QueryCtx};

struct Fx {
    bundle: Bundle,
    pages: MemPages,
    reference: BundleMatcher,
}

fn fixture() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let text = "||ads.example^\n|exact.example^\n@@||ok.ads.example^\n||imp.example^$important\n@@||imp.example^\n*.subs.example^\n0.0.0.0 hosts.example\n192.0.2.10 mapped.example\n||rw.example^$dnsrewrite=1.2.3.4\n@@||rw.example^$dnsrewrite=1.2.3.4\n||rw.example^$dnsrewrite=1.2.3.5\n||t.example^$dnstype=AAAA\n||d.example^$denyallow=x.d.example\n||ads*.track.example^\n/^b[0-9]+\\./\n/[!]/\n||e*.com^\n||1.2.3.4^\n@@||1.2.3.5^\n||10.0.0^\n||cold.example^\n||c.example^\n||2001:db8::1^\n";
        let cfg = ParseConfig::new(Format::Adblock, DomainsAs::Exact, jiff::Timestamp::now());
        let mut rules = Vec::new();
        parse_lines(text.as_bytes(), &cfg, |e| rules.push(e.rule)).unwrap();
        let c = compile_rules(&rules, &CompileOptions::new(BundleAction::Block, None));
        let tier = |k: &str, _f: Flags| if k.len() % 2 == 0 { Part::Cold } else { Part::Hot };
        let mut o = BuildOptions::new("fuzz", BundleAction::Block);
        o.part_of = Some(&tier);
        o.max_shard_keys = 3;
        let b = build(&c, &o).unwrap();
        let pages = MemPages { files: b.blobs.clone().into_iter().collect() };
        let bundle = load_bundle(&b.head_blob.bytes, &b.blobs, Some(&pages), 8 * 1024 * 1024).unwrap();
        Fx { bundle, pages, reference: BundleMatcher::new(BundleAction::Block, rules) }
    })
}

fuzz_target!(|data: &[u8]| {
    let fx = fixture();
    if data.is_empty() || data.len() > 400 {
        return;
    }
    let qtype = if data[0] & 1 == 1 { 28 } else { 1 };
    let ctx = QueryCtx {
        qtype,
        ..Default::default()
    };
    // Labels split at 0x2f ('/'), so `.` bytes stay inside labels.
    let labels: Vec<&[u8]> = data[1..]
        .split(|&b| b == b'/')
        .filter(|l| !l.is_empty() && l.len() <= 63)
        .collect();
    let wire_len: usize = labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1;
    if !labels.is_empty() && labels.len() <= 127 && wire_len <= 255 {
        let got = fx.bundle.lookup_labels_full(&labels, &ctx, &fx.pages).outcome;
        let want = fx.reference.match_name(&labels, &ctx).outcome;
        assert_eq!(got, want, "{labels:?}");
    }
    if data.len() >= 17 {
        let mut a = [0u8; 16];
        a.copy_from_slice(&data[1..17]);
        let ip = if data[0] & 2 == 2 {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(a))
        } else {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(a[0] % 12, a[1] % 4, a[2] % 4, a[3] % 8))
        };
        let d = fx.bundle.lookup_ip(ip, &ctx);
        let d = if d.cold == picket_bundle::ColdCheck::Needed {
            d.with_cold(fx.bundle.lookup_ip_cold(ip, &fx.pages))
        } else {
            d
        };
        assert_eq!(d.outcome, fx.reference.match_ip(ip, &ctx).outcome, "{ip}");
    }
});
