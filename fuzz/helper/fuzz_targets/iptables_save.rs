//! `iptables-save` / `iptables -S` text (UniFi writes these tables): the lossless text
//! conversion, the parser, jump placement on both platforms, the repair plan and the port-53
//! redirect check. The redirect walk must stay bounded on any table (README "Untrusted input",
//! "Bounded"): an input whose checks take longer than [`LIMIT`] is a crash, long before
//! libFuzzer's own `-timeout` (run with `-- -timeout=10` as well).
#![no_main]

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use picket_api::edge_config::FwMode;
use picket_edge_helper::iptables::exec::{restore_bytes, save_text};
use picket_edge_helper::iptables::layout::{self, Platform};
use picket_edge_helper::iptables::model::Table;
use picket_edge_helper::iptables::nat::{IfAddr, redirect_present};
use picket_edge_helper::iptables::plan::{Family, Want, plan};

/// Longest the placement, plan and redirect checks may take for one input.
const LIMIT: Duration = Duration::from_secs(2);

fuzz_target!(|data: &[u8]| {
    // Any bytes survive the text model: a rule read back is named again byte for byte.
    let text = save_text(data.to_vec());
    assert_eq!(restore_bytes(&text), data);
    let Ok(t) = Table::parse(&text) else { return };
    let start = Instant::now();
    let ifs = vec![
        ("br0".to_string(), FwMode::Enforce),
        ("br10".to_string(), FwMode::Monitor),
    ];
    let dns6 = vec!["br0".to_string()];
    for platform in [Platform::Unifi, Platform::Debian] {
        for (family, d) in [(Family::V4, &[][..]), (Family::V6, &dns6[..])] {
            for disabled in [false, true] {
                let p = plan(
                    &t,
                    &Want {
                        family,
                        platform,
                        interfaces: &ifs,
                        dns6: d,
                        disabled,
                    },
                );
                if let Some(r) = &p.restore {
                    // The restore text only ever names Picket's chains as declared chains.
                    for l in r.lines().filter(|l| l.starts_with(':')) {
                        assert!(l.starts_with(":PICKET-"), "{l}");
                    }
                }
            }
        }
        let _ = layout::place(&t, platform, "br0");
    }
    let addrs = vec![
        IfAddr {
            ifname: "br0".into(),
            addr: "192.168.1.1".parse().unwrap(),
            prefix: 24,
        },
        IfAddr {
            ifname: "br0".into(),
            addr: "fd00::1".parse().unwrap(),
            prefix: 64,
        },
    ];
    for f in [Family::V4, Family::V6] {
        let _ = redirect_present(&t, f, &["br0".to_string()], 5335, &addrs);
    }
    let _ = layout::dnsfilter_active(&t);
    assert!(start.elapsed() < LIMIT, "checks took {:?}", start.elapsed());
});
