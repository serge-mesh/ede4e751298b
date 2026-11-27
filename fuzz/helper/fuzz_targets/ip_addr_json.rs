//! `ip -j addr show` output: the gateway's addresses for the redirect check.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge_helper::iptables::exec::parse_ip_addr_json;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = parse_ip_addr_json(data) {
        for a in v {
            assert!(a.prefix <= if a.addr.is_ipv4() { 32 } else { 128 });
            assert!(!a.ifname.is_empty() && a.ifname.len() <= 15);
        }
    }
});
