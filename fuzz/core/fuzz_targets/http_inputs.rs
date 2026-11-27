//! Request headers and small text inputs the web port and CLI parse: `Authorization: Basic`,
//! `Host`, MACs, CIDRs, probe URLs, cursors, `Origin`. Never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = picket_core::web::auth::parse_basic(s);
    let _ = picket_core::net::host_without_port(s);
    let _ = picket_core::net::normalize_mac(s);
    let _ = picket_core::net::parse_net(s);
    let _ = picket_core::edge_api::parse_probe_target(s);
    let _ = picket_core::web::api::decode_cursor(s);
    let _ = picket_core::config::validate::registrable_domain(s);
    if s.is_char_boundary(s.len() / 2) {
        let (a, b) = s.split_at(s.len() / 2);
        let _ = picket_core::web::protect::origin_allowed(Some(a), Some(b), true);
    }
    let _ = picket_core::lanca::name_under_zones(s, &["home.arpa".to_string()]);
    let _ = picket_core::settings::parse_firmware_version(s);
});
