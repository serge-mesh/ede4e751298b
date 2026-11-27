//! `http_json` configs from arbitrary JSON: never panic; an accepted config always builds a
//! request for any name that passes the label check, to the template's own host.

#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_lookup::check_name;
use picket_lookup::modules::http_json::Config;
use picket_lookup_fuzz::split;

fuzz_target!(|data: &[u8]| {
    let (cfg, name) = split(data);
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(cfg) else {
        return;
    };
    let Ok(cfg) = serde_json::from_value::<Config>(value) else {
        return;
    };
    let reference = cfg.request("a.example").expect("a valid template");
    assert_eq!(reference.url.scheme(), "https");
    let Ok(name) = std::str::from_utf8(name) else {
        return;
    };
    if let Some(name) = check_name(name) {
        assert!(name.len() <= 253);
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
        );
        let req = cfg.request(&name).expect("a checked name always makes a URL");
        assert_eq!(req.url.host_str(), reference.url.host_str());
        assert_eq!(
            req.url.port_or_known_default(),
            reference.url.port_or_known_default()
        );
    }
});
