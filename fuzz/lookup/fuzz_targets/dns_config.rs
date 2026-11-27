//! `dns` configs and preset parameters from arbitrary JSON: never panic; an accepted config keeps
//! the spec's bounds; a preset's config is always accepted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_lookup::LookupModule;
use picket_lookup::modules::dns::{self, Config};

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    if let Ok(cfg) = serde_json::from_value::<Config>(value.clone()) {
        assert!((1..=8).contains(&cfg.servers.len()));
        assert!(cfg.rules.len() <= 32);
        for s in &cfg.servers {
            assert_eq!(s.dns.tls_host.is_some(), s.dns.transport.is_encrypted());
            assert_ne!(s.dns.port, 0);
        }
        for r in &cfg.rules {
            assert!(!r.id.is_empty() && r.id.len() <= 32);
        }
        if let Some(t) = &cfg.self_test {
            assert!(picket_lookup::selftest::parse_cron(&t.cron).is_ok());
            assert!(picket_lookup::check_name(&t.name).is_some());
        }
    }
    for p in dns::Module.presets() {
        if let Ok((built, _)) = (p.build)(&value) {
            serde_json::from_value::<Config>(built).expect("a preset builds a valid config");
        }
    }
});
