//! The config object core serves (api.md §4): the shape check, verification, parsing,
//! validation, the stripped hash, the request fields read leniently, and the bound on the lookup
//! flush ids kept.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge::convergence::{
    Fetched, MAX_FLUSH_LOOKUPS, check_shape, prune_flush_lookups, requests_of, stripped, validate,
};

fuzz_target!(|data: &[u8]| {
    let _ = check_shape(data);
    if let Ok(f) = Fetched::from_bytes(data, None) {
        let mut applied = f.requests.flush.lookups.clone();
        prune_flush_lookups(&mut applied, &f.requests);
        assert!(applied.len() <= MAX_FLUSH_LOOKUPS);
        assert_eq!(picket_api::ids::object_id(&f.canonical), f.hash);
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
            let _ = requests_of(&v);
            assert_eq!(stripped(&v).0, f.hash);
        }
        if let Ok(c) = &f.config {
            let _ = validate(c);
            let _ = c.needs_helper();
        }
        let _ = picket_edge::update::decide_install(f.requests.release.as_ref(), None, true, None, "1.0.0");
    }
});
