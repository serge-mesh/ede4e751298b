//! head.json, manifest.json and a verdict set's head: parse and validate.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_bundle::head::{Head, Manifest};
use picket_bundle::verdict::VerdictHead;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Head::from_bytes(data) {
        let _ = h.dir();
        let _ = h.cold_dir();
        let _ = h.ip_fast_path();
        let back = Head::from_bytes(&h.to_bytes()).expect("a valid head round-trips");
        assert_eq!(back, h);
    }
    if let Ok(m) = Manifest::from_bytes(data) {
        assert_eq!(Manifest::from_bytes(&m.to_blob().0).expect("round-trips"), m);
    }
    let _ = VerdictHead::from_bytes(data);
});
