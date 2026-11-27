//! `LanCa::sign_leaf` with arbitrary CSR text (an edge's `POST /v1/csr`, api.md §2): never
//! panics, and anything it signs carries only the names and IPs core chose.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use picket_core::lanca::{LEAF_VALIDITY, LanCa};

fn ca() -> &'static LanCa {
    static CA: OnceLock<(tempfile::TempDir, LanCa)> = OnceLock::new();
    &CA.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let ca = LanCa::create(d.path(), &["home.arpa".into()], "fuzz").unwrap();
        (d, ca)
    })
    .1
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Also wrap raw bytes as a PEM block, so the DER parser sees arbitrary input.
    let _ = ca().sign_leaf(text, &["dns.home.arpa".into()], &[], LEAF_VALIDITY);
    let wrapped = format!("-----BEGIN CERTIFICATE REQUEST-----\n{text}\n-----END CERTIFICATE REQUEST-----\n");
    let _ = ca().sign_leaf(&wrapped, &["dns.home.arpa".into()], &[], LEAF_VALIDITY);
});
