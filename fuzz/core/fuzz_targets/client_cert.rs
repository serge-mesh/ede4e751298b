//! Untrusted client-certificate DER from the edge port's handshake (api.md §1, core.md §4): the
//! check `AnyClientCert::verify_client_cert` makes, then what `admit` reads from it (the SPKI
//! fingerprint and the claimed CN). None of them may panic, and a fingerprint is always
//! `SHA256:…`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = picket_core::edge_api::check_client_cert(data, 1_800_000_000);
    if let Ok(fp) = picket_core::identity::cert_fingerprint(data) {
        assert!(fp.starts_with("SHA256:"), "{fp}");
    }
    if let Some(cn) = picket_core::identity::cert_common_name(data) {
        // What reaches the pending list and alerts is sanitised and capped.
        let shown = picket_core::util::sanitize_for_message(&cn, 128);
        assert!(!shown.chars().any(char::is_control));
    }
});
