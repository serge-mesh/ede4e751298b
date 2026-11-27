//! The edge's session messages (api.md §3): `hello` and `heartbeat` text frames, decoded and
//! bounded, then flattened into metric series as core stores them. Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::edges::messages::{self, Incoming};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match messages::decode(text) {
        Ok(Incoming::Hello(h)) => {
            assert!(h.have.config.len() <= messages::MAX_HAVE_IDS);
            assert!(h.conditions.len() <= messages::MAX_CONDITIONS);
            // cert_roots (core.md §11): bounded, every root a certificate fingerprint.
            assert!(h.cert_roots.len() <= messages::MAX_CERT_ROOTS);
            assert!(
                h.cert_roots
                    .values()
                    .all(|r| picket_api::ids::is_cert_fingerprint(r))
            );
            let info =
                picket_core::edges::hub::HelloInfo::from_hello(&h, None, "2026-11-13T12:00:00.000000Z", None);
            let _ = info.bind_allowed("192.168.1.1:53");
            let _ = picket_core::edges::status::firmware_problem(
                h.firmware.as_deref(),
                &picket_core::settings::compiled_min_firmware(),
            );
        }
        Ok(Incoming::Heartbeat(hb)) => {
            assert!(hb.cert_roots.len() <= messages::MAX_CERT_ROOTS);
            assert!(
                hb.cert_roots
                    .values()
                    .all(|r| picket_api::ids::is_cert_fingerprint(r))
            );
            for (_, labels, _) in picket_core::metrics::store::flatten("e-01", &hb) {
                for v in labels.values() {
                    let _ = picket_core::metrics::export::escape(v);
                }
            }
        }
        _ => {}
    }
});
