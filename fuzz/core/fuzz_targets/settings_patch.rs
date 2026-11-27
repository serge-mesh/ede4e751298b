//! `PUT /api/ui/v1/settings` bodies: any JSON as a settings patch, then validation. Never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::settings::{Settings, apply_patch, validate};

fuzz_target!(|data: &[u8]| {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    if let Ok((s, _rows)) = apply_patch(&Settings::default(), &v, false) {
        let _ = validate(&s);
        let _ = picket_core::settings::flat(&s);
    }
});
