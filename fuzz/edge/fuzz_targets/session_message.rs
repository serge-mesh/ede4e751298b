//! WebSocket messages from core (api.md §3).
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_api::session::SessionMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = serde_json::from_slice::<SessionMessage>(data) {
        let _ = serde_json::to_string(&m);
    }
});
