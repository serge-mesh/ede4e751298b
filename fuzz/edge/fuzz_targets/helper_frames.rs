//! Frames from picket-edge-helper as the firewall client reads them (edge-firewall.md §4): the
//! helper is untrusted as seen by the edge (README §2), so every response and event type is
//! decoded from arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_api::helper::*;

fuzz_target!(|data: &[u8]| {
    let Ok(f) = picket_edge::firewall::conn::parse_frame(data) else {
        return;
    };
    let _ = f.parse_data::<HelloResponse>();
    let _ = f.parse_data::<ApplyResponse>();
    let _ = f.parse_data::<EnsureResponse>();
    let _ = f.parse_data::<DumpResponse>();
    let _ = f.parse_data::<StatusResponse>();
    let _ = f.parse_data::<RulesRepaired>();
    let _ = f.parse_data::<Conditions>();
    let _ = f.parse_data::<SetFull>();
    let _ = f.parse_data::<HelperError>();
});
