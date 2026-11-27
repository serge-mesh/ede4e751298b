//! `<data_dir>/releases/pending.json`, written by the unprivileged edge (edge.md §14).
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge_update::api::is_release_version;
use picket_edge_update::update::parse_pending_bytes;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = parse_pending_bytes(data) {
        assert!(p.request_id.as_ref().is_none_or(|id| id.len() <= 256));
        // A version that passes the check is safe as one path component.
        if is_release_version(&p.version) {
            assert!(!p.version.contains('/') && p.version != "." && p.version != "..");
        }
    }
});
