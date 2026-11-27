//! `snap.json` (read back at start, after a reboot): the streaming restore into fake sets.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_api::helper::{MAX_TIMEOUT_S, sets};
use picket_edge_helper::backend::Backend;
use picket_edge_helper::engine::SETS;
use picket_edge_helper::fake::FakeBackend;
use picket_edge_helper::snapshot::{SNAP_FILE, restore};

fuzz_target!(|data: &[u8]| {
    let b = FakeBackend::new();
    for d in &SETS {
        b.ipset_create(&d.spec()).unwrap();
    }
    b.st().files.insert(SNAP_FILE.into(), data.to_vec());
    let _ = restore(&b, &sets::TIMED);
    for s in sets::TIMED {
        for (_, t) in b.members(s) {
            assert!(t.is_some_and(|t| t <= MAX_TIMEOUT_S));
        }
    }
});
