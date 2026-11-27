//! Spool segments read back from disk (edge.md §11): gzip members, possibly torn or damaged.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = picket_edge::logs::spool::read_segment_bytes(data, 1 << 20);
});
