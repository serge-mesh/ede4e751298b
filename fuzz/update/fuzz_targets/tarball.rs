//! A release tarball's listing and contents, through the same checks as unpacking
//! (edge.md §14 step 2), with small bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge_update::release::{BINARIES, Limits, scan_tarball};

const LIMITS: Limits = Limits {
    tarball: 1 << 20,
    signature: 1 << 10,
    entry: 1 << 16,
    decompressed: 1 << 20,
    entries: 64,
};

fuzz_target!(|data: &[u8]| {
    let mut seen = Vec::new();
    let r = scan_tarball(data, &LIMITS, |name, reader, size| {
        assert!(size <= LIMITS.entry);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        assert!(buf.len() as u64 <= size);
        seen.push(name);
        Ok(())
    });
    if r.is_ok() {
        let mut seen = seen.clone();
        seen.sort_unstable();
        let mut want = BINARIES.to_vec();
        want.sort_unstable();
        assert_eq!(seen, want);
    }
});
