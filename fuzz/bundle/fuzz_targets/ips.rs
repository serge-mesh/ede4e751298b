//! ips.bin: every container and table validated at load; lookups never fail.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_bundle::ips::IpBase;

fuzz_target!(|data: &[u8]| {
    let Ok(b) = IpBase::from_bytes(data) else {
        return;
    };
    let (lo, hi) = b.shard().bounds();
    for a in [lo, hi, lo.wrapping_add(1), lo / 2 + hi / 2, u128::from(data.len() as u32)] {
        let _ = b.get(a);
    }
    if data.len() < 64 * 1024 {
        let runs = b.runs();
        for w in runs.windows(2) {
            assert!(w[0].last < w[1].first, "runs read back sorted and disjoint");
        }
    }
});
