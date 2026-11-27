//! Delta files: domain/cold, IP and verdict-set deltas, as gzip input and as lines compressed here
//! (so the JSON-lines parser sees structured input).
#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use picket_bundle::delta::{read_key_delta, read_range_delta};
use picket_bundle::verdict::read_delta;

fuzz_target!(|data: &[u8]| {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let _ = enc.write_all(data);
    let gz = enc.finish().unwrap_or_default();
    for input in [data, gz.as_slice()] {
        if let Ok(d) = read_key_delta(input) {
            for op in &d.ops {
                assert!(picket_bundle::delta::valid_key(op.key()));
            }
        }
        if let Ok(d) = read_range_delta(input) {
            let (lo, hi) = d.header.ip_shard.unwrap().bounds();
            for op in &d.ops {
                let (a, b) = match *op {
                    picket_bundle::delta::RangeOp::Upsert { first, last, .. } => (first, last),
                    picket_bundle::delta::RangeOp::Delete { first, last } => (first, last),
                };
                assert!(lo <= a && a <= b && b <= hi);
            }
        }
        let _ = read_delta(input);
    }
});
