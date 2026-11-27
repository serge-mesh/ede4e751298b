//! Manual feed write bodies (api.md §7): `{content, base_version}` and `{lines}`, streamed
//! through the pull parser, plain and gzip-compressed, with the body cap. Never panic; a line
//! handed on never holds a line break.
#![no_main]

use std::io::Read;

use libfuzzer_sys::fuzz_target;
use picket_core::feeds::body::{Capped, parse_lines, parse_save};

fuzz_target!(|data: &[u8]| {
    let mut total = 0usize;
    let _ = parse_save(Capped::new(data, 1 << 20), &mut |b| {
        total += b.len();
        Ok(())
    });
    let _ = parse_lines(Capped::new(data, 1 << 20), 4096, &mut |l| {
        assert!(!l.contains(&b'\n') && !l.contains(&b'\r'));
        assert!(l.len() <= 4096);
        Ok(())
    });
    // The same bytes as a gzip stream (truncated or garbage gzip must fail cleanly).
    let gz = flate2::read::MultiGzDecoder::new(data);
    let _ = parse_save(Capped::new(gz, 1 << 16), &mut |_| Ok(()));
    let mut sink = Vec::new();
    let _ = Capped::new(data, 7).read_to_end(&mut sink);
});
