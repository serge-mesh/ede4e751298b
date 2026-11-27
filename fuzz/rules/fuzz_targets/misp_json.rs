//! MISP list.json: the streaming reader never panics, and bounded memory holds per value.
#![no_main]

use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;
use picket_rules::formats::{DomainsAs, Format, ParseConfig};
use picket_rules::misp::parse_misp;

fuzz_target!(|data: &[u8]| {
    let cfg = ParseConfig {
        max_line_len: 256,
        ..ParseConfig::new(Format::MispWarninglist, DomainsAs::Exact, Timestamp::now())
    };
    let _ = parse_misp(|| Ok(data), &cfg, |e| assert!(e.raw.len() <= 256));
});
