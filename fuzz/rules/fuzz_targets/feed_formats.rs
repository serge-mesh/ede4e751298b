//! Whole feeds in each line format: counts stay consistent and nothing panics.
#![no_main]

use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;
use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};

fuzz_target!(|data: &[u8]| {
    for format in [Format::Adblock, Format::Hosts, Format::Plain] {
        for domains_as in [DomainsAs::Exact, DomainsAs::Subdomains] {
            let cfg = ParseConfig {
                max_line_len: 512,
                ..ParseConfig::new(format, domains_as, Timestamp::now())
            };
            let mut n = 0u64;
            let stats = parse_lines(data, &cfg, |_| n += 1).expect("in-memory reads don't fail");
            assert_eq!(stats.entries.total(), n);
            assert!(stats.skipped + stats.rule_lines <= stats.lines);
        }
    }
});
