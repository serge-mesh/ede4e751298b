//! `Retry-After` parsing on arbitrary header bytes: never panics; delay-seconds read as seconds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_lookup::modules::http_json::retry_after;

fuzz_target!(|data: &[u8]| {
    let now = jiff::Timestamp::from_second(1_800_000_000).unwrap();
    let r = retry_after::parse(data, now);
    let t = data.trim_ascii();
    if !t.is_empty() && t.len() <= 19 && data.len() <= 64 && t.iter().all(u8::is_ascii_digit) {
        let secs: u64 = std::str::from_utf8(t).unwrap().parse().unwrap();
        assert_eq!(r, Some(std::time::Duration::from_secs(secs)));
    }
});
