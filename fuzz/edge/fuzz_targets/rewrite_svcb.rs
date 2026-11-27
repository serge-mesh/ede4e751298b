//! `$dnsrewrite` HTTPS/SVCB values from bundles (core is untrusted as seen by the edge): the edge
//! encodes them for its reply; what it writes must be valid RFC 9460 RDATA.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let mut parts = s.split('\n');
    let prio: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(1);
    let target = parts.next().unwrap_or(".");
    let params: Vec<(String, String)> = parts
        .take(16)
        .filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect();
    if let Some(rdata) = picket_edge::dns::pipeline::svcb_rdata(prio, target, &params) {
        assert!(picket_wire::svcb::rdata_facts(65, &rdata).is_some());
        assert!(rdata.len() <= 65_535);
    }
});
