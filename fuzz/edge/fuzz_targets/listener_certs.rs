//! Listener certificate files, stored managed pairs and core's CSR answers (edge.md §5): PEM
//! chains and keys, which must load or fail cleanly.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|&b| b == 0).unwrap_or(data.len() / 2);
    let (cert, key) = data.split_at(split);
    let _ = picket_edge::dns::certs::certified_key(cert, key);
    // A stored managed pair: key and chain in one PEM text (edge.md §5).
    let _ = picket_edge::dns::certs::certified_key(data, data);
    let _ = serde_json::from_slice::<picket_api::edge_api::CsrResponse>(data);
});
