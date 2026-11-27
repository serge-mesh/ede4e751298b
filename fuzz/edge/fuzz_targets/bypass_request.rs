//! What the extension sends the edge (edge.md §12, api.md §6): bypass API bodies, and the reverse
//! names of its PTR probes; the extension is untrusted (README §2).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = picket_edge::bypass::parse_entries(data);
    let labels: Vec<&[u8]> = data.split(|b| *b == b'.').collect();
    let _ = picket_edge::bypass::reverse_ip(&labels);
    let _ = picket_edge::bypass::wire_text(data);
});
