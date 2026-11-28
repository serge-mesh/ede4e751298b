//! A whole bundle (head, manifests, FST, filters, cold page file, ips.bin, segments, deltas) with
//! one blob replaced by fuzz input: loading never panics, and whatever loads answers lookups.
#![no_main]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use picket_bundle::compile::{BuildOptions, BuiltBundle, CompileOptions, build, compile_rules, load_bundle};
use picket_bundle::page::MemPages;
use picket_rules::compile::Part;
use picket_rules::formats::{DomainsAs, Format, ParseConfig, parse_lines};
use picket_rules::matcher::BundleAction;
use picket_rules::{Flags, QueryCtx};

fn fixture() -> &'static (BuiltBundle, Vec<String>) {
    static F: OnceLock<(BuiltBundle, Vec<String>)> = OnceLock::new();
    F.get_or_init(|| {
        let text = "||ads.example^\n@@||ok.ads.example^\n||rw.example^$dnsrewrite=1.2.3.4\n||t.example^$dnstype=AAAA\n||ads*.track.example^\n/^b[0-9]+\\./\n||1.2.3.4^\n@@||1.2.3.5^\n||cold.example^\n||2001:db8::1^\n";
        let cfg = ParseConfig::new(Format::Adblock, DomainsAs::Exact, jiff::Timestamp::now());
        let mut rules = Vec::new();
        parse_lines(text.as_bytes(), &cfg, |e| rules.push(e.rule)).unwrap();
        let c = compile_rules(&rules, &CompileOptions::new(BundleAction::Block, None));
        let tier = |k: &str, _f: Flags| if k.starts_with("example.cold") { Part::Cold } else { Part::Hot };
        let mut o = BuildOptions::new("fuzz", BundleAction::Block);
        o.part_of = Some(&tier);
        let b = build(&c, &o).unwrap();
        let ids: Vec<String> = b.blobs.keys().cloned().collect();
        (b, ids)
    })
}

fuzz_target!(|data: &[u8]| {
    let (b, ids) = fixture();
    if data.is_empty() {
        return;
    }
    let which = usize::from(data[0]) % (ids.len() + 1);
    let mut store: BTreeMap<String, Vec<u8>> = b.blobs.clone();
    let mut head = b.head_blob.bytes.clone();
    match ids.get(which) {
        // Replace the blob's bytes; also re-key it so BLAKE3 verification passes and the parsers
        // behind it run.
        Some(id) => {
            store.insert(id.clone(), data[1..].to_vec());
            let new_id = picket_bundle::bytes::object_id(&data[1..]);
            let h = String::from_utf8_lossy(&head).replace(id.as_str(), &new_id);
            let mut s2 = BTreeMap::new();
            for (k, v) in store {
                let v = String::from_utf8(v.clone())
                    .map(|t| t.replace(id.as_str(), &new_id).into_bytes())
                    .unwrap_or(v);
                s2.insert(if &k == id { new_id.clone() } else { k }, v);
            }
            store = s2;
            head = h.into_bytes();
        }
        None => head = data[1..].to_vec(),
    }
    let pages = MemPages {
        files: store.clone().into_iter().collect(),
    };
    if let Ok(bundle) = load_bundle(&head, &store, Some(&pages), 4 * 1024 * 1024) {
        let ctx = QueryCtx {
            qtype: 1,
            ..Default::default()
        };
        for n in [
            "ads.example",
            "x.ok.ads.example",
            "rw.example",
            "ads1.track.example",
            "cold.example",
            "1.2.3.4",
        ] {
            let labels: Vec<&[u8]> = n.split('.').map(str::as_bytes).collect();
            let _ = bundle.lookup_labels_full(&labels, &ctx, &pages);
        }
        for ip in ["1.2.3.4", "1.2.3.5", "2001:db8::1"] {
            let _ = bundle.lookup_ip(ip.parse().unwrap(), &ctx);
        }
        let _ = bundle.versions();
    }
});
