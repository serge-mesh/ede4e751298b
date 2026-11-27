//! `dns` rules and detail over arbitrary answers (checked like an upstream answer first): never
//! panic, and the detail always stays under 512 bytes (providers.md §4 "Detail").

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use picket_lookup::LookupModule;
use picket_lookup::modules::dns::config::Config;
use picket_lookup::modules::dns::{self, detail, rules};
use picket_lookup_fuzz::sent_of;
use picket_wire::answer::SentQuery;
use picket_wire::facts::lookup_answer_facts;
use serde_json::json;

static CONFIGS: LazyLock<Vec<Config>> = LazyLock::new(|| {
    let presets = dns::Module.presets();
    let mut out: Vec<Config> = vec![
        (presets[0].build)(&json!({})).unwrap().0,
        (presets[1].build)(&json!({"profile": "abc123", "transport": "doh"}))
            .unwrap()
            .0,
        json!({"transport": "udp", "servers": [{"ip": "192.0.2.1", "port": 5353}],
        "rules": [
          {"id": "a", "when": {"rcode": ["SERVFAIL"], "ede": "none"}, "verdict": "unknown"},
          {"id": "b", "when": {"ede_text": "BlOcK", "soa": false}, "verdict": "block", "score": 1.5},
          {"id": "c", "when": {"answers_in": ["0.0.0.0/8", "::/128", "192.0.2.0/24"]}, "verdict": "block"},
          {"id": "d", "when": {"cname_suffix": ["example", "."]}, "verdict": "clean"},
          {"id": "e", "when": {"soa": true, "rcode": ["NXDOMAIN", "NOERROR"]}, "verdict": "clean"}
        ]}),
    ]
    .into_iter()
    .map(|v| serde_json::from_value(v).unwrap())
    .collect();
    out.shrink_to_fit();
    out
});

fuzz_target!(|data: &[u8]| {
    let Some((id, qname, qtype, qclass)) = sent_of(data) else {
        return;
    };
    let sent = SentQuery {
        id,
        qname: qname.as_name(),
        qtype,
        qclass,
    };
    let Ok(facts) = lookup_answer_facts(data, &sent) else {
        return;
    };
    for cfg in CONFIGS.iter() {
        let (_verdict, rule) = rules::decide(cfg, &facts);
        let d = detail::build(&cfg.servers[0], cfg.transport, &facts, rule);
        let text = serde_json::to_string(&d).unwrap();
        assert!(picket_lookup::detail_fits(text.len()), "{} bytes", text.len());
    }
});
