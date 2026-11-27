//! The `dns` module's detail (providers.md §5 `dns` "Detail"): `{server, transport, rcode, ede:
//! [{code, text?}], answers, cname, soa, rule}`, with at most 4 addresses and 4 CNAME hops (names
//! as in log records, api.md §5), EXTRA-TEXT cut to 64 bytes with control characters escaped
//! (picket-wire's `detail_text`), and `rule` the matched rule's id or null. Kept under 512 bytes
//! serialised by shedding the least telling parts first.

use picket_api::edge_config::UpstreamProtocol;
use picket_wire::facts::LookupFacts;
use picket_wire::types::rcode_mnemonic;
use serde_json::{Value, json};

use super::config::Server;
use crate::module::detail_fits;

/// The most addresses in the detail.
pub const MAX_ANSWERS: usize = 4;
/// The most CNAME hops in the detail.
pub const MAX_CNAME: usize = 4;

/// The transport as the config and the detail write it.
pub(crate) fn transport_text(t: UpstreamProtocol) -> &'static str {
    match t {
        UpstreamProtocol::Dot => "dot",
        UpstreamProtocol::Doh => "doh",
        UpstreamProtocol::Udp => "udp",
        UpstreamProtocol::Tcp => "tcp",
    }
}

/// How much of the facts a detail carries; each step down sheds more.
#[derive(Clone, Copy)]
struct Shape {
    ede: usize,
    /// EDE entries (from the first) that keep their text.
    ede_texts: usize,
    answers: usize,
    cname: usize,
}

const SHAPES: [Shape; 9] = [
    Shape {
        ede: usize::MAX,
        ede_texts: usize::MAX,
        answers: MAX_ANSWERS,
        cname: MAX_CNAME,
    },
    Shape {
        ede: 4,
        ede_texts: 4,
        answers: MAX_ANSWERS,
        cname: MAX_CNAME,
    },
    Shape {
        ede: 4,
        ede_texts: 1,
        answers: MAX_ANSWERS,
        cname: MAX_CNAME,
    },
    Shape {
        ede: 4,
        ede_texts: 1,
        answers: MAX_ANSWERS,
        cname: 1,
    },
    Shape {
        ede: 4,
        ede_texts: 0,
        answers: MAX_ANSWERS,
        cname: 1,
    },
    Shape {
        ede: 4,
        ede_texts: 0,
        answers: 1,
        cname: 1,
    },
    Shape {
        ede: 4,
        ede_texts: 0,
        answers: 1,
        cname: 0,
    },
    Shape {
        ede: 1,
        ede_texts: 0,
        answers: 1,
        cname: 0,
    },
    Shape {
        ede: 0,
        ede_texts: 0,
        answers: 0,
        cname: 0,
    },
];

fn render(
    server: &Server,
    transport: UpstreamProtocol,
    f: &LookupFacts,
    rule: Option<&str>,
    s: Shape,
) -> Value {
    let rcode = rcode_mnemonic(f.rcode).map_or_else(|| f.rcode.to_string(), str::to_owned);
    let ede: Vec<Value> = f
        .ede
        .iter()
        .take(s.ede)
        .enumerate()
        .map(|(i, e)| {
            let text = e.detail_text();
            if i < s.ede_texts && !text.is_empty() {
                json!({"code": e.code, "text": text})
            } else {
                json!({"code": e.code})
            }
        })
        .collect();
    let answers: Vec<String> = f.addrs.iter().take(s.answers).map(|a| a.to_string()).collect();
    let cname: Vec<String> = f.chain.iter().take(s.cname).map(|n| n.log_text()).collect();
    json!({
        "server": server.label,
        "transport": transport_text(transport),
        "rcode": rcode,
        "ede": ede,
        "answers": answers,
        "cname": cname,
        "soa": f.soa,
        "rule": rule,
    })
}

/// The detail for an answer, under [`crate::DETAIL_MAX`] bytes serialised (providers.md §4 "Detail").
pub fn build(server: &Server, transport: UpstreamProtocol, f: &LookupFacts, rule: Option<&str>) -> Value {
    let mut last = Value::Null;
    for s in SHAPES {
        let v = render(server, transport, f, rule, s);
        if serde_json::to_string(&v).is_ok_and(|t| detail_fits(t.len())) {
            return v;
        }
        last = v;
    }
    // The smallest shape holds a server label, an rcode and a rule id of at most 32 bytes: it
    // always fits. Should it not, the LookupClient drops it.
    last
}
