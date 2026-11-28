//! Single-threaded allocation budgets: do not count fixture construction or other tests.
//! Requested bytes exclude allocator metadata/retention; the isolated RSS probe covers those.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test assertions"
)]

use picket_api::edge_config::FwMode;
use picket_api::helper::{ApplyRequest, InterfaceMode, MAX_FRAME, RedirectCheck};
use picket_edge_helper::rules::{Desired, MAX_INPUT_NETS, MAX_INTERFACES, STATIC_MAX};
use picket_edge_helper::server::{Request, parse_request};
use serde_json::json;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

fn measure(f: &[u8], valid: bool, budget: usize) -> Option<Box<Desired>> {
    assert!(f.len() <= MAX_FRAME);
    let region = Region::new(GLOBAL);
    let parsed = parse_request(f);
    let stats = region.change();
    assert!(
        stats.bytes_allocated <= budget,
        "{} allocated; budget {budget}",
        stats.bytes_allocated
    );
    assert_eq!(parsed.is_ok(), valid, "{parsed:?}");
    match parsed {
        Ok((Some(42), Request::Apply(d))) => Some(d),
        Err((Some(42), e)) => {
            assert_eq!(e.code, "invalid");
            None
        }
        other => panic!("wrong response: {other:?}"),
    }
}

fn frame(data: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": "apply", "id": 42, "data": data})).unwrap()
}

#[test]
fn bounded_apply_decode_and_semantic_parity() {
    // The previous decoder retained a 12 MiB Vec for this 1 MiB frame, despite the first
    // string already being an invalid CIDR. The streaming decoder stops at that string.
    let prefix = br#"{"type":"apply","id":42,"data":{"static":["#;
    let count = (MAX_FRAME - prefix.len() - 3 + 1) / 3;
    let mut empty = prefix.to_vec();
    for i in 0..count {
        if i != 0 {
            empty.push(b',');
        }
        empty.extend_from_slice(br#""""#);
    }
    empty.extend_from_slice(b"]}}");
    measure(&empty, false, 16 * 1024);

    // Maximum legal raw count, near the frame limit across both lists. Normalisation during
    // decode preserves duplicate acceptance without retaining a string for every duplicate.
    let duplicate = frame(json!({"static": vec!["::"; MAX_INPUT_NETS], "exempt": vec!["::"; 78000]}));
    let d = measure(&duplicate, true, 16 * 1024).unwrap();
    assert_eq!((d.static6.len(), d.exempt6.len()), (1, 1));
    let excess = frame(json!({"exempt": vec!["::"; MAX_INPUT_NETS + 1]}));
    measure(&excess, false, 16 * 1024);

    // All 65536 unique members of one family remain supported, with exact-sized final storage.
    let unique: Vec<String> = (0..STATIC_MAX)
        .map(|i| format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255))
        .collect();
    let unique_frame = frame(json!({"static": unique}));
    let d = measure(&unique_frame, true, 6 << 20).unwrap();
    assert_eq!(d.static4.len(), STATIC_MAX as usize);
    assert_eq!(d.static4.capacity(), d.static4.len());
    let excess = frame(
        json!({"static": (0..=STATIC_MAX).map(|i| format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255)).collect::<Vec<_>>()}),
    );
    measure(&excess, false, 6 << 20);

    for field in ["interfaces", "redirect"] {
        let entries = vec![json!({"name": "br0"}); MAX_INTERFACES + 1];
        let f = if field == "interfaces" {
            frame(json!({"interfaces": entries}))
        } else {
            frame(json!({"redirect": {"interfaces": vec!["br0"; MAX_INTERFACES + 1], "port": 53}}))
        };
        measure(&f, false, 16 * 1024);
    }
    let mut escaped = br#"{"type":"apply","id":42,"data":{"interfaces":[{"name":""#.to_vec();
    for _ in 0..170000 {
        escaped.extend_from_slice(br#"\u0061"#);
    }
    escaped.extend_from_slice(br#""}]}}"#);
    // Escaped strings require serde_json scratch space, still at most a wire-sized allocation.
    measure(&escaped, false, MAX_FRAME);

    let mut request = ApplyRequest {
        interfaces: (0..MAX_INTERFACES)
            .map(|i| InterfaceMode {
                name: format!("br{i}"),
                mode: FwMode::Enforce,
            })
            .collect(),
        static_allow: vec![" 0.0.0.0/0 ".into(), "::/0".into(), "2001:db8::7/64".into()],
        exempt: vec!["::".into(), " 192.0.2.1 ".into()],
        redirect: Some(RedirectCheck {
            interfaces: (0..MAX_INTERFACES).map(|i| format!("br{i}")).collect(),
            port: 5335,
            ipv6: true,
        }),
    };
    for mode in [FwMode::Enforce, FwMode::Monitor, FwMode::Off] {
        request.interfaces[0].mode = mode;
        let f = frame(serde_json::to_value(&request).unwrap());
        let d = measure(&f, true, 128 * 1024).unwrap();
        assert_eq!(*d, Desired::from_request(&request).unwrap());
    }
    for data in [
        json!({"interfaces": [{"name": "br0", "mode": "off"}, {"name": "br0", "mode": "enforce"}]}),
        json!({"redirect": {"interfaces": ["br0"], "port": 0}}),
        json!({"interfaces": [{}]}),
        json!({"static": ["bad"]}),
        json!({"interfaces": [{"name": "a".repeat(MAX_FRAME / 2)}]}),
        json!({"exempt": ["a".repeat(MAX_FRAME / 2)]}),
        json!({"static": null}),
        json!({"redirect": {"interfaces": ["-bad"]}}),
    ] {
        measure(&frame(data), false, 16 * 1024);
    }
    for data in [json!(null), json!({}), json!({"future": {"nested": ["ignored"]}})] {
        assert_eq!(
            *measure(&frame(data), true, 16 * 1024).unwrap(),
            Desired::default()
        );
    }
}
