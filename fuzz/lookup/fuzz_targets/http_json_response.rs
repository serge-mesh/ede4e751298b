//! `http_json` response handling (providers.md §5) on arbitrary status, headers and body: never
//! panics, and each status maps to its row of the table.

#![no_main]

use std::sync::LazyLock;

use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use picket_lookup::modules::http_json::{Config, interpret};
use picket_lookup::{HttpResponse, LookupError, Verdict};
use picket_lookup_fuzz::split;
use serde_json::json;

static CONFIGS: LazyLock<Vec<Config>> = LazyLock::new(|| {
    [
        json!({"url": "https://api.example.net/v1/domain/{domain}",
               "verdict": {"pointer": "/risk_score", "block_if": ">= 7.0", "clean_if": "< 4.0"}}),
        json!({"url": "https://api.example.net/{domain}",
               "verdict": {"pointer": "/data/0/category", "block_if": "== \"malicious\"", "clean_if": "!= \"malicious\""}}),
        json!({"url": "https://api.example.net/?q={domain}",
               "verdict": {"pointer": "", "clean_if": "== true"}}),
        json!({"url": "https://api.example.net/{domain}",
               "verdict": {"pointer": "/a~1b/~0/1", "block_if": "!= 0"}}),
    ]
    .into_iter()
    .map(|v| serde_json::from_value(v).unwrap())
    .collect()
});

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let status = u16::from_be_bytes([data[0], data[1]]) % 1000;
    let cfg = &CONFIGS[data[2] as usize % CONFIGS.len()];
    let (head, body) = split(&data[3..]);
    let mut headers = HeaderMap::new();
    for line in head.split(|&b| b == b'\n').take(16) {
        if let Some(i) = line.iter().position(|&b| b == b':')
            && let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(&line[..i]),
                HeaderValue::from_bytes(line[i + 1..].trim_ascii()),
            )
        {
            headers.append(n, v);
        }
    }
    let resp = HttpResponse {
        status,
        headers,
        body: body.to_vec(),
    };
    let now = jiff::Timestamp::from_second(1_800_000_000).unwrap();
    let r = interpret(cfg, Ok(resp), now);
    match (status, &r) {
        (200, Ok(a)) => {
            assert!(a.detail.is_none());
            if let Verdict::Block { score, .. } = &a.verdict {
                assert!(score.is_none_or(|s| s.is_finite()));
            }
        }
        (200, Err(LookupError::Failed(_))) => {}
        (404, Ok(a)) => assert_eq!(a.verdict, Verdict::Unknown),
        (429, Err(LookupError::Rejected { .. })) => {}
        (500..=599, Err(LookupError::Failed(_))) => {}
        (s, Err(LookupError::Other(_))) if !matches!(s, 200 | 404 | 429 | 500..=599) => {}
        _ => panic!("status {status} gave {r:?}"),
    }
});
