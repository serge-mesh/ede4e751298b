//! ClientHellos a DoT or DoH listener refused (edge.md §5; api.md §5 `tls_version_refused`): the
//! first bytes of a client's TLS records, read to describe what it offered. Must give a
//! description or `None`, never panic; an SNI is in its one reported form, and `offered` is none
//! exactly when TLS 1.3 is offered. Seeds: `corpus/client_hello/` (fuzz a scratch copy).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data
        .len()
        .min(picket_edge::dns::listeners::handshake::MAX_HELLO_BYTES)];
    if let Some(h) = picket_edge::dns::listeners::client_hello::read(data) {
        assert_eq!(h.offered().is_none(), h.offers_tls13());
        if let Some(s) = &h.sni {
            assert!(!s.is_empty() && s.len() <= 253 && !s.ends_with('.'), "{s:?}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')),
                "{s:?}"
            );
        }
        assert!(h.supported.as_ref().is_none_or(|v| v.len() <= 127));
    }
});
