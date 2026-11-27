//! What core reads from lookup providers' servers itself (core.md §7; providers.md §4
//! `LookupCtx`): a DNS server's length-prefixed answer over TCP or DoT, and the reasons and
//! verdict text it stores from untrusted logs and providers. Never panic; a framed answer is
//! 1–65,535 bytes; a cut reason is a prefix within its bound at a character boundary.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use picket_core::lookups::{clients, store};

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Builder::new_current_thread().build().unwrap())
}

fuzz_target!(|data: &[u8]| {
    rt().block_on(async {
        let mut r = data;
        if let Ok(m) = clients::read_framed(&mut r).await {
            assert!(!m.is_empty() && m.len() <= 65_535);
            assert_eq!(&data[2..2 + m.len()], m.as_slice());
        }
    });
    if let Ok(s) = std::str::from_utf8(data) {
        for max in [0usize, 1, 7, store::MAX_REASON] {
            let c = store::cut(s, max);
            assert!(c.len() <= max && s.starts_with(c));
        }
        let _ = store::parse_verdict(s);
    }
});
