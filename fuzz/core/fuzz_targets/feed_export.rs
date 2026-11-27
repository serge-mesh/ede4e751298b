//! Feed export documents an import reads (feeds.md §4, api.md §7): a JSON export (`feed`
//! settings, then entries with their `first_seen_at`) or `{"file": …}`, a file export's header
//! lines, and a MISP warninglist's `type`, `list`, `picket_first_seen` map and `picket_feed`
//! settings. Never panic; an entry's `raw` is at most the line cap and holds no line break, and
//! its `first_seen_at` is an RFC 3339 date or date-time or `none`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::feeds::{body, misp, transfer};

const MAX_LINE: usize = 512;

fuzz_target!(|data: &[u8]| {
    let mut entries = 0u64;
    let r = body::parse_import(
        data,
        MAX_LINE,
        &mut |_| Ok(()),
        &mut |e| {
            assert!(e.raw.len() <= MAX_LINE);
            assert!(!e.raw.contains(['\r', '\n']), "{:?}", e.raw);
            // It goes into a `picket-first-seen` directive line: a date or `none`, no line break.
            if let Some(f) = e.first_seen_at {
                assert!(body::first_seen_ok(f), "{f:?}");
                assert!(!f.contains(['\r', '\n']), "{f:?}");
            }
            entries += 1;
            Ok(())
        },
        &mut |_| Ok(()),
    );
    if let Ok(body::ImportBody::Export { entries: n, .. }) = r {
        assert_eq!(n, entries);
    }
    let _ = transfer::read_header(data);
    let _ = misp::list_type(data);
    let _ = misp::values(data, |_| Ok(()));
    let _ = misp::first_seen(data, |_, _| Ok(()));
    let _ = misp::picket_feed(data);
    if let Ok(s) = std::str::from_utf8(data) {
        assert_eq!(serde_json::from_str::<String>(&misp::quote(s)).unwrap(), s);
    }
});
