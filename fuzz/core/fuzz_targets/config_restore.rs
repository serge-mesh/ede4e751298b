//! The config restore's document (core.md §2): a `PUT config/export` body is untrusted. It goes
//! through what a restore does before anything changes: the byte-level bounds
//! (`stream::prescan`), the streaming first pass (manual files decoded and hashed, alerts, check
//! history and the journal checked row by row, previous-format single-string manual files cut
//! into chunks as they are read) and the checks against the model it holds (format,
//! `lanca.zones`, settings, every entity and reference, manual files). Never panics on any
//! input; the pre-scan fed in pieces (as the export feeds what it writes) decides as it does
//! fed at once; a document JSON refuses is refused.
#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use picket_core::config::export::{check_parsed, stream};

fuzz_target!(|data: &[u8]| {
    let whole = stream::prescan(data);
    let mut pieces = stream::Prescan::default();
    let split = data.first().map_or(0, |b| usize::from(*b) % (data.len() + 1));
    let fed = pieces
        .feed(&data[..split])
        .and_then(|()| pieces.feed(&data[split..]));
    assert_eq!(whole.is_ok(), fed.is_ok(), "{whole:?} {fed:?}");
    if whole.is_err() {
        return;
    }
    let mut read = stream::Checker::new(None);
    let parsed = stream::parse_reader(data, &mut read);
    // Previous-format single-string files are read as JSON reads them: a document JSON refuses
    // never parses (README §2 Untrusted input; api.md §7 `422`).
    if serde_json::from_slice::<serde::de::IgnoredAny>(data).is_err() {
        assert!(parsed.is_err(), "a malformed document parsed");
    }
    let Ok(head) = parsed else {
        return;
    };
    let zones = vec!["home.arpa".to_string()];
    let stored: BTreeSet<String> = ["s1".to_string()].into_iter().collect();
    let _ = check_parsed(&head, &read, &zones, &stored);
});
