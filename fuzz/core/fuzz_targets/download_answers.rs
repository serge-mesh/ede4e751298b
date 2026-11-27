//! What download modules read from sources (providers.md §3): git pkt-line `ls-refs` answers,
//! the GitHub trees, commits and contents APIs, alphaMountain's CSV, HTTP header values
//! (`Content-Range`, `Last-Modified`, `Retry-After`) and list date lines. Never panic; a tree's
//! entries are repository paths.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::modules::download::{alphamountain_threat_1000::csv, dates, github, http};

fuzz_target!(|data: &[u8]| {
    let _ = github::pktline::parse(data);
    let _ = github::pktline::find_ref(data, "HEAD");
    let _ = github::pktline::find_ref(data, "refs/heads/main");
    let _ = github::pktline::find_symref_branch(data, "HEAD");
    let _ = github::parse_commits(data);
    let _ = github::parse_blob_sha(data);
    if let Ok(tree) = github::parse_tree(data) {
        for e in &tree.entries {
            assert!(github::check_path(&e.path).is_ok(), "{:?}", e.path);
            assert!(
                e.sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
        }
    }
    let mut kept = 0u64;
    if let Ok(stats) = csv::convert(data, 7.0, |h| {
        assert!(!h.contains(['\r', '\n']));
        kept += 1;
        Ok(())
    }) {
        assert_eq!(stats.kept, kept);
    }
    let _ = dates::find_date_line(data, None);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = http::content_range_total(s);
        let _ = dates::parse_http_date(s);
        let _ = dates::parse_loose_date(s);
        let _ = dates::retry_after(s, jiff::Timestamp::now());
    }
});
