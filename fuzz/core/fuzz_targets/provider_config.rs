//! Feed providers as the UI API receives them (providers.md §1–§3, feeds.md §1): each module's
//! save-time check and stored form, the provider entity, its `files`/`exclude` globs, the
//! `github` URL forms and the `http` module's URL checks. Never panic; a config a module accepts
//! is accepted again in its stored form; a URL `check_url` accepts is accepted again as it prints
//! (when that still fits [`http::MAX_URL`]), under the same key, and `check_feed_url` accepts
//! only such URLs, without a fragment; a pattern without a wildcard matches exactly its literal
//! path; a glob that matches a path reaches its directories.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::config::model::FeedProviderDef;
use picket_core::modules::download::{github, glob, http, known_ids, normalize};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = github::parse_url(s);
        if let Ok(u) = http::check_url(s) {
            // Printing can percent-encode, so the printed form may outgrow the limit.
            if u.as_str().len() <= http::MAX_URL {
                let again = http::check_url(u.as_str()).unwrap();
                assert_eq!(http::url_key(&again), http::url_key(&u), "{u}");
            }
        }
        if let Ok(u) = http::check_feed_url(s) {
            assert!(http::check_url(s).is_ok(), "{u}");
            assert!(u.fragment().is_none(), "{u}");
        }
        // A pattern and a path, one per line.
        let (pattern, path) = s.split_once('\n').unwrap_or((s, s));
        if glob::check(pattern).is_ok() {
            let m = glob::matches(pattern, path);
            if !glob::is_glob(pattern) {
                // Not its text: in a pattern holding `*`, `\*` and `\\` are literals (`\*#\`
                // selects `*#\`, corpus `literal-escaped-star.txt`).
                let lit = literal(pattern);
                assert_eq!(m, path == lit, "{pattern:?} selects {lit:?}");
                let escaped = glob::escape(&lit);
                if escaped.len() <= glob::MAX_PATTERN {
                    assert!(glob::matches(&escaped, &lit), "{lit:?}");
                }
            }
            let _ = glob::literal_prefix(pattern);
            let segs: Vec<&str> = path.split('/').collect();
            if m {
                for n in 0..segs.len() {
                    assert!(
                        glob::may_reach(pattern, &segs[..n]),
                        "{pattern:?} matches {path:?}"
                    );
                }
            }
        }
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    for id in known_ids() {
        if let Ok(n) = normalize(id, &v) {
            assert!(
                normalize(id, &n.config).is_ok(),
                "{id}: the stored form is refused"
            );
        }
    }
    if let Ok(p) = serde_json::from_value::<FeedProviderDef>(v) {
        let _ = p.secret_refs();
        let _ = p.has_globs();
        for f in p.select() {
            let _ = glob::check(&f);
        }
        let _ = p.trigger.min_interval();
        let _ = serde_json::to_value(&p).unwrap();
    }
});

/// The one path a pattern without a wildcard selects (glob.rs "Literal paths"): in a pattern
/// holding `*`, `\*` stands for `*` and `\\` for `\`; any other character is itself.
fn literal(pattern: &str) -> String {
    if !pattern.contains('*') {
        return pattern.to_string();
    }
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('\\', Some(&n @ ('*' | '\\'))) => {
                out.push(n);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}
