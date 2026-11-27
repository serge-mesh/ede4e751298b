//! Feed providers as the UI API receives them (providers.md §1–§3, feeds.md §1): each module's
//! save-time check and stored form, the provider entity, its `files`/`exclude` globs, the
//! `github` URL forms and `http` file paths under a base URL. Never panic; a config a module
//! accepts is accepted again in its stored form; a file `resolve` accepts stays under the base
//! and maps back to the same URL; a pattern without a wildcard matches exactly its literal path;
//! a glob that matches a path reaches its directories.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::config::model::FeedProviderDef;
use picket_core::modules::download::{github, glob, http, known_ids, normalize};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = github::parse_url(s);
        let _ = http::check_base(s);
        let base = http::check_base("https://lists.example/dir/").unwrap();
        if let Ok(u) = http::resolve(&base, s) {
            assert!(u.as_str().starts_with(base.as_str()), "{u} is outside {base}");
            if let Some(f) = http::file_of(&base, &u) {
                assert_eq!(http::resolve(&base, &f).ok().as_ref(), Some(&u), "{f:?}");
            }
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
