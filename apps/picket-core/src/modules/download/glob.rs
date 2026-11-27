//! The globs of a feed provider's `files` and `exclude` (feeds.md §1 "Provider feeds"): `*`
//! matches within one path segment, `**` (a whole segment) across any number of segments, and
//! every other character matches itself. A pattern without `*` is a plain path.
//!
//! **Literal paths** ([`escape`]): in a pattern holding `*`, `\*` stands for a literal `*` and
//! `\\` for a literal `\` (any other `\` is itself). Core adds a file's path to `files` (adding a
//! feed) or `exclude` (deleting one) in this form, so a path that holds `*` selects or excludes
//! only itself, never its siblings (`?` and `[` aren't wildcards here).
//!
//! Matching is bounded: at most [`MAX_PATTERN`] bytes per pattern, and the segment matcher
//! memoises its states, so no pattern takes more than `segments × pattern segments` steps.

/// The longest pattern.
pub const MAX_PATTERN: usize = 512;

/// One element of a pattern segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Byte(u8),
    Star,
}

/// One pattern segment: `**`, or bytes and stars.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Seg {
    Any,
    Toks(Vec<Tok>),
}

/// The segments of a pattern holding `*`, with `\*` and `\\` read as literals.
fn parse(pattern: &str) -> Vec<Seg> {
    let b = pattern.as_bytes();
    let mut segs = Vec::new();
    let mut cur: Vec<Tok> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if matches!(b.get(i + 1), Some(b'*' | b'\\')) => {
                cur.push(Tok::Byte(b[i + 1]));
                i += 2;
                continue;
            }
            b'*' => cur.push(Tok::Star),
            b'/' => segs.push(std::mem::take(&mut cur)),
            c => cur.push(Tok::Byte(c)),
        }
        i += 1;
    }
    segs.push(cur);
    segs.into_iter()
        .map(|t| {
            if t == [Tok::Star, Tok::Star] {
                Seg::Any
            } else {
                Seg::Toks(t)
            }
        })
        .collect()
}

/// True when `p` holds a wildcard (an unescaped `*`): a pattern for a module that lists files.
pub fn is_glob(p: &str) -> bool {
    p.contains('*')
        && parse(p).iter().any(|s| match s {
            Seg::Any => true,
            Seg::Toks(t) => t.contains(&Tok::Star),
        })
}

/// A literal path as a pattern that matches only it: in a path holding `*`, each `\` becomes
/// `\\` and each `*` becomes `\*`; any other path is already its own pattern.
pub fn escape(path: &str) -> String {
    if !path.contains('*') {
        return path.to_string();
    }
    let mut out = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        if c == '\\' || c == '*' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Checks a pattern's syntax: a `**` must be a whole segment, and at most 512 bytes.
pub fn check(p: &str) -> Result<(), String> {
    if p.len() > MAX_PATTERN {
        return Err(format!("a pattern is at most {MAX_PATTERN} bytes"));
    }
    if p.chars().any(char::is_control) {
        return Err("a pattern can't hold control characters".into());
    }
    if p.contains('*') {
        for seg in parse(p) {
            if let Seg::Toks(t) = seg
                && t.windows(2).any(|w| w == [Tok::Star, Tok::Star])
            {
                return Err(format!("{p:?}: ** must be a whole path segment"));
            }
        }
    }
    Ok(())
}

/// True when `path` matches `pattern`.
pub fn matches(pattern: &str, path: &str) -> bool {
    if pattern.len() > MAX_PATTERN {
        return false;
    }
    if !pattern.contains('*') {
        return pattern == path;
    }
    let p = parse(pattern);
    let s: Vec<&str> = path.split('/').collect();
    // memo[i][j]: pattern segments from i match path segments from j.
    let mut memo = vec![vec![None::<bool>; s.len() + 1]; p.len() + 1];
    seg_match(&p, &s, 0, 0, &mut memo)
}

fn seg_match(p: &[Seg], s: &[&str], i: usize, j: usize, memo: &mut [Vec<Option<bool>>]) -> bool {
    if let Some(v) = memo[i][j] {
        return v;
    }
    let r = if i == p.len() {
        j == s.len()
    } else if p[i] == Seg::Any {
        // Zero or more whole segments.
        (j..=s.len()).any(|k| seg_match(p, s, i + 1, k, memo))
    } else if j == s.len() {
        false
    } else {
        seg_one(&p[i], s[j].as_bytes()) && seg_match(p, s, i + 1, j + 1, memo)
    };
    memo[i][j] = Some(r);
    r
}

fn seg_one(p: &Seg, s: &[u8]) -> bool {
    match p {
        Seg::Any => true,
        Seg::Toks(t) => one(t, s),
    }
}

/// One segment against a pattern segment where `*` matches any run of bytes (iterative, with
/// the usual single-backtrack-point algorithm: linear in practice, quadratic at worst).
fn one(p: &[Tok], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while si < s.len() {
        match p.get(pi) {
            Some(Tok::Byte(b)) if *b == s[si] => {
                pi += 1;
                si += 1;
            }
            Some(Tok::Star) => {
                star = Some(pi);
                pi += 1;
                mark = si;
            }
            _ => {
                if let Some(st) = star {
                    pi = st + 1;
                    mark += 1;
                    si = mark;
                } else {
                    return false;
                }
            }
        }
    }
    while p.get(pi) == Some(&Tok::Star) {
        pi += 1;
    }
    pi == p.len()
}

/// The directory prefix a pattern can reach: the leading segments without a wildcard (`""` for
/// a pattern that starts with one). A walk descends only into directories on such a prefix, or
/// below one whose rest may hold `**`.
pub fn literal_prefix(pattern: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let segs: Vec<&str> = pattern.split('/').collect();
    for (i, seg) in segs.iter().enumerate() {
        if i + 1 == segs.len() || seg.contains('*') {
            break;
        }
        out.push(*seg);
    }
    out
}

/// True when a directory `dir` (segments) may hold a file `pattern` matches: the pattern's
/// directory part can match `dir` itself or something below it.
pub fn may_reach(pattern: &str, dir: &[&str]) -> bool {
    let p: Vec<Seg> = if pattern.contains('*') {
        parse(pattern)
    } else {
        pattern
            .split('/')
            .map(|s| Seg::Toks(s.bytes().map(Tok::Byte).collect()))
            .collect()
    };
    // The pattern's directory segments: all but the last, unless the last is `**`, which
    // matches directories too.
    let dirs = match p.last() {
        Some(Seg::Any) => &p[..],
        _ => &p[..p.len().saturating_sub(1)],
    };
    reach(dirs, dir, 0, 0)
}

fn reach(p: &[Seg], d: &[&str], i: usize, j: usize) -> bool {
    if j == d.len() {
        // The whole directory matched a prefix of the pattern: files or deeper directories
        // below it may match.
        return true;
    }
    if i == p.len() {
        return false;
    }
    if p[i] == Seg::Any {
        // `**` absorbs any number of the directory's segments: anything below may match.
        return true;
    }
    seg_one(&p[i], d[j].as_bytes()) && reach(p, d, i + 1, j + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stars_stay_in_a_segment_and_double_stars_cross() {
        assert!(matches("adblock/*.txt", "adblock/tif.txt"));
        assert!(!matches("adblock/*.txt", "adblock/sub/tif.txt"));
        assert!(!matches("adblock/*.txt", "hosts/tif.txt"));
        assert!(matches(
            "adblock/*-onlydomains.txt",
            "adblock/pro-onlydomains.txt"
        ));
        assert!(matches("**/*.txt", "a.txt"));
        assert!(matches("**/*.txt", "a/b/c.txt"));
        assert!(matches("lists/**/list.json", "lists/x/list.json"));
        assert!(matches("lists/**/list.json", "lists/list.json"));
        assert!(!matches("lists/**/list.json", "other/x/list.json"));
        assert!(matches("a/b.txt", "a/b.txt"));
        assert!(!matches("a/b.txt", "a/bxtxt"));
        assert!(matches("*", "anything"));
        assert!(!matches("*", "a/b"));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(!matches("a*b*c", "aXXbYY"));
    }

    #[test]
    fn checks_and_reach() {
        assert!(check("a/**/b").is_ok());
        assert!(check("a/x**/b").is_err());
        assert!(check(&"a".repeat(600)).is_err());
        assert!(is_glob("a/*.txt") && !is_glob("a/b.txt"));
        assert_eq!(literal_prefix("adblock/*.txt"), vec!["adblock"]);
        assert_eq!(literal_prefix("lists/x/list.json"), vec!["lists", "x"]);
        assert!(literal_prefix("*.txt").is_empty());
        assert!(may_reach("adblock/*.txt", &["adblock"]));
        assert!(!may_reach("adblock/*.txt", &["hosts"]));
        assert!(!may_reach("adblock/*.txt", &["adblock", "sub"]));
        assert!(may_reach("lists/**/list.json", &["lists", "a", "b"]));
        assert!(may_reach("lists/*/list.json", &["lists", "a"]));
        assert!(!may_reach("lists/*/list.json", &["lists", "a", "b"]));
        assert!(may_reach("**/x.txt", &["any", "depth"]));
        assert!(may_reach("x.txt", &[]));
        assert!(!may_reach("x.txt", &["sub"]));
        // A trailing `**` matches files at any depth below, so the walk goes there.
        assert!(matches("lists/**", "lists/sub/x.txt"));
        assert!(may_reach("lists/**", &["lists", "sub"]));
        assert!(!may_reach("lists/**", &["hosts"]));
        assert!(may_reach("**", &["any", "depth"]));
    }

    /// feeds.md §1: a literal path added to `files` or `exclude` selects only itself, even when
    /// it holds `*` (`?` and `[` match themselves anyway).
    #[test]
    fn escaped_literal_paths_match_only_themselves() {
        for path in [
            "lists/a*b.txt",
            "x/*",
            "back\\slash*.txt",
            "q?x[1].txt",
            "plain/a.txt",
            "**",
        ] {
            let e = escape(path);
            assert!(matches(&e, path), "{e:?} vs {path:?}");
            assert!(!is_glob(&e), "{e:?} is no glob");
            assert!(check(&e).is_ok(), "{e:?}");
        }
        assert_eq!(
            escape("plain/a.txt"),
            "plain/a.txt",
            "a path without * is unchanged"
        );
        let e = escape("lists/a*b.txt");
        assert_eq!(e, "lists/a\\*b.txt");
        assert!(!matches(&e, "lists/aXb.txt"), "a sibling isn't selected");
        assert!(!matches(&escape("**"), "a/b"));
        assert!(!matches(&escape("x/*"), "x/y"));
        assert!(matches("q?x[1].txt", "q?x[1].txt") && !matches("q?x[1].txt", "qax1.txt"));
        // An escaped star beside a real one.
        assert!(matches("a\\**", "a*xyz") && !matches("a\\**", "axyz"));
        assert!(is_glob("a\\**"));
        // A directory a literal path names is reached, its siblings aren't.
        assert!(may_reach(&escape("d*r/x.txt"), &["d*r"]));
        assert!(!may_reach(&escape("d*r/x.txt"), &["dXr"]));
    }

    #[test]
    fn pathological_patterns_stay_fast() {
        let p = "*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let s = "a".repeat(400);
        assert!(!matches(p, &s));
        let p = vec!["**"; 100].join("/") + "/x";
        let s = vec!["d"; 100].join("/");
        assert!(!matches(&p, &s));
    }
}
