//! `${secret:name}` references in a lookup provider's config (providers.md §4, security.md §4):
//! resolved by the `LookupClient` before a call, and redacted from every message it passes on, so
//! a secret value never reaches a log, a detail, an error or the UI (README §2 "Secrets").
//! Redaction knows every form the code can write a value in (as written, JSON-escaped,
//! Rust-quoted, URL-serialised, form- and percent-encoded) and also checks percent-decoded text;
//! a value shorter than [`MIN_SUBSTRING_SECRET`] is redacted only as a whole token.
//!
//! Every value [`resolve`] fills in is also remembered process-wide (the newest
//! [`MAX_REMEMBERED`]), so `Debug` output of a type holding a resolved config or request, which
//! has no redactor of its own, can redact them too ([`redact_resolved`]).

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;

/// Opens a reference; the name runs to the next `}`.
pub const SECRET_PREFIX: &str = "${secret:";
/// The longest secret name.
pub const MAX_SECRET_NAME: usize = 128;
/// The deepest config nesting resolved (configs come from serde_json, which stops at 128).
const MAX_DEPTH: usize = 64;

/// Why a config's references couldn't be resolved. Names a secret, never a value.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    #[error("secret {0:?} has no value")]
    Missing(String),
    #[error("malformed secret reference (expected ${{secret:name}})")]
    Malformed,
    #[error("config nested too deeply")]
    TooDeep,
}

/// Calls `f` for each reference in `s`: `Ok(name)` per well-formed reference.
fn for_each_ref<'a>(
    s: &'a str,
    mut f: impl FnMut(&'a str) -> Result<(), SecretError>,
) -> Result<(), SecretError> {
    let mut rest = s;
    while let Some(i) = rest.find(SECRET_PREFIX) {
        let after = rest.get(i + SECRET_PREFIX.len()..).unwrap_or("");
        let Some(end) = after.find('}') else {
            return Err(SecretError::Malformed);
        };
        let name = after.get(..end).unwrap_or("");
        if name.is_empty() || name.len() > MAX_SECRET_NAME {
            return Err(SecretError::Malformed);
        }
        f(name)?;
        rest = after.get(end + 1..).unwrap_or("");
    }
    Ok(())
}

/// `s` with each reference replaced by `value(name)`.
fn substitute<'v>(
    s: &str,
    mut value: impl FnMut(&str) -> Result<&'v str, SecretError>,
) -> Result<String, SecretError> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(SECRET_PREFIX) {
        out.push_str(rest.get(..i).unwrap_or(""));
        let after = rest.get(i + SECRET_PREFIX.len()..).unwrap_or("");
        let end = after.find('}').ok_or(SecretError::Malformed)?;
        let name = after.get(..end).unwrap_or("");
        if name.is_empty() || name.len() > MAX_SECRET_NAME {
            return Err(SecretError::Malformed);
        }
        out.push_str(value(name)?);
        rest = after.get(end + 1..).unwrap_or("");
    }
    out.push_str(rest);
    Ok(out)
}

/// The secret names a config references, sorted and deduplicated.
pub fn referenced_names(cfg: &Value) -> Result<Vec<String>, SecretError> {
    fn walk(v: &Value, depth: usize, out: &mut Vec<String>) -> Result<(), SecretError> {
        if depth > MAX_DEPTH {
            return Err(SecretError::TooDeep);
        }
        match v {
            Value::String(s) => for_each_ref(s, |n| {
                out.push(n.to_owned());
                Ok(())
            }),
            Value::Array(a) => a.iter().try_for_each(|x| walk(x, depth + 1, out)),
            Value::Object(m) => m.values().try_for_each(|x| walk(x, depth + 1, out)),
            _ => Ok(()),
        }
    }
    let mut out = Vec::new();
    walk(cfg, 0, &mut out)?;
    out.sort();
    out.dedup();
    Ok(out)
}

/// A config with its references resolved, and the redactor for the values used.
#[derive(Clone, Debug)]
pub struct Resolved {
    pub config: Value,
    pub redactor: Redactor,
}

/// Resolves every `${secret:name}` in the config's string values (object keys are left alone)
/// against `secrets`, and remembers the values used ([`redact_resolved`]).
pub fn resolve(cfg: &Value, secrets: &BTreeMap<String, String>) -> Result<Resolved, SecretError> {
    let (config, used) = resolve_values(cfg, secrets)?;
    remember(&used);
    Ok(Resolved {
        config,
        redactor: Redactor::new(used),
    })
}

/// The resolved config and the `(name, value)` pairs used.
fn resolve_values(
    cfg: &Value,
    secrets: &BTreeMap<String, String>,
) -> Result<(Value, Vec<(String, String)>), SecretError> {
    fn walk(
        v: &Value,
        depth: usize,
        secrets: &BTreeMap<String, String>,
        used: &mut Vec<(String, String)>,
    ) -> Result<Value, SecretError> {
        if depth > MAX_DEPTH {
            return Err(SecretError::TooDeep);
        }
        Ok(match v {
            Value::String(s) if s.contains(SECRET_PREFIX) => Value::String(substitute(s, |name| {
                let value = secrets
                    .get(name)
                    .ok_or_else(|| SecretError::Missing(name.to_owned()))?;
                if !used.iter().any(|(n, _)| n == name) {
                    used.push((name.to_owned(), value.clone()));
                }
                Ok(value.as_str())
            })?),
            Value::Array(a) => Value::Array(
                a.iter()
                    .map(|x| walk(x, depth + 1, secrets, used))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Object(m) => {
                let mut out = serde_json::Map::new();
                for (k, x) in m {
                    out.insert(k.clone(), walk(x, depth + 1, secrets, used)?);
                }
                Value::Object(out)
            }
            other => other.clone(),
        })
    }
    let mut used = Vec::new();
    let config = walk(cfg, 0, secrets, &mut used)?;
    Ok((config, used))
}

/// How many resolved `(name, value)` pairs [`redact_resolved`] remembers (the newest).
pub const MAX_REMEMBERED: usize = 256;

/// The remembered pairs and their redactor.
type Remembered = (Vec<(String, String)>, Arc<Redactor>);

static REMEMBERED: LazyLock<Mutex<Remembered>> = LazyLock::new(Mutex::default);

/// Adds `used` to the remembered pairs (bounded: the oldest go first).
fn remember(used: &[(String, String)]) {
    let mut g = REMEMBERED.lock().unwrap_or_else(|p| p.into_inner());
    let fresh: Vec<&(String, String)> = used
        .iter()
        .filter(|u| !u.1.is_empty() && !g.0.contains(u))
        .collect();
    if fresh.is_empty() {
        return;
    }
    g.0.extend(fresh.into_iter().cloned());
    let over = g.0.len().saturating_sub(MAX_REMEMBERED);
    g.0.drain(..over);
    g.1 = Arc::new(Redactor::new(g.0.clone()));
}

/// Writes what `write` writes as `Debug` output with every resolved secret value redacted
/// ([`redact_resolved`]): for types holding a resolved config or request, wherever in their
/// output a value lands (a URL's host or path, a comparison, …).
pub fn debug_redacted(
    f: &mut std::fmt::Formatter<'_>,
    write: impl Fn(&mut std::fmt::Formatter<'_>) -> std::fmt::Result,
) -> std::fmt::Result {
    struct With<F>(F);
    impl<F: Fn(&mut std::fmt::Formatter<'_>) -> std::fmt::Result> std::fmt::Debug for With<F> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            (self.0)(f)
        }
    }
    let text = if f.alternate() {
        format!("{:#?}", With(write))
    } else {
        format!("{:?}", With(write))
    };
    f.write_str(&redact_resolved(&text))
}

/// `text` with every secret value [`resolve`] filled in (the newest [`MAX_REMEMBERED`]) replaced
/// by its reference: for `Debug` output of resolved configs and requests (README §2 Secrets).
pub fn redact_resolved(text: &str) -> String {
    let r = Arc::clone(&REMEMBERED.lock().unwrap_or_else(|p| p.into_inner()).1);
    r.redact(text)
}

/// The same config with each reference replaced by a placeholder, for validating a stored config
/// whose secrets aren't at hand (core's save path).
pub fn with_placeholders(cfg: &Value) -> Result<Value, SecretError> {
    let names = referenced_names(cfg)?;
    let secrets = names
        .into_iter()
        .map(|n| (n, "secret".to_owned()))
        .collect::<BTreeMap<_, _>>();
    // Placeholders aren't secrets: not remembered.
    resolve_values(cfg, &secrets).map(|(config, _)| config)
}

/// Characters a URL path or query encodes (RFC 3986 unreserved stay as they are).
const URL_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// A secret shorter than this (bytes) is redacted only as a whole token: where the bytes on
/// either side of it are not letters, digits, `-` or `_` (or the text ends). Matching a very
/// short value anywhere would rewrite every message and drop every detail holding its
/// characters; a longer one is redacted wherever it appears.
pub const MIN_SUBSTRING_SECRET: usize = 8;

/// The forms a secret value can take in text the code produces (README §2 "Secrets"): as
/// written; JSON-escaped (serde_json, details); Rust-debug-quoted (serde's error messages and
/// config errors); serialised by the url crate as a path, a path segment, a query, a fragment
/// and user info; form-encoded; and percent-encoded with RFC 3986's unreserved characters kept
/// or with everything but letters and digits encoded. Empty and duplicate forms are left out.
fn encodings(value: &str) -> Vec<String> {
    let quoted = |s: String| {
        s.strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .map(str::to_owned)
    };
    let mut forms = vec![
        value.to_owned(),
        utf8_percent_encode(value, URL_SET).to_string(),
        utf8_percent_encode(value, NON_ALPHANUMERIC).to_string(),
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect(),
    ];
    forms.extend(serde_json::to_string(value).ok().and_then(quoted));
    forms.extend(quoted(format!("{value:?}")));
    if let Ok(base) = url::Url::parse("https://h.invalid/") {
        let mut u = base.clone();
        u.set_path(&format!("/{value}"));
        forms.extend(u.path().strip_prefix('/').map(str::to_owned));
        let mut u = base.clone();
        if let Ok(mut segments) = u.path_segments_mut() {
            segments.clear().push(value);
        }
        forms.extend(u.path().strip_prefix('/').map(str::to_owned));
        let mut u = base.clone();
        u.set_query(Some(value));
        forms.extend(u.query().map(str::to_owned));
        let mut u = base.clone();
        u.set_fragment(Some(value));
        forms.extend(u.fragment().map(str::to_owned));
        let mut u = base.clone();
        if u.set_username(value).is_ok() {
            forms.push(u.username().to_owned());
        }
        let mut u = base;
        if u.set_password(Some(value)).is_ok() {
            forms.extend(u.password().map(str::to_owned));
        }
    }
    let mut out: Vec<String> = Vec::with_capacity(forms.len());
    for f in forms {
        if !f.is_empty() && !out.contains(&f) {
            out.push(f);
        }
    }
    out
}

/// One form of one secret.
#[derive(Clone, Debug)]
struct Needle {
    text: String,
    reference: String,
    /// Only where it stands as a whole token ([`MIN_SUBSTRING_SECRET`]).
    whole_token: bool,
}

/// A byte that continues a token: a short secret next to one isn't redacted.
fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

impl Needle {
    /// `text` with each occurrence replaced; `None` when there is none.
    fn replace(&self, text: &str) -> Option<String> {
        let needle = self.text.as_str();
        if !text.contains(needle) {
            return None;
        }
        if !self.whole_token {
            return Some(text.replace(needle, &self.reference));
        }
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut done = 0;
        let mut found = false;
        for (i, _) in text.match_indices(needle) {
            let end = i + needle.len();
            let before = i.checked_sub(1).and_then(|j| bytes.get(j)).copied();
            let after = bytes.get(end).copied();
            if before.is_some_and(token_byte) || after.is_some_and(token_byte) {
                continue;
            }
            out.push_str(text.get(done..i).unwrap_or(""));
            out.push_str(&self.reference);
            done = end;
            found = true;
        }
        if !found {
            return None;
        }
        out.push_str(text.get(done..).unwrap_or(""));
        Some(out)
    }
}

/// Replaces resolved secret values in text with their `${secret:name}` reference, in every form
/// the code can write them ([`encodings`]).
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    /// Longest first, so a value containing another is replaced whole.
    needles: Vec<Needle>,
}

impl Redactor {
    fn new(used: Vec<(String, String)>) -> Self {
        let mut needles: Vec<Needle> = Vec::new();
        for (name, value) in used {
            if value.is_empty() {
                continue;
            }
            let reference = format!("{SECRET_PREFIX}{name}}}");
            let whole_token = value.len() < MIN_SUBSTRING_SECRET;
            for text in encodings(&value) {
                if !needles.iter().any(|n| n.text == text) {
                    needles.push(Needle {
                        text,
                        reference: reference.clone(),
                        whole_token,
                    });
                }
            }
        }
        needles.sort_by_key(|n| std::cmp::Reverse(n.text.len()));
        Self { needles }
    }

    /// True when there is nothing to redact.
    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    fn redact_forms(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for n in &self.needles {
            if let Some(r) = n.replace(&out) {
                out = r;
            }
        }
        out
    }

    /// `text` with every secret value replaced by its reference. A value hidden by a
    /// percent-encoding [`encodings`] doesn't produce (another client's encode set, lower-case
    /// hex) is caught on the percent-decoded text, which is then returned, redacted.
    pub fn redact(&self, text: &str) -> String {
        let out = self.redact_forms(text);
        if self.needles.is_empty() || !out.contains('%') {
            return out;
        }
        let decoded = percent_encoding::percent_decode_str(&out).decode_utf8_lossy();
        if decoded == out {
            return out;
        }
        let redacted = self.redact_forms(&decoded);
        if redacted == decoded { out } else { redacted }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// README §2 Bounded: the process-wide record of resolved values keeps the newest
    /// MAX_REMEMBERED; placeholders (the save path's check) aren't recorded.
    #[test]
    fn remembered_values_are_bounded_and_skip_placeholders() {
        let names: Vec<String> = (0..MAX_REMEMBERED + 20).map(|i| format!("n{i}")).collect();
        let secrets: BTreeMap<String, String> = names
            .iter()
            .map(|n| (n.clone(), format!("bound-test-value-{n}")))
            .collect();
        let cfg = Value::Array(names.iter().map(|n| json!(format!("${{secret:{n}}}"))).collect());
        resolve(&cfg, &secrets).unwrap();
        let g = REMEMBERED.lock().unwrap();
        assert!(g.0.len() <= MAX_REMEMBERED, "{}", g.0.len());
        assert!(
            g.0.iter().any(|(n, _)| *n == format!("n{}", MAX_REMEMBERED + 19)),
            "the newest kept"
        );
        drop(g);
        with_placeholders(&json!({"h": "Bearer ${secret:placeholder_only}"})).unwrap();
        assert!(
            !REMEMBERED
                .lock()
                .unwrap()
                .0
                .iter()
                .any(|(n, _)| n == "placeholder_only")
        );
    }

    fn secrets() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("key".to_owned(), "s3cr3t/value".to_owned()),
            ("other".to_owned(), "x".to_owned()),
        ])
    }

    #[test]
    fn resolves_strings_only() {
        let cfg = json!({"headers": {"Authorization": "Bearer ${secret:key}", "${secret:key}": "k"},
                         "list": ["a${secret:other}b${secret:other}"], "n": 1});
        let r = resolve(&cfg, &secrets()).unwrap();
        assert_eq!(r.config["headers"]["Authorization"], "Bearer s3cr3t/value");
        assert_eq!(r.config["headers"]["${secret:key}"], "k");
        assert_eq!(r.config["list"][0], "axbx");
        assert_eq!(r.config["n"], 1);
        assert_eq!(referenced_names(&cfg).unwrap(), vec!["key", "other"]);
    }

    #[test]
    fn errors_name_the_secret_not_a_value() {
        let cfg = json!({"h": "${secret:nope}"});
        let e = resolve(&cfg, &secrets()).unwrap_err();
        assert_eq!(e, SecretError::Missing("nope".into()));
        assert_eq!(
            resolve(&json!("${secret:key"), &secrets()).unwrap_err(),
            SecretError::Malformed
        );
        assert_eq!(
            resolve(&json!("${secret:}"), &secrets()).unwrap_err(),
            SecretError::Malformed
        );
    }

    #[test]
    fn redacts_raw_and_encoded_values() {
        let r = resolve(&json!({"u": "https://x/?k=${secret:key}"}), &secrets()).unwrap();
        let red = r.redactor;
        assert_eq!(
            red.redact("error for https://x/?k=s3cr3t/value"),
            "error for https://x/?k=${secret:key}"
        );
        assert_eq!(red.redact("k=s3cr3t%2Fvalue"), "k=${secret:key}");
        assert_eq!(red.redact("nothing here"), "nothing here");
    }

    fn redactor(value: &str) -> Redactor {
        let secrets = BTreeMap::from([("k".to_owned(), value.to_owned())]);
        resolve(&json!("${secret:k}"), &secrets).unwrap().redactor
    }

    /// README §2 Secrets: every encoding the code can produce is redacted: JSON escaping, Rust
    /// debug quoting (serde's and our config errors), the url crate's serialisation per
    /// component, form encoding and percent forms.
    #[test]
    fn redacts_every_encoding() {
        let value = "a b/c\"d\\e?f#g&h+i%j";
        let red = redactor(value);
        let json = serde_json::to_string(value).unwrap();
        let debug = format!("{value:?}");
        let mut url = url::Url::parse("https://api.example.net/").unwrap();
        url.set_path(&format!("/v1/{value}"));
        url.set_query(Some(&format!("key={value}")));
        let mut forms = vec![
            value.to_owned(),
            json.trim_matches('"').to_owned(),
            debug.trim_matches('"').to_owned(),
            url.to_string(),
            url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>(),
        ];
        let mut u2 = url::Url::parse("https://h.example/").unwrap();
        u2.path_segments_mut().unwrap().push(value);
        forms.push(u2.to_string());
        let mut u3 = url::Url::parse("https://h.example/").unwrap();
        u3.set_fragment(Some(value));
        forms.push(u3.to_string());
        let mut u4 = url::Url::parse("https://h.example/").unwrap();
        u4.set_username(value).unwrap();
        u4.set_password(Some(value)).unwrap();
        forms.push(u4.to_string());
        // Whole messages as serde_json would print them.
        forms.push(serde_json::json!({"echo": value}).to_string());
        for f in forms {
            let out = red.redact(&format!("error: {f} end"));
            for leak in ["g&h", "g%26h", "f#g", "f%23g", "i%j", "i%25j", "h+i", "h%2Bi"] {
                assert!(!out.contains(leak), "{f} -> {out}");
            }
            assert!(out.contains("${secret:k}"), "{f} -> {out}");
        }
        // A space as the url crate writes it in a path.
        let red = redactor("a b/c");
        assert_eq!(
            red.redact("GET https://x/a%20b/c failed"),
            "GET https://x/${secret:k} failed"
        );
        // Any other percent-encoding is caught on the decoded text.
        assert!(!red.redact("x a%20b%2fc y").contains("a b/c"));
        assert!(red.redact("x a%20b%2fc y").contains("${secret:k}"));
    }

    /// A secret shorter than [`MIN_SUBSTRING_SECRET`] is redacted only as a whole token, so a
    /// one-character secret doesn't swallow every message.
    #[test]
    fn short_secrets_only_as_whole_tokens() {
        let red = redactor("x");
        assert_eq!(red.redact("example x.example"), "example ${secret:k}.example");
        assert_eq!(red.redact("Bearer x"), "Bearer ${secret:k}");
        assert_eq!(red.redact("max xx"), "max xx");
        let red = redactor("abc123");
        assert_eq!(
            red.redact("abc123.dns.nextdns.io /abc123 abc1234"),
            "${secret:k}.dns.nextdns.io /${secret:k} abc1234"
        );
        // From the minimum on, anywhere.
        let red = redactor("abcd1234");
        assert_eq!(red.redact("xabcd1234y"), "x${secret:k}y");
    }

    #[test]
    fn placeholders_validate_without_values() {
        let v = with_placeholders(&json!({"h": "Bearer ${secret:a}"})).unwrap();
        assert_eq!(v["h"], "Bearer secret");
    }
}
