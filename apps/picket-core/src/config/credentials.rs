//! Credentials in provider configs (README §2 Secrets; security.md §4: provider secrets are
//! stored in `secrets`, never returned by the UI API). A config carries a credential only as a
//! `${secret:name}` reference, resolved just before use (providers.md §2, §4). A field's name
//! can't always tell a credential, so the rules are strict where they can be:
//!
//! - a header map (`headers`, providers.md §3 `http`, §5 `http_json`): every header outside
//!   [`LITERAL_HEADERS`] holds only references, whatever its name (`X-Key`,
//!   `Ocp-Apim-Subscription-Key`, …); a `headers` value that isn't a map holds only references;
//! - any field whose name names a credential (`Authorization`, `Cookie`, `token`, `password`,
//!   `secret`, `license`, `*key`, …), whatever is nested under it;
//! - any value that starts with an auth scheme (`Bearer …`, `Basic …`, `Token …`);
//! - in a URL, read as the HTTP client reads it, by the `url` crate (WHATWG: surrounding spaces
//!   and C0 controls dropped, tabs and newlines removed, `\` as `/`, names percent-decoded; text
//!   it doesn't parse, such as a template with a placeholder port, by a hand reader that
//!   follows the same rules): its user info (`https://user:pass@host`) and credential-named
//!   query parameters (`?apikey=…`, `?%61pikey=…`, `?key=…`, `?k=…`, `?license=…`, `?sig=…`).
//!
//! Query parameter names stay a heuristic (a feed URL's `?hostformat=hosts` is no credential):
//! put an API's key in a header where the API allows it.
//!
//! [`find_literal`] tells a save where one is written in clear (the save is refused, even when
//! it was already stored); [`mask`] hides any that are there anyway (an older release's save)
//! from every UI response, stored copy and journal. [`mask_generic`] is the name-based subset
//! the journal applies to every other entity.

use serde_json::{Map, Value};

use super::journal::{only_secret_refs, sensitive_key};

const MASK: &str = "<redacted>";

/// Header names whose value may be written in clear in a provider's header map; any other
/// header takes only `${secret:…}` references. Matched without case, as written (no trimming).
pub const LITERAL_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "cache-control",
    "content-type",
    "pragma",
    "user-agent",
];

/// Name-based detection for any entity (`generic`), or the provider-config rules (`strict`).
#[derive(Clone, Copy, PartialEq)]
enum Rules {
    Generic,
    Strict,
}

/// Where a value sits.
#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Plain,
    /// Under a credential-named field or a non-allowlisted header: only references.
    Credential,
    /// The members of a header map.
    Headers,
}

/// A name with case and separators dropped (`Ocp-Apim-Subscription-Key` → `ocpapimsubscriptionkey`).
fn squash(k: &str) -> String {
    k.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// A field name that names a credential.
pub fn credential_key(k: &str) -> bool {
    if sensitive_key(k) {
        return true;
    }
    let k = k.to_ascii_lowercase();
    ["session", "x-auth", "access_key", "accesskey", "privatekey"]
        .iter()
        .any(|w| k.contains(w))
}

/// The provider-config form: also `license`, `subscription`, `auth…`, `signature` and any name
/// ending in `key`/`keys` (`X-Key`, `license_key`, `client-key`).
fn strict_credential_key(k: &str) -> bool {
    if credential_key(k) {
        return true;
    }
    let n = squash(k);
    n.ends_with("key")
        || n.ends_with("keys")
        || ["licen", "subscription", "auth", "signature", "passw", "jwt"]
            .iter()
            .any(|w| n.contains(w))
}

fn key_rule(rules: Rules, k: &str) -> bool {
    match rules {
        Rules::Generic => credential_key(k),
        Rules::Strict => strict_credential_key(k),
    }
}

/// A URL query parameter (its decoded name) that carries a credential.
fn credential_param(rules: Rules, name: &str) -> bool {
    let n = squash(name);
    key_rule(rules, name)
        || matches!(n.as_str(), "key" | "auth" | "sig" | "signature" | "pass" | "pwd")
        || (rules == Rules::Strict
            && matches!(
                n.as_str(),
                "k" | "sid" | "code" | "otp" | "pin" | "ak" | "sk" | "access" | "hmac"
            ))
}

/// A value that is a credential in clear: not empty, and not only `${secret:…}` references.
fn literal(s: &str) -> bool {
    !s.trim().is_empty() && !only_secret_refs(s)
}

/// `Bearer abc`, `Basic dXNlcjpwYXNz`, … with something other than references after the scheme.
fn scheme_literal(s: &str) -> bool {
    let t = s.trim_start();
    ["bearer", "basic", "token", "digest", "bot", "apikey"]
        .iter()
        .any(|scheme| {
            t.get(..scheme.len())
                .is_some_and(|w| w.eq_ignore_ascii_case(scheme))
                && t[scheme.len()..].starts_with(char::is_whitespace)
                && literal(&t[scheme.len()..])
        })
}

/// Percent-decoding as servers read URL parts (`%XX` a byte, invalid UTF-8 replaced); in a
/// query (`application/x-www-form-urlencoded`) `+` is a space too.
fn decode(s: &str, plus_is_space: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' if plus_is_space => out.push(b' '),
            b'%' if i + 2 < b.len() => match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    (c as char).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// The URL with its literal credentials masked, or `None` when it holds none (or isn't one).
/// Text the `url` crate parses (the HTTP client's parser) is read through it; other text (a
/// template with a placeholder port, …) by [`text_url_masked`].
fn url_masked(rules: Rules, s: &str) -> Option<String> {
    match url::Url::parse(s) {
        Ok(u) => parsed_url_masked(rules, &u),
        Err(_) => text_url_masked(rules, s),
    }
}

/// The special schemes, whose URLs have an authority (and so user info) and a query read as the
/// HTTP client reads them.
fn special(scheme: &str) -> bool {
    ["http", "https", "ws", "wss", "ftp"]
        .iter()
        .any(|x| scheme.eq_ignore_ascii_case(x))
}

/// [`url_masked`] for a parsed URL: its user info and query as `url` reads them; the masked text
/// is written from its parts.
fn parsed_url_masked(rules: Rules, u: &url::Url) -> Option<String> {
    if !special(u.scheme()) {
        return None;
    }
    // The user info as one text: a reference may hold the `:` that splits name and password.
    let mut userinfo = decode(u.username(), false);
    if let Some(p) = u.password() {
        userinfo.push(':');
        userinfo.push_str(&decode(p, false));
    }
    let user_literal = literal(&userinfo);
    let mut changed = user_literal;
    let query = u.query().map(|q| mask_query(rules, q, &mut changed));
    if !changed {
        return None;
    }
    let mut out = format!("{}://", u.scheme());
    if user_literal {
        out.push_str(MASK);
        out.push('@');
    } else if !userinfo.is_empty() {
        // Only references: as written, not percent-encoded, so they stay references.
        out.push_str(&userinfo);
        out.push('@');
    }
    out.push_str(u.host_str().unwrap_or_default());
    if let Some(port) = u.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(u.path());
    if let Some(q) = query {
        out.push('?');
        out.push_str(&q);
    }
    if let Some(f) = u.fragment() {
        out.push('#');
        out.push_str(f);
    }
    Some(out)
}

/// The query `q` (no `?`, no fragment) with each credential-named parameter's literal value
/// masked; `changed` is set when one is. `&` separates pairs; some servers also split on `;`.
fn mask_query(rules: Rules, q: &str, changed: &mut bool) -> String {
    let mut out = String::with_capacity(q.len());
    let mut start = 0;
    for (i, c) in q.char_indices().chain([(q.len(), '&')]) {
        if c != '&' && c != ';' {
            continue;
        }
        let pair = &q[start..i];
        match pair.split_once('=') {
            Some((n, v)) if credential_param(rules, decode(n, true).trim()) && literal(&decode(v, true)) => {
                *changed = true;
                out.push_str(n);
                out.push('=');
                out.push_str(MASK);
            }
            _ => out.push_str(pair),
        }
        if i < q.len() {
            out.push(c);
        }
        start = i + 1;
    }
    out
}

/// [`url_masked`] for text the `url` crate doesn't parse, read by hand as its parser would
/// (WHATWG: surrounding spaces and C0 controls dropped, tabs and newlines removed, `\` as `/`
/// after a special scheme): user info and query parameters are masked as in a parsed URL.
fn text_url_masked(rules: Rules, s: &str) -> Option<String> {
    let s: String = s
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let colon = s.find(':')?;
    if !special(&s[..colon]) {
        return None;
    }
    let after = &s[colon + 1..];
    let slashes = after.len() - after.trim_start_matches(['/', '\\']).len();
    let (head, rest) = s.split_at(colon + 1 + slashes);
    let auth_end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    let mut changed = false;
    let authority = match authority.rfind('@') {
        Some(at) if literal(&decode(&authority[..at], false)) => {
            changed = true;
            format!("{MASK}@{}", &authority[at + 1..])
        }
        _ => authority.to_string(),
    };
    let (path, query_and_frag) = match tail.find('?') {
        Some(q) => tail.split_at(q),
        None => (tail, ""),
    };
    let mut query = String::new();
    if let Some(qf) = query_and_frag.strip_prefix('?') {
        let (q, frag) = match qf.find('#') {
            Some(h) => qf.split_at(h),
            None => (qf, ""),
        };
        query.push('?');
        query.push_str(&mask_query(rules, q, &mut changed));
        query.push_str(frag);
    }
    changed.then(|| format!("{head}{authority}{path}{query}"))
}

/// The JSON path (`headers.Authorization`, `url`) of the first credential written in clear in
/// a provider config `v`, if any.
pub fn find_literal(v: &Value) -> Option<String> {
    find(Rules::Strict, v, String::new(), Ctx::Plain)
}

fn join(path: &str, k: &str) -> String {
    if path.is_empty() {
        k.to_string()
    } else {
        format!("{path}.{k}")
    }
}

/// The context of the member `k` (holding `x`) of an object in context `ctx`.
fn child(rules: Rules, ctx: Ctx, k: &str, x: &Value) -> Ctx {
    match ctx {
        Ctx::Credential => Ctx::Credential,
        Ctx::Headers if LITERAL_HEADERS.iter().any(|h| k.eq_ignore_ascii_case(h)) => Ctx::Plain,
        Ctx::Headers => Ctx::Credential,
        Ctx::Plain if key_rule(rules, k) => Ctx::Credential,
        Ctx::Plain if rules == Rules::Strict && k.eq_ignore_ascii_case("headers") => {
            if x.is_object() {
                Ctx::Headers
            } else {
                Ctx::Credential
            }
        }
        Ctx::Plain => Ctx::Plain,
    }
}

fn flagged(rules: Rules, s: &str, ctx: Ctx) -> bool {
    (ctx == Ctx::Credential && literal(s)) || scheme_literal(s) || url_masked(rules, s).is_some()
}

fn find(rules: Rules, v: &Value, path: String, ctx: Ctx) -> Option<String> {
    match v {
        Value::Object(m) => m
            .iter()
            .find_map(|(k, x)| find(rules, x, join(&path, k), child(rules, ctx, k, x))),
        Value::Array(a) => a
            .iter()
            .enumerate()
            .find_map(|(i, x)| find(rules, x, join(&path, &i.to_string()), ctx)),
        Value::String(s) => flagged(rules, s, ctx).then_some(path),
        Value::Number(_) if ctx == Ctx::Credential => Some(path),
        _ => None,
    }
}

/// A provider config `v` with every credential [`find_literal`] would report masked;
/// references stay.
pub fn mask(v: &Value) -> Value {
    mask_in(Rules::Strict, v, Ctx::Plain)
}

/// Masks credentials by field name, auth scheme and URL in any entity's value (the journal).
pub fn mask_generic(v: &Value) -> Value {
    mask_in(Rules::Generic, v, Ctx::Plain)
}

fn mask_in(rules: Rules, v: &Value, ctx: Ctx) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (k.clone(), mask_in(rules, x, child(rules, ctx, k, x))))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|x| mask_in(rules, x, ctx)).collect()),
        Value::String(s) if (ctx == Ctx::Credential && literal(s)) || scheme_literal(s) => {
            Value::String(MASK.into())
        }
        Value::String(s) => match url_masked(rules, s) {
            Some(m) => Value::String(m),
            None => Value::String(s.clone()),
        },
        Value::Number(_) if ctx == Ctx::Credential => Value::String(MASK.into()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finds_credentials_in_clear() {
        for (v, path) in [
            (
                json!({"headers": {"Authorization": "Bearer abc"}}),
                "headers.Authorization",
            ),
            (json!({"headers": {"X-Api-Key": "k-123"}}), "headers.X-Api-Key"),
            (json!({"headers": {"X-Custom": "Bearer abc"}}), "headers.X-Custom"),
            (json!({"token": "ghp_abc"}), "token"),
            (json!({"url": "https://api.example/v1?apikey=abc&q=1"}), "url"),
            (json!({"url": "https://api.example/v1?key=abc"}), "url"),
            (json!({"url": "https://user:pw@api.example/v1"}), "url"),
            (json!({"credentials": {"user": "u"}}), "credentials.user"),
            (json!({"api_key": 12345}), "api_key"),
            (json!({"list": [{"cookie": "sid=1"}]}), "list.0.cookie"),
        ] {
            assert_eq!(find_literal(&v).as_deref(), Some(path), "{v}");
        }
    }

    #[test]
    fn references_and_plain_fields_pass() {
        for v in [
            json!({"headers": {"Authorization": "Bearer ${secret:am_rt}", "Accept": "application/json"}}),
            json!({"headers": {"X-Api-Key": "${secret:k}"}}),
            json!({"token": "${secret:gh}"}),
            json!({"url": "https://api.example/v1/domain/{domain}?apikey=${secret:k}&format=json"}),
            json!({"url": "https://${secret:u}:${secret:p}@api.example/x"}),
            json!({"url": "https://github.com/o/r/blob/main/list.txt", "owner": "o", "token": ""}),
            json!({"transport": "dot", "servers": [{"ip": "9.9.9.9", "tls_host": "dns.quad9.net"}],
                   "self_test": {"name": "isitblocked.org", "expect": "block", "cron": "0 * * * *"}}),
            json!({"verdict": {"pointer": "/risk_score", "block_if": ">= 7.0"}, "min_risk_score": 7.0}),
        ] {
            assert_eq!(find_literal(&v), None, "{v}");
        }
    }

    #[test]
    fn masking_keeps_references_and_hides_the_rest() {
        let v = json!({
            "url": "https://u:p@api.example/v1?apikey=abc&q=1#f",
            "headers": {"Authorization": "Bearer abc", "X-Ref": "${secret:x}", "Accept": "text/plain"},
            "other": "Basic dXNlcjpwYXNz"
        });
        let m = mask(&v);
        assert_eq!(
            m["url"],
            "https://<redacted>@api.example/v1?apikey=<redacted>&q=1#f"
        );
        assert_eq!(m["headers"]["Authorization"], MASK);
        assert_eq!(m["headers"]["X-Ref"], "${secret:x}");
        assert_eq!(m["headers"]["Accept"], "text/plain");
        assert_eq!(m["other"], MASK);
        let text = m.to_string();
        for leak in ["u:p", "apikey=abc", "Bearer abc", "dXNlcjpwYXNz"] {
            assert!(!text.contains(leak), "{leak} left in {text}");
        }
        // A masked value saved back is refused like any literal (it isn't a reference).
        assert!(find_literal(&m).is_some());
    }

    #[test]
    fn encoded_and_padded_urls_are_read_as_the_http_client_reads_them() {
        // CC1 (a): the HTTP client percent-decodes query names, drops leading and trailing
        // spaces and C0 controls, removes tabs and newlines anywhere and reads `\` as `/`.
        for v in [
            json!({"url": "https://api.example/v1?%61pikey=value"}),
            json!({"url": "https://api.example/v1?api%5Fkey=value"}),
            json!({"url": "  https://api.example/v1?apikey=value"}),
            json!({"url": "\thttps://api.example/v1?apikey=value"}),
            json!({"url": "https://api.example/v1?api\tkey=value"}),
            json!({"url": "HTTPS:\\\\api.example\\v1?apikey=value"}),
            json!({"url": "https:api.example/v1?apikey=value"}),
            json!({"url": "https://api.example/v1?a=1;apikey=value"}),
            json!({"url": " https://user:pw@api.example/v1"}),
            json!({"url": "https://us%65r:pw@api.example/v1"}),
        ] {
            assert_eq!(find_literal(&v).as_deref(), Some("url"), "{v}");
            let m = mask(&v).to_string();
            assert!(!m.contains("value") && !m.contains("pw"), "{m}");
        }
    }

    /// URLs the `url` crate parses are read through it; text it doesn't (a template with a
    /// placeholder for the port) by the hand reader, which masks the same parts.
    #[test]
    fn parsed_and_unparsed_urls() {
        let cases = [
            // Parsed: the path as `url` writes it, references kept as written.
            (
                "https://api.example:8443/v1?apikey=abc&q=1",
                "https://api.example:8443/v1?apikey=<redacted>&q=1",
            ),
            (
                "https://${secret:u}:${secret:p}@api.example/x?token=abc",
                "https://${secret:u}:${secret:p}@api.example/x?token=<redacted>",
            ),
            ("https://us%65r@api.example/x", "https://<redacted>@api.example/x"),
            (
                "https://user:pw@{domain}.dnsbl.example/x",
                "https://<redacted>@{domain}.dnsbl.example/x",
            ),
            // Not parsed (a placeholder for the port): the hand reader.
            (
                "https://user:pw@api.example:{port}/x?key=abc",
                "https://<redacted>@api.example:{port}/x?key=<redacted>",
            ),
        ];
        for (url, masked) in cases {
            let v = json!({ "url": url });
            assert_eq!(find_literal(&v).as_deref(), Some("url"), "{url}");
            assert_eq!(mask(&v)["url"], masked, "{url}");
        }
        assert!(url::Url::parse("https://user:pw@api.example:{port}/x").is_err());
        // References only, parsed or not: nothing to mask.
        for url in [
            "https://${secret:u}:${secret:p}@api.example/x?apikey=${secret:k}",
            "https://{domain}.dnsbl.example/x?key=${secret:k}",
            "mailto:user:pw@example.org",
        ] {
            let v = json!({ "url": url });
            assert_eq!(find_literal(&v), None, "{url}");
            assert_eq!(mask(&v), v, "{url}");
        }
    }

    #[test]
    fn header_maps_hold_only_references_outside_a_short_allowlist() {
        // CC1 (b): names alone can't tell a credential header; every header outside the
        // allowlist takes only ${secret:…}.
        for (v, path) in [
            (
                json!({"headers": {"Ocp-Apim-Subscription-Key": "abc"}}),
                "headers.Ocp-Apim-Subscription-Key",
            ),
            (json!({"headers": {"X-Key": "abc"}}), "headers.X-Key"),
            (json!({"headers": {"License-Key": "abc"}}), "headers.License-Key"),
            (json!({"headers": {"X-Whatever": 12345}}), "headers.X-Whatever"),
            (json!({"headers": {" Accept": "abc"}}), "headers. Accept"),
            (json!({"headers": [["X-Key", "abc"]]}), "headers.0.0"),
            (json!({"headers": "X-Key: abc"}), "headers"),
            (json!({"url": "https://api.example/v1?license=abc"}), "url"),
            (json!({"url": "https://api.example/v1?k=abc"}), "url"),
            (
                json!({"url": "https://api.example/v1?subscription-key=abc"}),
                "url",
            ),
            (json!({"license_key": "abc"}), "license_key"),
        ] {
            assert_eq!(find_literal(&v).as_deref(), Some(path), "{v}");
            let m = mask(&v).to_string();
            assert!(!m.contains("abc") && !m.contains("12345"), "{m}");
        }
        for v in [
            json!({"headers": {"Accept": "application/json", "User-Agent": "picket", "content-type": "text/plain",
                               "Cache-Control": "no-cache", "X-Key": "${secret:k}", "Accept-Language": "en"}}),
            json!({"url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"}),
            json!({"url": "https://api.example/v1?keyword=ads&format=json"}),
        ] {
            assert_eq!(find_literal(&v), None, "{v}");
            assert_eq!(mask(&v), v);
        }
    }
}
