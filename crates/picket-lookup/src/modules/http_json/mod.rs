//! `http_json` (providers.md §5): reads a verdict from a JSON API.
//!
//! Config: `{method, url: "https://api.example.net/v1/domain/{domain}", headers: {"Authorization":
//! "Bearer ${secret:key}"}, verdict: {pointer: "/risk_score", block_if: ">= 7.0", clean_if: "<
//! 4.0"}}`. `pointer` is a JSON Pointer (RFC 6901); comparisons are numeric or string equality
//! (booleans by equality too), and `block_if` is checked first. Redirects aren't followed.
//!
//! | Answer | Result |
//! |---|---|
//! | 200 | Parsed. A missing pointer or no matching comparison → Unknown; a body that isn't JSON → `Failed`. |
//! | 404 | Unknown |
//! | 429 | `Rejected`, with its `Retry-After` in seconds or as an HTTP date (none or unreadable: `None`) |
//! | 5xx, a timeout or a transport error | `Failed` (counts against health) |
//! | Any other status (redirects included) | `Other` (doesn't count against health) |
//!
//! The detail is `None`. Error messages never quote the URL, headers or body.

pub mod compare;
pub mod pointer;
pub mod retry_after;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use http::header::{ACCEPT, RETRY_AFTER};
use http::{HeaderMap, HeaderName, HeaderValue};
use jiff::Timestamp;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ctx::{HttpError, HttpRequest, HttpResponse, LookupCtx};
use crate::module::{Answer, LookupError, LookupModule, Verdict};

pub use compare::{CompareError, Comparison};
pub use pointer::{JsonPointer, PointerError};

/// The module id.
pub const ID: &str = "http_json";
/// The most response body bytes read; a longer body is `Failed`.
pub const MAX_BODY: usize = 256 * 1024;
/// The longest URL template.
pub const MAX_URL: usize = 2048;
/// The most configured headers.
pub const MAX_HEADERS: usize = 32;
/// The longest configured header value.
pub const MAX_HEADER_VALUE: usize = 4096;
/// The HTTP client's own bound on one exchange; the `LookupClient`'s `async_timeout_ms` ends a
/// call sooner.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Where the name goes in the URL template.
pub const DOMAIN: &str = "{domain}";

/// Headers a config may not set: the client owns them.
const RESERVED_HEADERS: [&str; 6] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
];

/// What the name is percent-encoded with: everything but RFC 3986's unreserved characters, so it
/// is safe in a path segment and in a query.
const NAME_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Default)]
pub struct Module;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    #[default]
    Get,
    Post,
}

/// The config as stored and edited (the UI form comes from its schema). Its `Debug` leaves out
/// the URL's query and user info and the header values, and redacts resolved secret values, as
/// [`Config`]'s does.
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RawConfig {
    #[serde(default)]
    pub method: Method,
    /// An `https://` URL with `{domain}` where the name goes, after the host (the name is
    /// percent-encoded).
    #[schemars(length(max = 2048))]
    pub url: String,
    /// Request headers; values may reference secrets as `${secret:name}`.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub verdict: RawVerdict,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RawVerdict {
    /// A JSON Pointer (RFC 6901) to the value compared, e.g. `/risk_score`.
    pub pointer: String,
    /// Checked first: e.g. `>= 7.0` or `== "malicious"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_if: Option<String>,
    /// e.g. `< 4.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_if: Option<String>,
}

impl std::fmt::Debug for RawConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::secrets::debug_redacted(f, |f| {
            f.debug_struct("RawConfig")
                .field("method", &self.method)
                .field("url", &template_for_logs(&self.url))
                .field("headers", &self.headers.keys().collect::<Vec<_>>())
                .field("verdict", &self.verdict)
                .finish()
        })
    }
}

/// A checked config: deserialises from [`RawConfig`] and checks it; its schema is
/// [`RawConfig`]'s. Its `Debug` leaves out the URL's query and user info and the header values,
/// and redacts every resolved secret value from the rest (README §2 Secrets).
#[derive(Clone)]
pub struct Config {
    method: Method,
    url: String,
    headers: Arc<HeaderMap>,
    pointer: JsonPointer,
    block_if: Option<Comparison>,
    clean_if: Option<Comparison>,
    /// A Block's reason: the pointer and the `block_if` text.
    reason: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::secrets::debug_redacted(f, |f| {
            f.debug_struct("Config")
                .field("method", &self.method)
                .field("url", &template_for_logs(&self.url))
                .field("headers", &crate::header_names(&self.headers))
                .field("pointer", &self.pointer)
                .field("block_if", &self.block_if)
                .field("clean_if", &self.clean_if)
                .finish_non_exhaustive()
        })
    }
}

/// `scheme://host/path` of URL template text, read by hand (a template with `{domain}` needn't
/// parse as a URL): without user info, query or fragment.
fn template_for_logs(t: &str) -> String {
    let (scheme, rest) = t.split_once("://").unwrap_or(("", t));
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let rest = &rest[..end];
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    format!("{scheme}://{host}{path}")
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawConfig::deserialize(d)?;
        Config::try_from(raw).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for Config {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        RawConfig::schema_name()
    }

    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        RawConfig::json_schema(g)
    }
}

/// Why a config was refused. Names the field, never a header value (which may hold a secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn err(msg: impl Into<String>) -> ConfigError {
    ConfigError(msg.into())
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, ConfigError> {
        check_url_template(&raw.url)?;
        if raw.headers.len() > MAX_HEADERS {
            return Err(err(format!("headers: at most {MAX_HEADERS}")));
        }
        let mut headers = HeaderMap::new();
        for (k, v) in &raw.headers {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|_| err(format!("headers: invalid header name {:?}", cut(k, 64))))?;
            if RESERVED_HEADERS.contains(&name.as_str()) {
                return Err(err(format!("headers: {name} is set by the client")));
            }
            if v.len() > MAX_HEADER_VALUE {
                return Err(err(format!(
                    "headers: {name}: value over {MAX_HEADER_VALUE} bytes"
                )));
            }
            let value = HeaderValue::from_str(v)
                .map_err(|_| err(format!("headers: {name}: invalid value (control characters?)")))?;
            headers.append(name, value);
        }
        if !headers.contains_key(ACCEPT) {
            headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        }
        let pointer =
            JsonPointer::parse(&raw.verdict.pointer).map_err(|e| err(format!("verdict.pointer: {e}")))?;
        let parse = |field: &str, s: &Option<String>| -> Result<Option<Comparison>, ConfigError> {
            s.as_deref()
                .map(|t| Comparison::parse(t).map_err(|e| err(format!("verdict.{field}: {e}"))))
                .transpose()
        };
        let block_if = parse("block_if", &raw.verdict.block_if)?;
        let clean_if = parse("clean_if", &raw.verdict.clean_if)?;
        if block_if.is_none() && clean_if.is_none() {
            return Err(err("verdict: set block_if, clean_if or both"));
        }
        // The pointer and the comparison as written, untrimmed: the client redacts the reason, and
        // a secret resolved into `block_if` with its own surrounding spaces must stay whole for
        // that (README §2 "Secrets"; review round 2, CR7).
        let reason = match &raw.verdict.block_if {
            Some(b) => format!("{} {b}", raw.verdict.pointer),
            None => String::new(),
        };
        Ok(Self {
            method: raw.method,
            url: raw.url,
            headers: Arc::new(headers),
            pointer,
            block_if,
            clean_if,
            reason,
        })
    }
}

fn cut(s: &str, max: usize) -> &str {
    let mut n = max.min(s.len());
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s.get(..n).unwrap_or("")
}

/// The template must be an `https` URL with a host, no user info and no fragment, with
/// `{domain}` after the host (two different names give the same scheme, host and port).
fn check_url_template(t: &str) -> Result<(), ConfigError> {
    if t.len() > MAX_URL {
        return Err(err(format!("url: over {MAX_URL} bytes")));
    }
    if !t.contains(DOMAIN) {
        return Err(err("url: must contain {domain}"));
    }
    let parse = |name: &str| url::Url::parse(&t.replace(DOMAIN, name)).map_err(|e| err(format!("url: {e}")));
    let a = parse("a.example")?;
    let b = parse("b.example")?;
    if a.scheme() != "https" {
        return Err(err("url: must be https"));
    }
    if a.host_str().is_none_or(str::is_empty) {
        return Err(err("url: needs a host"));
    }
    if !a.username().is_empty() || a.password().is_some() {
        return Err(err("url: no user info (put credentials in a header)"));
    }
    if a.fragment().is_some() {
        return Err(err("url: no fragment"));
    }
    if a.host_str() != b.host_str() || a.port_or_known_default() != b.port_or_known_default() {
        return Err(err("url: {domain} must come after the host"));
    }
    Ok(())
}

impl Config {
    /// The request URL for a name (the name percent-encoded).
    pub fn url_for(&self, name: &str) -> Result<url::Url, LookupError> {
        let encoded = utf8_percent_encode(name, NAME_SET).to_string();
        url::Url::parse(&self.url.replace(DOMAIN, &encoded))
            .map_err(|_| LookupError::Other(anyhow!("the URL template gives an invalid URL")))
    }

    /// The request for a name.
    pub fn request(&self, name: &str) -> Result<HttpRequest, LookupError> {
        Ok(HttpRequest {
            method: match self.method {
                Method::Get => http::Method::GET,
                Method::Post => http::Method::POST,
            },
            url: self.url_for(name)?,
            headers: (*self.headers).clone(),
            body: None,
            timeout: REQUEST_TIMEOUT,
            max_body: MAX_BODY,
        })
    }

    /// The verdict a JSON document gives (providers.md §5 `http_json`, 200 row).
    pub fn decide(&self, doc: &Value) -> Verdict {
        let Some(v) = self.pointer.resolve(doc) else {
            return Verdict::Unknown;
        };
        if let Some(b) = &self.block_if
            && b.matches(v)
        {
            let score = v
                .as_f64()
                .filter(|_| v.is_number())
                .map(score_f32)
                .filter(|f| f.is_finite());
            return Verdict::Block {
                score,
                reason: self.reason.clone(),
            };
        }
        if let Some(c) = &self.clean_if
            && c.matches(v)
        {
            return Verdict::Clean;
        }
        Verdict::Unknown
    }
}

/// Maps a response (or the failure to get one) to the module's result, per the status table.
pub fn interpret(
    cfg: &Config,
    resp: Result<HttpResponse, HttpError>,
    now: Timestamp,
) -> Result<Answer, LookupError> {
    let r = match resp {
        Ok(r) => r,
        Err(HttpError::Refused(m)) => return Err(LookupError::Other(anyhow!("request refused: {m}"))),
        Err(e) => return Err(LookupError::Failed(anyhow!("{e}"))),
    };
    let answer = |verdict| {
        Ok(Answer {
            verdict,
            detail: None,
        })
    };
    match r.status {
        200 => {
            if r.body.len() > MAX_BODY {
                return Err(LookupError::Failed(anyhow!(
                    "response body over {MAX_BODY} bytes"
                )));
            }
            let doc: Value = serde_json::from_slice(&r.body)
                .map_err(|_| LookupError::Failed(anyhow!("HTTP 200 with a body that isn't JSON")))?;
            answer(cfg.decide(&doc))
        }
        404 => answer(Verdict::Unknown),
        429 => Err(LookupError::Rejected {
            retry_after: r
                .headers
                .get(RETRY_AFTER)
                .and_then(|v| retry_after::parse(v.as_bytes(), now)),
        }),
        500..=599 => Err(LookupError::Failed(anyhow!("HTTP {}", r.status))),
        s => Err(LookupError::Other(anyhow!("unexpected HTTP status {s}"))),
    }
}

#[async_trait::async_trait]
impl LookupModule for Module {
    fn id(&self) -> &'static str {
        ID
    }

    fn config_schema(&self) -> schemars::Schema {
        schemars::schema_for!(RawConfig)
    }

    async fn lookup(&self, ctx: &LookupCtx, cfg: &Value, name: &str) -> Result<Answer, LookupError> {
        let cfg = ctx
            .parsed::<Config>(cfg)
            .map_err(|e| LookupError::Other(anyhow!("invalid http_json config: {e}")))?;
        let req = cfg.request(name)?;
        let resp = ctx.http().send(req).await;
        interpret(&cfg, resp, ctx.now())
    }
}

/// A score as the verdict keeps it.
#[expect(
    clippy::cast_possible_truncation,
    reason = "scores are kept as f32: a value beyond its range becomes infinite and is dropped next"
)]
fn score_f32(f: f64) -> f32 {
    f as f32
}

#[cfg(test)]
mod tests;
