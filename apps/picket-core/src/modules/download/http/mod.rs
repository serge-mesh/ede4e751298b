//! `http` (providers.md §3): one list at one HTTPS URL. A provider is one URL: its one file,
//! [`FILE`] (`response`), is what the URL answers, read by its one feed.
//!
//! - **Config:** `{url, headers?, date_line_regex?}`. `url`: `https://`, a host, no user info, no
//!   fragment; a query is part of it ([`check_feed_url`]). A header other than the plain ones
//!   (`Accept`, `User-Agent`, …) carries a credential, written as `${secret:name}` (README §2
//!   Secrets); headers go to the URL's host only, never across a redirect.
//! - **File:** one, [`FILE`], which `files` selects by default; its feed's id is the provider's id
//!   and its default name the provider's name (feeds.md §1). **Location:** the URL (editing it
//!   points the feed elsewhere). **Lists files:** no.
//! - **Probe on the first check:** a plain GET (body, `ETag`, `Last-Modified`, size, any date
//!   line), the same GET conditionally (`304` support?), and `Range: bytes=0-4095` (`206`
//!   support?). The method found goes in the file's `state.method`.
//! - **Check ladder:** (1) `conditional`: `If-None-Match` / `If-Modified-Since`; (2) `range`: the
//!   first 4 KiB, comparing the total size from `Content-Range`, the date line and the hash of
//!   those bytes, then a full GET if any differ, and at least one full GET a day; (3) `full`: a
//!   full GET compared by SHA-256. A body identical to the last run's is `Unchanged` (with the
//!   new validators in `state`); a `404` or `410` is `Missing`.
//! - **Change time:** `Last-Modified`, else a header date line, else an interval.
//!   `version` = the ETag, else the SHA-256; `updated_at` = that time, or the download time.
//!
//! A `Range` answer never confirms a held run (feeds.md §5): its method is `range`.

use std::collections::BTreeMap;

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use url::Url;

use super::client::{HttpError, Req, Resp};
use super::{
    ChangeTime, CheckError, CheckOutcome, Ctx, DownloadModule, FileCheck, LastRun, Normalized, ProviderCheck,
    StagedFile,
};

/// How much of a list's head the `range` rung reads.
pub const HEAD_BYTES: u64 = 4096;
/// The full-download backstop on the `range` rung (feed-scheduling.md §5).
pub const FULL_EVERY: jiff::SignedDuration = jiff::SignedDuration::from_hours(24);
/// The most extra headers a provider may send.
const MAX_HEADERS: usize = 32;
/// The longest `date_line_regex`.
const MAX_REGEX: usize = 512;
/// What a response head costs, for the scheduler's cost ratio.
pub const HEAD_COST: u64 = 600;
/// A provider's one file: what its URL answers (no file name is empty).
pub const FILE: &str = "response";

/// An `http` feed provider's settings.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The list's `https://` URL (a query is part of it; no user info or fragment).
    pub url: String,
    /// Extra request headers. Any header but `Accept`, `Accept-Language`, `Cache-Control`,
    /// `Content-Type`, `Pragma` and `User-Agent` takes only `${secret:name}` references; headers
    /// go to the URL's host only, never across a redirect.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// A regular expression for the list's date line; its first capture group (or the whole
    /// match) is the time of the last change. Without it, a comment line such as
    /// `! Last modified: …` or `# Updated : …` is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_line_regex: Option<String>,
}

/// What a file keeps between checks.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// `conditional`, `range` or `full`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// SHA-256 of the whole body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// SHA-256 of the first [`HEAD_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_sha256: Option<String>,
    /// Times in chrono's default serde form, as stored states have always held them (README §2).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "picket_api::time::autosi_opt"
    )]
    pub date_line: Option<Timestamp>,
    /// The last full GET.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "picket_api::time::autosi_opt"
    )]
    pub last_full: Option<Timestamp>,
}

#[derive(Default)]
pub struct Module;

/// The longest URL: what an older release's `base_url` (2,048 bytes) and a file path under it
/// (2,048 bytes, up to three times that once percent-encoded) could make, so an upgraded
/// provider's URL always fits (README §2 Compatibility).
pub const MAX_URL: usize = 2048 + 3 * 2048;

/// Checks an `https://` URL with a host and no user info: a user name or password in a URL
/// would go out as Basic auth on every hop of a same-host redirect (README §2 Secrets:
/// credentials go only to the host they're configured for); credentials go in headers.
pub fn check_url(url: &str) -> Result<Url, String> {
    if url.len() > MAX_URL {
        return Err(format!("the url is longer than {MAX_URL} bytes"));
    }
    let u = Url::parse(url).map_err(|_| "the url isn't a URL".to_string())?;
    if u.scheme() != "https" {
        return Err("the url must be https:// (downloads are HTTPS only)".into());
    }
    if u.host_str().is_none_or(str::is_empty) {
        return Err("the url has no host".into());
    }
    if has_user_info(&u) {
        return Err("the url can't hold a user name or password; use a header with a secret".into());
    }
    Ok(u)
}

/// True when `u` carries a user name or a password.
pub fn has_user_info(u: &Url) -> bool {
    !u.username().is_empty() || u.password().is_some()
}

/// Checks a provider's `url` ([`check_url`]; no fragment, which a server never sees).
pub fn check_feed_url(url: &str) -> Result<Url, String> {
    let u = check_url(url)?;
    if u.fragment().is_some() {
        return Err("the url can't have a #fragment".into());
    }
    Ok(u)
}

/// A URL as providers are matched by it (adding a feed by URL): parsed, so the scheme and host
/// are lowercase and a default port is dropped, without a fragment; otherwise exact, the query
/// included.
pub fn url_key(u: &Url) -> String {
    let mut u = u.clone();
    u.set_fragment(None);
    u.to_string()
}

/// The refusal of any file but [`FILE`].
fn one_file() -> String {
    format!("an http provider has one file, {FILE:?}: its url's answer")
}

/// Builds a GET with the feed's headers (credentials marked).
pub fn base_get(url: &Url, headers: &BTreeMap<String, String>) -> Result<Req, HttpError> {
    let mut r = Req::get(url.clone());
    for (k, v) in headers {
        let plain = crate::config::credentials::LITERAL_HEADERS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(k));
        r = if plain {
            r.header(k, v)?
        } else {
            r.credential(k, v)?
        };
    }
    Ok(r)
}

/// `Content-Range: bytes 0-4095/123456` → the total size (`None` for `*` or junk).
pub fn content_range_total(v: &str) -> Option<u64> {
    let v = v.trim();
    let rest = v.strip_prefix("bytes")?.trim_start();
    let (_, total) = rest.split_once('/')?;
    let total = total.trim();
    if total.len() > 20 {
        return None;
    }
    total.parse().ok()
}

/// An ETag as a version: trimmed, at most 256 bytes of visible ASCII.
pub fn etag_of(resp: &Resp) -> Option<String> {
    let v = resp.header("etag")?.trim();
    (!v.is_empty() && v.len() <= 256 && v.bytes().all(|b| (0x21..0x7f).contains(&b))).then(|| v.to_string())
}

/// `Last-Modified` as received (for `If-Modified-Since`) and as a time.
pub fn last_modified_of(resp: &Resp) -> Option<(String, Timestamp)> {
    let v = resp.header("last-modified")?.trim();
    if v.len() > 80 {
        return None;
    }
    super::dates::parse_http_date(v).map(|t| (v.to_string(), t))
}

/// The first `n` bytes of a staged file.
pub async fn read_head(f: &StagedFile, n: u64) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    if let Ok(file) = tokio::fs::File::open(f.path()).await {
        let _ = file.take(n).read_to_end(&mut out).await;
    }
    out
}

/// A failed check for an unexpected status (providers.md §2: anything but 200, 206 or 304).
pub fn bad_status(resp: &Resp) -> CheckError {
    CheckError::Failed(anyhow::anyhow!(
        "the server answered HTTP {}",
        resp.status.as_u16()
    ))
}

fn compile_regex(re: Option<&str>) -> Result<Option<regex::Regex>, String> {
    match re {
        None => Ok(None),
        Some(r) if r.len() > MAX_REGEX => Err(format!("date_line_regex is longer than {MAX_REGEX} bytes")),
        Some(r) => regex::RegexBuilder::new(r)
            .size_limit(256 * 1024)
            .dfa_size_limit(256 * 1024)
            .build()
            .map(Some)
            .map_err(|_| "date_line_regex isn't a valid regular expression".to_string()),
    }
}

/// One full download's facts.
struct Full {
    file: StagedFile,
    etag: Option<String>,
    last_modified: Option<(String, Timestamp)>,
    date_line: Option<Timestamp>,
    head_sha256: String,
}

async fn full_from(ctx: &Ctx, resp: Resp, re: Option<&regex::Regex>) -> Result<Full, CheckError> {
    let etag = etag_of(&resp);
    let last_modified = last_modified_of(&resp);
    let file = ctx.stage(resp).await?;
    let head = read_head(&file, HEAD_BYTES).await;
    Ok(Full {
        date_line: super::dates::find_date_line(&head, re),
        head_sha256: hex::encode(sha2::Sha256::digest(&head)),
        etag,
        last_modified,
        file,
    })
}

/// A failed check for a status that means the file is gone (`404`, `410`): `Missing`.
fn missing_or_bad(resp: &Resp) -> CheckError {
    match resp.status.as_u16() {
        404 | 410 => CheckError::Missing,
        _ => bad_status(resp),
    }
}

impl Module {
    async fn get(&self, ctx: &Ctx, req: Req) -> Result<Resp, CheckError> {
        Ok(ctx.http.send(req).await?)
    }

    /// The outcome of a full download, given the previous state.
    fn outcome(
        &self,
        ctx: &Ctx,
        full: Full,
        method_state: Option<String>,
        prev: &State,
        method: &'static str,
    ) -> CheckOutcome {
        let state = State {
            method: method_state,
            etag: full.etag.clone(),
            last_modified: full.last_modified.as_ref().map(|(s, _)| s.clone()),
            sha256: Some(full.file.sha256().to_string()),
            size: Some(full.file.size()),
            head_sha256: Some(full.head_sha256.clone()),
            date_line: full.date_line,
            last_full: Some(ctx.now),
        };
        let bytes = full.file.size() + HEAD_COST;
        let state_json = serde_json::to_value(&state).unwrap_or(Value::Null);
        if prev.sha256.as_deref() == Some(full.file.sha256()) {
            return CheckOutcome::Unchanged {
                state: Some(state_json),
                observed: vec![],
                bytes,
                method,
            };
        }
        let exact = full.last_modified.as_ref().map(|(_, t)| *t).or(full.date_line);
        let change_times = match (exact, ctx.last_ok) {
            (Some(t), _) => vec![ChangeTime::Exact(t)],
            (None, Some(lo)) => vec![ChangeTime::Interval { lo, hi: ctx.now }],
            (None, None) => vec![],
        };
        CheckOutcome::Changed {
            updated_at: exact.unwrap_or(ctx.now),
            version: full
                .etag
                .clone()
                .unwrap_or_else(|| full.file.sha256().to_string()),
            state: state_json,
            change_times,
            file: full.file,
            bytes,
            method,
        }
    }

    /// First check: plain GET, then the conditional and Range probes (providers.md §3).
    async fn probe(
        &self,
        ctx: &Ctx,
        cfg: &Config,
        url: &Url,
        re: Option<&regex::Regex>,
    ) -> Result<CheckOutcome, CheckError> {
        let resp = self.get(ctx, base_get(url, &cfg.headers)?).await?;
        if resp.status != http::StatusCode::OK {
            return Err(missing_or_bad(&resp));
        }
        let full = full_from(ctx, resp, re).await?;
        // The same GET, conditionally.
        let mut conditional = false;
        if full.etag.is_some() || full.last_modified.is_some() {
            let mut r = base_get(url, &cfg.headers)?;
            if let Some(e) = &full.etag {
                r = r.header("if-none-match", e)?;
            }
            if let Some((lm, _)) = &full.last_modified {
                r = r.header("if-modified-since", lm)?;
            }
            if let Ok(resp) = ctx.http.send(r).await {
                conditional = resp.status == http::StatusCode::NOT_MODIFIED;
                resp.discard();
            }
        }
        let mut method = if conditional { "conditional" } else { "full" };
        if !conditional {
            let r = base_get(url, &cfg.headers)?
                .header("range", &format!("bytes=0-{}", HEAD_BYTES - 1))?
                .header("accept-encoding", "identity")?;
            if let Ok(resp) = ctx.http.send(r).await
                && resp.status == http::StatusCode::PARTIAL_CONTENT
                && resp
                    .header("content-range")
                    .and_then(content_range_total)
                    .is_some_and(|t| t == full.file.size())
            {
                method = "range";
            }
        }
        let prev = State::default();
        Ok(self.outcome(ctx, full, Some(method.to_string()), &prev, "probe"))
    }

    async fn full_check(
        &self,
        ctx: &Ctx,
        st: &State,
        re: Option<&regex::Regex>,
        req: Req,
        method: &'static str,
    ) -> Result<CheckOutcome, CheckError> {
        let resp = self.get(ctx, req).await?;
        match resp.status {
            http::StatusCode::NOT_MODIFIED if method == "conditional" => Ok(CheckOutcome::Unchanged {
                state: None,
                observed: vec![],
                bytes: HEAD_COST,
                method,
            }),
            http::StatusCode::OK => {
                // The whole file came back (also to a conditional GET): a full download.
                let full = full_from(ctx, resp, re).await?;
                Ok(self.outcome(ctx, full, st.method.clone(), st, "full"))
            }
            _ => Err(missing_or_bad(&resp)),
        }
    }

    /// One file's check (the probe on its first, then its rung of the ladder).
    async fn check_one(
        &self,
        ctx: &Ctx,
        cfg: &Config,
        url: &Url,
        re: Option<&regex::Regex>,
        last: Option<&LastRun>,
    ) -> Result<CheckOutcome, CheckError> {
        let st: State = last
            .and_then(|l| serde_json::from_value(l.state.clone()).ok())
            .unwrap_or_default();
        let Some(method) = st.method.clone().filter(|_| last.is_some()) else {
            return self.probe(ctx, cfg, url, re).await;
        };
        match method.as_str() {
            "conditional" => {
                let mut r = base_get(url, &cfg.headers)?;
                if let Some(e) = &st.etag {
                    r = r.header("if-none-match", e)?;
                }
                if let Some(lm) = &st.last_modified {
                    r = r.header("if-modified-since", lm)?;
                }
                self.full_check(ctx, &st, re, r, "conditional").await
            }
            "range" => {
                let full_due = st.last_full.is_none_or(|t| ctx.now - t >= FULL_EVERY);
                if !full_due {
                    let r = base_get(url, &cfg.headers)?
                        .header("range", &format!("bytes=0-{}", HEAD_BYTES - 1))?
                        .header("accept-encoding", "identity")?;
                    let resp = self.get(ctx, r).await?;
                    match resp.status {
                        http::StatusCode::PARTIAL_CONTENT => {
                            if resp.is_html() {
                                return Err(CheckError::Failed(anyhow::anyhow!(
                                    "the server answered with text/html (a captive portal or an error page)"
                                )));
                            }
                            let total = resp.header("content-range").and_then(content_range_total);
                            let head = resp
                                .bytes_limited(usize::try_from(HEAD_BYTES).unwrap_or(usize::MAX))
                                .await?;
                            let same = total.is_some()
                                && total == st.size
                                && st.head_sha256.as_deref()
                                    == Some(hex::encode(sha2::Sha256::digest(&head)).as_str())
                                && super::dates::find_date_line(&head, re) == st.date_line;
                            if same {
                                return Ok(CheckOutcome::Unchanged {
                                    state: None,
                                    observed: vec![],
                                    bytes: head.len() as u64 + HEAD_COST,
                                    method: "range",
                                });
                            }
                        }
                        http::StatusCode::OK => {
                            // The server ignored the Range header: this is a full answer.
                            let full = full_from(ctx, resp, re).await?;
                            return Ok(self.outcome(ctx, full, Some("full".into()), &st, "full"));
                        }
                        _ => return Err(missing_or_bad(&resp)),
                    }
                }
                let r = base_get(url, &cfg.headers)?;
                self.full_check(ctx, &st, re, r, "full").await
            }
            _ => {
                let r = base_get(url, &cfg.headers)?;
                self.full_check(ctx, &st, re, r, "full").await
            }
        }
    }
}

#[async_trait::async_trait]
impl DownloadModule for Module {
    fn id(&self) -> &'static str {
        "http"
    }

    fn config_schema(&self) -> schemars::Schema {
        super::schema_of::<Config>()
    }

    fn location(&self, cfg: &Value) -> String {
        cfg.get("url")
            .and_then(Value::as_str)
            .and_then(|u| Url::parse(u).ok())
            .map(|u| url_key(&u))
            .unwrap_or_default()
    }

    fn check_file(&self, _cfg: &Value, file: &str, _pattern: bool) -> Result<(), String> {
        if file == FILE { Ok(()) } else { Err(one_file()) }
    }

    fn default_files(&self) -> Vec<(String, Value)> {
        vec![(FILE.to_string(), serde_json::json!({"format": "adblock"}))]
    }

    fn fixed_file(&self) -> Option<&'static str> {
        Some(FILE)
    }

    fn normalize_config(&self, cfg: &Value) -> Result<Normalized, String> {
        let c: Config = super::parse_config(cfg)?;
        check_feed_url(&c.url)?;
        if c.headers.len() > MAX_HEADERS {
            return Err(format!("at most {MAX_HEADERS} headers"));
        }
        for (k, v) in &c.headers {
            if http::HeaderName::from_bytes(k.as_bytes()).is_err() {
                return Err(format!("headers: {k:?} is not a header name"));
            }
            if matches!(
                k.to_ascii_lowercase().as_str(),
                "host"
                    | "range"
                    | "if-none-match"
                    | "if-modified-since"
                    | "accept-encoding"
                    | "content-length"
                    | "transfer-encoding"
                    | "connection"
            ) {
                return Err(format!("headers: {k} is set by the module"));
            }
            if v.len() > 4096 {
                return Err(format!("headers: the value of {k} is longer than 4096 bytes"));
            }
        }
        compile_regex(c.date_line_regex.as_deref())?;
        Ok(Normalized {
            config: cfg.clone(),
            notice: None,
        })
    }

    async fn check(
        &self,
        ctx: &Ctx,
        cfg: &Value,
        _state: Option<&Value>,
        feeds: &[FileCheck],
        _select: &[String],
    ) -> Result<ProviderCheck, CheckError> {
        let cfg: Config = super::config_of(cfg)?;
        let url = check_feed_url(&cfg.url).map_err(|e| CheckError::Failed(anyhow::anyhow!(e)))?;
        let re = compile_regex(cfg.date_line_regex.as_deref())
            .map_err(|e| CheckError::Failed(anyhow::anyhow!(e)))?;
        let mut files = Vec::with_capacity(feeds.len());
        for f in feeds {
            let out = if f.file == FILE {
                self.check_one(ctx, &cfg, &url, re.as_ref(), f.last.as_ref())
                    .await
            } else {
                Err(CheckError::Failed(anyhow::anyhow!(one_file())))
            };
            files.push((f.file.clone(), out));
        }
        Ok(ProviderCheck {
            state: Value::Object(Default::default()),
            files,
            listing: None,
        })
    }
}

#[cfg(test)]
mod tests;
