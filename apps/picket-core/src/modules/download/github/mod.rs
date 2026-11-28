//! `github` (providers.md §3): the files of one GitHub repository, followed on a branch (the
//! default branch unless `branch` is set).
//!
//! - **Config:** `{owner, repo, branch?, token?}`. `token` is a read-only GitHub token
//!   (`${secret:name}`), sent with the git, REST and raw requests to GitHub's hosts only (never
//!   across a redirect). **File:** a path in the repository; `files` holds globs.
//!   **Location:** `https://github.com/<o>/<r>/`. **Lists files:** yes.
//! - **Check:** one git smart-HTTP protocol v2 `ls-refs` POST (no API quota; sees a push within
//!   about a second). A file whose own `state.head` is the current head → `Unchanged`; every
//!   other file (new, newly enabled, failed or missing last time) is resolved at the head.
//! - **Files not yet checked at the head, and the listing when `listed_head` isn't the head:**
//!   one `GET /git/trees/<head>?recursive=1` gives every blob's SHA and the listing (blobs only;
//!   symlinks and submodules left out). A truncated tree is walked again without `recursive`,
//!   from the root down only into directories a `select` pattern or a feed's path can reach, in
//!   at most [`WALK_BUDGET`] requests, giving a listing limited to what `select` reaches
//!   (`whole: false`); a file still unresolved takes the contents API. The walk is bounded in
//!   total too: [`MAX_WALK_ENTRIES`] entries and [`MAX_WALK_BYTES`] of answers across its
//!   requests. A walk that can't finish gives no listing and reports it
//!   ([`Ctx::listing_incomplete`]); the provider state remembers the head it failed at, and
//!   until the head moves or [`WALK_RETRY`] passes, checks don't read the tree for a listing
//!   again (the files not yet checked at the head take the contents API), so an unfinishable walk
//!   costs its requests once per head and not at every check (GitHub's 60 requests an hour
//!   without a token); the tree at a commit never changes, so the same head would fail the same
//!   way. `feed_provider_listing_incomplete` stays raised meanwhile. A file absent from its
//!   directory's complete tree, or a `404` from `contents`, is `Missing`; a partial listing never
//!   makes a file `Missing`.
//! - **Changed files:** the commits API (`sha=<head>`, `path=<path>`, `since=<last check − 1 d>`)
//!   gives exact change times; the download goes by commit, never by branch
//!   (`raw.githubusercontent.com/<o>/<r>/<head>/<path>`), verified against git's blob hash
//!   `sha1("blob <len>\0" + body)`; a mismatch fails that file's check.
//! - `version` = the blob SHA; `updated_at` = the newest commit time touching the path; file
//!   `state` = `{head, blob}`; provider `state` = `{listed_head}`.
//! - **Rate limits:** HTTP 429, or 403 with a rate-limit header, is `RateLimited` until
//!   `Retry-After` or `x-ratelimit-reset`, kept whole however long past an hour (held to
//!   [`super::dates::MAX_COOLDOWN`] against a bad header), which pauses every `github` check
//!   (the module is the pause scope: one API quota).
//! - `history()` pages through the commits API for one path (the warm start).
//! - **Adding a feed by URL** ([`parse_url`]): `raw.githubusercontent.com/<o>/<r>/<branch>/<path>`,
//!   `cdn.jsdelivr.net/gh/<o>/<r>@latest/<path>` (the default branch; jsDelivr caches for up to
//!   12 h) and a file's page on github.com. Tags are never followed; `<o>.github.io` is `http`.

pub mod pktline;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::Duration;

use base64::Engine as _;
use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Digest;
use url::Url;

use super::client::{Http, Req, Resp};
use super::{
    ChangeTime, CheckError, CheckOutcome, Ctx, DownloadModule, FileCheck, Listing, Normalized, ProviderCheck,
    StagedFile, glob,
};

/// The longest one `ls-refs` exchange may take (a small answer).
const LS_REFS_DEADLINE: Duration = Duration::from_secs(60);
/// The largest `ls-refs` answer read.
const MAX_LS_REFS: usize = 256 * 1024;
/// The largest commits-API page read.
const MAX_COMMITS: usize = 4 << 20;
/// The largest contents-API answer read (it carries files up to 1 MB as base64).
const MAX_CONTENTS: usize = 6 << 20;
/// The largest trees-API answer read (GitHub's recursive limit is 100,000 entries, 7 MB).
pub const MAX_TREE: usize = 16 << 20;
/// The most entries one tree answer may hold.
pub const MAX_TREE_ENTRIES: usize = 200_000;
/// The most requests a truncated tree's walk may take (providers.md §3).
pub const WALK_BUDGET: usize = 50;
/// The most entries a walk keeps across its requests (policy choice: one recursive tree's
/// worth), so 50 answers can't add up past core's peak RAM (README §2 Bounded, core.md §3).
pub const MAX_WALK_ENTRIES: usize = MAX_TREE_ENTRIES;
/// The most bytes a walk reads and keeps across its requests (policy choice): the answers' bytes
/// plus, for each entry it keeps, its full path (directory prefix included) and SHA, so the
/// paths a walk builds can't add up past core's peak RAM however short the names in the answers
/// are (README §2 Bounded).
pub const MAX_WALK_BYTES: u64 = 32 << 20;
/// The longest file path in a repository core takes ([`check_path`]; a feed's `file` must pass
/// it): a walk keeps no longer path, and doesn't descend where every path would be longer.
pub const MAX_PATH: usize = 1024;
/// How long a walk that couldn't finish at a head isn't tried again at that head (policy
/// choice); a head move tries at once.
pub const WALK_RETRY: jiff::SignedDuration = jiff::SignedDuration::from_hours(6);
/// Warm start: how far back, and how many changes (feed-scheduling.md §6).
pub use picket_schedule::{HISTORY_CHANGES, HISTORY_DAYS};
const HISTORY_PAGES: u32 = 10;

const GIT_HOST: &str = "https://github.com";
const API_HOST: &str = "https://api.github.com";
const RAW_HOST: &str = "https://raw.githubusercontent.com";

/// A `github` feed provider's settings.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The repository's owner (user or organisation).
    pub owner: String,
    /// The repository.
    pub repo: String,
    /// The branch to follow; left out: the repository's default branch. Tags are never followed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// A read-only GitHub token, as `${secret:name}`; sent to GitHub only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// What a file keeps between checks.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FileState {
    pub head: String,
    pub blob: String,
}

/// What the provider keeps between checks.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProviderState {
    /// The head the latest listing was taken at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed_head: Option<String>,
    /// A walk of a truncated tree that couldn't finish: the head and when ([`WALK_RETRY`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walk_failed: Option<WalkFailed>,
}

/// Where and when a walk couldn't finish.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WalkFailed {
    pub head: String,
    /// chrono's default serde form, as stored states have always held it (README §2).
    #[serde(with = "picket_api::time::autosi")]
    pub at: Timestamp,
}

fn check_name(what: &str, s: &str) -> Result<(), String> {
    let ok = !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(format!("{what} isn't a GitHub {what} name"))
    }
}

/// A branch name git accepts (a safe subset of `git check-ref-format`).
pub fn check_branch(b: &str) -> Result<(), String> {
    let bad = b.is_empty()
        || b.len() > 255
        || b.starts_with(['-', '/', '.'])
        || b.ends_with(['/', '.'])
        || b.ends_with(".lock")
        || b.contains("..")
        || b.contains("//")
        || b.contains("@{")
        || b.bytes()
            .any(|c| c <= b' ' || c == 0x7f || b"~^:?*[\\".contains(&c));
    if bad {
        Err("branch isn't a valid branch name".into())
    } else {
        Ok(())
    }
}

/// A file path in a repository.
pub fn check_path(p: &str) -> Result<(), String> {
    let bad = p.is_empty()
        || p.len() > MAX_PATH
        || p.starts_with('/')
        || p.split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        || p.chars().any(char::is_control);
    if bad {
        Err(format!("{p:?} isn't a file path in the repository"))
    } else {
        Ok(())
    }
}

/// A file named by a URL ([`parse_url`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlFile {
    pub owner: String,
    pub repo: String,
    /// `None`: the default branch (a jsDelivr `@latest` URL).
    pub branch: Option<String>,
    pub path: String,
    /// What the UI says about the mapping (jsDelivr's cache).
    pub notice: Option<String>,
}

/// Maps a URL to a repository file (adding a feed by URL, providers.md §3).
pub fn parse_url(url: &str) -> Result<UrlFile, String> {
    let u = Url::parse(url).map_err(|_| "the URL isn't a URL".to_string())?;
    if u.scheme() != "https" {
        return Err("the URL must be https://".into());
    }
    let segs: Vec<String> = u
        .path_segments()
        .map(|s| {
            s.map(|x| {
                percent_encoding::percent_decode_str(x)
                    .decode_utf8_lossy()
                    .into_owned()
            })
            .collect()
        })
        .unwrap_or_default();
    let fixed = |b: &str| b.len() == 40 && b.bytes().all(|c| c.is_ascii_hexdigit());
    let out = match u.host_str().map(str::to_ascii_lowercase).as_deref() {
        Some("raw.githubusercontent.com") => {
            let bad = || "a raw.githubusercontent.com URL is /<owner>/<repo>/<branch>/<path>".to_string();
            let [owner, repo, rest @ ..] = segs.as_slice() else {
                return Err(bad());
            };
            let (branch, path) = match rest {
                [refs, heads, b, p @ ..] if refs == "refs" && heads == "heads" && !p.is_empty() => {
                    (b.clone(), p.join("/"))
                }
                [b, p @ ..] if !p.is_empty() => (b.clone(), p.join("/")),
                _ => return Err(bad()),
            };
            if fixed(&branch) {
                return Err("a raw URL at a fixed commit never changes; use the branch's URL".into());
            }
            UrlFile {
                owner: owner.clone(),
                repo: repo.clone(),
                branch: Some(branch),
                path,
                notice: None,
            }
        }
        Some("github.com" | "www.github.com") => {
            let bad = || "a github.com URL is /<owner>/<repo>/blob/<branch>/<path>".to_string();
            let [owner, repo, mode, branch, path @ ..] = segs.as_slice() else {
                return Err(bad());
            };
            if !(mode == "blob" || mode == "raw") || path.is_empty() {
                return Err(bad());
            }
            if fixed(branch) {
                return Err("a URL at a fixed commit never changes; use the branch's URL".into());
            }
            UrlFile {
                owner: owner.clone(),
                repo: repo.clone(),
                branch: Some(branch.clone()),
                path: path.join("/"),
                notice: None,
            }
        }
        Some("cdn.jsdelivr.net") => {
            let bad = || "a jsDelivr URL is /gh/<owner>/<repo>@latest/<path>".to_string();
            let [gh, owner, repo_ver, path @ ..] = segs.as_slice() else {
                return Err(bad());
            };
            if gh != "gh" || path.is_empty() {
                return Err(bad());
            }
            let repo = match repo_ver.split_once('@') {
                None => repo_ver.clone(),
                Some((r, "latest")) => r.to_string(),
                Some(_) => {
                    return Err(
                        "github follows branches, never tags or versions: use @latest, or the http module for a list published by tag"
                            .into(),
                    );
                }
            };
            UrlFile {
                owner: owner.clone(),
                repo,
                branch: None,
                path: path.join("/"),
                notice: Some(
                    "A jsDelivr @latest URL follows the default branch; jsDelivr caches files for up to 12 hours, GitHub doesn't, so the file is fetched from GitHub."
                        .into(),
                ),
            }
        }
        Some(h) if h.ends_with(".github.io") => {
            return Err("<owner>.github.io pages are served by the http module".into());
        }
        _ => {
            return Err("the URL must be a raw.githubusercontent.com, github.com/…/blob/… or cdn.jsdelivr.net/gh URL".into());
        }
    };
    check_name("owner", &out.owner)?;
    check_name("repo", out.repo.trim_end_matches(".git"))?;
    if let Some(b) = &out.branch {
        check_branch(b)?;
    }
    check_path(&out.path)?;
    Ok(UrlFile {
        repo: out.repo.trim_end_matches(".git").to_string(),
        ..out
    })
}

fn checked(c: &Config) -> Result<(), String> {
    check_name("owner", &c.owner)?;
    check_name("repo", &c.repo)?;
    if let Some(b) = &c.branch {
        check_branch(b)?;
    }
    Ok(())
}

/// The location of a repository (providers.md §3): `https://github.com/<o>/<r>/`, lowercased
/// (GitHub names are case-insensitive).
pub fn location_of(owner: &str, repo: &str) -> String {
    format!(
        "https://github.com/{}/{}/",
        owner.to_ascii_lowercase(),
        repo.to_ascii_lowercase()
    )
}

/// `RateLimited` for a GitHub rate-limit reply: 429, or 403 with a rate-limit header.
pub fn rate_limit_until(resp: &Resp, now: Timestamp) -> Option<Timestamp> {
    let status = resp.status.as_u16();
    let remaining_zero = resp.header("x-ratelimit-remaining").map(str::trim) == Some("0");
    let retry = resp.header("retry-after");
    if !(status == 429 || (status == 403 && (remaining_zero || retry.is_some()))) {
        return None;
    }
    let until = retry
        .and_then(|v| super::dates::retry_after(v, now))
        .or_else(|| {
            resp.header("x-ratelimit-reset")
                .and_then(|v| v.trim().parse::<i64>().ok())
                .and_then(|s| Timestamp::from_second(s).ok())
        })
        .unwrap_or(now + jiff::SignedDuration::from_secs(60));
    let max = picket_api::time::saturating_add(now, super::dates::MAX_COOLDOWN);
    Some(until.clamp(now + jiff::SignedDuration::from_secs(1), max))
}

#[derive(Deserialize)]
struct CommitItem {
    #[serde(default)]
    parents: Vec<serde::de::IgnoredAny>,
    commit: CommitInner,
}

#[derive(Deserialize)]
struct CommitInner {
    #[serde(default)]
    committer: Option<Person>,
    #[serde(default)]
    author: Option<Person>,
}

#[derive(Deserialize)]
struct Person {
    #[serde(default)]
    date: Option<String>,
}

/// One commit from the commits API: its time and whether it is a root commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commit {
    pub time: Timestamp,
    pub root: bool,
}

/// Reads a commits-API page (at most 100 items).
pub fn parse_commits(body: &[u8]) -> Result<Vec<Commit>, String> {
    let items: Vec<CommitItem> = serde_json::from_slice(body)
        .map_err(|_| "the commits API answered something that isn't a commit list".to_string())?;
    Ok(items
        .into_iter()
        .take(100)
        .filter_map(|c| {
            let d = c
                .commit
                .committer
                .and_then(|p| p.date)
                .or_else(|| c.commit.author.and_then(|p| p.date))?;
            let time = picket_api::time::parse(&d).ok()?;
            Some(Commit {
                time,
                root: c.parents.is_empty(),
            })
        })
        .collect())
}

fn sha_ok(sha: &str) -> bool {
    (sha.len() == 40 || sha.len() == 64) && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Reads a contents-API answer: the blob SHA of a file.
pub fn parse_blob_sha(body: &[u8]) -> Result<String, String> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|_| "the contents API answered something that isn't JSON".to_string())?;
    if v.is_array() {
        return Err("the path is a directory, not a file".into());
    }
    if v.get("type").and_then(Value::as_str) != Some("file") {
        return Err("the path isn't a file".into());
    }
    let sha = v.get("sha").and_then(Value::as_str).unwrap_or_default();
    if sha_ok(sha) {
        Ok(sha.to_ascii_lowercase())
    } else {
        Err("the contents API gave no blob SHA".into())
    }
}

#[derive(Deserialize)]
struct TreeAnswer {
    #[serde(default)]
    truncated: bool,
    tree: Vec<TreeItem>,
}

#[derive(Deserialize)]
struct TreeItem {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    sha: String,
    #[serde(default)]
    mode: String,
}

/// One entry of a trees-API answer: a file (blob) or a directory (tree), with its SHA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntry {
    pub path: String,
    pub dir: bool,
    pub sha: String,
}

/// A trees-API answer: blobs and directories (symlinks and submodules left out) and whether
/// GitHub cut it short.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
    pub truncated: bool,
}

/// Reads a trees-API answer (untrusted: bounded, never panicking). Entry paths are checked as
/// repository paths; entries with another type (a submodule's `commit`), symlinks (mode
/// `120000`) and bad paths are left out.
pub fn parse_tree(body: &[u8]) -> Result<Tree, String> {
    let a: TreeAnswer = serde_json::from_slice(body)
        .map_err(|_| "the trees API answered something that isn't a tree".to_string())?;
    if a.tree.len() > MAX_TREE_ENTRIES {
        return Err(format!("the tree has more than {MAX_TREE_ENTRIES} entries"));
    }
    let entries = a
        .tree
        .into_iter()
        .filter(|e| sha_ok(&e.sha) && check_path(&e.path).is_ok())
        .filter_map(|e| match e.kind.as_str() {
            "blob" if e.mode != "120000" => Some(TreeEntry {
                path: e.path,
                dir: false,
                sha: e.sha.to_ascii_lowercase(),
            }),
            "tree" => Some(TreeEntry {
                path: e.path,
                dir: true,
                sha: e.sha.to_ascii_lowercase(),
            }),
            _ => None,
        })
        .collect();
    Ok(Tree {
        entries,
        truncated: a.truncated,
    })
}

/// `sha1("blob <len>\0" + body)` of a file (git's blob id), read in blocks.
pub fn git_blob_sha1(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let len = std::fs::metadata(path)?.len();
    let mut h = sha1::Sha1::new();
    h.update(format!("blob {len}\0").as_bytes());
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// One commits-API request.
#[derive(Clone, Copy)]
struct CommitsQuery<'a> {
    path: &'a str,
    sha: Option<&'a str>,
    since: Option<Timestamp>,
    per_page: u32,
    page: u32,
}

/// Where a file stands at the head.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Found {
    Blob(String),
    Missing,
    /// The listing couldn't say (a partial walk): the contents API decides.
    Unknown,
}

/// What resolving files at the head found.
struct Resolved {
    found: HashMap<String, Found>,
    listing: Option<Listing>,
    bytes: u64,
    /// The tree was truncated and its walk couldn't finish.
    walk_failed: bool,
}

#[derive(Default)]
pub struct Module;

fn token_of(c: &Config) -> Option<&str> {
    c.token.as_deref().filter(|t| !t.is_empty())
}

fn failed(msg: impl std::fmt::Display) -> CheckError {
    CheckError::Failed(anyhow::anyhow!("{msg}"))
}

/// The `ls-refs` request and its answer for one branch (`None`: the default branch), with the
/// rate-limit and status handling every git request needs.
async fn ls_refs_answer(
    http: &Http,
    now: Timestamp,
    owner: &str,
    repo: &str,
    branch: Option<&str>,
    token: Option<&str>,
) -> Result<bytes::Bytes, CheckError> {
    let url = Url::parse(&format!("{GIT_HOST}/{owner}/{repo}.git/git-upload-pack"))
        .map_err(|_| failed("bad repository URL"))?;
    let body = pktline::ls_refs_request(branch, &super::client::user_agent());
    let mut req = Req::post(url, bytes::Bytes::from(body))
        .header("git-protocol", "version=2")?
        .header("content-type", "application/x-git-upload-pack-request")?
        .header("accept", "application/x-git-upload-pack-result")?;
    if let Some(tok) = token {
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{tok}"));
        req = req.credential("authorization", &format!("Basic {basic}"))?;
    }
    let resp = tokio::time::timeout(LS_REFS_DEADLINE, http.send(req))
        .await
        .map_err(|_| failed("git ls-refs timed out"))??;
    if let Some(until) = rate_limit_until(&resp, now) {
        return Err(CheckError::RateLimited { until });
    }
    if resp.status != http::StatusCode::OK {
        return Err(failed(format!(
            "git ls-refs answered HTTP {} (repository missing or private?)",
            resp.status.as_u16()
        )));
    }
    Ok(resp.bytes_limited(MAX_LS_REFS).await?)
}

/// The name of a repository's default branch (one `ls-refs` with `symrefs`): adding a feed by
/// URL maps a branch URL onto a provider that follows the default branch when they agree
/// (providers.md §3).
pub async fn default_branch(http: &Http, owner: &str, repo: &str, token: Option<&str>) -> Result<String, CheckError> {
    let answer = ls_refs_answer(http, Timestamp::now(), owner, repo, None, token).await?;
    pktline::find_symref_branch(&answer, "HEAD")
        .map_err(|e| failed(format!("git ls-refs: {e}")))?
        .ok_or_else(|| failed("the repository's HEAD names no branch"))
}

impl Module {
    /// The branch head: one `ls-refs`.
    async fn head(&self, ctx: &Ctx, c: &Config, token: Option<&str>) -> Result<String, CheckError> {
        let answer = ls_refs_answer(&ctx.http, ctx.now, &c.owner, &c.repo, c.branch.as_deref(), token).await?;
        let refname = match &c.branch {
            Some(b) => format!("refs/heads/{b}"),
            None => "HEAD".to_string(),
        };
        pktline::find_ref(&answer, &refname)
            .map_err(|e| failed(format!("git ls-refs: {e}")))?
            .ok_or_else(|| failed(format!("the repository has no {refname}")))
    }

    /// A GET to the REST API: the body, `None` for a 404, rate limits and other statuses
    /// handled.
    async fn rest(&self, ctx: &Ctx, url: Url, token: Option<&str>, max: usize) -> Result<Option<bytes::Bytes>, CheckError> {
        let mut req = Req::get(url)
            .header("accept", "application/vnd.github+json")?
            .header("x-github-api-version", "2022-11-28")?;
        if let Some(tok) = token {
            req = req.credential("authorization", &format!("Bearer {tok}"))?;
        }
        let resp = ctx.http.send(req).await?;
        if let Some(until) = rate_limit_until(&resp, ctx.now) {
            return Err(CheckError::RateLimited { until });
        }
        if resp.status == http::StatusCode::NOT_FOUND {
            resp.discard();
            return Ok(None);
        }
        if resp.status != http::StatusCode::OK {
            return Err(failed(format!("the GitHub API answered HTTP {}", resp.status.as_u16())));
        }
        Ok(Some(resp.bytes_limited(max).await?))
    }

    fn api_url(c: &Config, tail: &[&str], query: &[(&str, &str)]) -> Result<Url, CheckError> {
        let mut u = Url::parse(API_HOST).map_err(|_| failed("bad API URL"))?;
        {
            let mut segs = u.path_segments_mut().map_err(|_| failed("bad API URL"))?;
            segs.clear().push("repos").push(&c.owner).push(&c.repo);
            for s in tail {
                segs.push(s);
            }
        }
        if !query.is_empty() {
            u.query_pairs_mut().extend_pairs(query);
        }
        Ok(u)
    }

    async fn commits(&self, ctx: &Ctx, c: &Config, q: CommitsQuery<'_>, token: Option<&str>) -> Result<Vec<Commit>, CheckError> {
        let since_s = q.since.map(|s| picket_api::time::format_secs(&s));
        let per_page_s = q.per_page.to_string();
        let page_s = q.page.to_string();
        let mut query: Vec<(&str, &str)> = vec![("path", q.path), ("per_page", per_page_s.as_str())];
        if let Some(s) = q.sha {
            query.push(("sha", s));
        }
        if let Some(s) = &since_s {
            query.push(("since", s.as_str()));
        }
        if q.page > 1 {
            query.push(("page", page_s.as_str()));
        }
        let url = Self::api_url(c, &["commits"], &query)?;
        let body = self
            .rest(ctx, url, token, MAX_COMMITS)
            .await?
            .ok_or_else(|| failed("the commits API answered HTTP 404"))?;
        parse_commits(&body).map_err(failed)
    }

    /// One trees-API answer: `recursive` from the head, or one directory's own entries.
    async fn tree(&self, ctx: &Ctx, c: &Config, sha: &str, recursive: bool, token: Option<&str>) -> Result<(Tree, u64), CheckError> {
        let query: &[(&str, &str)] = if recursive { &[("recursive", "1")] } else { &[] };
        let url = Self::api_url(c, &["git", "trees", sha], query)?;
        let body = self
            .rest(ctx, url, token, MAX_TREE)
            .await?
            .ok_or_else(|| failed("the trees API answered HTTP 404"))?;
        let n = body.len() as u64;
        Ok((parse_tree(&body).map_err(failed)?, n))
    }

    /// The contents API for one file at the head: its blob, or `Missing` on a 404.
    async fn contents(&self, ctx: &Ctx, c: &Config, head: &str, path: &str, token: Option<&str>) -> Result<Found, CheckError> {
        let mut tail = vec!["contents"];
        tail.extend(path.split('/'));
        let url = Self::api_url(c, &tail, &[("ref", head)])?;
        match self.rest(ctx, url, token, MAX_CONTENTS).await? {
            None => Ok(Found::Missing),
            Some(body) => Ok(Found::Blob(parse_blob_sha(&body).map_err(failed)?)),
        }
    }

    /// Resolves `paths` at `head`, and the listing when `list` (providers.md §3): one recursive
    /// tree, or a bounded walk of a truncated one, then the contents API for what a partial walk
    /// left unresolved.
    #[expect(clippy::too_many_arguments, reason = "one listing request's inputs")]
    async fn resolve(
        &self,
        ctx: &Ctx,
        c: &Config,
        head: &str,
        token: Option<&str>,
        paths: &[&str],
        select: &[String],
        list: bool,
    ) -> Result<Resolved, CheckError> {
        let (tree, mut bytes) = self.tree(ctx, c, head, true, token).await?;
        let mut found: HashMap<String, Found> = HashMap::new();
        if !tree.truncated {
            {
                let blobs: HashMap<&str, &str> = tree
                    .entries
                    .iter()
                    .filter(|e| !e.dir)
                    .map(|e| (e.path.as_str(), e.sha.as_str()))
                    .collect();
                for p in paths {
                    let f = blobs.get(p).map_or(Found::Missing, |s| Found::Blob((*s).to_string()));
                    found.insert((*p).to_string(), f);
                }
            }
            // The listing takes the answer's paths over rather than copying them.
            let listing = list.then(|| Listing {
                files: tree
                    .entries
                    .into_iter()
                    .filter(|e| !e.dir)
                    .map(|e| e.path)
                    .collect(),
                whole: true,
            });
            return Ok(Resolved {
                found,
                listing,
                bytes,
                walk_failed: false,
            });
        }
        // The truncated answer is of no further use: it goes before the walk adds its own.
        drop(tree);
        // Truncated: walk from the root, only into directories a pattern or a feed's path can
        // reach, within the budget.
        let reach = |dir: &[&str]| -> bool {
            let joined = dir.join("/");
            select.iter().any(|p| glob::may_reach(p, dir))
                || paths
                    .iter()
                    .any(|p| p.strip_prefix(joined.as_str()).is_some_and(|r| r.starts_with('/')))
        };
        let mut queue: VecDeque<(String, String)> = VecDeque::from([(String::new(), head.to_string())]);
        let mut requests = 0usize;
        let mut complete_dirs: BTreeSet<String> = BTreeSet::new();
        let mut blobs: BTreeMap<String, String> = BTreeMap::new();
        let mut finished = true;
        // Answer bytes read, plus each kept entry's full path and SHA (MAX_WALK_BYTES).
        let mut walked_bytes = 0u64;
        'walk: while let Some((dir, sha)) = queue.pop_front() {
            if requests >= WALK_BUDGET
                || walked_bytes >= MAX_WALK_BYTES
                || blobs.len() + queue.len() >= MAX_WALK_ENTRIES
            {
                finished = false;
                break;
            }
            requests += 1;
            let (t, n) = self.tree(ctx, c, &sha, false, token).await?;
            bytes += n;
            walked_bytes += n;
            if t.truncated {
                finished = false;
            }
            for e in t.entries {
                let full = if dir.is_empty() {
                    e.path
                } else {
                    format!("{dir}/{}", e.path)
                };
                // No file path can be longer than MAX_PATH: such an entry is never kept, and a
                // directory with no room for `/<name>` below it isn't walked.
                let keep = if e.dir {
                    full.len() + 2 <= MAX_PATH && reach(&full.split('/').collect::<Vec<_>>())
                } else {
                    check_path(&full).is_ok()
                };
                if !keep {
                    continue;
                }
                walked_bytes += (full.len() + e.sha.len()) as u64;
                if walked_bytes > MAX_WALK_BYTES || blobs.len() + queue.len() >= MAX_WALK_ENTRIES {
                    // Over budget inside an answer: this directory isn't complete, and the walk
                    // can't finish.
                    finished = false;
                    break 'walk;
                }
                if e.dir {
                    queue.push_back((full, e.sha));
                } else {
                    blobs.insert(full, e.sha);
                }
            }
            if !t.truncated {
                complete_dirs.insert(dir);
            }
        }
        if !queue.is_empty() {
            finished = false;
        }
        for p in paths {
            let parent = p.rsplit_once('/').map_or("", |(d, _)| d);
            let f = match blobs.get(*p) {
                Some(s) => Found::Blob(s.clone()),
                None if complete_dirs.contains(parent) => Found::Missing,
                None => Found::Unknown,
            };
            found.insert((*p).to_string(), f);
        }
        let listing = if finished {
            // The listing takes the kept paths over rather than copying them.
            list.then(|| Listing {
                files: blobs.into_keys().collect(),
                whole: false,
            })
        } else {
            ctx.listing_incomplete(format!(
                "the repository's tree is truncated and walking the directories `files` can reach takes more than {WALK_BUDGET} requests, {MAX_WALK_ENTRIES} entries or {} MiB of answers and paths",
                MAX_WALK_BYTES >> 20
            ));
            None
        };
        Ok(Resolved {
            found,
            listing,
            bytes,
            walk_failed: !finished,
        })
    }

    /// Downloads a file at `head` (never by branch) and checks its blob hash.
    async fn download(&self, ctx: &Ctx, c: &Config, head: &str, path: &str, blob: &str, token: Option<&str>) -> Result<StagedFile, CheckError> {
        let mut u = Url::parse(RAW_HOST).map_err(|_| failed("bad raw URL"))?;
        {
            let mut segs = u.path_segments_mut().map_err(|_| failed("bad raw URL"))?;
            segs.clear().push(&c.owner).push(&c.repo).push(head);
            for s in path.split('/') {
                segs.push(s);
            }
        }
        let mut req = Req::get(u);
        if let Some(tok) = token {
            req = req.credential("authorization", &format!("Bearer {tok}"))?;
        }
        let resp = ctx.http.send(req).await?;
        if let Some(until) = rate_limit_until(&resp, ctx.now) {
            return Err(CheckError::RateLimited { until });
        }
        if resp.status == http::StatusCode::NOT_FOUND {
            resp.discard();
            return Err(CheckError::Missing);
        }
        if resp.status != http::StatusCode::OK {
            return Err(failed(format!(
                "raw.githubusercontent.com answered HTTP {}",
                resp.status.as_u16()
            )));
        }
        let file = ctx.stage(resp).await?;
        let p = file.path().to_path_buf();
        let got = tokio::task::spawn_blocking(move || git_blob_sha1(&p))
            .await
            .map_err(|e| failed(format!("hashing failed: {e}")))?
            .map_err(|e| failed(format!("cannot hash the download: {e}")))?;
        if blob.len() == 40 && got != blob {
            return Err(failed(format!(
                "the download doesn't match git's blob hash ({got} ≠ {blob})"
            )));
        }
        Ok(file)
    }

    /// One file whose blob at the head differs from its last: its commits and its download.
    async fn changed(
        &self,
        ctx: &Ctx,
        c: &Config,
        head: &str,
        f: &FileCheck,
        blob: &str,
        token: Option<&str>,
    ) -> Result<CheckOutcome, CheckError> {
        // Commits since the file's last known change (and the provider's last check), a day of
        // slack for clocks; a first check reads only the newest commit, for `updated_at`.
        let (since, per_page) = match &f.last {
            Some(l) => {
                let lo = ctx.last_ok.map_or(l.updated_at, |t| t.min(l.updated_at));
                // `lo` is a remote commit time: saturate at the start of the range.
                let since = picket_api::time::saturating_sub(lo, jiff::SignedDuration::from_hours(24));
                (Some(since), 100)
            }
            None => (None, 1),
        };
        let q = CommitsQuery {
            path: &f.file,
            sha: Some(head),
            since,
            per_page,
            page: 1,
        };
        let commits = self.commits(ctx, c, q, token).await?;
        let file = self.download(ctx, c, head, &f.file, blob, token).await?;
        let bytes = file.size() + 4096;
        let newest = commits.iter().map(|x| x.time).max();
        let mut change_times: Vec<ChangeTime> = match &f.last {
            Some(l) => commits
                .iter()
                .filter(|x| x.time > l.updated_at)
                .map(|x| ChangeTime::Exact(x.time))
                .collect(),
            None => vec![],
        };
        if change_times.is_empty()
            && f.last.is_some()
            && let Some(lo) = ctx.last_ok
        {
            change_times.push(ChangeTime::Interval { lo, hi: ctx.now });
        }
        let state = serde_json::to_value(FileState {
            head: head.to_string(),
            blob: blob.to_string(),
        })
        .unwrap_or(Value::Null);
        Ok(CheckOutcome::Changed {
            updated_at: newest.unwrap_or(ctx.now),
            version: blob.to_string(),
            state,
            change_times,
            file,
            bytes,
            method: "download",
        })
    }
}

#[async_trait::async_trait]
impl DownloadModule for Module {
    fn id(&self) -> &'static str {
        "github"
    }

    fn config_schema(&self) -> schemars::Schema {
        super::schema_of::<Config>()
    }

    fn location(&self, cfg: &Value) -> String {
        let owner = cfg.get("owner").and_then(Value::as_str).unwrap_or_default();
        let repo = cfg.get("repo").and_then(Value::as_str).unwrap_or_default();
        location_of(owner, repo.trim_end_matches(".git"))
    }

    fn lists_files(&self) -> bool {
        true
    }

    /// A walk that couldn't finish waits [`WALK_RETRY`] before its head is walked again; a
    /// selection edit ends that wait unless the whole listing kept is for that very head (then
    /// the edit applies to it, and nothing is out of date).
    fn state_for_selection_edit(&self, state: &Value) -> Option<Value> {
        let mut s: ProviderState = serde_json::from_value(state.clone()).ok()?;
        let failed = s.walk_failed.as_ref()?;
        if s.listed_head.as_deref() == Some(failed.head.as_str()) {
            return None;
        }
        s.walk_failed = None;
        serde_json::to_value(&s).ok()
    }

    fn epoch_key(&self, cfg: &Value) -> String {
        // Another branch is another set of files (feeds.md §3 "points elsewhere").
        let branch = cfg.get("branch").and_then(Value::as_str).unwrap_or("HEAD");
        format!("{}#{branch}", self.location(cfg))
    }

    fn check_file(&self, _cfg: &Value, file: &str, pattern: bool) -> Result<(), String> {
        if pattern && glob::is_glob(file) {
            glob::check(file)
        } else {
            check_path(file)
        }
    }

    fn normalize_config(&self, cfg: &Value) -> Result<Normalized, String> {
        let c: Config = super::parse_config(cfg)?;
        checked(&c)?;
        if c.repo.ends_with(".git") {
            return Err("repo is the repository's name, without .git".into());
        }
        if c.token.is_some() && !cfg.get("token").and_then(Value::as_str).is_some_and(super::is_secret_ref) {
            return Err("token takes a ${secret:name} reference".into());
        }
        Ok(Normalized {
            config: cfg.clone(),
            notice: None,
        })
    }

    async fn check(
        &self,
        ctx: &Ctx,
        cfg: &Value,
        state: Option<&Value>,
        feeds: &[FileCheck],
        select: &[String],
    ) -> Result<ProviderCheck, CheckError> {
        let c: Config = super::config_of(cfg)?;
        checked(&c).map_err(failed)?;
        let token = token_of(&c);
        let pstate: ProviderState = state
            .and_then(|s| serde_json::from_value(s.clone()).ok())
            .unwrap_or_default();
        let head = self.head(ctx, &c, token).await?;
        let mut results: Vec<Option<Result<CheckOutcome, CheckError>>> = feeds.iter().map(|_| None).collect();
        let mut todo: Vec<(usize, Option<FileState>)> = Vec::new();
        for (i, f) in feeds.iter().enumerate() {
            let fs: Option<FileState> = f
                .last
                .as_ref()
                .and_then(|l| serde_json::from_value(l.state.clone()).ok());
            if fs.as_ref().is_some_and(|s| s.head == head) {
                results[i] = Some(Ok(CheckOutcome::Unchanged {
                    state: None,
                    observed: vec![],
                    bytes: 1024,
                    method: "ls-refs",
                }));
            } else {
                todo.push((i, fs));
            }
        }
        // A walk that couldn't finish at this head isn't tried again before WALK_RETRY: no tree
        // request for a listing, and the files not yet checked at the head go straight to the
        // contents API (providers.md §3; README §2 Bounded).
        let backoff = pstate
            .walk_failed
            .as_ref()
            .is_some_and(|w| w.head == head && ctx.now - w.at < WALK_RETRY);
        let list = pstate.listed_head.as_deref() != Some(head.as_str()) && !backoff;
        let mut listing = None;
        let mut new_state = pstate.clone();
        if !todo.is_empty() || list {
            let paths: Vec<&str> = todo.iter().map(|(i, _)| feeds[*i].file.as_str()).collect();
            let resolved = if backoff {
                Ok(Resolved {
                    found: HashMap::new(),
                    listing: None,
                    bytes: 0,
                    walk_failed: false,
                })
            } else {
                self.resolve(ctx, &c, &head, token, &paths, select, list).await
            };
            match resolved {
                Err(e) => {
                    // The head's tree couldn't be read: every file not yet checked at the head
                    // fails with it; the files checked at it keep their `Unchanged`.
                    let msg = e.to_string();
                    for (i, _) in &todo {
                        results[*i] = Some(Err(match &e {
                            CheckError::RateLimited { until } => CheckError::RateLimited { until: *until },
                            CheckError::Missing => CheckError::Missing,
                            CheckError::Failed(_) => failed(&msg),
                        }));
                    }
                    if feeds.is_empty() || todo.len() == feeds.len() {
                        // Nothing in the check succeeded: the provider's check failed as a whole.
                        return Err(e);
                    }
                    return Ok(ProviderCheck {
                        state: serde_json::to_value(&new_state).unwrap_or(Value::Null),
                        files: feeds
                            .iter()
                            .zip(results)
                            .map(|(f, r)| (f.file.clone(), r.unwrap_or_else(|| Err(failed("no result")))))
                            .collect(),
                        listing: None,
                    });
                }
                Ok(r) => {
                    if r.listing.is_some() {
                        new_state.listed_head = Some(head.clone());
                        new_state.walk_failed = None;
                    } else if r.walk_failed && list {
                        new_state.walk_failed = Some(WalkFailed {
                            head: head.clone(),
                            at: ctx.now,
                        });
                    }
                    listing = r.listing;
                    let mut limited: Option<Timestamp> = None;
                    for (i, fs) in &todo {
                        let f = &feeds[*i];
                        if let Some(until) = limited {
                            results[*i] = Some(Err(CheckError::RateLimited { until }));
                            continue;
                        }
                        let found = match r.found.get(&f.file).cloned().unwrap_or(Found::Unknown) {
                            Found::Unknown => match self.contents(ctx, &c, &head, &f.file, token).await {
                                Ok(x) => x,
                                Err(e) => {
                                    if let CheckError::RateLimited { until } = &e {
                                        limited = Some(*until);
                                    }
                                    results[*i] = Some(Err(e));
                                    continue;
                                }
                            },
                            x => x,
                        };
                        let out = match found {
                            Found::Missing | Found::Unknown => Err(CheckError::Missing),
                            Found::Blob(blob) if fs.as_ref().is_some_and(|s| s.blob == blob) => {
                                Ok(CheckOutcome::Unchanged {
                                    state: serde_json::to_value(FileState {
                                        head: head.clone(),
                                        blob,
                                    })
                                    .ok(),
                                    observed: vec![],
                                    bytes: 1024 + r.bytes / (todo.len() as u64).max(1),
                                    method: "tree",
                                })
                            }
                            Found::Blob(blob) => self.changed(ctx, &c, &head, f, &blob, token).await,
                        };
                        if let Err(CheckError::RateLimited { until }) = &out {
                            limited = Some(*until);
                        }
                        results[*i] = Some(out);
                    }
                }
            }
        }
        Ok(ProviderCheck {
            state: serde_json::to_value(&new_state).unwrap_or(Value::Null),
            files: feeds
                .iter()
                .zip(results)
                .map(|(f, r)| (f.file.clone(), r.unwrap_or_else(|| Err(failed("no result")))))
                .collect(),
            listing,
        })
    }

    async fn history(&self, ctx: &Ctx, cfg: &Value, file: &str) -> anyhow::Result<Vec<ChangeTime>> {
        let c: Config = serde_json::from_value(cfg.clone())?;
        checked(&c).map_err(|e| anyhow::anyhow!(e))?;
        check_path(file).map_err(|e| anyhow::anyhow!(e))?;
        let token = token_of(&c);
        let since = ctx.now - jiff::SignedDuration::from_hours(24 * (HISTORY_DAYS));
        let mut out = Vec::new();
        for page in 1..=HISTORY_PAGES {
            let q = CommitsQuery {
                path: file,
                sha: c.branch.as_deref(),
                since: Some(since),
                per_page: 100,
                page,
            };
            let commits = match self.commits(ctx, &c, q, token).await {
                Ok(c) => c,
                // Core pauses the module on it (providers.md §2): the error carries it.
                Err(e @ CheckError::RateLimited { .. }) => return Err(anyhow::Error::new(e)),
                Err(CheckError::Failed(e)) => return Err(e),
                Err(e @ CheckError::Missing) => return Err(anyhow::Error::new(e)),
            };
            let n = commits.len();
            // Root commits are history rewrites, not changes (feed-scheduling.md §6).
            out.extend(
                commits
                    .into_iter()
                    .filter(|c| !c.root && c.time >= since)
                    .map(|c| ChangeTime::Exact(c.time)),
            );
            if out.len() >= HISTORY_CHANGES || n < 100 {
                break;
            }
        }
        out.truncate(HISTORY_CHANGES);
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
