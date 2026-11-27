//! The `objects` bucket (api.md §2): path-style S3 `GetObject` and `HeadObject` only, no
//! listing, no version in keys.
//!
//! | Key | Source | Readable by | `Cache-Control` |
//! |---|---|---|---|
//! | `configs/<fp>.json` | the edge's published `EdgeConfig` (`edges::publish`) | edge `<fp>` only | `no-store` |
//! | `bundles/<bundle>/heads/<id>.json` | a `bundle_versions` head, from the blob store | any pinned edge | immutable |
//! | `verdict-sets/<provider>/heads/<id>.json` | a `verdict_sets` head, from the blob store | any pinned edge | immutable |
//! | `blobs/<blake3>` | the blob store: bundle and verdict-set blobs only (their kind, or a version naming them) | any pinned edge | immutable |
//! | `releases/<version>/picket-edge-<version>-<arch>.tar.gz` (+ `.minisig`) | `edge_releases` | any pinned edge | immutable |
//!
//! Headers: `ETag: "<id>"` (the BLAKE3 of the bytes), `Content-Length`, `Last-Modified`,
//! `Accept-Ranges: bytes`. Errors are the status alone, with no body and no `Content-Type`:
//! `304` `If-None-Match` matches; `403` another edge's config (existing or not); `404` any other
//! missing key (raw downloads and manual files included); `405` not `GET` or `HEAD`; `412`
//! `If-Match` fails; `416` a bad `Range`. Serving a config pins what it names for that edge
//! before the bytes go out (storage.md §4).
//!
//! Bundle heads and blobs come from the compiler (`compiler::commit` registers each version's
//! blobs as kind `bundle`); verdict-set heads and blobs from the verdict-set publisher
//! (`lookups::verdict_sets` registers each version's head, base and deltas as kind
//! `verdict_set`). A blob keeps the kind it was first registered with (`crate::blobs`), so a
//! head or release is served whatever kind its blob has: the row that names it decides.

use std::path::PathBuf;

use axum::Extension;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use rusqlite::OptionalExtension;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::EdgePeer;
use crate::state::SharedState;

const IMMUTABLE: &str = "max-age=31536000, immutable";

/// Where an object's bytes come from.
enum Source {
    Memory(Bytes),
    File { path: PathBuf, len: u64 },
}

/// A resolved object.
struct Object {
    source: Source,
    etag: String,
    last_modified: Option<String>,
    cache_control: &'static str,
    content_type: &'static str,
}

impl Object {
    fn len(&self) -> u64 {
        match &self.source {
            Source::Memory(b) => b.len() as u64,
            Source::File { len, .. } => *len,
        }
    }
}

/// A status with no body and no `Content-Type` (api.md §2 Objects errors).
fn bare(status: StatusCode) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = status;
    r
}

/// True when `s` is a key segment core accepts (a bundle or provider id).
fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && s != "."
        && s != ".."
}

/// Why a key resolves to nothing servable.
enum Miss {
    Forbidden,
    NotFound,
    Internal,
}

/// Which blobs a key may serve.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Serve {
    /// The blob a row the caller found names (a release, a head): any kind, since blobs keep the
    /// kind they were first registered with and the same bytes may have come in as another
    /// (`crate::blobs`).
    Named,
    /// `blobs/<b3>`: bundle and verdict-set blobs only, never raw downloads or manual files
    /// (api.md §2), whatever kind they were first registered with.
    EdgeBlob,
}

async fn blob_object(
    state: &SharedState,
    b3: &str,
    serve: Serve,
    content_type: &'static str,
) -> Result<Object, Miss> {
    if !picket_api::ids::is_object_id(b3) {
        return Err(Miss::NotFound);
    }
    let b = b3.to_string();
    let info = state
        .db
        .read(move |c| {
            let Some((kind, size, created)) = crate::blobs::info(c, &b)? else {
                return Ok(None);
            };
            let servable = serve == Serve::Named
                || matches!(
                    kind.as_str(),
                    crate::blobs::kind::BUNDLE | crate::blobs::kind::VERDICT_SET
                )
                || c.query_row(
                    "SELECT EXISTS (SELECT 1 FROM bundle_version_blobs WHERE blake3 = ?1)
                         OR EXISTS (SELECT 1 FROM verdict_set_blobs WHERE blake3 = ?1)",
                    [&b],
                    |r| r.get::<_, bool>(0),
                )?;
            Ok::<_, anyhow::Error>(Some((servable, size, created)))
        })
        .await
        .map_err(|_| Miss::Internal)?;
    let Some((servable, _size, created)) = info else {
        return Err(Miss::NotFound);
    };
    if !servable {
        return Err(Miss::NotFound); // raw downloads and manual files (api.md §2)
    }
    let path = crate::blobs::path(&state.data_dir, b3).map_err(|_| Miss::NotFound)?;
    let len = tokio::fs::metadata(&path)
        .await
        .map_err(|_| Miss::NotFound)?
        .len();
    Ok(Object {
        source: Source::File { path, len },
        etag: b3.to_string(),
        last_modified: Some(created),
        cache_control: IMMUTABLE,
        content_type,
    })
}

async fn resolve(state: &SharedState, peer: &EdgePeer, key: &str) -> Result<Object, Miss> {
    let parts: Vec<&str> = key.split('/').collect();
    match parts.as_slice() {
        ["configs", file] => {
            // Only the edge's own config, existing or not (api.md §2).
            let own = picket_api::ids::parse_fingerprint(&peer.fingerprint)
                .map(|h| format!("{}.json", picket_api::ids::fingerprint_path(&h)));
            if own.as_deref() != Some(*file) {
                return Err(Miss::Forbidden);
            }
            let p = state
                .edges
                .publisher
                .current_or_render(state, &peer.edge_id)
                .await
                .map_err(|_| Miss::Internal)?;
            // Pin what it names before the bytes go out (storage.md §4).
            state
                .edges
                .publisher
                .pin_served(state, &p)
                .await
                .map_err(|_| Miss::Internal)?;
            Ok(Object {
                source: Source::Memory(p.bytes.clone()),
                etag: p.id.clone(),
                last_modified: Some(p.published_at.clone()),
                cache_control: "no-store",
                content_type: "application/json",
            })
        }
        ["bundles", bundle, "heads", file] | ["verdict-sets", bundle, "heads", file] => {
            let Some(id) = file.strip_suffix(".json") else {
                return Err(Miss::NotFound);
            };
            if !segment_ok(bundle) || !picket_api::ids::is_object_id(id) {
                return Err(Miss::NotFound);
            }
            let sql = if parts[0] == "bundles" {
                "SELECT 1 FROM bundle_versions WHERE bundle_id = ?1 AND head_id = ?2"
            } else {
                "SELECT 1 FROM verdict_sets WHERE provider_id = ?1 AND head_id = ?2"
            };
            let (b, i) = (bundle.to_string(), id.to_string());
            let known = state
                .db
                .read(move |c| {
                    c.query_row(sql, [&b, &i], |_| Ok(()))
                        .optional()
                        .map(|o| o.is_some())
                        .map_err(anyhow::Error::from)
                })
                .await
                .map_err(|_| Miss::Internal)?;
            if !known {
                return Err(Miss::NotFound);
            }
            blob_object(state, id, Serve::Named, "application/json").await
        }
        ["blobs", b3] => blob_object(state, b3, Serve::EdgeBlob, "application/octet-stream").await,
        ["releases", version, file] => {
            if !picket_api::update::is_release_version(version) {
                return Err(Miss::NotFound);
            }
            let prefix = format!("picket-edge-{version}-");
            let rest = file.strip_prefix(&prefix).ok_or(Miss::NotFound)?;
            let (arch, sig) = match rest.strip_suffix(".tar.gz.minisig") {
                Some(a) => (a, true),
                None => (rest.strip_suffix(".tar.gz").ok_or(Miss::NotFound)?, false),
            };
            if !crate::edges::releases::ARCHES.contains(&arch) {
                return Err(Miss::NotFound);
            }
            let (v, a) = (version.to_string(), arch.to_string());
            let row = state
                .db
                .read(move |c| crate::edges::releases::lookup(c, &v, &a).map_err(anyhow::Error::from))
                .await
                .map_err(|_| Miss::Internal)?;
            let Some((blob, minisig, added)) = row else {
                return Err(Miss::NotFound);
            };
            if sig {
                let bytes = Bytes::from(minisig.into_bytes());
                Ok(Object {
                    etag: picket_api::ids::object_id(&bytes),
                    source: Source::Memory(bytes),
                    last_modified: Some(added),
                    cache_control: IMMUTABLE,
                    content_type: "text/plain",
                })
            } else {
                let mut o = blob_object(state, &blob, Serve::Named, "application/gzip").await?;
                o.last_modified = Some(added);
                Ok(o)
            }
        }
        _ => Err(Miss::NotFound),
    }
}

/// True when an `If-Match`/`If-None-Match` value lists `etag` (or is `*`).
pub fn tag_matches(value: &str, etag: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|t| t == "*" || t.trim_start_matches("W/").trim_matches('"') == etag)
}

/// A `Range` header core can't serve (`416`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadRange;

/// A parsed single `Range: bytes=…`: `Ok(None)` when there is none, `Err` for a bad one.
pub fn parse_range(h: Option<&HeaderValue>, len: u64) -> Result<Option<(u64, u64)>, BadRange> {
    let Some(h) = h else { return Ok(None) };
    let s = h.to_str().map_err(|_| BadRange)?.trim();
    let spec = s.strip_prefix("bytes=").ok_or(BadRange)?;
    if spec.contains(',') {
        return Err(BadRange); // one range at a time
    }
    let (a, b) = spec.split_once('-').ok_or(BadRange)?;
    let (a, b) = (a.trim(), b.trim());
    let (start, end) = if a.is_empty() {
        let n: u64 = b.parse().map_err(|_| BadRange)?;
        if n == 0 || len == 0 {
            return Err(BadRange);
        }
        (len.saturating_sub(n), len - 1)
    } else {
        let start: u64 = a.parse().map_err(|_| BadRange)?;
        let end: u64 = if b.is_empty() {
            len.saturating_sub(1)
        } else {
            b.parse::<u64>().map_err(|_| BadRange)?.min(len.saturating_sub(1))
        };
        (start, end)
    };
    if len == 0 || start > end || start >= len {
        return Err(BadRange);
    }
    Ok(Some((start, end)))
}

fn http_date(ts: &str) -> Option<String> {
    crate::util::parse_ts(ts).map(|t| crate::util::http_date(&t))
}

/// `GET`/`HEAD /objects/<key>`.
pub async fn handle(
    State(state): State<SharedState>,
    Extension(peer): Extension<EdgePeer>,
    method: Method,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        let mut r = bare(StatusCode::METHOD_NOT_ALLOWED);
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return r;
    }
    if key.len() > 512 {
        return bare(StatusCode::NOT_FOUND);
    }
    let obj = match resolve(&state, &peer, &key).await {
        Ok(o) => o,
        Err(Miss::Forbidden) => return bare(StatusCode::FORBIDDEN),
        Err(Miss::NotFound) => return bare(StatusCode::NOT_FOUND),
        Err(Miss::Internal) => return bare(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let len = obj.len();
    let etag = format!("\"{}\"", obj.etag);
    let mut base = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&etag) {
        base.insert(header::ETAG, v);
    }
    base.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    base.insert(header::CACHE_CONTROL, HeaderValue::from_static(obj.cache_control));
    if let Some(lm) = obj.last_modified.as_deref().and_then(http_date)
        && let Ok(v) = HeaderValue::from_str(&lm)
    {
        base.insert(header::LAST_MODIFIED, v);
    }
    if let Some(im) = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok())
        && !tag_matches(im, &obj.etag)
    {
        return bare(StatusCode::PRECONDITION_FAILED);
    }
    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok())
        && tag_matches(inm, &obj.etag)
    {
        let mut r = bare(StatusCode::NOT_MODIFIED);
        r.headers_mut().extend(base);
        return r;
    }
    // `If-Range` with another validator serves the whole object.
    let range_header = match headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) {
        Some(ir) if !tag_matches(ir, &obj.etag) => None,
        _ => headers.get(header::RANGE),
    };
    let range = match parse_range(range_header, len) {
        Ok(r) => r,
        Err(BadRange) => {
            let mut r = bare(StatusCode::RANGE_NOT_SATISFIABLE);
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{len}")) {
                r.headers_mut().insert(header::CONTENT_RANGE, v);
            }
            return r;
        }
    };
    let (start, end, status) = match range {
        Some((s, e)) => (s, e, StatusCode::PARTIAL_CONTENT),
        None => (0, len.saturating_sub(1), StatusCode::OK),
    };
    let count = if len == 0 { 0 } else { end - start + 1 };
    let mut out = HeaderMap::new();
    out.extend(base);
    out.insert(header::CONTENT_TYPE, HeaderValue::from_static(obj.content_type));
    out.insert(header::CONTENT_LENGTH, HeaderValue::from(count));
    if status == StatusCode::PARTIAL_CONTENT
        && let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{end}/{len}"))
    {
        out.insert(header::CONTENT_RANGE, v);
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        match obj.source {
            Source::Memory(b) => {
                // The range was checked against the body's length above.
                let range = usize::try_from(start)
                    .ok()
                    .zip(usize::try_from(start + count).ok());
                Body::from(range.map_or_else(bytes::Bytes::new, |(s, e)| b.slice(s..e)))
            }
            Source::File { path, .. } => {
                let mut f = match tokio::fs::File::open(&path).await {
                    Ok(f) => f,
                    Err(_) => return bare(StatusCode::NOT_FOUND),
                };
                if f.seek(std::io::SeekFrom::Start(start)).await.is_err() {
                    return bare(StatusCode::INTERNAL_SERVER_ERROR);
                }
                Body::from_stream(tokio_util::io::ReaderStream::new(f.take(count)))
            }
        }
    };
    let mut r = (status, body).into_response();
    *r.headers_mut() = out;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let h = |s: &str| HeaderValue::from_str(s).unwrap();
        assert_eq!(parse_range(None, 10), Ok(None));
        assert_eq!(parse_range(Some(&h("bytes=0-3")), 10), Ok(Some((0, 3))));
        assert_eq!(parse_range(Some(&h("bytes=5-")), 10), Ok(Some((5, 9))));
        assert_eq!(parse_range(Some(&h("bytes=-3")), 10), Ok(Some((7, 9))));
        assert_eq!(parse_range(Some(&h("bytes=8-100")), 10), Ok(Some((8, 9))));
        for bad in [
            "bytes=10-",
            "bytes=5-2",
            "items=0-1",
            "bytes=0-1,3-4",
            "bytes=-0",
            "bytes=x-1",
        ] {
            assert_eq!(parse_range(Some(&h(bad)), 10), Err(BadRange), "{bad}");
        }
    }

    #[test]
    fn etags() {
        assert!(tag_matches("\"abc\"", "abc"));
        assert!(tag_matches("W/\"abc\", \"x\"", "abc"));
        assert!(tag_matches("*", "abc"));
        assert!(!tag_matches("\"abd\"", "abc"));
    }
}
