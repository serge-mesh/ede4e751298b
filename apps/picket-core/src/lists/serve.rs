//! Serving browser lists (bundles.md §8 "Serving"; core.md §12): `GET /lists/<bundle>.txt`,
//! `GET /lists/profiles/<profile>.txt` and `GET /lists/profiles/<profile>-full.txt` on the web port
//! and the plain-HTTP port, behind `lists.allow_cidrs` (the protection layer checks it) and
//! without basic auth. `ETag` is the BLAKE3 of the text, `Last-Modified` the write time, `304`
//! for a matching `If-None-Match`, and the gzip copy when the client accepts it. A list core
//! doesn't serve (an unknown bundle or profile, a profile whose list is off) is `404`.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::OptionalExtension;

use crate::state::SharedState;

/// True for a path segment a list name may hold (bundle and profile ids).
fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !s.starts_with('.')
}

/// The stored path (`lists/…`) of a request path (after `/lists/`), if it names a list.
pub fn list_path(p: &str) -> Option<String> {
    let parts: Vec<&str> = p.split('/').collect();
    match parts.as_slice() {
        [file] => {
            let name = file.strip_suffix(".txt")?;
            segment_ok(name).then(|| format!("lists/{name}.txt"))
        }
        ["profiles", file] => {
            let name = file.strip_suffix(".txt")?;
            segment_ok(name).then(|| format!("lists/profiles/{name}.txt"))
        }
        _ => None,
    }
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// `GET /lists/{*path}`.
pub async fn get(State(s): State<SharedState>, Path(p): Path<String>, headers: HeaderMap) -> Response {
    let Some(path) = list_path(&p) else {
        return not_found();
    };
    let p2 = path.clone();
    let row: Option<(String, String)> = match s
        .db
        .read(move |c| {
            c.query_row(
                "SELECT blake3, written_at FROM browser_lists WHERE path = ?1",
                [&p2],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(anyhow::Error::from)
        })
        .await
    {
        Ok(r) => r,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let Some((etag, written)) = row else {
        return not_found();
    };
    let last_modified = crate::util::parse_ts(&written)
        .map(|t| crate::util::http_date(&t))
        .unwrap_or_default();
    let quoted = format!("\"{etag}\"");
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| crate::edge_api::objects::tag_matches(v, &etag))
    {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        if let Ok(v) = HeaderValue::from_str(&quoted) {
            r.headers_mut().insert(header::ETAG, v);
        }
        return r;
    }
    let gzip = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|e| e.trim().split(';').next() == Some("gzip")));
    let mut file = s.data_dir.join(&path);
    if gzip {
        let mut g = file.clone().into_os_string();
        g.push(".gz");
        file = g.into();
    }
    let bytes = match tokio::fs::read(&file).await {
        Ok(b) => b,
        Err(_) => return not_found(),
    };
    let mut r = Response::new(Body::from(bytes));
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    if gzip {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    if let Ok(v) = HeaderValue::from_str(&quoted) {
        h.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&last_modified) {
        h.insert(header::LAST_MODIFIED, v);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_paths() {
        assert_eq!(
            list_path("block-common.txt").as_deref(),
            Some("lists/block-common.txt")
        );
        assert_eq!(
            list_path("profiles/kids.txt").as_deref(),
            Some("lists/profiles/kids.txt")
        );
        assert_eq!(
            list_path("profiles/kids-full.txt").as_deref(),
            Some("lists/profiles/kids-full.txt")
        );
        for bad in [
            "../x.txt",
            "profiles/../x.txt",
            "x",
            "a/b/c.txt",
            ".x.txt",
            "profiles/.txt",
            "",
        ] {
            assert_eq!(list_path(bad), None, "{bad}");
        }
    }
}
