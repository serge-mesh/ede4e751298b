//! The embedded UI (`ui/dist`, core.md §12). A missing `ui/dist` still compiles (rust-embed
//! `allow_missing`), and core then serves a minimal placeholder page. An unknown GET path is a
//! client-side route and gets `index.html` (the UI routes on the client), whatever its last
//! segment holds (`/clients/device/192.168.1.20`); a missing asset path ([`is_asset_path`]) is a
//! `404`, so a missing script never gets HTML with 200.

use axum::http::{Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../ui/dist"]
#[allow_missing = true]
struct Ui;

/// Shown while no UI is embedded. No inline script or style, so it holds under the CSP.
const PLACEHOLDER: &str = "<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Picket core</title></head>
<body><h1>Picket core</h1>
<p>The web UI isn't part of this build yet. The UI API is at <code>/api/ui/v1</code>
(OpenAPI document: <a href=\"/api/ui/v1/openapi.json\">/api/ui/v1/openapi.json</a>).</p>
</body></html>
";

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// True when a UI is embedded.
pub fn embedded() -> bool {
    Ui::get("index.html").is_some()
}

/// Extensions of the files a UI build has at its top level (icons, manifests, robots.txt…) or
/// loads (scripts, styles, fonts, images).
const STATIC_EXTENSIONS: &[&str] = &[
    "html",
    "js",
    "mjs",
    "css",
    "map",
    "json",
    "webmanifest",
    "svg",
    "png",
    "ico",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "avif",
    "woff",
    "woff2",
    "ttf",
    "otf",
    "txt",
    "xml",
    "wasm",
];

/// True for a path only a file of the UI build can answer: anything under `assets/` (the
/// build's hashed output) and a top-level name with a static file's extension (`favicon.ico`,
/// `robots.txt`, `/main.js`). A path deeper than the top level outside `assets/` is a client-side
/// route, dots and all.
pub fn is_asset_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    if path == "assets" || path.starts_with("assets/") {
        return true;
    }
    if path.contains('/') {
        return false;
    }
    path.rsplit_once('.')
        .is_some_and(|(_, ext)| STATIC_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

pub async fn serve(method: Method, uri: Uri) -> Response {
    // Paths outside the UI's class (`/lists*`, `/lanca/*`, `/browser-extension/*`, `/healthz`,
    // `/metrics`) pass the guard without basic auth: they serve only their exact resources, and
    // never the UI document (core.md §12).
    if super::protect::classify(uri.path()) != super::protect::PathClass::Ui {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }
    // The UI is read, never written: only GET and HEAD are served.
    if method != Method::GET && method != Method::HEAD {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if path.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(f) = Ui::get(path) {
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return (
            [
                (header::CONTENT_TYPE, content_type(path)),
                (header::CACHE_CONTROL, cache),
            ],
            f.data.into_owned(),
        )
            .into_response();
    }
    // A missing asset is a 404; any other GET is a client-side route.
    if path != "index.html" && is_asset_path(path) {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }
    match Ui::get("index.html") {
        Some(f) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            f.data.into_owned(),
        )
            .into_response(),
        None => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            PLACEHOLDER,
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_paths_and_client_routes() {
        for p in [
            "assets/index-abc123.js",
            "/assets/x.css",
            "assets/sub/font.woff2",
            "assets/noext",
            "assets",
            "favicon.ico",
            "favicon.svg",
            "robots.txt",
            "main.JS",
            "site.webmanifest",
        ] {
            assert!(is_asset_path(p), "{p}");
        }
        for p in [
            "clients/device/192.168.1.20",
            "/logs/qname/example.com",
            "feeds/hagezi-tif",
            "192.168.1.20",
            "settings",
            "feeds/x.js",
            "",
        ] {
            assert!(!is_asset_path(p), "{p}");
        }
    }
}
