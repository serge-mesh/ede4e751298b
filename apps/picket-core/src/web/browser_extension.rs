//! The browser extension downloads (core.md §1 `web`, §11 `lists.allow_cidrs`, §12 "Browser
//! extension"; browser-extension.md §1; build-and-test.md §3).
//!
//! The core package carries the CI-built extension under `/usr/share/picket-core/browser-extension/`
//! (build-and-test.md §3: "the edge release tarballs and extension builds are under
//! `/usr/share/picket-core/`"; the release pipeline adds them to the `.deb` beside the edge
//! release): `picket-browser-extension-<version>-brave.zip` and
//! `picket-browser-extension-<version>-firefox.xpi`. Nothing leaves the network: core serves
//! exactly those files.
//!
//! - **Builds** ([`Builds`]): the directory is read once, on first use, on a blocking thread
//!   (at most [`MAX_FILES`] files of at most [`MAX_FILE_BYTES`] each; anything else in it is
//!   ignored) and each build's SHA-256 is computed then; callers meanwhile wait without holding a
//!   runtime worker. Released files never change while core runs. Newest version first per
//!   browser, versions compared part by part, numbers as numbers (`0.10` after `0.9`).
//! - `GET /browser-extension/<file>` streams a listed build (never read whole into memory), open under
//!   `lists.allow_cidrs` without basic auth (devices and browsers fetch it without credentials,
//!   core.md §12); any other name is `404`, so no path outside the listing is ever read.
//! - `GET /api/ui/v1/browser-extension` lists the builds: browser, version, file, download path, size
//!   and SHA-256.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use schemars::JsonSchema;
use serde::Serialize;
use sha2::Digest;

use crate::state::SharedState;

/// Where the package puts the builds.
pub const DEFAULT_DIR: &str = "/usr/share/picket-core/browser-extension";
/// Files read from the directory at most (README §2 Bounded).
pub const MAX_FILES: usize = 16;
/// The largest build served.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const PREFIX: &str = "picket-browser-extension-";

/// One extension build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct BrowserExtensionBuild {
    /// `brave` or `firefox`.
    pub browser: String,
    pub version: String,
    /// The file name.
    pub file: String,
    /// Where to download it: `/browser-extension/<file>` (open, no basic auth).
    pub path: String,
    pub size: u64,
    /// The file's SHA-256, hex.
    pub sha256: String,
}

/// The builds in the package.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub struct BrowserExtensionBuilds {
    pub items: Vec<BrowserExtensionBuild>,
}

/// The builds core serves, read once from the package directory.
pub struct Builds {
    dir: PathBuf,
    list: tokio::sync::OnceCell<Arc<[BrowserExtensionBuild]>>,
}

impl Builds {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            list: tokio::sync::OnceCell::new(),
        }
    }

    /// The builds (read and hashed on first use, on a blocking thread; a read error lists none).
    pub async fn list(&self) -> Arc<[BrowserExtensionBuild]> {
        self.list
            .get_or_init(|| async {
                let dir = self.dir.clone();
                let scanned = tokio::task::spawn_blocking(move || scan(&dir)).await;
                let l = match scanned {
                    Ok(Ok(l)) => l,
                    Ok(Err(e)) => {
                        tracing::info!(dir = %self.dir.display(), error = %e, "no browser extension builds");
                        Vec::new()
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "the browser extension scan failed");
                        Vec::new()
                    }
                };
                Arc::from(l)
            })
            .await
            .clone()
    }

    async fn file(&self, name: &str) -> Option<(BrowserExtensionBuild, PathBuf)> {
        self.list()
            .await
            .iter()
            .find(|b| b.file == name)
            .map(|b| (b.clone(), self.dir.join(&b.file)))
    }
}

/// Compares two versions as SemVer orders them: the dotted parts, numbers as numbers (`0.10`
/// after `0.9`); then a pre-release (`-rc1`) before the release; build metadata (`+…`) ignored
/// except as a last tie-break.
pub fn version_cmp(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (&str, Option<&str>) {
        let v = v.split('+').next().unwrap_or(v);
        match v.split_once('-') {
            Some((m, p)) => (m, Some(p)),
            None => (v, None),
        }
    }
    fn parts(a: &str, b: &str) -> Ordering {
        let pa: Vec<&str> = a.split(['.', '_']).collect();
        let pb: Vec<&str> = b.split(['.', '_']).collect();
        for (x, y) in pa.iter().zip(&pb) {
            let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                (Ok(m), Ok(n)) => m.cmp(&n),
                // SemVer §11: numeric identifiers sort before alphanumeric ones.
                (Ok(_), Err(_)) => Ordering::Less,
                (Err(_), Ok(_)) => Ordering::Greater,
                (Err(_), Err(_)) => x.cmp(y),
            };
            if o != Ordering::Equal {
                return o;
            }
        }
        pa.len().cmp(&pb.len())
    }
    let ((ma, pa), (mb, pb)) = (split(a), split(b));
    parts(ma, mb)
        .then_with(|| match (pa, pb) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(x), Some(y)) => parts(x, y),
        })
        .then_with(|| a.cmp(b))
}

/// `(browser, version)` of a build file name.
pub fn parse_name(name: &str) -> Option<(&'static str, String)> {
    let rest = name.strip_prefix(PREFIX)?;
    let (version, browser) = match rest.strip_suffix("-brave.zip") {
        Some(v) => (v, "brave"),
        None => (rest.strip_suffix("-firefox.xpi")?, "firefox"),
    };
    let ok = !version.is_empty()
        && version.len() <= 64
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'));
    ok.then(|| (browser, version.to_string()))
}

/// Reads the builds in `dir`, newest version first per browser.
pub fn scan(dir: &Path) -> std::io::Result<Vec<BrowserExtensionBuild>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)?.take(256) {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let Some((browser, version)) = parse_name(&name) else {
            continue;
        };
        let meta = std::fs::symlink_metadata(e.path())?;
        if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let mut f = std::io::Read::take(std::fs::File::open(e.path())?, MAX_FILE_BYTES + 1);
        let mut h = sha2::Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut n: u64 = 0;
        loop {
            let k = std::io::Read::read(&mut f, &mut buf)?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            n += k as u64;
        }
        if n > MAX_FILE_BYTES {
            continue;
        }
        out.push(BrowserExtensionBuild {
            browser: browser.into(),
            version,
            path: format!("/browser-extension/{name}"),
            file: name,
            size: n,
            sha256: hex::encode(h.finalize()),
        });
        if out.len() >= MAX_FILES {
            break;
        }
    }
    out.sort_by(|a, b| {
        a.browser
            .cmp(&b.browser)
            .then(version_cmp(&b.version, &a.version))
    });
    Ok(out)
}

/// `GET /browser-extension/<file>`: streamed, at most the listed size.
pub async fn download(State(s): State<SharedState>, AxPath(name): AxPath<String>) -> Response {
    let not_found = || (StatusCode::NOT_FOUND, "not found\n").into_response();
    let Some((b, path)) = s.browser_extension.file(&name).await else {
        return not_found();
    };
    let Ok(f) = tokio::fs::File::open(path).await else {
        return not_found();
    };
    let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::with_capacity(
        tokio::io::AsyncReadExt::take(f, b.size),
        64 * 1024,
    ));
    let ct = if b.browser == "firefox" {
        "application/x-xpinstall"
    } else {
        "application/zip"
    };
    (
        [
            (header::CONTENT_TYPE, ct.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", b.file),
            ),
            (header::CACHE_CONTROL, "no-cache".to_string()),
            (header::CONTENT_LENGTH, b.size.to_string()),
        ],
        body,
    )
        .into_response()
}

/// `GET /api/ui/v1/browser-extension`.
pub async fn list(State(s): State<SharedState>) -> Json<BrowserExtensionBuilds> {
    Json(BrowserExtensionBuilds {
        items: s.browser_extension.list().await.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_names() {
        assert_eq!(
            parse_name("picket-browser-extension-1.2.3-brave.zip"),
            Some(("brave", "1.2.3".into()))
        );
        assert_eq!(
            parse_name("picket-browser-extension-0.1.0-firefox.xpi"),
            Some(("firefox", "0.1.0".into()))
        );
        assert_eq!(parse_name("picket-browser-extension--brave.zip"), None);
        assert_eq!(parse_name("picket-browser-extension-1/../x-brave.zip"), None);
        assert_eq!(parse_name("other.zip"), None);
    }

    #[test]
    fn scans_builds_with_their_sums() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("picket-browser-extension-0.1.0-brave.zip"), b"zip").unwrap();
        std::fs::write(
            d.path().join("picket-browser-extension-0.1.0-firefox.xpi"),
            b"xpi",
        )
        .unwrap();
        std::fs::write(d.path().join("README"), b"no").unwrap();
        let l = scan(d.path()).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].browser, "brave");
        assert_eq!(l[0].sha256, hex::encode(sha2::Sha256::digest(b"zip")));
        assert_eq!(
            l[1].path,
            "/browser-extension/picket-browser-extension-0.1.0-firefox.xpi"
        );
    }

    #[test]
    fn versions_sort_as_numbers() {
        let d = tempfile::tempdir().unwrap();
        for v in ["0.9.0", "0.10.0", "0.2.1"] {
            std::fs::write(
                d.path().join(format!("picket-browser-extension-{v}-brave.zip")),
                v.as_bytes(),
            )
            .unwrap();
        }
        let l = scan(d.path()).unwrap();
        let v: Vec<&str> = l.iter().map(|b| b.version.as_str()).collect();
        assert_eq!(v, ["0.10.0", "0.9.0", "0.2.1"], "newest first, 0.10 after 0.9");
        assert_eq!(version_cmp("1.0.0", "1.0.0-rc.2"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0-rc.10", "1.0.0-rc.2"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0", "1.0"), Ordering::Greater);
    }
}
