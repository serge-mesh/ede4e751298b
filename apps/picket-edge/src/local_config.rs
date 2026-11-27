//! `edge.json`, the only file written by hand, by `picket-edge setup` or by a deployment tool
//! (edge.md §2). Plain JSON; unknown fields are kept when `setup` rewrites it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use serde::Deserialize;

use crate::fsutil::{self, Owner, WriteOpts};
use crate::paths::HostPlatform;
use crate::users;

// Compiled-in release public keys: the default `release_keys` (edge.md §2), populated at build
// time from `PICKET_RELEASE_PUB` / `PICKET_RELEASE_PUB_FILE`.
include!(concat!(env!("OUT_DIR"), "/release_keys.rs"));

/// Largest `edge.json` we read.
const MAX_EDGE_JSON: u64 = 256 << 10;
/// Most `allowed_binds` / `release_keys` entries.
const MAX_LIST: usize = 1024;

/// The validated contents of `edge.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalConfig {
    /// `https://<ip literal>[:port]`; `None` until setup.
    pub core_url: Option<CoreUrl>,
    /// Pinned SPKI hash of picket-core (`SHA256:…`); `None` until setup confirms it.
    pub core_key: Option<String>,
    /// `["*"]` (default) or exact `ip:port` strings.
    pub allowed_binds: Vec<String>,
    pub ssd_dir: Option<PathBuf>,
    pub updates_enabled: bool,
    /// Minisign public keys (base64 lines).
    pub release_keys: Vec<String>,
    /// `data_dir` from the file, if set (`--data-dir` and the platform default come on top).
    pub data_dir: Option<PathBuf>,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            core_url: None,
            core_key: None,
            allowed_binds: vec!["*".into()],
            ssd_dir: None,
            updates_enabled: true,
            release_keys: default_release_keys(),
            data_dir: None,
        }
    }
}

impl LocalConfig {
    /// True when `allowed_binds` lets a listener bind `bind` (exact `ip:port` match, edge.md §2).
    pub fn bind_allowed(&self, bind: &str) -> bool {
        self.allowed_binds.iter().any(|b| b == "*" || b == bind)
    }
}

/// Core's address: an IP literal and port (api.md §1: setup and config load reject a name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreUrl {
    pub addr: SocketAddr,
    /// The text as written, for display and for rewriting `edge.json`.
    pub text: String,
}

impl CoreUrl {
    /// Parses `https://<ip literal>[:port][/]`. A host name, another scheme, user info, a path,
    /// a query or a fragment is refused, and so is an IPv4 address in any form but the dotted
    /// quad: the URL standard reads `192.168.1.020` as 192.168.1.16 (octal), `3232235796` and
    /// `0xc0.168.1.20` as 192.168.1.20, so the text shown and written back would name another
    /// address than the one dialled.
    pub fn parse(s: &str) -> Result<Self> {
        let u = url::Url::parse(s.trim()).with_context(|| format!("core URL {s:?} isn't a URL"))?;
        if u.scheme() != "https" {
            bail!("core URL {s:?} must use https");
        }
        if !u.username().is_empty() || u.password().is_some() {
            bail!("core URL {s:?} must not carry user info");
        }
        if u.query().is_some() || u.fragment().is_some() || !(u.path().is_empty() || u.path() == "/") {
            bail!("core URL {s:?} must have no path, query or fragment");
        }
        let ip: IpAddr = match u.host() {
            Some(url::Host::Ipv4(v4)) => {
                if written_host(s.trim()).and_then(|h| h.parse::<Ipv4Addr>().ok()) != Some(v4) {
                    bail!("core URL {s:?}: write the IPv4 address as a dotted quad ({v4})");
                }
                v4.into()
            }
            Some(url::Host::Ipv6(v6)) => v6.into(),
            Some(url::Host::Domain(d)) => bail!(
                "core URL {s:?} names a host ({d}); it must be an IP literal (the edge has no resolver before its first config)"
            ),
            None => bail!("core URL {s:?} has no host"),
        };
        let port = u.port_or_known_default().unwrap_or(443);
        Ok(Self {
            addr: SocketAddr::new(ip, port),
            text: normalised_text(s),
        })
    }

    /// The `host:port` authority (IPv6 in brackets), for `Host` headers and WebSocket URLs.
    pub fn authority(&self) -> String {
        self.addr.to_string()
    }
}

/// The text of a parsed core URL as shown and written back: as written, without surrounding
/// spaces, a trailing `/` or an empty port (`https://192.168.1.20:`).
fn normalised_text(s: &str) -> String {
    let t = s.trim().trim_end_matches('/');
    t.strip_suffix(':').unwrap_or(t).to_owned()
}

/// The host of URL text `s` as written: between `://` and the first `/`, `\`, `?` or `#`, less a
/// `:port`. Only for an IPv4 host, which has no colon of its own.
fn written_host(s: &str) -> Option<&str> {
    let (_, rest) = s.split_once("://")?;
    let authority = rest.split(['/', '\\', '?', '#']).next()?;
    Some(match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    })
}

/// The compiled-in release keys (from `PICKET_RELEASE_PUB` / `PICKET_RELEASE_PUB_FILE`).
pub fn default_release_keys() -> Vec<String> {
    RELEASE_KEYS.iter().map(|k| (*k).to_owned()).collect()
}

/// Checks a minisign public key line: base64 of 42 bytes starting with the `Ed` algorithm id.
pub fn valid_release_key(k: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(k.trim())
        .is_ok_and(|b| b.len() == 42 && b.starts_with(b"Ed"))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Raw {
    core_url: Option<String>,
    core_key: Option<String>,
    allowed_binds: Option<Vec<String>>,
    ssd_dir: Option<PathBuf>,
    updates_enabled: Option<bool>,
    release_keys: Option<Vec<String>>,
    data_dir: Option<PathBuf>,
}

/// Parses and validates `edge.json` text.
pub fn parse(text: &[u8]) -> Result<LocalConfig> {
    let raw: Raw = serde_json::from_slice(text)
        .map_err(|e| anyhow!("edge.json isn't valid: {}", crate::diag::cap(e)))?;
    let mut c = LocalConfig::default();
    if let Some(u) = raw.core_url.filter(|s| !s.trim().is_empty()) {
        c.core_url = Some(CoreUrl::parse(&u)?);
    }
    if let Some(k) = raw.core_key.filter(|s| !s.trim().is_empty()) {
        if picket_api::ids::parse_fingerprint(k.trim()).is_none() {
            bail!(
                "edge.json: core_key {:?} isn't a SHA256:… fingerprint",
                crate::diag::cap(&k)
            );
        }
        c.core_key = Some(k.trim().to_owned());
        if c.core_url.is_none() {
            // The pin names core's key, but nothing says where core is (edge.md §3 step 4).
            bail!("edge.json: core_key is set but core_url isn't");
        }
    }
    if let Some(b) = raw.allowed_binds {
        if b.len() > MAX_LIST {
            bail!("edge.json: allowed_binds has more than {MAX_LIST} entries");
        }
        for e in &b {
            if e != "*" && e.parse::<SocketAddr>().is_err() {
                bail!(
                    "edge.json: allowed_binds entry {:?} is neither \"*\" nor ip:port",
                    crate::diag::cap(e)
                );
            }
        }
        c.allowed_binds = b;
    }
    if let Some(d) = raw.ssd_dir {
        if !d.is_absolute() || d.parent().is_none_or(|p| p == Path::new("/")) {
            bail!(
                "edge.json: ssd_dir {} must be an absolute folder directly under the SSD's mount point",
                d.display()
            );
        }
        c.ssd_dir = Some(d);
    }
    if let Some(u) = raw.updates_enabled {
        c.updates_enabled = u;
    }
    if let Some(keys) = raw.release_keys {
        if keys.len() > MAX_LIST {
            bail!("edge.json: release_keys has more than {MAX_LIST} entries");
        }
        for k in &keys {
            if !valid_release_key(k) {
                bail!(
                    "edge.json: release key {:?} isn't a minisign public key",
                    crate::diag::cap(k)
                );
            }
        }
        c.release_keys = keys.into_iter().map(|k| k.trim().to_owned()).collect();
    }
    c.data_dir = raw.data_dir;
    Ok(c)
}

/// Loads `edge.json`. A missing file is an empty config (a first start before `setup`, or a
/// development edge); anything unreadable or invalid is an error.
pub fn load(path: &Path) -> Result<LocalConfig> {
    match fsutil::read_bounded(path, MAX_EDGE_JSON) {
        Ok(b) => parse(&b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LocalConfig::default()),
        Err(e) => Err(anyhow!("can't read {}: {}", path.display(), crate::diag::cap(e))),
    }
}

/// Resolves `data_dir`: `--data-dir`, else `edge.json`'s, else the platform default.
pub fn resolve_data_dir(flag: Option<&Path>, cfg: &LocalConfig, platform: HostPlatform) -> PathBuf {
    flag.map(Path::to_path_buf)
        .or_else(|| cfg.data_dir.clone())
        .unwrap_or_else(|| platform.default_data_dir())
}

/// Rewrites `edge.json` with `core_url` and `core_key` set, keeping every other field (unknown
/// ones included), and the existing file's owner, group and mode (root:picket 0640 under the
/// updater, edge-unifi.md §2). The config directory is opened without following a symlink and
/// the file is replaced atomically; a new file is created 0640, group `picket` when root.
pub fn write_core_pin(path: &Path, core_url: &CoreUrl, core_key: &str) -> Result<()> {
    let (dir, name) = fsutil::split(path)?;
    let dir_owner = if users::is_root() {
        Owner {
            uid: Some(0),
            gid: users::picket_gid(),
        }
    } else {
        Owner::default()
    };
    let dirfd = fsutil::ensure_dir_nofollow(dir, 0o750, dir_owner)
        .with_context(|| format!("config directory {}", dir.display()))?;

    let (mut doc, opts) = match fsutil::read_at_bounded(&dirfd, name, MAX_EDGE_JSON) {
        Ok((bytes, meta)) => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| anyhow!("{} isn't valid JSON: {}", path.display(), crate::diag::cap(e)))?;
            let serde_json::Value::Object(map) = v else {
                bail!("{} isn't a JSON object", path.display());
            };
            let opts = WriteOpts {
                mode: meta.mode() & 0o7777,
                owner: Owner {
                    uid: Some(meta.uid()),
                    gid: Some(meta.gid()),
                },
            };
            (map, opts)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let owner = if users::is_root() {
                Owner {
                    uid: Some(0),
                    gid: users::picket_gid(),
                }
            } else {
                Owner::default()
            };
            (serde_json::Map::new(), WriteOpts { mode: 0o640, owner })
        }
        Err(e) => return Err(anyhow!("can't read {}: {}", path.display(), crate::diag::cap(e))),
    };
    doc.insert(
        "core_url".into(),
        serde_json::Value::String(core_url.text.clone()),
    );
    doc.insert("core_key".into(), serde_json::Value::String(core_key.to_owned()));
    let mut text = serde_json::to_vec_pretty(&serde_json::Value::Object(doc))?;
    text.push(b'\n');
    // Validate what we're about to write, so setup can't leave a file the edge refuses.
    parse(&text)?;
    // Only root may hand a file to another owner; a developer rewriting their own file keeps it.
    let opts = if users::is_root() {
        opts
    } else {
        WriteOpts {
            mode: opts.mode,
            owner: Owner {
                uid: None,
                gid: opts
                    .owner
                    .gid
                    .filter(|g| *g == rustix::process::getegid().as_raw()),
            },
        }
    };
    fsutil::atomic_write_at(&dirfd, name, &text, opts)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn core_url_must_be_ip_literal() {
        let u = CoreUrl::parse("https://192.168.1.20:7443").unwrap();
        assert_eq!(u.addr, "192.168.1.20:7443".parse().unwrap());
        let u = CoreUrl::parse("https://[fd00::20]:7443/").unwrap();
        assert_eq!(u.authority(), "[fd00::20]:7443");
        assert_eq!(CoreUrl::parse("https://10.0.0.1").unwrap().addr.port(), 443);
        for bad in [
            "https://core.home.arpa:7443",
            "http://192.168.1.20:7443",
            "https://user@192.168.1.20:7443",
            "https://192.168.1.20:7443/x",
            "https://192.168.1.20:7443?a=b",
            "192.168.1.20:7443",
            // The URL standard's other IPv4 forms (octal, one number, hex, a trailing dot):
            // what's shown would differ from what's dialled.
            "https://192.168.1.020:7443",
            "https://3232235796:7443",
            "https://0xc0.168.1.20",
            "https://0300.0250.1.20",
            "https://192.168.1.20.:7443",
            "https://192.168.1:7443",
            "https://@192.168.1.20:7443",
        ] {
            assert!(CoreUrl::parse(bad).is_err(), "{bad}");
        }
        let e = CoreUrl::parse("https://192.168.1.020:7443").unwrap_err();
        assert!(e.to_string().contains("dotted quad (192.168.1.16)"), "{e}");
        // The dotted quad, with or without a port or a trailing slash, in any case of scheme.
        // The text shown and written back has no trailing `/` or empty port.
        for (written, text) in [
            ("https://192.168.1.20:", "https://192.168.1.20"),
            ("https://192.168.1.20:/", "https://192.168.1.20"),
            ("https://[fd00::20]:", "https://[fd00::20]"),
            (" https://192.168.1.20:7443/ ", "https://192.168.1.20:7443"),
        ] {
            assert_eq!(CoreUrl::parse(written).unwrap().text, text, "{written:?}");
        }
        for ok in [
            "https://192.168.1.20:7443/",
            "HTTPS://192.168.1.20:7443",
            "https://192.168.1.20:",
        ] {
            assert_eq!(
                CoreUrl::parse(ok).unwrap().addr.ip(),
                "192.168.1.20".parse::<IpAddr>().unwrap(),
                "{ok}"
            );
        }
        let e = parse(br#"{"core_url": "https://core.lan:7443"}"#).unwrap_err();
        assert!(e.to_string().contains("IP literal"), "{e}");
    }

    #[test]
    fn defaults_and_validation() {
        let c = parse(b"{}").unwrap();
        assert_eq!(c.allowed_binds, vec!["*"]);
        assert!(c.updates_enabled);
        assert_eq!(c.release_keys, default_release_keys());
        for k in &c.release_keys {
            assert!(valid_release_key(k), "{:?}", c.release_keys);
        }
        assert!(c.bind_allowed("127.0.0.1:5353"));

        let c = parse(br#"{"release_keys": ["RWQAAAAAAAAAAA5pMKK7EBOb2uv67gn1XqmH3z7rjtF8/4sRaQSD+CLV"]}"#)
            .unwrap();
        assert_eq!(
            c.release_keys,
            vec!["RWQAAAAAAAAAAA5pMKK7EBOb2uv67gn1XqmH3z7rjtF8/4sRaQSD+CLV"]
        );

        let c = parse(
            br#"{"allowed_binds": ["[::]:5335", "192.168.1.1:853"], "updates_enabled": false,
              "ssd_dir": "/volume1/.picket", "data_dir": "/tmp/x", "future": 1}"#,
        )
        .unwrap();
        assert!(c.bind_allowed("[::]:5335"));
        assert!(!c.bind_allowed("0.0.0.0:53"));
        assert!(!c.updates_enabled);
        assert_eq!(c.data_dir.as_deref(), Some(Path::new("/tmp/x")));

        assert!(parse(br#"{"allowed_binds": ["localhost:53"]}"#).is_err());
        assert!(parse(br#"{"core_key": "nope"}"#).is_err());
        let fp = picket_api::ids::fingerprint_spki(b"core");
        let e = parse(format!(r#"{{"core_key": "{fp}"}}"#).as_bytes()).unwrap_err();
        assert!(e.to_string().contains("core_url"), "{e}");
        let c = parse(format!(r#"{{"core_url": "https://10.0.0.2:7443", "core_key": "{fp}"}}"#).as_bytes())
            .unwrap();
        assert_eq!(c.core_key.as_deref(), Some(fp.as_str()));
        assert!(parse(br#"{"release_keys": ["Zm9v"]}"#).is_err());
        assert!(parse(br#"{"ssd_dir": "/volume1"}"#).is_err());
        assert!(parse(br#"{"ssd_dir": "rel/x"}"#).is_err());
    }

    #[test]
    fn setup_rewrite_keeps_fields_mode_and_group() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("etc/edge.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            br#"{"allowed_binds": ["127.0.0.1:5353"], "updates_enabled": false, "x-future": {"a": 1}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let gid_before = std::fs::metadata(&p).unwrap().gid();
        let url = CoreUrl::parse("https://192.168.1.20:7443").unwrap();
        let key = picket_api::ids::fingerprint_spki(b"core");
        write_core_pin(&p, &url, &key).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o640);
        assert_eq!(m.gid(), gid_before);
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["x-future"]["a"], 1);
        assert_eq!(v["updates_enabled"], false);
        assert_eq!(v["core_key"], key.as_str());
        let c = load(&p).unwrap();
        assert_eq!(c.core_url.unwrap().addr, url.addr);
    }

    #[test]
    fn setup_refuses_symlinked_config_dir() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, d.path().join("etc")).unwrap();
        let url = CoreUrl::parse("https://192.168.1.20:7443").unwrap();
        let e = write_core_pin(
            &d.path().join("etc/edge.json"),
            &url,
            &picket_api::ids::fingerprint_spki(b"c"),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        assert!(!real.join("edge.json").exists());
    }
}
