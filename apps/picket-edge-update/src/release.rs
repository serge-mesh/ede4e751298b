//! A pending release: copied out of the edge's `data_dir` into a root-owned directory, verified
//! there against `release_keys` with the version and architecture taken only from the verified
//! trusted comment, and unpacked from that copy (edge.md §14 step 2, security.md §3).

use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::{Component, Path};

use flate2::read::GzDecoder;
use minisign_verify::{PublicKey, Signature};

use crate::api::parse_trusted_comment;
use crate::fsx::{self, Dir, ReadError};
use crate::system::System;

/// The binaries a release tarball carries (build-and-test.md §3).
pub const BINARIES: [&str; 3] = ["picket-edge", "picket-edge-helper", "picket-edge-update"];

/// Size bounds (README §2, Bounded).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub tarball: u64,
    pub signature: u64,
    /// Each binary, unpacked.
    pub entry: u64,
    /// Everything the gzip stream yields, skipped entries and tar headers included.
    pub decompressed: u64,
    pub entries: usize,
}

pub const LIMITS: Limits = Limits {
    tarball: 256 * 1024 * 1024,
    signature: 64 * 1024,
    entry: 256 * 1024 * 1024,
    decompressed: 768 * 1024 * 1024,
    entries: 256,
};

/// `picket-edge-<version>-<arch>.tar.gz` (edge.md §14, Offer).
pub fn tarball_name(version: &str, arch: &str) -> String {
    format!("picket-edge-{version}-{arch}.tar.gz")
}

pub fn signature_name(version: &str, arch: &str) -> String {
    format!("{}.minisig", tarball_name(version, arch))
}

/// Copies the tarball and its signature from `<data_dir>/releases/<version>/` into `staging`
/// (root-owned, 0700), opening each without following links and refusing anything but a
/// regular file within the size bounds.
pub fn copy_release(
    data: &Dir,
    version: &str,
    arch: &str,
    staging: &Dir,
    limits: &Limits,
) -> Result<(), String> {
    let releases = data
        .subdir("releases")
        .map_err(|e| format!("{}/releases: {e}", data.logical().display()))?;
    let dir = releases
        .subdir(version)
        .map_err(|e| format!("{}: {e}", releases.logical_at(version).display()))?;
    for (name, max) in [
        (tarball_name(version, arch), limits.tarball),
        (signature_name(version, arch), limits.signature),
    ] {
        let (mut src, _) = dir
            .open_regular(&name)
            .map_err(|e| format!("{}: {e}", dir.logical_at(&name).display()))?;
        let mut dst = staging
            .create_new(&name, 0o600)
            .map_err(|e| format!("can't create {}: {e}", staging.logical_at(&name).display()))?;
        fsx::copy_capped(&mut src, &mut dst, max)
            .and_then(|_| dst.sync_all())
            .map_err(|e| format!("copying {}: {e}", dir.logical_at(&name).display()))?;
    }
    Ok(())
}

/// Verifies the staged copy against `keys`, then checks the verified trusted comment names the
/// pending version and the host's architecture.
pub fn verify_staged(
    staging: &Dir,
    version: &str,
    arch: &str,
    keys: &[String],
    limits: &Limits,
) -> Result<(), String> {
    let sig_name = signature_name(version, arch);
    let sig_bytes = staging
        .read_bounded(&sig_name, limits.signature, true)
        .map_err(|e| format!("{sig_name}: {e}"))?;
    let sig = decode_signature(&sig_bytes).map_err(|e| format!("{sig_name}: {e}"))?;
    let tar_name = tarball_name(version, arch);
    let (mut file, _) = staging
        .open_regular(&tar_name)
        .map_err(|e| format!("{tar_name}: {e}"))?;
    verify_with_keys(&sig, keys, &mut file, limits.tarball).map_err(|e| format!("{tar_name}: {e}"))?;
    // Only now is the trusted comment authenticated (the global signature covers it).
    check_signed_release(&sig, version, arch)
}

/// Verifies `data`, read to its end (at most `max` bytes), against `sig` with any of `keys`.
/// Public for the fuzz target.
pub fn verify_with_keys<R: Read + Seek>(
    sig: &Signature,
    keys: &[String],
    data: &mut R,
    max: u64,
) -> Result<(), String> {
    let keys: Vec<PublicKey> = keys
        .iter()
        .filter_map(|k| PublicKey::from_base64(k.trim()).ok())
        .collect();
    if keys.is_empty() {
        return Err("no usable release_keys".into());
    }
    let mut last = String::from("no release key matches the signature");
    for key in &keys {
        let mut v = match key.verify_stream(sig) {
            Ok(v) => v,
            Err(e) => {
                last = format!("signature: {e}");
                continue;
            }
        };
        data.rewind().map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = data.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > max {
                return Err(format!("larger than {max} bytes"));
            }
            v.update(&buf[..n]);
        }
        match v.finalize() {
            Ok(()) => return Ok(()),
            Err(e) => last = format!("signature: {e}"),
        }
    }
    Err(last)
}

/// Decodes a `.minisig` file, which picket-edge wrote and the updater doesn't trust (README §2,
/// Untrusted input). Public for the fuzz target.
pub fn decode_signature(bytes: &[u8]) -> Result<Signature, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "isn't text".to_string())?;
    Signature::decode(text).map_err(|e| e.to_string())
}

/// Checks a verified signature's trusted comment names `picket-edge <version> <arch>`. Public for
/// the fuzz target.
pub fn check_signed_release(sig: &Signature, version: &str, arch: &str) -> Result<(), String> {
    let comment = sig.trusted_comment();
    match parse_trusted_comment(comment) {
        Some((v, a)) if v == version && a == arch => Ok(()),
        Some((v, a)) => Err(format!(
            "the signed release is picket-edge {v} {a}, not {version} {arch}"
        )),
        None => Err(format!("unexpected trusted comment {comment:?}")),
    }
}

/// Counts bytes read and refuses to go past a bound.
struct Bounded<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            // One more byte would pass the bound: is there one?
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other("decompressed size over the bound")),
            };
        }
        let max = buf.len().min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..max])?;
        self.left -= n as u64;
        Ok(n)
    }
}

/// Where a tarball entry's file goes.
enum Target {
    Binary(&'static str),
    Skip,
}

/// Walks a `.tar.gz`, checking every entry, and hands each binary to `sink`. Accepted layouts:
/// the binaries at the top level or in one top-level directory. Refused: absolute paths, `..`,
/// links that leave the archive or replace a binary, devices and FIFOs, a binary over the
/// bound or twice, too many entries, a decompressed stream over the bound, and a missing binary.
pub fn scan_tarball<R: Read>(
    reader: R,
    limits: &Limits,
    mut sink: impl FnMut(&'static str, &mut dyn Read, u64) -> io::Result<()>,
) -> Result<(), String> {
    let gz = GzDecoder::new(reader);
    let mut archive = tar::Archive::new(Bounded {
        inner: gz,
        left: limits.decompressed,
    });
    let mut seen: Vec<&'static str> = Vec::new();
    let mut top: Option<String> = None;
    let mut count = 0usize;
    for entry in archive.entries().map_err(|e| format!("tarball: {e}"))? {
        let mut entry = entry.map_err(|e| format!("tarball: {e}"))?;
        count += 1;
        if count > limits.entries {
            return Err(format!("more than {} entries", limits.entries));
        }
        let path_bytes = entry.path_bytes().into_owned();
        let path = std::str::from_utf8(&path_bytes).map_err(|_| "an entry name isn't UTF-8".to_string())?;
        let parts = entry_parts(path)?;
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            let link = entry
                .link_name_bytes()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            check_link(&parts, &link, kind.is_hard_link())?;
        } else if !(kind.is_file() || kind.is_dir() || kind.is_pax_global_extensions()) {
            return Err(format!("{path}: unsupported entry type {:?}", kind));
        }
        let target = classify(&parts, &mut top);
        match target {
            Target::Binary(name) => {
                if !kind.is_file() {
                    return Err(format!("{path}: {name} must be a regular file"));
                }
                if seen.contains(&name) {
                    return Err(format!("{name} appears twice"));
                }
                let size = entry.size();
                if size > limits.entry {
                    return Err(format!("{path} is larger than {} bytes", limits.entry));
                }
                seen.push(name);
                let mut take = (&mut entry).take(size);
                sink(name, &mut take, size).map_err(|e| format!("{path}: {e}"))?;
            }
            Target::Skip => {}
        }
    }
    for b in BINARIES {
        if !seen.contains(&b) {
            return Err(format!("{b} is missing from the tarball"));
        }
    }
    Ok(())
}

/// The normal components of an entry path; refuses absolute paths and `..`.
fn entry_parts(path: &str) -> Result<Vec<String>, String> {
    let p = Path::new(path);
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                return Err(format!("{path:?}: absolute or parent-relative entry path"));
            }
        }
    }
    Ok(parts)
}

/// A link may not point outside the archive (absolute, or `..` past its root).
fn check_link(entry: &[String], link: &str, hard: bool) -> Result<(), String> {
    if link.starts_with('/') {
        return Err(format!("{}: link to absolute path {link:?}", entry.join("/")));
    }
    // A symlink resolves from its own directory; a hard link from the archive root.
    let mut depth: i64 = if hard {
        0
    } else {
        i64::try_from(entry.len().saturating_sub(1)).unwrap_or(i64::MAX)
    };
    for c in Path::new(link).components() {
        match c {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(format!("{}: link {link:?} leaves the archive", entry.join("/")));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("{}: link to absolute path {link:?}", entry.join("/")));
            }
        }
    }
    Ok(())
}

fn classify(parts: &[String], top: &mut Option<String>) -> Target {
    let (dir, name) = match parts {
        [name] => (None, name),
        [dir, name] => (Some(dir), name),
        _ => return Target::Skip,
    };
    let Some(bin) = BINARIES.iter().find(|b| *b == name) else {
        return Target::Skip;
    };
    // All binaries come from the same place: the top level, or one directory.
    let place = dir.cloned().unwrap_or_default();
    match top {
        Some(t) if *t != place => Target::Skip,
        _ => {
            *top = Some(place);
            Target::Binary(bin)
        }
    }
}

/// Unpacks the staged tarball into `dest` (a fresh directory): each binary root-owned, 0755,
/// fsynced, then the directory.
pub fn unpack(
    staging: &Dir,
    tar_name: &str,
    dest: &Dir,
    sys: &dyn System,
    limits: &Limits,
) -> Result<(), String> {
    let (file, _) = staging
        .open_regular(tar_name)
        .map_err(|e: ReadError| format!("{tar_name}: {e}"))?;
    scan_tarball(file, limits, |name, r, _size| {
        let mut out: File = dest.create_new(name, 0o755)?;
        io::copy(r, &mut out)?;
        out.flush()?;
        out.set_permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755))?;
        sys.chown(&out, &dest.logical_at(name), 0, 0)?;
        out.sync_all()
    })?;
    dest.sync().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Keys, TarEntry, tar_gz};

    /// The `.minisig` decoder and the checks after it, as the fuzz target drives them.
    #[test]
    fn signatures() {
        let keys = Keys::new();
        let data = b"tarball";
        let text = keys.sign(data, "picket-edge 1.2.3 x86_64");
        let sig = decode_signature(text.as_bytes()).unwrap();
        let mine = [keys.pub_b64.clone()];
        verify_with_keys(&sig, &mine, &mut io::Cursor::new(data), 1024).unwrap();
        check_signed_release(&sig, "1.2.3", "x86_64").unwrap();
        assert!(check_signed_release(&sig, "1.2.4", "x86_64").is_err());
        assert!(check_signed_release(&sig, "1.2.3", "aarch64").is_err());
        // Another key, other data, a bound passed, or no usable key: refused.
        let other = [Keys::new().pub_b64];
        assert!(verify_with_keys(&sig, &other, &mut io::Cursor::new(data), 1024).is_err());
        assert!(verify_with_keys(&sig, &mine, &mut io::Cursor::new(b"tarbal"), 1024).is_err());
        assert!(verify_with_keys(&sig, &mine, &mut io::Cursor::new(data), 3).is_err());
        assert!(verify_with_keys(&sig, &["nope".into()], &mut io::Cursor::new(data), 1024).is_err());
        let wrong_comment = keys.sign(data, "picket-edge 1.2.3");
        let sig = decode_signature(wrong_comment.as_bytes()).unwrap();
        assert!(check_signed_release(&sig, "1.2.3", "x86_64").is_err());
        for bad in [&b""[..], b"\xff\xfe", b"untrusted comment: x\nnot base64\n"] {
            assert!(decode_signature(bad).is_err(), "{bad:?}");
        }
    }

    fn collect(bytes: &[u8], limits: &Limits) -> Result<Vec<(String, Vec<u8>)>, String> {
        let mut out = Vec::new();
        scan_tarball(bytes, limits, |name, r, _| {
            let mut b = Vec::new();
            r.read_to_end(&mut b)?;
            out.push((name.to_string(), b));
            Ok(())
        })?;
        Ok(out)
    }

    fn bins(prefix: &str) -> Vec<TarEntry> {
        BINARIES
            .iter()
            .map(|b| TarEntry::file(&format!("{prefix}{b}"), format!("bin {b}").as_bytes()))
            .collect()
    }

    #[test]
    fn layouts() {
        let got = collect(&tar_gz(&bins("")), &LIMITS).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], ("picket-edge".into(), b"bin picket-edge".to_vec()));
        let mut e = vec![TarEntry::dir("picket-edge-1.5.0-x86_64/")];
        e.extend(bins("picket-edge-1.5.0-x86_64/"));
        e.push(TarEntry::file("picket-edge-1.5.0-x86_64/README", b"hi"));
        e.push(TarEntry::symlink("picket-edge-1.5.0-x86_64/LATEST", "README"));
        assert_eq!(collect(&tar_gz(&e), &LIMITS).unwrap().len(), 3);
        let mut e = bins("./");
        e.push(TarEntry::file("other/picket-edge", b"decoy"));
        let got = collect(&tar_gz(&e), &LIMITS).unwrap();
        assert_eq!(got[0].1, b"bin picket-edge");
    }

    #[test]
    fn refusals() {
        let cases: Vec<(Vec<TarEntry>, &str)> = vec![
            (bins("")[..2].to_vec(), "missing"),
            (
                [bins(""), vec![TarEntry::file("picket-edge", b"again")]].concat(),
                "twice",
            ),
            (
                [bins(""), vec![TarEntry::file("../evil", b"x")]].concat(),
                "parent-relative",
            ),
            (
                [bins(""), vec![TarEntry::file("/etc/evil", b"x")]].concat(),
                "absolute",
            ),
            (
                [bins(""), vec![TarEntry::symlink("x", "/etc/shadow")]].concat(),
                "absolute",
            ),
            (
                [bins(""), vec![TarEntry::symlink("d/x", "../../etc")]].concat(),
                "leaves",
            ),
            (
                [bins(""), vec![TarEntry::hardlink("x", "../y")]].concat(),
                "leaves",
            ),
            (
                [
                    bins("")[1..].to_vec(),
                    vec![TarEntry::symlink("picket-edge", "picket-edge-helper")],
                ]
                .concat(),
                "regular file",
            ),
            ([bins(""), vec![TarEntry::fifo("p")]].concat(), "unsupported"),
        ];
        for (entries, want) in cases {
            let e = collect(&tar_gz(&entries), &LIMITS).unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        }
        let small = Limits { entry: 4, ..LIMITS };
        assert!(
            collect(&tar_gz(&bins("")), &small)
                .unwrap_err()
                .contains("larger")
        );
        let few = Limits { entries: 2, ..LIMITS };
        assert!(collect(&tar_gz(&bins("")), &few).unwrap_err().contains("entries"));
        let tight = Limits {
            decompressed: 1024,
            ..LIMITS
        };
        assert!(collect(&tar_gz(&bins("")), &tight).is_err());
        assert!(collect(b"not gzip", &LIMITS).is_err());
        assert!(collect(&[], &LIMITS).is_err());
    }
}
