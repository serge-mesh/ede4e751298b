// Compile-time release public keys shared by the build scripts of picket-core, picket-edge and
// picket-edge-update: each `include!`s this file and calls `emit_release_keys(...)`.
//
// Keys are supplied via environment variables instead of being committed to the repository:
//   - `PICKET_RELEASE_PUB`: one or more minisign public keys (bare base64 lines, comma/whitespace
//     separated, or full `.pub` text including `untrusted comment:` lines). Suitable for CI
//     Actions variables such as `${{ vars.RELEASE_PUB }}`.
//   - `PICKET_RELEASE_PUB_FILE`: path to a `.pub` file (absolute, or relative to the workspace
//     root). Suitable for local builds or a separate private deployment repository.
//   - `PICKET_REQUIRE_RELEASE_KEYS=1`: fail the build if no keys were supplied (for release jobs).
//
// When neither source is set (or empty, e.g. an unset CI variable on a fork), the generated
// `RELEASE_KEYS` slice is empty (`&[]`), so verification fails closed unless keys are supplied at
// runtime (`edge.json` on edges) or at build time.
//
// Paths are spelled out in full: the including build script has its own `use` lines.

/// Decodes a standard RFC 4648 base64 string (no whitespace).
fn decode_base64_std(s: &str) -> Result<std::vec::Vec<u8>, &'static str> {
    let (chunks, rem) = s.as_bytes().as_chunks::<4>();
    if !rem.is_empty() {
        return Err("base64 length must be a multiple of 4");
    }
    let mut out = std::vec::Vec::with_capacity(chunks.len() * 3);
    let mut seen_pad = false;
    for &[c0, c1, c2, c3] in chunks {
        if seen_pad {
            return Err("base64 padding before end");
        }
        let b0 = b64_val(c0).ok_or("invalid base64 character")?;
        let b1 = b64_val(c1).ok_or("invalid base64 character")?;
        out.push((b0 << 2) | (b1 >> 4));
        match (c2, c3) {
            (b'=', b'=') => {
                if (b1 & 0x0f) != 0 {
                    return Err("non-zero base64 padding bits");
                }
                seen_pad = true;
            }
            (b'=', _) => return Err("invalid base64 padding"),
            (c2, b'=') => {
                let b2 = b64_val(c2).ok_or("invalid base64 character")?;
                if (b2 & 0x03) != 0 {
                    return Err("non-zero base64 padding bits");
                }
                out.push((b1 << 4) | (b2 >> 2));
                seen_pad = true;
            }
            (c2, c3) => {
                let b2 = b64_val(c2).ok_or("invalid base64 character")?;
                let b3 = b64_val(c3).ok_or("invalid base64 character")?;
                out.push((b1 << 4) | (b2 >> 2));
                out.push((b2 << 6) | b3);
            }
        }
    }
    Ok(out)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Checks one minisign Ed25519 public key line: base64 of 42 bytes starting with `Ed`.
fn is_valid_minisign_pubkey(k: &str) -> bool {
    decode_base64_std(k).is_ok_and(|b| b.len() == 42 && b.starts_with(b"Ed"))
}

/// Parses minisign public keys from `.pub` text or a comma/whitespace-separated list of base64
/// key lines. Blank lines and `untrusted comment:` lines are skipped. Duplicates are removed while
/// preserving order.
fn parse_release_keys(text: &str) -> Result<std::vec::Vec<std::string::String>, std::string::String> {
    let mut keys = std::vec::Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("untrusted comment:") {
            continue;
        }
        for token in trimmed.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if !is_valid_minisign_pubkey(token) {
                let preview: std::string::String = token.chars().take(24).collect();
                return Err(format!(
                    "invalid minisign public key {preview:?} (expected 42-byte base64 Ed25519 public key)"
                ));
            }
            if !keys.iter().any(|existing| existing == token) {
                keys.push(token.to_owned());
            }
        }
    }
    Ok(keys)
}

fn parse_require_flag(val: Option<&str>) -> Result<bool, std::string::String> {
    let Some(raw) = val else {
        return Ok(false);
    };
    let s = raw.trim();
    if s.is_empty() || s == "0" || s.eq_ignore_ascii_case("false") {
        Ok(false)
    } else if s == "1" || s.eq_ignore_ascii_case("true") {
        Ok(true)
    } else {
        Err(format!(
            "PICKET_REQUIRE_RELEASE_KEYS={raw:?} must be 1, 0, true, false, or empty"
        ))
    }
}

/// Resolves the release keys from the build environment, validates them, and renders
/// `$OUT_DIR/release_keys.rs`.
fn render_release_keys_source(
    origin: &str,
    workspace_root: &std::path::Path,
) -> Result<std::string::String, std::string::String> {
    use std::fmt::Write as _;

    println!("cargo:rerun-if-env-changed=PICKET_RELEASE_PUB");
    println!("cargo:rerun-if-env-changed=PICKET_RELEASE_PUB_FILE");
    println!("cargo:rerun-if-env-changed=PICKET_REQUIRE_RELEASE_KEYS");

    let require = parse_require_flag(std::env::var("PICKET_REQUIRE_RELEASE_KEYS").ok().as_deref())?;
    let inline = std::env::var("PICKET_RELEASE_PUB")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let file_var = std::env::var("PICKET_RELEASE_PUB_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let keys = match (inline, file_var) {
        (Some(_), Some(_)) => {
            return Err("set only one of PICKET_RELEASE_PUB or PICKET_RELEASE_PUB_FILE, not both".into());
        }
        (Some(text), None) => {
            let parsed = parse_release_keys(&text).map_err(|e| format!("PICKET_RELEASE_PUB: {e}"))?;
            if parsed.is_empty() {
                return Err("PICKET_RELEASE_PUB was set but contained no minisign public keys".into());
            }
            parsed
        }
        (None, Some(path_str)) => {
            let path = workspace_root.join(path_str.trim());
            println!("cargo:rerun-if-changed={}", path.display());
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("PICKET_RELEASE_PUB_FILE ({}): {e}", path.display()))?;
            let parsed = parse_release_keys(&text)
                .map_err(|e| format!("PICKET_RELEASE_PUB_FILE ({}): {e}", path.display()))?;
            if parsed.is_empty() {
                return Err(format!(
                    "PICKET_RELEASE_PUB_FILE ({}) contained no minisign public keys",
                    path.display()
                ));
            }
            parsed
        }
        (None, None) => {
            if require {
                return Err(
                    "PICKET_REQUIRE_RELEASE_KEYS is set, but neither PICKET_RELEASE_PUB nor PICKET_RELEASE_PUB_FILE provided a key"
                        .into(),
                );
            }
            std::vec::Vec::new()
        }
    };

    let mut s = std::string::String::new();
    let _ = writeln!(s, "// @generated by {origin} (build-support/release_keys.rs).\n");
    let _ = writeln!(
        s,
        "/// Compiled-in default minisign release public keys (base64 lines)."
    );
    s.push_str("pub const RELEASE_KEYS: &[&str] = &[");
    if !keys.is_empty() {
        s.push('\n');
        for k in &keys {
            let _ = writeln!(s, "    {k:?},");
        }
    }
    s.push_str("];\n");
    Ok(s)
}

/// Generates `$OUT_DIR/release_keys.rs`, or stops the build with an error message on stderr.
fn emit_release_keys(origin: &str, workspace_root: &std::path::Path, out_dir: &std::path::Path) {
    let source = match render_release_keys_source(origin, workspace_root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{origin}: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = std::fs::write(out_dir.join("release_keys.rs"), source) {
        eprintln!("{origin}: cannot write release_keys.rs: {e}");
        std::process::exit(1);
    }
}
