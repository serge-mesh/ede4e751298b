//! picket-core's build script:
//!
//! 1. Compiles `dist/firmware.json` into picket-core (edge-unifi.md §1, core.md §11:
//!    `edges.min_firmware`). While the file doesn't exist yet in this checkout, the minimum the
//!    spec states (UCG-Fiber, UniFi OS 6.0.17) is used instead.
//! 2. Compiles the release public keys from `PICKET_RELEASE_PUB` / `PICKET_RELEASE_PUB_FILE` into
//!    `$OUT_DIR/release_keys.rs` (core.md §11).
//! 3. The download module registry (providers.md §1): scans `src/modules/download/*/` and
//!    writes `$OUT_DIR/download_registry.rs`, which declares each module with `#[path]` and lists
//!    one boxed `Module::default()` each. No linker tricks, no `unsafe`. The build fails on a
//!    directory without `mod.rs`, an id that isn't `[a-z0-9_]` (or isn't a usable Rust module
//!    name), and a duplicate id (the scan shared with picket-lookup's build script).

#![expect(clippy::expect_used, reason = "a build script reports failure by panicking")]

use std::path::{Path, PathBuf};
use std::{env, fs};

include!("../../build-support/module_registry.rs");
include!("../../build-support/release_keys.rs");

const FALLBACK: &str = r#"[{"target":"UCGF","min":"6.0.17"}]"#;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.join("../..");

    let src = Path::new("../../dist/firmware.json");
    println!("cargo:rerun-if-changed=../../dist/firmware.json");
    println!("cargo:rerun-if-changed=../../dist");
    let content = fs::read_to_string(src).unwrap_or_else(|_| FALLBACK.to_string());
    fs::write(out.join("firmware.json"), content).expect("write firmware.json");

    emit_release_keys("picket-core's build.rs", &workspace_root, &out);

    let dir = manifest.join("src").join("modules").join("download");
    println!("cargo:rerun-if-changed={}", dir.display());
    let registry = registry_or_exit("picket-core download module registry", &dir, |modules| {
        render_registry(
            "picket-core's build.rs from src/modules/download/*/",
            modules,
            "MODULE_IDS",
            "all_modules",
            "crate::modules::download::DownloadModule",
        )
    });
    fs::write(out.join("download_registry.rs"), registry).expect("write download_registry.rs");
}
