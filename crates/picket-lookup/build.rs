//! Lookup module registry (providers.md §1): scans `src/modules/*/` and writes
//! `$OUT_DIR/registry.rs`, which declares each module with `#[path]`, lists one boxed
//! `Module::default()` each and checks a config against a module's `Config`. No linker tricks, no
//! `unsafe`.
//!
//! The build fails on a directory without `mod.rs`, an id that isn't `[a-z0-9_]` (or isn't a
//! usable Rust module name), and a duplicate id (the scan shared with picket-core's build script).

#![expect(clippy::expect_used, reason = "a build script reports failure by panicking")]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::{env, fs};

include!("../../build-support/module_registry.rs");

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let dir = manifest.join("src").join("modules");
    println!("cargo:rerun-if-changed={}", dir.display());
    let registry = registry_or_exit("picket-lookup registry", &dir, |modules| {
        let mut s = render_registry(
            "picket-lookup's build.rs from src/modules/*/",
            modules,
            "IDS",
            "all",
            "crate::LookupModule",
        )?;
        s.push('\n');
        s.push_str(
            "/// Checks a config against a module's `Config` (its serde validation). `None` for an\n\
             /// unknown module id.\n\
             pub(crate) fn check_config(\n    id: &str,\n    cfg: &::serde_json::Value,\n) -> \
             ::core::option::Option<::core::result::Result<(), ::serde_json::Error>> {\n    \
             match id {\n",
        );
        for id in modules.keys() {
            let _ = writeln!(
                s,
                "        {id:?} => ::core::option::Option::Some(\n            \
                 <{id}::Config as ::serde::Deserialize>::deserialize(cfg).map(|_| ()),\n        ),"
            );
        }
        s.push_str("        _ => ::core::option::Option::None,\n    }\n}\n");
        Ok(s)
    });
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("registry.rs");
    fs::write(&out, registry).expect("write registry.rs");
}
