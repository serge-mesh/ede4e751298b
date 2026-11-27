//! picket-edge-update's build script: compiles default release public keys from
//! `PICKET_RELEASE_PUB` or `PICKET_RELEASE_PUB_FILE` into `$OUT_DIR/release_keys.rs`
//! (edge.md §2).

#![expect(clippy::expect_used, reason = "a build script reports failure by panicking")]

use std::env;
use std::path::PathBuf;

include!("../../build-support/release_keys.rs");

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    emit_release_keys("picket-edge-update's build.rs", &manifest.join("../.."), &out);
}
