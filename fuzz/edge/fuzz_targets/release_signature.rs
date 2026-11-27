//! A release signature from core (edge.md §14): decoded and checked against a fixed tarball and a
//! fixed key; core is untrusted (README §2).
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn tarball() -> &'static std::path::Path {
    static P: OnceLock<std::path::PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        let p = std::env::temp_dir().join(format!("picket-fuzz-release-{}", std::process::id()));
        std::fs::write(&p, b"release bytes").unwrap();
        p
    })
}

const KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

fuzz_target!(|data: &[u8]| {
    let _ = picket_edge::release::verify_release(tarball(), data, &[KEY.to_owned()], "1.2.3", "x86_64");
});
