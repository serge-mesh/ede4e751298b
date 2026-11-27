//! A release's `.minisig`, which picket-edge wrote (edge.md §14 step 2): decoded, its trusted
//! comment parsed, and verified over the input with a synthetic key, as `verify_staged` does.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use picket_edge_update::api::parse_trusted_comment;
use picket_edge_update::release::{check_signed_release, decode_signature, verify_with_keys};

/// Synthetic Ed25519 minisign public key whose private half was discarded: no input verifies.
const FUZZ_RELEASE_KEY: &str = "RWQAAAAAAAAAAA5pMKK7EBOb2uv67gn1XqmH3z7rjtF8/4sRaQSD+CLV";

fuzz_target!(|data: &[u8]| {
    let Ok(sig) = decode_signature(data) else {
        return;
    };
    let comment = sig.trusted_comment();
    if let Some((version, arch)) = parse_trusted_comment(comment) {
        assert_eq!(comment, format!("picket-edge {version} {arch}"));
        assert!(check_signed_release(&sig, version, arch).is_ok());
    }
    assert_eq!(
        check_signed_release(&sig, "1.2.3", "x86_64").is_ok(),
        comment == "picket-edge 1.2.3 x86_64"
    );
    let keys = [FUZZ_RELEASE_KEY.to_owned()];
    assert!(verify_with_keys(&sig, &keys, &mut Cursor::new(data), 1 << 20).is_err());
});
