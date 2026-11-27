//! Provider secrets at rest (security.md §4): stored in `core.db` `secrets(name, value_enc)`,
//! encrypted with XChaCha20-Poly1305 under `secrets.key` (0600) when it exists, never returned
//! by the UI API (write-only), never in logs, exports or change diffs.
//!
//! `value_enc` layout: a format byte, then
//! - `0x01`: 24-byte random nonce ‖ ciphertext+tag, with the secret's name as associated data
//!   (a row copied under another name doesn't decrypt);
//! - `0x00`: the UTF-8 value (no `secrets.key`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

pub const SECRETS_KEY_FILE: &str = "secrets.key";
const FORMAT_PLAIN: u8 = 0x00;
const FORMAT_XCHACHA: u8 = 0x01;
/// Secret values are small (API keys, tokens).
pub const MAX_SECRET_LEN: usize = 16 * 1024;

/// The key in `secrets.key`.
pub struct SecretsKey {
    cipher: XChaCha20Poly1305,
}

impl std::fmt::Debug for SecretsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretsKey(..)")
    }
}

pub fn key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SECRETS_KEY_FILE)
}

impl SecretsKey {
    /// Writes a new random 32-byte key (0600). `init` creates one, so secrets are encrypted at
    /// rest by default. Refuses to replace an existing key, which would make every stored
    /// secret unreadable.
    pub fn create(data_dir: &Path) -> Result<Self> {
        let key = crate::util::random_bytes::<32>();
        let p = key_path(data_dir);
        crate::util::write_private_new(&p, &key)
            .with_context(|| format!("{} must not exist yet", p.display()))?;
        crate::util::fsync_dir(data_dir)?;
        Self::from_bytes(&key)
    }

    /// Loads `secrets.key` when it exists.
    pub fn load(data_dir: &Path) -> Result<Option<Self>> {
        let p = key_path(data_dir);
        match std::fs::read(&p) {
            Ok(bytes) => Self::from_bytes(&bytes).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}", p.display())),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            bail!("secrets.key must hold 32 bytes");
        }
        let cipher = XChaCha20Poly1305::new_from_slice(bytes).map_err(|_| anyhow!("bad secrets.key"))?;
        Ok(Self { cipher })
    }
}

fn aad(name: &str) -> Vec<u8> {
    format!("picket-secret:{name}").into_bytes()
}

/// Encodes a value for storage.
pub fn seal(key: Option<&SecretsKey>, name: &str, value: &str) -> Result<Vec<u8>> {
    if value.len() > MAX_SECRET_LEN {
        bail!("a secret value is at most {MAX_SECRET_LEN} bytes");
    }
    match key {
        None => {
            let mut out = vec![FORMAT_PLAIN];
            out.extend_from_slice(value.as_bytes());
            Ok(out)
        }
        Some(k) => {
            let nonce_bytes = crate::util::random_bytes::<24>();
            let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| anyhow!("nonce size"))?;
            let ct = k
                .cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: value.as_bytes(),
                        aad: &aad(name),
                    },
                )
                .map_err(|_| anyhow!("secret encryption failed"))?;
            let mut out = Vec::with_capacity(1 + 24 + ct.len());
            out.push(FORMAT_XCHACHA);
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ct);
            Ok(out)
        }
    }
}

/// Decodes a stored value.
pub fn open(key: Option<&SecretsKey>, name: &str, stored: &[u8]) -> Result<String> {
    match stored.split_first() {
        Some((&FORMAT_PLAIN, rest)) => Ok(String::from_utf8(rest.to_vec())?),
        Some((&FORMAT_XCHACHA, rest)) => {
            let k = key.ok_or_else(|| anyhow!("secret {name:?} is encrypted but secrets.key is missing"))?;
            if rest.len() < 24 + 16 {
                bail!("secret {name:?} is truncated");
            }
            let (nonce, ct) = rest.split_at(24);
            let nonce = XNonce::try_from(nonce).map_err(|_| anyhow!("nonce size"))?;
            let pt = k
                .cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ct,
                        aad: &aad(name),
                    },
                )
                .map_err(|_| anyhow!("secret {name:?} doesn't decrypt with secrets.key"))?;
            Ok(String::from_utf8(pt)?)
        }
        _ => bail!("secret {name:?} has an unknown format"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypted_and_plain() {
        let d = tempfile::tempdir().unwrap();
        let k = SecretsKey::create(d.path()).unwrap();
        let sealed = seal(Some(&k), "am_rt", "token-123").unwrap();
        assert_eq!(sealed[0], FORMAT_XCHACHA);
        assert!(!sealed.windows(9).any(|w| w == b"token-123"));
        assert_eq!(open(Some(&k), "am_rt", &sealed).unwrap(), "token-123");
        // Bound to the name.
        assert!(open(Some(&k), "other", &sealed).is_err());
        // Without the key it can't be read.
        assert!(open(None, "am_rt", &sealed).is_err());
        let plain = seal(None, "x", "v").unwrap();
        assert_eq!(open(Some(&k), "x", &plain).unwrap(), "v");
        let loaded = SecretsKey::load(d.path()).unwrap().unwrap();
        assert_eq!(open(Some(&loaded), "am_rt", &sealed).unwrap(), "token-123");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(key_path(d.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        // Another key can't read it.
        let other = SecretsKey::from_bytes(&[9u8; 32]).unwrap();
        assert!(open(Some(&other), "am_rt", &sealed).is_err());
    }

    #[test]
    fn an_existing_key_is_never_replaced() {
        // Replacing secrets.key would make every stored secret unreadable.
        let d = tempfile::tempdir().unwrap();
        SecretsKey::create(d.path()).unwrap();
        let before = std::fs::read(key_path(d.path())).unwrap();
        assert!(SecretsKey::create(d.path()).is_err());
        assert_eq!(std::fs::read(key_path(d.path())).unwrap(), before);
    }
}
