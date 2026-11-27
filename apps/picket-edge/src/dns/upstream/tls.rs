//! Client TLS for upstreams and lookup servers (edge.md §6): a server is named by IP plus TLS
//! name (hard rule 9), verified against `trust_store` (PEM text) or the Mozilla roots
//! (`webpki-roots`). One `ClientConfig` per endpoint, kept across reconnects, so its in-memory
//! session cache gives TLS 1.3 resumption.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject};

/// Most certificates read from one `trust_store` (README §2 Bounded).
pub const MAX_TRUST_CERTS: usize = 256;

/// The roots: `trust_store`'s certificates, or the Mozilla roots.
pub fn roots(trust_store: Option<&str>) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    match trust_store {
        None => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        Some(pem) => {
            let mut n = 0usize;
            for c in CertificateDer::pem_slice_iter(pem.as_bytes()).take(MAX_TRUST_CERTS) {
                let c = c.map_err(|e| anyhow!("trust_store: {e}"))?;
                store.add(c).context("trust_store certificate")?;
                n += 1;
            }
            if n == 0 {
                return Err(anyhow!("trust_store holds no certificate"));
            }
        }
    }
    Ok(store)
}

/// A client config for lookup providers' HTTPS APIs: the Mozilla roots plus `extra` (PEM; tests
/// add a local CA), TLS 1.2 and 1.3, ALPN `alpn`.
pub fn web_client_config(extra: Option<&str>, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut store = roots(None)?;
    if let Some(pem) = extra {
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()).take(MAX_TRUST_CERTS) {
            store
                .add(c.map_err(|e| anyhow!("extra roots: {e}"))?)
                .context("extra root")?;
        }
    }
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("TLS versions")?
        .with_root_certificates(store)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// A client config: the given roots, TLS 1.3 only (`tls13_only`, upstreams: edge.md §6) or 1.2
/// and 1.3 (lookup providers' HTTPS APIs), and ALPN `alpn`.
pub fn client_config(
    trust_store: Option<&str>,
    alpn: &[&[u8]],
    tls13_only: bool,
) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let versions: &[&'static rustls::SupportedProtocolVersion] = if tls13_only {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .context("TLS versions")?
        .with_root_certificates(roots(trust_store)?)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// The name a server's certificate is checked against: its TLS name, or its IP when none is set.
pub fn server_name(tls_host: Option<&str>, ip: IpAddr) -> Result<ServerName<'static>> {
    match tls_host {
        Some(h) if !h.is_empty() => {
            ServerName::try_from(h.to_owned()).map_err(|_| anyhow!("bad TLS name {h:?}"))
        }
        _ => Ok(ServerName::IpAddress(ip.into())),
    }
}
