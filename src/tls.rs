use std::{path::Path, sync::Arc};

use anyhow::Context;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;
use tracing::info;

pub struct RelayTls {
    pub acceptor: TlsAcceptor,
    /// SHA-256 hex of DER SubjectPublicKeyInfo — add this to iOS `ICEConfig.mskRelayPinnedSPKI`
    pub spki_hex: String,
}

/// Load existing TLS cert/key from `state_dir`, or generate a new self-signed cert for `sni`.
/// Files: `<state_dir>/relay.crt` (DER), `<state_dir>/relay.key` (PKCS#8 DER).
pub fn setup(state_dir: &str, sni: &str) -> anyhow::Result<RelayTls> {
    let cert_path = format!("{state_dir}/relay.crt");
    let key_path = format!("{state_dir}/relay.key");

    let (cert_der, key_der) = if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
        info!("Loaded existing TLS cert from {cert_path}");
        (std::fs::read(&cert_path)?, std::fs::read(&key_path)?)
    } else {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {state_dir}"))?;
        info!("Generating self-signed TLS cert for SNI: {sni}");
        let (c, k) = generate_cert(sni)?;
        std::fs::write(&cert_path, &c)
            .with_context(|| format!("writing {cert_path}"))?;
        std::fs::write(&key_path, &k)
            .with_context(|| format!("writing {key_path}"))?;
        (c, k)
    };

    let spki_hex = spki_fingerprint(&cert_der).context("computing SPKI fingerprint")?;

    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());

    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("building rustls ServerConfig")?;

    // WebTunnel uses HTTP/1.1 WebSocket upgrade — advertise http/1.1 only so
    // clients with h2+http/1.1 ALPN negotiate HTTP/1.1 explicitly.  This avoids
    // any ambiguity if a future client or middlebox tries to speak HTTP/2.
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(RelayTls {
        acceptor: TlsAcceptor::from(Arc::new(tls_cfg)),
        spki_hex,
    })
}

fn generate_cert(sni: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let kp = rcgen::KeyPair::generate().context("generating key pair")?;
    let mut params = rcgen::CertificateParams::new(vec![sni.to_string()])
        .context("building cert params")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, sni);
    let cert = params.self_signed(&kp).context("self-signing cert")?;
    Ok((cert.der().to_vec(), kp.serialize_der()))
}

fn spki_fingerprint(cert_der: &[u8]) -> anyhow::Result<String> {
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("encoding SPKI")?;
    Ok(hex::encode(Sha256::digest(&spki_der)))
}
