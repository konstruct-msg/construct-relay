use std::path::Path;

use anyhow::Context;
use construct_ice::ServerConfig;
use tracing::{info, warn};

/// Build a rustls ClientConfig that trusts OS/system root certificates.
/// ALPN is set to ["h2"] so the upstream gRPC server negotiates HTTP/2.
/// Without this, rustls sends no ALPN extension and the server defaults to
/// HTTP/1.1, causing an immediate close when it receives the HTTP/2 preface.
pub fn make_upstream_tls_config() -> anyhow::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        for e in &native_certs.errors {
            warn!("Native cert load warning: {}", e);
        }
    }
    for cert in native_certs.certs {
        roots.add(cert).ok(); // skip invalid certs silently
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // gRPC requires HTTP/2; advertise it via ALPN so the upstream server
    // negotiates h2 instead of falling back to http/1.1.
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// Load existing obfs4 identity from `state_dir/relay.obfs4`, or generate a new one.
pub fn load_or_generate_obfs4(state_dir: &str) -> anyhow::Result<ServerConfig> {
    let path = format!("{state_dir}/relay.obfs4");
    let p = Path::new(&path);
    if p.exists() {
        let bytes = std::fs::read(p).with_context(|| format!("reading {path}"))?;
        let cfg = ServerConfig::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("corrupt obfs4 state file: {e}"))?;
        info!("Loaded obfs4 identity from {path}");
        Ok(cfg)
    } else {
        let cfg = ServerConfig::generate();
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {state_dir}"))?;
        std::fs::write(p, cfg.to_bytes()).with_context(|| format!("writing {path}"))?;
        info!("Generated new obfs4 identity → {path}");
        Ok(cfg)
    }
}
