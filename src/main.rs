mod tls;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use construct_ice::{Obfs4Listener, Obfs4Stream, ServerConfig};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{error, info, warn};

const DEFAULT_LISTEN:     &str = "0.0.0.0:443";
const DEFAULT_STATE:      &str = "/data";
const DEFAULT_SNI:        &str = "storage.yandexcloud.net";
const TLS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 requires explicit provider selection when multiple crypto
    // backends are compiled in (ring from construct-ice + aws-lc-rs from rcgen).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let upstream  = std::env::var("UPSTREAM")
        .context("UPSTREAM env var required (e.g. ams.konstruct.cc:443)")?;
    let listen    = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let state_dir = std::env::var("STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE.to_string());
    let sni       = std::env::var("TLS_SNI_HOST").unwrap_or_else(|_| DEFAULT_SNI.to_string());

    let relay_tls = tls::setup(&state_dir, &sni)?;
    let config    = load_or_generate_obfs4(&state_dir)?;

    info!("╔══════════════════════════════════════════════════════════");
    info!("║  construct-relay  v{}", env!("CARGO_PKG_VERSION"));
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  listen    {}", listen);
    info!("║  upstream  {}", upstream);
    info!("║  TLS SNI   {}", sni);
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  obfs4 bridge cert:");
    info!("║    {}", config.bridge_cert());
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  TLS SPKI fingerprint (→ iOS ICEConfig.mskRelayPinnedSPKI):");
    info!("║    {}", relay_tls.spki_hex);
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  bridge line:");
    info!("║    {}", config.bridge_line());
    info!("╚══════════════════════════════════════════════════════════");

    let listener = Arc::new(Obfs4Listener::bind(&listen, config).await?);
    info!("Listening on {} (TLS+obfs4 / SNI: {})", listen, sni);

    loop {
        match listener.accept_tcp().await {
            Ok((tcp, peer)) => {
                let acceptor  = relay_tls.acceptor.clone();
                let listener2 = Arc::clone(&listener);
                let upstream  = upstream.clone();
                tokio::spawn(async move {
                    handle_conn(tcp, peer, acceptor, listener2, upstream).await;
                });
            }
            Err(e) => warn!("TCP accept error: {}", e),
        }
    }
}

async fn handle_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    obfs4_listener: Arc<Obfs4Listener>,
    upstream: String,
) {
    let tls_stream = match tokio::time::timeout(TLS_ACCEPT_TIMEOUT, tls_acceptor.accept(tcp)).await {
        Ok(Ok(s))  => s,
        Ok(Err(e)) => { warn!("TLS handshake failed from {}: {}", peer, e); return; }
        Err(_)     => { warn!("TLS handshake timed out from {}", peer); return; }
    };

    let obfs4_stream = match obfs4_listener.accept_stream(tls_stream).await {
        Ok(s)  => s,
        Err(e) => { warn!("obfs4 handshake failed from {}: {}", peer, e); return; }
    };

    relay_conn(obfs4_stream, peer, upstream).await;
}

async fn relay_conn(
    stream: Obfs4Stream<TlsStream<TcpStream>>,
    peer: SocketAddr,
    upstream: String,
) {
    let up = match tokio::net::TcpStream::connect(&upstream).await {
        Ok(s)  => s,
        Err(e) => { error!("Upstream connect ({}) for {}: {}", upstream, peer, e); return; }
    };

    let (mut cr, mut cw) = tokio::io::split(stream);
    let (mut ur, mut uw) = up.into_split();

    match tokio::try_join!(
        tokio::io::copy(&mut cr, &mut uw),
        tokio::io::copy(&mut ur, &mut cw),
    ) {
        Ok((sent, recv)) => info!("Relay closed {} — ↑{}B ↓{}B", peer, sent, recv),
        Err(e) if is_routine_disconnect(&e) => {}
        Err(e) => warn!("Relay error for {}: {}", peer, e),
    }
}

fn is_routine_disconnect(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), ConnectionReset | BrokenPipe | ConnectionAborted | UnexpectedEof)
}

fn load_or_generate_obfs4(state_dir: &str) -> anyhow::Result<ServerConfig> {
    let path = format!("{state_dir}/relay.obfs4");
    let p    = Path::new(&path);
    if p.exists() {
        let bytes = std::fs::read(p).with_context(|| format!("reading {path}"))?;
        let cfg   = ServerConfig::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("corrupt obfs4 state file: {}", e))?;
        info!("Loaded obfs4 identity from {path}");
        Ok(cfg)
    } else {
        let cfg = ServerConfig::generate();
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {state_dir}"))?;
        std::fs::write(p, cfg.to_bytes())
            .with_context(|| format!("writing {path}"))?;
        info!("Generated new obfs4 identity → {path}");
        Ok(cfg)
    }
}
