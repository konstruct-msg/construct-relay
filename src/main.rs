mod tls;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use construct_ice::{Obfs4Listener, ServerConfig, WebTunnelServerStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{error, info, warn};

const DEFAULT_LISTEN:      &str = "0.0.0.0:443";
const DEFAULT_STATE:       &str = "/data";
const DEFAULT_SNI:         &str = "storage.yandexcloud.net";
const DEFAULT_WT_PATH:     &str = "/construct-ice";
const TLS_ACCEPT_TIMEOUT:  Duration = Duration::from_secs(10);

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
    let wt_path   = std::env::var("WT_PATH").unwrap_or_else(|_| DEFAULT_WT_PATH.to_string());

    let relay_tls = tls::setup(&state_dir, &sni)?;
    let config    = load_or_generate_obfs4(&state_dir)?;

    info!("╔══════════════════════════════════════════════════════════");
    info!("║  construct-relay  v{}", env!("CARGO_PKG_VERSION"));
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  listen    {}", listen);
    info!("║  upstream  {}", upstream);
    info!("║  TLS SNI   {}", sni);
    info!("║  wt_path   {} (WebTunnel v2)", wt_path);
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
    info!("Listening on {} (TLS+obfs4 / WebTunnel / SNI: {})", listen, sni);

    loop {
        match listener.accept_tcp().await {
            Ok((tcp, peer)) => {
                let acceptor  = relay_tls.acceptor.clone();
                let listener2 = Arc::clone(&listener);
                let upstream  = upstream.clone();
                let wt_path   = wt_path.clone();
                tokio::spawn(async move {
                    handle_conn(tcp, peer, acceptor, listener2, upstream, wt_path).await;
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
    wt_path: String,
) {
    let tls_stream = match tokio::time::timeout(TLS_ACCEPT_TIMEOUT, tls_acceptor.accept(tcp)).await {
        Ok(Ok(s))  => s,
        Ok(Err(e)) => { warn!("TLS handshake failed from {}: {}", peer, e); return; }
        Err(_)     => { warn!("TLS handshake timed out from {}", peer); return; }
    };

    // Peek the first byte to distinguish WebTunnel (HTTP GET) from obfs4.
    // WebTunnel always opens with "GET /path HTTP/1.1\r\n..." → first byte is b'G'.
    // obfs4 sends random-looking bytes that never start with b'G' in practice,
    // but we fall back gracefully even if they do (obfs4 accept will just fail).
    let mut buffered = tokio::io::BufReader::with_capacity(8192, tls_stream);
    let first = match peek_first_byte(&mut buffered).await {
        Ok(b)  => b,
        Err(e) => { warn!("peek failed from {}: {}", peer, e); return; }
    };

    if first == b'G' {
        // WebTunnel path: perform WebSocket handshake then relay
        info!("WebTunnel connection from {}", peer);
        match WebTunnelServerStream::accept(buffered, &wt_path).await {
            Ok(ws) => relay_conn(ws, peer, upstream).await,
            Err(e) => warn!("WebTunnel handshake failed from {}: {}", peer, e),
        }
    } else {
        // obfs4 path: existing encrypted transport
        match obfs4_listener.accept_stream(buffered).await {
            Ok(s)  => relay_conn(s, peer, upstream).await,
            Err(e) => warn!("obfs4 handshake failed from {}: {}", peer, e),
        }
    }
}

async fn peek_first_byte<S: AsyncRead + Unpin>(reader: &mut tokio::io::BufReader<S>) -> std::io::Result<u8> {
    use tokio::io::AsyncBufReadExt;
    let buf = reader.fill_buf().await?;
    buf.first().copied().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty TLS stream"))
}

async fn relay_conn<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
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
