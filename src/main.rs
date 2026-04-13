use std::net::SocketAddr;
use std::path::Path;

use anyhow::Context;
use construct_ice::{
    Obfs4Listener, Obfs4Stream, ServerConfig,
    transport::cover::{CoverProxyConfig, MixedAccept},
};
use tokio::net::TcpStream;
use tracing::{error, info, warn};

const DEFAULT_LISTEN: &str = "0.0.0.0:443";
const DEFAULT_STATE: &str = "/data/relay.key";
const DEFAULT_COVER: &str = "cloudflare.com:443";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let upstream = std::env::var("UPSTREAM")
        .context("UPSTREAM env var required (e.g. ams.konstruct.cc:443)")?;
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let state = std::env::var("STATE_FILE").unwrap_or_else(|_| DEFAULT_STATE.to_string());
    let cover = std::env::var("COVER_SITE").unwrap_or_else(|_| DEFAULT_COVER.to_string());

    let config = load_or_generate(&state)?;

    info!("╔══════════════════════════════════════════════════════════");
    info!("║  construct-relay  v{}", env!("CARGO_PKG_VERSION"));
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  listen    {}", listen);
    info!("║  upstream  {}", upstream);
    info!("║  cover     {}", cover);
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  bridge cert (add to iOS app / server config):");
    info!("║    {}", config.bridge_cert());
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  bridge line:");
    info!("║    {}", config.bridge_line());
    info!("╚══════════════════════════════════════════════════════════");

    let cover_cfg = CoverProxyConfig::new(&cover);
    let listener = Obfs4Listener::bind(&listen, config).await?;
    info!("Listening on {}", listen);

    loop {
        match listener.accept_obfs4_or_proxy(cover_cfg.clone()).await {
            Ok((MixedAccept::Obfs4(stream), peer)) => {
                let upstream = upstream.clone();
                tokio::spawn(relay_conn(stream, peer, upstream));
            }
            Ok((MixedAccept::Proxied(_handle), peer)) => {
                // Active probe detected — connection is being forwarded to cover site.
                info!("Active probe from {} → proxied to cover", peer);
            }
            Err(e) => warn!("Accept error: {}", e),
        }
    }
}

async fn relay_conn(
    stream: Box<Obfs4Stream<TcpStream>>,
    peer: SocketAddr,
    upstream: String,
) {
    let up = match TcpStream::connect(&upstream).await {
        Ok(s) => s,
        Err(e) => {
            error!("Upstream connect failed ({}) for {}: {}", upstream, peer, e);
            return;
        }
    };

    let (mut cr, mut cw) = tokio::io::split(*stream);
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
    matches!(
        e.kind(),
        ConnectionReset | BrokenPipe | ConnectionAborted | UnexpectedEof
    )
}

fn load_or_generate(path: &str) -> anyhow::Result<ServerConfig> {
    let p = Path::new(path);
    if p.exists() {
        let bytes = std::fs::read(p).with_context(|| format!("reading state file {}", path))?;
        let cfg = ServerConfig::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("corrupt state file {}: {}", path, e))?;
        info!("Loaded relay identity from {}", path);
        Ok(cfg)
    } else {
        let cfg = ServerConfig::generate();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating state dir {}", parent.display()))?;
        }
        std::fs::write(p, cfg.to_bytes())
            .with_context(|| format!("writing state file {}", path))?;
        info!("Generated new relay identity → {}", path);
        Ok(cfg)
    }
}

