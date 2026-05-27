mod config;
mod conn;
mod ratelimit;
mod tls;
mod upstream;
mod webtunnel;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use construct_ice::Obfs4Listener;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::{
    AUTH_FAIL_CLEANUP_INTERVAL, DEFAULT_ALT_LISTEN, DEFAULT_LISTEN, DEFAULT_MAX_CONNS_PER_IP,
    DEFAULT_SNI, DEFAULT_STATE, DEFAULT_WT_PATH, MAX_GLOBAL_CONNECTIONS, WT_TOKEN_REFRESH_INTERVAL,
    is_trusted_proxy,
};
use crate::conn::{HandlerCtx, apply_tcp_keepalive, handle_incoming};
use crate::ratelimit::{AuthFailTable, ConnGuard, ConnTable, try_acquire};
use crate::webtunnel::{WtTokenCache, current_auth_period, webtunnel_token};

/// Per-accept-loop context that bundles all shared state needed to spawn
/// a connection handler.  Keeps `spawn_handler` to just 3 arguments.
struct SpawnCtx {
    conn_table: ConnTable,
    auth_fail: AuthFailTable,
    trusted_proxies: Arc<Vec<(IpAddr, u8)>>,
    global_conns: Arc<Semaphore>,
    max_conns_per_ip: usize,
    handler: HandlerCtx,
}

/// Shared spawn logic used by both primary and alt accept loops.
async fn spawn_handler(tcp: TcpStream, peer: SocketAddr, ctx: &SpawnCtx) {
    #[cfg(unix)]
    apply_tcp_keepalive(&tcp);
    let ip = peer.ip();
    debug!("[{label}] TCP accept from {peer}", label = ctx.handler.label);

    let trusted = is_trusted_proxy(ip, &ctx.trusted_proxies);
    if trusted {
        debug!("[{label}] {ip} is trusted proxy — bypassing rate limits", label = ctx.handler.label);
    }
    if !trusted && ctx.auth_fail.is_blocked(ip) {
        warn!("[{label}] Auth-cooldown: dropping connection from {ip}", label = ctx.handler.label);
        return;
    }
    let guard: Option<ConnGuard> = if trusted {
        None
    } else {
        match try_acquire(&ctx.conn_table, ip, ctx.max_conns_per_ip) {
            Some(g) => Some(g),
            None => {
                warn!(
                    "[{label}] Connection limit ({max}) exceeded for {ip} — dropping",
                    label = ctx.handler.label,
                    max = ctx.max_conns_per_ip,
                );
                return;
            }
        }
    };
    let global_permit = match ctx.global_conns.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            debug!("Global semaphore closed — dropping connection from {peer}");
            return; // semaphore closed, shutting down
        }
    };
    let handler = ctx.handler.clone();
    tokio::spawn(async move {
        handle_incoming(tcp, peer, &handler).await;
        drop(guard);
        drop(global_permit);
    });
}

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

    // ── Environment ─────────────────────────────────────────────────────────

    let upstream = std::env::var("UPSTREAM")
        .context("UPSTREAM env var required (e.g. ams.konstruct.cc:443)")?;
    let upstream_tls = std::env::var("UPSTREAM_TLS")
        .map(|v| !v.eq_ignore_ascii_case("false") && v != "0")
        .unwrap_or(true);
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let alt_listen =
        std::env::var("ALT_LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_ALT_LISTEN.to_string());
    let state_dir = std::env::var("STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE.to_string());
    let sni = std::env::var("TLS_SNI_HOST").unwrap_or_else(|_| DEFAULT_SNI.to_string());
    let wt_path = std::env::var("WT_PATH").unwrap_or_else(|_| DEFAULT_WT_PATH.to_string());
    let max_conns_per_ip: usize = std::env::var("MAX_CONNS_PER_IP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONNS_PER_IP);
    let trusted_proxies: Arc<Vec<(IpAddr, u8)>> = Arc::new(
        std::env::var("TRUSTED_PROXIES")
            .ok()
            .map(|v| config::parse_trusted_proxies(&v))
            .unwrap_or_default(),
    );
    debug!("Global connection limit: {MAX_GLOBAL_CONNECTIONS}");
    debug!(
        "Background tasks: token refresh ({WT_TOKEN_REFRESH_INTERVAL:?}), auth-fail cleanup ({AUTH_FAIL_CLEANUP_INTERVAL:?})"
    );

    // ── TLS + obfs4 identity ────────────────────────────────────────────────

    let upstream_tls_config = if upstream_tls {
        Some(Arc::new(upstream::make_upstream_tls_config()?))
    } else {
        None
    };

    let relay_tls = tls::setup(&state_dir, &sni)?;
    let config = upstream::load_or_generate_obfs4(&state_dir)?;
    let bridge_cert = config.bridge_cert();

    // ── Startup banner ──────────────────────────────────────────────────────

    let now_period = current_auth_period();

    info!("╔══════════════════════════════════════════════════════════");
    info!("║  construct-relay  v{}", env!("CARGO_PKG_VERSION"));
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  listen    {listen}");
    if !alt_listen.is_empty() {
        info!("║  alt-listen {alt_listen} (TLS+obfs4, CDN bypass)");
    }
    info!("║  upstream  {upstream} (TLS: {upstream_tls})");
    info!("║  TLS SNI   {sni}");
    info!(
        "║  wt_path   {wt_path}/{} (WebTunnel v2, current token)",
        webtunnel_token(&bridge_cert, now_period)
    );
    info!("║  max_conns {max_conns_per_ip}/IP");
    if !trusted_proxies.is_empty() {
        info!(
            "║  trusted_proxies: {} range(s) (auth-fail + conn limits bypassed)",
            trusted_proxies.len()
        );
    } else {
        debug!("No trusted proxies configured");
    }
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  obfs4 bridge cert:");
    info!("║    {bridge_cert}");
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  TLS SPKI fingerprint (→ iOS ICEConfig.mskRelayPinnedSPKI):");
    info!("║    {}", relay_tls.spki_hex);
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  bridge line:");
    info!("║    {}", config.bridge_line());
    info!("╚══════════════════════════════════════════════════════════");

    // ── Bind primary listener ───────────────────────────────────────────────

    let listener = Arc::new(Obfs4Listener::bind(&listen, config).await?);
    info!("Listening on {listen} (TLS+obfs4 / WebTunnel / SNI: {sni})");

    // ── Shared state ────────────────────────────────────────────────────────

    let conn_table: ConnTable = Arc::new(Mutex::new(HashMap::new()));
    let auth_fail_table = AuthFailTable::new();
    let global_conns = Arc::new(Semaphore::new(MAX_GLOBAL_CONNECTIONS));
    let wt_token_cache = Arc::new(WtTokenCache::new(&bridge_cert, &wt_path));

    // Build the reusable handler context
    let handler = HandlerCtx {
        tls_acceptor: relay_tls.acceptor.clone(),
        obfs4_listener: Arc::clone(&listener),
        upstream: upstream.clone(),
        upstream_tls: upstream_tls_config.clone(),
        wt_cache: Arc::clone(&wt_token_cache),
        auth_fail: auth_fail_table.clone(),
        trusted_proxies: Arc::clone(&trusted_proxies),
        label: "primary".to_string(),
    };

    let spawn_ctx = SpawnCtx {
        conn_table: Arc::clone(&conn_table),
        auth_fail: auth_fail_table.clone(),
        trusted_proxies: Arc::clone(&trusted_proxies),
        global_conns: Arc::clone(&global_conns),
        max_conns_per_ip,
        handler,
    };

    // Background tasks
    WtTokenCache::spawn_refresh_task(
        Arc::clone(&wt_token_cache),
        bridge_cert.clone(),
        wt_path.clone(),
    );
    AuthFailTable::spawn_cleanup_task(auth_fail_table.clone());

    // ── Alt listener (optional) ─────────────────────────────────────────────

    if !alt_listen.is_empty() {
        let alt_tcp = tokio::net::TcpListener::bind(&alt_listen)
            .await
            .with_context(|| format!("binding ALT_LISTEN_ADDR {alt_listen}"))?;
        info!("Alt listener on {alt_listen} (TLS+obfs4 direct, CDN bypass)");

        let alt_spawn_ctx = SpawnCtx {
            conn_table: Arc::clone(&conn_table),
            auth_fail: auth_fail_table.clone(),
            trusted_proxies: Arc::clone(&trusted_proxies),
            global_conns: Arc::clone(&global_conns),
            max_conns_per_ip,
            handler: HandlerCtx {
                tls_acceptor: relay_tls.acceptor.clone(),
                obfs4_listener: Arc::clone(&listener),
                upstream: upstream.clone(),
                upstream_tls: upstream_tls_config.clone(),
                wt_cache: Arc::clone(&wt_token_cache),
                auth_fail: auth_fail_table.clone(),
                trusted_proxies: Arc::clone(&trusted_proxies),
                label: "alt".to_string(),
            },
        };

        tokio::spawn(async move {
            loop {
                match alt_tcp.accept().await {
                    Ok((tcp, peer)) => spawn_handler(tcp, peer, &alt_spawn_ctx).await,
                    Err(e) => warn!("alt TCP accept error: {e}"),
                }
            }
        });
    }

    // ── Primary accept loop ─────────────────────────────────────────────────

    let primary_accept = tokio::spawn(async move {
        loop {
            match spawn_ctx.handler.obfs4_listener.accept_tcp().await {
                Ok((tcp, peer)) => spawn_handler(tcp, peer, &spawn_ctx).await,
                Err(e) => warn!("primary TCP accept error: {e}"),
            }
        }
    });

    // ── Graceful shutdown ───────────────────────────────────────────────────

    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal — draining active connections...");
            primary_accept.abort();
            tokio::time::sleep(Duration::from_secs(10)).await;
            info!("Shutdown complete.");
        }
        Err(e) => error!("Failed to listen for shutdown signal: {e}"),
    }
    Ok(())
}
