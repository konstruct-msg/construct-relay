mod tls;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use construct_ice::{Obfs4Listener, ServerConfig, WebTunnelServerStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{error, info, warn};

const DEFAULT_LISTEN:      &str = "0.0.0.0:443";
const DEFAULT_STATE:       &str = "/data";
const DEFAULT_SNI:         &str = "storage.yandexcloud.net";
/// Neutral WebSocket path that looks like a generic API endpoint.
/// Override with WT_PATH env var on the relay.  Avoid service-identifying
/// names — this path appears in HTTP Upgrade requests and is DPI-visible.
const DEFAULT_WT_PATH:     &str = "/api/stream";
/// Secondary listener port for direct TLS+obfs4 connections that bypass CDN.
/// Set ALT_LISTEN_ADDR=0.0.0.0:9443 on CDN-fronted relays (e.g. MSK/Yandex Cloud)
/// so mobile clients can reach the relay without going through the CDN layer.
/// Uses the same TLS cert, obfs4 identity, and upstream as the primary listener.
const DEFAULT_ALT_LISTEN:  &str = "";
const TLS_ACCEPT_TIMEOUT:  Duration = Duration::from_secs(10);
/// Each auth period is 5 minutes. We accept current ± 1 period (±5 min clock drift).
const AUTH_PERIOD_SECS:    u64    = 300;
/// Default maximum concurrent connections per IP if MAX_CONNS_PER_IP env var is not set.
/// HTTP/2 keepalive + happy-eyeballs dual-relay probing + WebTunnel pre-probe means a
/// single legitimate client can hold 6–12 simultaneous connections.  Set conservatively
/// high enough to not rate-limit real clients while still blocking floods.
const DEFAULT_MAX_CONNS_PER_IP: usize = 24;
/// Number of auth failures before an IP enters cooldown.
/// Uses a simple cumulative counter (no sliding window) so slow persistent
/// probers (e.g. one attempt per hour) are caught after exactly N tries.
const AUTH_FAIL_THRESHOLD:  usize    = 3;
/// How long a blocked IP stays in cooldown. Counter resets on expiry.
const AUTH_FAIL_COOLDOWN:   Duration = Duration::from_secs(86_400); // 24 hours

// ---------------------------------------------------------------------------
// Per-IP connection limiter (RAII guard)
// ---------------------------------------------------------------------------

type ConnTable = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// RAII guard that decrements the per-IP counter when the connection ends.
struct ConnGuard {
    ip: IpAddr,
    table: ConnTable,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut t = self.table.lock().unwrap();
        match t.get_mut(&self.ip) {
            Some(n) if *n <= 1 => { t.remove(&self.ip); }
            Some(n) => { *n -= 1; }
            None => {}
        }
    }
}

/// Try to acquire a connection slot for `ip`.  Returns `None` if the limit is reached.
fn try_acquire(table: &ConnTable, ip: IpAddr, max: usize) -> Option<ConnGuard> {
    let mut t = table.lock().unwrap();
    let count = t.entry(ip).or_insert(0);
    if *count >= max {
        return None;
    }
    *count += 1;
    Some(ConnGuard { ip, table: Arc::clone(table) })
}

// ---------------------------------------------------------------------------
// Per-IP auth-failure rate limiter
// ---------------------------------------------------------------------------
//
// Tracks WebTunnel bad-path rejections and obfs4 HMAC failures per source IP.
// Uses a simple cumulative counter (not a sliding window) so slow persistent
// probers that stay under the per-hour rate are still caught after N total tries.
// After AUTH_FAIL_THRESHOLD failures the IP enters AUTH_FAIL_COOLDOWN: incoming
// TCP connections are dropped immediately (before TLS), saving CPU on obfs4
// key derivation and WebSocket parsing. Counter resets when the cooldown expires.

#[derive(Default)]
struct FailEntry {
    /// Cumulative auth failure count since the entry was created / last reset.
    count:          usize,
    /// If Some, the IP is blocked until this instant.
    cooldown_until: Option<Instant>,
}

#[derive(Clone)]
struct AuthFailTable(Arc<Mutex<HashMap<IpAddr, FailEntry>>>);

impl AuthFailTable {
    fn new() -> Self { Self(Arc::new(Mutex::new(HashMap::new()))) }

    /// Returns `true` if the IP is currently in cooldown. Lazily evicts expired entries.
    fn is_blocked(&self, ip: IpAddr) -> bool {
        let mut map = self.0.lock().unwrap();
        let now = Instant::now();
        if let Some(e) = map.get_mut(&ip) {
            if let Some(until) = e.cooldown_until {
                if now < until {
                    return true;
                }
                map.remove(&ip); // cooldown expired — reset counter
            }
        }
        false
    }

    /// Record an auth failure for `ip`. Logs a warning if cooldown is newly triggered.
    fn record_failure(&self, ip: IpAddr) {
        let newly_blocked;
        {
            let mut map = self.0.lock().unwrap();
            let now = Instant::now();
            let e = map.entry(ip).or_default();
            e.count += 1;
            if e.count >= AUTH_FAIL_THRESHOLD && e.cooldown_until.is_none() {
                e.cooldown_until = Some(now + AUTH_FAIL_COOLDOWN);
                newly_blocked = true;
            } else {
                newly_blocked = false;
            }
        }
        if newly_blocked {
            warn!(
                "Auth-fail threshold ({} failures) reached for {} — \
                 dropping new connections for {}h",
                AUTH_FAIL_THRESHOLD,
                ip,
                AUTH_FAIL_COOLDOWN.as_secs() / 3600,
            );
        }
    }
}

/// Compute a WebTunnel path auth token for a given time period.
///
/// Both the relay and the iOS client derive the token identically:
///   `SHA-256( bridge_cert_base64_string || "webtunnel-v1" || period_u64_be )[:8]`
/// encoded as 16 lowercase hex characters.  The `bridge_cert` string is the
/// `cert=...` value from the relay's obfs4 bridge line — available to clients
/// via the relay manifest they download at startup.
fn webtunnel_token(bridge_cert: &str, period: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bridge_cert.as_bytes());
    h.update(b"webtunnel-v1");
    h.update(period.to_be_bytes());
    hex::encode(&h.finalize()[..8])
}

/// Return the set of valid authenticated WebTunnel paths for right now.
/// Accepts current period ± 1 to tolerate up to 5 minutes of clock drift.
fn valid_wt_paths(bridge_cert: &str, base_path: &str) -> Vec<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let period = now / AUTH_PERIOD_SECS;
    // period-1, period, period+1
    [period.saturating_sub(1), period, period + 1]
        .iter()
        .map(|&p| format!("{base_path}/{}", webtunnel_token(bridge_cert, p)))
        .collect()
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

    let upstream     = std::env::var("UPSTREAM")
        .context("UPSTREAM env var required (e.g. ams.konstruct.cc:443)")?;
    // Default: TLS=true. Almost all deployments target port 443 which requires TLS.
    // Set UPSTREAM_TLS=false only when upstream is a plain HTTP/2 port (rare, internal).
    let upstream_tls = std::env::var("UPSTREAM_TLS")
        .map(|v| !v.eq_ignore_ascii_case("false") && v != "0")
        .unwrap_or(true);
    let listen    = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let alt_listen = std::env::var("ALT_LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_ALT_LISTEN.to_string());
    let state_dir = std::env::var("STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE.to_string());
    let sni       = std::env::var("TLS_SNI_HOST").unwrap_or_else(|_| DEFAULT_SNI.to_string());
    let wt_path   = std::env::var("WT_PATH").unwrap_or_else(|_| DEFAULT_WT_PATH.to_string());
    let max_conns_per_ip: usize = std::env::var("MAX_CONNS_PER_IP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONNS_PER_IP);

    // Build upstream TLS config once (reused for every connection).
    let upstream_tls_config = if upstream_tls {
        Some(Arc::new(make_upstream_tls_config()?))
    } else {
        None
    };

    let relay_tls   = tls::setup(&state_dir, &sni)?;
    let config      = load_or_generate_obfs4(&state_dir)?;
    let bridge_cert = config.bridge_cert();

    // Log the current auth token so operators can verify client-side derivation.
    let now_period = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / AUTH_PERIOD_SECS;

    info!("╔══════════════════════════════════════════════════════════");
    info!("║  construct-relay  v{}", env!("CARGO_PKG_VERSION"));
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  listen    {}", listen);
    if !alt_listen.is_empty() {
        info!("║  alt-listen {} (TLS+obfs4, CDN bypass)", alt_listen);
    }
    info!("║  upstream  {} (TLS: {})", upstream, upstream_tls);
    info!("║  TLS SNI   {}", sni);
    info!("║  wt_path   {}/{} (WebTunnel v2, current token)", wt_path, webtunnel_token(&bridge_cert, now_period));
    info!("║  max_conns {}/IP", max_conns_per_ip);
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  obfs4 bridge cert:");
    info!("║    {}", bridge_cert);
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  TLS SPKI fingerprint (→ iOS ICEConfig.mskRelayPinnedSPKI):");
    info!("║    {}", relay_tls.spki_hex);
    info!("╠══════════════════════════════════════════════════════════");
    info!("║  bridge line:");
    info!("║    {}", config.bridge_line());
    info!("╚══════════════════════════════════════════════════════════");

    let listener = Arc::new(Obfs4Listener::bind(&listen, config).await?);
    info!("Listening on {} (TLS+obfs4 / WebTunnel / SNI: {})", listen, sni);

    let conn_table:      ConnTable      = Arc::new(Mutex::new(HashMap::new()));
    let auth_fail_table: AuthFailTable  = AuthFailTable::new();

    // Optional secondary listener: bypasses CDN so raw TLS+obfs4 connections can
    // reach the relay directly.  Shares the same obfs4 identity and TLS cert as the
    // primary listener — clients pin the same SPKI fingerprint regardless of port.
    // Typical deployment: ALT_LISTEN_ADDR=0.0.0.0:9443 on a CDN-fronted relay.
    if !alt_listen.is_empty() {
        let alt_tcp = tokio::net::TcpListener::bind(&alt_listen).await
            .with_context(|| format!("binding ALT_LISTEN_ADDR {alt_listen}"))?;
        info!("Alt listener on {} (TLS+obfs4 direct, CDN bypass)", alt_listen);

        let listener_alt    = Arc::clone(&listener);
        let tls_alt         = relay_tls.acceptor.clone();
        let upstream_alt    = upstream.clone();
        let wt_path_alt     = wt_path.clone();
        let bridge_cert_alt = bridge_cert.clone();
        let conn_table_alt  = Arc::clone(&conn_table);
        let auth_fail_alt   = auth_fail_table.clone();
        let tls_config_alt  = upstream_tls_config.clone();

        tokio::spawn(async move {
            loop {
                match alt_tcp.accept().await {
                    Ok((tcp, peer)) => {
                        let ip = peer.ip();
                        if auth_fail_alt.is_blocked(ip) {
                            warn!("Auth-cooldown: dropping connection from {}", ip);
                            continue;
                        }
                        let guard = match try_acquire(&conn_table_alt, ip, max_conns_per_ip) {
                            Some(g) => g,
                            None => {
                                warn!("Alt connection limit ({}) exceeded for {} — dropping", max_conns_per_ip, ip);
                                continue;
                            }
                        };
                        let acceptor     = tls_alt.clone();
                        let listener2    = Arc::clone(&listener_alt);
                        let upstream     = upstream_alt.clone();
                        let wt_path      = wt_path_alt.clone();
                        let bridge_cert  = bridge_cert_alt.clone();
                        let tls_cfg      = tls_config_alt.clone();
                        let auth_fail    = auth_fail_alt.clone();
                        tokio::spawn(async move {
                            handle_conn(tcp, peer, acceptor, listener2, upstream, wt_path, bridge_cert, tls_cfg, auth_fail).await;
                            drop(guard);
                        });
                    }
                    Err(e) => warn!("Alt listener TCP accept error: {}", e),
                }
            }
        });
    }

    loop {
        match listener.accept_tcp().await {
            Ok((tcp, peer)) => {
                let ip = peer.ip();
                if auth_fail_table.is_blocked(ip) {
                    warn!("Auth-cooldown: dropping connection from {}", ip);
                    continue;
                }
                let guard = match try_acquire(&conn_table, ip, max_conns_per_ip) {
                    Some(g) => g,
                    None => {
                        warn!("Connection limit ({}) exceeded for {} — dropping", max_conns_per_ip, ip);
                        continue;
                    }
                };
                let acceptor         = relay_tls.acceptor.clone();
                let listener2        = Arc::clone(&listener);
                let upstream         = upstream.clone();
                let wt_path          = wt_path.clone();
                let bridge_cert      = bridge_cert.clone();
                let upstream_tls_cfg = upstream_tls_config.clone();
                let auth_fail        = auth_fail_table.clone();
                tokio::spawn(async move {
                    handle_conn(tcp, peer, acceptor, listener2, upstream, wt_path, bridge_cert, upstream_tls_cfg, auth_fail).await;
                    drop(guard); // release slot when connection ends
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
    bridge_cert: String,
    upstream_tls: Option<Arc<rustls::ClientConfig>>,
    auth_fail: AuthFailTable,
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
        // WebTunnel path: validate time-based auth token derived from bridge cert,
        // then perform WebSocket handshake and relay.
        info!("WebTunnel connection from {}", peer);
        let valid_paths = valid_wt_paths(&bridge_cert, &wt_path);

        // Peek at the HTTP request path without consuming the buffer.
        // fill_buf() fills the internal 8 KiB buffer but does NOT advance the read
        // position, so accept_validated() will see the same bytes on its own reads.
        let path_ok = {
            use tokio::io::AsyncBufReadExt;
            match buffered.fill_buf().await {
                Ok(buf) => extract_http_path(buf)
                    .map(|p| valid_paths.iter().any(|v| v == p))
                    .unwrap_or(false),
                Err(_) => false,
            }
        };

        if path_ok {
            match WebTunnelServerStream::accept_validated(buffered, |p| valid_paths.iter().any(|v| v == p)).await {
                Ok(ws) => relay_conn(ws, peer, upstream, upstream_tls).await,
                Err(e) => warn!("WebTunnel handshake failed from {}: {}", peer, e),
            }
        } else {
            // Unknown path: delay then respond as a generic nginx server.
            // The delay makes automated path enumeration ~500× slower.
            // The HTTP response hides the relay from internet scanners (Shodan, Censys).
            auth_fail.record_failure(peer.ip());
            warn!("WebTunnel auth rejected from {} — sending decoy response", peer);
            tokio::time::sleep(Duration::from_millis(500)).await;
            send_decoy_http_response(&mut buffered).await;
        }
    } else {
        // obfs4 path: existing encrypted transport
        match obfs4_listener.accept_stream(buffered).await {
            Ok(s)  => relay_conn(s, peer, upstream, upstream_tls).await,
            Err(e) => {
                auth_fail.record_failure(peer.ip());
                warn!("obfs4 handshake failed from {}: {}", peer, e);
            }
        }
    }
}

async fn peek_first_byte<S: AsyncRead + Unpin>(reader: &mut tokio::io::BufReader<S>) -> std::io::Result<u8> {
    use tokio::io::AsyncBufReadExt;
    let buf = reader.fill_buf().await?;
    buf.first().copied().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty TLS stream"))
}

/// Extract the HTTP request path from bytes already in the BufReader's buffer.
/// Parses the request line "GET /path HTTP/1.1" and returns "/path".
/// Does not advance the buffer's read position.
fn extract_http_path(buf: &[u8]) -> Option<&str> {
    let line_end = buf.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    let mut parts = line.splitn(3, ' ');
    let _method = parts.next()?;
    parts.next()
}

/// Respond with a minimal nginx-like 404 page to hide the relay from internet scanners.
/// Called when a WebTunnel connection arrives with an invalid (unrecognised) path.
/// Using `reader.get_mut()` writes directly to the underlying TLS stream without
/// disturbing the BufReader's unread buffer (which the scanner never reads anyway).
async fn send_decoy_http_response<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut tokio::io::BufReader<S>,
) {
    use tokio::io::AsyncWriteExt;
    // Matches the default nginx 404 page byte-for-byte (body length = 153 bytes).
    const BODY: &[u8] = b"<html>\r\n\
<head><title>404 Not Found</title></head>\r\n\
<body>\r\n\
<center><h1>404 Not Found</h1></center>\r\n\
<hr><center>nginx/1.24.0</center>\r\n\
</body>\r\n\
</html>\r\n";
    let head = format!(
        "HTTP/1.1 404 Not Found\r\n\
Server: nginx/1.24.0\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\r\n",
        BODY.len()
    );
    let stream = reader.get_mut();
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(BODY).await;
    let _ = stream.flush().await;
}

async fn relay_conn<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    peer: SocketAddr,
    upstream: String,
    upstream_tls: Option<Arc<rustls::ClientConfig>>,
) {
    let tcp = match tokio::net::TcpStream::connect(&upstream).await {
        Ok(s)  => s,
        Err(e) => { error!("Upstream connect ({}) for {}: {}", upstream, peer, e); return; }
    };

    if let Some(tls_config) = upstream_tls {
        // Re-encrypt to upstream with TLS (required when UPSTREAM is a TLS port).
        let hostname = upstream.split(':').next().unwrap_or(&upstream).to_string();
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = match rustls::pki_types::ServerName::try_from(hostname.as_str()) {
            Ok(n)  => n.to_owned(),
            Err(e) => { error!("Invalid upstream hostname '{}': {}", hostname, e); return; }
        };
        match connector.connect(server_name, tcp).await {
            Ok(tls_stream) => {
                info!("Relay {} → upstream {} (TLS) connected", peer, upstream);
                pipe(stream, tls_stream, peer).await;
            }
            Err(e) => error!("Upstream TLS handshake to {} failed: {}", upstream, e),
        }
    } else {
        info!("Relay {} → upstream {} (plain) connected", peer, upstream);
        pipe(stream, tcp, peer).await;
    }
}

async fn pipe<A, B>(a: A, b: B, peer: SocketAddr)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    match tokio::try_join!(
        tokio::io::copy(&mut ar, &mut bw),
        tokio::io::copy(&mut br, &mut aw),
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

/// Build a rustls ClientConfig that trusts OS/system root certificates.
/// ALPN is set to ["h2"] so the upstream gRPC server negotiates HTTP/2.
/// Without this, rustls sends no ALPN extension and the server defaults to
/// HTTP/1.1, causing an immediate close when it receives the HTTP/2 preface.
fn make_upstream_tls_config() -> anyhow::Result<rustls::ClientConfig> {
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
