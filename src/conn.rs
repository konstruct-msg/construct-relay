use std::net::SocketAddr;
use std::sync::Arc;

use construct_ice::{Obfs4Listener, WebTunnelServerStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{error, info, warn};

use crate::config::{TLS_ACCEPT_TIMEOUT, is_trusted_proxy};
use crate::ratelimit::AuthFailTable;
use crate::webtunnel::WtTokenCache;

/// Shared context passed to each connection handler.
/// Bundles all the shared state so we keep the function signature small.
#[derive(Clone)]
pub struct HandlerCtx {
    pub tls_acceptor: tokio_rustls::TlsAcceptor,
    pub obfs4_listener: Arc<Obfs4Listener>,
    pub upstream: String,
    pub upstream_tls: Option<Arc<rustls::ClientConfig>>,
    pub wt_cache: Arc<WtTokenCache>,
    pub auth_fail: AuthFailTable,
    pub trusted_proxies: Arc<Vec<(std::net::IpAddr, u8)>>,
    pub label: String,
}

/// Set TCP keepalive on `stream` so OS-level probes prevent NAT/HAProxy from
/// treating the connection as idle during silent gRPC periods.
///
/// Uses 15 s idle delay + 5 s probe interval so the first keepalive probe fires
/// well before HAProxy's configured timeout.  SAFETY: the raw fd is only borrowed
/// for the setsockopt call; `mem::forget` prevents socket2 from closing it.
#[cfg(unix)]
pub fn apply_tcp_keepalive(stream: &TcpStream) {
    use std::os::fd::{AsRawFd, FromRawFd};
    let ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(15))
        .with_interval(std::time::Duration::from_secs(5));
    #[cfg(target_os = "linux")]
    let ka = ka.with_retries(3);
    // SAFETY: fd is valid and still owned by `stream`. We forget the Socket so
    // socket2's Drop impl doesn't close the same fd a second time.
    let socket = unsafe { socket2::Socket::from_raw_fd(stream.as_raw_fd()) };
    if let Err(e) = socket.set_tcp_keepalive(&ka) {
        warn!("set_tcp_keepalive failed: {}", e);
    }
    std::mem::forget(socket);
}

/// Handle a single incoming TLS stream: peek the first byte to decide between
/// WebTunnel (HTTP GET → WebSocket) and obfs4 (encrypted transport).
pub async fn handle_incoming(tcp: TcpStream, peer: SocketAddr, ctx: &HandlerCtx) {
    let tls_stream =
        match tokio::time::timeout(TLS_ACCEPT_TIMEOUT, ctx.tls_acceptor.accept(tcp)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!("TLS handshake failed from {}: {}", peer, e);
                return;
            }
            Err(_) => {
                warn!("TLS handshake timed out from {}", peer);
                return;
            }
        };

    // Peek the first byte to distinguish WebTunnel (HTTP GET) from obfs4.
    // WebTunnel always opens with "GET /path HTTP/1.1\r\n..." → first byte is b'G'.
    // obfs4 sends random-looking bytes that never start with b'G' in practice,
    // but we fall back gracefully even if they do (obfs4 accept will just fail).
    let mut buffered = tokio::io::BufReader::with_capacity(8192, tls_stream);
    let first = match peek_first_byte(&mut buffered).await {
        Ok(b) => b,
        Err(e) => {
            warn!("peek failed from {}: {}", peer, e);
            return;
        }
    };

    if first == b'G' {
        // WebTunnel path: validate time-based auth token derived from bridge cert,
        // then perform WebSocket handshake and relay.
        info!("WebTunnel connection from {} ({})", peer, ctx.label);
        let valid_paths = ctx.wt_cache.get();

        // Peek at the HTTP request path without consuming the buffer.
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
            match WebTunnelServerStream::accept_validated(buffered, |p| {
                valid_paths.iter().any(|v| v == p)
            })
            .await
            {
                Ok(ws) => relay_conn(ws, peer, &ctx.upstream, &ctx.upstream_tls).await,
                Err(e) => warn!("WebTunnel handshake failed from {}: {}", peer, e),
            }
        } else {
            // Unknown path: delay then respond as a generic nginx server.
            if !is_trusted_proxy(peer.ip(), &ctx.trusted_proxies) {
                ctx.auth_fail.record_failure(peer.ip());
            }
            warn!(
                "WebTunnel auth rejected from {} — sending decoy response",
                peer
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            send_decoy_http_response(&mut buffered).await;
        }
    } else {
        // obfs4 path: existing encrypted transport
        match ctx.obfs4_listener.accept_stream(buffered).await {
            Ok(s) => relay_conn(s, peer, &ctx.upstream, &ctx.upstream_tls).await,
            Err(e) => {
                if !is_trusted_proxy(peer.ip(), &ctx.trusted_proxies) {
                    ctx.auth_fail.record_failure(peer.ip());
                }
                warn!("obfs4 handshake failed from {}: {}", peer, e);
            }
        }
    }
}

async fn peek_first_byte<S: AsyncRead + Unpin>(
    reader: &mut tokio::io::BufReader<S>,
) -> std::io::Result<u8> {
    use tokio::io::AsyncBufReadExt;
    let buf = reader.fill_buf().await?;
    buf.first()
        .copied()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty TLS stream"))
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
    const BODY: &[u8] = b"<html>\r\n\
<head><title>404 Not Found</title></head>\r\n\
<body>\r\n\
<center><h1>404 Not Found</h1></center>\r\n\
<hr><center>nginx</center>\r\n\
</body>\r\n\
</html>\r\n";
    let head = format!(
        "HTTP/1.1 404 Not Found\r\n\
Server: nginx\r\n\
Content-Type: text/html\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\r\n",
        BODY.len()
    );
    let stream = reader.get_mut();
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(BODY).await;
    let _ = stream.flush().await;
}

/// Connect to the upstream server and pipe traffic.  Optionally re-encrypt
/// with TLS if the upstream speaks HTTPS (the typical case for gRPC).
async fn relay_conn<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    peer: SocketAddr,
    upstream: &str,
    upstream_tls: &Option<Arc<rustls::ClientConfig>>,
) {
    let tcp = match tokio::net::TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => {
            error!("Upstream connect ({upstream}) for {peer}: {e}");
            return;
        }
    };
    #[cfg(unix)]
    apply_tcp_keepalive(&tcp);

    if let Some(tls_config) = upstream_tls {
        // Re-encrypt to upstream with TLS (required when UPSTREAM is a TLS port).
        // Correctly handles both IPv4 (host:port) and IPv6 ([host]:port) formats.
        let hostname = if upstream.starts_with('[') {
            upstream.split(']').next().unwrap_or(upstream)[1..].to_string()
        } else {
            upstream.split(':').next().unwrap_or(upstream).to_string()
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls_config));
        let server_name = match rustls::pki_types::ServerName::try_from(hostname.as_str()) {
            Ok(n) => n.to_owned(),
            Err(e) => {
                error!("Invalid upstream hostname '{hostname}': {e}");
                return;
            }
        };
        match connector.connect(server_name, tcp).await {
            Ok(tls_stream) => {
                info!("Relay {peer} → upstream {upstream} (TLS) connected");
                pipe(stream, tls_stream, peer).await;
            }
            Err(e) => error!("Upstream TLS handshake to {upstream} failed: {e}"),
        }
    } else {
        info!("Relay {peer} → upstream {upstream} (plain) connected");
        pipe(stream, tcp, peer).await;
    }
}

/// Bidirectional pipe between two read/write streams.  Exits cleanly when
/// either side closes the connection.
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
    matches!(
        e.kind(),
        ConnectionReset | BrokenPipe | ConnectionAborted | UnexpectedEof
    )
}
