use std::net::IpAddr;
use std::time::Duration;

// ── Defaults ────────────────────────────────────────────────────────────────

pub const DEFAULT_LISTEN: &str = "0.0.0.0:443";
pub const DEFAULT_STATE: &str = "/data";
pub const DEFAULT_SNI: &str = "storage.yandexcloud.net";
/// Neutral WebSocket path that looks like a generic API endpoint.
/// Override with WT_PATH env var on the relay.  Avoid service-identifying
/// names — this path appears in HTTP Upgrade requests and is DPI-visible.
pub const DEFAULT_WT_PATH: &str = "/api/stream";
/// Secondary listener port for direct TLS+obfs4 connections that bypass CDN.
pub const DEFAULT_ALT_LISTEN: &str = "";

// ── Limits & timeouts ───────────────────────────────────────────────────────

/// Maximum total concurrent connections across all IPs (global DoS guard).
pub const MAX_GLOBAL_CONNECTIONS: usize = 2048;

/// TLS handshake timeout.
pub const TLS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Each auth period is 5 minutes. We accept current ± 1 period (±5 min clock drift).
pub const AUTH_PERIOD_SECS: u64 = 300;

/// Default maximum concurrent connections per IP if MAX_CONNS_PER_IP env var is not set.
/// HTTP/2 keepalive + happy-eyeballs dual-relay probing + WebTunnel pre-probe means a
/// single legitimate client can hold 6–12 simultaneous connections.
pub const DEFAULT_MAX_CONNS_PER_IP: usize = 24;

// ── Auth-fail rate limiter config ───────────────────────────────────────────

/// Number of auth failures before an IP enters cooldown.
pub const AUTH_FAIL_THRESHOLD: usize = 3;

/// How long a blocked IP stays in cooldown.
pub const AUTH_FAIL_COOLDOWN: Duration = Duration::from_secs(86_400); // 24 h

/// Interval for background cleanup of expired AuthFailTable entries.
pub const AUTH_FAIL_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// TTL for AuthFailTable entries that never reached the threshold.
pub const AUTH_FAIL_ENTRY_TTL: Duration = Duration::from_secs(86_400); // 24 h

// ── WebTunnel token cache ───────────────────────────────────────────────────

/// How often to refresh the cached WebTunnel token set.
/// Tokens change every 5 min; refreshing every 2.5 min ensures overlap coverage.
pub const WT_TOKEN_REFRESH_INTERVAL: Duration = Duration::from_secs(150);

// ── Trusted proxy IP ranges ─────────────────────────────────────────────────
//
// When the relay runs behind a local L4 proxy (e.g. nginx stream block, Docker
// network bridge), all TCP connections appear to originate from the proxy's IP.
// Rate-limit and per-IP conn tracking by source IP is useless and harmful —
// a single failed auth attempt from any real client can trigger a 24 h ban
// that blocks ALL subsequent clients going through the same proxy IP.
//
// Set TRUSTED_PROXIES to a comma-separated list of IPs or CIDRs that should
// be exempt from auth-fail rate-limiting and per-IP connection limits.

pub fn parse_trusted_proxies(raw: &str) -> Vec<(IpAddr, u8)> {
    raw.split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            if let Some((ip_part, prefix_part)) = s.split_once('/') {
                let ip: IpAddr = ip_part.trim().parse().ok()?;
                let prefix: u8 = prefix_part.trim().parse().ok()?;
                Some((ip, prefix))
            } else {
                let ip: IpAddr = s.parse().ok()?;
                let prefix = match ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                Some((ip, prefix))
            }
        })
        .collect()
}

pub fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix == 0 {
                return true;
            }
            if prefix >= 32 {
                return ip == net;
            }
            let mask = !0u32 << (32 - prefix);
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix == 0 {
                return true;
            }
            if prefix >= 128 {
                return ip == net;
            }
            let mask = !0u128 << (128 - prefix);
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

pub fn is_trusted_proxy(ip: IpAddr, proxies: &[(IpAddr, u8)]) -> bool {
    proxies
        .iter()
        .any(|&(net, prefix)| ip_in_cidr(ip, net, prefix))
}
