use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, warn};

use crate::config::{
    AUTH_FAIL_CLEANUP_INTERVAL, AUTH_FAIL_COOLDOWN, AUTH_FAIL_ENTRY_TTL, AUTH_FAIL_THRESHOLD,
};

// ---------------------------------------------------------------------------
// Per-IP connection limiter (RAII guard)
// ---------------------------------------------------------------------------

pub type ConnTable = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// RAII guard that decrements the per-IP counter when the connection ends.
pub struct ConnGuard {
    ip: IpAddr,
    table: ConnTable,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut t = self.table.lock().unwrap();
        match t.get_mut(&self.ip) {
            Some(n) if *n <= 1 => {
                t.remove(&self.ip);
            }
            Some(n) => {
                *n -= 1;
            }
            None => {}
        }
    }
}

/// Try to acquire a connection slot for `ip`.  Returns `None` if the limit is reached.
pub fn try_acquire(table: &ConnTable, ip: IpAddr, max: usize) -> Option<ConnGuard> {
    let mut t = table.lock().unwrap();
    let count = t.entry(ip).or_insert(0);
    if *count >= max {
        return None;
    }
    *count += 1;
    Some(ConnGuard {
        ip,
        table: Arc::clone(table),
    })
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

struct FailEntry {
    /// When this entry was first created (used for TTL-based cleanup).
    created_at: Instant,
    /// Cumulative auth failure count since the entry was created / last reset.
    count: usize,
    /// If Some, the IP is blocked until this instant.
    cooldown_until: Option<Instant>,
}

impl Default for FailEntry {
    fn default() -> Self {
        Self {
            created_at: Instant::now(),
            count: 0,
            cooldown_until: None,
        }
    }
}

#[derive(Clone)]
pub struct AuthFailTable(Arc<Mutex<HashMap<IpAddr, FailEntry>>>);

impl AuthFailTable {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    /// Purge entries that have either expired their cooldown or are stale
    /// (below threshold and older than AUTH_FAIL_ENTRY_TTL).
    fn cleanup(&self) {
        let mut map = self.0.lock().unwrap();
        let before = map.len();
        let now = Instant::now();
        map.retain(|_, e| {
            // Cooldown expired → remove.
            if let Some(until) = e.cooldown_until {
                return now < until;
            }
            // Below threshold but entry is old → remove (prevents unbounded growth
            // under slow distributed probing with unique source IPs).
            now.duration_since(e.created_at) < AUTH_FAIL_ENTRY_TTL
        });
        let removed = before.saturating_sub(map.len());
        if removed > 0 {
            debug!("AuthFailTable cleanup: removed {removed} entries (remaining: {})", map.len());
        }
    }

    /// Spawn a background task that periodically calls `cleanup()`.
    pub fn spawn_cleanup_task(table: AuthFailTable) {
        tokio::spawn(async move {
            debug!("AuthFailTable cleanup task started (interval: {AUTH_FAIL_CLEANUP_INTERVAL:?})");
            let mut interval = tokio::time::interval(AUTH_FAIL_CLEANUP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                table.cleanup();
            }
        });
    }

    /// Returns `true` if the IP is currently in cooldown. Lazily evicts expired entries.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let mut map = self.0.lock().unwrap();
        let now = Instant::now();
        if let Some(e) = map.get_mut(&ip) {
            if let Some(until) = e.cooldown_until {
                if now < until {
                    debug!("AuthFailTable: {ip} is blocked (cooldown expires in {}s)",
                        (until - now).as_secs());
                    return true;
                }
                debug!("AuthFailTable: {ip} cooldown expired — resetting counter (was {} failures)", e.count);
                map.remove(&ip); // cooldown expired — reset counter
            }
        }
        false
    }

    /// Record an auth failure for `ip`. Logs a warning if cooldown is newly triggered.
    pub fn record_failure(&self, ip: IpAddr) {
        let newly_blocked;
        {
            let mut map = self.0.lock().unwrap();
            let now = Instant::now();
            let e = map.entry(ip).or_insert_with(|| FailEntry {
                created_at: Instant::now(),
                ..Default::default()
            });
            e.count += 1;
            if e.count >= AUTH_FAIL_THRESHOLD && e.cooldown_until.is_none() {
                e.cooldown_until = Some(now + AUTH_FAIL_COOLDOWN);
                newly_blocked = true;
            } else {
                newly_blocked = false;
            }
            if !newly_blocked {
                debug!("AuthFailTable: {ip} failure #{count} (threshold: {AUTH_FAIL_THRESHOLD})", count = e.count);
            }
        }
        if newly_blocked {
            warn!(
                "Auth-fail threshold ({AUTH_FAIL_THRESHOLD} failures) reached for {ip} — \
                 dropping new connections for {}h",
                AUTH_FAIL_COOLDOWN.as_secs() / 3600,
            );
        }
    }
}
