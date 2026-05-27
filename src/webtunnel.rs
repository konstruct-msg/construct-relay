use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use crate::config::{AUTH_PERIOD_SECS, WT_TOKEN_REFRESH_INTERVAL};

/// Compute a WebTunnel path auth token for a given time period.
///
/// Both the relay and the iOS client derive the token identically:
///   `SHA-256( bridge_cert_base64_string || "webtunnel-v1" || period_u64_be )[:8]`
/// encoded as 16 lowercase hex characters.  The `bridge_cert` string is the
/// `cert=...` value from the relay's obfs4 bridge line — available to clients
/// via the relay manifest they download at startup.
pub fn webtunnel_token(bridge_cert: &str, period: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bridge_cert.as_bytes());
    h.update(b"webtunnel-v1");
    h.update(period.to_be_bytes());
    hex::encode(&h.finalize()[..8])
}

/// Return the set of valid authenticated WebTunnel paths for a given period.
/// Includes period-1, period, period+1 to tolerate up to 5 minutes of clock drift.
pub fn valid_wt_paths_at(bridge_cert: &str, base_path: &str, period: u64) -> Vec<String> {
    [period.saturating_sub(1), period, period + 1]
        .iter()
        .map(|&p| format!("{base_path}/{}", webtunnel_token(bridge_cert, p)))
        .collect()
}

/// Compute the current auth period, logging a warning if the system clock
/// is clearly wrong (before 2025-01-01).
pub fn current_auth_period() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    const MIN_REASONABLE_TIMESTAMP: u64 = 1_735_689_600; // 2025-01-01 00:00 UTC
    if now < MIN_REASONABLE_TIMESTAMP {
        warn!(
            "System clock appears incorrect (epoch {} = {}). \
             WebTunnel auth tokens may not work.",
            now, now
        );
    }
    now / AUTH_PERIOD_SECS
}

// ---------------------------------------------------------------------------
// Cached WebTunnel token set (refreshed every 2.5 min)
// ---------------------------------------------------------------------------

pub struct WtTokenCache {
    /// Arc-swapped list of valid paths.  Reads are lock-free.
    paths: Arc<std::sync::RwLock<Vec<String>>>,
}

impl WtTokenCache {
    pub fn new(bridge_cert: &str, base_path: &str) -> Self {
        let period = current_auth_period();
        let paths = valid_wt_paths_at(bridge_cert, base_path, period);
        Self {
            paths: Arc::new(std::sync::RwLock::new(paths)),
        }
    }

    pub fn get(&self) -> Vec<String> {
        self.paths.read().unwrap().clone()
    }

    pub fn refresh(&self, bridge_cert: &str, base_path: &str) {
        let period = current_auth_period();
        let paths = valid_wt_paths_at(bridge_cert, base_path, period);
        let mut w = self.paths.write().unwrap();
        debug!("WtTokenCache refreshed for period {period} (paths: {paths:?})");
        *w = paths;
    }

    pub fn spawn_refresh_task(cache: Arc<WtTokenCache>, bridge_cert: String, base_path: String) {
        tokio::spawn(async move {
            debug!("WtTokenCache refresh task started (interval: {WT_TOKEN_REFRESH_INTERVAL:?})");
            let mut interval = tokio::time::interval(WT_TOKEN_REFRESH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                cache.refresh(&bridge_cert, &base_path);
            }
        });
    }
}
