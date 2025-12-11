// Health monitoring module for self-healing
//
// Provides heartbeat tracking and watchdog functionality to detect
// zombie states where the agent is connected but not processing messages.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Last successful heartbeat timestamp (Unix seconds)
static LAST_HEARTBEAT: AtomicU64 = AtomicU64::new(0);

/// Last activity timestamp (any message processed)
static LAST_ACTIVITY: AtomicU64 = AtomicU64::new(0);

/// Timeout for considering the agent unhealthy (no heartbeat response)
const HEARTBEAT_TIMEOUT_SECS: u64 = 120; // 2 minutes

/// Timeout for considering the agent stuck (no activity at all)
const ACTIVITY_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// Get current Unix timestamp in seconds
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Record a successful heartbeat (pong received from gateway)
pub fn record_heartbeat() {
    LAST_HEARTBEAT.store(now_secs(), Ordering::Relaxed);
    record_activity(); // Heartbeat is also activity
}

/// Record any activity (message processed)
pub fn record_activity() {
    LAST_ACTIVITY.store(now_secs(), Ordering::Relaxed);
}

/// Initialize health state (call on startup/reconnect)
pub fn init() {
    let now = now_secs();
    LAST_HEARTBEAT.store(now, Ordering::Relaxed);
    LAST_ACTIVITY.store(now, Ordering::Relaxed);
}

/// Check if the agent is healthy based on heartbeat responses
pub fn is_heartbeat_healthy() -> bool {
    let last = LAST_HEARTBEAT.load(Ordering::Relaxed);
    if last == 0 {
        return true; // Not yet initialized, assume healthy
    }
    now_secs() - last < HEARTBEAT_TIMEOUT_SECS
}

/// Check if the agent has recent activity
pub fn is_active() -> bool {
    let last = LAST_ACTIVITY.load(Ordering::Relaxed);
    if last == 0 {
        return true; // Not yet initialized, assume active
    }
    now_secs() - last < ACTIVITY_TIMEOUT_SECS
}

/// Overall health check
pub fn is_healthy() -> bool {
    is_heartbeat_healthy() && is_active()
}

/// Get health status as a string for diagnostics
pub fn health_status() -> String {
    let now = now_secs();
    let last_hb = LAST_HEARTBEAT.load(Ordering::Relaxed);
    let last_act = LAST_ACTIVITY.load(Ordering::Relaxed);
    
    format!(
        "heartbeat: {}s ago (timeout: {}s), activity: {}s ago (timeout: {}s), healthy: {}",
        if last_hb > 0 { now - last_hb } else { 0 },
        HEARTBEAT_TIMEOUT_SECS,
        if last_act > 0 { now - last_act } else { 0 },
        ACTIVITY_TIMEOUT_SECS,
        is_healthy()
    )
}

/// Spawn a watchdog thread that exits the process if unhealthy
/// 
/// This allows systemd/launchd to restart the agent when it becomes
/// unresponsive. The watchdog checks health every 60 seconds.
pub fn spawn_watchdog() {
    std::thread::spawn(|| {
        // Wait a bit before first check to allow startup
        std::thread::sleep(Duration::from_secs(60));
        
        let mut consecutive_failures = 0;
        const MAX_FAILURES: u32 = 3; // Exit after 3 consecutive failures
        
        loop {
            std::thread::sleep(Duration::from_secs(60));
            
            if is_healthy() {
                consecutive_failures = 0;
                tracing::debug!("Health check passed: {}", health_status());
            } else {
                consecutive_failures += 1;
                tracing::warn!(
                    "Health check failed ({}/{}): {}",
                    consecutive_failures,
                    MAX_FAILURES,
                    health_status()
                );
                
                if consecutive_failures >= MAX_FAILURES {
                    tracing::error!(
                        "Health check failed {} times consecutively, forcing restart",
                        MAX_FAILURES
                    );
                    // Exit with non-zero code so service manager restarts us
                    std::process::exit(1);
                }
            }
        }
    });
    
    tracing::info!("Health watchdog started (timeout: {}s heartbeat, {}s activity)",
        HEARTBEAT_TIMEOUT_SECS, ACTIVITY_TIMEOUT_SECS);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_init() {
        init();
        assert!(is_healthy());
        assert!(is_heartbeat_healthy());
        assert!(is_active());
    }

    #[test]
    fn test_record_heartbeat() {
        init();
        record_heartbeat();
        assert!(is_heartbeat_healthy());
    }

    #[test]
    fn test_health_status_format() {
        init();
        let status = health_status();
        assert!(status.contains("heartbeat:"));
        assert!(status.contains("healthy: true"));
    }
}
