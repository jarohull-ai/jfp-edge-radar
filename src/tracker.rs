use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_HISTORY_PER_IP: usize = 32;
const DEFAULT_MAX_SESSIONS: usize = 131_072; // 128k bounded sessions

/// Normalizes an IP for tracking: aggregates IPv6 to /64 subnet to neutralize rotating-host state floods.
pub fn canonicalize_tracking_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // Retain top 64 bits (4 segments of 16 bits), zero out bottom 64 host bits
            let masked = std::net::Ipv6Addr::new(segs[0], segs[1], segs[2], segs[3], 0, 0, 0, 0);
            IpAddr::V6(masked)
        }
    }
}

/// Snapshot of an individual HTTP request for behavioral analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSnapshot {
    pub timestamp_utc: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub user_agent: Option<String>,
    pub payload_size: usize,
    pub response_status: Option<u16>,
    /// Time delta (in milliseconds) since previous request from the same IP
    pub delta_prev_ms: Option<u64>,
}

/// In-memory state tracking for an external IP session.
pub struct IpSession {
    pub ip: IpAddr,
    pub first_seen_instant: Instant,
    pub last_seen_instant: Instant,
    pub total_requests: AtomicU64,
    pub error_responses: AtomicU64,
    pub history: parking_lot::RwLock<VecDeque<RequestSnapshot>>,
    pub threat_score: parking_lot::RwLock<f64>,
    pub flags: parking_lot::RwLock<Vec<String>>,
}

impl IpSession {
    pub fn new(ip: IpAddr) -> Self {
        let now = Instant::now();
        Self {
            ip,
            first_seen_instant: now,
            last_seen_instant: now,
            total_requests: AtomicU64::new(0),
            error_responses: AtomicU64::new(0),
            history: parking_lot::RwLock::new(VecDeque::with_capacity(MAX_HISTORY_PER_IP)),
            threat_score: parking_lot::RwLock::new(0.0),
            flags: parking_lot::RwLock::new(Vec::new()),
        }
    }

    pub fn record_request(
        &mut self,
        method: String,
        path: String,
        query: Option<String>,
        user_agent: Option<String>,
        payload_size: usize,
    ) -> (u64, Option<u64>) {
        let now_instant = Instant::now();
        let delta_ms = now_instant
            .checked_duration_since(self.last_seen_instant)
            .map(|d| d.as_millis() as u64);
        self.last_seen_instant = now_instant;

        let total = self.total_requests.fetch_add(1, Ordering::SeqCst) + 1;

        let snapshot = RequestSnapshot {
            timestamp_utc: Utc::now().to_rfc3339(),
            method,
            path,
            query,
            user_agent,
            payload_size,
            response_status: None,
            delta_prev_ms: delta_ms,
        };

        {
            let mut hist = self.history.write();
            if hist.len() >= MAX_HISTORY_PER_IP {
                hist.pop_front();
            }
            hist.push_back(snapshot);
        }

        (total, delta_ms)
    }

    pub fn record_response(&self, status: u16) {
        if status >= 400 {
            self.error_responses.fetch_add(1, Ordering::SeqCst);
        }

        let mut hist = self.history.write();
        if let Some(last) = hist.back_mut() {
            last.response_status = Some(status);
        }
    }
}

/// Lock-free, bounded session tracking engine with IPv6 aggregation and anti-flooding eviction.
pub struct SessionTracker {
    sessions: DashMap<IpAddr, IpSession>,
    max_sessions: usize,
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionTracker {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_SESSIONS)
    }

    pub fn with_capacity(max_sessions: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            max_sessions,
        }
    }

    /// Records incoming request metadata and returns (request_count, inter_arrival_ms).
    /// Automatically applies IPv6 subnet aggregation and state bounding eviction.
    pub fn track_request(
        &self,
        raw_ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        user_agent: Option<&str>,
        payload_size: usize,
    ) -> (u64, Option<u64>) {
        let tracking_ip = canonicalize_tracking_ip(raw_ip);

        // State Bounding: prevent Memory Exhaustion DoS
        if self.sessions.len() >= self.max_sessions {
            self.evict_pressure();
        }

        let mut entry = self
            .sessions
            .entry(tracking_ip)
            .or_insert_with(|| IpSession::new(tracking_ip));
        entry.record_request(
            method.to_string(),
            path.to_string(),
            query.map(|q| q.to_string()),
            user_agent.map(|ua| ua.to_string()),
            payload_size,
        )
    }

    /// Records the HTTP status code returned to this IP.
    pub fn track_response(&self, raw_ip: IpAddr, status_code: u16) {
        let tracking_ip = canonicalize_tracking_ip(raw_ip);
        if let Some(entry) = self.sessions.get(&tracking_ip) {
            entry.record_response(status_code);
        }
    }

    /// Retrieves a snapshot of the recent history for an IP.
    pub fn get_recent_history(&self, raw_ip: &IpAddr) -> Vec<RequestSnapshot> {
        let tracking_ip = canonicalize_tracking_ip(*raw_ip);
        if let Some(entry) = self.sessions.get(&tracking_ip) {
            entry.history.read().iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Active session count in memory.
    pub fn active_sessions_count(&self) -> usize {
        self.sessions.len()
    }

    /// Evicts one-hit scanner sessions when memory table reaches saturation.
    fn evict_pressure(&self) {
        // Pass 1: Prune all one-hit sessions (total_requests <= 1)
        let before = self.sessions.len();
        self.sessions
            .retain(|_, s| s.total_requests.load(Ordering::Relaxed) > 1);
        let after_pass1 = self.sessions.len();

        // Pass 2: If still overflowing, aggressively evict older 25% of sessions
        if after_pass1 >= self.max_sessions {
            let now = Instant::now();
            self.sessions
                .retain(|_, s| now.duration_since(s.last_seen_instant) < Duration::from_secs(60));
        }

        tracing::info!(
            "STATE FLOODING SHIELD: Evicted {} stale/one-hit sessions to protect system memory",
            before - self.sessions.len()
        );
    }

    /// Evicts expired sessions exceeding TTL.
    pub fn prune_stale_sessions(&self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let mut evicted = 0;
        self.sessions.retain(|_, session| {
            let keep = now.duration_since(session.last_seen_instant) < max_idle;
            if !keep {
                evicted += 1;
            }
            keep
        });
        evicted
    }

    /// Returns the current number of active tracked sessions in memory.
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_subnet_aggregation() {
        let ip1: IpAddr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap();
        let ip2: IpAddr = "2001:0db8:85a3:0000:ffff:ffff:ffff:ffff".parse().unwrap();

        let canon1 = canonicalize_tracking_ip(ip1);
        let canon2 = canonicalize_tracking_ip(ip2);

        // Must map to exact same /64 subnet prefix
        assert_eq!(canon1, canon2);
        assert_eq!(canon1.to_string(), "2001:db8:85a3::");
    }

    #[test]
    fn test_bounded_state_evicts_one_hit_scanners() {
        let tracker = SessionTracker::with_capacity(3);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();

        // ip1 makes 2 requests
        tracker.track_request(ip1, "GET", "/", None, None, 0);
        tracker.track_request(ip1, "GET", "/api", None, None, 0);

        // ip2 and ip3 are one-hit scanners
        tracker.track_request(ip2, "GET", "/", None, None, 0);
        tracker.track_request(ip3, "GET", "/", None, None, 0);
        assert_eq!(tracker.active_sessions_count(), 3);

        // Adding 4th exceeds max_sessions (3) -> triggers evict_pressure()
        let ip4: IpAddr = "192.168.1.4".parse().unwrap();
        tracker.track_request(ip4, "GET", "/", None, None, 0);

        // One-hit scanners (ip2 and ip3) were dropped; ip1 and ip4 survived
        assert!(tracker
            .sessions
            .contains_key(&canonicalize_tracking_ip(ip1)));
        assert!(tracker
            .sessions
            .contains_key(&canonicalize_tracking_ip(ip4)));
        assert!(!tracker
            .sessions
            .contains_key(&canonicalize_tracking_ip(ip2)));
    }
}
