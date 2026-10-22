use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_HISTORY_PER_IP: usize = 32;

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

/// Lock-free, concurrent session tracking engine across all ingress IPs.
pub struct SessionTracker {
    sessions: DashMap<IpAddr, IpSession>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Records incoming request metadata and returns (request_count, inter_arrival_ms).
    pub fn track_request(
        &self,
        ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        user_agent: Option<&str>,
        payload_size: usize,
    ) -> (u64, Option<u64>) {
        let mut entry = self.sessions.entry(ip).or_insert_with(|| IpSession::new(ip));
        entry.record_request(
            method.to_string(),
            path.to_string(),
            query.map(|q| q.to_string()),
            user_agent.map(|ua| ua.to_string()),
            payload_size,
        )
    }

    /// Records the HTTP status code returned to this IP.
    pub fn track_response(&self, ip: IpAddr, status_code: u16) {
        if let Some(entry) = self.sessions.get(&ip) {
            entry.record_response(status_code);
        }
    }

    /// Retrieves a snapshot of the recent history for an IP.
    pub fn get_recent_history(&self, ip: &IpAddr) -> Vec<RequestSnapshot> {
        if let Some(entry) = self.sessions.get(ip) {
            entry.history.read().iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Active session count in memory.
    pub fn active_sessions_count(&self) -> usize {
        self.sessions.len()
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
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_tracker_basic() {
        let tracker = SessionTracker::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        let (count1, delta1) = tracker.track_request(ip, "GET", "/index.html", None, Some("test-ua"), 0);
        assert_eq!(count1, 1);
        assert!(delta1.is_none() || delta1.unwrap() < 100);

        tracker.track_response(ip, 200);

        let (count2, delta2) = tracker.track_request(ip, "POST", "/api/login", None, Some("test-ua"), 45);
        assert_eq!(count2, 2);
        assert!(delta2.is_some());

        let history = tracker.get_recent_history(&ip);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].response_status, Some(200));
        assert_eq!(history[1].method, "POST");
    }
}
