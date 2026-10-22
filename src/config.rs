use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadarConfig {
    pub bind_addr: SocketAddr,
    pub upstream_addr: Option<SocketAddr>,
    pub proof_log_path: PathBuf,
    pub proof_log_max_bytes: u64,
    pub max_session_idle_secs: u64,
    pub max_sessions_capacity: usize,
    pub enable_honey_tokens: bool,
    pub dry_run: bool,
    pub enable_os_firewall_drop: bool,
    pub ban_ttl_secs: u64,
    pub tarpit_drip_interval_ms: u64,
    pub max_tarpit_concurrency: usize,
    pub trusted_proxies: Vec<String>,
}

impl Default for RadarConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            upstream_addr: None,
            proof_log_path: PathBuf::from("/var/log/jfp/asa_radar_proof.jsonl"),
            proof_log_max_bytes: 10 * 1024 * 1024, // 10 MB
            max_session_idle_secs: 300,
            max_sessions_capacity: 131_072, // 128k bounded sessions limit
            enable_honey_tokens: true,
            dry_run: false,
            enable_os_firewall_drop: false,
            ban_ttl_secs: 3600,            // 1 hour ban TTL
            tarpit_drip_interval_ms: 3000, // 1 byte every 3 seconds
            max_tarpit_concurrency: 512,   // Max 512 active Tarpit file descriptors
            trusted_proxies: Vec::new(),
        }
    }
}
