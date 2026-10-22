use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadarConfig {
    pub bind_addr: SocketAddr,
    pub upstream_addr: Option<SocketAddr>,
    pub proof_log_path: PathBuf,
    pub max_session_idle_secs: u64,
    pub enable_honey_tokens: bool,
}

impl Default for RadarConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            upstream_addr: None,
            proof_log_path: PathBuf::from("/var/log/jfp/asa_radar_proof.jsonl"),
            max_session_idle_secs: 300,
            enable_honey_tokens: true,
        }
    }
}
