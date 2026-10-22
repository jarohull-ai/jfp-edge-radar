use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Tamper-evident proof record adhering to JFP-Paradox cryptographic specifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRecord {
    pub counter: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub timestamp: String,
    pub event_type: String,
    pub ip: String,
    pub payload_summary: serde_json::Value,
}

/// Thread-safe ProofLogger maintaining an immutable SHA-256 hash chain on disk.
pub struct ProofLogger {
    log_path: PathBuf,
    state: Mutex<ProofState>,
}

struct ProofState {
    prev_hash: String,
    counter: u64,
}

impl ProofLogger {
    pub fn new(log_path: PathBuf, seed_hash: Option<String>) -> Self {
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let seed = seed_hash.unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });

        Self {
            log_path,
            state: Mutex::new(ProofState {
                prev_hash: seed,
                counter: 0,
            }),
        }
    }

    /// Appends a new security event to the tamper-evident proof chain.
    pub fn log_event(
        &self,
        event_type: &str,
        ip: &str,
        details: serde_json::Value,
    ) -> Result<ProofRecord, String> {
        let mut state = self.state.lock().map_err(|e| e.to_string())?;

        let timestamp = Utc::now().to_rfc3339();
        let counter = state.counter;
        let prev_hash = state.prev_hash.clone();

        let mut record_map = serde_json::Map::new();
        record_map.insert("counter".to_string(), serde_json::json!(counter));
        record_map.insert("prev_hash".to_string(), serde_json::json!(prev_hash));
        record_map.insert("timestamp".to_string(), serde_json::json!(timestamp));
        record_map.insert("event_type".to_string(), serde_json::json!(event_type));
        record_map.insert("ip".to_string(), serde_json::json!(ip));
        record_map.insert("payload_summary".to_string(), details.clone());

        let canonical_str = serde_json::to_string(&record_map).map_err(|e| e.to_string())?;

        // Cryptographic linking: entry_hash = SHA256(prev_hash + canonical_json)
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(canonical_str.as_bytes());
        let entry_hash = format!("{:x}", hasher.finalize());

        record_map.insert("entry_hash".to_string(), serde_json::json!(entry_hash));

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| e.to_string())?;

        let serialized = serde_json::to_string(&record_map).map_err(|e| e.to_string())?;
        writeln!(file, "{}", serialized).map_err(|e| e.to_string())?;

        state.prev_hash = entry_hash.clone();
        state.counter += 1;

        Ok(ProofRecord {
            counter,
            prev_hash,
            entry_hash,
            timestamp,
            event_type: event_type.to_string(),
            ip: ip.to_string(),
            payload_summary: details,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_logger_chain_integrity() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let logger = ProofLogger::new(tmp.path().to_path_buf(), None);

        let rec1 = logger.log_event("TEST_EVENT_1", "10.0.0.1", serde_json::json!({"action": "probe"})).unwrap();
        assert_eq!(rec1.counter, 0);

        let rec2 = logger.log_event("TEST_EVENT_2", "10.0.0.1", serde_json::json!({"action": "blocked"})).unwrap();
        assert_eq!(rec2.counter, 1);
        assert_eq!(rec2.prev_hash, rec1.entry_hash);

        // Verify file contains 2 lines
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
