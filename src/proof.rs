use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

const DEFAULT_MAX_SEGMENT_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

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

/// Thread-safe ProofLogger maintaining an immutable SHA-256 hash chain with automated rotation.
pub struct ProofLogger {
    log_path: PathBuf,
    max_segment_bytes: u64,
    state: Mutex<ProofState>,
}

struct ProofState {
    prev_hash: String,
    counter: u64,
}

impl ProofLogger {
    pub fn new(log_path: PathBuf, seed_hash: Option<String>, max_segment_bytes: Option<u64>) -> Self {
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let seed = seed_hash.unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });

        Self {
            log_path,
            max_segment_bytes: max_segment_bytes.unwrap_or(DEFAULT_MAX_SEGMENT_BYTES),
            state: Mutex::new(ProofState {
                prev_hash: seed,
                counter: 0,
            }),
        }
    }

    /// Appends a new security event to the tamper-evident proof chain with automatic rotation.
    pub fn log_event(
        &self,
        event_type: &str,
        ip: &str,
        details: serde_json::Value,
    ) -> Result<ProofRecord, String> {
        let mut state = self.state.lock().map_err(|e| e.to_string())?;

        // 1. Check if log rotation is required
        self.check_and_rotate(&mut state)?;

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

    /// Rotates the proof log file if size exceeds threshold, preserving cryptographic hash continuity.
    fn check_and_rotate(&self, state: &mut ProofState) -> Result<(), String> {
        if let Ok(metadata) = std::fs::metadata(&self.log_path) {
            if metadata.len() >= self.max_segment_bytes {
                let rot_timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
                let rotated_name = format!("{}.{}.jsonl", self.log_path.display(), rot_timestamp);

                // Rename existing log to archive segment
                std::fs::rename(&self.log_path, &rotated_name).map_err(|e| e.to_string())?;

                // Emit rotation seal event into the newly created log segment
                let prev_hash = state.prev_hash.clone();
                let counter = state.counter;
                let timestamp = Utc::now().to_rfc3339();

                let mut seal_map = serde_json::Map::new();
                seal_map.insert("counter".to_string(), serde_json::json!(counter));
                seal_map.insert("prev_hash".to_string(), serde_json::json!(prev_hash));
                seal_map.insert("timestamp".to_string(), serde_json::json!(timestamp));
                seal_map.insert("event_type".to_string(), serde_json::json!("PROOF_SEGMENT_SEAL"));
                seal_map.insert("ip".to_string(), serde_json::json!("127.0.0.1"));
                seal_map.insert(
                    "payload_summary".to_string(),
                    serde_json::json!({
                        "previous_segment": rotated_name,
                        "action": "continuous_chain_rotation",
                    }),
                );

                let canonical = serde_json::to_string(&seal_map).map_err(|e| e.to_string())?;
                let mut hasher = Sha256::new();
                hasher.update(prev_hash.as_bytes());
                hasher.update(canonical.as_bytes());
                let entry_hash = format!("{:x}", hasher.finalize());

                seal_map.insert("entry_hash".to_string(), serde_json::json!(entry_hash));

                let mut new_file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&self.log_path)
                    .map_err(|e| e.to_string())?;

                let serialized = serde_json::to_string(&seal_map).map_err(|e| e.to_string())?;
                writeln!(new_file, "{}", serialized).map_err(|e| e.to_string())?;

                state.prev_hash = entry_hash;
                state.counter += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_logger_chain_integrity() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let logger = ProofLogger::new(tmp.path().to_path_buf(), None, None);

        let rec1 = logger
            .log_event("TEST_EVENT_1", "10.0.0.1", serde_json::json!({"action": "probe"}))
            .unwrap();
        assert_eq!(rec1.counter, 0);

        let rec2 = logger
            .log_event("TEST_EVENT_2", "10.0.0.1", serde_json::json!({"action": "blocked"}))
            .unwrap();
        assert_eq!(rec2.counter, 1);
        assert_eq!(rec2.prev_hash, rec1.entry_hash);

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_proof_logger_automatic_rotation_preserves_continuity() {
        let dir = tempfile::tempdir().unwrap();
        let log_file = dir.path().join("proof.jsonl");

        // Small threshold to force rotation after first event (300 bytes)
        let logger = ProofLogger::new(log_file.clone(), None, Some(300));

        let _rec1 = logger
            .log_event("EVENT_A", "10.0.0.1", serde_json::json!({"data": "payload_1"}))
            .unwrap();

        // This second event will trigger rotation before writing
        let rec2 = logger
            .log_event("EVENT_B", "10.0.0.1", serde_json::json!({"data": "payload_2"}))
            .unwrap();

        // Check that rotated segment exists
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 2); // original active file + 1 rotated segment

        // rec2 must be part of continuous counter
        assert_eq!(rec2.counter, 2); // 0 (rec1), 1 (seal), 2 (rec2)
    }
}
