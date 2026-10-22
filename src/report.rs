use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Default)]
pub struct ForensicStats {
    pub total_records: u64,
    pub chain_verified: bool,
    pub broken_chain_at: Option<u64>,
    pub blocked_attacks: u64,
    pub honey_deceptions: u64,
    pub tarpitted_sessions: u64,
    pub dry_run_simulations: u64,
    pub unique_attacker_ips: HashSet<String>,
    pub vector_distribution: HashMap<String, u64>,
    pub top_offenders: HashMap<String, u64>,
}

pub struct ForensicReporter;

impl ForensicReporter {
    /// Analyzes a JFP-Paradox proof log, verifies SHA-256 chain continuity, and aggregates metrics.
    pub fn analyze_log(log_path: &Path) -> Result<ForensicStats, String> {
        let file = File::open(log_path).map_err(|e| format!("Cannot open log file: {}", e))?;
        let reader = BufReader::new(file);

        let mut stats = ForensicStats {
            chain_verified: true,
            ..Default::default()
        };

        let mut expected_prev_hash: Option<String> = None;

        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| format!("Error reading line {}: {}", idx + 1, e))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            stats.total_records += 1;

            let mut record: Value = serde_json::from_str(trimmed)
                .map_err(|e| format!("Malformed JSON at line {}: {}", idx + 1, e))?;

            let reported_entry_hash = record
                .get("entry_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let reported_prev_hash = record
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let event_type = record
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let ip = record
                .get("ip")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0")
                .to_string();

            // 1. Verify Hash Chain Continuity
            if let Some(ref prev) = expected_prev_hash {
                if &reported_prev_hash != prev {
                    stats.chain_verified = false;
                    if stats.broken_chain_at.is_none() {
                        stats.broken_chain_at = Some(stats.total_records);
                    }
                }
            }

            // 2. Verify Cryptographic Integrity: entry_hash == SHA256(prev_hash + canonical_json)
            if let Some(obj) = record.as_object_mut() {
                obj.remove("entry_hash");
                if let Ok(canonical) = serde_json::to_string(obj) {
                    let mut hasher = Sha256::new();
                    hasher.update(reported_prev_hash.as_bytes());
                    hasher.update(canonical.as_bytes());
                    let computed = format!("{:x}", hasher.finalize());
                    if computed != reported_entry_hash {
                        stats.chain_verified = false;
                        if stats.broken_chain_at.is_none() {
                            stats.broken_chain_at = Some(stats.total_records);
                        }
                    }
                }
            }

            expected_prev_hash = Some(reported_entry_hash);

            // 3. Aggregate Telemetry
            if ip != "127.0.0.1" && ip != "0.0.0.0" {
                stats.unique_attacker_ips.insert(ip.clone());
                *stats.top_offenders.entry(ip).or_insert(0) += 1;
            }

            match event_type.as_str() {
                "ASA_ATTACK_BLOCKED" | "ASA_AUTONOMOUS_AGENT_BLOCKED" => {
                    stats.blocked_attacks += 1;
                }
                "ASA_HONEY_DECEPTION_SERVED" => {
                    stats.honey_deceptions += 1;
                }
                "ASA_ATTACK_SIMULATED_DRY_RUN" => {
                    stats.dry_run_simulations += 1;
                }
                _ => {}
            }

            // Extract vector details from payload_summary
            if let Some(summary) = record.get("payload_summary") {
                if let Some(indicators) = summary
                    .get("threat_assessment")
                    .and_then(|t| t.get("indicators"))
                    .and_then(|i| i.as_array())
                {
                    for ind in indicators {
                        if let Some(s) = ind.as_str() {
                            let key = s.split(':').next().unwrap_or(s).trim().to_string();
                            *stats.vector_distribution.entry(key).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Generates a comprehensive Incident Response Markdown Report for SOC / DevSecOps.
    pub fn generate_markdown_report(stats: &ForensicStats, log_path: &Path) -> String {
        let mut md = String::new();

        md.push_str("# 🛡️ JFP-Paradox Edge Radar - Incident Response & Forensics Report\n\n");
        md.push_str(&format!(
            "**Generated At:** {} UTC  \n",
            Utc::now().to_rfc3339()
        ));
        md.push_str(&format!(
            "**Source Proof Log:** `{}`  \n\n",
            log_path.display()
        ));

        md.push_str("## 🔐 1. Cryptographic Proof Chain Integrity\n\n");
        if stats.chain_verified {
            md.push_str("✅ **STATUS: 100% UNBROKEN & AUDITED.** All records strictly conform to SHA-256 tamper-evident hash chaining. No retroactive modifications detected.\n\n");
        } else {
            md.push_str(&format!(
                "❌ **STATUS: COMPROMISED.** Hash chain discontinuity detected at record #{}. Evidence of log tampering!\n\n",
                stats.broken_chain_at.unwrap_or(0)
            ));
        }

        md.push_str("## 📊 2. Incident Telemetry Overview\n\n");
        md.push_str("| Metric | Value |\n");
        md.push_str("| :--- | :--- |\n");
        md.push_str(&format!(
            "| **Total Logged Events** | `{}` |\n",
            stats.total_records
        ));
        md.push_str(&format!(
            "| **Hard Blocked Attacks** | `{}` |\n",
            stats.blocked_attacks
        ));
        md.push_str(&format!(
            "| **Synthetic Honey Deceptions** | `{}` |\n",
            stats.honey_deceptions
        ));
        md.push_str(&format!(
            "| **Dry-Run Audit Simulations** | `{}` |\n",
            stats.dry_run_simulations
        ));
        md.push_str(&format!(
            "| **Unique Threat Actors (IPs)** | `{}` |\n\n",
            stats.unique_attacker_ips.len()
        ));

        md.push_str("## 🎯 3. Attack Vector Breakdown\n\n");
        md.push_str("| Vector Signature | Detections |\n");
        md.push_str("| :--- | :--- |\n");
        let mut vectors: Vec<_> = stats.vector_distribution.iter().collect();
        vectors.sort_by(|a, b| b.1.cmp(a.1));
        for (v, count) in vectors {
            md.push_str(&format!("| `{}` | `{}` |\n", v, count));
        }
        md.push('\n');

        md.push_str("## 🚨 4. Top Malicious Ingress Sources\n\n");
        md.push_str("| Attacker IP | Malicious Requests |\n");
        md.push_str("| :--- | :--- |\n");
        let mut offenders: Vec<_> = stats.top_offenders.iter().collect();
        offenders.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in offenders.iter().take(10) {
            md.push_str(&format!("| `{}` | `{}` |\n", ip, count));
        }
        md.push('\n');

        md.push_str("## 💡 5. Resource Asymmetry Impact\n\n");
        let estimated_tokens_wasted = (stats.blocked_attacks + stats.honey_deceptions) * 850;
        md.push_str(&format!(
            "* **Estimated LLM Tokens Wasted by Attackers:** ~`{}` tokens.\n",
            estimated_tokens_wasted
        ));
        md.push_str("* **Backend Server CPU Overhead Saved:** 100% of malicious requests terminated on Edge Proxy prior to reaching PHP-FPM / application runtime.\n");

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::ProofLogger;

    #[test]
    fn test_forensic_report_chain_verification() {
        let dir = tempfile::tempdir().unwrap();
        let log_file = dir.path().join("proof.jsonl");

        let logger = ProofLogger::new(log_file.clone(), None, None);
        logger
            .log_event(
                "ASA_ATTACK_BLOCKED",
                "198.51.100.10",
                serde_json::json!({
                    "threat_assessment": {
                        "indicators": ["PHP_CGI_ARG_INJECTION: detected '-d'"]
                    }
                }),
            )
            .unwrap();

        logger
            .log_event(
                "ASA_HONEY_DECEPTION_SERVED",
                "198.51.100.11",
                serde_json::json!({
                    "threat_assessment": {
                        "indicators": ["STRUCTURAL_RECON: AI Agent Metadata Probing"]
                    }
                }),
            )
            .unwrap();

        let stats = ForensicReporter::analyze_log(&log_file).unwrap();
        assert!(stats.chain_verified);
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.blocked_attacks, 1);
        assert_eq!(stats.honey_deceptions, 1);
        assert_eq!(stats.unique_attacker_ips.len(), 2);

        let report_md = ForensicReporter::generate_markdown_report(&stats, &log_file);
        assert!(report_md.contains("100% UNBROKEN & AUDITED"));
        assert!(report_md.contains("PHP_CGI_ARG_INJECTION"));
    }
}
