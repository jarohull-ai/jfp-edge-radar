use crate::php_signatures::PhpSignatureEngine;
use crate::tracker::RequestSnapshot;
use serde::{Deserialize, Serialize};

/// Verdict returned by the deterministic ASA Analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub anomaly_score: f64,
    pub is_autonomous_agent: bool,
    pub indicators: Vec<String>,
    pub recommended_action: DefensiveAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefensiveAction {
    Allow,
    Tarpit(u64),  // Delay response by N ms to exhaust attacker's LLM tokens/context
    DeceiveHoney, // Return synthetic poisoned decoy (e.g., fake llms.txt or AGENTS.md)
    BlockProof,   // Immediate drop and proof-log entry
}

pub struct AsaAnalyzer;

impl AsaAnalyzer {
    /// Evaluates current request against past IP trajectory and PHP-2-Shell/OOM signatures.
    pub fn assess(
        current_path: &str,
        query: Option<&str>,
        headers: &[(String, String)],
        content_length: Option<usize>,
        delta_ms: Option<u64>,
        history: &[RequestSnapshot],
    ) -> ThreatAssessment {
        let mut score: f64 = 0.0;
        let mut indicators = Vec::new();

        // 1. Structural Reconnaissance Patterns (AI Agents)
        let path_lower = current_path.to_lowercase();
        if path_lower.contains("agents.md")
            || path_lower.contains("llms.txt")
            || path_lower.contains("ai-plugin.json")
            || path_lower.starts_with("/.well-known/agent")
        {
            score += 0.45;
            indicators.push("STRUCTURAL_RECON: AI Agent Metadata Probing".to_string());
        }

        // 2. PHP-2-Shell & OOM Exploit Heuristics (CVE-2026-109618 / CVE-2026-109619)
        let php_inspection =
            PhpSignatureEngine::inspect_request(current_path, query, headers, content_length);

        if php_inspection.is_suspicious {
            score += php_inspection.severity_score;
            indicators.extend(php_inspection.flags);
        }

        // 3. Mathematical Timing Analysis (LLM Think-Time Window)
        if let Some(dt) = delta_ms {
            // Autonomous agents typically exhibit a thinking window between 1200ms and 8500ms
            // when parsing tool responses / error reflections
            if (1200..=8500).contains(&dt) {
                score += 0.25;
                indicators.push(format!(
                    "TIMING_WINDOW: Delta {}ms fits LLM reflection loop",
                    dt
                ));
            } else if dt < 40 && history.len() >= 2 {
                score += 0.20;
                indicators.push(format!(
                    "TIMING_BURST: High-rate automated flood ({}ms)",
                    dt
                ));
            }
        }

        // 4. Adaptive Mutation Loop (Reflection on recent 4xx/5xx errors)
        if let Some(last) = history.last() {
            if let Some(status) = last.response_status {
                if status == 403 || status == 422 || status == 500 {
                    // Check if current request follows an error in the agent thinking window
                    if let Some(dt) = delta_ms {
                        if (1000..=10000).contains(&dt) {
                            score += 0.40;
                            indicators.push(format!(
                                "ADAPTIVE_MUTATION: Rapid retry after HTTP {} within {}ms thinking window",
                                status, dt
                            ));
                        }
                    }
                }
            }
        }

        // Action recommendation based on mathematical score gradient
        let action = if score >= 0.70 {
            DefensiveAction::BlockProof
        } else if score >= 0.45 {
            DefensiveAction::DeceiveHoney
        } else if score >= 0.30 {
            DefensiveAction::Tarpit(3000)
        } else {
            DefensiveAction::Allow
        };

        ThreatAssessment {
            anomaly_score: score.min(1.0),
            is_autonomous_agent: score >= 0.45,
            indicators,
            recommended_action: action,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structural_recon_detection() {
        let history = vec![];
        let assessment = AsaAnalyzer::assess(
            "/.well-known/agents/manifest.json",
            None,
            &[],
            None,
            Some(2500),
            &history,
        );
        assert!(assessment.is_autonomous_agent);
        assert!(assessment.anomaly_score >= 0.45);
        assert!(assessment
            .indicators
            .iter()
            .any(|i| i.contains("STRUCTURAL_RECON")));
    }

    #[test]
    fn test_php_cgi_argument_injection_blocked() {
        let history = vec![];
        let headers = vec![(
            "PHP_VALUE".to_string(),
            "auto_prepend_file=php://input".to_string(),
        )];
        let assessment = AsaAnalyzer::assess(
            "/index.php",
            Some("-d+allow_url_include=on"),
            &headers,
            None,
            None,
            &history,
        );
        assert_eq!(assessment.recommended_action, DefensiveAction::BlockProof);
        assert!(assessment.anomaly_score >= 0.80);
        assert!(assessment
            .indicators
            .iter()
            .any(|i| i.contains("PHP_CGI_ARG_INJECTION")));
        assert!(assessment
            .indicators
            .iter()
            .any(|i| i.contains("PHP_ENV_POLLUTION")));
    }

    #[test]
    fn test_adaptive_mutation_window() {
        let history = vec![RequestSnapshot {
            timestamp_utc: "2026-10-22T20:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/chat".to_string(),
            query: None,
            user_agent: None,
            payload_size: 100,
            response_status: Some(403),
            delta_prev_ms: None,
        }];

        // 3200ms reflection delay by an agent
        let assessment = AsaAnalyzer::assess("/api/chat", None, &[], None, Some(3200), &history);
        assert!(assessment.anomaly_score >= 0.6);
        assert!(assessment
            .indicators
            .iter()
            .any(|i| i.contains("ADAPTIVE_MUTATION")));
    }
}
