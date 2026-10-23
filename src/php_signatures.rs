use serde::{Deserialize, Serialize};

/// High-fidelity structural and payload checks for PHP-2-Shell (CVE-2026-109618 / CVE-2026-109619).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhpExploitInspection {
    pub is_suspicious: bool,
    pub severity_score: f64,
    pub flags: Vec<String>,
}

pub struct PhpSignatureEngine;

impl PhpSignatureEngine {
    /// Inspects headers, query strings, and paths for PHP core memory exhaustion and RCE patterns.
    pub fn inspect_request(
        path: &str,
        query: Option<&str>,
        headers: &[(String, String)],
        content_length: Option<usize>,
    ) -> PhpExploitInspection {
        let mut score: f64 = 0.0;
        let mut flags = Vec::new();

        let path_lower = path.to_lowercase();
        let query_str = query.unwrap_or("").to_lowercase();

        // 1. PHP-CGI / SAPI Argument Injection (CVE-2024-4577 & mutating PHP-2-Shell variants)
        let cgi_patterns = [
            "-d",
            "allow_url_include",
            "auto_prepend_file",
            "auto_append_file",
            "allow_url_fopen",
            "disable_functions",
            "cgi.force_redirect",
            "%add", // Soft hyphen evasion (CVE-2024-4577)
            "%ad",
            "php://input",
            "php://filter",
            "php://memory",
            "php://temp",
            "data://text/plain",
            "phar://",
            "zip://",
            "compress.zlib://",
            "compress.bzip2://",
            "expect://",
            "glob://",
        ];

        for pattern in &cgi_patterns {
            if query_str.contains(pattern) || path_lower.contains(pattern) {
                score += 0.50;
                flags.push(format!("PHP_CGI_ARG_INJECTION: detected '{}'", pattern));
            }
        }

        // 1b. PHP Object Deserialization Gadget Injections (RCE Vector)
        if query_str.contains("o:") && (query_str.contains(":\"]") || query_str.contains(":\""))
            || query_str.contains("a:") && query_str.contains(":{")
        {
            score += 0.65;
            flags.push(
                "PHP_OBJECT_INJECTION: serialized gadget payload pattern detected".to_string(),
            );
        }

        // 2. Probing for high-risk PHP endpoints & debug consoles
        let probe_paths = [
            ".php",
            "phpinfo",
            "cgi-bin",
            "_ignition",
            "eval-stdin.php",
            "vendor/phpunit",
            "telescope",
            "wp-includes",
            "xmlrpc.php",
        ];

        for probe in &probe_paths {
            if path_lower.contains(probe) {
                score += 0.35;
                flags.push(format!("PHP_TARGETED_PROBE: matching '{}'", probe));
                break;
            }
        }

        // 3. Header-based SAPI / FPM environment tampering & pollution (CVE-2026-109619)
        for (name, val) in headers {
            let name_lower = name.to_lowercase();
            let val_lower = val.to_lowercase();

            if name_lower == "php_value" || name_lower == "php_admin_value" {
                score += 0.70;
                flags.push(format!("PHP_ENV_POLLUTION: unauthorized header '{}'", name));
            }

            if name_lower == "proxy" || name_lower == "http_proxy" {
                score += 0.60;
                flags.push("HTTP_PROXY_ENV_INJECTION: potential Httpoxy attack".to_string());
            }

            // FastCGI / Apache header smuggling via spaces or invalid control chars
            if name.starts_with(' ') || name.ends_with(' ') || val.contains('\0') {
                score += 0.55;
                flags.push(format!(
                    "HEADER_SMUGGLING: malformed header name '{}'",
                    name
                ));
            }

            // Multipart boundary depth attack (CVE-2026-109618 OOM Heap Exhaustion)
            if name_lower == "content-type" && val_lower.contains("multipart/form-data") {
                let boundary_count = val_lower.matches("boundary").count();
                if boundary_count > 1 || val_lower.len() > 512 {
                    score += 0.45;
                    flags.push(
                        "OOM_MULTIPART_ANOMALY: nested or oversized multipart boundary".to_string(),
                    );
                }
            }

            // Transfer-Encoding chunked smuggling tricks
            if name_lower == "transfer-encoding"
                && val_lower.contains("chunked")
                && val_lower != "chunked"
            {
                score += 0.50;
                flags.push(format!(
                    "OOM_CHUNKED_SMUGGLING: obfuscated chunked header '{}'",
                    val
                ));
            }
        }

        // 4. Memory Exhaustion / OOM Size checks
        if let Some(cl) = content_length {
            // Suspicious single request payload aiming for immediate OOM bailout (> 32MB by default)
            if cl > 32 * 1024 * 1024 {
                score += 0.40;
                flags.push(format!(
                    "OOM_MASSIVE_BODY: Content-Length {} bytes exceeds threshold",
                    cl
                ));
            }
        }

        PhpExploitInspection {
            is_suspicious: score >= 0.30,
            severity_score: score.min(1.0),
            flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_php_stream_wrapper_and_deserialization_detection() {
        let phar_res = PhpSignatureEngine::inspect_request(
            "/index.php",
            Some("file=phar://malicious.phar/shell.php"),
            &[],
            None,
        );
        assert!(phar_res.is_suspicious);
        assert!(phar_res.flags.iter().any(|f| f.contains("phar://")));

        let gadget_res = PhpSignatureEngine::inspect_request(
            "/index.php",
            Some("data=O:8:\"Exploit\":0:{}"),
            &[],
            None,
        );
        assert!(gadget_res.is_suspicious);
        assert!(gadget_res
            .flags
            .iter()
            .any(|f| f.contains("PHP_OBJECT_INJECTION")));
    }
}
