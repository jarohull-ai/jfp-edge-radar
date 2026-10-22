use hyper::HeaderMap;

/// Strict Protocol Normalization and Smuggling Shield.
pub struct CanonicalShield;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmbiguityViolation {
    RequestSmugglingBothLengthAndEncoding,
    MultipleConflictingContentLengths,
    ControlCharacterInHeader(String),
    DoubleUrlEncodingDetected(String),
    MalformedPercentEncoding,
}

impl CanonicalShield {
    /// Inspects headers for classic and modern HTTP Request Smuggling indicators.
    pub fn inspect_headers(headers: &HeaderMap) -> Result<(), AmbiguityViolation> {
        let has_cl = headers.contains_key("content-length");
        let has_te = headers.contains_key("transfer-encoding");

        // RFC 7230 §3.3.3: Having both Content-Length and Transfer-Encoding is primary smuggling vector
        if has_cl && has_te {
            return Err(AmbiguityViolation::RequestSmugglingBothLengthAndEncoding);
        }

        // Multiple Content-Length headers check
        let cl_values: Vec<_> = headers.get_all("content-length").iter().collect();
        if cl_values.len() > 1 {
            let first = cl_values[0];
            for other in &cl_values[1..] {
                if first != *other {
                    return Err(AmbiguityViolation::MultipleConflictingContentLengths);
                }
            }
        }

        // Control characters in header names or values (CRLF / NULL injection)
        for (k, v) in headers.iter() {
            let k_str = k.as_str();
            if k_str.contains('\0') || k_str.contains('\r') || k_str.contains('\n') {
                return Err(AmbiguityViolation::ControlCharacterInHeader(
                    k_str.to_string(),
                ));
            }
            if let Ok(val) = v.to_str() {
                if val.contains('\0') || val.contains('\r') || val.contains('\n') {
                    return Err(AmbiguityViolation::ControlCharacterInHeader(
                        k_str.to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Performs multi-pass (Fixed-Point) URL decoding and path canonicalization.
    /// Returns the canonical path and query, or fails if multi-layered evasion is detected.
    pub fn canonicalize_uri(
        path: &str,
        query: Option<&str>,
    ) -> Result<(String, Option<String>), AmbiguityViolation> {
        let (canonical_path, path_double_encoded) = multi_pass_url_decode(path);
        let (canonical_query, query_double_encoded) = match query {
            Some(q) => {
                let (dec, dbl) = multi_pass_url_decode(q);
                (Some(dec), dbl)
            }
            None => (None, false),
        };

        if path_double_encoded {
            return Err(AmbiguityViolation::DoubleUrlEncodingDetected(
                path.to_string(),
            ));
        }
        if query_double_encoded {
            return Err(AmbiguityViolation::DoubleUrlEncodingDetected(
                query.unwrap_or("").to_string(),
            ));
        }

        // Normalize path slashes: multiple consecutive slashes collapsed, resolve '.' and '..'
        let normalized_path = normalize_path_segments(&canonical_path);

        Ok((normalized_path, canonical_query))
    }
}

/// Decodes URL percent-encoding until fixed-point (no changes), detecting multi-pass evasion.
fn multi_pass_url_decode(input: &str) -> (String, bool) {
    let mut current = input.to_string();
    let mut passes = 0;
    let max_passes = 4;
    let mut double_encoded = false;

    while passes < max_passes {
        match percent_decode_pass(&current) {
            Some(decoded) => {
                if decoded == current {
                    break;
                }
                passes += 1;
                if passes > 1 {
                    // Changing in pass 2+ means input was double/multi-encoded!
                    double_encoded = true;
                }
                current = decoded;
            }
            None => {
                break;
            }
        }
    }

    (current, double_encoded)
}

fn percent_decode_pass(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h1), Some(h2)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                let byte = (h1 << 4) | h2;
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(result).ok()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn normalize_path_segments(path: &str) -> String {
    let mut segments = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            segments.pop();
        } else {
            segments.push(seg);
        }
    }

    let mut out = String::from("/");
    out.push_str(&segments.join("/"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn test_smuggling_cl_and_te_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("42"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));

        assert_eq!(
            CanonicalShield::inspect_headers(&headers),
            Err(AmbiguityViolation::RequestSmugglingBothLengthAndEncoding)
        );
    }

    #[test]
    fn test_double_url_encoding_detected() {
        // %252d is '%2d' (double encoded '-')
        let uri = "/index.php";
        let query = Some("%252dallow_url_include=1");

        let res = CanonicalShield::canonicalize_uri(uri, query);
        assert!(matches!(
            res,
            Err(AmbiguityViolation::DoubleUrlEncodingDetected(_))
        ));
    }

    #[test]
    fn test_clean_single_encoding_normalized() {
        let uri = "/api/v1/%63atalog/../products";
        let query = Some("category=tools");

        let (path, q) = CanonicalShield::canonicalize_uri(uri, query).unwrap();
        assert_eq!(path, "/api/v1/products");
        assert_eq!(q, Some("category=tools".to_string()));
    }
}
