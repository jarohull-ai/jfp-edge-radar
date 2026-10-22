use hyper::HeaderMap;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

/// Anti-spoofing Real Client IP extraction engine for Cloudflare, Nginx, and AWS ALBs.
#[derive(Debug, Clone)]
pub struct ClientIpExtractor {
    trusted_proxies: Vec<IpNet>,
}

impl Default for ClientIpExtractor {
    fn default() -> Self {
        // Standard loopback and RFC1918 private network ranges
        let default_cidrs = [
            "127.0.0.0/8",
            "::1/128",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
        ];

        let trusted = default_cidrs
            .iter()
            .filter_map(|cidr| IpNet::from_str(cidr).ok())
            .collect();

        Self {
            trusted_proxies: trusted,
        }
    }
}

impl ClientIpExtractor {
    pub fn new(custom_cidrs: &[String]) -> Self {
        let mut extractor = Self::default();
        for cidr in custom_cidrs {
            if let Ok(net) = IpNet::from_str(cidr.trim()) {
                extractor.trusted_proxies.push(net);
            }
        }
        extractor
    }

    /// Verifies if a network peer is a trusted reverse proxy.
    pub fn is_trusted(&self, peer_ip: &IpAddr) -> bool {
        self.trusted_proxies.iter().any(|net| net.contains(peer_ip))
    }

    /// Extracts the true client IP with spoofing protection.
    /// If peer_ip is untrusted, headers like X-Forwarded-For or CF-Connecting-IP are ignored.
    pub fn extract_real_ip(&self, peer_ip: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.is_trusted(&peer_ip) {
            return peer_ip;
        }

        // 1. Cloudflare header
        if let Some(cf_ip) = headers
            .get("cf-connecting-ip")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return cf_ip;
        }

        // 2. Akamai / Cloudflare True-Client-IP
        if let Some(true_ip) = headers
            .get("true-client-ip")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return true_ip;
        }

        // 3. Nginx / Forwarder X-Real-IP
        if let Some(real_ip) = headers
            .get("x-real-ip")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return real_ip;
        }

        // 4. Standard X-Forwarded-For (inspect from right to left to find first untrusted IP)
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
            let mut candidate = None;
            for part in xff.split(',').rev() {
                if let Ok(ip) = part.trim().parse::<IpAddr>() {
                    if !self.is_trusted(&ip) {
                        return ip;
                    }
                    candidate = Some(ip);
                }
            }
            if let Some(ip) = candidate {
                return ip;
            }
        }

        peer_ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn test_untrusted_peer_ignores_spoofed_headers() {
        let extractor = ClientIpExtractor::default();
        let untrusted_peer: IpAddr = "203.0.113.50".parse().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("198.51.100.1"),
        );
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );

        let real_ip = extractor.extract_real_ip(untrusted_peer, &headers);
        assert_eq!(real_ip, untrusted_peer);
    }

    #[test]
    fn test_trusted_peer_extracts_cloudflare_ip() {
        let extractor = ClientIpExtractor::default();
        let trusted_nginx: IpAddr = "127.0.0.1".parse().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("198.51.100.77"),
        );

        let real_ip = extractor.extract_real_ip(trusted_nginx, &headers);
        assert_eq!(real_ip, "198.51.100.77".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_trusted_peer_extracts_rightmost_untrusted_xff() {
        let extractor = ClientIpExtractor::default();
        let trusted_proxy: IpAddr = "10.0.0.2".parse().unwrap();

        let mut headers = HeaderMap::new();
        // Attacker -> Proxy 1 (untrusted) -> Proxy 2 (trusted) -> Radar
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.99, 10.0.0.5"),
        );

        let real_ip = extractor.extract_real_ip(trusted_proxy, &headers);
        assert_eq!(real_ip, "198.51.100.99".parse::<IpAddr>().unwrap());
    }
}
