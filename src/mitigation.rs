use std::net::IpAddr;
use std::process::Command;
use tracing::{error, info, warn};

/// Autonomous OS Firewall Mitigation Engine (iptables/nftables).
pub struct OsFirewallMitigation {
    enabled: bool,
}

impl OsFirewallMitigation {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Determines if an IP is whitelisted from OS-level banning (e.g., loopback, private ranges).
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_broadcast()
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }

    /// Enforces an immediate OS kernel level drop via iptables.
    pub fn drop_ip(&self, ip: IpAddr) -> Result<bool, String> {
        if !self.enabled {
            return Ok(false);
        }

        if self.is_whitelisted(&ip) {
            warn!("Mitigation skipped: IP {} is whitelisted (loopback/private)", ip);
            return Ok(false);
        }

        let ip_str = ip.to_string();

        // 1. Check if rule already exists (idempotency check)
        let check_status = Command::new("iptables")
            .args(["-C", "INPUT", "-s", &ip_str, "-j", "DROP"])
            .output();

        match check_status {
            Ok(output) => {
                if output.status.success() {
                    // Rule already present
                    return Ok(false);
                }
            }
            Err(e) => {
                let err_msg = format!("Failed to check iptables rule: {}", e);
                warn!("{}", err_msg);
                return Err(err_msg);
            }
        }

        // 2. Insert DROP rule at the head of INPUT chain
        let insert_status = Command::new("iptables")
            .args(["-I", "INPUT", "-s", &ip_str, "-j", "DROP"])
            .output();

        match insert_status {
            Ok(output) => {
                if output.status.success() {
                    info!("OS FIREWALL: successfully dropped malicious IP {} via iptables", ip);
                    Ok(true)
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!("OS FIREWALL: iptables failed with: {}", stderr);
                    Err(stderr.to_string())
                }
            }
            Err(e) => {
                let err_msg = format!("Failed to execute iptables command: {}", e);
                error!("{}", err_msg);
                Err(err_msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelisted_ip_never_banned() {
        let mitigation = OsFirewallMitigation::new(true);
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(mitigation.is_whitelisted(&loopback));
        let res = mitigation.drop_ip(loopback).unwrap();
        assert!(!res); // Not dropped
    }

    #[test]
    fn test_disabled_mitigation_returns_false() {
        let mitigation = OsFirewallMitigation::new(false);
        let untrusted: IpAddr = "198.51.100.42".parse().unwrap();
        let res = mitigation.drop_ip(untrusted).unwrap();
        assert!(!res);
    }
}
