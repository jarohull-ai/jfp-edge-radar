use dashmap::DashMap;
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Autonomous OS Firewall Mitigation Engine with Dynamic TTL Expiration (iptables).
pub struct OsFirewallMitigation {
    enabled: bool,
    ban_ttl: Duration,
    active_bans: DashMap<IpAddr, Instant>,
}

impl OsFirewallMitigation {
    pub fn new(enabled: bool, ban_ttl_secs: u64) -> Self {
        Self {
            enabled,
            ban_ttl: Duration::from_secs(ban_ttl_secs),
            active_bans: DashMap::new(),
        }
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

    /// Enforces an immediate OS kernel level drop via iptables and records TTL expiration.
    pub fn drop_ip(&self, ip: IpAddr) -> Result<bool, String> {
        if !self.enabled {
            return Ok(false);
        }

        if self.is_whitelisted(&ip) {
            warn!("Mitigation skipped: IP {} is whitelisted (loopback/private)", ip);
            return Ok(false);
        }

        if self.active_bans.contains_key(&ip) {
            // Already under active quarantine
            return Ok(false);
        }

        let ip_str = ip.to_string();

        // 1. Check if rule already exists in iptables
        let check_status = Command::new("iptables")
            .args(["-C", "INPUT", "-s", &ip_str, "-j", "DROP"])
            .output();

        match check_status {
            Ok(output) => {
                if output.status.success() {
                    self.active_bans.insert(ip, Instant::now());
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
                    info!(
                        "OS FIREWALL: successfully dropped malicious IP {} via iptables (Quarantine TTL: {}s)",
                        ip, self.ban_ttl.as_secs()
                    );
                    self.active_bans.insert(ip, Instant::now());
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

    /// Scans active bans and removes expired IP rules from the kernel table.
    pub fn prune_expired_bans(&self) -> Vec<IpAddr> {
        if !self.enabled {
            return Vec::new();
        }

        let now = Instant::now();
        let mut expired = Vec::new();

        self.active_bans.retain(|ip, banned_at| {
            if now.duration_since(*banned_at) >= self.ban_ttl {
                expired.push(*ip);
                false // remove from map
            } else {
                true
            }
        });

        for ip in &expired {
            let ip_str = ip.to_string();
            let _ = Command::new("iptables")
                .args(["-D", "INPUT", "-s", &ip_str, "-j", "DROP"])
                .output();
            info!("OS FIREWALL: Quarantine TTL expired for IP {}, unbanned from iptables", ip);
        }

        expired
    }

    pub fn active_bans_count(&self) -> usize {
        self.active_bans.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelisted_ip_never_banned() {
        let mitigation = OsFirewallMitigation::new(true, 3600);
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(mitigation.is_whitelisted(&loopback));
        let res = mitigation.drop_ip(loopback).unwrap();
        assert!(!res); // Not dropped
    }

    #[test]
    fn test_disabled_mitigation_returns_false() {
        let mitigation = OsFirewallMitigation::new(false, 3600);
        let untrusted: IpAddr = "198.51.100.42".parse().unwrap();
        let res = mitigation.drop_ip(untrusted).unwrap();
        assert!(!res);
    }

    #[test]
    fn test_active_bans_ttl_pruning() {
        let mitigation = OsFirewallMitigation::new(true, 0); // Immediate expiration
        let ip: IpAddr = "198.51.100.99".parse().unwrap();
        mitigation.active_bans.insert(ip, Instant::now() - Duration::from_secs(1));

        assert_eq!(mitigation.active_bans_count(), 1);
        let pruned = mitigation.prune_expired_bans();
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0], ip);
        assert_eq!(mitigation.active_bans_count(), 0);
    }
}
