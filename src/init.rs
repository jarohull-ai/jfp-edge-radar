use std::fs;
use std::io::Write;
use std::path::Path;

/// Deployment & configuration initialization wizard for system administrators.
pub struct InitWizard;

impl InitWizard {
    /// Generates the standard production environment configuration file.
    pub fn generate_env_config(bind: &str, upstream: &str, log_path: &str) -> String {
        format!(
            r#"# ==============================================================================
# JFP-Paradox Edge Radar v0.4.1 Production Environment Configuration
# ==============================================================================

# Network Ingress & Egress
RADAR_BIND_ADDR={bind}
RADAR_UPSTREAM_ADDR={upstream}
RADAR_PROOF_LOG={log_path}

# Hardened Defense Limits
RADAR_MAX_SESSIONS=131072
RADAR_MAX_TARPIT_SESSIONS=512
RADAR_TARPIT_DRIP_MS=3000
RADAR_MAX_SEGMENT_MB=10

# OS Kernel Mitigation
RADAR_ENABLE_IPTABLES=false
RADAR_BAN_TTL_SECS=86400

# Audit Simulation Mode (Set to true for dry-run observation)
RADAR_DRY_RUN=false

# Trusted Reverse Proxy CIDRs (e.g. Cloudflare / Internal Load Balancer)
# RADAR_TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,10.0.0.0/8

# Telemetry Logging
RUST_LOG=info
"#,
            bind = bind,
            upstream = upstream,
            log_path = log_path
        )
    }

    /// Generates a hardened Linux systemd service unit file.
    pub fn generate_systemd_unit(bin_path: &str, env_path: &str) -> String {
        format!(
            r#"[Unit]
Description=JFP-Paradox Edge Radar (Autonomous Agent Sniffer)
Documentation=https://github.com/jarohull-ai/jfp-edge-radar
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile={env_path}
ExecStart={bin_path}
Restart=always
RestartSec=3s
LimitNOFILE=65535
LimitNPROC=65535

# Security Hardening Directives
ProtectSystem=full
ProtectHome=read-only
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
            bin_path = bin_path,
            env_path = env_path
        )
    }

    /// Writes configuration and systemd service templates to the specified directory.
    pub fn run(
        target_dir: &Path,
        bind: Option<&str>,
        upstream: Option<&str>,
    ) -> Result<(), std::io::Error> {
        let bind_addr = bind.unwrap_or("0.0.0.0:8080");
        let upstream_addr = upstream.unwrap_or("127.0.0.1:8000");
        let log_path = "/var/log/jfp/asa_radar_proof.jsonl";

        fs::create_dir_all(target_dir)?;

        let env_file = target_dir.join("radar.env");
        let service_file = target_dir.join("jfp-edge-radar.service");

        let env_content = Self::generate_env_config(bind_addr, upstream_addr, log_path);
        let mut f_env = fs::File::create(&env_file)?;
        f_env.write_all(env_content.as_bytes())?;

        let service_content = Self::generate_systemd_unit(
            "/usr/local/bin/jfp-edge-radar",
            "/etc/jfp-edge-radar/radar.env",
        );
        let mut f_service = fs::File::create(&service_file)?;
        f_service.write_all(service_content.as_bytes())?;

        println!("============================================================");
        println!("🚀 JFP-Paradox Edge Radar Production Initializer");
        println!("============================================================");
        println!("✅ Created environment config: {}", env_file.display());
        println!("✅ Created systemd service:    {}", service_file.display());
        println!();
        println!("To deploy as a Linux system daemon:");
        println!("  1. sudo mkdir -p /etc/jfp-edge-radar /var/log/jfp");
        println!(
            "  2. sudo cp {} /etc/jfp-edge-radar/radar.env",
            env_file.display()
        );
        println!(
            "  3. sudo cp {} /etc/systemd/system/",
            service_file.display()
        );
        println!("  4. sudo cp $(which jfp-edge-radar) /usr/local/bin/");
        println!("  5. sudo systemctl daemon-reload");
        println!("  6. sudo systemctl enable --now jfp-edge-radar");
        println!("============================================================");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_wizard_generation() {
        let env =
            InitWizard::generate_env_config("127.0.0.1:8080", "127.0.0.1:3000", "/tmp/proof.jsonl");
        assert!(env.contains("RADAR_BIND_ADDR=127.0.0.1:8080"));
        assert!(env.contains("RADAR_UPSTREAM_ADDR=127.0.0.1:3000"));
        assert!(env.contains("RADAR_PROOF_LOG=/tmp/proof.jsonl"));

        let unit = InitWizard::generate_systemd_unit("/usr/bin/radar", "/etc/radar.env");
        assert!(unit.contains("ExecStart=/usr/bin/radar"));
        assert!(unit.contains("EnvironmentFile=/etc/radar.env"));
        assert!(unit.contains("LimitNOFILE=65535"));
    }

    #[test]
    fn test_init_wizard_file_creation() {
        let tmp = tempfile::tempdir().unwrap();
        InitWizard::run(tmp.path(), Some("0.0.0.0:80"), Some("127.0.0.1:8080")).unwrap();

        assert!(tmp.path().join("radar.env").exists());
        assert!(tmp.path().join("jfp-edge-radar.service").exists());
    }
}
