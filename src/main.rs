use jfp_edge_radar::{RadarConfig, RadarServer};
use std::path::PathBuf;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "jfp_edge_radar=info,info".into()),
        )
        .init();

    info!("Initializing JFP-Paradox Edge Radar (ASA Sniffer) v0.2.0...");

    let mut config = RadarConfig::default();
    if let Ok(addr) = std::env::var("RADAR_BIND_ADDR") {
        config.bind_addr = addr.parse().expect("Invalid RADAR_BIND_ADDR");
    }
    if let Ok(upstream) = std::env::var("RADAR_UPSTREAM_ADDR") {
        config.upstream_addr = Some(upstream.parse().expect("Invalid RADAR_UPSTREAM_ADDR"));
    }
    if let Ok(path) = std::env::var("RADAR_PROOF_LOG") {
        config.proof_log_path = PathBuf::from(path);
    }
    if let Ok(max_bytes) = std::env::var("RADAR_PROOF_MAX_BYTES") {
        config.proof_log_max_bytes = max_bytes.parse().expect("Invalid RADAR_PROOF_MAX_BYTES");
    }
    if std::env::var("RADAR_DRY_RUN").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false) {
        config.dry_run = true;
    }
    if std::env::var("RADAR_ENABLE_IPTABLES").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false) {
        config.enable_os_firewall_drop = true;
    }
    if let Ok(proxies) = std::env::var("RADAR_TRUSTED_PROXIES") {
        config.trusted_proxies = proxies.split(',').map(|s| s.trim().to_string()).collect();
    }

    let server = RadarServer::new(config);
    server.run().await
}
