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

    info!("Initializing JFP-Paradox Edge Radar (ASA Sniffer)...");

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

    let server = RadarServer::new(config);
    server.run().await
}
