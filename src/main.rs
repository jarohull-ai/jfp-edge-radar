use jfp_edge_radar::{ForensicReporter, RadarConfig, RadarServer};
use std::path::PathBuf;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();

    // Check for CLI subcommands
    if args.len() > 1 && args[1] == "report" {
        run_report_subcommand(&args[2..])?;
        return Ok(());
    }
    if args.len() > 1 && args[1] == "monitor" {
        let mut log_path = PathBuf::from("/var/log/jfp/asa_radar_proof.jsonl");
        if let Ok(path) = std::env::var("RADAR_PROOF_LOG") {
            log_path = PathBuf::from(path);
        }
        let mut i = 2;
        while i < args.len() {
            if args[i] == "--log" && i + 1 < args.len() {
                log_path = PathBuf::from(&args[i + 1]);
                i += 2;
            } else {
                i += 1;
            }
        }
        jfp_edge_radar::TerminalMonitor::run(&log_path, std::time::Duration::from_secs(1)).await?;
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "jfp_edge_radar=info,info".into()),
        )
        .init();

    info!("Initializing JFP-Paradox Edge Radar (ASA Sniffer) v0.3.0...");

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
    if let Ok(ttl) = std::env::var("RADAR_BAN_TTL_SECS") {
        config.ban_ttl_secs = ttl.parse().expect("Invalid RADAR_BAN_TTL_SECS");
    }
    if let Ok(drip) = std::env::var("RADAR_TARPIT_DRIP_MS") {
        config.tarpit_drip_interval_ms = drip.parse().expect("Invalid RADAR_TARPIT_DRIP_MS");
    }
    if let Ok(proxies) = std::env::var("RADAR_TRUSTED_PROXIES") {
        config.trusted_proxies = proxies.split(',').map(|s| s.trim().to_string()).collect();
    }

    let server = RadarServer::new(config);
    server.run().await
}

fn run_report_subcommand(subargs: &[String]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut log_path = PathBuf::from("/var/log/jfp/asa_radar_proof.jsonl");
    let mut out_path = None;

    let mut i = 0;
    while i < subargs.len() {
        if subargs[i] == "--log" && i + 1 < subargs.len() {
            log_path = PathBuf::from(&subargs[i + 1]);
            i += 2;
        } else if subargs[i] == "--out" && i + 1 < subargs.len() {
            out_path = Some(PathBuf::from(&subargs[i + 1]));
            i += 2;
        } else {
            i += 1;
        }
    }

    println!("============================================================");
    println!("🔍 JFP-Paradox Edge Radar Forensic Analyzer");
    println!("Analyzing proof log: {}", log_path.display());
    println!("============================================================");

    let stats = ForensicReporter::analyze_log(&log_path)
        .map_err(|e| format!("Forensics error: {}", e))?;

    let report_content = ForensicReporter::generate_markdown_report(&stats, &log_path);

    println!("\n{}", report_content);

    if let Some(out) = out_path {
        std::fs::write(&out, &report_content)?;
        println!("\n💾 Incident report saved to: {}", out.display());
    }

    Ok(())
}
