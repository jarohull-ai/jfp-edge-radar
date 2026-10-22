use jfp_edge_radar::{ForensicReporter, RadarConfig, RadarServer};
use std::path::PathBuf;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h" || args[1] == "help") {
        print_help();
        return Ok(());
    }

    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V" || args[1] == "version") {
        println!("jfp-edge-radar v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

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

    info!("Initializing JFP-Paradox Edge Radar (ASA Sniffer) v0.4.0 Hardened Enterprise Core...");

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
    if let Ok(max_sess) = std::env::var("RADAR_MAX_SESSIONS_CAPACITY") {
        config.max_sessions_capacity = max_sess.parse().expect("Invalid RADAR_MAX_SESSIONS_CAPACITY");
    }
    if let Ok(max_tarpit) = std::env::var("RADAR_MAX_TARPIT_SESSIONS") {
        config.max_tarpit_concurrency = max_tarpit.parse().expect("Invalid RADAR_MAX_TARPIT_SESSIONS");
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

fn print_help() {
    println!(
        r#"🛡️ JFP-Paradox Edge Radar v{} - Autonomous Agent Sniffer (ASA)

USAGE:
    jfp-edge-radar [COMMAND] [OPTIONS]

COMMANDS:
    (default)       Start the reverse-proxy radar engine listening on RADAR_BIND_ADDR.
    monitor         Start live terminal dashboard displaying real-time threats and statistics.
    report          Verify cryptographic SHA-256 proof chain and generate forensic Markdown report.
    --help, -h      Print help information.
    --version, -V   Print version information.

OPTIONS FOR 'report':
    --log <PATH>    Path to proof JSONL log file (default: /var/log/jfp/asa_radar_proof.jsonl or $RADAR_PROOF_LOG)
    --out <PATH>    Export generated Markdown report to file

OPTIONS FOR 'monitor':
    --log <PATH>    Path to proof JSONL log file to monitor in real-time

ENVIRONMENT VARIABLES:
    RADAR_BIND_ADDR          Address to bind the radar server (default: 0.0.0.0:8080)
    RADAR_UPSTREAM_ADDR      Upstream backend to protect (e.g. 127.0.0.1:8000)
    RADAR_PROOF_LOG          Path to cryptographically chained proof log (default: /var/log/jfp/asa_radar_proof.jsonl)
    RADAR_DRY_RUN            Enable audit/dry-run mode without active blocking (true/false)
    RADAR_MAX_SESSIONS       Max tracking capacity for IP state LRU table (default: 131072)
    RADAR_MAX_TARPIT_SESSIONS Max concurrent Slow-Drip Tarpit sockets (default: 512)
    RADAR_ENABLE_MITIGATION  Enable automated iptables kernel blocking (true/false)
    RADAR_BAN_TTL_SECS       Duration in seconds for kernel ban before auto-unban (default: 86400)
"#,
        env!("CARGO_PKG_VERSION")
    );
}
