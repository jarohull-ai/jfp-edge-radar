use crate::report::ForensicReporter;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

pub struct TerminalMonitor;

impl TerminalMonitor {
    /// Runs a live-updating terminal dashboard (NOC screen) monitoring the proof log.
    pub async fn run(log_path: &Path, refresh_interval: Duration) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            // ANSI escape to clear terminal and reset cursor
            print!("\x1B[2J\x1B[1;1H");

            println!("╔════════════════════════════════════════════════════════════════════════════╗");
            println!("║          📡 JFP-PARADOX EDGE RADAR (v0.3.0) — LIVE COMBAT MONITOR         ║");
            println!("╚════════════════════════════════════════════════════════════════════════════╝");
            println!(" Monitoring: {}\n", log_path.display());

            match ForensicReporter::analyze_log(log_path) {
                Ok(stats) => {
                    let seal_status = if stats.chain_verified {
                        "🟢 VERIFIED (Unbroken SHA-256)"
                    } else {
                        "🔴 COMPROMISED (Discontinuity detected)"
                    };

                    println!("  [ SYSTEM TELEMETRY ]");
                    println!("  • Proof Chain Integrity: {}", seal_status);
                    println!("  • Total Ingress Events:   {}", stats.total_records);
                    println!("  • Hard Blocked Attacks:  {}", stats.blocked_attacks);
                    println!("  • Honey Deceptions:      {}", stats.honey_deceptions);
                    println!("  • Dry-Run Simulations:   {}", stats.dry_run_simulations);
                    println!("  • Unique Threat Actors:  {}", stats.unique_attacker_ips.len());
                    println!();

                    println!("  [ THREAT VECTOR DISTRIBUTION ]");
                    let mut vectors: Vec<_> = stats.vector_distribution.iter().collect();
                    vectors.sort_by(|a, b| b.1.cmp(a.1));
                    if vectors.is_empty() {
                        println!("  • No malicious vectors detected yet.");
                    } else {
                        for (vec, count) in vectors.iter().take(6) {
                            println!("  • {:<26} -> {} hits", vec, count);
                        }
                    }
                    println!();

                    println!("  [ ASYMMETRY METRICS ]");
                    let tokens = (stats.blocked_attacks + stats.honey_deceptions) * 850;
                    println!("  • Estimated Attacker Tokens Burned: ~{} tokens", tokens);
                    println!("  • Backend PHP-FPM Overhead Avoided: 100%");
                    println!();
                    println!("────────────────────────────────────────────────────────────────────────────");
                    println!(" Press Ctrl+C to exit monitor | Refreshing every {}s...", refresh_interval.as_secs());
                }
                Err(e) => {
                    println!("  ⚠️ Waiting for telemetry: {}", e);
                }
            }

            sleep(refresh_interval).await;
        }
    }
}
