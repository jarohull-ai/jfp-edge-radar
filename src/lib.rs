pub mod analyzer;
pub mod canonical;
pub mod config;
pub mod hud;
pub mod init;
pub mod ip_extractor;
pub mod mitigation;
pub mod monitor;
pub mod php_signatures;
pub mod proof;
pub mod report;
pub mod server;
pub mod tarpit;
pub mod tracker;

pub use analyzer::{AsaAnalyzer, DefensiveAction, ThreatAssessment};
pub use canonical::{AmbiguityViolation, CanonicalShield};
pub use config::RadarConfig;
pub use hud::{CommandCenterHud, HudState, HudTheme};
pub use init::InitWizard;
pub use ip_extractor::ClientIpExtractor;
pub use mitigation::OsFirewallMitigation;
pub use monitor::TerminalMonitor;
pub use php_signatures::{PhpExploitInspection, PhpSignatureEngine};
pub use proof::{ProofLogger, ProofRecord};
pub use report::{ForensicReporter, ForensicStats};
pub use server::RadarServer;
pub use tarpit::{
    SlowDripBody, TarpitGuard, TarpitMetrics, TarpitPayloadMode, GLOBAL_TARPIT_BYTES_DRAINED,
    GLOBAL_TARPIT_SECONDS_DRAINED,
};
pub use tracker::{canonicalize_tracking_ip, IpSession, RequestSnapshot, SessionTracker};
