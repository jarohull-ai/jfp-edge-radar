# JFP-Paradox Edge Radar (ASA - Autonomous Agent Sniffer)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/badge/crates.io-v0.4.0-red.svg)](https://crates.io/crates/jfp-edge-radar)
[![Release](https://img.shields.io/github/v/release/jarohull-ai/jfp-edge-radar)](https://github.com/jarohull-ai/jfp-edge-radar/releases)
[![Build Status](https://img.shields.io/badge/tests-27%2F27%20passing-brightgreen.svg)]()

**JFP-Paradox Edge Radar** is an ultra-lightweight, high-performance, deterministic perimeter security gateway and reverse proxy built in **Rust** as part of the **JARO Flash Protocol (JFP)** ecosystem.

It is engineered specifically to intercept autonomous AI agent botnets, mutating zero-day exploit scanners, and memory-exhaustion/RCE attacks targeting PHP runtimes (including **PHP-2-Shell: CVE-2026-109618 and CVE-2026-109619**) with **zero LLM overhead in the network critical path (0ms inference latency, 100% deterministic execution)**.

---

## 🏛️ Architecture & Core Defenses

```
                        INCOMING HTTP(S) TRAFFIC
                                   │
                                   ▼
         ┌──────────────────────────────────────────────────┐
         │          JFP Edge Radar v0.4.0 Gateway           │
         │                                                  │
         │  [1] Protocol Canonical Shield                   │
         │      • RFC 7230 §3.3.3 Request Smuggling Check   │
         │      • Fixed-Point Multi-Pass URL Decoding       │
         │      • Path Segment & Header Null-Byte Sanitizer │
         │                                                  │
         │  [2] Real Client IP & State Tracker              │
         │      • Anti-Spoofing CIDR Header Extraction      │
         │      • IPv6 /64 Prefix Subnet Aggregation        │
         │      • Bounded LRU Capacity (131k Sessions Max)  │
         │      • One-Hit Scanner Aggressive Eviction       │
         │                                                  │
         │  [3] ASA Engine (Deterministic Sniffer)          │
         │      • LLM Timing Window (1.2s - 8.5s) RTT       │
         │      • AI Structural Recon (/AGENTS.md, llms.txt)│
         │      • PHP-2-Shell / CGI Query-String Injection  │
         │      • Anomaly Score Calculation [0.00 - 1.00]   │
         │                                                  │
         │  [4] Asymmetric Defensive Response Dispatch      │
         │      • Score < 0.30:  Clean Proxy Forward        │
         │      • Score 0.3-0.6: Slow-Drip Tarpit (Cap 512) │
         │      • Score > 0.60:  Instant 403 BlockProof     │
         │      • Dry-Run Mode:  Audit-Only Simulation      │
         └─────────────┬──────────────────────┬─────────────┘
                       │                      │
       Legitimate Traffic (Score < 0.3)        Threats Blocked / Tarpitted
                       │                      │
                       ▼                      ▼
           ┌──────────────────────┐   ┌───────────────────────────────┐
           │   Upstream Backend   │   │  Tamper-Evident Proof Logger  │
           │ (PHP-FPM, Web App)   │   │  SHA-256 Chained JSONL Ledger │
           └──────────────────────┘   └───────────────────────────────┘
```

---

## 🛡️ The Three Enterprise Hardening Shields (v0.4.0)

### 1. State Flooding Shield (RAM Exhaustion Protection)
* **IPv6 Subnet Aggregation (`/64`):** Eliminates state fragmentation from residential proxy pools cycling ephemeral IPv6 host addresses. All requests within the same `/64` block share a single tracking bucket.
* **Bounded LRU & Single-Hit Eviction:** A hard cap (`RADAR_MAX_SESSIONS_CAPACITY`, default 131,072). When the table saturates, single-request scanner records (`total_requests == 1`) are evicted first, completely preventing Out-Of-Memory (OOM) crashes on the gateway.

### 2. Protocol Ambiguity & Request Smuggling Shield
* **Fixed-Point URL Decoding:** Multi-pass decoding loop continuously strips nested percent-encodings (`%252d` $\to$ `%2d` $\to$ `-d`). Evasion attempts requiring $>1$ pass are immediately disqualified with an anomaly score of `1.0`.
* **RFC 7230 §3.3.3 Enforcement:** Ingress requests presenting both `Content-Length` and `Transfer-Encoding: chunked` are rejected with `400 Bad Request` before reaching any proxy logic.
* **Path Canonicalization:** Collapses double slashes (`///`), normalizes `/./` and `/../`, and verifies that no null bytes (`\0`) or CRLF injections exist in header keys or values.

### 3. File Descriptor Exhaustion Guard (Slow-Drip Tarpit Cap)
* **Atomic Concurrency Cap:** Protects the operating system's `nofile` socket table by strictly limiting concurrent tarpit connections (`RADAR_MAX_TARPIT_SESSIONS`, default 512).
* **Automatic Fallback:** When the concurrency limit is reached, subsequent attacker traffic does not allocate a hanging socket; it immediately falls back to a fast `403 Forbidden` with a cryptographic proof header.

---

## 🔬 Verified Test Scenarios & Live Execution Dumps

All 27 automated unit, integration, and end-to-end tests run green (`cargo test`). Detailed documentation is available in [docs/SCENARIOS_AND_SECURITY_PROOFS.md](docs/SCENARIOS_AND_SECURITY_PROOFS.md).

### Scenario 1: Intercepting PHP-2-Shell (CVE-2026-109618)
* **Vector:** Attacker injects `-d allow_url_include=on` and `PHP_VALUE: auto_prepend_file=php://input`.
* **Client Request:**
  ```bash
  curl -i -H "PHP_VALUE: auto_prepend_file=php://input" \
    "http://localhost:8080/index.php?-d+allow_url_include=on"
  ```
* **Radar Gateway Response:**
  ```http
  HTTP/1.1 403 Forbidden
  content-type: application/json
  x-jfp-proof-hash: 6701b1eeeb52f0b1c3d2376e0eaa7ddceb35770253dc0abae4a1669be167ef69
  content-length: 83

  {"error":"Forbidden","reason":"Threat blocked by JFP Edge Radar (Hardened Shield)"}
  ```
* **System Action:** Request isolated at the perimeter. Zero bytes forwarded to backend PHP-FPM.

---

### Scenario 2: Multi-Pass URL Encoding Evasion
* **Vector:** Double-encoded `-d` parameter (`%252d` $\to$ `%2d` $\to$ `-`).
* **Test Dump:**
  ```text
  -> Raw obfuscated query: %252d+allow_url_include=on
  <- Canonical check result: Err(DoubleUrlEncodingDetected("%252d+allow_url_include=on"))
  ✅ Verified: Fixed-point URL decoding caught nested %252d evasion and blocked it.
  ```

---

### Scenario 3: Autonomous AI Agent Timing Window & Recon
* **Vector:** AI crawler checks `/robots.txt`, pauses during LLM token inference ($\Delta t = 2000\text{ms}$), then requests `/AGENTS.md`.
* **Gateway Log Output:**
  ```text
  WARN jfp_edge_radar::server: ASA Alert: Client IP 127.0.0.1 (Req #2) Score: 0.70 Action: BlockProof
  Indicators: [
    "STRUCTURAL_RECON: AI Agent Metadata Probing ('/AGENTS.md')",
    "TIMING_WINDOW: Delta 2000ms fits LLM reflection loop (1200ms - 8500ms)"
  ]
  ```

---

### Scenario 4: Slow-Drip Tarpit Concurrency Cap Fallback
* **Vector:** Massive connection flood attempting to exhaust server file descriptors.
* **Test Execution:**
  ```text
  [Active Tarpits: 1/1] Request 1 from Attacker A -> Assigned Chunked Slow-Drip (1 byte / sec)
  [Active Tarpits: 1/1] Request 2 from Attacker B -> Concurrency Cap Hit!
  <- Response 2: 403 Forbidden (Immediate drop, zero hanging sockets allocated)
  ```

---

### Scenario 5: Cryptographic Chain Verification & Tamper Detection
* **Audit Execution:**
  ```bash
  jfp-edge-radar report --log /tmp/jfp_radar_proof.jsonl
  ```
* **Tampering Test Dump:**
  ```text
  -> Legitimate 3-block chain: 100% UNBROKEN (SHA-256 verification passed)
  -> Modifying 1 byte in block #1 (/admin.php -> /legit.php)...
  <- Tampered verification status: chain_verified = false, broken_at = Some(2)
  ✅ Verified: Any byte modification invalidates all downstream SHA-256 digests.
  ```

---

## 🚀 Quick Start & Installation

### Option A: Install from Source with Cargo
```bash
git clone https://github.com/jarohull-ai/jfp-edge-radar.git
cd jfp-edge-radar
cargo install --path .
```

### Option B: Build Release Binary Directly
```bash
cargo build --release
./target/release/jfp-edge-radar --help
```

---

## 💻 CLI Commands & Usage

```text
🛡️ JFP-Paradox Edge Radar v0.4.0 - Autonomous Agent Sniffer (ASA)

USAGE:
    jfp-edge-radar [COMMAND] [OPTIONS]

COMMANDS:
    (default)       Start the reverse-proxy radar engine listening on RADAR_BIND_ADDR.
    monitor         Start live terminal dashboard displaying real-time threats and statistics.
    report          Verify cryptographic SHA-256 proof chain and generate forensic Markdown report.
    --help, -h      Print help information.
    --version, -V   Print version information.
```

### 1. Run the Reverse Proxy Gateway
```bash
export RADAR_BIND_ADDR="0.0.0.0:8080"
export RADAR_UPSTREAM_ADDR="127.0.0.1:8000"
export RADAR_PROOF_LOG="/var/log/jfp/asa_radar_proof.jsonl"

jfp-edge-radar
```

### 2. Live NOC Terminal Monitor
To observe live attacks, request rates, anomaly scores, and tarpit sessions in real-time:
```bash
jfp-edge-radar monitor --log /var/log/jfp/asa_radar_proof.jsonl
```

### 3. Generate SOC Incident Report
To run a cryptographic audit on the proof chain and produce a Markdown incident report:
```bash
jfp-edge-radar report \
  --log /var/log/jfp/asa_radar_proof.jsonl \
  --out /tmp/security_incident_report.md
```

---

## ⚙️ Configuration Reference

All settings can be configured via environment variables:

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `RADAR_BIND_ADDR` | SocketAddr | `0.0.0.0:8080` | IP and port for the incoming edge proxy. |
| `RADAR_UPSTREAM_ADDR` | SocketAddr | `None` | Upstream backend application to protect. |
| `RADAR_PROOF_LOG` | Path | `/var/log/jfp/asa_radar_proof.jsonl` | Tamper-evident chained audit ledger path. |
| `RADAR_DRY_RUN` | Bool | `false` | Audit mode: logs threats but forwards traffic. |
| `RADAR_MAX_SESSIONS` | Usize | `131072` | In-memory IP tracking bounded LRU capacity. |
| `RADAR_MAX_TARPIT_SESSIONS` | Usize | `512` | Max concurrent Slow-Drip Tarpit open sockets. |
| `RADAR_ENABLE_IPTABLES` | Bool | `false` | Enables automatic OS kernel blocking. |
| `RADAR_BAN_TTL_SECS` | U64 | `86400` | Duration of kernel ban before automated cleanup. |
| `RADAR_TRUSTED_PROXIES` | String | `""` | Comma-separated trusted proxy CIDRs (e.g. Cloudflare). |

---

## 🧪 Testing Suite

Execute the complete 27-test validation suite:

```bash
# Run all unit, integration, and scenario tests
cargo test

# Run end-to-end scenario traces with full console output
cargo test --test e2e_scenarios_test -- --nocapture
```

---

## 📜 License

Licensed under the [MIT License](LICENSE). Built with precision by the JARO Flash Protocol (JFP) defensive engineering team.
