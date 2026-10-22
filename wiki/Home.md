# Welcome to the JFP-Paradox Edge Radar Wiki 🛡️

**JFP-Paradox Edge Radar (ASA - Autonomous Agent Sniffer)** is an ultra-fast, deterministic edge defensive proxy written in **Rust**. It operates at the network perimeter to detect, throttle, and neutralize hostile autonomous AI agent botnets, mutating exploit scanners, and memory-exhaustion/RCE attacks targeting web applications (including **PHP-2-Shell: CVE-2026-109618 and CVE-2026-109619**).

---

## ⚡ Why Edge Radar?

Traditional Web Application Firewalls (WAFs) rely on static Regular Expressions that are easily bypassed by mutating LLM prompts, multi-pass URL encoding, or request smuggling. Conversely, AI-based security gateways that invoke LLMs in the request loop add hundreds of milliseconds of latency, cost millions in inference tokens, and become prime targets for Denial of Service.

**JFP-Paradox Edge Radar solves this by applying strict mathematical and protocol asymmetry:**
1. **0ms LLM Latency (Deterministic Defense):** Runs at wire speed using Tokio and Hyper 1.x.
2. **Timing Window Heuristics:** Detects the physical latency signature ($1.2\text{s} - 8.5\text{s}$) of agent reflection and tool execution.
3. **Slow-Drip Tarpit with Concurrency Cap:** Drains the memory and connection pools of attacking botnets while strictly capping local resource utilization.
4. **Tamper-Evident SHA-256 Ledger:** Maintains a cryptographically chained proof log for legal-grade incident response.

---

## 📚 Knowledge Base Navigation

Explore the dedicated chapters below:

1. **[Architecture and The Three Shields](Architecture-and-The-Three-Shields)**  
   Deep dive into the v0.4.0 Hardened Enterprise Core: State Flooding Protection, Protocol Canonical Shield, and File Descriptor Concurrency Guard.

2. **[Production Deployment Guide](Production-Deployment-Guide)**  
   Step-by-step instructions for bare-metal, systemd, Docker, and reverse-proxy setups behind Cloudflare, AWS ALB, and Nginx.

3. **[Incident Response and Forensics](Incident-Response-and-Forensics)**  
   How to verify the cryptographic SHA-256 chain, parse JSONL proof ledgers, and generate automated Markdown reports for SOC teams.

4. **[Configuration and Tuning Reference](Configuration-and-Tuning)**  
   Complete breakdown of all environment variables, memory limits, tarpit drip intervals, and CIDR trust policies.

5. **[Licensing and Commercial Use](Licensing-and-Commercial-Use)**  
   Comprehensive explanation of the JFP Community Defensive Shield (< $10M Free) and Commercial Enterprise Licensing ($10M+).
