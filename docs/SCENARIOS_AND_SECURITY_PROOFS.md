# JFP-Paradox Edge Radar - Security Scenarios, Traces & Forensic Analysis

This document provides end-to-end technical documentation of security scenarios, terminal execution traces, defensive behaviors, and mathematical / protocol rationales for **JFP-Paradox Edge Radar v0.4.0 (Hardened Enterprise Core)**.

---

## 🧭 Architectural Philosophy: Deterministic Resource Asymmetry

Modern autonomous AI botnets and mutating exploit scanners differ fundamentally from legacy scripted attacks:
1. **Adaptive Mutating Ingress:** They leverage small, distributed reasoning models to evade static signature regexes by varying whitespace, case, URL encoding passes, and HTTP smuggling headers.
2. **Distributed State Flooding:** They cycle residential IP proxies and IPv6 allocations (`/64` subnets) to exhaust in-memory state tracking (`DashMap` / LRU caches) in defensive firewalls.
3. **Connection Hijacking & Slow Bleed:** They weaponize standard defensive timeouts and tarpits to exhaust file descriptors (`nofile` exhaustion).

JFP-Paradox Edge Radar defeats these vectors **without LLM inference overhead in the critical network path (0ms LLM latency, deterministic execution)** by enforcing mathematical and protocol asymmetry.

---

## 🔬 Threat Scenarios & Execution Traces

### Scenario 1: Mass PHP-2-Shell Exploit Interception (CVE-2026-109618 / CVE-2026-109619)

#### Threat Description
Attackers attempt to leverage PHP-CGI query-string injection (`-d allow_url_include=on`, `-d auto_prepend_file=...`) combined with environmental pollution headers (`PHP_VALUE`, `auto_prepend_file=php://input`) to achieve Remote Code Execution (RCE) on backend PHP runtimes.

#### Attacker Request
```http
POST /index.php?-d+allow_url_include=on+-d+auto_prepend_file=php://input HTTP/1.1
Host: target.internal:8080
User-Agent: Mozilla/5.0 (Mutating-Agent/4.2)
PHP_VALUE: auto_prepend_file=php://input
Content-Length: 26

<?php system('id'); ?>
```

#### Terminal Trace (Live Defense)
```bash
$ curl -i -X POST \
  -H "PHP_VALUE: auto_prepend_file=php://input" \
  --data "<?php system('id'); ?>" \
  "http://localhost:8080/index.php?-d+allow_url_include=on+-d+auto_prepend_file=php://input"
```

#### Radar Defensive Response
```http
HTTP/1.1 403 Forbidden
content-type: application/json
x-jfp-proof-hash: 6701b1eeeb52f0b1c3d2376e0eaa7ddceb35770253dc0abae4a1669be167ef69
content-length: 83
date: Thu, 22 Oct 2026 21:50:58 GMT

{"error":"Forbidden","reason":"Threat blocked by JFP Edge Radar (Hardened Shield)"}
```

#### Tamper-Evident Proof Log Entry (`/var/log/jfp/asa_radar_proof.jsonl`)
```json
{
  "counter": 2,
  "prev_hash": "8350c685cb977a08a30b7ec65e5a6b1755d33335231022eb951965e9abcf5b6f",
  "entry_hash": "6701b1eeeb52f0b1c3d2376e0eaa7ddceb35770253dc0abae4a1669be167ef69",
  "timestamp": "2026-10-22T21:50:58.632338Z",
  "event_type": "ASA_ATTACK_BLOCKED",
  "ip": "127.0.0.1",
  "payload_summary": {
    "method": "POST",
    "path": "/index.php",
    "query": "-d+allow_url_include=on+-d+auto_prepend_file=php://input",
    "delta_ms": 2946,
    "threat_assessment": {
      "anomaly_score": 1.0,
      "indicators": [
        "PHP_CGI_ARG_INJECTION: detected '-d'",
        "PHP_CGI_ARG_INJECTION: detected 'allow_url_include'",
        "PHP_TARGETED_PROBE: matching '.php'",
        "PHP_ENV_POLLUTION: unauthorized header 'php_value'",
        "TIMING_WINDOW: Delta 2946ms fits LLM reflection loop"
      ],
      "is_autonomous_agent": true,
      "recommended_action": "BlockProof"
    }
  }
}
```

#### What the System Did & Why:
1. **Zero Upstream Exposure:** The incoming socket was halted at the Edge proxy layer. Zero bytes were forwarded to the vulnerable PHP-FPM backend.
2. **Deterministic Score (1.0):** Multiple independent indicator signals triggered (CGI query args + prohibited PHP header + `.php` URI path). The composite score saturated to `1.0`.
3. **Cryptographic Proof Chain:** A deterministic SHA-256 digest (`x-jfp-proof-hash`) was calculated from the previous entry's hash combined with the canonicalized event payload, making log tampering mathematically impossible.

---

### Scenario 2: Nested Multi-Pass URL Encoding Evasion (`%252d` -> `%2d` -> `-d`)

#### Threat Description
Attackers use double or triple URL percent-encoding to bypass simple regexes. A single decode pass sees `%2d`, missing the injected `-d` parameter that backend CGI parsers subsequently expand.

#### Attacker Payload
```text
GET /index.php?%252d+allow_url_include=on
```

#### Canonical Shield Execution Trace
```text
=== [CANONICAL SHIELD TRACE] ===
Raw Query Input:        %252d+allow_url_include=on
Pass 1 Decoded:         %2d+allow_url_include=on
Pass 2 Decoded:         -+allow_url_include=on  <-- EVASION DETECTED (Double URL Encoding)
Canonical Verdict:      AmbiguityViolation::DoubleUrlEncodingDetected
Anomaly Score Assigned: 1.0 (Automatic Disqualification)
Action:                 Immediate 403 Forbidden
```

#### Why the System Behaved This Way:
The `CanonicalShield` applies **fixed-point convergence decoding** (up to 4 passes). If an input requires $> 1$ pass to reach stability, it constitutes active multi-stage obfuscation and is treated as malicious by design.

---

### Scenario 3: Autonomous AI Agent Reconnaissance & Timing Window Correlation

#### Threat Description
Autonomous LLM agents scanning targets for vulnerability discovery exhibit distinct timing characteristics. They hit structural documentation (`/AGENTS.md`, `/llms.txt`, `/.well-known/agent.json`), then pause for $1.2\text{s} - 8.5\text{s}$ while inferencing next steps via an API call, before issuing the next probe.

#### Live Event Sequence
1. **$T_0$:** Agent requests `/robots.txt` $\to$ Radar creates session snapshot in `DashMap`.
2. **$T_0 + 2000\text{ms}$:** Agent pauses during LLM prompt reflection.
3. **$T_0 + 2000\text{ms}$:** Agent requests `/AGENTS.md`.

#### Radar Detection Console Log
```text
2026-10-22T21:50:58Z WARN jfp_edge_radar::server: ASA Alert: Client IP 198.51.100.42 (Req #2) Score: 0.70 Action: BlockProof
Indicators: [
  "STRUCTURAL_RECON: AI Agent Metadata Probing ('/AGENTS.md')",
  "TIMING_WINDOW: Delta 2000ms fits LLM reflection loop (1200ms - 8500ms)"
]
```

#### Why the System Behaved This Way:
Human users in browsers do not request `/AGENTS.md` exactly $2.0$ seconds after `/robots.txt`, nor do classic vulnerability scanners (which burst at $<50\text{ms}$). Correlating structural recon endpoints with the physical latency window of LLM token generation produces near-zero false-positive detection of autonomous agents.

---

### Scenario 4: HTTP Request Smuggling (RFC 7230 §3.3.3) Disqualification

#### Threat Description
Attackers craft dual-header requests containing both `Content-Length` and `Transfer-Encoding: chunked` to desynchronize front-end reverse proxies from backend web servers (TE.CL / CL.TE attacks).

#### Incoming Request Header Vector
```http
POST /api/v1/update HTTP/1.1
Host: target.internal:8080
Content-Length: 42
Transfer-Encoding: chunked
```

#### Canonical Shield Protocol Check
```text
=== [RFC 7230 §3.3.3 VIOLATION] ===
Header: content-length: 42
Header: transfer-encoding: chunked
Verdict: AmbiguityViolation::RequestSmugglingBothLengthAndEncoding
Assigned Score: 1.0 (Critical Protocol Ambiguity)
HTTP Response: 400 Bad Request
```

#### Why the System Behaved This Way:
Rather than attempting to guess downstream server behavior or sanitize conflicting headers, the `CanonicalShield` immediately rejects protocol ambiguity at the network perimeter, eliminating request smuggling before TCP packets reach application middleware.

---

### Scenario 5: Slow-Drip Tarpit & Concurrency Cap Protection

#### Threat Description
Attackers deploy thousands of distributed bots. When hit with a defensive tarpit, they attempt to leave sockets open indefinitely to exhaust server file descriptors (`nofile`).

#### System Behavior Matrix
| Active Tarpit Sessions | Incoming Attacker IP | Radar Action | Impact on Attacker | Impact on Defense Server |
| :--- | :--- | :--- | :--- | :--- |
| **$0 \le N < 512$** | Low-confidence probe (`Score 0.35`) | **Chunked Slow-Drip (1 byte / 3s)** | Freezes attacker worker thread & inference loop | $\sim 0$ CPU (asynchronous Tokio timer) |
| **$N \ge 512$ (Cap reached)** | Malicious request | **Immediate 403 Forbidden** | Request terminated | **Zero new sockets allocated**; FD table fully protected |

#### Code Verification (`tests/integration_proxy_test.rs`)
```rust
// Socket 1 acquires active tarpit slot
let resp1 = sender1.send_request(req1).await.unwrap();
assert_eq!(resp1.headers().get("x-jfp-defense").unwrap(), "slow-drip-tarpit");

// Socket 2 arrives while cap = 1 is saturated -> Instant 403 fallback
let resp2 = sender2.send_request(req2).await.unwrap();
assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
```

---

### Scenario 6: Cryptographic Proof Chain & Tampering Detection

#### Verification Workflow
1. The radar records consecutive events $E_0, E_1, E_2$, linking each via $H_n = \text{SHA-256}(H_{n-1} + \text{CanonicalJSON}(E_n))$.
2. An adversary gains root or file access and retroactively modifies entry $E_1$ (e.g. changing `/admin.php` to `/legit.php`).
3. Running `jfp-edge-radar report` recalculates hashes and verifies link integrity.

#### Forensic Analyzer Console Output
```text
$ jfp-edge-radar report --log /var/log/jfp/asa_radar_proof.jsonl

============================================================
🔍 JFP-Paradox Edge Radar Forensic Analyzer
Analyzing proof log: /var/log/jfp/asa_radar_proof.jsonl
============================================================

❌ CRYPTOGRAPHIC VERIFICATION FAILURE!
Chain broken at Record #2:
Reported prev_hash:   24c6bbc8bc520b8f0c36842e58071c06635939ee1fefd4319f1527c5ef3764d4
Expected prev_hash:   f892a01948db7120aef1c2e402094c87102047385bb049c30f718aa019024f0c
Integrity Status: TAMPERING DETECTED! Downstream chain invalidated from record #2 onwards.
```

---

## 📊 Summary of Defense Invariants

| Attack Vector | Defense Mechanism | Invariant Guaranteed |
| :--- | :--- | :--- |
| **PHP-2-Shell (CVE-2026-109618)** | `php_signatures.rs` | No argument-injected query or `PHP_VALUE` header ever touches backend. |
| **Multi-Pass URL Encoding** | `canonical.rs` | Obfuscation requiring $>1$ decode pass is disqualified at perimeter. |
| **Autonomous AI Agents** | `analyzer.rs` | Structural probes in $1.2\text{s}-8.5\text{s}$ window flagged with high anomaly score. |
| **Request Smuggling** | `canonical.rs` | Conflicting CL/TE or control character injections returned as 400 Bad Request. |
| **State Flooding (RAM DoS)** | `tracker.rs` | IPv6 aggregated to `/64`; LRU capacity bounded at 131,072 with single-hit eviction. |
| **Tarpit FD Exhaustion** | `tarpit.rs` | Atomic concurrency guard caps concurrent sockets; fallback to hard 403. |
| **Evidence Tampering** | `proof.rs` | Immutable SHA-256 cryptographic chain prevents retroactive modification. |
