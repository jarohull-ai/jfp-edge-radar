# Deep Tarpit Economy & Prometheus Metrics

## 1. Asymmetric Warfare Against Botnets & Autonomous Scanners

Traditional Web Application Firewalls (WAFs) and edge filters rely on fast termination (`403 Forbidden` or `404 Not Found`). In modern automated attacks, this gives an unfair economic advantage to the adversary:

* **Attacker Costs:** Near zero. Botnets rotate residential proxy IPs or VPN endpoints within milliseconds. Their multi-threaded scanner scripts simply move to the next target without loss of concurrency.
* **Defender Costs:** High. The defending server must parse the TCP handshake, evaluate rules, generate an error body, flush socket buffers, and write logs to disk.

**JFP-Paradox Edge Radar v0.4.3 reverses this economic asymmetry through Deep Tarpit Slow-Drip streaming.**

---

## 2. Dynamic Asymmetric Slow-Drip Architecture

When incoming traffic is scored with suspicious timing or structural reconnaissance indicators (anomaly score `0.30 - 0.60` or classified as an autonomous agent), the gateway engages the slow-drip tarpit engine:

```
Adversary Scanner (Python requests, Go http, Axios)
                       │
                       ▼ (HTTP Request)
          ┌──────────────────────────────┐
          │  JFP Edge Radar v0.4.3 Gate  │
          └──────────────┬───────────────┘
                         │
        DefensiveAction::Tarpit Engaged
                         │
                         ▼
          ┌──────────────────────────────┐
          │ SlowDripBody (Hyper 1.x Body)│
          │ • Tick: 1 chunk / 3,000ms    │
          │ • Zero server-side memory    │
          │ • Non-closing stream         │
          └──────────────┬───────────────┘
                         │
                 Adversary Impact:
        - Thread/coroutine blocked indefinitely
        - Client RAM buffers payload until OOM crash
```

### Lethal Sink Payload Modes:

1. **`InfiniteJsonSink` (Autonomous Agents / API Scanners):**
   * Target: Endpoints matching `/api`, `.json`, or requests with `Accept: application/json`.
   * Mechanism: Generates an infinite unclosed JSON document:
     ```json
     {"status":"active_sync","protocol":"jfp-paradox-v0.4.3","stream":[{"node_id":0,"depth":0,"data":[
       {"node_id":1,"depth":1,"timestamp":1729679000,"entropy":"...
     ```
   * Result: Standard client parsers (`requests.json()`, `json.loads()`, `json.Unmarshal`, `axios`) buffer chunks into RAM waiting for the root `]}` closing tokens, rapidly inducing Out-Of-Memory (OOM) crashes on the adversary's C2 machine.

2. **`InfiniteHtmlSink` (Headless Browsers & Web Scrapers):**
   * Target: Endpoints matching `.php`, `.html`, `/admin`, `/wp-`, or requests with `Accept: text/html`.
   * Mechanism: Streams unclosed HTML table and DOM structures:
     ```html
     <!DOCTYPE html><html><head><title>JFP Security Gateway</title></head><body><table><tbody>
       <tr><td>1</td><td>Stream Node 1</td><td>...
     ```
   * Result: Headless browser engines (Puppeteer, Playwright, Selenium, Chromium) allocate megabytes of DOM nodes per second until the worker process is terminated by the kernel OOM killer.

3. **`RawChaff`:**
   * Streams uncompressed pseudo-random binary noise for arbitrary non-HTTP protocol probes.

---

## 3. Server-Side Safety & Resource Guarantees

* **Zero-Allocation Stream Generation:** Each chunk is synthesized dynamically during the timer tick; the server retains zero state in RAM.
* **Atomic Concurrency Cap:** Limited by `RADAR_MAX_TARPIT_SESSIONS` (default `512`). If the tarpit queue is full, traffic falls back instantly to `403 Forbidden` to prevent exhausting the operating system's `nofile` socket descriptor limit.
* **RAII Lifecycle Telemetry:** When an adversary connection terminates, a drop guard updates global atomic counters (`GLOBAL_TARPIT_SECONDS_DRAINED` and `GLOBAL_TARPIT_BYTES_DRAINED`).

---

## 4. Real-Time Prometheus Metrics (`/metrics`)

JFP-Paradox Edge Radar exposes native OpenMetrics / Prometheus scrape endpoints directly on the ingress port:

```bash
curl -s http://127.0.0.1:8080/metrics
```

### Metrics Dictionary:

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `jfp_radar_up` | Gauge | Daemon operational status (`1` = healthy). |
| `jfp_radar_tracked_sessions_total` | Gauge | Number of active client IP sessions tracked in bounded LRU memory. |
| `jfp_radar_active_tarpits` | Gauge | Current number of adversary sockets trapped in the slow-drip tarpit. |
| `jfp_radar_tarpit_seconds_drained_total` | Counter | Cumulative adversary compute/thread seconds wasted in the tarpit. |
| `jfp_radar_tarpit_bytes_drained_total` | Counter | Cumulative asymmetric entropy bytes served to adversary sockets. |
| `jfp_radar_proof_events_total{action="..."}` | Counter | Cryptographically sealed security events by action (`block`, `honey`, `tarpit`, `dry_run`, `total`). |
| `jfp_radar_unique_attackers` | Gauge | Total unique attacker IP addresses recorded in the cryptographic ledger. |
| `jfp_radar_cryptographic_chain_intact` | Gauge | Cryptographic SHA-256 chain verification status (`1` = intact, `0` = tampered). |
