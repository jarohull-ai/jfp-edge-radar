# Architecture & The Three Shields (v0.4.0)

Version **0.4.0** of JFP-Paradox Edge Radar introduces the **Hardened Enterprise Core**, designed to withstand red-team state-exhaustion and evasive botnet attacks.

---

## 🏛️ System Component Flow

```
                      INCOMING REQUEST STREAM
                                 │
                                 ▼
                   ┌───────────────────────────┐
                   │    1. Canonical Shield    │
                   │   • RFC 7230 §3.3.3 Check │
                   │   • Fixed-Point URL Decode│
                   │   • Path Segment Scrubber │
                   └─────────────┬─────────────┘
                                 │
                                 ▼
                   ┌───────────────────────────┐
                   │  2. Client IP & State     │
                   │   • Trusted CIDR Unpacking│
                   │   • IPv6 /64 Aggregation  │
                   │   • Bounded LRU (131k Cap)│
                   └─────────────┬─────────────┘
                                 │
                                 ▼
                   ┌───────────────────────────┐
                   │     3. ASA Engine Core    │
                   │   • LLM Reflection Window │
                   │   • Structural Recon Flags│
                   │   • PHP-2-Shell Signatures│
                   └─────────────┬─────────────┘
                                 │
       ┌─────────────────────────┼─────────────────────────┐
       ▼                         ▼                         ▼
 [Score < 0.30]            [Score 0.3-0.6]           [Score > 0.60]
Forward Upstream        Slow-Drip Tarpit           Instant 403 Forbidden
Backend Protected       (Cap: 512 Sockets)         SHA-256 Proof Logged
```

---

## 🛡️ Shield 1: State Flooding Shield (Memory Protection)

### The Threat
Modern residential proxy botnets cycle millions of IPv6 addresses. If an in-memory tracking structure allocates an entry per unique host IP, the firewall exhausts system RAM (OOM Killer trigger).

### The Defense
1. **IPv6 Subnet Masking (`/64`):**  
   Every IPv6 address is canonicalized using bitmask retention on the first 64 bits (`segs[0..4]`). All hosts within the same `/64` allocation map to the identical session bucket in `DashMap`.
2. **Bounded LRU with Single-Hit Pruning:**  
   The capacity is capped by `RADAR_MAX_SESSIONS` (default `131,072`). When the table exceeds capacity:
   * Sessions with `total_requests == 1` (one-hit scanners) are aggressively pruned first.
   * Older sessions are evicted in LRU order, preventing memory inflation.

---

## 🛡️ Shield 2: Protocol Ambiguity & Request Smuggling Shield

### The Threat
Attackers inject conflicting transport headers (`Content-Length` combined with `Transfer-Encoding: chunked`) to cause front-end/back-end desynchronization (HTTP Request Smuggling, RFC 7230 §3.3.3 violations).

### The Defense
* **Zero Downstream Ambiguity:** Any request exhibiting conflicting content boundaries is rejected immediately with `400 Bad Request`.
* **Control Character Rejection:** Headers containing null bytes (`\0`), Carriage Returns (`\r`), or Line Feeds (`\n`) are instantly disqualified.
* **Fixed-Point URL Decoding:** Runs up to 4 decoding passes. Inputs containing nested encoding (`%252d` $\to$ `%2d` $\to$ `-d`) are detected on pass $\ge 2$ and assigned an anomaly score of `1.0`.

---

## 🛡️ Shield 3: Slow-Drip Tarpit Concurrency Guard

### The Threat
A defensive tarpit drains the attacker's resources by dripping bytes slowly. However, if an attacker floods 100,000 connections into the tarpit, the *defensive server* exhausts its own file descriptors (`nofile` exhaustion).

### The Defense
* **Atomic Concurrency Cap:** An `Arc<AtomicUsize>` counter tracks live active tarpit sockets (default limit: 512).
* **RAII Drop Guard:** When a socket closes or times out, the guard automatically decrements the active counter.
* **Automatic 403 Fallback:** When `active_tarpits >= max_tarpit_concurrency`, any further low/medium severity probe bypasses the tarpit and is immediately closed with `403 Forbidden`. **Zero hanging sockets are allocated.**
