# JFP-Paradox Edge Radar (ASA - Autonomous Agent Sniffer)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/badge/crates.io-v0.4.0-red.svg)](https://crates.io/crates/jfp-edge-radar)

Lekki, deterministyczny system obronny w języku **Rust** w ekosystemie **JARO Flash Protocol (JFP)**, zaprojektowany jako brzegowy radar oraz bramka inline (Reverse Proxy) wykrywająca wrogie autonomiczne botnety AI, mutujące skanery exploitów oraz ataki sterty/OOM na serwery PHP (w tym **PHP-2-Shell: CVE-2026-109618 i CVE-2026-109619**).

---

## 🏛️ Trzy Tarcze v0.4.0 Hardened Enterprise Core

W wersji **v0.4.0** system został poddany bezkompromisowemu hardeningowi przeciwko zaawansowanym botnetom przyszłości, neutralizując 3 krytyczne wektory asymetryczne:

### 1. State Flooding Shield (Ochrona Pamięci RAM)
* **Agregacja IPv6 `/64`:** Wszystkie rotujące adresy IPv6 botnetów są automatycznie maskowane do prefiksu `/64` (`canonicalize_tracking_ip`), uniemożliwiając rozproszenie stanu sesji.
* **Bounded LRU & One-Hit Eviction:** Twardy limit pojemności mapy sesji (`RADAR_MAX_SESSIONS_CAPACITY`, domyślnie 131,072). Przy nasyceniu tablicy silnik natychmiastowo usuwa jednorazowe uderzenia botów (`total_requests == 1`), eliminując ryzyko OOM (Out-Of-Memory DoS) na serwerze obronnym.

### 2. Protocol Ambiguity & Smuggling Shield
* **Fixed-Point URL Decoding:** Wieloprzebiegowe odkodowywanie URL w pętli wyłapujące zaciemnianie podwójnym lub potrójnym kodowaniem (`%252d`, `%25ADd`).
* **Smuggling Disqualification (Score 1.0):** Wykrywanie niejednoznaczności protokołu HTTP (jednoczesne występowanie `Content-Length` i `Transfer-Encoding`, sprzeczne nagłówki, wstrzykiwanie znaków kontrolnych `\0`, `\r`, `\n`) i ich natychmiastowe odrzucenie z kodem `400 Bad Request`.
* **Path Canonicalization:** Normalizacja ścieżek URI (`/./`, `/../`, powtarzające się slashe `///`) przed przekazaniem do analizatora i backendu.

### 3. File Descriptor Exhaustion Guard (Ochrona Tarpitu)
* **Atomic Concurrency Cap:** Twardy limit aktywnych gniazd TCP w pułapce Tarpit (`RADAR_MAX_TARPIT_SESSIONS`, domyślnie 512).
* **RAII Drop Counter:** Precyzyjne zliczanie otwartych deskryptorów w locie. W momencie osiągnięcia limitu kolejne złośliwe pakiety **nie otrzymują wiszącego gniazda**, lecz są natychmiast ucinane twardym `403 BlockProof`, chroniąc limit `nofile` systemu operacyjnego przed wyczerpaniem.

---

## 📂 Struktura projektu

```text
jfp-edge-radar/
├── Cargo.toml
├── README.md
├── tests/
│   └── integration_proxy_test.rs # E2E tests: Proxy, Dry-Run, Tarpit, Cap & Smuggling
└── src/
    ├── lib.rs                    # Eksport biblioteki
    ├── main.rs                   # CLI demona & komendy report/monitor
    ├── canonical.rs              # Fixed-Point URL Decode & Request Smuggling Shield
    ├── config.rs                 # Konfiguracja (bind, upstream, TTL, Tarpit, Cap)
    ├── ip_extractor.rs           # Anti-spoofing Real Client IP (Cloudflare / Nginx)
    ├── mitigation.rs             # OS Kernel Mitigation z automatycznym TTL (iptables)
    ├── tarpit.rs                 # SlowDripBody z RAII TarpitGuard (1 byte / N sec)
    ├── monitor.rs                # Terminal NOC Live Monitor Dashboard
    ├── report.rs                 # Silnik weryfikacji hashy i generator raportów SOC
    ├── tracker.rs                # SessionTracker: Bounded State + IPv6 /64 Aggregation
    ├── php_signatures.rs         # Silnik detekcji PHP-2-Shell / OOM / CGI
    ├── analyzer.rs               # ASA Engine (Timing + Heurystyki + Mutacje)
    ├── proof.rs                  # ProofLogger: Tamper-Evident SHA-256 z rotacją
    └── server.rs                 # Reverse Proxy & Defensive Handlers (Tokio + Hyper 1.x)
```

---

## 🚀 Uruchomienie

### 1. Testy automatyczne (22/22)
```bash
cargo test
```

### 2. Produkcyjne uruchomienie w trybie Hardened Enterprise
```bash
export RADAR_BIND_ADDR="0.0.0.0:8080"
export RADAR_UPSTREAM_ADDR="127.0.0.1:80"
export RADAR_ENABLE_IPTABLES=1
export RADAR_BAN_TTL_SECS=3600
export RADAR_MAX_TARPIT_SESSIONS=512
export RADAR_MAX_SESSIONS_CAPACITY=131072
export RADAR_PROOF_LOG="/var/log/jfp/asa_radar_proof.jsonl"

jfp-edge-radar
```

### 3. Ekran Radaru na żywo (Live NOC Terminal)
```bash
jfp-edge-radar monitor --log /tmp/jfp_radar_proof.jsonl
```

### 4. Generowanie raportu forensycznego dla SOC
```bash
jfp-edge-radar report --log /tmp/jfp_radar_proof.jsonl --out incident_report.md
```
