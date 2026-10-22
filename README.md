# JFP-Paradox Edge Radar (ASA - Autonomous Agent Sniffer)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/badge/crates.io-v0.2.0-red.svg)](https://crates.io/crates/jfp-edge-radar)

Lekki, deterministyczny system obronny w języku **Rust** w ekosystemie **JARO Flash Protocol (JFP)**, zaprojektowany jako brzegowy radar oraz bramka inline (Reverse Proxy) wykrywająca wrogie autonomiczne botnety AI, mutujące skanery exploitów oraz ataki sterty/OOM na serwery PHP (w tym **PHP-2-Shell: CVE-2026-109618 i CVE-2026-109619**).

---

## 🏛️ Główne filary architektoniczne (v0.2.0 Enterprise Hardening)

1. **Inline Reverse Proxy Gateway & Anti-Spoofing:**
   * Działa jako inteligentna brama brzegowa przed Twoimi właściwymi serwisami (np. Nginx, API w chmurze, aplikacje PHP).
   * **Real Client IP Extraction:** Bezpieczne wyciąganie prawdziwego IP klienta za Cloudflare (`CF-Connecting-IP`, `True-Client-IP`) oraz Nginx (`X-Real-IP`, `X-Forwarded-For`). Posiada mechanizm anty-spoofingowy: nagłówki proxy są uwzględniane **tylko wtedy**, gdy bezpośredni peer należy do listy zaufanych podsieci (`RADAR_TRUSTED_PROXIES`).
   * Czysty ruch jest bezstratnie przekazywany do upstreamu z nagłówkiem `X-JFP-Inspected: clean`.

2. **Dedykowany silnik sygnatur PHP-2-Shell (CVE-2026-109618 / CVE-2026-109619):**
   * **OOM Heap Exhaustion:** Wykrywanie zmutowanych nagłówków `multipart/form-data; boundary=...`, podwójnych deklaracji `Transfer-Encoding: chunked`, nadmiarowych nagłówków MIME oraz zapytań o nienaturalnych rozmiarach.
   * **SAPI / FPM Environment Pollution:** Blokowanie nagłówków środowiskowych (`PHP_VALUE`, `PHP_ADMIN_VALUE`, `HTTP_PROXY`), prób wstrzykiwania opcji PHP-CGI (`-d allow_url_include=1`, `auto_prepend_file=php://input`, `%ADd+...`).
   * **Targeted Debug Probing:** Wykrywanie prób dotarcia do konsol debugowania (`_ignition`, `telescope`, `vendor/phpunit`, `phpinfo`).

3. **Deterministyczna detekcja zachowań autonomicznych agentów AI (ASA):**
   * **Timing Windows:** Identyfikacja charakterystycznego okna myślenia LLM ($1200\text{ms} - 8500\text{ms}$) pomiędzy kolejnymi zapytaniami agenta.
   * **Adaptive Mutation Loops:** Wykrywanie ponawiania lekko zmutowanego żądania w oknie myślenia po napotkaniu kodów `403` lub `422`.
   * **Strukturalny rekonesans:** Wykrywanie prób odpytywania o specyfikację agentów (`AGENTS.md`, `llms.txt`, `.well-known/agent*`).

4. **Automatyczna blokada jądra systemu (OS Kernel Mitigation - iptables):**
   * Opcjonalna flaga `RADAR_ENABLE_IPTABLES=1` automatycznie wstawia reguły `iptables -I INPUT -s <IP> -j DROP` dla napastników o krytycznym scoringu zagrożenia, całkowicie odcinając pakiety na poziomie jądra Linuxa i chroniąc zasoby sieciowe.
   * Zabezpieczenie przed samoblokadą: automatyczna biała lista dla adresów loopback i prywatnych podsieci.

5. **Kryptograficzny Tamper-Evident Proof Log z ciągłą rotacją:**
   * Niezaprzeczalny kryptograficzny rejestr zdarzeń SHA-256 w formacie JSONL:
     $$\text{entry\_hash} = \text{SHA256}(\text{prev\_hash} + \text{canonical\_json})$$
   * **Bezpieczna rotacja segmentów:** Po osiągnięciu zadanego limitu rozmiaru (np. 10MB) plik jest archiwizowany z pieczęcią `PROOF_SEGMENT_SEAL`, a nowy plik zachowuje ciągłość hashy z poprzedniego segmentu.

6. **Tryb audytowy (Dry-Run / Canary Mode):**
   * Flaga `RADAR_DRY_RUN=1` pozwala na uruchomienie radaru w trybie pasywnym – symuluje detekcje, loguje audyt w ProofLogu i terminalu, bez ucinania ruchu ani blokowania IP w iptables. Idealne do bezpiecznego wdrożenia na produkcji bez ryzyka False Positives.

---

## 📂 Struktura projektu

```text
jfp-edge-radar/
├── Cargo.toml
├── README.md
├── tests/
│   └── integration_proxy_test.rs # E2E tests: Reverse Proxy, Attack Block & Dry-Run
└── src/
    ├── lib.rs                    # Eksport biblioteki
    ├── main.rs                   # CLI demona sieciowego
    ├── config.rs                 # Konfiguracja (bind, upstream, dry-run, iptables)
    ├── ip_extractor.rs           # Anti-spoofing Real Client IP (Cloudflare / Nginx)
    ├── mitigation.rs             # OS Kernel Firewall Drop (iptables)
    ├── tracker.rs                # SessionTracker: DashMap<IpAddr, IpSession>
    ├── php_signatures.rs         # Silnik detekcji PHP-2-Shell / OOM / CGI
    ├── analyzer.rs               # ASA Engine (Timing + Heurystyki + Mutacje)
    ├── proof.rs                  # ProofLogger: Tamper-Evident SHA-256 z rotacją
    └── server.rs                 # Reverse Proxy & Defensive Handlers (Tokio + Hyper 1.x)
```

---

## 🚀 Uruchomienie

### 1. Testy jednostkowe i integracyjne
```bash
cargo test
```

### 2. Produkcyjne uruchomienie jako bramka Reverse Proxy z ochroną iptables
```bash
# Proxy nasłuchuje na 8080 i przekazuje czysty ruch do Nginx na 80
export RADAR_BIND_ADDR="0.0.0.0:8080"
export RADAR_UPSTREAM_ADDR="127.0.0.1:80"
export RADAR_ENABLE_IPTABLES=1
export RADAR_TRUSTED_PROXIES="127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
export RADAR_PROOF_LOG="/var/log/jfp/asa_radar_proof.jsonl"

cargo run --release
```

### 3. Tryb audytowy (Dry-Run / Canary)
```bash
export RADAR_DRY_RUN=1
export RADAR_UPSTREAM_ADDR="127.0.0.1:80"
cargo run --release
```
