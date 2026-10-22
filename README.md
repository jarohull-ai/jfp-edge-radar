# JFP-Paradox Edge Radar (ASA - Autonomous Agent Sniffer)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/badge/crates.io-v0.3.0-red.svg)](https://crates.io/crates/jfp-edge-radar)

Lekki, deterministyczny system obronny w języku **Rust** w ekosystemie **JARO Flash Protocol (JFP)**, zaprojektowany jako brzegowy radar oraz bramka inline (Reverse Proxy) wykrywająca wrogie autonomiczne botnety AI, mutujące skanery exploitów oraz ataki sterty/OOM na serwery PHP (w tym **PHP-2-Shell: CVE-2026-109618 i CVE-2026-109619**).

---

## 🏛️ Nowości w wersji v0.3.0 (Operational Defense & Forensics)

1. **Strumieniowy Slow-Drip Tarpit (Chunked Slow-Drip Body):**
   * Zamiast zwykłego odrzucania połączeń (które uwalnia wątki atakującego), radar uruchamia asynchroniczny strumień HTTP `Transfer-Encoding: chunked`, wysyłając **1 bajt danych co $N$ sekund** (domyślnie 3s).
   * **Wpływ na atakującego:** Blokuje pule połączeń bota, paraliżuje pętle inferencyjne agentów AI i zmusza atakującego do marnowania własnych zasobów pamięci i tokenów przy zerowym narzucie na procesor serwera.

2. **Automatyczny TTL Banów (Kernel Hygiene):**
   * Reguły `iptables -I INPUT -s <IP> -j DROP` posiadają teraz konfigurowalny czas życia (`RADAR_BAN_TTL_SECS`, domyślnie 3600s).
   * Wątek w tle samoczynnie usuwa wygasłe reguły z jądra Linuxa, zapobiegając degradacji tablicy routingu i puchnięciu pamięci kernela.

3. **Moduł Forensyki i Raportowania (`jfp-edge-radar report`):**
   * Dedykowana podkomenda CLI analizująca kryptograficzny łańcuch `proof.jsonl`.
   * **Weryfikacja kryptograficzna:** Sprawdza poprawność każdego hasha SHA-256 w łańcuchu (wykrywa próby sfałszowania historii).
   * **Generacja raportu:** Tworzy gotowy do audytu raport incydentu w formacie Markdown z rozkładem wektorów, listą top atakujących i oszacowaniem zaoszczędzonych tokenów LLM.

4. **Real Client IP Anti-Spoofing:**
   * Ekstrakcja `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP` i `X-Forwarded-For` wyłącznie od zaufanych podsieci (`RADAR_TRUSTED_PROXIES`).

5. **Tryb Audytowy (Dry-Run / Canary Mode):**
   * Bezpieczny rozruch na produkcji (`RADAR_DRY_RUN=1`) bez ryzyka False Positives.

---

## 📂 Struktura projektu

```text
jfp-edge-radar/
├── Cargo.toml
├── README.md
├── tests/
│   └── integration_proxy_test.rs # E2E tests: Reverse Proxy, Attack Block, Dry-Run & Tarpit
└── src/
    ├── lib.rs                    # Eksport biblioteki
    ├── main.rs                   # CLI demona sieciowego & komenda report
    ├── config.rs                 # Konfiguracja (bind, upstream, TTL, Tarpit, Dry-Run)
    ├── ip_extractor.rs           # Anti-spoofing Real Client IP (Cloudflare / Nginx)
    ├── mitigation.rs             # OS Kernel Mitigation z automatycznym TTL (iptables)
    ├── tarpit.rs                 # Asynchroniczny strumień SlowDripBody (1 byte / N sec)
    ├── report.rs                 # Silnik weryfikacji hashy i generator raportów SOC
    ├── tracker.rs                # SessionTracker: DashMap<IpAddr, IpSession>
    ├── php_signatures.rs         # Silnik detekcji PHP-2-Shell / OOM / CGI
    ├── analyzer.rs               # ASA Engine (Timing + Heurystyki + Mutacje)
    ├── proof.rs                  # ProofLogger: Tamper-Evident SHA-256 z rotacją
    └── server.rs                 # Reverse Proxy & Defensive Handlers (Tokio + Hyper 1.x)
```

---

## 🚀 Uruchomienie

### 1. Testy automatyczne
```bash
cargo test
```

### 2. Uruchomienie jako Reverse Proxy z Tarpitem i TTL
```bash
export RADAR_BIND_ADDR="0.0.0.0:8080"
export RADAR_UPSTREAM_ADDR="127.0.0.1:80"
export RADAR_ENABLE_IPTABLES=1
export RADAR_BAN_TTL_SECS=3600
export RADAR_TARPIT_DRIP_MS=3000
export RADAR_PROOF_LOG="/var/log/jfp/asa_radar_proof.jsonl"

cargo run --release
```

### 3. Generowanie raportu forensycznego dla SOC
```bash
# Analiza logu i wygenerowanie raportu Markdown
jfp-edge-radar report --log /var/log/jfp/asa_radar_proof.jsonl --out incident_report.md
```
