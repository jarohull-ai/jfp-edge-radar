# JFP-Paradox Edge Radar (ASA - Autonomous Agent Sniffer)

Lekki, deterministyczny system obronny w języku **Rust** w ekosystemie **JARO Flash Protocol (JFP)**, zaprojektowany jako brzegowy radar oraz bramka inline (Reverse Proxy) wykrywająca wrogie autonomiczne botnety AI, mutujące skanery exploitów oraz ataki sterty/OOM na serwery PHP (w tym **PHP-2-Shell: CVE-2026-109618 i CVE-2026-109619**).

---

## 🏛️ Główne filary architektoniczne

1. **Inline Reverse Proxy Gateway:**
   * Działa jako inteligentna brama brzegowa przed Twoimi właściwymi serwisami (np. Nginx, API w chmurze, aplikacje PHP).
   * Czysty ruch jest bezstratnie przekazywany do upstreamu z zachowaniem nagłówków `X-Forwarded-For`, `X-Forwarded-Proto` oraz wstrzyknięciem nagłówka inspekcji `X-JFP-Inspected: clean`.
   * Ataki są blokowane natychmiast na brzegu sieci, chroniąc backend przed wyczerpaniem pamięci (OOM) czy RCE.

2. **Dedykowany silnik sygnatur PHP-2-Shell (CVE-2026-109618 / CVE-2026-109619):**
   * **OOM Heap Exhaustion:** Wykrywanie zmutowanych nagłówków `multipart/form-data; boundary=...`, podwójnych deklaracji `Transfer-Encoding: chunked`, nadmiarowych nagłówków MIME oraz zapytań o nienaturalnych rozmiarach.
   * **SAPI / FPM Environment Pollution:** Blokowanie nagłówków środowiskowych (`PHP_VALUE`, `PHP_ADMIN_VALUE`, `HTTP_PROXY`), prób wstrzykiwania opcji PHP-CGI (`-d allow_url_include=1`, `auto_prepend_file=php://input`, `%ADd+...`).
   * **Targeted Debug Probing:** Wykrywanie prób dotarcia do konsol debugowania (`_ignition`, `telescope`, `vendor/phpunit`, `phpinfo`).

3. **Deterministyczna detekcja zachowań autonomicznych agentów AI (ASA):**
   * **Timing Windows:** Identyfikacja charakterystycznego okna myślenia LLM ($1200\text{ms} - 8500\text{ms}$) pomiędzy kolejnymi zapytaniami agenta.
   * **Adaptive Mutation Loops:** Wykrywanie ponawiania lekko zmutowanego żądania w oknie myślenia po napotkaniu kodów `403` lub `422`.
   * **Strukturalny rekonesans:** Wykrywanie prób odpytywania o specyfikację agentów (`AGENTS.md`, `llms.txt`, `.well-known/agent*`).

4. **Tamper-Evident Proof Logging (JFP-Paradox Standard):**
   * Niezaprzeczalny kryptograficzny rejestr zdarzeń w formacie JSONL:
     $$\text{entry\_hash} = \text{SHA256}(\text{prev\_hash} + \text{canonical\_json})$$
   * Dołączany nagłówek `X-JFP-Proof-Hash: <entry_hash>` przy decyzjach blokujących.

---

## 📂 Struktura projektu

```text
jfp-edge-radar/
├── Cargo.toml
├── README.md
├── tests/
│   └── integration_proxy_test.rs # Test E2E: Upstream backend + Radar Gateway + Interception
└── src/
    ├── lib.rs                    # Eksport biblioteki
    ├── main.rs                   # CLI demona sieciowego
    ├── config.rs                 # Konfiguracja (bind, upstream, TTL, logi)
    ├── tracker.rs                # SessionTracker: DashMap<IpAddr, IpSession>
    ├── php_signatures.rs         # Silnik detekcji PHP-2-Shell / OOM / CGI
    ├── analyzer.rs               # ASA Engine (Timing + Heurystyki + Mutacje)
    ├── proof.rs                  # ProofLogger: Tamper-Evident SHA-256 chain
    └── server.rs                 # Reverse Proxy & Defensive Handlers (Tokio + Hyper 1.x)
```

---

## 🚀 Uruchomienie

### 1. Uruchomienie testów (jednostkowe + integracyjne)
```bash
cargo test
```

### 2. Uruchomienie jako Reverse Proxy przed Twoim backendem
```bash
# Proxy nasłuchuje na porcie 8080 i przekazuje czysty ruch do Nginx / backendu na porcie 80
export RADAR_BIND_ADDR="0.0.0.0:8080"
export RADAR_UPSTREAM_ADDR="127.0.0.1:80"
export RADAR_PROOF_LOG="/var/log/jfp/asa_radar_proof.jsonl"

cargo run --release
```

### 3. Uruchomienie jako samodzielny Honeynet / Sensor
```bash
unset RADAR_UPSTREAM_ADDR
cargo run --release
```
