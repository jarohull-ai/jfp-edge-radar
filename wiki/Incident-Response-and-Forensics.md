# Incident Response & Forensics 🔍

JFP-Paradox Edge Radar implements an immutable, tamper-evident cryptographic ledger designed for legal evidence preservation and Security Operations Center (SOC) incident response.

---

## 🔐 The JFP-Paradox Proof Chain

Every defensive action (attack blocked, honeynet deception, or tarpit session) is chained using SHA-256:

$$\text{EntryHash}_n = \text{SHA-256}\left(\text{PrevHash}_{n-1} \parallel \text{CanonicalJSON}(E_n)\right)$$

* **Block 0 Seed:** Begins with 64 zeros (`0000000000000000000000000000000000000000000000000000000000000000`).
* **Header Verification:** Every blocked HTTP response includes the header `x-jfp-proof-hash: <EntryHash>`.
* **Automated Rotation:** Rotates at 10 MB per segment with cryptographic continuity seals (`ASA_SEGMENT_ROTATION_SEAL`).

---

## 🚨 CLI Forensic Verification

To audit the proof ledger on disk:
```bash
jfp-edge-radar report --log /var/log/jfp/asa_radar_proof.jsonl
```

### Exporting Markdown Reports for SOC / Executives
```bash
jfp-edge-radar report \
  --log /var/log/jfp/asa_radar_proof.jsonl \
  --out /tmp/soc_incident_report_$(date +%F).md
```

### Tamper Detection
If any record is modified, inserted, or deleted retroactively by an intruder or compromised process, the verification engine pinpoints the exact record:
```text
❌ CRYPTOGRAPHIC VERIFICATION FAILURE!
Chain broken at Record #42:
Reported prev_hash:   24c6bbc8bc520b8f0c36842e58071c06635939ee1fefd4319f1527c5ef3764d4
Expected prev_hash:   f892a01948db7120aef1c2e402094c87102047385bb049c30f718aa019024f0c
Integrity Status: TAMPERING DETECTED!
```

---

## 🖥️ Live NOC Console Monitoring

Launch the live terminal dashboard:
```bash
jfp-edge-radar monitor --log /var/log/jfp/asa_radar_proof.jsonl
```

Displays:
* Cumulative attacks blocked & tarpitted
* Unique attacking IPs
* Live attack vector distribution
* Estimated LLM tokens burned by adversaries
