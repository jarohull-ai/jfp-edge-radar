# Configuration & Tuning Reference ⚙️

All runtime settings are configured via environment variables.

---

## 📋 Complete Variables Reference

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `RADAR_BIND_ADDR` | SocketAddr | `0.0.0.0:8080` | Interface and port for incoming traffic. |
| `RADAR_UPSTREAM_ADDR` | SocketAddr | `None` | Upstream backend application to protect. |
| `RADAR_PROOF_LOG` | Path | `/var/log/jfp/asa_radar_proof.jsonl` | Path to cryptographic audit ledger. |
| `RADAR_DRY_RUN` | Bool | `false` | Audit mode: logs threats but forwards traffic. |
| `RADAR_MAX_SESSIONS` | Usize | `131072` | Bounded capacity for in-memory IP sessions. |
| `RADAR_MAX_TARPIT_SESSIONS` | Usize | `512` | Max concurrent Slow-Drip Tarpit sockets. |
| `RADAR_TARPIT_DRIP_MS` | U64 | `3000` | Delay between single byte chunks in tarpit. |
| `RADAR_ENABLE_IPTABLES` | Bool | `false` | Enables automated OS kernel firewall bans. |
| `RADAR_BAN_TTL_SECS` | U64 | `86400` | Duration of kernel ban before auto-unban. |
| `RADAR_TRUSTED_PROXIES` | String | `""` | Comma-separated CIDR blocks for trusted proxies. |
| `RADAR_MAX_SEGMENT_MB` | U64 | `10` | Size threshold in MB for proof log rotation. |
| `RUST_LOG` | String | `info` | Logging verbosity (`error`, `warn`, `info`, `debug`). |

---

## 🎯 High-Traffic Production Tuning

```bash
# Recommended environment for high-throughput edge nodes
export RADAR_BIND_ADDR="0.0.0.0:80"
export RADAR_UPSTREAM_ADDR="127.0.0.1:8000"
export RADAR_MAX_SESSIONS="262144"
export RADAR_MAX_TARPIT_SESSIONS="1024"
export RADAR_TARPIT_DRIP_MS="2500"
export RADAR_BAN_TTL_SECS="43200"
export RADAR_PROOF_LOG="/var/log/jfp/asa_radar_proof.jsonl"
```
