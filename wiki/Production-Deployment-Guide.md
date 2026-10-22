# Production Deployment Guide 🚀

This guide explains how to deploy **JFP-Paradox Edge Radar** in production environments.

---

## 1. System Requirements & Tuning

For high-throughput ingress nodes handling $>10,000$ req/sec:

```bash
# Increase file descriptor limit in /etc/security/limits.conf
*    soft    nofile    65535
*    hard    nofile    65535

# Optimize TCP socket queue in /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
```
Apply changes:
```bash
sudo sysctl -p
```

---

## 2. Systemd Service Deployment

Create a dedicated system user and directory:
```bash
sudo useradd -r -s /bin/false jfp-radar
sudo mkdir -p /var/log/jfp
sudo chown -R jfp-radar:jfp-radar /var/log/jfp
```

Install the binary:
```bash
sudo cp target/release/jfp-edge-radar /usr/local/bin/jfp-edge-radar
sudo chmod +x /usr/local/bin/jfp-edge-radar
```

Create `/etc/systemd/system/jfp-edge-radar.service`:
```ini
[Unit]
Description=JFP-Paradox Edge Radar (ASA Defense Gateway)
After=network.target

[Service]
Type=simple
User=jfp-radar
Group=jfp-radar
Environment="RADAR_BIND_ADDR=0.0.0.0:8080"
Environment="RADAR_UPSTREAM_ADDR=127.0.0.1:8000"
Environment="RADAR_PROOF_LOG=/var/log/jfp/asa_radar_proof.jsonl"
Environment="RADAR_MAX_SESSIONS=131072"
Environment="RADAR_MAX_TARPIT_SESSIONS=512"
Environment="RUST_LOG=info"
ExecStart=/usr/local/bin/jfp-edge-radar
Restart=always
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now jfp-edge-radar
sudo systemctl status jfp-edge-radar
```

---

## 3. Cloudflare / Reverse Proxy Integration

When running behind Cloudflare or a CDN:
1. Configure `RADAR_TRUSTED_PROXIES` with Cloudflare CIDR blocks:
   ```bash
   export RADAR_TRUSTED_PROXIES="173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22"
   ```
2. The radar will unpack the true origin client IP from `CF-Connecting-IP` or `X-Forwarded-For`, preventing spoofing from untrusted public peers.
