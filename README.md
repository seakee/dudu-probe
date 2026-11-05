# dudu-probe

[中文文档](./README.zh-CN.md)

Lightweight, zero-CGO server monitoring probe agent for **Dudu Server Monitor**.

## Features

- **Zero CGO Static Binary**: Built with pure Go + `gopsutil/v3`, runs out-of-the-box on any Linux (`amd64`, `arm64`, `386`, `arm`, `mipsle`), macOS, or Windows machine.
- **Comprehensive Telemetry**:
  - Static metadata: Hostname, OS/Kernel version, CPU model & cores, total RAM/Swap/Disk, private IP, boot time.
  - Real-time metrics: CPU usage, Load Average (`1m/5m/15m`), RAM & Swap usage, per-partition disk usage & disk I/O speed, real-time network ingress/egress speed & cumulative traffic, active TCP/UDP connections, process count, and uptime.
  - Hardware insights: CPU package/core temperature plus up to 8 sensor readings, and the Top 5 processes by CPU usage (PID, name, CPU%, mem%, RSS).
  - Network quality: concurrent lightweight TCP-ping probing against server-assigned targets (e.g. the three Chinese carriers, home broadband, Cloudflare) reporting latency and packet loss.
- **Server-Driven Self-Upgrade**: The agent compares `target_version` delivered in the heartbeat response with its own version and upgrades in place (mirror acceleration supported), so no inbound port or manual SSH is required.
- **Authenticated Reporting**: Every payload is signed with `HMAC-SHA256(node_key + timestamp + body, secret)`.
- **One-Command Persistent Deployment**: Auto-detects `systemd`, `OpenRC` (Alpine), `procd` (OpenWrt), and `launchd` (macOS).

## Quick Start

### 1. One-Line Install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh | sudo bash -s -- \
  --server "https://your-dudu-server.example.com" \
  --key "probe_xxxxxx" \
  --secret "sec_yyyyyyyyyyyy"
```

Upgrade or uninstall:
```bash
# Upgrade binary while keeping existing config
curl -fsSL https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh | sudo bash -s -- upgrade

# Uninstall service and remove files
curl -fsSL https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh | sudo bash -s -- uninstall
```

### 2. Docker Deployment

```bash
docker run -d --name dudu-probe --restart=always \
  --net=host --pid=host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  -v /:/host/root:ro \
  -e HOST_PROC=/host/proc \
  -e HOST_SYS=/host/sys \
  -e HOST_ETC=/host/etc \
  -e HOST_ROOT=/host/root \
  -e DUDU_PROBE_SERVER="https://your-dudu-server.example.com" \
  -e DUDU_PROBE_KEY="probe_xxxxxx" \
  -e DUDU_PROBE_SECRET="sec_yyyyyyyyyyyy" \
  ghcr.io/seakee/dudu-probe:latest
```

### 3. Local Inspection

```bash
./bin/dudu-probe -inspect
```
