# dudu-probe

[English](./README.md)

轻量级、零 CGO 依赖的跨平台服务器监控探针，配合 **Dudu 服务端与 Dudu Dashboard** 实现多服务器实时状态监控、历史趋势分析与离线/高负载飞书告警。

## 核心特性

- **零依赖静态单文件**：基于 Go + `gopsutil/v3` 静态编译（`CGO_ENABLED=0`），支持 `linux/amd64`、`linux/arm64`、`linux/386`、`linux/arm`、`linux/mipsle`、`darwin`、`windows`。
- **全维度指标采集**：
  - **静态元信息**：主机名、操作系统发行版与内核版本、CPU 型号与核数、总内存/Swap/磁盘容量、内网 IP、启动时间。
  - **实时性能指标**：CPU 使用率、系统平均负载（1/5/15 分钟）、内存与 Swap 使用率、各真实磁盘挂载点使用率与读写速率、实时上下行网速与累计总流量、TCP/UDP 连接数、进程数、在线时长。
  - **硬件与进程洞察**：CPU 主温度与最多 8 个温度传感器读数、CPU 占用 Top 5 进程快照（PID / 进程名 / CPU% / 内存% / RSS）。
  - **网络质量拨测**：并发对服务端下发的拨测目标（三网公共节点、家宽动态 IP、Cloudflare 等）执行轻量 TCP Ping，上报握手延迟与丢包率。
- **服务端驱动的远程自升级**：心跳响应中的 `target_version` 高于本机版本时自动下载并平滑重启（支持镜像加速），无需开放入站端口或手动 SSH。
- **安全签名通信**：每次请求均使用 `HMAC-SHA256(node_key + timestamp + body, secret)` 签名防篡改与防重放，支持 Gzip 压缩与服务端动态调整上报间隔。
- **一键安装与常驻自启**：自动适配 `systemd`（Ubuntu/Debian/CentOS/Rocky/Arch）、`OpenRC`（Alpine）、`procd`（OpenWrt）与 `launchd`（macOS）。

## 快速部署

### 1. 一键安装常驻脚本

```bash
curl -fsSL https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh | sudo bash -s -- \
  --server "https://your-dudu-server.example.com" \
  --key "probe_xxxxxx" \
  --secret "sec_yyyyyyyyyyyy"
```

使用国内 GitHub 镜像加速安装：
```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh | sudo bash -s -- \
  --mirror "https://ghfast.top" \
  --server "https://your-dudu-server.example.com" \
  --key "probe_xxxxxx" \
  --secret "sec_yyyyyyyyyyyy"
```

日常维护：
```bash
# 平滑升级探针版本（保留原配置）
curl -fsSL https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh | sudo bash -s -- upgrade

# 卸载探针服务与配置
curl -fsSL https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh | sudo bash -s -- uninstall
```

### 2. Docker 容器常驻运行

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

### 3. 本地采集自检

```bash
make build
./bin/dudu-probe -inspect
```
