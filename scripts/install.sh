#!/usr/bin/env bash
# ==============================================================================
# dudu-probe 一键安装 / 升级 / 卸载 / 常驻守护管理脚本
# 支持系统: Linux (systemd / OpenRC / OpenWrt procd), macOS (launchd)
#
# 用法示例:
#   curl -fsSL https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh | sudo bash -s -- \
#     --server "https://api.example.com" \
#     --key "probe_xxxx" \
#     --secret "sec_yyyy"
#
#   升级: curl -fsSL .../install.sh | sudo bash -s -- upgrade
#   卸载: curl -fsSL .../install.sh | sudo bash -s -- uninstall
# ==============================================================================
set -euo pipefail

REPO="${DUDU_PROBE_REPO:-seakee/dudu-probe}"
BINARY_NAME="dudu-probe"
INSTALL_BIN="/usr/local/bin/${BINARY_NAME}"
CONFIG_DIR="/etc/dudu-probe"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SYSTEMD_UNIT="/etc/systemd/system/dudu-probe.service"
OPENRC_INIT="/etc/init.d/dudu-probe"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.seakee.dudu-probe.plist"
LAUNCHD_LOG="/var/log/dudu-probe.log"
LAUNCHD_ERR="/var/log/dudu-probe.err"
TMP_DIR=""

cleanup_tmp() {
  if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup_tmp EXIT

ACTION="install"
SERVER_URL="${DUDU_PROBE_SERVER:-}"
NODE_KEY="${DUDU_PROBE_KEY:-}"
SECRET="${DUDU_PROBE_SECRET:-}"
INTERVAL="${DUDU_PROBE_INTERVAL:-10}"
VERSION="${DUDU_PROBE_VERSION:-latest}"
MIRROR="${DUDU_PROBE_MIRROR:-}"
INSECURE="false"

info()  { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m[ OK ]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()   { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|upgrade|uninstall|status|restart)
      ACTION="$1"
      shift
      ;;
    --server|-s)
      SERVER_URL="${2:-}"
      shift 2
      ;;
    --key|-k)
      NODE_KEY="${2:-}"
      shift 2
      ;;
    --secret|-p)
      SECRET="${2:-}"
      shift 2
      ;;
    --interval|-i)
      INTERVAL="${2:-10}"
      shift 2
      ;;
    --version|-v)
      VERSION="${2:-latest}"
      shift 2
      ;;
    --mirror|-m)
      MIRROR="${2:-}"
      shift 2
      ;;
    --insecure)
      INSECURE="true"
      shift
      ;;
    *)
      err "未知参数: $1"
      ;;
  esac
done

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "请使用 root 权限或 sudo 运行此脚本"
  fi
}

detect_platform() {
  local os arch
  os="$(uname -s | tr 'A-Z' 'a-z')"
  arch="$(uname -m)"

  case "$os" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    *)      err "暂不支持的操作系统: $os" ;;
  esac

  case "$arch" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    i386|i686)      ARCH="386" ;;
    armv7*|armv6*)  ARCH="arm" ;;
    mipsel|mipsle)  ARCH="mipsle" ;;
    *)              err "暂不支持的 CPU 架构: $arch" ;;
  esac
}

stop_service() {
  if [[ "$(uname -s)" == "Darwin" && -f "$LAUNCHD_PLIST" ]]; then
    launchctl unload "$LAUNCHD_PLIST" >/dev/null 2>&1 || true
  elif command -v systemctl >/dev/null 2>&1 && [[ -f "$SYSTEMD_UNIT" ]]; then
    systemctl stop dudu-probe >/dev/null 2>&1 || true
  elif command -v rc-service >/dev/null 2>&1 && [[ -f "$OPENRC_INIT" ]]; then
    rc-service dudu-probe stop >/dev/null 2>&1 || true
  elif [[ "$(uname -s)" == "Linux" && -f /etc/rc.common && -f "$OPENRC_INIT" ]]; then
    "$OPENRC_INIT" stop >/dev/null 2>&1 || true
  fi
}

uninstall_probe() {
  require_root
  info "正在停止并卸载 dudu-probe ..."
  stop_service
  if command -v systemctl >/dev/null 2>&1 && [[ -f "$SYSTEMD_UNIT" ]]; then
    systemctl disable dudu-probe >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_UNIT"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if command -v rc-update >/dev/null 2>&1 && [[ -f "$OPENRC_INIT" ]]; then
    rc-update del dudu-probe default >/dev/null 2>&1 || true
  elif [[ "$(uname -s)" == "Linux" && -f /etc/rc.common && -f "$OPENRC_INIT" ]]; then
    "$OPENRC_INIT" disable >/dev/null 2>&1 || true
  fi
  rm -f "$OPENRC_INIT" "$LAUNCHD_PLIST" "$INSTALL_BIN" "$LAUNCHD_LOG" "$LAUNCHD_ERR"
  rm -rf "$CONFIG_DIR"
  ok "dudu-probe 已彻底卸载"
}

download_binary() {
  detect_platform
  local tag="$VERSION"
  local prefix=""
  if [[ -n "$MIRROR" ]]; then
    prefix="${MIRROR%/}/"
  fi

  if [[ "$tag" == "latest" ]]; then
    info "正在查询 GitHub 最新 Release 版本..."
    if [[ -z "$MIRROR" ]]; then
      tag="$(curl -fsSL --connect-timeout 8 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -Eo '"tag_name": *"[^"]+"' | head -n1 | cut -d'"' -f4 || true)"
    fi
    if [[ -z "$tag" ]]; then
      local effective_url
      effective_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' --connect-timeout 10 "${prefix}https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
      if [[ "$effective_url" == *"/releases/tag/"* ]]; then
        tag="${effective_url##*/releases/tag/}"
        tag="${tag%%\?*}"
      fi
    fi
    if [[ -z "$tag" ]]; then
      err "无法获取最新版本号，请使用 --version 指定版本（如 v1.0.0）"
    fi
  fi

  local ver_num="${tag#v}"
  local tarball="${BINARY_NAME}_${ver_num}_${OS}_${ARCH}.tar.gz"
  local url="${prefix}https://github.com/${REPO}/releases/download/${tag}/${tarball}"
  cleanup_tmp
  TMP_DIR="$(mktemp -d)"

  info "正在下载 ${url} ..."
  curl -fL --retry 3 --connect-timeout 15 -o "${TMP_DIR}/${tarball}" "$url"
  tar -xzf "${TMP_DIR}/${tarball}" -C "$TMP_DIR"

  local bin_path
  bin_path="$(find "$TMP_DIR" -type f -name "$BINARY_NAME" | head -n1)"
  if [[ -z "$bin_path" ]]; then
    err "解压后未找到 ${BINARY_NAME} 可执行文件"
  fi

  mkdir -p "$(dirname "$INSTALL_BIN")"
  stop_service
  cp -f "$bin_path" "$INSTALL_BIN"
  chmod 0755 "$INSTALL_BIN"
  ok "已安装二进制至 ${INSTALL_BIN} ($(${INSTALL_BIN} -version))"
  cleanup_tmp
  TMP_DIR=""
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/}"
  s="${s//$'\r'/}"
  printf "%s" "$s"
}

write_config() {
  mkdir -p "$CONFIG_DIR"
  chmod 0700 "$CONFIG_DIR"

  if [[ "$ACTION" == "upgrade" && -f "$CONFIG_FILE" && -z "$SERVER_URL" ]]; then
    info "升级模式：保留现有配置文件 ${CONFIG_FILE}"
    return
  fi

  if [[ -z "$SERVER_URL" || -z "$NODE_KEY" || -z "$SECRET" ]]; then
    if [[ -f "$CONFIG_FILE" ]]; then
      info "未传入新凭证，保留现有配置文件 ${CONFIG_FILE}"
      return
    fi
    err "首次安装必须提供 --server、--key 和 --secret 参数"
  fi

  if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [[ "$INTERVAL" -lt 2 ]]; then
    err "--interval 必须为大于等于 2 的正整数"
  fi

  local esc_server esc_key esc_secret
  esc_server="$(json_escape "$SERVER_URL")"
  esc_key="$(json_escape "$NODE_KEY")"
  esc_secret="$(json_escape "$SECRET")"

  cat >"$CONFIG_FILE" <<EOF
{
  "server_url": "${esc_server}",
  "node_key": "${esc_key}",
  "secret": "${esc_secret}",
  "report_interval_sec": ${INTERVAL},
  "http_timeout_sec": 10,
  "insecure_tls": ${INSECURE},
  "enable_gzip": false,
  "host_root": "/"
}
EOF
  chmod 0600 "$CONFIG_FILE"
  ok "配置文件已写入 ${CONFIG_FILE}"
}

setup_service() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    mkdir -p "$(dirname "$LAUNCHD_PLIST")"
    cat >"$LAUNCHD_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.seakee.dudu-probe</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_BIN}</string>
    <string>-config</string>
    <string>${CONFIG_FILE}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>StandardOutPath</key>
  <string>${LAUNCHD_LOG}</string>
  <key>StandardErrorPath</key>
  <string>${LAUNCHD_ERR}</string>
</dict>
</plist>
EOF
    launchctl unload "$LAUNCHD_PLIST" >/dev/null 2>&1 || true
    launchctl load -w "$LAUNCHD_PLIST"
    ok "macOS launchd 服务已启动并设为常驻"
  elif command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    cat >"$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Dudu Server Probe Agent
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_BIN} -config ${CONFIG_FILE}
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now dudu-probe
    ok "systemd 服务已启动并设置为开机自启 (systemctl status dudu-probe)"
  elif command -v rc-service >/dev/null 2>&1; then
    mkdir -p "$(dirname "$OPENRC_INIT")"
    cat >"$OPENRC_INIT" <<EOF
#!/sbin/openrc-run
name="dudu-probe"
description="Dudu Server Probe Agent"
command="${INSTALL_BIN}"
command_args="-config ${CONFIG_FILE}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
respawn_delay=5
respawn_max=0
EOF
    chmod +x "$OPENRC_INIT"
    rc-update add dudu-probe default
    rc-service dudu-probe restart
    ok "OpenRC 服务已启动并设为开机自启"
  elif [[ "$(uname -s)" == "Linux" && -f /etc/rc.common && -d /etc/init.d ]]; then
    cat >"$OPENRC_INIT" <<EOF
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command ${INSTALL_BIN} -config ${CONFIG_FILE}
    procd_set_param respawn
    procd_close_instance
}
EOF
    chmod +x "$OPENRC_INIT"
    "$OPENRC_INIT" enable
    if "$OPENRC_INIT" running >/dev/null 2>&1; then
      "$OPENRC_INIT" restart
    else
      "$OPENRC_INIT" start
    fi
    ok "OpenWrt procd 服务已启动并设为开机自启"
  else
    warn "未检测到受支持的 init 系统，请手动后台运行: ${INSTALL_BIN} -config ${CONFIG_FILE}"
  fi
}
status_service() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    launchctl list | grep com.seakee.dudu-probe || info "dudu-probe 未在运行"
  elif command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl status dudu-probe --no-pager
  elif command -v rc-service >/dev/null 2>&1 && [[ -f "$OPENRC_INIT" ]]; then
    rc-service dudu-probe status
  elif [[ "$(uname -s)" == "Linux" && -f /etc/rc.common && -f "$OPENRC_INIT" ]]; then
    "$OPENRC_INIT" status || true
  else
    pgrep -fl dudu-probe || info "dudu-probe 未在运行"
  fi
}

restart_service() {
  require_root
  if [[ "$(uname -s)" == "Darwin" && -f "$LAUNCHD_PLIST" ]]; then
    launchctl unload "$LAUNCHD_PLIST" >/dev/null 2>&1 || true
    launchctl load -w "$LAUNCHD_PLIST"
  elif command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl restart dudu-probe
  elif command -v rc-service >/dev/null 2>&1 && [[ -f "$OPENRC_INIT" ]]; then
    rc-service dudu-probe restart
  elif [[ "$(uname -s)" == "Linux" && -f /etc/rc.common && -f "$OPENRC_INIT" ]]; then
    "$OPENRC_INIT" restart
  else
    err "未检测到已注册的系统服务"
  fi
  ok "dudu-probe 已重启"
}

case "$ACTION" in
  uninstall)
    uninstall_probe
    ;;
  status)
    status_service
    ;;
  restart)
    restart_service
    ;;
  install|upgrade)
    require_root
    download_binary
    write_config
    setup_service
    ;;
esac
