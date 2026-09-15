#!/usr/bin/env bash
# StrikeAgent_Coder-Flash 前端常驻：systemd 拉起 Vite :5302，崩溃自动重启。
# 用法: scripts/code-frontend.sh {install|start|stop|restart|status|logs|uninstall}
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_SRC="$REPO/deploy/systemd/code-frontend.service"
UNIT_DST="/etc/systemd/system/code-flash-frontend.service"
LOG_DIR="$REPO/backend/data/logs"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [[ "$(id -u)" -eq 0 ]] || die "需要 root（sudo）"; }

# shellcheck source=/dev/null
source "$REPO/scripts/_code-systemd.sh"

cmd_install() {
  need_root
  command -v npm >/dev/null || die "找不到 npm"
  [[ -f "$UNIT_SRC" ]] || die "找不到 unit: $UNIT_SRC"
  [[ -d "$REPO/frontend/node_modules" || -d "$REPO/node_modules" ]] || die "先在仓库根执行 npm run install:all"
  mkdir -p "$LOG_DIR"
  kill_stray_frontend
  render_unit "$UNIT_SRC" "$UNIT_DST"
  systemctl daemon-reload
  systemctl enable "$FRONTEND_UNIT"
  systemctl restart "$FRONTEND_UNIT"
  sleep 1
  cmd_status
  echo "[*] 前端已常驻。之后请用本脚本 restart，勿在 Cursor shell 里前台跑 npm run dev"
}

cmd_start() {
  need_root
  mkdir -p "$LOG_DIR"
  systemctl start "$FRONTEND_UNIT"
  cmd_status
}

cmd_stop() {
  need_root
  systemctl stop "$FRONTEND_UNIT"
  cmd_status
}

cmd_restart() {
  need_root
  mkdir -p "$LOG_DIR"
  if [[ ! -f "$UNIT_DST" ]]; then
    cmd_install
    return
  fi
  render_unit "$UNIT_SRC" "$UNIT_DST"
  systemctl daemon-reload
  systemctl restart "$FRONTEND_UNIT"
  sleep 1
  cmd_status
}

cmd_status() {
  systemctl --no-pager --full status "$FRONTEND_UNIT" || true
  echo "---"
  code="$(curl -sS -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${FRONTEND_PORT}/" 2>/dev/null || echo 000)"
  echo "vite: HTTP $code (${FRONTEND_PORT})"
}

cmd_logs() {
  need_root
  journalctl -u "$FRONTEND_UNIT" -n "${1:-80}" --no-pager
}

cmd_uninstall() {
  need_root
  systemctl disable --now "$FRONTEND_UNIT" 2>/dev/null || true
  rm -f "$UNIT_DST"
  systemctl daemon-reload
  echo "[*] 已卸载前端 systemd unit"
}

usage() {
  echo "用法: $0 {install|start|stop|restart|status|logs|uninstall}"
}

case "${1:-}" in
  install) cmd_install ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  logs) cmd_logs "${2:-80}" ;;
  uninstall) cmd_uninstall ;;
  *) usage; exit 1 ;;
esac
