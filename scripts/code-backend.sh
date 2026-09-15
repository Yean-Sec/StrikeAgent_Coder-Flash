#!/usr/bin/env bash
# StrikeAgent_Coder-Flash 后端常驻：systemd 拉起 supervisor.mjs（探活失败数秒内重启）。
# 用法: scripts/code-backend.sh {install|start|stop|restart|status|logs|uninstall}
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_SRC="$REPO/deploy/systemd/code-backend.service"
UNIT_DST="/etc/systemd/system/code-flash-backend.service"
LOG_DIR="$REPO/backend/data/logs"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [[ "$(id -u)" -eq 0 ]] || die "需要 root（sudo）"; }

# shellcheck source=/dev/null
source "$REPO/scripts/_code-systemd.sh"

cmd_install() {
  need_root
  [[ -f "$UNIT_SRC" ]] || die "找不到 unit: $UNIT_SRC"
  [[ -d "$REPO/node_modules" || -d "$REPO/backend/node_modules" ]] || die "先在仓库根执行 npm run install:all"
  mkdir -p "$LOG_DIR"
  snapshot_agent_env
  kill_stray_backend
  render_unit "$UNIT_SRC" "$UNIT_DST"
  systemctl daemon-reload
  systemctl enable "$BACKEND_UNIT"
  systemctl restart "$BACKEND_UNIT"
  wait_backend_health || true
  cmd_status
  echo "[*] 后端已常驻。之后请用本脚本 restart，勿在 Cursor shell 里前台跑 npm run dev / tsx watch"
}

cmd_start() {
  need_root
  mkdir -p "$LOG_DIR"
  snapshot_agent_env
  systemctl start "$BACKEND_UNIT"
  wait_backend_health || true
  cmd_status
}

cmd_stop() {
  need_root
  systemctl stop "$BACKEND_UNIT"
  cmd_status
}

cmd_restart() {
  need_root
  mkdir -p "$LOG_DIR"
  if [[ ! -f "$UNIT_DST" ]]; then
    cmd_install
    return
  fi
  snapshot_agent_env
  render_unit "$UNIT_SRC" "$UNIT_DST"
  systemctl daemon-reload
  systemctl restart "$BACKEND_UNIT"
  wait_backend_health || true
  cmd_status
}

cmd_status() {
  systemctl --no-pager --full status "$BACKEND_UNIT" || true
  echo "---"
  if curl -fsS -m 3 "http://127.0.0.1:${BACKEND_PORT}/api/health" >/tmp/code-health.json 2>/dev/null; then
    python3 - <<'PY' || echo "health: $(cat /tmp/code-health.json)"
import json
d=json.load(open("/tmp/code-health.json"))
print(f"health: ok={d.get('ok')} pid={d.get('pid')} ts={d.get('ts')}")
PY
  else
    echo "health: DOWN (${BACKEND_PORT} 无响应)"
  fi
}

cmd_logs() {
  need_root
  journalctl -u "$BACKEND_UNIT" -n "${1:-80}" --no-pager
}

cmd_uninstall() {
  need_root
  systemctl disable --now "$BACKEND_UNIT" 2>/dev/null || true
  rm -f "$UNIT_DST"
  systemctl daemon-reload
  echo "[*] 已卸载后端 systemd unit"
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
