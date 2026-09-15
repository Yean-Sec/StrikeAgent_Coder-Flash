#!/usr/bin/env bash
# 无 systemd / 无 sudo 时的后台常驻：supervisor 探活拉起后端 + nohup 前端。
# 用法: scripts/code-daemon.sh {start|stop|restart|status}
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$REPO/backend/data/logs"
PID_DIR="$REPO/backend/data"
BACKEND_PID_FILE="$PID_DIR/daemon-backend.pid"
FRONTEND_PID_FILE="$PID_DIR/daemon-frontend.pid"
BACKEND_PORT="${PORT:-8787}"
FRONTEND_PORT="${FRONTEND_PORT:-5302}"
BIND_HOST="${BIND_HOST:-0.0.0.0}"

die() { echo "error: $*" >&2; exit 1; }

alive_pid() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  local pid
  pid="$(tr -d ' \n' < "$f" || true)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

stop_pidfile() {
  local f="$1" name="$2"
  if alive_pid "$f"; then
    local pid
    pid="$(tr -d ' \n' < "$f")"
    echo "[*] 停止 $name pid=$pid"
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$f"
}

cmd_stop() {
  stop_pidfile "$FRONTEND_PID_FILE" frontend
  stop_pidfile "$BACKEND_PID_FILE" backend
  # supervisor 会再写 data/supervisor.pid / backend.pid
  if [[ -f "$PID_DIR/supervisor.pid" ]] && alive_pid "$PID_DIR/supervisor.pid"; then
    kill "$(tr -d ' \n' < "$PID_DIR/supervisor.pid")" 2>/dev/null || true
  fi
  if ss -H -tlnp 2>/dev/null | grep -q ":${BACKEND_PORT} "; then
    fuser -k "${BACKEND_PORT}/tcp" 2>/dev/null || true
  fi
  if ss -H -tlnp 2>/dev/null | grep -q ":${FRONTEND_PORT} "; then
    fuser -k "${FRONTEND_PORT}/tcp" 2>/dev/null || true
  fi
  echo "[*] daemon 已停"
}

cmd_start() {
  mkdir -p "$LOG_DIR"
  if curl -fsS -m 2 "http://127.0.0.1:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
    echo "[*] 后端 ${BACKEND_PORT} 已在响应，跳过拉起"
  else
    echo "[*] 后台拉起 supervisor（探活失败会在约 0.5–6s 内重启后端）…"
    (
      cd "$REPO/backend"
      nohup env BIND_HOST="$BIND_HOST" PORT="$BACKEND_PORT" \
        node --disable-warning=DEP0169 supervisor.mjs \
        >>"$LOG_DIR/daemon-backend.log" 2>&1 &
      echo $! >"$BACKEND_PID_FILE"
    )
  fi

  local i
  for i in $(seq 1 40); do
    if curl -fsS -m 2 "http://127.0.0.1:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done

  if curl -fsS -m 2 -o /dev/null "http://127.0.0.1:${FRONTEND_PORT}/" 2>/dev/null; then
    echo "[*] 前端 ${FRONTEND_PORT} 已在响应，跳过拉起"
  else
    echo "[*] 后台拉起 Vite 前端…"
    (
      cd "$REPO"
      nohup env BIND_HOST="$BIND_HOST" FRONTEND_PORT="$FRONTEND_PORT" BACKEND_PORT="$BACKEND_PORT" PORT="$BACKEND_PORT" \
        npm run dev:frontend \
        >>"$LOG_DIR/daemon-frontend.log" 2>&1 &
      echo $! >"$FRONTEND_PID_FILE"
    )
  fi

  cmd_status
  echo "[*] 日志: $LOG_DIR/daemon-backend.log / daemon-frontend.log"
  echo "[*] 有 systemd 时请改用: sudo scripts/code-up.sh"
}

cmd_status() {
  if curl -fsS -m 3 "http://127.0.0.1:${BACKEND_PORT}/api/health" >/tmp/code-health.json 2>/dev/null; then
    echo "backend: UP $(cat /tmp/code-health.json)"
  else
    echo "backend: DOWN"
  fi
  code="$(curl -sS -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${FRONTEND_PORT}/" 2>/dev/null || echo 000)"
  echo "frontend: HTTP $code"
  alive_pid "$BACKEND_PID_FILE" && echo "daemon-backend.pid=$(tr -d ' \n' < "$BACKEND_PID_FILE")" || true
  alive_pid "$FRONTEND_PID_FILE" && echo "daemon-frontend.pid=$(tr -d ' \n' < "$FRONTEND_PID_FILE")" || true
}

cmd_restart() {
  cmd_stop
  sleep 1
  cmd_start
}

case "${1:-}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  *) echo "用法: $0 {start|stop|restart|status}"; exit 1 ;;
esac
