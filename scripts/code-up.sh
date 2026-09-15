#!/usr/bin/env bash
# 一键把 StrikeAgent_Coder-Flash 前后端交给 systemd（崩溃 / 卡死数秒内拉起，不依赖 Cursor shell）。
# 用法: sudo scripts/code-up.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
"$REPO/scripts/code-backend.sh" install
"$REPO/scripts/code-frontend.sh" install
echo
echo "[*] 控制台: http://127.0.0.1:5302/"
echo "[*] API:    http://127.0.0.1:8787/api/health"
echo "[*] 之后不要在临时 shell 里再跑 npm run dev / tsx watch（会抢端口、热重载会掐审计）"
echo "[*] 无 systemd 时可用: scripts/code-daemon.sh start"
