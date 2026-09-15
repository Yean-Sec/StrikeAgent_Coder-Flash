# 被 code-backend.sh / code-frontend.sh / code-up.sh source。不要直接执行。

BACKEND_UNIT=code-flash-backend.service
FRONTEND_UNIT=code-flash-frontend.service
BACKEND_PORT="${BACKEND_PORT:-8787}"
FRONTEND_PORT="${FRONTEND_PORT:-5302}"

resolve_bins() {
  NODE_BIN="$(command -v node || true)"
  NPM_BIN="$(command -v npm || true)"
  [[ -n "$NODE_BIN" ]] || die "找不到 node"
  [[ -n "$NPM_BIN" ]] || die "找不到 npm"
  RUN_HOME="${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}"
  RUN_HOME="${RUN_HOME:-${HOME:-/root}}"
}

render_unit() {
  local src="$1" dst="$2"
  resolve_bins
  sed \
    -e "s|__REPO__|$REPO|g" \
    -e "s|__NODE__|$NODE_BIN|g" \
    -e "s|__NPM__|$NPM_BIN|g" \
    -e "s|__HOME__|$RUN_HOME|g" \
    "$src" > "$dst"
  chmod 644 "$dst"
}

snapshot_agent_env() {
  local dest="${REPO}/backend/data/code-agent.env"
  DEST="$dest" /usr/bin/python3 - <<'PY'
import os, re
from pathlib import Path

dest = Path(os.environ["DEST"])
dest.parent.mkdir(parents=True, exist_ok=True)

keep_prefixes = ("ANTHROPIC_", "CLAUDE_", "DEEPSEEK_", "PI_", "OPENAI_", "STRIKEAGENT_")
existing: dict[str, str] = {}

def unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v

if dest.exists():
    for line in dest.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        existing[k.strip()] = unquote(v)

for k, v in os.environ.items():
    if re.search(r"[\n\r]", v or ""):
        continue
    if not k.startswith(keep_prefixes):
        continue
    existing[k] = v

existing.setdefault("BIND_HOST", "0.0.0.0")
existing.setdefault("PORT", os.environ.get("PORT", "8787"))

def esc(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

rows = sorted(existing.items())
dest.write_text("\n".join(f"{k}={esc(v)}" for k, v in rows) + "\n", encoding="utf-8")
os.chmod(dest, 0o600)
print(f"[*] 已写入 {len(rows)} 个环境变量到 {dest}（不打印内容）")
PY
}

kill_port() {
  local port="$1"
  if ss -H -tlnp 2>/dev/null | grep -q ":${port} "; then
    echo "[*] 释放 :${port} 上的占用 …"
    fuser -k "${port}/tcp" 2>/dev/null || true
    sleep 1
  fi
}

kill_stray_backend() {
  kill_port "$BACKEND_PORT"
}

kill_stray_frontend() {
  kill_port "$FRONTEND_PORT"
}

wait_backend_health() {
  local i
  for i in $(seq 1 40); do
    if curl -fsS -m 2 "http://127.0.0.1:${BACKEND_PORT}/api/health" >/tmp/code-health.json 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}
