import fs from 'fs';
import os from 'os';
import path from 'path';

const SLEEP_WAIT_SECONDS = 10;
const WRAPPED = ['find', 'grep', 'egrep', 'fgrep', 'rgrep', 'rg', 'ag', 'fd', 'locate', 'mlocate', 'sleep'] as const;

const PASS_THROUGH_ABS = new Set(['/dev/null', '/dev/stdin', '/dev/stdout', '/dev/stderr']);

function stripQuotes(token: string): string {
  return token.replace(/^['"]+|['"]+$/g, '');
}

function looksLikeAbsPath(token: string): boolean {
  const t = stripQuotes(token);
  if (PASS_THROUGH_ABS.has(t)) return false;
  if (t === '/') return true;
  if (!t.startsWith('/')) return false;
  if (t.includes('://')) return false;
  return true;
}

function isInsideRoot(absPath: string, root: string): boolean {
  const resolved = path.resolve(absPath);
  const base = path.resolve(root);
  return resolved === base || resolved.startsWith(base + path.sep);
}

/** sleep ≥ 10s：主控用来空等其它路落盘，属于空转。 */
export function sleepWaitReason(command: string): string | null {
  const re = /\bsleep(?:\s+|.*?bin\/sleep\s+)(\d+(?:\.\d+)?)\b/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(command))) {
    if (Number(m[1]) >= SLEEP_WAIT_SECONDS) {
      return `禁止 sleep ${m[1]}s 等待其它专项或 JSON 落盘；后端会等各路结束`;
    }
  }
  return null;
}

/** find/grep/rg 等以源码树之外的绝对路径为起点。 */
export function outOfTreeSearchReason(command: string, root: string): string | null {
  if (!root) return null;
  const tokens = command.split(/\s+/).map(stripQuotes).filter(Boolean);
  for (const token of tokens) {
    if (!looksLikeAbsPath(token)) continue;
    if (isInsideRoot(token, root)) continue;
    return `禁止在源码目录外检索（命中路径 ${token}）。只允许在 ${root} 内 find/grep`;
  }
  return null;
}

export function forbiddenAuditShellReason(command: string, root: string): string | null {
  return sleepWaitReason(command) || outOfTreeSearchReason(command, root);
}

function realBin(name: string): string | null {
  const aliases: Record<string, string> = {
    egrep: 'grep',
    fgrep: 'grep',
    rgrep: 'grep',
    mlocate: 'locate',
  };
  const bin = aliases[name] || name;
  for (const dir of ['/usr/bin', '/bin', '/usr/local/bin']) {
    const p = path.join(dir, bin);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

const WRAPPER = `#!/usr/bin/env bash
set -euo pipefail
cmd="$(basename "$0")"
root="\${STRIKEAGENT_AUDIT_ROOT:-}"
refuse() { echo "[StrikeAgent] $1" >&2; exit 2; }

if [[ "$cmd" == "sleep" ]]; then
  n="\${1:-0}"
  if [[ "$n" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    int="\${n%%.*}"
    if (( int >= ${SLEEP_WAIT_SECONDS} )); then
      refuse "禁止 sleep \${n}s 等待其它专项或 JSON 落盘。后端会等各路结束，请立刻结束本会话或继续在源码目录内审计。"
    fi
  fi
  exec "\${STRIKEAGENT_REAL_SLEEP:-/bin/sleep}" "$@"
fi

if [[ "$cmd" == "locate" || "$cmd" == "mlocate" ]]; then
  refuse "禁止 locate。只允许在源码目录内 Grep/Glob/find。"
fi

if [[ -n "$root" ]]; then
  for arg in "$@"; do
    case "$arg" in
      /dev/null|/dev/stdin|/dev/stdout|/dev/stderr) continue ;;
      /*)
        case "$arg" in
          "$root"|"$root"/*) ;;
          *)
            refuse "禁止在源码目录外检索（命中路径 $arg）。请在 $root 内使用相对路径。"
            ;;
        esac
        ;;
    esac
  done
fi

case "$cmd" in
  find) exec "\${STRIKEAGENT_REAL_FIND:-/usr/bin/find}" "$@" ;;
  grep|egrep|fgrep|rgrep) exec "\${STRIKEAGENT_REAL_GREP:-/usr/bin/grep}" "$@" ;;
  rg) exec "\${STRIKEAGENT_REAL_RG:-/usr/bin/rg}" "$@" ;;
  ag) exec "\${STRIKEAGENT_REAL_AG:-/usr/bin/ag}" "$@" ;;
  fd) exec "\${STRIKEAGENT_REAL_FD:-/usr/bin/fd}" "$@" ;;
  *) refuse "未知包装命令 $cmd" ;;
esac
`;

const guardCache = new Map<string, string>();

/** 生成 PATH 前置目录：包装 find/grep/sleep，拦截全盘检索与长 sleep。 */
export function createAuditPathGuardDir(root: string): string {
  const key = path.resolve(root);
  const cached = guardCache.get(key);
  if (cached && fs.existsSync(cached)) return cached;

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sa-audit-bin-'));
  const script = path.join(dir, '_guard.sh');
  fs.writeFileSync(script, WRAPPER, { encoding: 'utf8', mode: 0o755 });
  for (const name of WRAPPED) {
    if (name !== 'sleep' && !realBin(name) && !['egrep', 'fgrep', 'rgrep', 'mlocate'].includes(name)) {
      continue;
    }
    const dest = path.join(dir, name);
    try {
      fs.symlinkSync(script, dest);
    } catch {
      fs.copyFileSync(script, dest);
      fs.chmodSync(dest, 0o755);
    }
  }
  guardCache.set(key, dir);
  return dir;
}

export function auditGuardSpawnEnv(root: string): NodeJS.ProcessEnv {
  const bin = createAuditPathGuardDir(root);
  const extra: NodeJS.ProcessEnv = {
    STRIKEAGENT_AUDIT_ROOT: path.resolve(root),
    PATH: `${bin}${path.delimiter}${process.env.PATH || ''}`,
  };
  const find = realBin('find');
  const grep = realBin('grep');
  const sleep = realBin('sleep');
  const rg = realBin('rg');
  const ag = realBin('ag');
  const fd = realBin('fd');
  if (find) extra.STRIKEAGENT_REAL_FIND = find;
  if (grep) extra.STRIKEAGENT_REAL_GREP = grep;
  if (sleep) extra.STRIKEAGENT_REAL_SLEEP = sleep;
  if (rg) extra.STRIKEAGENT_REAL_RG = rg;
  if (ag) extra.STRIKEAGENT_REAL_AG = ag;
  if (fd) extra.STRIKEAGENT_REAL_FD = fd;
  return extra;
}

export const AUDIT_GUARD_CHANNELS = new Set(['main', 'subagent', 'codeverify']);
