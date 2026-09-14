// 零依赖后端守护进程：拉起后端子进程，崩溃/被杀后按退避自动重启，
// 并把每次退出的 code/signal/uptime/时间滚动记入 data/supervisor.log。
//
// 背景：后端进程会因大库下的 V8 堆溢出（heap out of memory，退出码 134）或被 OS
// OOM-killer 杀（SIGKILL）而直接消失，且 process.on('uncaughtException') 抓不住这两类；
// 后端此前挂在前台终端裸跑、无任何 supervisor，一崩就永久停摆。此守护负责恢复与取证。
//
// 用法：node backend/supervisor.mjs（见根 package.json 的 start / start:backend / start:web）。
// 环境变量：
//   BACKEND_MAX_OLD_SPACE_MB  子进程 V8 老生代堆上限（MB），默认 4096。
//   PORT / BIND_HOST          透传给后端；用于 EADDRINUSE 探活判定。

import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const backendDir = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(backendDir, 'data');
const logFile = path.join(dataDir, 'supervisor.log');

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.BIND_HOST || '127.0.0.1';
const maxOldSpaceMb = Number(process.env.BACKEND_MAX_OLD_SPACE_MB || 4096);

// 退避：初始 1s，指数翻倍，封顶 30s；子进程健康存活 ≥60s 视为正常运行，退避重置。
const BACKOFF_MIN_MS = 1_000;
const BACKOFF_MAX_MS = 30_000;
const HEALTHY_UPTIME_MS = 60_000;
const LOG_MAX_LINES = 2_000;

let backoffMs = BACKOFF_MIN_MS;
let child = null;
let shuttingDown = false;
let restartTimer = null;

function ts() {
  return new Date().toISOString();
}

function appendLog(line) {
  const entry = `[${ts()}] ${line}\n`;
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.appendFileSync(logFile, entry);
    // 滚动截断：超过上限行数时只保留最近 LOG_MAX_LINES 行，避免无限增长。
    const stat = fs.statSync(logFile);
    if (stat.size > 512 * 1024) {
      const lines = fs.readFileSync(logFile, 'utf8').split('\n');
      if (lines.length > LOG_MAX_LINES) {
        fs.writeFileSync(logFile, lines.slice(-LOG_MAX_LINES).join('\n'));
      }
    }
  } catch {
    /* 记日志失败不影响守护本身 */
  }
  process.stdout.write(`[supervisor] ${line}\n`);
}

// 探活：EADDRINUSE 快速退出后，确认端口上是否已有健康后端在跑。
function probeHealth(timeoutMs = 2_000) {
  return new Promise((resolve) => {
    const req = http.get(
      { host: HOST, port: PORT, path: '/api/health', timeout: timeoutMs },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

function resolveEntry() {
  // 单进程直起：node --import tsx src/index.ts，服务器就是本子进程本身，
  // 这样能精准拿到它的退出 code/signal（区分 V8 OOM=134 与 OS OOM-kill=SIGKILL）。
  // 校验 tsx 可解析，缺失则显式报错而非静默失败。
  require.resolve('tsx');
  return {
    cmd: process.execPath,
    args: ['--disable-warning=DEP0169', '--import', 'tsx', 'src/index.ts'],
  };
}

function buildEnv() {
  const extras = [`--max-old-space-size=${maxOldSpaceMb}`, '--disable-warning=DEP0169'];
  const existing = (process.env.NODE_OPTIONS || '').split(/\s+/).filter(Boolean);
  for (const flag of extras) {
    const key = flag.split('=')[0];
    if (!existing.some((p) => p === flag || p.startsWith(`${key}=`))) existing.push(flag);
  }
  return { ...process.env, NODE_OPTIONS: existing.join(' ') };
}

function scheduleRestart() {
  if (shuttingDown) return;
  appendLog(`将在 ${Math.round(backoffMs / 1000)}s 后重启后端…`);
  // 关键：不要 unref——子进程已退出时，这个定时器是唯一让事件循环存活的句柄，
  // unref 会让守护在重启前就自行退出（曾导致「记完 SIGKILL 后守护也没了」）。
  restartTimer = setTimeout(start, backoffMs);
  backoffMs = Math.min(backoffMs * 2, BACKOFF_MAX_MS);
}

function start() {
  restartTimer = null;
  const { cmd, args } = resolveEntry();
  const startedAt = Date.now();
  child = spawn(cmd, args, { cwd: backendDir, env: buildEnv(), stdio: 'inherit' });

  child.on('exit', (code, signal) => {
    const uptimeMs = Date.now() - startedAt;
    child = null;
    const upSec = (uptimeMs / 1000).toFixed(1);
    appendLog(
      `后端子进程退出：code=${code ?? 'null'} signal=${signal ?? 'null'} uptime=${upSec}s` +
        (signal === 'SIGKILL'
          ? '（疑似被 OS OOM-killer 杀）'
          : code === 134 || code === 137
            ? '（疑似 V8 堆溢出 heap out of memory）'
            : '')
    );

    if (shuttingDown) {
      process.exit(0);
      return;
    }

    // 快速退出：可能是端口被占用（已有后端实例）。注意 index.ts 的 EADDRINUSE 会被其
    // 全局 uncaughtException 兜底吞掉、最终以 code=0 退出，故这里不看退出码，一律探活：
    // 端口上若已有健康后端在应答，说明是重复实例 → 守护退出（不重复拉起，避免多实例抢占）；
    // 端口已空说明是真崩溃 → 正常走退避重启。
    if (uptimeMs < 5_000) {
      void probeHealth().then((alive) => {
        if (alive) {
          appendLog(`检测到 ${HOST}:${PORT} 已有健康后端在运行，守护退出（不重复拉起）。`);
          process.exit(0);
        } else {
          scheduleRestart();
        }
      });
      return;
    }

    // 健康存活过阈值 → 视为正常运行后的偶发崩溃，退避重置为最小值。
    if (uptimeMs >= HEALTHY_UPTIME_MS) backoffMs = BACKOFF_MIN_MS;
    scheduleRestart();
  });

  child.on('error', (err) => {
    appendLog(`拉起后端失败：${err?.message || err}`);
    if (!shuttingDown) scheduleRestart();
  });

  appendLog(
    `已拉起后端：${cmd} ${args.join(' ')}（--max-old-space-size=${maxOldSpaceMb}，pid=${child.pid}）`
  );
}

function shutdown(sig) {
  if (shuttingDown) return;
  shuttingDown = true;
  appendLog(`收到 ${sig}，正在停止后端…`);
  if (restartTimer) {
    clearTimeout(restartTimer);
    restartTimer = null;
  }
  if (child) {
    child.kill(sig);
    // 兜底：宽限期后仍未退出则强杀，避免留下孤儿。
    const force = setTimeout(() => {
      if (child) child.kill('SIGKILL');
      process.exit(0);
    }, 10_000);
    if (typeof force.unref === 'function') force.unref();
  } else {
    process.exit(0);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
// 兜底：守护自身因任何可捕获原因退出时，同步带走子进程，杜绝孤儿后端继续占端口。
process.on('exit', () => {
  if (child && child.pid) {
    try {
      process.kill(child.pid, 'SIGKILL');
    } catch {
      /* 子进程已退出 */
    }
  }
});

appendLog('后端守护启动。');
start();
