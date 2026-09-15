// 零依赖后端守护：拉起后端子进程；崩溃、被杀、卡死（/api/health 无响应）后在约 0.5–6s 内拉起。
// 滚动日志：data/supervisor.log。PID：data/supervisor.pid、data/backend.pid。
//
// 背景：后端会因 V8 OOM（退出码 134）、OS OOM-killer（SIGKILL）、未捕获异常、或启动对账堵死
// 事件循环而停摆。前台 npm run dev / tsx watch 关终端即整组退出，且 tsx watch 改源码会掐断审计。
// 此守护负责恢复；systemd Restart=always 再兜一层（守护自身挂了也会被拉起）。
//
// 用法：node backend/supervisor.mjs（npm start / scripts/code-up.sh）。
// 环境变量：
//   BACKEND_MAX_OLD_SPACE_MB  子进程 V8 老生代堆上限（MB），默认 4096。
//   PORT / BIND_HOST          透传给后端；探活时 0.0.0.0 改打 127.0.0.1。

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
const supervisorPidFile = path.join(dataDir, 'supervisor.pid');
const backendPidFile = path.join(dataDir, 'backend.pid');

const PORT = Number(process.env.PORT || 8787);
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';
const PROBE_HOST =
  !BIND_HOST || BIND_HOST === '0.0.0.0' || BIND_HOST === '::' || BIND_HOST === '::0'
    ? '127.0.0.1'
    : BIND_HOST;
const maxOldSpaceMb = Number(process.env.BACKEND_MAX_OLD_SPACE_MB || 4096);

const BACKOFF_MIN_MS = 500;
const BACKOFF_MAX_MS = 6_000;
const HEALTHY_UPTIME_MS = 60_000;
const HEALTH_INTERVAL_MS = 2_000;
const HEALTH_TIMEOUT_MS = 1_500;
const HEALTH_FAILS = 3;
const HEALTH_GRACE_MS = 8_000;
const LOG_MAX_LINES = 2_000;

let backoffMs = BACKOFF_MIN_MS;
let child = null;
let shuttingDown = false;
let restartTimer = null;
let healthTimer = null;
let healthFails = 0;
let childStartedAt = 0;
let healthOkSince = 0;
let mode = 'idle'; // idle | child | standby

function ts() {
  return new Date().toISOString();
}

function writePid(file, pid) {
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(file, `${pid}\n`);
  } catch {
    /* ignore */
  }
}

function clearPid(file) {
  try {
    fs.unlinkSync(file);
  } catch {
    /* ignore */
  }
}

function appendLog(line) {
  const entry = `[${ts()}] ${line}\n`;
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.appendFileSync(logFile, entry);
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

function probeHealth(timeoutMs = HEALTH_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const req = http.get(
      { host: PROBE_HOST, port: PORT, path: '/api/health', timeout: timeoutMs },
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

function stopHealthWatch() {
  if (healthTimer) {
    clearInterval(healthTimer);
    healthTimer = null;
  }
  healthFails = 0;
}

function startChildHealthWatch() {
  stopHealthWatch();
  healthOkSince = 0;
  healthTimer = setInterval(() => {
    void tickChildHealth();
  }, HEALTH_INTERVAL_MS);
}

async function tickChildHealth() {
  if (shuttingDown || mode !== 'child' || !child) return;
  if (Date.now() - childStartedAt < HEALTH_GRACE_MS) return;
  const ok = await probeHealth();
  if (ok) {
    healthFails = 0;
    if (!healthOkSince) healthOkSince = Date.now();
    if (Date.now() - healthOkSince >= HEALTHY_UPTIME_MS) backoffMs = BACKOFF_MIN_MS;
    return;
  }
  healthFails += 1;
  healthOkSince = 0;
  appendLog(
    `健康检查失败 ${healthFails}/${HEALTH_FAILS}（${PROBE_HOST}:${PORT}/api/health 无 200）`
  );
  if (healthFails < HEALTH_FAILS) return;
  healthFails = 0;
  backoffMs = BACKOFF_MIN_MS;
  appendLog('连续探活失败，判定后端卡死，SIGKILL 后立即拉起');
  try {
    if (child && child.pid) child.kill('SIGKILL');
  } catch {
    /* 子进程已退出 */
  }
}

function enterStandby() {
  mode = 'standby';
  child = null;
  clearPid(backendPidFile);
  stopHealthWatch();
  appendLog(`待命：${PROBE_HOST}:${PORT} 已有健康后端，不重复拉起；它挂了再接管`);
  healthTimer = setInterval(() => {
    void tickStandby();
  }, HEALTH_INTERVAL_MS);
}

async function tickStandby() {
  if (shuttingDown || mode !== 'standby') return;
  const ok = await probeHealth();
  if (ok) {
    healthFails = 0;
    return;
  }
  healthFails += 1;
  appendLog(`待命探活失败 ${healthFails}/${HEALTH_FAILS}，准备接管`);
  if (healthFails < HEALTH_FAILS) return;
  healthFails = 0;
  stopHealthWatch();
  appendLog('原后端已无响应，开始接管拉起');
  start();
}

function scheduleRestart() {
  if (shuttingDown) return;
  appendLog(`将在 ${Math.round(backoffMs)}ms 后重启后端…`);
  restartTimer = setTimeout(start, backoffMs);
  backoffMs = Math.min(Math.max(backoffMs * 2, BACKOFF_MIN_MS), BACKOFF_MAX_MS);
}

function spawnBackend() {
  const { cmd, args } = resolveEntry();
  const startedAt = Date.now();
  childStartedAt = startedAt;
  mode = 'child';
  child = spawn(cmd, args, { cwd: backendDir, env: buildEnv(), stdio: 'inherit' });
  if (child.pid) writePid(backendPidFile, child.pid);
  startChildHealthWatch();

  child.on('exit', (code, signal) => {
    const uptimeMs = Date.now() - startedAt;
    const wasChild = mode === 'child';
    child = null;
    clearPid(backendPidFile);
    stopHealthWatch();
    if (mode === 'child') mode = 'idle';
    const upSec = (uptimeMs / 1000).toFixed(1);
    appendLog(
      `后端子进程退出：code=${code ?? 'null'} signal=${signal ?? 'null'} uptime=${upSec}s` +
        (signal === 'SIGKILL'
          ? '（SIGKILL：可能是探活判定卡死、systemd 停机或 OS OOM-killer）'
          : code === 134 || code === 137
            ? '（疑似 V8 堆溢出 heap out of memory）'
            : '')
    );

    if (shuttingDown) {
      process.exit(0);
      return;
    }
    if (!wasChild) return;

    if (uptimeMs < 5_000) {
      void probeHealth().then((alive) => {
        if (alive) enterStandby();
        else scheduleRestart();
      });
      return;
    }

    if (uptimeMs >= HEALTHY_UPTIME_MS) backoffMs = BACKOFF_MIN_MS;
    scheduleRestart();
  });

  child.on('error', (err) => {
    appendLog(`拉起后端失败：${err?.message || err}`);
    clearPid(backendPidFile);
    if (!shuttingDown) scheduleRestart();
  });

  appendLog(
    `已拉起后端：${cmd} ${args.join(' ')}（--max-old-space-size=${maxOldSpaceMb}，pid=${child.pid}）`
  );
}

function start() {
  restartTimer = null;
  if (shuttingDown) return;
  if (child) return;
  void probeHealth().then((alive) => {
    if (shuttingDown) return;
    if (alive) {
      enterStandby();
      return;
    }
    spawnBackend();
  });
}

function shutdown(sig) {
  if (shuttingDown) return;
  shuttingDown = true;
  mode = 'idle';
  appendLog(`收到 ${sig}，正在停止后端…`);
  if (restartTimer) {
    clearTimeout(restartTimer);
    restartTimer = null;
  }
  stopHealthWatch();
  if (child) {
    child.kill(sig);
    const force = setTimeout(() => {
      if (child) child.kill('SIGKILL');
      clearPid(backendPidFile);
      clearPid(supervisorPidFile);
      process.exit(0);
    }, 10_000);
    if (typeof force.unref === 'function') force.unref();
  } else {
    clearPid(supervisorPidFile);
    process.exit(0);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('exit', () => {
  if (child && child.pid) {
    try {
      process.kill(child.pid, 'SIGKILL');
    } catch {
      /* 子进程已退出 */
    }
  }
  clearPid(backendPidFile);
  clearPid(supervisorPidFile);
});

writePid(supervisorPidFile, process.pid);
appendLog(`后端守护启动（探活 ${PROBE_HOST}:${PORT}/api/health，失败 ${HEALTH_FAILS} 次后拉起）。`);
start();
