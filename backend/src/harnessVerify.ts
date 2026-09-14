import fs from 'fs';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { harnessDir, readTargetEnv, harnessTargetUrl } from './projectShape';

const execFileAsync = promisify(execFile);

export function harnessVerifyDir(codeDir: string): string {
  return path.join(codeDir, '_harness_verify');
}

function safeReadJsonArray(file: string): any[] {
  try {
    const txt = fs.readFileSync(file, 'utf8').trim();
    if (!txt) return [];
    const o = JSON.parse(txt);
    if (Array.isArray(o)) return o;
    if (o && typeof o === 'object') {
      if (Array.isArray(o.exploits)) return o.exploits;
      if (typeof o.vulnerability === 'string' && o.vulnerability.trim()) return [o];
    }
    return [];
  } catch {
    return [];
  }
}

/** 读 _harness_verify 磁盘结果（与 _remote_verify 同结构）。 */
export function readHarnessVerifyResults(codeDir: string): { exploits: any[]; chains: any[] } {
  const base = harnessVerifyDir(codeDir);
  const exDir = path.join(base, 'exploits');
  const exploits: any[] = [];
  try {
    for (const f of fs.readdirSync(exDir)) {
      if (f.startsWith('_') || !f.toLowerCase().endsWith('.json')) continue;
      for (const e of safeReadJsonArray(path.join(exDir, f))) exploits.push(e);
    }
  } catch {
    /* 目录尚不存在 */
  }
  const chains = safeReadJsonArray(path.join(base, 'chains.json'));
  return { exploits, chains };
}

/** Harness 环境是否就绪：TARGET_ENV mode=harness + _harness 目录存在。 */
export function isHarnessEnvReady(codeDir: string): boolean {
  const env = readTargetEnv(codeDir);
  if (!env || String(env.mode || '').toLowerCase() !== 'harness') return false;
  const hdir = harnessDir(codeDir, env);
  try {
    return fs.statSync(hdir).isDirectory();
  } catch {
    return false;
  }
}

/** 可选执行 smoke_command；无命令或失败时仍允许就绪（目录存在即可）。 */
export async function runHarnessSmokeIfConfigured(codeDir: string): Promise<boolean> {
  const env = readTargetEnv(codeDir);
  if (!env) return false;
  const smoke = String(env.smoke_command || '').trim();
  if (!smoke) return true;
  try {
    await execFileAsync(process.platform === 'win32' ? 'cmd' : 'sh', process.platform === 'win32' ? ['/c', smoke] : ['-lc', smoke], {
      cwd: codeDir,
      timeout: 120_000,
      windowsHide: true,
    });
    return true;
  } catch {
    return false;
  }
}

export function harnessReadyTargetUrl(): string {
  return harnessTargetUrl();
}
