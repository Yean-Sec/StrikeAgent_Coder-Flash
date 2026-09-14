import db from './db';
import { getSetting } from './settings';

export type VerifyRuntime = 'full' | 'none';

/** 历史值 mini 一律视为完整靶机。 */
export function parseVerifyRuntime(raw: unknown): VerifyRuntime | null {
  const s = String(raw || '').trim().toLowerCase();
  if (s === 'mini' || s === 'full') return 'full';
  if (s === 'none') return 'none';
  return null;
}

/**
 * 解析远程验证形态。
 * - 项目列已写入 full/none（或历史 mini→full）：用之
 * - 空列 + opt_auto_verify=1：旧项目，视为完整靶机
 * - 空列 + opt_auto_verify=0：仅代码审计
 * - 空列且 auto_verify 亦空：全局 verify_runtime，再否则按全局 auto_verify 得 full/none
 */
export function resolveVerifyRuntime(opts: {
  opt_verify_runtime?: string | null;
  opt_auto_verify?: number | null;
  globalRuntime?: string;
  globalAutoVerify?: string;
}): VerifyRuntime {
  const parsed = parseVerifyRuntime(opts.opt_verify_runtime);
  if (parsed) return parsed;
  if (opts.opt_auto_verify === 1) return 'full';
  if (opts.opt_auto_verify === 0) return 'none';
  const global = parseVerifyRuntime(opts.globalRuntime);
  if (global) return global;
  const auto = String(opts.globalAutoVerify || '').trim().toLowerCase();
  if (auto === '1' || auto === 'true') return 'full';
  return 'none';
}

export function verifyRuntime(projectId: string): VerifyRuntime {
  const row = db
    .prepare('SELECT opt_verify_runtime AS r, opt_auto_verify AS a FROM projects WHERE id = ?')
    .get(projectId) as { r: string | null; a: number | null } | undefined;
  return resolveVerifyRuntime({
    opt_verify_runtime: row?.r,
    opt_auto_verify: row?.a ?? null,
    globalRuntime: getSetting('verify_runtime'),
    globalAutoVerify: getSetting('auto_verify'),
  });
}

/** 是否需要整栈 Compose / Harness 预搭建。仅完整靶机。 */
export function needsComposeEnv(projectId: string): boolean {
  return verifyRuntime(projectId) === 'full';
}

/** 实际执行形态：完整靶机走 Compose/HTTP；仅代码审计不入队远程验证。 */
export function verifyExecMode(projectId: string): 'full' | 'none' {
  return verifyRuntime(projectId) === 'none' ? 'none' : 'full';
}
