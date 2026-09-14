/** CVE / GitHub 报送共用的 Pi 子进程启动、浏览器预检与日志判定。 */
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import { getSetting } from './settings';
import { piSpawnEnv, buildAgentCliArgs, cleanupPromptFile } from './piResolver';

export type ReportJobStatus = 'running' | 'completed' | 'failed' | 'stopped';

export interface ReportJobMeta {
  id: string;
  count: number;
  status: ReportJobStatus;
  startedAt: number;
  finishedAt?: number;
  exitCode?: number;
  /** 日志判定：进程 exit 0 但未真正完成时写入原因。 */
  failureNote?: string;
}

export const REPORT_AUTOMATION_RULES = `
# 无人值守自动化（硬性）
- **禁止**使用 AskUserQuestion 或向用户提问、等待人工确认；必须自动决策并执行到全部条目处理完毕。
- **禁止**运行 \`gh auth login\`、device flow 等需要人工扫码/输入的交互式认证。
- GitHub 报送**优先**用 \`gh api\` / GitHub REST（已配置 token）。CVE 报送若无法自动填表，如实记录失败，**禁止**编造已提交。
- 浏览器跳转到 GitHub 登录页且无法自动登录时：如实记录「需先在设置中配置有效 github_token」，**禁止**无限重试认证。
- 最终总结必须逐条给出：已提交 / 失败（原因）/ 仓库未开启需手动。`;

const FAIL_LOG_PATTERNS: RegExp[] = [
  /请问选哪种|能否手动先关闭\s*Chrome/i,
  /chrome-devtools MCP 无法/i,
  /browser is already running/i,
  /无法启动.*浏览器/i,
  /don't have working browser/i,
  /没有可用的浏览器/i,
  /禁止编造已提交/i,
];

const SUCCESS_LOG_PATTERNS: RegExp[] = [
  /已提交(?:至|到)?\s*(?:GitHub|MITRE|CVE|Security Advisory)/i,
  /submitted successfully/i,
  /Security Advisory.*(?:created|已创建)/i,
  /CVE.*(?:request|ID).*(?:submitted|已提交)/i,
  /ghsa-[a-z0-9-]+/i,
  /advisory.*https:\/\/github\.com/i,
];

/** 报送前预检（已不再注入浏览器 MCP）。 */
export function preflightBrowserAutomation(): void {
  /* no-op */
}

/** 根据日志内容修正 exit code 误判的 completed。 */
export function resolveReportJobStatus(exitCode: number | null | undefined, log: string): {
  status: ReportJobStatus;
  failureNote?: string;
} {
  const hasSuccess = SUCCESS_LOG_PATTERNS.some((p) => p.test(log));
  const failHit = FAIL_LOG_PATTERNS.find((p) => p.test(log));
  if (failHit && !hasSuccess) {
    return {
      status: 'failed',
      failureNote: '日志显示任务未完成（如等待用户确认），未检测到成功提交记录',
    };
  }
  if (!hasSuccess && exitCode === 0 && /StructuredOutput|结构化输出/.test(log) && !/MITRE|Security Advisory|gh api/.test(log)) {
    // exit 0 但只输出了结构化占位、未触及报送站点
    const askedUser = /请问|选哪种|手动关闭/.test(log);
    if (askedUser) {
      return {
        status: 'failed',
        failureNote: 'Pi 会话结束但未完成报送（曾等待用户确认浏览器）',
      };
    }
  }
  if (exitCode === 0) return { status: 'completed' };
  return { status: 'failed', failureNote: `进程退出码 ${exitCode ?? '?'}` };
}

export function spawnReportPiJob(opts: {
  cwd: string;
  logPath: string;
  prompt: string;
  meta: ReportJobMeta;
  writeMeta: (m: ReportJobMeta) => void;
  children: Map<string, ChildProcess>;
  logPrefix: string;
  env?: NodeJS.ProcessEnv;
}): void {
  if (getSetting('claude_jobs_enabled') === '0') {
    const m = {
      ...opts.meta,
      status: 'failed' as const,
      finishedAt: Date.now(),
      failureNote: 'Pi 任务已停摆',
    };
    opts.writeMeta(m);
    try {
      fs.appendFileSync(opts.logPath, `\n[${opts.logPrefix}] Pi 任务已停摆，跳过报送\n`);
    } catch {
      /* ignore */
    }
    return;
  }
  preflightBrowserAutomation();

  const template = getSetting('default_command');
  const { program, args, promptFile } = buildAgentCliArgs({
    template,
    prompt: opts.prompt,
    schemaStr: '{"type":"object"}',
  });

  const out = fs.openSync(opts.logPath, 'a');
  try {
    const child = spawn(program, args, {
      cwd: opts.cwd,
      env: opts.env ?? piSpawnEnv(),
      windowsHide: true,
      stdio: ['ignore', out, out],
    });
    opts.children.set(opts.meta.id, child);
    child.on('error', () => {
      cleanupPromptFile(promptFile);
      opts.children.delete(opts.meta.id);
      try {
        fs.appendFileSync(opts.logPath, `\n[${opts.logPrefix}] 无法启动 Pi 进程\n`);
      } catch {
        /* ignore */
      }
      const m = { ...opts.meta, status: 'failed' as const, finishedAt: Date.now(), failureNote: 'spawn error' };
      opts.writeMeta(m);
    });
    child.on('close', (code) => {
      cleanupPromptFile(promptFile);
      opts.children.delete(opts.meta.id);
      let log = '';
      try {
        log = fs.readFileSync(opts.logPath, 'utf8');
      } catch {
        log = '';
      }
      const resolved = resolveReportJobStatus(code, log);
      const m: ReportJobMeta = {
        ...opts.meta,
        status: resolved.status,
        exitCode: code ?? undefined,
        finishedAt: Date.now(),
        failureNote: resolved.failureNote,
      };
      opts.writeMeta(m);
      try {
        fs.appendFileSync(
          opts.logPath,
          `\n[${opts.logPrefix}] 进程结束，退出码 ${code ?? '?'}，判定状态：${resolved.status}${
            resolved.failureNote ? `（${resolved.failureNote}）` : ''
          }\n`
        );
      } catch {
        /* ignore */
      }
    });
  } catch {
    cleanupPromptFile(promptFile);
    opts.children.delete(opts.meta.id);
    fs.appendFileSync(opts.logPath, `\n[${opts.logPrefix}] spawn 异常\n`);
    opts.writeMeta({ ...opts.meta, status: 'failed', finishedAt: Date.now(), failureNote: 'spawn exception' });
  }
}
