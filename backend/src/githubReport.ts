// GitHub Security Advisory 自动报送：spawn Pi 优先 gh api，浏览器 MCP 兜底。
import { ChildProcess, execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { getSetting } from './settings';
import { collectReportItems, type ReportSubmitItem } from './reportSubmit';
import { REPORT_AUTOMATION_RULES, spawnReportPiJob, type ReportJobMeta } from './reportSpawn';

const DATA_DIR = path.join(__dirname, '..', 'data');
const GH_DIR = path.join(DATA_DIR, 'github-report');

export type GhJobStatus = 'running' | 'completed' | 'failed' | 'stopped';

interface GhMeta extends ReportJobMeta {}

const ghChildren = new Map<string, ChildProcess>();

function metaFile(id: string) {
  return path.join(GH_DIR, `${id}.meta.json`);
}
function logFile(id: string) {
  return path.join(GH_DIR, `${id}.log`);
}

function writeMeta(meta: GhMeta) {
  fs.writeFileSync(metaFile(meta.id), JSON.stringify(meta), 'utf8');
}

function readMeta(id: string): GhMeta | null {
  try {
    return JSON.parse(fs.readFileSync(metaFile(id), 'utf8')) as GhMeta;
  } catch {
    return null;
  }
}

function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  const pid = child.pid;
  try {
    if (process.platform === 'win32') {
      execSync(`taskkill /pid ${pid} /T /F`, { stdio: 'ignore' });
      return;
    }
    try {
      process.kill(-pid, 'SIGTERM');
    } catch {
      /* 非进程组 leader */
    }
    try {
      execSync(`pkill -TERM -P ${pid}`, { stdio: 'ignore' });
    } catch {
      /* 无子进程 */
    }
    child.kill('SIGTERM');
  } catch {
    /* ignore */
  }
  setTimeout(() => {
    try {
      if (process.platform !== 'win32') {
        try {
          process.kill(-pid, 'SIGKILL');
        } catch {
          /* ignore */
        }
        try {
          execSync(`pkill -KILL -P ${pid}`, { stdio: 'ignore' });
        } catch {
          /* ignore */
        }
      }
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }, 1500);
}

function buildGithubPrompt(dataFile: string, token: string): string {
  return `你是一名漏洞披露助理。请把下面 JSON 文件中的漏洞逐条提交到对应 GitHub 仓库的 Security Advisory（私有漏洞报告）。

# 待提交漏洞数据
${dataFile}

# GitHub Token
${token ? '(已配置：优先用 gh api / GitHub REST，环境变量 GH_TOKEN 或 gh auth 可用)' : '(未配置：请在设置中填写 github_token)'}

# 对每一条漏洞/组合链（按此顺序，禁止跳步）
1. 从数据读取 source_ref（GitHub 仓库 URL）解析 owner/repo；source_version 为受影响版本。
2. **优先 API 路径（有 token 时必须先试）**：
   - \`gh api repos/{owner}/{repo}\` 确认仓库存在
   - \`gh api repos/{owner}/{repo}/private-vulnerability-reporting\` 检测是否开启私有漏洞报告
   - **外部研究者应优先** \`POST /repos/{owner}/{repo}/security-advisories/reports\`（私有漏洞报告，无需仓库写权限）
   - 仅当上述失败且 token 有仓库 maintainer 权限时再试 \`POST .../security-advisories\`
3. **API 全部失败时**用浏览器 MCP：先 \`gh auth status\` 确认 CLI 已登录；浏览器未登录则执行 \`gh auth login --web\` 或 \`gh auth setup-git\` 同步 cookie，再打开 \`https://github.com/{owner}/{repo}/security/advisories/new\` 填写提交。
4. **禁止**向用户提问或等待确认；**禁止**在公开 Issue 中披露漏洞细节（除非私有报告完全不可用且 maintainer 无 SECURITY.md）。
5. **若仓库未开启**私有报告：日志明确写原因并搜索 maintainer 公开邮箱；**禁止**编造已提交。
6. 描述须包含：title、file_path、line、taint_chain、复现步骤（POC curl/请求）、影响、修复建议。

# 约束
- 逐条处理；某条失败不阻断其它条。
- 完成后用中文逐条总结：已提交（advisory URL/GHSA id）/ 失败原因 / 需手动。
${REPORT_AUTOMATION_RULES}`;
}

export function startGithubReport(items: ReportSubmitItem[]): { id: string; count: number } {
  if (!fs.existsSync(GH_DIR)) fs.mkdirSync(GH_DIR, { recursive: true });
  const detailed = collectReportItems(items);
  const id = crypto.randomUUID().slice(0, 8);
  const dataFile = path.join(GH_DIR, `${id}.json`);
  const log = logFile(id);
  fs.writeFileSync(dataFile, JSON.stringify(detailed, null, 2), 'utf8');

  const meta: GhMeta = { id, count: detailed.length, status: 'running', startedAt: Date.now() };
  writeMeta(meta);
  fs.writeFileSync(log, `[GitHub 报送] 开始处理 ${detailed.length} 条\n`, 'utf8');

  const token = getSetting('github_token').trim();
  const prompt = buildGithubPrompt(dataFile, token);
  const env = {
    ...process.env,
    ...(token ? { GH_TOKEN: token, GITHUB_TOKEN: token } : {}),
  };

  spawnReportPiJob({
    cwd: GH_DIR,
    logPath: log,
    prompt,
    meta,
    writeMeta,
    children: ghChildren,
    logPrefix: 'GitHub 报送',
    env,
  });

  return { id, count: detailed.length };
}

export function getGithubReport(id: string): (GhMeta & { log: string }) | null {
  const meta = readMeta(id);
  if (!meta) return null;
  let log = '';
  try {
    log = fs.readFileSync(logFile(id), 'utf8');
  } catch {
    log = '';
  }
  return { ...meta, log };
}

export function getLatestGithubReport(): (GhMeta & { log: string }) | null {
  if (!fs.existsSync(GH_DIR)) return null;
  const metas = fs
    .readdirSync(GH_DIR)
    .filter((f) => f.endsWith('.meta.json'))
    .map((f) => readMeta(f.replace('.meta.json', '')))
    .filter(Boolean) as GhMeta[];
  if (metas.length === 0) return null;
  metas.sort((a, b) => b.startedAt - a.startedAt);
  return getGithubReport(metas[0].id);
}

export function stopGithubReport(id: string): boolean {
  const child = ghChildren.get(id);
  if (!child) return false;
  killTree(child);
  ghChildren.delete(id);
  const m = readMeta(id);
  if (m && m.status === 'running') {
    m.status = 'stopped';
    m.finishedAt = Date.now();
    writeMeta(m);
  }
  return true;
}
