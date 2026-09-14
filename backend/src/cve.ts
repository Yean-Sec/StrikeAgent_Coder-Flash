// 一键上传 CVE（item 10）：把选中的漏洞/组合链信息交给本地 Pi Agent，
// 用浏览器 MCP 自动打开 MITRE CVE 提交表单填写、按 NVD CVSS v3 计算器评分。
// 语言/项目无关：数据来自跨项目聚合，Pi Agent 全自动填报。
import { ChildProcess, execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import db from './db';
import { getSetting } from './settings';
import { collectReportItems, type ReportSubmitItem } from './reportSubmit';
import { REPORT_AUTOMATION_RULES, spawnReportPiJob, type ReportJobMeta } from './reportSpawn';
import { ensureLegacyExploitChainsBackfilled } from './exploitChains';

export type { ReportSubmitItem as CveSubmitItem };

const DATA_DIR = path.join(__dirname, '..', 'data');
const CVE_DIR = path.join(DATA_DIR, 'cve');

export type CveJobStatus = 'running' | 'completed' | 'failed' | 'stopped';

interface CveMeta extends ReportJobMeta {}

/** 运行中的 CVE 提交进程（用于暂停/中止）。 */
const cveChildren = new Map<string, ChildProcess>();

function metaFile(id: string) {
  return path.join(CVE_DIR, `${id}.meta.json`);
}
function logFile(id: string) {
  return path.join(CVE_DIR, `${id}.log`);
}

function writeMeta(meta: CveMeta) {
  fs.writeFileSync(metaFile(meta.id), JSON.stringify(meta), 'utf8');
}

function readMeta(id: string): CveMeta | null {
  try {
    return JSON.parse(fs.readFileSync(metaFile(id), 'utf8')) as CveMeta;
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

/** 跨项目聚合漏洞库（分页 + 持久化 verified/auth_required 列）。 */
export function buildVulnLibrary(opts?: {
  page?: number;
  pageSize?: number;
  onlyVerified?: boolean;
  onlyUnauth?: boolean;
  severity?: string;
  search?: string;
}): { vulns: any[]; chains: any[]; total: number; page: number; pageSize: number; chainTotal: number } {
  const page = Math.max(1, opts?.page ?? 1);
  const pageSize = Math.min(200, Math.max(1, opts?.pageSize ?? 50));
  const onlyVerified = opts?.onlyVerified === true;
  const onlyUnauth = opts?.onlyUnauth === true;
  const severity = String(opts?.severity || 'all');
  const search = String(opts?.search || '').trim();

  const conds: string[] = [];
  const params: any[] = [];
  if (onlyVerified) {
    conds.push('v.verified = 1');
  }
  if (onlyUnauth) {
    conds.push("v.auth_required = 'none'");
  }
  if (severity !== 'all') {
    conds.push('v.severity = ?');
    params.push(severity);
  }
  if (search) {
    const like = `%${search}%`;
    conds.push('(v.title LIKE ? OR v.category LIKE ? OR p.project_name LIKE ?)');
    params.push(like, like, like);
  }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const JOIN = 'FROM vulnerabilities v JOIN projects p ON p.id = v.project_id';

  const total = (
    db.prepare(`SELECT COUNT(*) AS c ${JOIN} ${where}`).get(...params) as { c: number }
  ).c;

  const vulns = db
    .prepare(
      `SELECT v.id, v.project_id, v.title, v.severity, v.regrade_value, v.category, v.file_path, v.line,
              v.description, v.recommendation, v.taint_chain, v.verified, v.auth_required,
              p.project_name, p.system_name, p.source_version, p.source_type, p.source_ref, p.target_url
       ${JOIN} ${where}
       ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                v.created_at DESC
       LIMIT ? OFFSET ?`
    )
    .all(...params, pageSize, (page - 1) * pageSize) as any[];

  for (const v of vulns) {
    v.verified = v.verified === 1 ? 'success' : null;
  }

  // 历史报告只在首次访问时增量物化一次；正常写入由 runner.saveExploitReport
  // 同步维护，此处只读小型链表，不再扫描/解析所有 projects.exploit_report。
  ensureLegacyExploitChainsBackfilled();
  const chainConds = ["ec.status = 'success'"];
  const chainParams: unknown[] = [];
  if (onlyUnauth) chainConds.push("ec.auth_required = 'none'");
  if (search) {
    const like = `%${search}%`;
    chainConds.push('(ec.name LIKE ? OR ec.impact LIKE ? OR p.project_name LIKE ?)');
    chainParams.push(like, like, like);
  }
  const chainRows = db
    .prepare(
      `SELECT ec.project_id, ec.name, ec.auth_required, ec.payload_json, p.project_name
       FROM exploit_chains ec
       JOIN projects p ON p.id = ec.project_id
       WHERE ${chainConds.join(' AND ')}
       ORDER BY ec.project_id, ec.chain_order`
    )
    .all(...chainParams) as {
    project_id: string;
    name: string;
    auth_required: string;
    payload_json: string;
    project_name: string;
  }[];

  const chains = chainRows.map((row) => {
    let chain: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(row.payload_json) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        chain = parsed as Record<string, unknown>;
      }
    } catch {
      // 物化行损坏时仍返回可识别的最小数据，不回退扫描大型报告。
    }
    const rawName = chain.name || row.name;
    return {
      ref: `${row.project_id}::${rawName || ''}`,
      project_id: row.project_id,
      project_name: row.project_name,
      name: rawName || '组合利用链',
      impact: chain.impact || '',
      auth_required: String(chain.auth_required || row.auth_required || 'unknown'),
      steps: Array.isArray(chain.steps) ? chain.steps : [],
      detail: chain.detail || '',
      verified: 'success',
    };
  });

  return { vulns, chains, total, page, pageSize, chainTotal: chains.length };
}

/** 取出选中条目的完整信息，供 Pi Agent 读取填报。 */
function collectItems(items: ReportSubmitItem[]): any[] {
  return collectReportItems(items);
}

function buildCvePrompt(dataFile: string, email: string): string {
  return `你是一名漏洞披露助理。请把下面文件中的漏洞逐条提交到 MITRE CVE 申请表单，并用 NVD CVSS v3 计算器打分。

# 待提交漏洞数据（JSON，逐条处理）
${dataFile}

# 上报邮箱（表单 requester email 一律用这个）
${email || '(设置中未配置 CVE 邮箱，请在页面提示用户先到设置里填写)'}

# 步骤（对每一条漏洞/组合链）
1. 用浏览器 MCP 打开 MITRE CVE 申请表单：https://cveform-legacy.mitre.org/
2. 选择 "Report Vulnerability/Request CVE ID"，requester email 填上面的邮箱。
3. 依据该漏洞的 title/category/description/taint_chain/受影响产品与版本，填写产品、版本、漏洞类型、攻击场景、影响、发现者等字段。
4. 打开 NVD CVSS v3 计算器：https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator ，按该漏洞的可达性/影响勾选各项，得到 CVSS 向量与评分，回填到 CVE 表单的严重度/评分说明里。
5. 核对无误后提交表单；记录每条的提交结果（成功/失败原因）。

# 约束
- 全程用浏览器 MCP 真实操作页面，不要编造已提交。
- 逐条处理，互不影响；某条失败不阻断其它条。
- 完成后用中文总结每条的提交状态。
${REPORT_AUTOMATION_RULES}`;
}

/**
 * 发起 CVE 自动提交：把选中项写入临时 JSON，spawn 一个 Pi Agent 执行浏览器自动填报。
 * 输出写入 data/cve/<id>.log；前端轮询 GET /cve/submissions/:id 查看日志与状态。
 */
export function startCveSubmission(items: ReportSubmitItem[]): { id: string; count: number } {
  if (!fs.existsSync(CVE_DIR)) fs.mkdirSync(CVE_DIR, { recursive: true });
  const detailed = collectItems(items);
  const id = crypto.randomUUID().slice(0, 8);
  const dataFile = path.join(CVE_DIR, `${id}.json`);
  const log = logFile(id);
  fs.writeFileSync(dataFile, JSON.stringify(detailed, null, 2), 'utf8');

  const meta: CveMeta = {
    id,
    count: detailed.length,
    status: 'running',
    startedAt: Date.now(),
  };
  writeMeta(meta);
  fs.writeFileSync(log, `[CVE 提交] 开始处理 ${detailed.length} 条漏洞/组合链\n`, 'utf8');

  const email = getSetting('cve_email').trim();
  const prompt = buildCvePrompt(dataFile, email);

  spawnReportPiJob({
    cwd: CVE_DIR,
    logPath: log,
    prompt,
    meta,
    writeMeta,
    children: cveChildren,
    logPrefix: 'CVE 提交',
  });
  return { id, count: detailed.length };
}

/** 查询 CVE 提交任务状态与日志（log 为原始 stream-json + 文本，前端可格式化展示）。 */
export function getCveSubmission(id: string): (CveMeta & { log: string }) | null {
  let meta = readMeta(id);
  if (!meta && fs.existsSync(logFile(id))) {
    const st = fs.statSync(logFile(id));
    meta = {
      id,
      count: 0,
      status: cveChildren.has(id) ? 'running' : 'completed',
      startedAt: st.birthtimeMs || st.mtimeMs,
      finishedAt: cveChildren.has(id) ? undefined : st.mtimeMs,
    };
  }
  if (!meta) return null;
  let log = '';
  try {
    log = fs.readFileSync(logFile(id), 'utf8');
  } catch {
    log = '';
  }
  const max = 200_000;
  if (log.length > max) log = `…(仅显示最近 ${max} 字符)\n` + log.slice(-max);
  return { ...meta, log };
}

/** 返回最近一次 CVE 提交（优先 running，否则按 startedAt 最新）。 */
export function getLatestCveSubmission(): (CveMeta & { log: string }) | null {
  if (!fs.existsSync(CVE_DIR)) return null;
  const ids = new Set<string>();
  for (const f of fs.readdirSync(CVE_DIR)) {
    if (f.endsWith('.meta.json')) ids.add(f.replace('.meta.json', ''));
    else if (f.endsWith('.log')) ids.add(f.replace('.log', ''));
  }
  const metas: (CveMeta & { log: string })[] = [];
  for (const id of ids) {
    const job = getCveSubmission(id);
    if (job) metas.push(job);
  }
  if (metas.length === 0) return null;
  metas.sort((a, b) => b.startedAt - a.startedAt);
  const running = metas.find((m) => m.status === 'running');
  return running ?? metas[0];
}

/** 暂停/中止正在运行的 CVE 提交。 */
export function stopCveSubmission(id: string): boolean {
  const meta = readMeta(id);
  if (!meta || meta.status !== 'running') return false;
  const child = cveChildren.get(id);
  if (child) killTree(child);
  cveChildren.delete(id);
  meta.status = 'stopped';
  meta.finishedAt = Date.now();
  writeMeta(meta);
  try {
    fs.appendFileSync(logFile(id), '\n[已中止] 用户暂停 CVE 自动提交\n');
  } catch {
    /* ignore */
  }
  return true;
}
