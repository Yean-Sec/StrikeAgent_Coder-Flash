import { Router, type Request, type Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import zlib from 'zlib';
import { Readable } from 'stream';
import db from './db';
import { UPLOAD_DIR } from './ingest';
import { newId } from './util';
import {
  createProject,
  getProject,
  projectNameExists,
  updateProjectMeta,
} from './projectsService';
import {
  enqueueAudit,
  enqueueVerify,
  enqueueVerifyOne,
  clearProjectEnv,
  retryEnvPrebuild,
  recoverEnvFalseFailures,
  pruneQueuedVerifyEnvBuilds,
  reconcileIdleDockerContainers,
  reconcileEnvAndContainers,
  reconcileStrictTargetProvenance,
  pauseProject,
  pauseNonWebVerifyProjects,
  stopPiVerifyForCursorManagedBatch,
  resumeProject,
  recoverMispausedAudits,
  reconcileMispausedCompletedAudits,
  bulkScheduleResume,
  restartAudit,
  restartVerify,
  restartVerifyChain,
  restartReprocess,
  restartStage,
  reingestFromDisk,
  reingestRemoteVerifyFromDisk,
  reingestAllStaleFromDisk,
  purgeProject,
  runningCount,
  kickScheduler,
  haltAllPiJobs,
  startWebClassifyBatch,
  getWebClassifyStatus,
  confirmWebClassifyDelete,
  cancelWebClassifyBatch,
  startImportPrescreen,
  getImportScreenStatus,
  cancelImportPrescreen,
} from './runner';
import {
  getAllSettings,
  setSettings,
  setSetting,
  getSetting,
  MAX_CONCURRENCY_CEILING,
  CLASSIFY_CONCURRENCY_CEILING,
} from './settings';
import { buildVulnLibrary, startCveSubmission, getCveSubmission, getLatestCveSubmission, stopCveSubmission } from './cve';
import {
  startGithubReport,
  getGithubReport,
  getLatestGithubReport,
  stopGithubReport,
} from './githubReport';
import { buildPocText, buildVulnMarkdown, resolveVulnTitle } from './vulnReport';
import { generateReport } from './report';
import { checkMonitorNow } from './monitor';
import { resolvePiExecutable, PI_INSTALL_HINT } from './piResolver';
import { parseOwnerRepo, rankBiggestChangeVersions } from './githubMeta';
import {
  analyzeGithubImport,
  filterGithubReposForScope,
  parseGithubRepoForCreate,
  type GithubAuditScope,
} from './githubImportDedup';
import { isAuditLanguage } from './schema';
import { execFile } from 'child_process';
import { now, repoNameFromUrl, contentDispositionAttachment } from './util';
import { attachProjectKind } from './projectKind';
import {
  invalidateProjectStatusReads,
  readThroughCache,
} from './readCache';
import type { Project, Vulnerability, AgentEvent, Monitor } from './types';
import {
  getProjectVerificationProgress,
  listProjectVerificationItems,
} from './verificationStore';
import {
  archiveProjectEvents,
  eventArchivePath,
} from './eventArchive';
import {
  auditVerifyVersionCohort,
  applyVerifyVersionInvalidations,
  purgeAllRemoteVerifyResidue,
} from './verifyVersionAudit';
import {
  auditCompletedProjectCoverage,
  applyAuditCoverageInvalidations,
  resetUnverifiableCompletedAudits,
  resetPausedAuditProjects,
} from './auditCoverageAudit';

const router = Router();

// 列表/看板只需要项目摘要。尤其不能 SELECT *：exploit_report 可能达到数 MB，
// 项目较多时会同时拖慢 SQLite 取行、JSON 序列化、网络传输和前端解析。
const PROJECT_SUMMARY_COLUMNS = `
  id, project_name, archive_name, source_type, source_ref, source_version, system_name,
  NULL AS workspace_path, env_status, target_url, status, error_message, monitor_id,
  count_critical, count_high, count_medium, count_low, count_info,
  NULL AS exploit_report, verify_status, verify_started_at, verify_finished_at, verify_error,
  git_ref, audit_duration_ms, verify_duration_ms,
  opt_auto_verify, opt_verify_history, opt_ai_dedup, opt_ai_regrade, opt_verify_runtime, audit_language,
  has_registration, reg_default_open, has_web, frontend_rce,
  CASE WHEN (
    COALESCE(opt_verify_history, 0) <> 0
    AND (
      exploit_report LIKE '%"historical_verification":[{%'
      OR exploit_report LIKE '%"historical_verification": [{%'
    )
  ) THEN 1 ELSE 0 END AS has_history_verify,
  created_at, started_at, finished_at
`;

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    cb(null, `${newId('up_')}${ext}`);
  },
});
const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 * 1024 } });

function decodeName(name: string): string {
  // multer 在某些环境下会将 UTF-8 文件名按 latin1 解析，这里尝试纠正
  try {
    return Buffer.from(name, 'latin1').toString('utf8');
  } catch {
    return name;
  }
}

/** 解析新建审计页传来的"审计流程选项"（兼容 JSON 字符串 / 对象；缺省项返回 undefined=沿用全局默认）。 */
function parseAuditOptions(
  raw: unknown
): {
  auto_verify?: boolean;
  verify_history?: boolean;
  ai_dedup?: boolean;
  ai_regrade?: boolean;
  verify_runtime?: 'mini' | 'full' | 'none';
} | undefined {
  let o: any = raw;
  if (typeof raw === 'string') {
    try {
      o = JSON.parse(raw);
    } catch {
      return undefined;
    }
  }
  if (!o || typeof o !== 'object') return undefined;
  const b = (v: any): boolean | undefined =>
    v === undefined || v === null ? undefined : v === true || v === 'true' || v === 1 || v === '1';
  const rt = String(o.verify_runtime || '').trim().toLowerCase();
  return {
    auto_verify: b(o.auto_verify),
    verify_history: b(o.verify_history),
    ai_dedup: b(o.ai_dedup),
    ai_regrade: b(o.ai_regrade),
    verify_runtime: rt === 'mini' || rt === 'full' ? 'full' : rt === 'none' ? 'none' : undefined,
  };
}

/* ----------------------------- 大屏看板 ----------------------------- */
// 全部走 SQL 聚合 + 持久化 verified 列，避免 SELECT * 全表扫描与逐项目解析 exploit_report
// （支撑万项目 / 百万漏洞下的大屏流畅刷新）。
router.get('/dashboard', (_req, res) => {
  const payload = readThroughCache<Record<string, unknown>>('dashboard', 'all', 15_000, () => {
    const emptySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    const totalProjects = (db.prepare('SELECT COUNT(*) AS c FROM projects').get() as { c: number }).c;

  // 项目级严重度累计（各项目 count_* 之和）
  const sevAgg = db
    .prepare(
      `SELECT COALESCE(SUM(count_critical),0) AS critical, COALESCE(SUM(count_high),0) AS high,
              COALESCE(SUM(count_medium),0) AS medium, COALESCE(SUM(count_low),0) AS low,
              COALESCE(SUM(count_info),0) AS info FROM projects`
    )
    .get() as Record<Sev, number>;
  const totals = { ...emptySev, ...sevAgg };
  const totalVulns = totals.critical + totals.high + totals.medium + totals.low + totals.info;

  // 项目状态分布
  const byStatus: Record<string, number> = {};
  for (const r of db
    .prepare('SELECT status, COUNT(*) AS c FROM projects GROUP BY status')
    .all() as { status: string; c: number }[]) {
    byStatus[r.status] = r.c;
  }

  // 代码审计漏洞：前端只展示前 8 类，直接在 SQL 侧裁剪，避免把数千个类别
  // （部分扫描器会生成高度离散的类别文本）每 4 秒传给浏览器。
  const auditCategories: Record<string, number> = {};
  for (const r of db
    .prepare(
      `SELECT COALESCE(NULLIF(TRIM(category), ''), '其他') AS category, COUNT(*) AS c
       FROM vulnerabilities
       GROUP BY COALESCE(NULLIF(TRIM(category), ''), '其他')
       ORDER BY c DESC
       LIMIT 8`
    )
    .all() as { category: string; c: number }[]) {
    auditCategories[r.category] = r.c;
  }

  // 已远程验证成功：按严重级 + 类型分布（直接用持久化 verified 列，无需解析 exploit_report）
  const verifiedTotals = { ...emptySev };
  for (const r of db
    .prepare('SELECT severity, COUNT(*) AS c FROM vulnerabilities WHERE verified = 1 GROUP BY severity')
    .all() as { severity: Sev; c: number }[]) {
    if (r.severity in verifiedTotals) verifiedTotals[r.severity] += r.c;
  }
  const verifiedCategories: Record<string, number> = {};
  for (const r of db
    .prepare(
      `SELECT COALESCE(NULLIF(TRIM(category), ''), '其他') AS category, COUNT(*) AS c
       FROM vulnerabilities
       WHERE verified = 1
       GROUP BY COALESCE(NULLIF(TRIM(category), ''), '其他')
       ORDER BY c DESC
       LIMIT 8`
    )
    .all() as { category: string; c: number }[]) {
    verifiedCategories[r.category] = r.c;
  }
  const verifiedVulns = (
    db.prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE verified = 1').get() as { c: number }
  ).c;

  const frontendRceVulns = (
    db.prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE frontend_rce = 1').get() as { c: number }
  ).c;

  // 「已完成项目」= 远程验证已完成（与项目列表 status=verify_done 口径一致）。
  // 注意：不是更宽的 all_done（那还包含 status=completed 且从未发起验证的项目）。
  const allDoneProjects = (
    db.prepare("SELECT COUNT(*) AS c FROM projects WHERE verify_status = 'completed'").get() as { c: number }
  ).c;

  const activeProjects = (
    db
      .prepare(
        `SELECT COUNT(*) AS c FROM projects WHERE (status IN ('running','queued') OR verify_status IN ('running','queued'))`
      )
      .get() as { c: number }
  ).c;

    return {
      totalProjects,
      running: Math.max(runningCount(), activeProjects),
      byStatus,
      severityTotals: totals,
      totalVulns,
      verifiedSeverityTotals: verifiedTotals,
      auditCategoryTotals: auditCategories,
      verifiedCategoryTotals: verifiedCategories,
      verifiedVulns,
      frontendRceVulns,
      allDoneProjects,
      // 保留字段兼容旧前端；当前大屏不渲染项目明细，不再读取/传输 100 条完整记录。
      runningProjects: [],
      verifyingProjects: [],
    };
  });
  res.json(payload);
});

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** 把已验证利用项匹配回对应的漏洞记录（按标题相似度）。 */
function matchVuln<T extends { title: string }>(exploitName: string, vulns: T[]): T | null {
  const norm = (s: string) => s.replace(/\s+/g, '').toLowerCase();
  const en = norm(exploitName);
  for (const v of vulns) {
    const vt = norm(v.title);
    if (vt && (en.includes(vt) || vt.includes(en.slice(0, Math.min(en.length, 12))))) {
      return v;
    }
  }
  return null;
}

/** 从利用项描述里解析严重级编号(CRIT/HIGH/MED…)。 */
function severityFromText(text: string): Sev | null {
  if (/crit|严重/i.test(text)) return 'critical';
  if (/high|高危/i.test(text)) return 'high';
  if (/med|medium|中危/i.test(text)) return 'medium';
  if (/low|低危/i.test(text)) return 'low';
  if (/info|提示/i.test(text)) return 'info';
  return null;
}

/* --------------------------- 本地 Pi 引擎检测 --------------------------- */
type PiHealth = { ok: boolean; path: string; version?: string; error?: string; stale?: boolean };
let piHealthCache: { value: PiHealth; expiresAt: number } | null = null;
let piHealthInFlight: Promise<PiHealth> | null = null;

function refreshPiHealth(): Promise<PiHealth> {
  if (piHealthInFlight) return piHealthInFlight;
  const bin = resolvePiExecutable();
  const useShell = process.platform === 'win32' && !/\.exe$/i.test(bin) && !/\.cmd$/i.test(bin);
  piHealthInFlight = new Promise<PiHealth>((resolve) => {
    execFile(
      bin,
      ['--version'],
      { timeout: 8000, windowsHide: true, shell: useShell },
      (err, stdout, stderr) => {
        if (err) {
          resolve({
            ok: false,
            path: bin,
            error: `${String(err.message || err).slice(0, 220)}。未检测到 Pi，请安装：${PI_INSTALL_HINT}`,
          });
          return;
        }
        const version = String(stdout || stderr || '').trim().split('\n')[0] || '';
        resolve({ ok: true, path: bin, version });
      }
    );
  }).then((value) => {
    piHealthCache = { value, expiresAt: Date.now() + 60_000 };
    piHealthInFlight = null;
    return value;
  });
  return piHealthInFlight;
}

function sendPiHealth(_req: Request, res: Response) {
  if (piHealthCache && piHealthCache.expiresAt > Date.now()) {
    return res.json(piHealthCache.value);
  }
  if (piHealthCache) {
    void refreshPiHealth();
    return res.json({ ...piHealthCache.value, stale: true });
  }
  void refreshPiHealth().then((value) => res.json(value));
}

router.get('/pi/health', sendPiHealth);
router.get('/claude/health', sendPiHealth);

/* ----------------------------- 项目列表 ----------------------------- */
/**
 * 「是否真正做过历史版本验证」的 SQL 判据。
 * 不能单看 opt_verify_history：那只是「开启了历史版本验证」的偏好开关
 * （mantis 开关为 1 但报告无产物）。
 * 也不能单看报告里是否出现 historical_verification 非空数组：关闭历史验证时，
 * 模型仍可能写入对当前版本的代码层备注（frp 开关为 0 却有两条「伪历史」）。
 * 必须以「开关开启 ∧ 报告中确有非空 historical_verification」同时成立为准。
 */
const HAS_HISTORY_VERIFY_SQL = `(
  COALESCE(opt_verify_history, 0) <> 0
  AND (
    exploit_report LIKE '%"historical_verification":[{%'
    OR exploit_report LIKE '%"historical_verification": [{%'
  )
)`;

const PROJECT_STATUS_SQL: Record<string, string> = {
  all: '1 = 1',
  active:
    "(status IN ('running','queued') OR verify_status IN ('running','queued'))",
  verify_running: "verify_status = 'running'",
  verify_queued: "status = 'completed' AND verify_status = 'queued'",
  audit_queued: "status = 'queued'",
  audit_running: "status = 'running'",
  all_done:
    "((status = 'completed' AND verify_status = 'none') OR verify_status = 'completed')",
  audit_done: "status = 'completed' AND verify_status = 'none'",
  /**
   * 大屏「已完成项目」并集：凡远程验证 verify_status=completed 都算（含/不含历史）。
   * 列表细分见下方互斥的 verify_done / verify_done_history。
   */
  remote_done: "verify_status = 'completed'",
  /** 代码审计+远程验证（未产出真实历史版本验证）——与 verify_done_history 互斥 */
  verify_done: `verify_status = 'completed' AND NOT ${HAS_HISTORY_VERIFY_SQL}`,
  /** 代码审计+远程验证+历史版本验证（报告中确有非空 historical_verification；不以 opt 开关为准） */
  verify_done_history: `verify_status = 'completed' AND ${HAS_HISTORY_VERIFY_SQL}`,
  paused: "(status = 'paused' OR verify_status = 'paused')",
  audit_paused: "status = 'paused'",
  verify_paused: "verify_status = 'paused'",
  failed: "(status = 'failed' OR verify_status = 'failed')",
};

router.get('/projects', (req, res) => {
  const search = String(req.query.search || '').trim();
  const requestedPageSize = parseInt(String(req.query.pageSize || ''), 10);

  // 未传 pageSize 时保留旧版数组响应，兼容脚本/旧前端；新版 UI 始终走服务端分页。
  if (!Number.isFinite(requestedPageSize) || requestedPageSize <= 0) {
    const params: unknown[] = [];
    let where = '';
    if (search) {
      where = 'WHERE project_name LIKE ? OR archive_name LIKE ?';
      const like = `%${search}%`;
      params.push(like, like);
    }
    const rows = db
      .prepare(
        `SELECT ${PROJECT_SUMMARY_COLUMNS}
         FROM projects ${where}
         ORDER BY created_at DESC`
      )
      .all(...params) as Project[];
    return res.json(rows);
  }

  const pageSize = Math.min(200, Math.max(1, requestedPageSize));
  const requestedPage = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
  const statusKey = String(req.query.status || 'all');
  const statusSql = PROJECT_STATUS_SQL[statusKey] || PROJECT_STATUS_SQL.all;
  const includeCounts = String(req.query.includeCounts ?? '1') !== '0';
  const groupBy = String(req.query.groupBy || 'none');
  const orderBy =
    groupBy === 'system'
      ? "LOWER(COALESCE(NULLIF(TRIM(system_name), ''), project_name)) ASC, created_at DESC"
      : groupBy === 'date'
        ? 'COALESCE(finished_at, started_at, created_at) DESC'
        : 'created_at DESC';

  const searchSql = search ? '(project_name LIKE ? OR archive_name LIKE ?)' : '1 = 1';
  const searchParams: unknown[] = search ? [`%${search}%`, `%${search}%`] : [];
  const whereSql = `${searchSql} AND (${statusSql})`;

  let counts: Record<string, number> | undefined;
  let total: number;
  if (includeCounts) {
    counts = readThroughCache('project-status-counts', search, 10_000, () => {
      const countSelect = Object.entries(PROJECT_STATUS_SQL)
        .filter(([key]) => key !== 'all')
        .map(([key, sql]) => `SUM(CASE WHEN ${sql} THEN 1 ELSE 0 END) AS ${key}`)
        .join(', ');
      const countRow = db
        .prepare(`SELECT COUNT(*) AS all_count, ${countSelect} FROM projects WHERE ${searchSql}`)
        .get(...searchParams) as Record<string, number | null>;
      const result: Record<string, number> = { all: Number(countRow.all_count || 0) };
      for (const key of Object.keys(PROJECT_STATUS_SQL)) {
        if (key !== 'all') result[key] = Number(countRow[key] || 0);
      }
      return result;
    });
    // 当前状态的 total 已包含在同一次聚合中，不再重复执行 COUNT。
    total = counts[statusKey] ?? counts.all;
  } else {
    total = (
      db.prepare(`SELECT COUNT(*) AS c FROM projects WHERE ${whereSql}`).get(...searchParams) as {
        c: number;
      }
    ).c;
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(requestedPage, totalPages);
  const items = db
    .prepare(
      `SELECT ${PROJECT_SUMMARY_COLUMNS}
       FROM projects
       WHERE ${whereSql}
       ORDER BY ${orderBy}
       LIMIT ? OFFSET ?`
    )
    .all(...searchParams, pageSize, (page - 1) * pageSize) as Project[];

  res.json({
    items,
    total,
    page,
    pageSize,
    ...(counts ? { counts } : {}),
  });
});

/**
 * 全部漏洞（跨项目聚合，带项目名 + 持久化 verified 列）——服务端分页 + 过滤 + 计数。
 * 支撑百万级漏洞：不再一次性返回全表，改为 LIMIT/OFFSET + 索引过滤 + SQL 聚合计数。
 * 查询参数：page(1)、pageSize(50)、severity(all|critical…)、verified(0|1)、frontend_rce(0|1)、category、search。
 * 返回：{ items, total, page, pageSize, counts:{all,critical…,verified,frontend_rce} }。
 */
router.get('/vulnerabilities', (req, res) => {
  const page = Math.max(1, parseInt(String(req.query.page ?? '1'), 10) || 1);
  const pageSize = Math.min(200, Math.max(1, parseInt(String(req.query.pageSize ?? '50'), 10) || 50));
  const severity = String(req.query.severity ?? 'all');
  const onlyVerified = String(req.query.verified ?? '') === '1';
  const onlyFrontendRce = String(req.query.frontend_rce ?? '') === '1';
  const category = String(req.query.category ?? '').trim();
  const search = String(req.query.search ?? '').trim();

  // scoped 条件只含类别/搜索；verified/frontend_rce 在聚合 CASE 内处理，
  // 这样各严重度、已验证、前台 RCE 计数可由一次查询得到。
  const scopedConds: string[] = [];
  const scopedParams: unknown[] = [];
  if (category) {
    scopedConds.push("COALESCE(NULLIF(TRIM(v.category),''),'其他') = ?");
    scopedParams.push(category);
  }
  if (search) {
    const like = `%${search}%`;
    scopedConds.push('(v.title LIKE ? OR v.category LIKE ? OR v.file_path LIKE ? OR p.project_name LIKE ?)');
    scopedParams.push(like, like, like, like);
  }
  const withVerified = [...scopedConds];
  const withVerifiedParams = [...scopedParams];
  if (onlyVerified) withVerified.push('v.verified = 1');
  if (onlyFrontendRce) withVerified.push('v.frontend_rce = 1');
  const baseWhere = scopedConds.length ? 'WHERE ' + scopedConds.join(' AND ') : '';

  const JOIN = 'FROM vulnerabilities v JOIN projects p ON p.id = v.project_id';

  const activePredicate = [
    onlyVerified ? 'v.verified = 1' : '1 = 1',
    onlyFrontendRce ? 'v.frontend_rce = 1' : '1 = 1',
  ].join(' AND ');
  const countCacheKey = JSON.stringify([category, search, onlyVerified, onlyFrontendRce]);
  const counts = readThroughCache<Record<string, number>>(
    'vulnerability-counts',
    countCacheKey,
    10_000,
    () => {
      const row = db
        .prepare(
          `SELECT
             COALESCE(SUM(CASE WHEN ${activePredicate} THEN 1 ELSE 0 END), 0) AS all_count,
             COALESCE(SUM(CASE WHEN ${activePredicate} AND v.severity='critical' THEN 1 ELSE 0 END), 0) AS critical,
             COALESCE(SUM(CASE WHEN ${activePredicate} AND v.severity='high' THEN 1 ELSE 0 END), 0) AS high,
             COALESCE(SUM(CASE WHEN ${activePredicate} AND v.severity='medium' THEN 1 ELSE 0 END), 0) AS medium,
             COALESCE(SUM(CASE WHEN ${activePredicate} AND v.severity='low' THEN 1 ELSE 0 END), 0) AS low,
             COALESCE(SUM(CASE WHEN ${activePredicate} AND v.severity='info' THEN 1 ELSE 0 END), 0) AS info,
             COALESCE(SUM(CASE WHEN v.verified=1 THEN 1 ELSE 0 END), 0) AS verified,
             COALESCE(SUM(CASE WHEN v.frontend_rce=1 THEN 1 ELSE 0 END), 0) AS frontend_rce
           ${JOIN} ${baseWhere}`
        )
        .get(...scopedParams) as Record<string, number | null>;
      return {
        all: Number(row.all_count || 0),
        critical: Number(row.critical || 0),
        high: Number(row.high || 0),
        medium: Number(row.medium || 0),
        low: Number(row.low || 0),
        info: Number(row.info || 0),
        verified: Number(row.verified || 0),
        frontend_rce: Number(row.frontend_rce || 0),
      };
    }
  );

  // 列表项：在 scoped 基础上叠加 severity
  const itemConds = [...withVerified];
  const itemParams = [...withVerifiedParams];
  if (severity !== 'all') {
    itemConds.push('v.severity = ?');
    itemParams.push(severity);
  }
  const itemWhere = itemConds.length ? 'WHERE ' + itemConds.join(' AND ') : '';
  // severity 对应的总数已在上面的聚合内，避免为当前分页再 COUNT 一遍。
  const total = severity === 'all' ? counts.all : counts[severity] || 0;
  // 前台 RCE 视图：按「拿到前台 RCE 的时间」倒序（最新在上）；其余视图维持严重度优先排序。
  const orderBy = onlyFrontendRce
    ? 'v.frontend_rce_at DESC, v.created_at DESC'
    : `CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
         WHEN 'low' THEN 3 ELSE 4 END, v.created_at DESC`;
  const items = db
    .prepare(
      `SELECT v.id, v.project_id, v.title, v.severity, v.severity_original,
              v.regrade_value, v.category, v.file_path, v.line,
              v.verified, v.frontend_rce, v.frontend_rce_at, v.auth_required, v.created_at,
              p.project_name
       ${JOIN} ${itemWhere}
       ORDER BY ${orderBy}
       LIMIT ? OFFSET ?`
    )
    .all(...itemParams, pageSize, (page - 1) * pageSize);

  res.json({ items, total, page, pageSize, counts });
});

function loadVulnerabilityDetail(
  vulnerabilityId: string,
  projectId?: string
): (Vulnerability & { project_name: string }) | undefined {
  const projectClause = projectId ? 'AND v.project_id = ?' : '';
  const params = projectId ? [vulnerabilityId, projectId] : [vulnerabilityId];
  return db
    .prepare(
      `SELECT v.*, p.project_name
       FROM vulnerabilities v
       JOIN projects p ON p.id = v.project_id
       WHERE v.id = ? ${projectClause}`
    )
    .get(...params) as (Vulnerability & { project_name: string }) | undefined;
}

/** 跨项目漏洞列表的按需完整详情。 */
router.get('/vulnerabilities/:id', (req, res) => {
  const vulnerability = loadVulnerabilityDetail(req.params.id);
  if (!vulnerability) return res.status(404).json({ error: '漏洞不存在' });
  res.json(vulnerability);
});

/* ----------------------- 历史审计版本对比 & 趋势 ----------------------- */

/** 把项目归并到"同一系统"：优先用人工可编辑的 system_name，其次回退到旧推导逻辑。 */
function systemKeyOf(
  p: Pick<Project, 'system_name' | 'source_type' | 'source_ref' | 'project_name'>
): { key: string; label: string } {
  const sys = (p.system_name || '').trim();
  if (sys) return { key: 'sys:' + sys.toLowerCase(), label: sys };
  if (p.source_type === 'github') {
    const or = parseOwnerRepo(p.source_ref);
    if (or) return { key: `gh:${or.owner}/${or.repo}`.toLowerCase(), label: or.repo };
  }
  const base =
    p.project_name
      .replace(/[-_ ]v?\d+(\.\d+)*([.-][0-9A-Za-z]+)*$/i, '')
      .trim() || p.project_name;
  return { key: 'name:' + base.toLowerCase(), label: base };
}

/** 版本号自然排序（尽量 semver 友好），回退到审计时间。 */
function compareVersion(a: { version: string; createdAt: number }, b: typeof a): number {
  const na = (a.version || '').match(/\d+/g)?.map(Number) || [];
  const nb = (b.version || '').match(/\d+/g)?.map(Number) || [];
  if (na.length && nb.length) {
    for (let i = 0; i < Math.max(na.length, nb.length); i++) {
      const d = (na[i] || 0) - (nb[i] || 0);
      if (d !== 0) return d;
    }
  }
  return a.createdAt - b.createdAt;
}

/** 同一系统的多版本审计聚合（用于对比与趋势）。 */
router.get('/version-groups', (req, res) => {
  type VersionProjectRow = Pick<
    Project,
    | 'id'
    | 'project_name'
    | 'source_type'
    | 'source_ref'
    | 'source_version'
    | 'system_name'
    | 'status'
    | 'verify_status'
    | 'created_at'
    | 'finished_at'
    | 'count_critical'
    | 'count_high'
    | 'count_medium'
    | 'count_low'
    | 'count_info'
  > & { verified: number };
  interface VersionEntryRow {
    projectId: string;
    projectName: string;
    version: string;
    sourceType: Project['source_type'];
    status: Project['status'];
    verifyStatus: Project['verify_status'];
    createdAt: number;
    finishedAt: number | null;
    severity: Record<Sev, number>;
    total: number;
    verified: number;
  }
  interface VersionGroupRow {
    key: string;
    system: string;
    versions: VersionEntryRow[];
    versionCount: number;
  }

  const search = String(req.query.search ?? '').trim();
  const result = readThroughCache<VersionGroupRow[]>('version-groups', search, 10_000, () => {
    const searchWhere = search
      ? `WHERE p.project_name LIKE ? OR p.system_name LIKE ?
           OR p.source_version LIKE ? OR p.source_ref LIKE ?`
      : '';
    const like = `%${search}%`;
    const params: unknown[] = search ? [like, like, like, like] : [];
    const projects = db
      .prepare(
        `SELECT p.id, p.project_name, p.source_type, p.source_ref, p.source_version,
                p.system_name, p.status, p.verify_status, p.created_at, p.finished_at,
                p.count_critical, p.count_high, p.count_medium, p.count_low, p.count_info,
                COALESCE(v.verified, 0) AS verified
         FROM projects p
         LEFT JOIN (
           SELECT project_id, COUNT(*) AS verified
           FROM vulnerabilities
           WHERE verified = 1
           GROUP BY project_id
         ) v ON v.project_id = p.id
         ${searchWhere}
         ORDER BY p.created_at DESC`
      )
      .all(...params) as VersionProjectRow[];
    const groups = new Map<string, Omit<VersionGroupRow, 'versionCount'>>();

    for (const p of projects) {
      const { key, label } = systemKeyOf(p);
      if (!groups.has(key)) groups.set(key, { key, system: label, versions: [] });
      const total =
        p.count_critical + p.count_high + p.count_medium + p.count_low + p.count_info;
      groups.get(key)!.versions.push({
        projectId: p.id,
        projectName: p.project_name,
        version: p.source_version || '—',
        sourceType: p.source_type,
        status: p.status,
        verifyStatus: p.verify_status,
        createdAt: p.created_at,
        finishedAt: p.finished_at,
        severity: {
          critical: p.count_critical,
          high: p.count_high,
          medium: p.count_medium,
          low: p.count_low,
          info: p.count_info,
        },
        total,
        verified: Number(p.verified || 0),
      });
    }

    return [...groups.values()]
      .map((group) => ({
        ...group,
        versions: group.versions.sort(compareVersion),
        versionCount: group.versions.length,
      }))
      .sort((a, b) => b.versionCount - a.versionCount || a.system.localeCompare(b.system));
  });

  const paginated = req.query.page !== undefined || req.query.pageSize !== undefined;
  if (!paginated) return res.json(result);

  const requestedPage = Math.max(1, parseInt(String(req.query.page ?? '1'), 10) || 1);
  const pageSize = Math.min(
    200,
    Math.max(1, parseInt(String(req.query.pageSize ?? '50'), 10) || 50)
  );
  const total = result.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(requestedPage, totalPages);
  const items = result.slice((page - 1) * pageSize, page * pageSize);
  res.json({ items, total, page, pageSize });
});

/** 两个版本（项目）间的漏洞差异：新增 / 已修复 / 共有（按标题归一比对）。 */
router.get('/version-diff', (req, res) => {
  const baseId = String(req.query.base || '');
  const targetId = String(req.query.target || '');
  const loadProjectMeta = (id: string) =>
    db
      .prepare('SELECT id, project_name, source_version FROM projects WHERE id = ?')
      .get(id) as Pick<Project, 'id' | 'project_name' | 'source_version'> | undefined;
  const base = loadProjectMeta(baseId);
  const target = loadProjectMeta(targetId);
  if (!base || !target) return res.status(404).json({ error: '项目不存在' });

  const load = (id: string) =>
    db
      .prepare('SELECT title, severity, category, file_path, line FROM vulnerabilities WHERE project_id = ?')
      .all(id) as { title: string; severity: string; category: string; file_path: string; line: number | null }[];

  const norm = (s: string) => (s || '').replace(/\s+/g, '').toLowerCase();
  const baseName = (f: string) =>
    (f || '').toLowerCase().replace(/\\/g, '/').split('/').pop() || '';
  // 多信号匹配键：跨版本同一漏洞常因二次评级/措辞不同导致标题不完全一致，
  // 故除标题外，再用 文件名+类别、文件名+行号 作为补充匹配键，避免"共有"恒为 0。
  type V = { title: string; severity: string; category: string; file_path: string; line: number | null };
  const keysOf = (v: V): string[] => {
    const keys: string[] = [];
    if (v.title) keys.push('t:' + norm(v.title));
    const b = baseName(v.file_path);
    if (b && v.category) keys.push('fc:' + b + '|' + norm(v.category));
    if (b && v.line) keys.push('fl:' + b + '|' + v.line);
    return keys;
  };

  const baseVulns = load(baseId);
  const targetVulns = load(targetId);
  const baseKeys = new Set<string>();
  for (const v of baseVulns) for (const k of keysOf(v)) baseKeys.add(k);
  const targetKeys = new Set<string>();
  for (const v of targetVulns) for (const k of keysOf(v)) targetKeys.add(k);

  const inBase = (v: V) => keysOf(v).some((k) => baseKeys.has(k));
  const inTarget = (v: V) => keysOf(v).some((k) => targetKeys.has(k));

  const added = targetVulns.filter((v) => !inBase(v)); // 新版本独有（新增）
  const fixed = baseVulns.filter((v) => !inTarget(v)); // 旧版本有、新版本没有（疑似已修复）
  const common = targetVulns.filter((v) => inBase(v)); // 两版本都有（共有）

  res.json({
    base: { projectId: baseId, version: base.source_version, name: base.project_name },
    target: { projectId: targetId, version: target.source_version, name: target.project_name },
    added,
    fixed,
    common,
  });
});

router.get('/projects/check-name', (req, res) => {
  const name = String(req.query.name || '').trim();
  res.json({ available: !!name && !projectNameExists(name) });
});

router.get('/projects/:id', (req, res) => {
  const mode = String(req.query.mode ?? '').toLowerCase();
  const summaryMode = mode === 'summary' || String(req.query.summary ?? '') === '1';
  const compactMode =
    summaryMode || mode === 'compact' || String(req.query.compact ?? '') === '1';

  // 无模式参数时保持旧查询、旧字段和旧响应完全不变。
  if (!compactMode) {
    const project = getProject(req.params.id);
    if (!project) return res.status(404).json({ error: '项目不存在' });
    const vulnerabilities = db
      .prepare(
        "SELECT * FROM vulnerabilities WHERE project_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
      )
      .all(req.params.id) as Vulnerability[];
    return res.json({ project: attachProjectKind(project), vulnerabilities });
  }

  // compact/summary 不读取可能达数 MB 的 exploit_report；summary 也不读取漏洞行。
  const project = db
    .prepare(`SELECT ${PROJECT_SUMMARY_COLUMNS} FROM projects WHERE id = ?`)
    .get(req.params.id) as Project | undefined;
  if (!project) return res.status(404).json({ error: '项目不存在' });
  const vulnerabilityCount =
    project.count_critical +
    project.count_high +
    project.count_medium +
    project.count_low +
    project.count_info;
  if (summaryMode) {
    return res.json({
      project: attachProjectKind(project),
      vulnerabilities: [],
      vulnerabilityCount,
    });
  }

  const vulnerabilities = db
    .prepare(
      `SELECT id, project_id, title, severity, severity_original, regrade_value,
              category, file_path, line, verified, frontend_rce, auth_required,
              cluster_id, cluster_role, created_at
       FROM vulnerabilities
       WHERE project_id = ?
       ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
         WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`
    )
    .all(req.params.id);
  res.json({
    project: attachProjectKind(project),
    vulnerabilities,
    vulnerabilityCount,
  });
});

/** 项目内按需获取单条完整漏洞详情。 */
router.get('/projects/:id/vulnerabilities/:vulnerabilityId', (req, res) => {
  const vulnerability = loadVulnerabilityDetail(
    req.params.vulnerabilityId,
    req.params.id
  );
  if (!vulnerability) return res.status(404).json({ error: '漏洞不存在' });
  res.json(vulnerability);
});

/**
 * 独立获取大型利用报告。响应体直接是 ExploitReport JSON 对象；无报告为 null，
 * 从而 compact/summary 项目请求无需承担该字段的 SQLite 读取与传输成本。
 */
router.get('/projects/:id/exploit-report', (req, res) => {
  const exists = db.prepare('SELECT 1 AS ok FROM projects WHERE id = ?').get(req.params.id);
  if (!exists) return res.status(404).json({ error: '项目不存在' });
  // exploit_report 可达数 MB，JSON.parse 也不便宜；短 TTL 缓存去重详情页/验证轮询的重复解析。
  // 相关写路径（saveExploitReport → invalidateExploitReads）会提升 project-detail 版本立即失效。
  const payload = readThroughCache<{ ok: boolean; value: unknown }>(
    'project-detail',
    `exploit-report:${req.params.id}`,
    3_000,
    () => {
      const row = db
        .prepare('SELECT exploit_report FROM projects WHERE id = ?')
        .get(req.params.id) as { exploit_report: string | null } | undefined;
      if (!row || !row.exploit_report) return { ok: true, value: null };
      try {
        return { ok: true, value: JSON.parse(row.exploit_report) as unknown };
      } catch {
        return { ok: false, value: null };
      }
    }
  );
  if (!payload.ok) return res.status(500).json({ error: '利用报告数据损坏' });
  res.json(payload.value);
});

/** 权威远程验证进度：来自按漏洞 ID 持久化的验证项，不再由报告占位行推算。 */
router.get('/projects/:id/verification-progress', (req, res) => {
  const project = db.prepare('SELECT 1 AS ok FROM projects WHERE id = ?').get(req.params.id);
  if (!project) return res.status(404).json({ error: '项目不存在' });
  // 详情页轮询会高频命中；短 TTL 缓存聚合结果，验证状态变化时经 invalidate* 立即失效。
  res.json(
    readThroughCache('project-detail', `progress:${req.params.id}`, 1_500, () =>
      getProjectVerificationProgress(req.params.id)
    )
  );
});

/** 项目验证项详情（轻量字段），供详情页解释排队/运行/受限/失败。 */
router.get('/projects/:id/verification-items', (req, res) => {
  const project = db.prepare('SELECT 1 AS ok FROM projects WHERE id = ?').get(req.params.id);
  if (!project) return res.status(404).json({ error: '项目不存在' });
  res.json(listProjectVerificationItems(req.params.id));
});

/** 编辑项目名 / 版本号（便于版本对比）。 */
router.patch('/projects/:id', (req, res) => {
  const body = (req.body || {}) as {
    project_name?: string;
    source_version?: string | null;
    system_name?: string | null;
  };
  try {
    const updated = updateProjectMeta(req.params.id, {
      projectName: body.project_name,
      sourceVersion: body.source_version,
      systemName: body.system_name,
    });
    if (!updated) return res.status(404).json({ error: '项目不存在' });
    res.json(updated);
  } catch (e: any) {
    res.status(400).json({ error: e?.message || '更新失败' });
  }
});

router.get('/projects/:id/events', (req, res) => {
  // 可选 limit：只返回最近 N 条（仍按时间升序），减小超长审计（数千条事件）的首屏传输/解析负担。
  // 不传或非法则返回全部，保持旧行为与阶段判定的完整性。
  const rawLimit = parseInt(String(req.query.limit ?? ''), 10);
  const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? rawLimit : 0;
  const eventColumns = "id, project_id, ts, kind, agent, tool, text, '' AS raw, phase";
  const events = limit
    ? (db
        .prepare(`SELECT ${eventColumns} FROM agent_events WHERE project_id = ? ORDER BY ts DESC LIMIT ?`)
        .all(req.params.id, limit) as AgentEvent[]).reverse()
    : (db
        .prepare(`SELECT ${eventColumns} FROM agent_events WHERE project_id = ? ORDER BY ts ASC`)
        .all(req.params.id) as AgentEvent[]);
  res.json(events);
});

/** 流程图阶段锚点：仅返回少量 system 里程碑事件（不受 events?limit 截断影响）。 */
router.get('/projects/:id/events/anchors', (req, res) => {
  const events = db
    .prepare(
      `SELECT id, project_id, ts, kind, agent, tool, text, '' AS raw, phase FROM agent_events
       WHERE project_id = ? AND kind = 'system'
         AND (text LIKE '▶%' OR text LIKE '✓%' OR text LIKE '审计会话%')
       ORDER BY ts ASC`
    )
    .all(req.params.id) as AgentEvent[];
  res.json(events);
});

/** 下载该项目已归档的完整 Pi 日志（gzip JSONL）。 */
router.get('/projects/:id/events/archive', (req, res) => {
  const archived = archiveProjectEvents(req.params.id);
  if (archived.archived === 0) return res.status(404).json({ error: '该项目暂无日志' });
  res.download(eventArchivePath(req.params.id), `${req.params.id}-events.jsonl.gz`);
});

/** 每次 Pi Agent 阶段的原始 prompt/stdout/stderr 运行清单。 */
router.get('/projects/:id/logs/runs', (req, res) => {
  // 该聚合在大库上对 GB 级 content 做 SUM(length(...))，重项目可达 ~1s。
  // 运行清单边界变化很慢，短 TTL 缓存即可消除重复的昂贵聚合。
  const rows = readThroughCache('project-detail', `logs-runs:${req.params.id}`, 5_000, () =>
    db
      .prepare(
        `SELECT run_id, phase, channel, MIN(ts) AS started_at, MAX(ts) AS finished_at,
                COUNT(*) AS chunks, SUM(length(content)) AS bytes
         FROM project_run_logs
         WHERE project_id = ?
         GROUP BY run_id, phase, channel
         ORDER BY started_at ASC`
      )
      .all(req.params.id)
  );
  res.json(rows);
});

/**
 * 原始进程日志（SQLite 权威源）。
 * 默认分页 JSON；download=1 时导出当前项目/指定 run_id 的完整 gzip JSONL。
 */
router.get('/projects/:id/logs/raw', (req, res) => {
  const runId = String(req.query.run_id || '').trim();
  const where = runId ? 'project_id = ? AND run_id = ?' : 'project_id = ?';
  const params: unknown[] = runId ? [req.params.id, runId] : [req.params.id];
  if (req.query.download === '1') {
    // 流式导出：单项目日志可达数十万行（历史上有 40 万行/项目）。旧实现 .all() 全量入内存
    // 再拼大字符串 + gzipSync，一个大项目单请求就能吃掉 >1GB 堆、把后端 OOM 掉。
    // 现改为游标 .iterate() 惰性取行 + zlib.createGzip 流式压缩，内存占用与项目大小无关。
    const hasAny = db
      .prepare(`SELECT 1 FROM project_run_logs WHERE ${where} LIMIT 1`)
      .get(...params);
    if (!hasAny) return res.status(404).json({ error: '该项目暂无原始运行日志' });
    const stmt = db.prepare(
      `SELECT id, project_id, run_id, ts, phase, channel, stream, seq, content
       FROM project_run_logs WHERE ${where}
       ORDER BY ts ASC, run_id ASC, seq ASC`
    );
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader(
      'Content-Disposition',
      contentDispositionAttachment(
        req.params.id,
        runId ? `${runId}-raw-logs.jsonl.gz` : 'raw-logs.jsonl.gz'
      )
    );
    const gzip = zlib.createGzip({ level: zlib.constants.Z_BEST_SPEED });
    // Readable.from 会按下游背压节奏惰性拉取生成器，从而暂停 SQLite 游标，全程内存有界。
    const source = Readable.from(
      (function* () {
        for (const row of stmt.iterate(...params)) {
          yield JSON.stringify(row) + '\n';
        }
      })()
    );
    source.on('error', (err) => gzip.destroy(err as Error));
    gzip.on('error', () => {
      if (!res.headersSent) res.status(500);
      res.end();
    });
    // 客户端中断时销毁上游，及时释放 SQLite 游标，避免长时间持有读句柄。
    res.on('close', () => source.destroy());
    source.pipe(gzip).pipe(res);
    return;
  }
  const requestedLimit = Number(req.query.limit || 500);
  const requestedOffset = Number(req.query.offset || 0);
  const limit = Number.isFinite(requestedLimit)
    ? Math.max(1, Math.min(5000, Math.floor(requestedLimit)))
    : 500;
  const offset = Number.isFinite(requestedOffset) ? Math.max(0, Math.floor(requestedOffset)) : 0;
  const total = (
    db.prepare(`SELECT COUNT(*) AS c FROM project_run_logs WHERE ${where}`).get(...params) as {
      c: number;
    }
  ).c;
  const items = db
    .prepare(
      `SELECT id, project_id, run_id, ts, phase, channel, stream, seq, content
       FROM project_run_logs WHERE ${where}
       ORDER BY ts ASC, run_id ASC, seq ASC LIMIT ? OFFSET ?`
    )
    .all(...params, limit, offset);
  res.json({ items, total, limit, offset });
});

router.get('/projects/:id/report', (req, res) => {
  const html = generateReport(req.params.id);
  if (!html) return res.status(404).send('项目不存在');
  const project = getProject(req.params.id)!;
  const download = req.query.download === '1';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  if (download) {
    res.setHeader(
      'Content-Disposition',
      contentDispositionAttachment(`审计报告-${project.project_name}`, 'html')
    );
  }
  res.send(html);
});

/* --------------------------- 创建：上传压缩包 --------------------------- */
router.post('/projects/upload', upload.array('files'), (req, res) => {
  const files = (req.files as Express.Multer.File[]) || [];
  if (files.length === 0) return res.status(400).json({ error: '未收到文件' });

  let names: string[] = [];
  try {
    if (req.body.names) names = JSON.parse(req.body.names);
  } catch {
    names = [];
  }
  const options = parseAuditOptions(req.body.options);
  const auditLanguage = String(req.body.audit_language || req.body.auditLanguage || '').trim();
  if (!isAuditLanguage(auditLanguage)) {
    return res.status(400).json({ error: '请选择审计语言（11 选 1）' });
  }

  const created: Project[] = [];
  for (let idx = 0; idx < files.length; idx++) {
    const file = files[idx];
    const original = decodeName(file.originalname);
    const ext = path.extname(original).toLowerCase();
    if (ext !== '.zip') {
      return res.status(400).json({ error: '仅支持 .zip 压缩包' });
    }
    const project = createProject({
      projectName: names[idx]?.trim() || undefined,
      archiveName: original,
      sourceType: 'zip',
      sourceRef: file.path,
      options,
      auditLanguage,
    });
    created.push(project);
  }
  for (const p of created) enqueueAudit(p.id);
  res.json({ created });
});

/* --------------------------- 创建：GitHub 链接 --------------------------- */
router.post('/projects/github/preview', (req, res) => {
  const repos = (req.body.repos || []) as { url: string; projectName?: string }[];
  if (!Array.isArray(repos) || repos.length === 0) {
    return res.status(400).json({ error: '请提供至少一个 GitHub 地址' });
  }
  res.json(analyzeGithubImport(repos));
});

router.post('/projects/github', (req, res) => {
  const repos = (req.body.repos || []) as { url: string; projectName?: string }[];
  if (!Array.isArray(repos) || repos.length === 0) {
    return res.status(400).json({ error: '请提供至少一个 GitHub 地址' });
  }
  const scopeRaw = String(req.body.auditScope || 'all');
  const auditScope: GithubAuditScope = ['all', 'new_projects_only', 'new_versions_only'].includes(
    scopeRaw
  )
    ? (scopeRaw as GithubAuditScope)
    : 'all';
  const options = parseAuditOptions(req.body.options);
  const auditLanguage = String(req.body.audit_language || req.body.auditLanguage || '').trim();
  if (!isAuditLanguage(auditLanguage)) {
    return res.status(400).json({ error: '请选择审计语言（11 选 1）' });
  }
  const { repos: toCreate, skipped } = filterGithubReposForScope(repos, auditScope);
  const created: Project[] = [];
  for (const r of toCreate) {
    const url = String(r.url || '').trim();
    if (!url) continue;
    const parsed = parseGithubRepoForCreate(url);
    if (!parsed) continue;
    const project = createProject({
      projectName: r.projectName?.trim() || undefined,
      archiveName: parsed.gitRef ? `${parsed.repo}@${parsed.gitRef}` : url,
      sourceType: 'github',
      sourceRef: parsed.canonicalUrl,
      sourceVersion: parsed.gitRef,
      gitRef: parsed.gitRef,
      systemName: parsed.systemName,
      options,
      auditLanguage,
    });
    created.push(project);
  }
  for (const p of created) enqueueAudit(p.id);
  res.json({ created, skipped, auditScope });
});

/* ------------------- 多版本批量审计：近 N 年改动最大的 TopN 版本 ------------------- */
router.post('/projects/:id/batch-versions', async (req, res) => {
  const project = getProject(req.params.id);
  if (!project) return res.status(404).json({ error: '项目不存在' });

  const years = [1, 2, 3].includes(Number(req.body?.years)) ? Number(req.body.years) : 1;
  const topN = [3, 5, 10].includes(Number(req.body?.topN)) ? Number(req.body.topN) : 5;

  // 解析仓库地址：github 项目用自身地址；压缩包项目必须提供 githubUrl
  let url = '';
  if (project.source_type === 'github') {
    url = project.source_ref;
  } else {
    url = String(req.body?.githubUrl || '').trim();
    if (!url) return res.status(400).json({ error: '压缩包项目请填写该项目的 GitHub 地址' });
  }
  if (!parseOwnerRepo(url)) return res.status(400).json({ error: '无效的 GitHub 仓库地址' });

  try {
    const exclude = project.source_version ? [project.source_version] : [];
    const { candidates, hadReleases, error } = await rankBiggestChangeVersions(
      url,
      years,
      topN,
      exclude
    );
    if (error) {
      // GitHub API 失败（限流/认证/网络）：返回真实原因，避免误报"没有 release"
      return res.status(502).json({ error });
    }
    if (!hadReleases) {
      return res
        .status(400)
        .json({ error: '该仓库在 GitHub 上没有可用的 release/tag，无法进行多版本审计' });
    }
    if (candidates.length === 0) {
      return res
        .status(400)
        .json({ error: `近 ${years} 年内没有可审计的版本（可能都已排除或无 release）` });
    }

    const systemName = project.system_name || repoNameFromUrl(url);
    // 多版本项目继承源项目的审计流程选项（NULL→undefined 沿用全局默认）
    const inheritRt = String(project.opt_verify_runtime || '').trim().toLowerCase();
    const inheritOptions = {
      auto_verify: project.opt_auto_verify == null ? undefined : project.opt_auto_verify === 1,
      verify_history: project.opt_verify_history == null ? undefined : project.opt_verify_history === 1,
      ai_dedup: project.opt_ai_dedup == null ? undefined : project.opt_ai_dedup === 1,
      ai_regrade: project.opt_ai_regrade == null ? undefined : project.opt_ai_regrade === 1,
      verify_runtime:
        inheritRt === 'mini' || inheritRt === 'full'
          ? ('full' as const)
          : inheritRt === 'none'
            ? ('none' as const)
            : project.opt_auto_verify === 1
              ? ('full' as const)
              : project.opt_auto_verify === 0
                ? ('none' as const)
                : undefined,
    };
    const created: Project[] = [];
    const skipped: string[] = [];
    for (const c of candidates) {
      // 跳过已存在同系统同版本的 github 项目，避免重复审计
      const dup = db
        .prepare(
          "SELECT 1 FROM projects WHERE source_type='github' AND source_version = ? AND system_name = ?"
        )
        .get(c.tag, systemName);
      if (dup) {
        skipped.push(c.tag);
        continue;
      }
      const p = createProject({
        projectName: `${systemName}-${c.tag}`,
        archiveName: `${repoNameFromUrl(url)}@${c.tag}`,
        sourceType: 'github',
        sourceRef: url,
        sourceVersion: c.tag,
        systemName,
        gitRef: c.tag,
        options: inheritOptions,
        auditLanguage: project.audit_language || undefined,
      });
      created.push(p);
      enqueueAudit(p.id);
    }
    res.json({ created, candidates, skipped });
  } catch (e: any) {
    res.status(500).json({ error: String(e?.message || e).slice(0, 300) });
  }
});

/* --------------------------- 批量操作（须在 /:id 之前注册，避免 "bulk" 被当作 id） --------------------------- */
router.post('/projects/bulk/resume', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  if (ids.length === 0) return res.json({ ok: true, count: 0 });
  const ASYNC_THRESHOLD = 50;
  if (ids.length >= ASYNC_THRESHOLD) {
    res.json({ ok: true, accepted: ids.length, async: true });
    setImmediate(() => bulkScheduleResume(ids));
    return;
  }
  const result = bulkScheduleResume(ids);
  res.json({ ok: result.failed.length === 0, count: result.queued, failed: result.failed });
});

/** 一次性恢复 Web-only 策略误暂停的审计任务（运行中后端可调用，无需重启）。 */
router.post('/projects/bulk/recover-mispaused', (_req, res) => {
  if (getSetting('mispaused_audit_recovery_v1') === '1') {
    const paused = db
      .prepare("SELECT COUNT(*) as c FROM projects WHERE status='paused' AND verify_status='none' AND has_web IS NULL")
      .get() as { c: number };
    return res.json({ ok: true, alreadyDone: true, remaining: paused.c });
  }
  const result = recoverMispausedAudits();
  setSetting('mispaused_audit_recovery_v1', '1');
  res.json({ ok: true, ...result });
});

/** 校正「审计已完成却标成 paused」的脏数据，使其进入「代码审计完成」。 */
router.post('/projects/bulk/reconcile-mispaused-completed', (_req, res) => {
  const fixed = reconcileMispausedCompletedAudits();
  res.json({ ok: true, fixed });
});

/** 只读：实时重算全部 completed 项目的必需子智能体 JSON 覆盖。 */
router.get('/projects/bulk/audit-coverage-audit', (_req, res) => {
  res.json({ ok: true, ...auditCompletedProjectCoverage() });
});

/**
 * 将已审查且覆盖不完整的 completed 项目标记 failed。
 * 保留源码、JSON/ 原始产物和代码审计漏洞；清除基于不完整审计产生的远程验证结果。
 */
router.post('/projects/bulk/audit-coverage-invalidate', (req, res) => {
  const ids = Array.isArray(req.body?.ids) ? (req.body.ids as string[]).filter(Boolean) : [];
  if (!ids.length) return res.status(400).json({ error: '缺少 ids' });
  if (req.body?.confirm !== true) {
    return res.status(400).json({ error: '需要 confirm:true 才会标记失败' });
  }
  res.json({ ok: true, ...applyAuditCoverageInvalidations(ids) });
});

/** 清空不可复算 completed 的结果并转 paused；完整历史日志保留。 */
router.post('/projects/bulk/audit-coverage-reset-unverifiable', (req, res) => {
  if (req.body?.confirm !== true) {
    return res.status(400).json({ error: '需要 confirm:true 才会清除审计数据并转入已暂停' });
  }
  const ids = Array.isArray(req.body?.ids)
    ? (req.body.ids as string[]).filter(Boolean)
    : undefined;
  res.json({ ok: true, ...resetUnverifiableCompletedAudits(ids) });
});

/** 清空全部 status=paused 项目的审计/验证结果与磁盘 JSON/ 产物；继续时走全量 doAudit。 */
router.post('/projects/bulk/reset-paused-audit', (req, res) => {
  if (req.body?.confirm !== true) {
    return res.status(400).json({ error: '需要 confirm:true 才会清除已暂停项目的审计数据' });
  }
  const ids = Array.isArray(req.body?.ids)
    ? (req.body.ids as string[]).filter(Boolean)
    : undefined;
  res.json({ ok: true, ...resetPausedAuditProjects(ids) });
});

/** 只读审计所有已物化 TARGET_ENV 的 DB→源码→镜像→运行时来源链。 */
router.get('/projects/bulk/target-provenance', (_req, res) => {
  res.json({ ok: true, ...reconcileStrictTargetProvenance(false) });
});

/** 强制阻断不合格靶机；不启动/停止容器，也不触发产品环境构建。 */
router.post('/projects/bulk/target-provenance/enforce', (req, res) => {
  if (req.body?.confirm !== true) {
    return res.status(400).json({ error: '需要 confirm:true 才会更新靶机状态' });
  }
  res.json({ ok: true, ...reconcileStrictTargetProvenance(true) });
});

/**
 * 只读：审计 verify_done / verify_paused 的源码版本 vs 远程靶机版本对应关系。
 * 严格规则：缺少可证明对应证据一律视为不可保留。
 */
router.get('/projects/bulk/verify-version-audit', (_req, res) => {
  res.json({ ok: true, ...auditVerifyVersionCohort() });
});

/**
 * 应用版本审计清除：仅接受已审查的 project ids。
 * 只清除远程验证结果，保留代码审计发现，并将 verify_status 置为 none（回到 audit_done）。
 * body: { ids: string[], confirm: true }
 */
router.post('/projects/bulk/verify-version-invalidate', (req, res) => {
  const ids = Array.isArray(req.body?.ids) ? (req.body.ids as string[]).filter(Boolean) : [];
  if (!ids.length) return res.status(400).json({ error: '缺少 ids' });
  if (req.body?.confirm !== true) {
    return res.status(400).json({ error: '需要 confirm:true 才会执行清除' });
  }
  const result = applyVerifyVersionInvalidations(ids);
  res.json({ ok: true, ...result });
});

/**
 * 全局清除全部远程验证残留（含 verify_status=none 但仍有 verified=1 / VV / chains 的脏数据）。
 * body: { confirm: true }
 */
router.post('/projects/bulk/purge-remote-verify-residue', (req, res) => {
  if (req.body?.confirm !== true) {
    return res.status(400).json({ error: '需要 confirm:true 才会执行清除' });
  }
  const result = purgeAllRemoteVerifyResidue(
    String(req.body?.reason || '全局清除：漏洞库仍显示已远程验证，但 verify_done 为空')
  );
  res.json({ ok: true, ...result });
});

router.post('/projects/bulk/pause', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  for (const id of ids) if (getProject(id)) pauseProject(id);
  res.json({ ok: true, count: ids.length });
});

/** 暂停所有无 Web 端项目的验证（不影响审计；含 Web 端项目继续验证）。 */
router.post('/projects/bulk/pause-non-web-verify', (_req, res) => {
  const ids = pauseNonWebVerifyProjects();
  res.json({ ok: true, count: ids.length, ids });
});

/** Cursor 编排批次：终止产品 Pi 远程验证，仅保留 Cursor 子智能体验证。 */
router.post('/projects/bulk/cursor-verify-guard', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  const stopped = stopPiVerifyForCursorManagedBatch(ids);
  res.json({ ok: true, stopped, count: stopped.length });
});

router.post('/projects/bulk/delete', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  const failed: { id: string; error: string }[] = [];
  let count = 0;
  for (const id of ids) {
    if (!getProject(id)) continue;
    try {
      // 统一走 purgeProject：删除前写入回收站，再清任务/工作区/压缩包/数据库
      purgeProject(id, 'bulk');
      count += 1;
    } catch (e: any) {
      failed.push({ id, error: String(e?.message || e).slice(0, 200) });
    }
  }
  res.json({ ok: failed.length === 0, count, failed });
});

// 批量重新代码审计
router.post('/projects/bulk/reaudit', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  let count = 0;
  for (const id of ids) if (getProject(id) && restartAudit(id, false)) count += 1;
  res.json({ ok: true, count });
});

// 批量重新靶机验证（仅审计已完成的项目生效）
router.post('/projects/bulk/reverify', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  const vh = (req.body || {}).verify_history;
  let count = 0;
  let skipped = 0;
  for (const id of ids) {
    if (!getProject(id)) continue;
    if (typeof vh === 'boolean') {
      db.prepare('UPDATE projects SET opt_verify_history = ? WHERE id = ?').run(vh ? 1 : 0, id);
      invalidateProjectStatusReads();
    }
    if (restartVerify(id)) count += 1;
    else skipped += 1;
  }
  res.json({ ok: true, count, skipped });
});

// 批量仅重跑组合链验证（远程验证·组合）：复用已有单漏洞结果，只重跑组合利用链
router.post('/projects/bulk/reverify-chain', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  let count = 0;
  let skipped = 0;
  for (const id of ids) {
    if (!getProject(id)) continue;
    if (restartVerifyChain(id)) count += 1;
    else skipped += 1;
  }
  res.json({ ok: true, count, skipped });
});

// 批量重跑全流程（代码审计 + 靶机验证）
router.post('/projects/bulk/refull', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  let count = 0;
  for (const id of ids) if (getProject(id) && restartAudit(id, true)) count += 1;
  res.json({ ok: true, count });
});

// 批量复用子智能体结果重跑（跳过子智能体审计，仅重跑 去重→验证→评级）
router.post('/projects/bulk/reprocess', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  const chainVerify = req.body?.chainVerify === true || req.body?.chainVerify === 'true';
  let count = 0;
  for (const id of ids) if (getProject(id) && restartReprocess(id, chainVerify)) count += 1;
  res.json({ ok: true, count });
});

// 批量从磁盘重新汇总（不重跑 Pi）：把工作区已有产物一次性纳入库存
router.post('/projects/bulk/reingest', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  let count = 0;
  let totalVulns = 0;
  for (const id of ids) {
    if (!getProject(id)) continue;
    const r = reingestFromDisk(id);
    if (r.ok) {
      count += 1;
      totalVulns += r.count;
    }
  }
  res.json({ ok: true, count, totalVulns });
});

/** 自动扫描并补入库：审计已完成、DB 漏洞为 0、磁盘有产物的项目。 */
router.post('/projects/bulk/reingest-stale', (_req, res) => {
  const r = reingestAllStaleFromDisk();
  res.json({ ok: true, ...r });
});

/* ----------------------------- 项目操作 ----------------------------- */
router.post('/projects/:id/pause', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  pauseProject(req.params.id);
  res.json({ ok: true });
});

router.post('/projects/:id/resume', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  const ok = resumeProject(req.params.id);
  if (!ok) {
    return res.status(409).json({
      error: '无法继续：任务可能已在运行/排队中，或不满足当前策略（如「仅 Web 端」筛选）',
    });
  }
  res.json({ ok: true });
});

router.post('/projects/:id/verify', (req, res) => {
  const project = getProject(req.params.id);
  if (!project) return res.status(404).json({ error: '项目不存在' });
  if (project.status !== 'completed') {
    return res.status(400).json({ error: '请先完成漏洞审计后再发起验证' });
  }
  // 本次远程验证是否包含"其他历史版本"验证（前端两个入口：全流程 / 跳过其他版本）。
  // 显式传布尔即覆盖该项目的 opt_verify_history；不传则沿用项目/全局既有设置。
  const vh = (req.body || {}).verify_history;
  if (typeof vh === 'boolean') {
    db.prepare('UPDATE projects SET opt_verify_history = ? WHERE id = ?').run(vh ? 1 : 0, req.params.id);
    invalidateProjectStatusReads();
  }
  const ok = enqueueVerify(req.params.id);
  if (!ok) return res.status(409).json({ error: '验证已在进行中或排队中' });
  res.json({ ok: true });
});

// 单漏洞远程验证（item 12）：body { title }
router.post('/projects/:id/verify-one', (req, res) => {
  const project = getProject(req.params.id);
  if (!project) return res.status(404).json({ error: '项目不存在' });
  if (project.status !== 'completed') return res.status(400).json({ error: '请先完成漏洞审计' });
  const title = String((req.body || {}).title || '').trim();
  if (!title) return res.status(400).json({ error: '缺少漏洞标题' });
  const r = enqueueVerifyOne(req.params.id, title);
  // pending=true → 前端弹"等待验证"（当前有验证在跑，收尾后自动验证，靶机不关）
  res.json({ ok: true, ...r });
});

// 手动清除靶机（item 11）：验证完靶机是停止而非销毁，需用户主动清除才移除
router.post('/projects/:id/env/clear', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  clearProjectEnv(req.params.id);
  res.json({ ok: true });
});

router.post('/projects/:id/env/retry', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  const ok = retryEnvPrebuild(req.params.id);
  if (!ok) return res.status(400).json({ error: '无法重试环境搭建（项目不存在、验证进行中或非 Web 项目）' });
  res.json({ ok: true });
});

router.post('/projects/bulk/recover-env-false-failures', (_req, res) => {
  const result = recoverEnvFalseFailures();
  // 同步把 verify=queued 且 env=none 的补进预搭建队列
  void reconcileEnvAndContainers();
  res.json({ ok: true, ...result });
});

/** 立即对账靶机状态并补排队预搭建（修复 env=none/failed 卡住）。 */
router.post('/projects/bulk/reconcile-env', async (_req, res) => {
  try {
    await reconcileEnvAndContainers();
    res.json({ ok: true });
  } catch (e: unknown) {
    res.status(500).json({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});

/** 停掉 verify_queued 占用的靶机搭建，槽位只留给 verify_running。 */
router.post('/projects/bulk/prune-queued-env-builds', (_req, res) => {
  try {
    const result = pruneQueuedVerifyEnvBuilds();
    res.json({ ok: true, stopped: result.stopped.length, clearedQueue: result.clearedQueue, ids: result.stopped });
  } catch (e: unknown) {
    res.status(500).json({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});

/** 停止不在白名单内的闲置 Docker 靶机。body.verifyPipeline=true 时仅保留验证中/搭建中的项目。 */
router.post('/projects/reconcile-idle-containers', async (req, res) => {
  try {
    const verifyPipeline = !!(req.body || {}).verifyPipeline;
    const result = await reconcileIdleDockerContainers({ verifyPipeline });
    res.json({ ok: true, ...result });
  } catch (e: unknown) {
    res.status(500).json({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});

// 重新代码审计（从零开始，清空旧审计结果）
router.post('/projects/:id/reaudit', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  restartAudit(req.params.id, false);
  res.json({ ok: true });
});

// 重新靶机验证（需审计已完成）
router.post('/projects/:id/reverify', (req, res) => {
  const project = getProject(req.params.id);
  if (!project) return res.status(404).json({ error: '项目不存在' });
  if (project.status !== 'completed') {
    return res.status(400).json({ error: '请先完成代码审计后再重新验证' });
  }
  const vh = (req.body || {}).verify_history;
  if (typeof vh === 'boolean') {
    db.prepare('UPDATE projects SET opt_verify_history = ? WHERE id = ?').run(vh ? 1 : 0, req.params.id);
    invalidateProjectStatusReads();
  }
  const ok = restartVerify(req.params.id);
  if (!ok) return res.status(409).json({ error: '验证已在进行中或排队中' });
  res.json({ ok: true });
});

// 仅重跑组合链验证（远程验证·组合）：需审计已产出结果（不要求 status 恰为 completed，
// 审计完成后被暂停也可）；复用已有单漏洞结果，只重跑组合利用链
router.post('/projects/:id/reverify-chain', (req, res) => {
  const project = getProject(req.params.id);
  if (!project) return res.status(404).json({ error: '项目不存在' });
  const ok = restartVerifyChain(req.params.id);
  if (!ok) return res.status(400).json({ error: '该项目尚无可用于组合链验证的审计结果（审计未完成或非 Web 项目）' });
  res.json({ ok: true });
});

// 重跑全流程（代码审计 + 靶机验证）
router.post('/projects/:id/refull', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  restartAudit(req.params.id, true);
  res.json({ ok: true });
});

// 复用已有子智能体结果重跑（跳过专项子智能体审计，仅重跑 去重→代码级验证→二次评级）
router.post('/projects/:id/reprocess', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  const chainVerify = req.body?.chainVerify === true || req.body?.chainVerify === 'true';
  restartReprocess(req.params.id, chainVerify);
  res.json({ ok: true });
});

// 分环节运行：单独跑某环节(only) 或 从某环节跑到本流水线末尾(from)
const VALID_STAGES = ['subagent', 'dedup', 'codeverify', 'regrade', 'env', 'remote', 'chain'];
router.post('/projects/:id/stage', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  const stage = String(req.body?.stage || '');
  const mode = req.body?.mode === 'only' ? 'only' : 'from';
  if (!VALID_STAGES.includes(stage)) return res.status(400).json({ error: `无效环节：${stage}` });
  if (stage === 'remote') {
    const vh = (req.body || {}).verify_history;
    if (typeof vh === 'boolean') {
      db.prepare('UPDATE projects SET opt_verify_history = ? WHERE id = ?').run(vh ? 1 : 0, req.params.id);
      invalidateProjectStatusReads();
    }
  }
  restartStage(req.params.id, stage as any, mode);
  res.json({ ok: true });
});

// 从磁盘重新汇总（不重跑 Pi）：漏洞发现 + 远程验证组合链（chains/*.json）
router.post('/projects/:id/reingest', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  const r = reingestFromDisk(req.params.id);
  if (!r.ok) return res.status(400).json({ error: '产物目录无可汇总的结果（可能未审计或尚未归档）' });
  res.json({ ok: true, count: r.count, chains: r.chains ?? 0 });
});

/** 仅回填远程验证 exploit_report / 组合链（skill 落盘的 chains/*.json），不改动漏洞表。 */
router.post('/projects/:id/reingest-verify', (req, res) => {
  if (!getProject(req.params.id)) return res.status(404).json({ error: '项目不存在' });
  const r = reingestRemoteVerifyFromDisk(req.params.id);
  if (!r.ok) {
    return res.status(400).json({ error: '产物目录无远程验证落盘（_remote_verify/exploits 或 chains）' });
  }
  res.json({ ok: true, exploits: r.exploits, chains: r.chains });
});

router.delete('/projects/:id', (req, res) => {
  const id = req.params.id;
  if (!getProject(id)) return res.status(404).json({ error: '项目不存在' });
  try {
    // 统一走 purgeProject：删除前写入回收站，再清任务/工作区/压缩包/数据库
    purgeProject(id, 'manual');
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ error: String(e?.message || e).slice(0, 200) });
  }
});

/* ------------------------------ 回收站 ------------------------------ */
// 回收站：记录所有已删除项目（不支持还原，仅留痕）
router.get('/recycle', (req, res) => {
  const search = String(req.query.search ?? '').trim();
  const where = search
    ? `WHERE project_name LIKE ? OR source_ref LIKE ? OR archive_name LIKE ?
         OR source_link LIKE ? OR reason LIKE ? OR detail LIKE ?`
    : '';
  const like = `%${search}%`;
  const params: unknown[] = search ? [like, like, like, like, like, like] : [];
  const columns =
    'id, project_name, source_type, source_ref, archive_name, source_link, has_web, vuln_count, reason, detail, deleted_at';
  const paginated = req.query.page !== undefined || req.query.pageSize !== undefined;

  // 无分页参数时仍返回旧数组；仅 search 时返回过滤后的旧数组。
  if (!paginated) {
    const rows = db
      .prepare(
        `SELECT ${columns} FROM deleted_projects ${where} ORDER BY deleted_at DESC`
      )
      .all(...params);
    return res.json(rows);
  }

  const requestedPage = Math.max(1, parseInt(String(req.query.page ?? '1'), 10) || 1);
  const pageSize = Math.min(
    200,
    Math.max(1, parseInt(String(req.query.pageSize ?? '50'), 10) || 50)
  );
  const total = (
    db.prepare(`SELECT COUNT(*) AS c FROM deleted_projects ${where}`).get(...params) as {
      c: number;
    }
  ).c;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(requestedPage, totalPages);
  const items = db
    .prepare(
      `SELECT ${columns} FROM deleted_projects ${where}
       ORDER BY deleted_at DESC LIMIT ? OFFSET ?`
    )
    .all(...params, pageSize, (page - 1) * pageSize);
  res.json({ items, total, page, pageSize });
});

// 清空回收站记录（仅删记录，不影响已删项目本身）
router.delete('/recycle', (_req, res) => {
  const r = db.prepare('DELETE FROM deleted_projects').run();
  res.json({ ok: true, cleared: r.changes });
});

/* ------------------------ 批量 Web 端判定 + 清理 ------------------------ */
// 启动全库批量 LLM Web 端判定（未判定的首判、已判定的强制重判）
router.post('/projects/classify-web/start', (_req, res) => {
  const r = startWebClassifyBatch();
  if (!r.ok) return res.status(409).json({ error: r.error || '批处理已在进行中' });
  res.json({ ok: true, total: r.total });
});

// 查询批处理进度与非 Web 候选清单
router.get('/projects/classify-web/status', (_req, res) => {
  res.json(getWebClassifyStatus());
});

// 确认删除选中的非 Web 候选（进回收站，reason=auto_non_web）
router.post('/projects/classify-web/confirm-delete', (req, res) => {
  const ids = (req.body.ids || []) as string[];
  const r = confirmWebClassifyDelete(ids);
  res.json({ ok: true, ...r });
});

// 取消进行中的批处理
router.post('/projects/classify-web/cancel', (_req, res) => {
  cancelWebClassifyBatch();
  res.json({ ok: true });
});

/* ------------------- 新建审计：每批 Web 端前置识别进度 ------------------- */
// 查询前置识别进度（勾选"只审计 Web 端"时触发）
router.get('/projects/prescreen/status', (_req, res) => {
  res.json(getImportScreenStatus());
});
// 取消前置识别
router.post('/projects/prescreen/cancel', (_req, res) => {
  cancelImportPrescreen();
  res.json({ ok: true });
});

/* ----------------------------- 漏洞上报库 ----------------------------- */
router.get('/cve/library', (req, res) => {
  const page = Math.max(1, parseInt(String(req.query.page ?? '1'), 10) || 1);
  const pageSize = Math.min(200, Math.max(1, parseInt(String(req.query.pageSize ?? '50'), 10) || 50));
  const onlyVerified = String(req.query.onlyVerified ?? '') === '1';
  const onlyUnauth = String(req.query.onlyUnauth ?? '') === '1';
  const severity = String(req.query.severity ?? 'all');
  const search = String(req.query.search ?? '').trim();
  res.json(buildVulnLibrary({ page, pageSize, onlyVerified, onlyUnauth, severity, search }));
});

// 一键上传 CVE：body { items: [{ kind:'vuln'|'chain', ref }] } → 起 Pi Agent 用浏览器 MCP 自动填报
router.post('/cve/submit', (req, res) => {
  const items = Array.isArray((req.body || {}).items) ? req.body.items : [];
  if (items.length === 0) return res.status(400).json({ error: '未选择任何漏洞' });
  if (!getSetting('cve_email').trim()) {
    return res.status(400).json({ error: '请先到「设置」填写 CVE 上报邮箱' });
  }
  const r = startCveSubmission(items);
  res.json({ ok: true, ...r });
});

router.get('/cve/submissions/latest', (_req, res) => {
  const job = getLatestCveSubmission();
  if (!job) return res.json({ job: null });
  res.json({ job });
});

router.get('/cve/submissions/:id', (req, res) => {
  const job = getCveSubmission(req.params.id);
  if (!job) return res.status(404).json({ error: '提交任务不存在' });
  res.json({ job });
});

router.post('/cve/submissions/:id/stop', (req, res) => {
  const ok = stopCveSubmission(req.params.id);
  if (!ok) return res.status(400).json({ error: '任务未在运行或不存在' });
  res.json({ ok: true });
});

/* ----------------------------- GitHub 漏洞报送 ----------------------------- */
router.post('/github-report/submit', (req, res) => {
  const items = Array.isArray((req.body || {}).items) ? req.body.items : [];
  if (items.length === 0) return res.status(400).json({ error: '未选择任何漏洞' });
  const r = startGithubReport(items);
  res.json({ ok: true, ...r });
});

router.get('/github-report/submissions/latest', (_req, res) => {
  const job = getLatestGithubReport();
  if (!job) return res.json({ job: null });
  res.json({ job });
});

router.get('/github-report/submissions/:id', (req, res) => {
  const job = getGithubReport(req.params.id);
  if (!job) return res.status(404).json({ error: '提交任务不存在' });
  res.json({ job });
});

router.post('/github-report/submissions/:id/stop', (req, res) => {
  const ok = stopGithubReport(req.params.id);
  if (!ok) return res.status(400).json({ error: '任务未在运行或不存在' });
  res.json({ ok: true });
});

/* ----------------------------- 单漏洞 POC / Markdown ----------------------------- */
router.get('/projects/:id/vuln-poc', (req, res) => {
  const title = String(req.query.title || '').trim();
  if (!title) return res.status(400).json({ error: '缺少 title 参数' });
  const text = buildPocText(req.params.id, title);
  if (!text) return res.status(404).json({ error: '未找到已验证成功的漏洞' });
  res.type('text/plain; charset=utf-8').send(text);
});

router.get('/projects/:id/vuln-report.md', (req, res) => {
  const title = String(req.query.title || '').trim();
  if (!title) return res.status(400).json({ error: '缺少 title 参数' });
  const md = buildVulnMarkdown(req.params.id, title);
  if (!md) return res.status(404).json({ error: '未找到漏洞' });
  const v = resolveVulnTitle(req.params.id, title);
  res.setHeader('Content-Disposition', contentDispositionAttachment(v || title, 'md'));
  res.type('text/markdown; charset=utf-8').send(md);
});

/* ------------------------------- 设置 ------------------------------- */
router.get('/settings', (_req, res) => {
  res.json(getAllSettings());
});

router.put('/settings', (req, res) => {
  const allowed = [
    'audit_prompt',
    'verify_prompt',
    'default_command',
    'max_concurrency',
    'github_token',
    'poll_interval',
    'claude_path',
    'auto_verify',
    'ai_dedup',
    'dedup_keep_variants',
    'stage_timeout_min',
    'idle_timeout_min',
    'single_verify_timeout_min',
    'single_verify_idle_timeout_min',
    'settle_timeout_min',
    'env_concurrency',
    'code_verify_concurrency',
    'regrade_batch_size',
    'regrade_concurrency',
    'remote_verify_concurrency',
    'remote_verify_burst_concurrency',
    'protect_web_resources',
    'verify_global_concurrency',
    'verify_command',
    'lean_verify_prompt',
    'ai_dedup_min_candidates',
    'ai_dedup_concurrency',
    'code_verify_batch_size',
    'cve_email',
    'auto_resume_orphans_on_startup',
    'claude_jobs_enabled',
  ];
  const values: Record<string, string> = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) values[k] = String(req.body[k]);
  }
  // 并发数钳制到安全上限
  if (values.max_concurrency !== undefined) {
    const n = parseInt(values.max_concurrency, 10);
    if (Number.isFinite(n)) {
      values.max_concurrency = String(Math.min(Math.max(1, n), MAX_CONCURRENCY_CEILING));
    }
  }
  // 远程验证并发钳制到 1~12
  if (values.remote_verify_concurrency !== undefined) {
    const n = parseInt(values.remote_verify_concurrency, 10);
    if (Number.isFinite(n)) {
      values.remote_verify_concurrency = String(Math.min(Math.max(1, n), 12));
      values.verify_global_concurrency = values.remote_verify_concurrency;
    }
  }
  if (values.remote_verify_burst_concurrency !== undefined) {
    const n = parseInt(values.remote_verify_burst_concurrency, 10);
    if (Number.isFinite(n)) {
      values.remote_verify_burst_concurrency = String(Math.min(Math.max(1, n), 12));
    }
  }
  if (values.verify_global_concurrency !== undefined && values.remote_verify_concurrency === undefined) {
    const n = parseInt(values.verify_global_concurrency, 10);
    if (Number.isFinite(n)) {
      values.verify_global_concurrency = String(Math.min(Math.max(1, n), 12));
      values.remote_verify_concurrency = values.verify_global_concurrency;
    }
  }
  for (const key of ['single_verify_timeout_min', 'single_verify_idle_timeout_min']) {
    if (values[key] === undefined) continue;
    const n = parseInt(values[key], 10);
    if (Number.isFinite(n)) values[key] = String(Math.min(Math.max(3, n), 120));
  }
  // 环境搭建并发钳制到 1~12（与远程验证槽位一致，默认 3）
  if (values.env_concurrency !== undefined) {
    const n = parseInt(values.env_concurrency, 10);
    if (Number.isFinite(n)) values.env_concurrency = String(Math.min(Math.max(1, n), 12));
  }
  // 省 token 数值项钳制为非负整数（0=保持现状）
  for (const k of ['ai_dedup_min_candidates', 'code_verify_batch_size']) {
    if (values[k] !== undefined) {
      const n = parseInt(values[k], 10);
      values[k] = String(Number.isFinite(n) && n > 0 ? n : 0);
    }
  }
  if (values.regrade_batch_size !== undefined) {
    const n = parseInt(values.regrade_batch_size, 10);
    if (Number.isFinite(n)) values.regrade_batch_size = String(Math.min(Math.max(1, n), 50));
  }
  if (values.regrade_concurrency !== undefined) {
    const n = parseInt(values.regrade_concurrency, 10);
    if (Number.isFinite(n)) values.regrade_concurrency = String(Math.min(Math.max(1, n), 10));
  }
  // 旧键：AI 去重提示词建议并发，现已改走 regrade_concurrency
  if (values.ai_dedup_concurrency !== undefined) {
    const n = parseInt(values.ai_dedup_concurrency, 10);
    if (Number.isFinite(n)) {
      values.ai_dedup_concurrency = String(Math.min(Math.max(1, n), 50));
    }
  }
  // 批量 Web 判定并发钳制到 1~50（独立于代码审计并发）
  if (values.classify_concurrency !== undefined) {
    const n = parseInt(values.classify_concurrency, 10);
    if (Number.isFinite(n)) {
      values.classify_concurrency = String(Math.min(Math.max(1, n), CLASSIFY_CONCURRENCY_CEILING));
    }
  }
  setSettings(values);
  if (values.claude_jobs_enabled === '0') {
    const halted = haltAllPiJobs();
    console.log(
      `[code] 设置关闭 Pi 任务总闸：已暂停 ${halted.paused}、强杀 ${halted.killed}`
    );
  }
  // 调高/重存并发后立刻补开空槽；否则要等某个任务结束才会 startNext
  if (
    values.claude_jobs_enabled === '1' ||
    values.max_concurrency !== undefined ||
    values.remote_verify_concurrency !== undefined ||
    values.verify_global_concurrency !== undefined ||
    values.protect_web_resources !== undefined
  ) {
    kickScheduler();
  }
  res.json(getAllSettings());
});

/* ------------------------------ 监控模式 ------------------------------ */
router.get('/monitors', (_req, res) => {
  const monitors = db
    .prepare('SELECT * FROM monitors ORDER BY created_at DESC')
    .all() as Monitor[];
  res.json(monitors);
});

router.post('/monitors', (req, res) => {
  const url = String(req.body.repo_url || '').trim();
  if (!url) return res.status(400).json({ error: '请填写 GitHub 仓库地址' });
  const id = newId('m_');
  const interval = parseInt(req.body.interval_min, 10);
  db.prepare(
    `INSERT INTO monitors (id, repo_url, project_prefix, interval_min, enabled, created_at)
     VALUES (?, ?, ?, ?, 1, ?)`
  ).run(
    id,
    url,
    String(req.body.project_prefix || '').trim(),
    Number.isFinite(interval) && interval > 0 ? interval : 5,
    now()
  );
  void checkMonitorNow(id);
  res.json(db.prepare('SELECT * FROM monitors WHERE id = ?').get(id));
});

router.put('/monitors/:id', (req, res) => {
  const m = db.prepare('SELECT * FROM monitors WHERE id = ?').get(req.params.id) as Monitor | undefined;
  if (!m) return res.status(404).json({ error: '监控不存在' });
  const interval = parseInt(req.body.interval_min, 10);
  db.prepare(
    `UPDATE monitors SET repo_url=@repo_url, project_prefix=@project_prefix, interval_min=@interval_min, enabled=@enabled WHERE id=@id`
  ).run({
    id: req.params.id,
    repo_url: req.body.repo_url !== undefined ? String(req.body.repo_url) : m.repo_url,
    project_prefix:
      req.body.project_prefix !== undefined ? String(req.body.project_prefix) : m.project_prefix,
    interval_min: Number.isFinite(interval) && interval > 0 ? interval : m.interval_min,
    enabled: req.body.enabled !== undefined ? (req.body.enabled ? 1 : 0) : m.enabled,
  });
  res.json(db.prepare('SELECT * FROM monitors WHERE id = ?').get(req.params.id));
});

router.delete('/monitors/:id', (req, res) => {
  db.prepare('DELETE FROM monitors WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

router.post('/monitors/:id/check', async (req, res) => {
  await checkMonitorNow(req.params.id);
  res.json(db.prepare('SELECT * FROM monitors WHERE id = ?').get(req.params.id));
});

export default router;
