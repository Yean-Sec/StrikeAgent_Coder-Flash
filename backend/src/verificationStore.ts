import db from './db';
import {
  deriveMinimumAuth,
  deriveRemoteStatus,
  normalizeExploitStatus,
  normalizePrivilegeResults,
  type ExploitStatus,
  type VerificationLike,
} from './verificationStatus';

export type VerificationState =
  | 'pending'
  | 'queued'
  | 'running'
  | 'success'
  | 'restricted'
  | 'failed'
  | 'timeout';

export interface VerificationProgress {
  total: number;
  pending: number;
  queued: number;
  running: number;
  success: number;
  restricted: number;
  failed: number;
  timeout: number;
  concluded: number;
}

type VulnerabilityRow = { id: string; title: string };
type ExploitRow = VerificationLike & {
  vulnerability?: unknown;
  vulnerability_id?: unknown;
  id?: unknown;
  source_file?: unknown;
};

const TERMINAL_STATES = new Set<VerificationState>([
  'success',
  'restricted',
  'failed',
  'timeout',
]);

function normalizeTitle(value: unknown): string {
  return String(value ?? '')
    .replace(/\s+/g, '')
    .toLowerCase();
}

function titlesLooselyMatch(left: unknown, right: unknown): boolean {
  const a = normalizeTitle(left);
  const b = normalizeTitle(right);
  if (!a || !b) return false;
  if (a === b) return true;
  const short = a.length <= b.length ? a : b;
  const long = a.length <= b.length ? b : a;
  return short.length >= 12 && (long.includes(short) || long.startsWith(short.slice(0, 24)));
}

function matchExploit(vulnerability: VulnerabilityRow, exploits: ExploitRow[]): ExploitRow | undefined {
  const byId = exploits.find((entry) => {
    const id = String(entry.vulnerability_id ?? entry.id ?? '').trim();
    return id && id === vulnerability.id;
  });
  if (byId) return byId;
  return exploits.find((entry) => titlesLooselyMatch(vulnerability.title, entry.vulnerability));
}

function stateFromRemoteStatus(status: ExploitStatus): VerificationState {
  return status === 'unknown' ? 'pending' : status;
}

export function ensureProjectVerificationItems(projectId: string): number {
  const vulnerabilities = db
    .prepare(
      `SELECT id, title FROM vulnerabilities
       WHERE project_id = ? AND lower(severity) IN ('critical','high','medium')`
    )
    .all(projectId) as VulnerabilityRow[];
  const insert = db.prepare(
    `INSERT OR IGNORE INTO vulnerability_verifications
       (project_id, vulnerability_id, vulnerability_title, state, updated_at)
     VALUES (?, ?, ?, 'pending', ?)`
  );
  const timestamp = Date.now();
  const tx = db.transaction(() => {
    for (const vulnerability of vulnerabilities) {
      insert.run(projectId, vulnerability.id, vulnerability.title, timestamp);
    }
  });
  tx();
  return vulnerabilities.length;
}

export function syncProjectVerificationItems(
  projectId: string,
  rawExploits: unknown[],
  sourceFile?: string
): VerificationProgress {
  ensureProjectVerificationItems(projectId);
  const vulnerabilities = db
    .prepare(
      `SELECT id, title FROM vulnerabilities
       WHERE project_id = ? AND lower(severity) IN ('critical','high','medium')`
    )
    .all(projectId) as VulnerabilityRow[];
  const exploits = rawExploits.filter(
    (entry): entry is ExploitRow => !!entry && typeof entry === 'object'
  );
  const existingRows = db
    .prepare(
      `SELECT vulnerability_id, state FROM vulnerability_verifications WHERE project_id = ?`
    )
    .all(projectId) as { vulnerability_id: string; state: VerificationState }[];
  const existing = new Map(existingRows.map((row) => [row.vulnerability_id, row.state]));
  const upsert = db.prepare(
    `INSERT INTO vulnerability_verifications
       (project_id, vulnerability_id, vulnerability_title, state, code_status, remote_status,
        auth_required, privilege_results_json, local_result, detail, source_file,
        finished_at, updated_at, error)
     VALUES
       (@project_id, @vulnerability_id, @vulnerability_title, @state, @code_status, @remote_status,
        @auth_required, @privilege_results_json, @local_result, @detail, @source_file,
        @finished_at, @updated_at, @error)
     ON CONFLICT(project_id, vulnerability_id) DO UPDATE SET
       vulnerability_title=excluded.vulnerability_title,
       state=excluded.state,
       code_status=excluded.code_status,
       remote_status=excluded.remote_status,
       auth_required=excluded.auth_required,
       privilege_results_json=excluded.privilege_results_json,
       local_result=excluded.local_result,
       detail=excluded.detail,
       source_file=COALESCE(excluded.source_file, vulnerability_verifications.source_file),
       finished_at=excluded.finished_at,
       updated_at=excluded.updated_at,
       error=excluded.error`
  );
  const timestamp = Date.now();
  const tx = db.transaction(() => {
    for (const vulnerability of vulnerabilities) {
      const entry = matchExploit(vulnerability, exploits);
      if (!entry) continue;
      const privilegeResults = normalizePrivilegeResults(entry.privilege_results);
      const remoteStatus = deriveRemoteStatus({ ...entry, privilege_results: privilegeResults });
      const codeStatus = normalizeExploitStatus(entry.local_exploitable ?? entry.status);
      let state = stateFromRemoteStatus(remoteStatus);
      const priorState = existing.get(vulnerability.id);
      // unknown 占位不得覆盖已经落定的 success/restricted/failed/timeout 账本，
      // 否则组合链收尾会把证据冲掉，详情页计数还在、列表却是空的。
      if (state === 'pending' && priorState && TERMINAL_STATES.has(priorState)) {
        continue;
      }
      upsert.run({
        project_id: projectId,
        vulnerability_id: vulnerability.id,
        vulnerability_title: vulnerability.title,
        state,
        code_status: codeStatus,
        remote_status: remoteStatus,
        auth_required: deriveMinimumAuth(privilegeResults, entry.auth_required),
        privilege_results_json: privilegeResults ? JSON.stringify(privilegeResults) : null,
        local_result: String(entry.local_result ?? '').slice(0, 20_000),
        detail: String(entry.detail ?? '').slice(0, 20_000),
        source_file: sourceFile ?? (entry.source_file ? String(entry.source_file) : null),
        finished_at: state === 'pending' ? null : timestamp,
        updated_at: timestamp,
        error: null,
      });
    }
  });
  tx();
  return getProjectVerificationProgress(projectId);
}

export function setVerificationItemState(
  projectId: string,
  vulnerabilityId: string,
  state: VerificationState,
  error: string | null = null
): void {
  ensureProjectVerificationItems(projectId);
  const timestamp = Date.now();
  const startedAt = state === 'running' ? timestamp : null;
  const finishedAt = TERMINAL_STATES.has(state) ? timestamp : null;
  db.prepare(
    `UPDATE vulnerability_verifications
     SET state = ?, remote_status = CASE
           WHEN ? IN ('success','restricted','failed') THEN ?
           WHEN ? = 'timeout' THEN 'restricted'
           ELSE remote_status
         END,
         attempt_count = attempt_count + CASE WHEN ? = 'queued' AND state <> 'queued' THEN 1 ELSE 0 END,
         queued_at = CASE WHEN ? = 'queued' THEN ? ELSE queued_at END,
         started_at = COALESCE(?, started_at),
         finished_at = ?,
         updated_at = ?,
         error = ?
     WHERE project_id = ? AND vulnerability_id = ?`
  ).run(
    state,
    state,
    state,
    state,
    state,
    state,
    timestamp,
    startedAt,
    finishedAt,
    timestamp,
    error,
    projectId,
    vulnerabilityId
  );
}

export function markUnknownVerificationItemsPending(projectId: string): void {
  ensureProjectVerificationItems(projectId);
  db.prepare(
    `UPDATE vulnerability_verifications
     SET state = 'pending', remote_status = 'unknown', updated_at = ?
     WHERE project_id = ? AND state NOT IN ('success','restricted','failed','timeout')`
  ).run(Date.now(), projectId);
}

// 纯只读进度：曾经每次都调用 ensureProjectVerificationItems 写库，导致详情页最热的
// GET /verification-progress 变成读写混合，在验证进行中反复抢占 SQLite 写锁。
// 现在改为——total 直接由待验证漏洞（critical/high/medium）数量给出，各状态计数从
// vulnerability_verifications 聚合；尚未建行的漏洞隐式计入 pending。行的创建收敛到
// 验证生命周期（enqueue / 状态流转 / 结果入库）。语义与原先一致，但不再写库。
export function getProjectVerificationProgress(projectId: string): VerificationProgress {
  const base = (
    db
      .prepare(
        `SELECT COUNT(*) AS total FROM vulnerabilities
         WHERE project_id = ? AND lower(severity) IN ('critical','high','medium')`
      )
      .get(projectId) as { total: number | null }
  ).total;
  const row = db
    .prepare(
      `SELECT SUM(CASE WHEN state='queued' THEN 1 ELSE 0 END) AS queued,
              SUM(CASE WHEN state='running' THEN 1 ELSE 0 END) AS running,
              SUM(CASE WHEN state='success' THEN 1 ELSE 0 END) AS success,
              SUM(CASE WHEN state='restricted' THEN 1 ELSE 0 END) AS restricted,
              SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END) AS failed,
              SUM(CASE WHEN state='timeout' THEN 1 ELSE 0 END) AS timeout
       FROM vulnerability_verifications WHERE project_id = ?`
    )
    .get(projectId) as Record<string, number | null>;
  const value = (key: string) => Number(row?.[key] || 0);
  const queued = value('queued');
  const running = value('running');
  const success = value('success');
  const restricted = value('restricted');
  const failed = value('failed');
  const timeout = value('timeout');
  const concluded = success + restricted + failed + timeout;
  // total 以"待验证漏洞总数"与"账目行总数"的较大者为准，避免任一侧短暂落后导致进度回退。
  const accounted = queued + running + concluded;
  const total = Math.max(Number(base || 0), accounted);
  const pending = Math.max(0, total - accounted);
  return {
    total,
    pending,
    queued,
    running,
    success,
    restricted,
    failed,
    timeout,
    concluded,
  };
}

export function listProjectVerificationItems(projectId: string): unknown[] {
  return db
    .prepare(
      `SELECT vulnerability_id, vulnerability_title, state, code_status, remote_status,
              auth_required, privilege_results_json, local_result, detail, source_file,
              attempt_count, queued_at, started_at, finished_at, updated_at, error
       FROM vulnerability_verifications
       WHERE project_id = ?
       ORDER BY updated_at DESC`
    )
    .all(projectId)
    .map((row: any) => ({
      ...row,
      privilege_results: row.privilege_results_json
        ? safeJsonParse(row.privilege_results_json)
        : undefined,
      privilege_results_json: undefined,
    }));
}

function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

export function backfillVerificationItemsFromReports(): {
  projects: number;
  items: number;
} {
  const projects = db
    .prepare(`SELECT id, exploit_report FROM projects WHERE exploit_report IS NOT NULL`)
    .all() as { id: string; exploit_report: string }[];
  let items = 0;
  for (const project of projects) {
    let report: any;
    try {
      report = JSON.parse(project.exploit_report);
    } catch {
      continue;
    }
    const exploits = Array.isArray(report?.exploits) ? report.exploits : [];
    const progress = syncProjectVerificationItems(project.id, exploits, 'historical-exploit-report');
    db.prepare(
      `UPDATE vulnerabilities
       SET verified = CASE WHEN EXISTS (
         SELECT 1 FROM vulnerability_verifications vv
         WHERE vv.project_id = vulnerabilities.project_id
           AND vv.vulnerability_id = vulnerabilities.id
           AND vv.remote_status = 'success'
       ) THEN 1 ELSE 0 END
       WHERE project_id = ?`
    ).run(project.id);
    items += progress.total;
  }
  return { projects: projects.length, items };
}
