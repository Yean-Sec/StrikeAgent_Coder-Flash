import db from './db';
import {
  frontendRceKind,
  pickFrontendRceExploit,
  qualifiesFrontendRce,
  qualifiesStrictUnauthHttpRce,
} from './frontendRceCriteria';

export type FrontendRceRow = {
  id: string;
  project_id: string;
  title: string;
  category: string | null;
  description: string | null;
  auth_required: string | null;
  verified: number;
  severity: string;
  project_name: string;
  reg_default_open: number | null;
  frontend_rce_kind: 'none' | 'user';
  exploit: any;
};

/** @deprecated 别名 */
export type StrictUnauthHttpRceRow = FrontendRceRow;

type DbRow = {
  id: string;
  project_id: string;
  title: string;
  category: string | null;
  description: string | null;
  auth_required: string | null;
  verified: number;
  severity: string;
  project_name: string;
  reg_default_open: number | null;
  exploit_report: string | null;
};

function parseExploits(exploitReport: string | null): any[] {
  if (!exploitReport) return [];
  try {
    const report = JSON.parse(exploitReport);
    return Array.isArray(report?.exploits) ? report.exploits : [];
  } catch {
    return [];
  }
}

const BASE_SQL = `SELECT v.id, v.project_id, v.title, v.category, v.description, v.auth_required, v.verified,
                         v.severity, p.project_name, p.reg_default_open, p.exploit_report
                  FROM vulnerabilities v JOIN projects p ON p.id = v.project_id
                  WHERE v.verified = 1`;

/**
 * 前台 RCE（frontend_rce=1）：远程 HTTP 验证 + 标题级 RCE。
 * 含无权限(none)与注册默认开放下 user 权限 RCE。
 */
export function queryFrontendRceVulns(projectId?: string): FrontendRceRow[] {
  const rows = (
    projectId
      ? db.prepare(`${BASE_SQL} AND v.project_id = ?`).all(projectId)
      : db.prepare(BASE_SQL).all()
  ) as DbRow[];

  const out: FrontendRceRow[] = [];
  for (const r of rows) {
    const regOpen = r.reg_default_open === 1;
    const exploits = parseExploits(r.exploit_report);
    const kind = frontendRceKind(r, exploits, regOpen);
    if (!kind || !qualifiesFrontendRce(r, exploits, regOpen)) continue;
    const ex = pickFrontendRceExploit(r.title, exploits, kind);
    const { exploit_report: _drop, ...rest } = r;
    out.push({ ...rest, frontend_rce_kind: kind, exploit: ex });
  }
  return out;
}

/** 仅无权限 strict 导出用 */
export function queryStrictUnauthHttpRceVulns(projectId?: string): FrontendRceRow[] {
  return queryFrontendRceVulns(projectId).filter((v) => v.frontend_rce_kind === 'none');
}

export function countFrontendRceVulns(): number {
  return queryFrontendRceVulns().length;
}

export function countStrictUnauthHttpRceVulns(): number {
  return queryStrictUnauthHttpRceVulns().length;
}
