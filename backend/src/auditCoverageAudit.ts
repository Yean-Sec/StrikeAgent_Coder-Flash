import fs from 'fs';
import path from 'path';
import db from './db';
import { clearExploitChains } from './exploitChains';
import { harnessVerifyDir } from './harnessVerify';
import { miniVerifyDir } from './miniRuntime';
import { WORKSPACE_DIR } from './ingest';
import {
  invalidateExploitReads,
  invalidateProjectStatusReads,
  invalidateVulnerabilityReads,
} from './readCache';
import { auditCoverageSnapshot } from './runner';
import type { Project } from './types';
import { newId, now } from './util';
import { broadcast } from './ws';

export type AuditCoverageClassification = 'complete' | 'incomplete' | 'unverifiable';
export type AuditCoverageEvidenceSource = 'live_workspace' | 'audit_log' | 'none';

export interface AuditCoverageVerdict {
  project_id: string;
  project_name: string;
  classification: AuditCoverageClassification;
  should_invalidate: boolean;
  evidence_source: AuditCoverageEvidenceSource;
  workspace_path: string | null;
  expected_count: number | null;
  valid_count: number | null;
  missing_agents: string[];
  reason: string;
}

export interface AuditCoverageAuditReport {
  generated_at: string;
  summary: {
    scanned: number;
    complete: number;
    incomplete: number;
    unverifiable: number;
    invalidate_count: number;
  };
  projects: AuditCoverageVerdict[];
}

function resolveWorkspace(project: Pick<Project, 'id' | 'workspace_path'>): string | null {
  const candidates = [
    project.workspace_path,
    path.join(WORKSPACE_DIR, project.id),
  ].filter(Boolean) as string[];
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) return candidate;
    } catch {
      /* ignore */
    }
  }
  return null;
}

function classifyFromLatestCoverageLog(project: Project): AuditCoverageVerdict {
  const events = db
    .prepare(
      `SELECT ts, text
       FROM agent_events
       WHERE project_id = ? AND phase = 'audit'
         AND (
           text LIKE '%子智能体覆盖%'
           OR text LIKE '%补跑后仍有%JSON%'
           OR text LIKE '%审计完成硬闸%'
         )
       ORDER BY ts DESC, rowid DESC`
    )
    .all(project.id) as { ts: number; text: string }[];

  for (const event of events) {
    const text = String(event.text || '');
    if (/覆盖完整|覆盖已补齐|完成硬闸通过/.test(text)) {
      return {
        project_id: project.id,
        project_name: project.project_name,
        classification: 'complete',
        should_invalidate: false,
        evidence_source: 'audit_log',
        workspace_path: null,
        expected_count: null,
        valid_count: null,
        missing_agents: [],
        reason: `工作区已不存在；最新覆盖日志表明完整：${text.slice(0, 300)}`,
      };
    }
    const ratio = text.match(/(\d+)\s*\/\s*(\d+)\s*(?:个|份)?\s*JSON\s*缺失或无法解析/);
    const remaining = text.match(/补跑后仍有\s*(\d+)\s*个子智能体\s*JSON\s*缺失或无法解析/);
    const missingCount = ratio ? Number(ratio[1]) : remaining ? Number(remaining[1]) : 0;
    if (missingCount > 0) {
      const names =
        text
          .match(/（([^）]+)）/)?.[1]
          ?.split('、')
          .map((name) => name.trim())
          .filter(Boolean) || [];
      return {
        project_id: project.id,
        project_name: project.project_name,
        classification: 'incomplete',
        should_invalidate: true,
        evidence_source: 'audit_log',
        workspace_path: null,
        expected_count: ratio ? Number(ratio[2]) : null,
        valid_count: ratio ? Math.max(0, Number(ratio[2]) - missingCount) : null,
        missing_agents: names,
        reason: `工作区已不存在；最新覆盖日志仍有 ${missingCount} 个 JSON 缺失或无法解析`,
      };
    }
  }

  return {
    project_id: project.id,
    project_name: project.project_name,
    classification: 'unverifiable',
    should_invalidate: false,
    evidence_source: 'none',
    workspace_path: null,
    expected_count: null,
    valid_count: null,
    missing_agents: [],
    reason: '工作区已不存在，日志也没有可判定的覆盖证据；按策略保留 completed',
  };
}

export function classifyAuditCoverageProject(project: Project): AuditCoverageVerdict {
  const workspace = resolveWorkspace(project);
  if (!workspace) return classifyFromLatestCoverageLog(project);
  const coverage = auditCoverageSnapshot(workspace, { repair: false, projectId: project.id });
  if (coverage.status === 'unknown_language') {
    return {
      project_id: project.id,
      project_name: project.project_name,
      classification: 'incomplete',
      should_invalidate: true,
      evidence_source: 'live_workspace',
      workspace_path: workspace,
      expected_count: null,
      valid_count: null,
      missing_agents: [],
      reason: '无法从当前源码确定预期子智能体清单，不能证明覆盖完整',
    };
  }
  return {
    project_id: project.id,
    project_name: project.project_name,
    classification: coverage.status === 'complete' ? 'complete' : 'incomplete',
    should_invalidate: coverage.status !== 'complete',
    evidence_source: 'live_workspace',
    workspace_path: workspace,
    expected_count: coverage.expected.length,
    valid_count: coverage.valid.length,
    missing_agents: coverage.missing,
    reason:
      coverage.status === 'complete'
        ? `${coverage.expected.length} 个必需子智能体产物全部有效`
        : `缺失或无法解析 ${coverage.missing.length}/${coverage.expected.length} 个必需 JSON`,
  };
}

export function auditCompletedProjectCoverage(): AuditCoverageAuditReport {
  const projects = db
    .prepare("SELECT * FROM projects WHERE status = 'completed' ORDER BY project_name ASC")
    .all() as Project[];
  const verdicts = projects.map(classifyAuditCoverageProject);
  const summary = {
    scanned: verdicts.length,
    complete: verdicts.filter((item) => item.classification === 'complete').length,
    incomplete: verdicts.filter((item) => item.classification === 'incomplete').length,
    unverifiable: verdicts.filter((item) => item.classification === 'unverifiable').length,
    invalidate_count: verdicts.filter((item) => item.should_invalidate).length,
  };
  return { generated_at: new Date().toISOString(), summary, projects: verdicts };
}

function removeRemoteVerifyArtifacts(workspace: string | null): void {
  if (!workspace) return;
  for (const dir of [path.join(workspace, '_remote_verify'), harnessVerifyDir(workspace), miniVerifyDir(workspace)]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

/** 清除工作区内的审计/验证落盘产物，保留源码与 append-only 日志。 */
export function clearWorkspaceAuditArtifacts(workspace: string | null): void {
  if (!workspace) return;
  removeRemoteVerifyArtifacts(workspace);
  for (const dir of ['JSON', '_mcp', '_pipeline']) {
    try {
      fs.rmSync(path.join(workspace, dir), { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
  for (const file of ['directly_exploitable_vulns.json', 'TARGET_ENV.json']) {
    try {
      fs.rmSync(path.join(workspace, file), { force: true });
    } catch {
      /* ignore */
    }
  }
}

/**
 * 批量清空「代码审计已暂停」(status=paused) 项目的审计/验证结果与磁盘产物。
 * 保留 agent_events / project_run_logs；继续时将因无 JSON/ 产物而走全量 doAudit。
 */
export function resetPausedAuditProjects(ids?: string[]): {
  requested: number;
  reset: string[];
  skipped: { id: string; error: string }[];
} {
  const rows = db
    .prepare(`SELECT * FROM projects WHERE status = 'paused' ORDER BY project_name`)
    .all() as Project[];
  const requestedSet = ids?.length ? new Set(ids) : null;
  const targets = requestedSet ? rows.filter((p) => requestedSet.has(p.id)) : rows;
  const pausedIds = new Set(rows.map((p) => p.id));
  const reset: string[] = [];
  const skipped: { id: string; error: string }[] = [];

  if (requestedSet) {
    for (const id of requestedSet) {
      if (!pausedIds.has(id)) skipped.push({ id, error: '不在 status=paused 集合' });
    }
  }

  const reason =
    '审计数据已清除：漏洞/验证结果与工作区 JSON/ 产物已清空；点击「继续」将从头执行完整代码审计流程';
  for (const project of targets) {
    const workspace = resolveWorkspace(project);
    const lastEvent = db
      .prepare('SELECT MAX(ts) AS ts FROM agent_events WHERE project_id = ?')
      .get(project.id) as { ts: number | null };
    const eventTs = Math.max(now(), Number(lastEvent?.ts || 0) + 1);
    const event = {
      id: newId('e_'),
      project_id: project.id,
      ts: eventTs,
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `♻ ${reason}`,
      raw: JSON.stringify({ action: 'reset_paused_audit_data' }),
      phase: 'audit',
    };
    const tx = db.transaction(() => {
      db.prepare('DELETE FROM vulnerability_verifications WHERE project_id = ?').run(project.id);
      db.prepare('DELETE FROM vulnerabilities WHERE project_id = ?').run(project.id);
      clearExploitChains(project.id);
      db.prepare(
        `UPDATE projects
         SET error_message = NULL,
             started_at = NULL,
             finished_at = NULL,
             audit_duration_ms = 0,
             count_critical = 0,
             count_high = 0,
             count_medium = 0,
             count_low = 0,
             count_info = 0,
             verify_status = 'none',
             verify_started_at = NULL,
             verify_finished_at = NULL,
             verify_error = NULL,
             verify_duration_ms = 0,
             exploit_report = NULL,
             frontend_rce = 0,
             env_status = 'none',
             target_url = NULL
         WHERE id = ? AND status = 'paused'`
      ).run(project.id);
      db.prepare(
        `INSERT INTO agent_events (id, project_id, ts, kind, agent, tool, text, raw, phase)
         VALUES (@id, @project_id, @ts, @kind, @agent, @tool, @text, @raw, @phase)`
      ).run(event);
    });
    tx();
    clearWorkspaceAuditArtifacts(workspace);
    reset.push(project.id);
    broadcast({ type: 'agent_event', projectId: project.id, event });
    broadcast({
      type: 'project_status',
      projectId: project.id,
      status: 'paused',
      verify_status: 'none',
      frontend_rce: 0,
    });
  }

  invalidateProjectStatusReads();
  invalidateVulnerabilityReads();
  invalidateExploitReads();
  return { requested: targets.length, reset, skipped };
}

export function invalidateAuditCoverage(
  projectId: string,
  verdict: AuditCoverageVerdict
): { ok: boolean; error?: string } {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId) as
    | Project
    | undefined;
  if (!project) return { ok: false, error: '项目不存在' };
  if (project.status !== 'completed') return { ok: false, error: '项目当前不在 completed 集合' };
  if (!verdict.should_invalidate) return { ok: false, error: '当前覆盖判定完整，拒绝标记失败' };

  const workspace = resolveWorkspace(project);
  const lastEvent = db
    .prepare('SELECT MAX(ts) AS ts FROM agent_events WHERE project_id = ?')
    .get(projectId) as { ts: number | null };
  const eventTs = Math.max(now(), Number(lastEvent?.ts || 0) + 1);
  const missingText =
    verdict.missing_agents.length > 0
      ? `：${verdict.missing_agents.join('、')}`
      : '';
  const reason = `历史审计覆盖不完整，已从 completed 标记为 failed；${verdict.reason}${missingText}`;
  const event = {
    id: newId('e_'),
    project_id: projectId,
    ts: eventTs,
    kind: 'error',
    agent: '审计完整性校验器',
    tool: '',
    text: `⛔ ${reason}`,
    raw: JSON.stringify({
      evidence_source: verdict.evidence_source,
      expected_count: verdict.expected_count,
      valid_count: verdict.valid_count,
      missing_agents: verdict.missing_agents,
    }),
    phase: 'audit',
  };

  const tx = db.transaction(() => {
    db.prepare(
      `UPDATE projects
       SET status = 'failed',
           error_message = ?,
           finished_at = ?,
           verify_status = 'none',
           verify_started_at = NULL,
           verify_finished_at = NULL,
           verify_error = NULL,
           exploit_report = NULL,
           frontend_rce = 0
       WHERE id = ?`
    ).run(reason, eventTs, projectId);
    // 远程验证结果失效，但 audit/verify 日志均作为追加式证据保留。
    db.prepare('DELETE FROM vulnerability_verifications WHERE project_id = ?').run(projectId);
    db.prepare(
      `UPDATE vulnerabilities
       SET verified = 0, frontend_rce = 0, frontend_rce_at = NULL
       WHERE project_id = ?`
    ).run(projectId);
    clearExploitChains(projectId);
    db.prepare(
      `INSERT INTO agent_events (id, project_id, ts, kind, agent, tool, text, raw, phase)
       VALUES (@id, @project_id, @ts, @kind, @agent, @tool, @text, @raw, @phase)`
    ).run(event);
  });
  tx();
  removeRemoteVerifyArtifacts(workspace);

  invalidateProjectStatusReads();
  invalidateVulnerabilityReads();
  invalidateExploitReads();
  broadcast({ type: 'agent_event', projectId, event });
  broadcast({
    type: 'project_status',
    projectId,
    status: 'failed',
    verify_status: 'none',
    frontend_rce: 0,
  });
  return { ok: true };
}

export function applyAuditCoverageInvalidations(ids: string[]): {
  requested: number;
  invalidated: string[];
  skipped: { id: string; error: string }[];
  report: AuditCoverageAuditReport;
} {
  const report = auditCompletedProjectCoverage();
  const byId = new Map(report.projects.map((item) => [item.project_id, item]));
  const invalidated: string[] = [];
  const skipped: { id: string; error: string }[] = [];
  for (const id of Array.from(new Set(ids))) {
    const verdict = byId.get(id);
    if (!verdict) {
      skipped.push({ id, error: '不在当前 completed 审计集合中' });
      continue;
    }
    if (!verdict.should_invalidate) {
      skipped.push({ id, error: '覆盖完整或按策略保留，跳过' });
      continue;
    }
    const result = invalidateAuditCoverage(id, verdict);
    if (result.ok) invalidated.push(id);
    else skipped.push({ id, error: result.error || '未知错误' });
  }
  return { requested: ids.length, invalidated, skipped, report };
}

/**
 * 工作区已丢失且日志无法证明覆盖的 completed 项目：
 * 清空所有审计/验证结果并转 paused，保留 append-only 事件与原始运行日志。
 * 后续点击“继续审计”时因没有可复用 JSON，会重新准备源码并从完整子智能体阶段开始。
 */
export function resetUnverifiableCompletedAudits(ids?: string[]): {
  candidates: number;
  reset: string[];
  skipped: { id: string; error: string }[];
} {
  const report = auditCompletedProjectCoverage();
  const candidates = report.projects.filter(
    (item) => item.classification === 'unverifiable' && !item.should_invalidate
  );
  const requested = ids?.length ? new Set(ids) : null;
  const targets = requested
    ? candidates.filter((item) => requested.has(item.project_id))
    : candidates;
  const candidateIds = new Set(candidates.map((item) => item.project_id));
  const reset: string[] = [];
  const skipped: { id: string; error: string }[] = [];
  if (requested) {
    for (const id of requested) {
      if (!candidateIds.has(id)) skipped.push({ id, error: '不属于当前不可复算 completed 集合' });
    }
  }

  for (const verdict of targets) {
    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(verdict.project_id) as
      | Project
      | undefined;
    if (!project || project.status !== 'completed') {
      skipped.push({ id: verdict.project_id, error: '项目状态已变化' });
      continue;
    }
    const lastEvent = db
      .prepare('SELECT MAX(ts) AS ts FROM agent_events WHERE project_id = ?')
      .get(project.id) as { ts: number | null };
    const eventTs = Math.max(now(), Number(lastEvent?.ts || 0) + 1);
    const reason =
      '审计覆盖证据缺失：源码工作区已不存在且日志无法证明子智能体覆盖完整；审计数据已清除并转入已暂停，继续时将重新准备源码并执行完整覆盖审计';
    const event = {
      id: newId('e_'),
      project_id: project.id,
      ts: eventTs,
      kind: 'error',
      agent: '审计完整性校验器',
      tool: '',
      text: `⛔ ${reason}`,
      raw: JSON.stringify({ action: 'reset_unverifiable_to_paused', previous_status: 'completed' }),
      phase: 'audit',
    };
    const tx = db.transaction(() => {
      db.prepare('DELETE FROM vulnerability_verifications WHERE project_id = ?').run(project.id);
      db.prepare('DELETE FROM vulnerabilities WHERE project_id = ?').run(project.id);
      clearExploitChains(project.id);
      db.prepare(
        `UPDATE projects
         SET status = 'paused',
             error_message = ?,
             workspace_path = NULL,
             started_at = NULL,
             finished_at = ?,
             audit_duration_ms = 0,
             count_critical = 0,
             count_high = 0,
             count_medium = 0,
             count_low = 0,
             count_info = 0,
             verify_status = 'none',
             verify_started_at = NULL,
             verify_finished_at = NULL,
             verify_error = NULL,
             verify_duration_ms = 0,
             exploit_report = NULL,
             frontend_rce = 0,
             env_status = 'none',
             target_url = NULL
         WHERE id = ?`
      ).run(reason, eventTs, project.id);
      db.prepare(
        `INSERT INTO agent_events (id, project_id, ts, kind, agent, tool, text, raw, phase)
         VALUES (@id, @project_id, @ts, @kind, @agent, @tool, @text, @raw, @phase)`
      ).run(event);
    });
    tx();
    removeRemoteVerifyArtifacts(resolveWorkspace(project));
    reset.push(project.id);
    broadcast({ type: 'agent_event', projectId: project.id, event });
    broadcast({
      type: 'project_status',
      projectId: project.id,
      status: 'paused',
      verify_status: 'none',
      frontend_rce: 0,
    });
  }

  invalidateProjectStatusReads();
  invalidateVulnerabilityReads();
  invalidateExploitReads();
  return { candidates: candidates.length, reset, skipped };
}
