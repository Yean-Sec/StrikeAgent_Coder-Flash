import db from './db';
import {
  newId,
  now,
  repoNameFromUrl,
  versionFromName,
  systemNameFromName,
  placeholderLabel,
} from './util';
import type { Project, SourceType } from './types';
import {
  invalidateExploitReads,
  invalidateProjectStatusReads,
  invalidateVulnerabilityReads,
} from './readCache';

export function projectNameExists(name: string): boolean {
  return !!db.prepare('SELECT 1 FROM projects WHERE project_name = ?').get(name);
}

/** 保证项目名唯一：若重复则追加 -2、-3… */
export function uniqueProjectName(base: string): string {
  let name = (base || '未命名项目').trim();
  if (!projectNameExists(name)) return name;
  let i = 2;
  while (projectNameExists(`${name}-${i}`)) i++;
  return `${name}-${i}`;
}

interface CreateOptions {
  projectName?: string;
  archiveName: string;
  sourceType: SourceType;
  sourceRef: string;
  sourceVersion?: string | null;
  systemName?: string | null;
  monitorId?: string | null;
  /** github 项目按指定 tag 克隆（多版本批量审计）。 */
  gitRef?: string | null;
  /** 项目级审计流程选项（在新建审计页配置；未提供的项沿用全局默认）。 */
  options?: {
    auto_verify?: boolean;
    verify_history?: boolean;
    ai_dedup?: boolean;
    ai_regrade?: boolean;
    verify_runtime?: 'full' | 'none' | 'mini';
  };
  /** 用户手动选择的单一审计语言。 */
  auditLanguage?: string;
}

/** 把可选布尔选项转成入库值：true→1 / false→0 / 未提供→null（沿用全局默认）。 */
function optVal(v: boolean | undefined): number | null {
  return v === undefined ? null : v ? 1 : 0;
}

export function createProject(opts: CreateOptions): Project {
  const isGithub = opts.sourceType === 'github';
  const base =
    opts.projectName?.trim() ||
    (isGithub
      ? repoNameFromUrl(opts.sourceRef)
      : opts.archiveName.replace(/\.(zip|rar)$/i, ''));
  const project_name = uniqueProjectName(base);

  // 系统名：智能解析（github 用仓库名，压缩包从文件名解析），解析不到给随机占位待人工修改。
  const systemName =
    (opts.systemName?.trim() ||
      (isGithub
        ? repoNameFromUrl(opts.sourceRef)
        : systemNameFromName(opts.archiveName))) ??
    placeholderLabel('系统');

  // 版本号：压缩包从文件名解析，解析不到给随机占位；github 留空，待 clone 后由仓库 tag/commit 解析。
  let sourceVersion: string | null;
  if (opts.sourceVersion !== undefined && opts.sourceVersion !== null) {
    sourceVersion = opts.sourceVersion;
  } else if (isGithub) {
    sourceVersion = null;
  } else {
    sourceVersion = versionFromName(opts.archiveName) ?? placeholderLabel('版本');
  }

  const id = newId('p_');
  const o = opts.options ?? {};
  db.prepare(
    `INSERT INTO projects
      (id, project_name, archive_name, source_type, source_ref, source_version, system_name, status, monitor_id, git_ref,
       opt_auto_verify, opt_verify_history, opt_ai_dedup, opt_ai_regrade, opt_verify_runtime, audit_language, created_at)
     VALUES (@id, @project_name, @archive_name, @source_type, @source_ref, @source_version, @system_name, 'pending', @monitor_id, @git_ref,
       @opt_auto_verify, @opt_verify_history, @opt_ai_dedup, @opt_ai_regrade, @opt_verify_runtime, @audit_language, @created_at)`
  ).run({
    id,
    project_name,
    archive_name: opts.archiveName,
    source_type: opts.sourceType,
    source_ref: opts.sourceRef,
    source_version: sourceVersion,
    system_name: systemName,
    monitor_id: opts.monitorId ?? null,
    git_ref: opts.gitRef ?? null,
    opt_auto_verify: optVal(o.auto_verify),
    opt_verify_history: optVal(o.verify_history),
    opt_ai_dedup: optVal(o.ai_dedup),
    opt_ai_regrade: optVal(o.ai_regrade),
    opt_verify_runtime:
      o.verify_runtime === 'none'
        ? 'none'
        : o.verify_runtime === 'full' || o.verify_runtime === 'mini'
          ? 'full'
          : o.auto_verify === false
            ? 'none'
            : 'full',
    audit_language: opts.auditLanguage || 'php',
    created_at: now(),
  });
  invalidateProjectStatusReads();
  return db.prepare('SELECT * FROM projects WHERE id = ?').get(id) as Project;
}

export function getProject(id: string): Project | undefined {
  return db.prepare('SELECT * FROM projects WHERE id = ?').get(id) as Project | undefined;
}

/** 编辑项目名 / 版本号 / 系统名（用于版本对比）。项目名需保持唯一。 */
export function updateProjectMeta(
  id: string,
  fields: {
    projectName?: string;
    sourceVersion?: string | null;
    systemName?: string | null;
  }
): Project | undefined {
  const p = getProject(id);
  if (!p) return undefined;

  const sets: string[] = [];
  const params: Record<string, unknown> = { id };

  if (fields.systemName !== undefined) {
    const v =
      fields.systemName === null
        ? null
        : String(fields.systemName).trim() || null;
    sets.push('system_name = @system_name');
    params.system_name = v;
  }

  if (fields.projectName !== undefined) {
    const name = fields.projectName.trim();
    if (!name) throw new Error('项目名不能为空');
    const dup = db
      .prepare('SELECT 1 FROM projects WHERE project_name = ? AND id != ?')
      .get(name, id);
    if (dup) throw new Error('项目名已存在');
    sets.push('project_name = @project_name');
    params.project_name = name;
  }

  if (fields.sourceVersion !== undefined) {
    const v =
      fields.sourceVersion === null
        ? null
        : String(fields.sourceVersion).trim() || null;
    sets.push('source_version = @source_version');
    params.source_version = v;
  }

  if (sets.length === 0) return p;
  db.prepare(`UPDATE projects SET ${sets.join(', ')} WHERE id = @id`).run(params);
  invalidateProjectStatusReads();
  return getProject(id);
}

export function deleteProjectRows(id: string): void {
  const tx = db.transaction(() => {
    // 不依赖 foreign_keys pragma，显式清理所有项目派生表。
    db.prepare('DELETE FROM exploit_chains WHERE project_id = ?').run(id);
    db.prepare('DELETE FROM exploit_chain_sync WHERE project_id = ?').run(id);
    db.prepare('DELETE FROM vulnerability_verifications WHERE project_id = ?').run(id);
    db.prepare('DELETE FROM vulnerabilities WHERE project_id = ?').run(id);
    db.prepare('DELETE FROM project_run_logs WHERE project_id = ?').run(id);
    db.prepare('DELETE FROM agent_events WHERE project_id = ?').run(id);
    db.prepare('DELETE FROM projects WHERE id = ?').run(id);
  });
  tx();
  invalidateProjectStatusReads();
  invalidateVulnerabilityReads();
  invalidateExploitReads();
}
