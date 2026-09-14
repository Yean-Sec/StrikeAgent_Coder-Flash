import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import db from './db';
import { clearExploitChains } from './exploitChains';
import { WORKSPACE_DIR } from './ingest';
import { harnessVerifyDir } from './harnessVerify';
import { miniVerifyDir } from './miniRuntime';
import {
  invalidateExploitReads,
  invalidateProjectStatusReads,
  invalidateVulnerabilityReads,
} from './readCache';
import { readTargetEnv } from './projectShape';
import { broadcast } from './ws';
import { newId, now } from './util';
import type { Project } from './types';
import { versionsMatch } from './targetProvenance';

export { normalizeVersionToken, versionsMatch } from './targetProvenance';

export type VersionAuditClassification = 'matched' | 'mismatch' | 'unverifiable';

export type VersionAuditSubreason =
  | 'contract_match'
  | 'db_vs_target_env'
  | 'target_env_internal'
  | 'runtime_evidence_conflict'
  | 'legacy_target_env'
  | 'no_target_env_contract'
  | 'workspace_gone'
  | 'missing_provenance'
  | 'prebuilt_image'
  | 'no_structured_version'
  | 'harness_version_mismatch'
  | 'harness_unverifiable';

export interface VersionAuditEvidence {
  tier: 'db' | 'contract' | 'workspace' | 'agent_event' | 'remote_verify' | 'compose';
  path: string;
  field?: string;
  snippet?: string;
}

export interface VersionAuditVerdict {
  project_id: string;
  project_name: string;
  verify_status: string;
  classification: VersionAuditClassification;
  subreason: VersionAuditSubreason;
  should_invalidate: boolean;
  versions: {
    db_source_version: string | null;
    git_ref: string | null;
    target_env_version: string | null;
    target_env_source_version: string | null;
    runtime_reported_version: string | null;
    git_head: string | null;
    target_env_source_commit: string | null;
  };
  target_env: {
    mode: string | null;
    build_provenance: string | null;
    url: string | null;
    present: boolean;
  };
  evidence: VersionAuditEvidence[];
  confidence: 'high' | 'medium' | 'low';
  notes: string;
}

export interface VersionAuditReport {
  audit_meta: {
    generated_at: string;
    filters: string[];
    project_count: number;
  };
  summary: {
    matched: number;
    mismatch: number;
    unverifiable: number;
    invalidate_count: number;
    by_subreason: Record<string, number>;
  };
  projects: VersionAuditVerdict[];
}

function remoteVerifyDir(codeDir: string): string {
  return path.join(codeDir, '_remote_verify');
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

function readGitHead(codeDir: string): string | null {
  try {
    return execSync('git rev-parse HEAD', {
      cwd: codeDir,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim();
  } catch {
    return null;
  }
}

function composeHasLocalBuild(codeDir: string): boolean | null {
  const composePath = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']
    .map((name) => path.join(codeDir, name))
    .find((candidate) => fs.existsSync(candidate));
  if (!composePath) return null;
  try {
    const compose = fs.readFileSync(composePath, 'utf8');
    return /(?:^|\n)\s*build\s*:/m.test(compose);
  } catch {
    return null;
  }
}

function scanRuntimeVersionHints(codeDir: string): { version: string | null; snippets: string[]; prebuilt: boolean } {
  const snippets: string[] = [];
  let version: string | null = null;
  let prebuilt = false;
  const roots = [remoteVerifyDir(codeDir), harnessVerifyDir(codeDir), miniVerifyDir(codeDir)];
  const patterns = [
    /实际运行版本[^\n]{0,80}/g,
    /target[_ ]?version["'\s:=]+([^\s"',}]+)/gi,
    /verification_environment["'\s:=]+([^\n"']{0,120})/gi,
    /(?:openrefine|ums|conductoross\/conductor|felixlohmeier\/openrefine|apache\/hop-web)[:/]([\w.\-]+)/gi,
    /(?:prebuilt|official image|官方镜像)/gi,
  ];

  const walk = (dir: string, depth = 0) => {
    if (depth > 3) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, depth + 1);
        continue;
      }
      if (!entry.name.toLowerCase().endsWith('.json')) continue;
      let text = '';
      try {
        text = fs.readFileSync(full, 'utf8');
      } catch {
        continue;
      }
      if (/prebuilt|official image|官方镜像|felixlohmeier\/openrefine|conductoross\/conductor:next/i.test(text)) {
        prebuilt = true;
        snippets.push(`${path.basename(full)}: prebuilt/official image hint`);
      }
      for (const re of patterns) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(text))) {
          const hit = (m[1] || m[0] || '').trim();
          if (!hit) continue;
          snippets.push(`${path.basename(full)}: ${hit.slice(0, 120)}`);
          if (!version) {
            const extracted =
              m[1]?.trim() ||
              hit.replace(/^实际运行版本[:：\s]*/i, '').match(/[\w.\-]+/)?.[0] ||
              null;
            if (extracted && !/prebuilt|official|镜像/i.test(extracted)) version = extracted;
          }
          if (snippets.length >= 8) return;
        }
      }
    }
  };

  for (const root of roots) walk(root);
  return { version, snippets: snippets.slice(0, 8), prebuilt };
}

function scanAgentVersionHints(projectId: string): { version: string | null; snippets: string[] } {
  const rows = db
    .prepare(
      `SELECT substr(text, 1, 240) AS text FROM agent_events
       WHERE project_id = ? AND phase = 'verify'
         AND (
           text LIKE '%靶机规格%'
           OR text LIKE '%运行版本%'
           OR text LIKE '%实际运行版本%'
           OR text LIKE '%拒绝复用外部靶机%'
           OR text LIKE '%prebuilt%'
           OR text LIKE '%官方镜像%'
         )
       ORDER BY ts DESC LIMIT 12`
    )
    .all(projectId) as { text: string }[];
  const snippets = rows.map((r) => r.text);
  let version: string | null = null;
  for (const text of snippets) {
    const m =
      text.match(/靶机规格：版本\s+([^\s·]+)/) ||
      text.match(/运行版本[^\w]*([vV]?\d[\w.\-]+)/) ||
      text.match(/实际运行版本[^\w]*([vV]?\d[\w.\-]+)/);
    if (m?.[1]) {
      version = m[1];
      break;
    }
  }
  return { version, snippets };
}

function classifyOne(project: Project): VersionAuditVerdict {
  const evidence: VersionAuditEvidence[] = [
    {
      tier: 'db',
      path: 'projects.source_version',
      field: 'source_version',
      snippet: project.source_version || '(null)',
    },
  ];
  const workspace = resolveWorkspace(project);
  const env = workspace ? readTargetEnv(workspace) : null;
  const gitHead = workspace ? readGitHead(workspace) : null;
  const localBuild = workspace ? composeHasLocalBuild(workspace) : null;
  const runtime = workspace
    ? scanRuntimeVersionHints(workspace)
    : { version: null, snippets: [], prebuilt: false };
  const agent = scanAgentVersionHints(project.id);

  if (gitHead) {
    evidence.push({ tier: 'workspace', path: workspace!, field: 'git_head', snippet: gitHead });
  }
  if (env) {
    evidence.push({
      tier: 'contract',
      path: path.join(workspace!, 'TARGET_ENV.json'),
      field: 'version',
      snippet: String(env.version ?? ''),
    });
  }
  for (const snip of runtime.snippets.slice(0, 3)) {
    evidence.push({ tier: 'remote_verify', path: workspace ? remoteVerifyDir(workspace) : '', snippet: snip });
  }
  for (const snip of agent.snippets.slice(0, 2)) {
    evidence.push({ tier: 'agent_event', path: 'agent_events', snippet: snip });
  }
  if (localBuild != null) {
    evidence.push({
      tier: 'compose',
      path: workspace!,
      field: 'build',
      snippet: localBuild ? 'compose has build:' : 'compose lacks build:',
    });
  }

  const targetMode = env ? String(env.mode || '').toLowerCase() || null : null;
  const buildProvenance = env ? String(env.build_provenance || '') || null : null;
  const targetVersion = env?.version != null ? String(env.version) : null;
  const targetSourceVersion = env?.source_version != null ? String(env.source_version) : null;
  const targetCommit = env?.source_commit != null ? String(env.source_commit) : null;
  const runtimeVersion = runtime.version || agent.version;
  const dbVersion = project.source_version;

  let targetEnvMtime: number | null = null;
  if (workspace && env) {
    try {
      targetEnvMtime = fs.statSync(path.join(workspace, 'TARGET_ENV.json')).mtimeMs;
    } catch {
      targetEnvMtime = null;
    }
  }
  const contractAfterVerify =
    !!project.verify_finished_at &&
    targetEnvMtime != null &&
    targetEnvMtime > Number(project.verify_finished_at) + 60_000;

  const base = {
    project_id: project.id,
    project_name: project.project_name,
    verify_status: project.verify_status,
    versions: {
      db_source_version: dbVersion,
      git_ref: project.git_ref,
      target_env_version: targetVersion,
      target_env_source_version: targetSourceVersion,
      runtime_reported_version: runtimeVersion,
      git_head: gitHead,
      target_env_source_commit: targetCommit,
    },
    target_env: {
      mode: targetMode,
      build_provenance: buildProvenance,
      url: env?.url != null ? String(env.url) : project.target_url,
      present: !!env,
    },
    evidence,
  };

  if (!workspace) {
    return {
      ...base,
      classification: 'unverifiable',
      subreason: 'workspace_gone',
      should_invalidate: true,
      confidence: 'high',
      notes: '工作区缺失，无法证明靶机版本与审计源码版本对应',
    };
  }

  if (!env) {
    return {
      ...base,
      classification: 'unverifiable',
      subreason: 'no_target_env_contract',
      should_invalidate: true,
      confidence: 'high',
      notes: '缺少 TARGET_ENV.json 契约，无法证明靶机版本',
    };
  }

  // 验证结束后才写入/改写的 TARGET_ENV 不能为「当时」的远程验证背书
  if (contractAfterVerify) {
    evidence.push({
      tier: 'contract',
      path: path.join(workspace!, 'TARGET_ENV.json'),
      field: 'mtime',
      snippet: `mtime=${targetEnvMtime} > verify_finished_at=${project.verify_finished_at}`,
    });
    return {
      ...base,
      classification: 'unverifiable',
      subreason: 'no_structured_version',
      should_invalidate: true,
      confidence: 'high',
      notes: 'TARGET_ENV 在远程验证结束后才写入/更新，无法证明当时靶机版本与源码对应',
    };
  }

  // Harness path: require mode=harness + version match to DB when version present
  if (targetMode === 'harness') {
    if (!targetVersion && !targetSourceVersion) {
      return {
        ...base,
        classification: 'unverifiable',
        subreason: 'harness_unverifiable',
        should_invalidate: true,
        confidence: 'medium',
        notes: 'Harness 靶机未声明 version/source_version',
      };
    }
    const harnessVer = targetSourceVersion || targetVersion;
    if (dbVersion && versionsMatch(dbVersion, harnessVer)) {
      return {
        ...base,
        classification: 'matched',
        subreason: 'contract_match',
        should_invalidate: false,
        confidence: 'medium',
        notes: 'Harness 契约版本与 DB source_version 一致',
      };
    }
    return {
      ...base,
      classification: 'mismatch',
      subreason: 'harness_version_mismatch',
      should_invalidate: true,
      confidence: 'high',
      notes: `Harness 版本 ${harnessVer} 与审计版本 ${dbVersion} 不一致`,
    };
  }

  const notesBlob = String(env.notes || '');
  const prebuiltHint =
    runtime.prebuilt ||
    /prebuilt|official image|官方镜像|felixlohmeier\/|:latest\b|:next\b/i.test(notesBlob) ||
    (localBuild === false && /image\s*:/i.test(notesBlob));

  if (prebuiltHint) {
    return {
      ...base,
      classification: 'mismatch',
      subreason: 'prebuilt_image',
      should_invalidate: true,
      confidence: 'high',
      notes: '证据表明使用预构建应用镜像，而非当前工作区源码构建',
    };
  }

  // Legacy web TARGET_ENV without structured version fields
  if (!targetVersion && !targetSourceVersion) {
    return {
      ...base,
      classification: 'unverifiable',
      subreason: 'legacy_target_env',
      should_invalidate: true,
      confidence: 'high',
      notes: 'TARGET_ENV 缺少 version/source_version 结构化字段',
    };
  }

  if (targetVersion && targetSourceVersion && !versionsMatch(targetVersion, targetSourceVersion)) {
    return {
      ...base,
      classification: 'mismatch',
      subreason: 'target_env_internal',
      should_invalidate: true,
      confidence: 'high',
      notes: `TARGET_ENV.version(${targetVersion}) ≠ source_version(${targetSourceVersion})`,
    };
  }

  const contractVersion = targetSourceVersion || targetVersion;
  if (dbVersion && contractVersion && !versionsMatch(dbVersion, contractVersion)) {
    return {
      ...base,
      classification: 'mismatch',
      subreason: 'db_vs_target_env',
      should_invalidate: true,
      confidence: 'high',
      notes: `DB source_version(${dbVersion}) ≠ TARGET_ENV(${contractVersion})`,
    };
  }

  if (runtimeVersion && dbVersion && !versionsMatch(dbVersion, runtimeVersion)) {
    return {
      ...base,
      classification: 'mismatch',
      subreason: 'runtime_evidence_conflict',
      should_invalidate: true,
      confidence: 'high',
      notes: `运行时证据版本 ${runtimeVersion} 与审计版本 ${dbVersion} 冲突`,
    };
  }

  // Strict provenance for web/external targets
  const provenanceOk = buildProvenance === 'local-source';
  const commitOk =
    !gitHead ||
    !targetCommit ||
    versionsMatch(gitHead, targetCommit) ||
    gitHead.toLowerCase() === String(targetCommit).toLowerCase();
  const buildOk = localBuild === true;

  if (!provenanceOk || !buildOk) {
    return {
      ...base,
      classification: 'unverifiable',
      subreason: 'missing_provenance',
      should_invalidate: true,
      confidence: 'high',
      notes: !provenanceOk
        ? '缺少 build_provenance=local-source'
        : 'Compose 未证明本地源码 build:',
    };
  }

  if (!commitOk) {
    return {
      ...base,
      classification: 'mismatch',
      subreason: 'db_vs_target_env',
      should_invalidate: true,
      confidence: 'high',
      notes: `source_commit(${targetCommit}) 与工作区 HEAD(${gitHead}) 不一致`,
    };
  }

  if (!dbVersion || !contractVersion) {
    return {
      ...base,
      classification: 'unverifiable',
      subreason: 'no_structured_version',
      should_invalidate: true,
      confidence: 'medium',
      notes: '缺少可对齐的结构化版本字段',
    };
  }

  if (versionsMatch(dbVersion, contractVersion)) {
    return {
      ...base,
      classification: 'matched',
      subreason: 'contract_match',
      should_invalidate: false,
      confidence: runtimeVersion && !versionsMatch(dbVersion, runtimeVersion) ? 'medium' : 'high',
      notes: 'TARGET_ENV 与 DB source_version 对齐，且具备 local-source 证明',
    };
  }

  return {
    ...base,
    classification: 'unverifiable',
    subreason: 'no_structured_version',
    should_invalidate: true,
    confidence: 'medium',
    notes: '未能建立可证明的版本对应关系',
  };
}

export function auditVerifyVersionCohort(): VersionAuditReport {
  const rows = db
    .prepare(
      `SELECT * FROM projects
       WHERE verify_status IN ('completed', 'paused')
       ORDER BY verify_status ASC, project_name ASC`
    )
    .all() as Project[];

  const projects = rows.map(classifyOne);
  const by_subreason: Record<string, number> = {};
  let matched = 0;
  let mismatch = 0;
  let unverifiable = 0;
  let invalidate_count = 0;
  for (const p of projects) {
    by_subreason[p.subreason] = (by_subreason[p.subreason] || 0) + 1;
    if (p.classification === 'matched') matched += 1;
    else if (p.classification === 'mismatch') mismatch += 1;
    else unverifiable += 1;
    if (p.should_invalidate) invalidate_count += 1;
  }

  return {
    audit_meta: {
      generated_at: new Date().toISOString(),
      filters: ['verify_done', 'verify_paused'],
      project_count: projects.length,
    },
    summary: { matched, mismatch, unverifiable, invalidate_count, by_subreason },
    projects,
  };
}

function persistAuditInvalidationEvent(projectId: string, text: string): void {
  const payload = {
    id: newId('e_'),
    project_id: projectId,
    ts: now(),
    kind: 'system',
    agent: '主控',
    tool: '',
    text,
    raw: '',
    phase: 'audit',
  };
  db.prepare(
    `INSERT INTO agent_events (id, project_id, ts, kind, agent, tool, text, raw, phase)
     VALUES (@id, @project_id, @ts, @kind, @agent, @tool, @text, @raw, @phase)`
  ).run(payload);
  broadcast({ type: 'agent_event', projectId, event: payload });
}

/**
 * Wipe remote-verification outcomes and return the project to audit_done
 * (`status=completed`, `verify_status=none`) without touching audit findings.
 * Also accepts projects already on verify_status=none that still carry residual remote flags.
 */
export function invalidateRemoteVerifyForVersionAudit(
  projectId: string,
  reason: string
): { ok: boolean; error?: string } {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId) as Project | undefined;
  if (!project) return { ok: false, error: '项目不存在' };

  const workspace = resolveWorkspace(project);

  const tx = db.transaction(() => {
    // 仅清结果；验证日志是追加式审计证据，版本失配也不能删除。
    db.prepare('UPDATE projects SET exploit_report = NULL, frontend_rce = 0 WHERE id = ?').run(projectId);
    db.prepare('DELETE FROM vulnerability_verifications WHERE project_id = ?').run(projectId);
    db.prepare(
      `UPDATE vulnerabilities
       SET verified = 0, frontend_rce = 0, frontend_rce_at = NULL
       WHERE project_id = ?`
    ).run(projectId);
    clearExploitChains(projectId);
    db.prepare(
      `UPDATE projects
       SET verify_status = 'none',
           verify_started_at = NULL,
           verify_finished_at = NULL,
           verify_error = NULL
       WHERE id = ?`
    ).run(projectId);
  });
  tx();

  if (workspace) {
    for (const dir of [remoteVerifyDir(workspace), harnessVerifyDir(workspace), miniVerifyDir(workspace)]) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  }

  persistAuditInvalidationEvent(
    projectId,
    `已清除远程验证结果并退回「代码审计完成」：${reason}`
  );

  invalidateProjectStatusReads();
  invalidateVulnerabilityReads();
  invalidateExploitReads();
  broadcast({
    type: 'project_status',
    projectId,
    status: project.status,
    verify_status: 'none',
    frontend_rce: 0,
  });

  return { ok: true };
}

/** 找出仍残留远程验证痕迹的项目（含 verify_status=none 的历史脏数据）。 */
export function listProjectsWithRemoteVerifyResidue(): string[] {
  const rows = db
    .prepare(
      `SELECT id FROM projects
       WHERE exploit_report IS NOT NULL
          OR frontend_rce <> 0
          OR verify_status IN ('completed', 'paused', 'failed', 'queued', 'running')
          OR id IN (SELECT DISTINCT project_id FROM vulnerability_verifications)
          OR id IN (SELECT DISTINCT project_id FROM exploit_chains)
          OR id IN (SELECT DISTINCT project_id FROM vulnerabilities WHERE verified = 1 OR frontend_rce = 1)
          OR id IN (SELECT DISTINCT project_id FROM agent_events WHERE phase = 'verify')`
    )
    .all() as { id: string }[];
  return rows.map((r) => r.id);
}

/**
 * 全局清除全部远程验证残留，把相关项目退回 audit_done（保留代码审计漏洞）。
 * 用于「漏洞库 verified=1 仍有数据但 verify_done 为空」这类不一致状态。
 */
export function purgeAllRemoteVerifyResidue(reason: string): {
  scanned: number;
  invalidated: string[];
} {
  const ids = listProjectsWithRemoteVerifyResidue();
  const invalidated: string[] = [];
  for (const id of ids) {
    const r = invalidateRemoteVerifyForVersionAudit(id, reason);
    if (r.ok) invalidated.push(id);
  }
  // 兜底：全库再扫一遍，避免漏网的 verified / VV / chains
  db.prepare(
    `UPDATE vulnerabilities
     SET verified = 0, frontend_rce = 0, frontend_rce_at = NULL
     WHERE verified <> 0 OR frontend_rce <> 0 OR frontend_rce_at IS NOT NULL`
  ).run();
  db.prepare('DELETE FROM vulnerability_verifications').run();
  db.prepare('DELETE FROM exploit_chains').run();
  db.prepare('DELETE FROM exploit_chain_sync').run();
  db.prepare(
    `UPDATE projects
     SET exploit_report = NULL,
         frontend_rce = 0
     WHERE exploit_report IS NOT NULL OR frontend_rce <> 0`
  ).run();
  db.prepare(
    `UPDATE projects
     SET verify_status = 'none',
         verify_started_at = NULL,
         verify_finished_at = NULL,
         verify_error = NULL
     WHERE verify_status IN ('completed', 'paused', 'failed')`
  ).run();
  // 全局清理结果也保留所有 verify 阶段日志，便于后续追溯历史验证过程。

  invalidateProjectStatusReads();
  invalidateVulnerabilityReads();
  invalidateExploitReads();

  return { scanned: ids.length, invalidated };
}

export function applyVerifyVersionInvalidations(ids: string[]): {
  requested: number;
  invalidated: string[];
  skipped: { id: string; error: string }[];
  report: VersionAuditReport;
} {
  const report = auditVerifyVersionCohort();
  const byId = new Map(report.projects.map((p) => [p.project_id, p]));
  const invalidated: string[] = [];
  const skipped: { id: string; error: string }[] = [];

  for (const id of ids) {
    const verdict = byId.get(id);
    if (!verdict) {
      skipped.push({ id, error: '不在 verify_done/verify_paused 审计集合中' });
      continue;
    }
    if (!verdict.should_invalidate) {
      skipped.push({ id, error: '分类为 matched，跳过清除' });
      continue;
    }
    const result = invalidateRemoteVerifyForVersionAudit(
      id,
      `${verdict.classification}/${verdict.subreason}: ${verdict.notes}`
    );
    if (result.ok) invalidated.push(id);
    else skipped.push({ id, error: result.error || '清除失败' });
  }

  return {
    requested: ids.length,
    invalidated,
    skipped,
    report: auditVerifyVersionCohort(),
  };
}
