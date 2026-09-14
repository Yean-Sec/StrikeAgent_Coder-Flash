import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';
import {
  applySeverityPolicy,
  normalizeSeverity,
  realTeamLabel,
} from '../src/severityPolicy';

const ALL_DONE_SQL =
  "((p.status = 'completed' AND p.verify_status = 'none') OR p.verify_status = 'completed')";
const ALL_PROJECTS_SQL = '1=1';

type ScopeMode = 'all_done' | 'all';

interface VulnerabilityRow {
  id: string;
  project_id: string;
  project_name: string;
  source_version: string | null;
  title: string;
  severity: string;
  severity_original: string | null;
  regrade_value: string | null;
  regrade_reason: string | null;
  category: string | null;
  description: string | null;
  recommendation: string | null;
  code_snippet: string | null;
  taint_chain: string | null;
  auth_required: string | null;
}

interface ManifestChange {
  vulnerabilityId: string;
  projectId: string;
  projectName: string;
  sourceVersion: string | null;
  title: string;
  category: string;
  severityBefore: string;
  severityAfter: string;
  severityOriginalBefore: string | null;
  severityOriginalAfter: string | null;
  regradeValueAfter: string;
  regradeReasonBefore: string | null;
  regradeReasonAfter: string | null;
  ruleId: string;
  ruleReason: string;
  action: 'downgrade' | 'restore-protected';
}

interface RestoreEntry {
  vulnerabilityId: string;
  projectId: string;
  projectName: string;
  title: string;
  appliedRuleId: string;
  protectionRuleId: string;
  protectionReason: string;
  severityCurrent: string;
  severityRestored: string;
  severityOriginalRestored: string | null;
  regradeValueRestored: string | null;
  regradeReasonRestored: string | null;
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function increment(target: Record<string, number>, key: string): void {
  target[key] = (target[key] ?? 0) + 1;
}

function parseArgs(): {
  apply: boolean;
  dbPath: string;
  restoreManifest: string | null;
  scope: ScopeMode;
} {
  const args = process.argv.slice(2);
  const apply = args.includes('--apply');
  const dbArg = args.find((value) => value.startsWith('--db='));
  const restoreArg = args.find((value) => value.startsWith('--restore-protected-from='));
  const scopeArg = args.find((value) => value.startsWith('--scope='));
  const scopeRaw = scopeArg ? scopeArg.slice('--scope='.length) : 'all_done';
  if (scopeRaw !== 'all_done' && scopeRaw !== 'all') {
    throw new Error(`无效 --scope=${scopeRaw}，仅支持 all_done|all`);
  }
  const dbPath = dbArg
    ? path.resolve(dbArg.slice('--db='.length))
    : path.resolve(__dirname, '..', 'data', 'code.db');
  const restoreManifest = restoreArg
    ? path.resolve(restoreArg.slice('--restore-protected-from='.length))
    : null;
  return { apply, dbPath, restoreManifest, scope: scopeRaw };
}

async function restoreNewlyProtectedRows(
  db: Database.Database,
  dbPath: string,
  sourceManifestPath: string,
  apply: boolean,
  manifestDir: string,
  backupDir: string,
  runAt: string
): Promise<void> {
  if (!fs.existsSync(sourceManifestPath)) {
    throw new Error(`源 apply manifest 不存在: ${sourceManifestPath}`);
  }
  const sourceManifest = JSON.parse(fs.readFileSync(sourceManifestPath, 'utf8')) as {
    mode?: string;
    backup?: string | null;
    changes?: ManifestChange[];
  };
  if (sourceManifest.mode !== 'apply' || !Array.isArray(sourceManifest.changes)) {
    throw new Error('只允许从本脚本生成的 apply manifest 做保护规则纠偏');
  }
  const sourceBackup = sourceManifest.backup ? path.resolve(sourceManifest.backup) : '';
  if (!sourceBackup || !fs.existsSync(sourceBackup)) {
    throw new Error(`apply 前备份不存在，无法精确恢复原字段: ${sourceBackup || '(空)'}`);
  }

  const previousDb = new Database(sourceBackup, { readonly: true });
  previousDb.pragma('busy_timeout = 10000');
  const getCurrent = db.prepare(
    `SELECT v.id, v.project_id, p.project_name, p.source_version,
            v.title, v.severity, v.severity_original, v.regrade_value, v.regrade_reason,
            v.category, v.description, v.recommendation, v.code_snippet, v.taint_chain,
            v.auth_required
       FROM vulnerabilities v
       JOIN projects p ON p.id = v.project_id
      WHERE v.id = ?`
  );
  const getPrevious = previousDb.prepare(
    `SELECT severity, severity_original, regrade_value, regrade_reason
       FROM vulnerabilities WHERE id = ?`
  );

  const restores: RestoreEntry[] = [];
  let skippedChangedAgain = 0;
  let missing = 0;
  for (const change of sourceManifest.changes) {
    const current = getCurrent.get(change.vulnerabilityId) as VulnerabilityRow | undefined;
    const previous = getPrevious.get(change.vulnerabilityId) as
      | {
          severity: string;
          severity_original: string | null;
          regrade_value: string | null;
          regrade_reason: string | null;
        }
      | undefined;
    if (!current || !previous) {
      missing++;
      continue;
    }
    if (normalizeSeverity(current.severity) !== normalizeSeverity(change.severityAfter)) {
      skippedChangedAgain++;
      continue;
    }
    const policy = applySeverityPolicy(current);
    if (!policy.protected || !policy.ruleId || !policy.reason) continue;
    restores.push({
      vulnerabilityId: current.id,
      projectId: current.project_id,
      projectName: current.project_name,
      title: current.title,
      appliedRuleId: change.ruleId,
      protectionRuleId: policy.ruleId,
      protectionReason: policy.reason,
      severityCurrent: current.severity,
      severityRestored: previous.severity,
      severityOriginalRestored: previous.severity_original,
      regradeValueRestored: previous.regrade_value,
      regradeReasonRestored: previous.regrade_reason,
    });
  }
  previousDb.close();

  const affectedProjects = new Set(restores.map((entry) => entry.projectId));
  let correctionBackup: string | null = null;
  let restored = 0;
  let conflicts = 0;

  if (apply && restores.length > 0) {
    fs.mkdirSync(backupDir, { recursive: true });
    correctionBackup = path.join(backupDir, `pre-protected-correction-${runAt}.db`);
    await db.backup(correctionBackup);

    const update = db.prepare(
      `UPDATE vulnerabilities
          SET severity = @severityRestored,
              severity_original = @severityOriginalRestored,
              regrade_value = @regradeValueRestored,
              regrade_reason = @regradeReasonRestored
        WHERE id = @vulnerabilityId
          AND lower(severity) = lower(@severityCurrent)`
    );
    const updateProjectCounts = db.prepare(
      `UPDATE projects
          SET count_critical = (SELECT COUNT(*) FROM vulnerabilities WHERE project_id = @projectId AND lower(severity) = 'critical'),
              count_high = (SELECT COUNT(*) FROM vulnerabilities WHERE project_id = @projectId AND lower(severity) = 'high'),
              count_medium = (SELECT COUNT(*) FROM vulnerabilities WHERE project_id = @projectId AND lower(severity) = 'medium'),
              count_low = (SELECT COUNT(*) FROM vulnerabilities WHERE project_id = @projectId AND lower(severity) = 'low'),
              count_info = (SELECT COUNT(*) FROM vulnerabilities WHERE project_id = @projectId AND lower(severity) = 'info')
        WHERE id = @projectId`
    );
    const restoreTransaction = db.transaction(() => {
      for (const entry of restores) {
        const result = update.run(entry);
        if (result.changes === 1) restored++;
        else conflicts++;
      }
      for (const projectId of affectedProjects) updateProjectCounts.run({ projectId });
    });
    restoreTransaction();
  }

  const mode = apply ? 'restore-protected-apply' : 'restore-protected-dry-run';
  const outputPath = path.join(manifestDir, `${mode}-${runAt}.json`);
  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    mode,
    database: dbPath,
    sourceManifest: sourceManifestPath,
    sourceBackup,
    correctionBackup,
    summary: {
      scannedAppliedChanges: sourceManifest.changes.length,
      candidates: restores.length,
      restored,
      conflicts,
      affectedProjects: affectedProjects.size,
      skippedChangedAgain,
      missing,
    },
    restores,
  };
  fs.writeFileSync(outputPath, JSON.stringify(manifest, null, 2), 'utf8');
  console.log(JSON.stringify({ manifestPath: outputPath, ...manifest.summary, correctionBackup }, null, 2));

  if (apply && conflicts > 0) {
    throw new Error(`保护规则纠偏存在 ${conflicts} 条并发冲突，请复核 manifest`);
  }
}

async function main(): Promise<void> {
  const { apply, dbPath, restoreManifest, scope } = parseArgs();
  if (!fs.existsSync(dbPath)) throw new Error(`数据库不存在: ${dbPath}`);

  const dataDir = path.dirname(dbPath);
  const manifestDir = path.join(dataDir, 'downgrade-manifests');
  const backupDir = path.join(dataDir, 'backups');
  fs.mkdirSync(manifestDir, { recursive: true });
  if (apply) fs.mkdirSync(backupDir, { recursive: true });

  const runAt = timestamp();
  const db = new Database(dbPath, { readonly: !apply });
  db.pragma('busy_timeout = 10000');

  if (restoreManifest) {
    await restoreNewlyProtectedRows(
      db,
      dbPath,
      restoreManifest,
      apply,
      manifestDir,
      backupDir,
      runAt
    );
    db.close();
    return;
  }

  const scopeSql = scope === 'all' ? ALL_PROJECTS_SQL : ALL_DONE_SQL;
  const scopeLabel =
    scope === 'all'
      ? 'all projects / all vulnerabilities'
      : "(projects.status='completed' AND projects.verify_status='none') OR projects.verify_status='completed'";

  const rows = db
    .prepare(
      `SELECT v.id, v.project_id, p.project_name, p.source_version,
              v.title, v.severity, v.severity_original, v.regrade_value, v.regrade_reason,
              v.category, v.description, v.recommendation, v.code_snippet, v.taint_chain,
              v.auth_required
         FROM vulnerabilities v
         JOIN projects p ON p.id = v.project_id
        WHERE ${scopeSql}
        ORDER BY p.project_name, v.id`
    )
    .iterate() as IterableIterator<VulnerabilityRow>;

  const changes: ManifestChange[] = [];
  const affectedProjects = new Set<string>();
  const beforeBySeverity: Record<string, number> = {};
  const predictedAfterBySeverity: Record<string, number> = {};
  const changesByRule: Record<string, number> = {};
  const protectedByRule: Record<string, number> = {};
  const transitions: Record<string, number> = {};
  const protectedSample: Array<Record<string, unknown>> = [];
  let scanned = 0;
  let protectedCount = 0;
  let unmatchedCount = 0;

  for (const row of rows) {
    scanned++;
    const beforeSeverity = normalizeSeverity(row.severity);
    increment(beforeBySeverity, beforeSeverity);
    const result = applySeverityPolicy(row);
    increment(predictedAfterBySeverity, result.severity);

    if (result.protected) {
      protectedCount++;
      increment(protectedByRule, result.ruleId ?? 'protect.unknown');
      if (protectedSample.length < 100) {
        protectedSample.push({
          vulnerabilityId: row.id,
          projectId: row.project_id,
          projectName: row.project_name,
          title: row.title,
          severity: row.severity,
          severityOriginal: row.severity_original,
          ruleId: result.ruleId,
          reason: result.reason,
          wouldRestore: result.changed,
        });
      }
    } else if (!result.ruleId) {
      unmatchedCount++;
    }

    if (!result.changed || !result.ruleId || !result.reason) continue;
    const action =
      result.protected && result.severityOriginal
        ? ('restore-protected' as const)
        : ('downgrade' as const);
    const change: ManifestChange = {
      vulnerabilityId: row.id,
      projectId: row.project_id,
      projectName: row.project_name,
      sourceVersion: row.source_version,
      title: row.title,
      category: row.category ?? '',
      severityBefore: beforeSeverity,
      severityAfter: result.severity,
      severityOriginalBefore: row.severity_original,
      severityOriginalAfter: result.severityOriginal,
      regradeValueAfter: realTeamLabel(result.severity),
      regradeReasonBefore: row.regrade_reason,
      regradeReasonAfter: result.regradeReason,
      ruleId: result.ruleId,
      ruleReason: result.reason,
      action,
    };
    changes.push(change);
    affectedProjects.add(row.project_id);
    increment(changesByRule, result.ruleId);
    increment(transitions, `${beforeSeverity}->${result.severity}`);
  }

  const mode = apply ? 'apply' : 'dry-run';
  const manifestPath = path.join(manifestDir, `${mode}-${runAt}.json`);
  let backupPath: string | null = null;
  let applied = 0;
  let conflicts = 0;

  if (apply) {
    backupPath = path.join(backupDir, `pre-low-value-policy-${runAt}.db`);
    await db.backup(backupPath);

    const update = db.prepare(
      `UPDATE vulnerabilities
          SET severity = @severityAfter,
              severity_original = @severityOriginalAfter,
              regrade_value = @regradeValueAfter,
              regrade_reason = @regradeReasonAfter
        WHERE id = @vulnerabilityId
          AND lower(severity) = lower(@severityBefore)`
    );
    const updateProjectCounts = db.prepare(
      `UPDATE projects
          SET count_critical = (
                SELECT COUNT(*) FROM vulnerabilities
                 WHERE project_id = @projectId AND lower(severity) = 'critical'
              ),
              count_high = (
                SELECT COUNT(*) FROM vulnerabilities
                 WHERE project_id = @projectId AND lower(severity) = 'high'
              ),
              count_medium = (
                SELECT COUNT(*) FROM vulnerabilities
                 WHERE project_id = @projectId AND lower(severity) = 'medium'
              ),
              count_low = (
                SELECT COUNT(*) FROM vulnerabilities
                 WHERE project_id = @projectId AND lower(severity) = 'low'
              ),
              count_info = (
                SELECT COUNT(*) FROM vulnerabilities
                 WHERE project_id = @projectId AND lower(severity) = 'info'
              )
        WHERE id = @projectId`
    );

    const applyTransaction = db.transaction(() => {
      for (const change of changes) {
        const result = update.run(change);
        if (result.changes === 1) applied++;
        else conflicts++;
      }
      for (const projectId of affectedProjects) updateProjectCounts.run({ projectId });
    });
    applyTransaction();
  }

  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    mode,
    database: dbPath,
    backup: backupPath,
    scopeMode: scope,
    scope: scopeLabel,
    summary: {
      scanned,
      changed: changes.length,
      applied,
      conflicts,
      affectedProjects: affectedProjects.size,
      protected: protectedCount,
      unmatched: unmatchedCount,
      beforeBySeverity,
      predictedAfterBySeverity,
      transitions,
      changesByRule,
      protectedByRule,
    },
    protectedSample,
    changes,
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

  console.log(JSON.stringify({ manifestPath, ...manifest.summary, backup: backupPath }, null, 2));
  db.close();

  if (apply && conflicts > 0) {
    throw new Error(`存在 ${conflicts} 条并发冲突，已在 manifest 中记录；请复核后重跑`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : error);
  process.exitCode = 1;
});
