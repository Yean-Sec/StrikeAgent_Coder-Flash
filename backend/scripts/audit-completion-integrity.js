const fs = require('fs');
const path = require('path');
require('tsx/cjs');

const root = path.resolve(__dirname, '..');
const db = require('../src/db.ts').default;
const { auditCompletedProjectCoverage } = require('../src/auditCoverageAudit.ts');

// 直接调用后端的唯一覆盖判定，避免报告脚本与完成硬闸规则漂移。
const live = auditCompletedProjectCoverage();
const failed = db
  .prepare(
    `SELECT p.id, p.project_name, p.source_version, p.error_message,
            (SELECT raw FROM agent_events e
             WHERE e.project_id = p.id AND e.agent = '审计完整性校验器'
             ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) AS evidence_raw
     FROM projects p
     WHERE p.status = 'failed'
       AND p.error_message LIKE '%历史审计覆盖不完整%'
     ORDER BY p.project_name ASC`
  )
  .all();
const resetPaused = db
  .prepare(
    `SELECT id, project_name, source_version, error_message
     FROM projects
     WHERE status = 'paused'
       AND error_message LIKE '%审计覆盖证据缺失%'
     ORDER BY project_name ASC`
  )
  .all();

const rows = [
  ...failed.map((project) => {
    let evidence = {};
    try {
      evidence = JSON.parse(project.evidence_raw || '{}');
    } catch {
      /* keep empty evidence */
    }
    return {
      id: project.id,
      project_name: project.project_name,
      source_version: project.source_version,
      classification: 'coverage_failed',
      evidence_source: evidence.evidence_source || 'audit_log',
      expected_count: evidence.expected_count ?? null,
      valid_count: evidence.valid_count ?? null,
      missing_agents: Array.isArray(evidence.missing_agents) ? evidence.missing_agents : [],
      reason: project.error_message,
    };
  }),
  ...resetPaused.map((project) => ({
    id: project.id,
    project_name: project.project_name,
    source_version: project.source_version,
    classification: 'reset_paused',
    evidence_source: 'audit_log',
    expected_count: null,
    valid_count: null,
    missing_agents: [],
    reason: project.error_message,
  })),
  ...live.projects.map((project) => ({
    id: project.project_id,
    project_name: project.project_name,
    source_version: null,
    classification:
      project.classification === 'complete' ? 'complete' : project.classification,
    evidence_source: project.evidence_source,
    expected_count: project.expected_count,
    valid_count: project.valid_count,
    missing_agents: project.missing_agents,
    reason: project.reason,
  })),
];

const summary = {
  scanned: rows.length,
  coverage_failed: rows.filter((row) => row.classification === 'coverage_failed').length,
  reset_paused: rows.filter((row) => row.classification === 'reset_paused').length,
  complete: rows.filter((row) => row.classification === 'complete').length,
  unverifiable: rows.filter((row) => row.classification === 'unverifiable').length,
};
const report = {
  generated_at: new Date().toISOString(),
  policy:
    '工作区存在时实时重算；工作区不存在时仅依据最新覆盖日志；任一必需 JSON 缺失/无法解析即失败',
  summary,
  projects: rows,
};
const output = path.join(root, 'scripts', 'audit-completion-integrity-report.json');
fs.writeFileSync(output, JSON.stringify(report, null, 2), 'utf8');
console.log(JSON.stringify({ output, summary }, null, 2));
