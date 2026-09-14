/**
 * Real-time monitor for continueMode gap-fill batch.
 * Plan: missing agents only → dedup → codeverify → regrade (never full orchestrator for this wave).
 */
require('tsx/cjs');
const db = require('../src/db.ts').default;

const CONTINUE_MARK = '▶ 续跑代码审计：补全缺失子智能体';
const FULL_MARK = '▶ 漏洞审计：启动 multi-language-comprehensive-auditor';
// 本轮批量续跑的固定起点（2026-07-28 12:40 UTC+8）。不能使用滚动窗口，
// 否则长队列中的已完成项目会在 6 小时后从验收范围消失。
const WAVE_TS = 1785213000000;

const statusRows = db
  .prepare(
    `SELECT status, COUNT(*) AS c FROM projects
     WHERE status IN ('queued','running','completed','failed','paused')
     GROUP BY status`
  )
  .all();
const status = Object.fromEntries(statusRows.map((r) => [r.status, r.c]));

const running = db
  .prepare(
    `SELECT id, project_name, started_at FROM projects WHERE status = 'running' ORDER BY started_at DESC`
  )
  .all();

function latestEvent(projectId, like, sinceTs) {
  return db
    .prepare(
      `SELECT ts, substr(text, 1, 160) AS t FROM agent_events
       WHERE project_id = ? AND text LIKE ? AND ts >= ?
       ORDER BY ts DESC LIMIT 1`
    )
    .get(projectId, like, sinceTs);
}

function hasEvent(projectId, like, sinceTs) {
  return !!latestEvent(projectId, like, sinceTs);
}

const stageOf = (id) => {
  const continueEvent = latestEvent(id, `${CONTINUE_MARK}%`, WAVE_TS);
  const cont = !!continueEvent;
  const continueTs = continueEvent?.ts || WAVE_TS;
  const fullAfter = db
    .prepare(
      `SELECT e.ts FROM agent_events e
       WHERE e.project_id = ? AND e.text LIKE ? AND e.ts >= ?
         AND e.ts > COALESCE((
           SELECT MAX(c.ts) FROM agent_events c
           WHERE c.project_id = ? AND c.text LIKE ? AND c.ts >= ?
         ), 0)
       ORDER BY e.ts DESC LIMIT 1`
    )
    .get(id, `${FULL_MARK}%`, WAVE_TS, id, `${CONTINUE_MARK}%`, WAVE_TS);

  const gapFill = hasEvent(id, '%仅补跑这些子智能体%', continueTs);
  const gapOk =
    hasEvent(id, '%子智能体覆盖完整%', continueTs) ||
    hasEvent(id, '%审计完成硬闸通过%', continueTs);
  const dedup = hasEvent(id, '%▶ AI 智能去重%', continueTs);
  const verify = hasEvent(id, '%▶ 代码级验证%', continueTs);
  const regrade = hasEvent(id, '%▶ 红队实战二次评级%', continueTs);
  const done =
    hasEvent(id, '%✓ 实战二次评级完成%', continueTs) ||
    hasEvent(id, '%✓ 已合并二次评级到代码级验证%', continueTs);

  let stage = 'boot';
  if (done) stage = 'regrade_done';
  else if (regrade) stage = 'regrading';
  else if (verify) stage = 'codeverifying';
  else if (dedup) stage = 'deduping';
  else if (gapOk) stage = 'post_ready';
  else if (gapFill) stage = 'gap_filling';
  else if (cont) stage = 'continued';

  return {
    stage,
    continueMode: cont,
    continueTs,
    fullAuditorAfterContinue: !!fullAfter,
    coverageComplete: gapOk,
    dedupComplete: dedup,
    codeVerifyComplete: verify,
    regradeComplete: done,
  };
};

const runningDetail = running.map((p) => {
  const s = stageOf(p.id);
  return {
    name: p.project_name,
    id: p.id,
    ...s,
  };
});

const anomalies = runningDetail.filter((r) => r.fullAuditorAfterContinue || !r.continueMode);

const continuedProjects = db
  .prepare(
    `SELECT DISTINCT p.id, p.project_name, p.status, p.finished_at, p.error_message
     FROM projects p
     INNER JOIN agent_events e ON e.project_id = p.id
     WHERE e.text LIKE ? AND e.ts >= ?
     ORDER BY p.finished_at DESC`
  )
  .all(`${CONTINUE_MARK}%`, WAVE_TS);

const completionIssues = continuedProjects
  .filter((project) => project.status === 'completed')
  .map((project) => ({ ...project, ...stageOf(project.id) }))
  .filter(
    (project) =>
      project.fullAuditorAfterContinue ||
      !project.coverageComplete ||
      !project.dedupComplete ||
      !project.codeVerifyComplete ||
      !project.regradeComplete
  )
  .map((project) => ({
    id: project.id,
    name: project.project_name,
    missing: [
      !project.coverageComplete && 'coverage',
      !project.dedupComplete && 'dedup',
      !project.codeVerifyComplete && 'code_verify',
      !project.regradeComplete && 'regrade',
      project.fullAuditorAfterContinue && 'full_auditor_after_continue',
    ].filter(Boolean),
  }));

const continuedFailures = continuedProjects
  .filter((project) => project.status === 'failed')
  .map((project) => ({
    id: project.id,
    name: project.project_name,
    error: String(project.error_message || '').slice(0, 180),
  }));

// Recent completions in this wave that came from continue
const recentDone = db
  .prepare(
    `SELECT p.id, p.project_name, p.finished_at,
            p.count_critical, p.count_high, p.count_medium, p.count_low, p.count_info
     FROM projects p
     WHERE p.status = 'completed'
       AND p.finished_at >= ?
       AND EXISTS (
         SELECT 1 FROM agent_events e
         WHERE e.project_id = p.id AND e.text LIKE ? AND e.ts >= ?
       )
     ORDER BY p.finished_at DESC
     LIMIT 8`
  )
  .all(WAVE_TS, `${CONTINUE_MARK}%`, WAVE_TS);

const recentFailed = db
  .prepare(
    `SELECT id, project_name, substr(COALESCE(error_message,''),1,140) AS err
     FROM projects WHERE status = 'failed' ORDER BY finished_at DESC LIMIT 8`
  )
  .all();

const stageCounts = {};
for (const r of runningDetail) {
  stageCounts[r.stage] = (stageCounts[r.stage] || 0) + 1;
}

const report = {
  ts: new Date().toISOString(),
  status,
  running: running.length,
  stageCounts,
  anomalies: anomalies.map((a) => ({
    name: a.name,
    id: a.id,
    stage: a.stage,
    continueMode: a.continueMode,
    fullAuditorAfterContinue: a.fullAuditorAfterContinue,
  })),
  runningSample: runningDetail.slice(0, 12),
  recentContinueCompleted: recentDone,
  completionIssues,
  continuedFailures,
  recentFailed,
  verdict:
    anomalies.length === 0 && completionIssues.length === 0 && continuedFailures.length === 0
      ? 'OK: running jobs and completed jobs meet the continue/gap-fill design'
      : `ALERT: ${anomalies.length + completionIssues.length + continuedFailures.length} design-validation issues`,
};

console.log(JSON.stringify(report, null, 2));
