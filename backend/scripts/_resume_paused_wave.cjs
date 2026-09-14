require('tsx/cjs');

const db = require('../src/db.ts').default;
const { isAuditCoverageFailureMessage } = require('../src/runner.ts');

const WAVE_TS = 1785213000000;
const CONTINUE_MARK = '▶ 续跑代码审计：补全缺失子智能体';

async function main() {
  const paused = db
    .prepare(
      `SELECT id, project_name, error_message, status
       FROM projects
       WHERE status = 'paused'`
    )
    .all();

  const continuedIds = new Set(
    db
      .prepare(
        `SELECT DISTINCT project_id AS id
         FROM agent_events
         WHERE text LIKE ? AND ts >= ?`
      )
      .all(`${CONTINUE_MARK}%`, WAVE_TS)
      .map((row) => row.id)
  );

  const toResume = paused.filter(
    (project) =>
      continuedIds.has(project.id) ||
      isAuditCoverageFailureMessage(project.error_message)
  );

  const status = db
    .prepare(
      `SELECT status, COUNT(*) AS c FROM projects
       WHERE status IN ('queued','running','completed','failed','paused')
       GROUP BY status`
    )
    .all();

  console.log(
    JSON.stringify(
      {
        status,
        paused: paused.length,
        toResume: toResume.length,
        byReason: {
          continueMark: toResume.filter((p) => continuedIds.has(p.id)).length,
          coverageFailure: toResume.filter((p) =>
            isAuditCoverageFailureMessage(p.error_message)
          ).length,
        },
      },
      null,
      2
    )
  );

  if (!toResume.length) return;

  const ids = toResume.map((p) => p.id);
  const response = await fetch('http://127.0.0.1:8787/api/projects/bulk/resume', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ids }),
  });
  console.log(
    JSON.stringify(
      {
        resumeStatus: response.status,
        response: await response.json(),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
