/** 停 Pi 任务：关掉总闸并暂停 running/queued。库键仍为 claude_jobs_enabled。 */
const Database = require('better-sqlite3');
const path = require('path');
const db = new Database(path.join(__dirname, '..', 'data', 'code.db'));

db.prepare(
  "INSERT INTO settings(key,value) VALUES('claude_jobs_enabled','0') ON CONFLICT(key) DO UPDATE SET value=excluded.value"
).run();
db.prepare(
  "INSERT INTO settings(key,value) VALUES('auto_resume_orphans_on_startup','0') ON CONFLICT(key) DO UPDATE SET value=excluded.value"
).run();

const ra = db
  .prepare(
    "UPDATE projects SET status='paused', finished_at=datetime('now') WHERE status IN ('running','queued')"
  )
  .run();
const rv = db
  .prepare(
    "UPDATE projects SET verify_status='paused', verify_finished_at=datetime('now') WHERE verify_status IN ('running','queued')"
  )
  .run();
const vv = db
  .prepare(
    "UPDATE vulnerability_verifications SET state='paused', updated_at=datetime('now') WHERE state IN ('running','queued')"
  )
  .run();

console.log(
  JSON.stringify({
    claude_jobs_enabled: '0',
    auditPaused: ra.changes,
    verifyPaused: rv.changes,
    vvPaused: vv.changes,
  })
);
db.close();
