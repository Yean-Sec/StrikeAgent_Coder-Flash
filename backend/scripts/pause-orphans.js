const Database = require('better-sqlite3');
const path = require('path');
const dbPath = path.join(__dirname, '..', 'data', 'code.db');
const db = new Database(dbPath);
const auditBefore = db
  .prepare("SELECT COUNT(*) c FROM projects WHERE status IN ('running','queued')")
  .get().c;
const verifyBefore = db
  .prepare("SELECT COUNT(*) c FROM projects WHERE verify_status IN ('running','queued')")
  .get().c;
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
db.prepare(
  "INSERT INTO settings(key,value) VALUES('auto_resume_orphans_on_startup','0') ON CONFLICT(key) DO UPDATE SET value=excluded.value"
).run();
console.log(
  JSON.stringify({
    auditBefore,
    verifyBefore,
    auditPaused: ra.changes,
    verifyPaused: rv.changes,
  })
);
db.close();
