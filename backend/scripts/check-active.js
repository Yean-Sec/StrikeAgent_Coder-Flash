const Database = require('better-sqlite3');
const db = new Database('data/code.db');
const vv = db
  .prepare(
    `SELECT state, COUNT(*) c FROM vulnerability_verifications
     WHERE state IN ('queued','running') GROUP BY state`
  )
  .all();
console.log('vv states', vv);
const active = db
  .prepare(
    `SELECT id, project_name, status, verify_status, env_status
     FROM projects
     WHERE status IN ('running','queued') OR verify_status IN ('running','queued')
     ORDER BY verify_status, id`
  )
  .all();
console.log('active count', active.length);
console.log(active.slice(0, 5));
db.close();
