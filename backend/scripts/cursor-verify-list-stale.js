/**
 * List batch_NNN.json files still using auto-fill placeholder text.
 * Usage: node scripts/cursor-verify-list-stale.js <projectId>
 */
const fs = require('fs');
const path = require('path');

const projectId = process.argv[2];
if (!projectId) process.exit(1);
const dbPath = path.join(__dirname, '..', 'data', 'code.db');
const Database = require('better-sqlite3');
const row = new Database(dbPath, { readonly: true })
  .prepare('SELECT workspace_path FROM projects WHERE id=?')
  .get(projectId);
if (!row?.workspace_path) process.exit(1);
const dir = path.join(row.workspace_path, '_remote_verify', 'exploits');
const stale = [];
for (const f of fs.readdirSync(dir).filter((x) => x.match(/^batch_\d+_cursor\.json$/))) {
  const t = fs.readFileSync(path.join(dir, f), 'utf8');
  if (/未覆盖该 Sink|待后续波次复测/.test(t)) stale.push(f);
}
console.log(JSON.stringify({ projectId, stale, count: stale.length }, null, 2));
