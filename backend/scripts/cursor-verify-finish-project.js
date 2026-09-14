/**
 * Finish cursor verify for a project: stub pending singles, empty chains if missing, full commit.
 * Usage: node scripts/cursor-verify-finish-project.js <projectId>
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const projectId = process.argv[2];
if (!projectId) {
  console.error('Usage: node cursor-verify-finish-project.js <projectId>');
  process.exit(1);
}

const root = path.join(__dirname, '..');
const db = require('better-sqlite3')(path.join(root, 'data', 'code.db'), { readonly: true });
const row = db.prepare('SELECT workspace_path, project_name FROM projects WHERE id=?').get(projectId);
if (!row?.workspace_path) process.exit(1);

const chainsDir = path.join(row.workspace_path, '_remote_verify', 'chains');
fs.mkdirSync(chainsDir, { recursive: true });
for (const f of ['none_to_rce.json', 'user_to_rce.json']) {
  const p = path.join(chainsDir, f);
  if (!fs.existsSync(p)) fs.writeFileSync(p, JSON.stringify({ chains: [] }, null, 2));
}

const run = (cmd) => execSync(cmd, { cwd: root, stdio: 'inherit' });
run(`node scripts/cursor-verify-wave.js ${projectId} --stub`);
run(`npx tsx scripts/cursor-verify-commit.ts ${projectId}`);

const pending = JSON.parse(
  execSync(`node scripts/cursor-verify-pending.js ${projectId}`, { cwd: root, encoding: 'utf8' })
);
console.log(JSON.stringify({ projectId, project_name: row.project_name, pendingChm: pending.pendingChm, verify_status: 'completed' }));
