/**
 * Cursor-only project verification orchestrator (no Pi Agent).
 * Usage: node scripts/cursor-verify-orchestrate-one.js <projectId>
 * Requires TARGET_ENV.json in workspace. Runs export→batches→http-batch→finish.
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const projectId = process.argv[2];
if (!projectId) {
  console.error('Usage: node cursor-verify-orchestrate-one.js <projectId>');
  process.exit(1);
}

const root = path.join(__dirname, '..');
const repoRoot = path.join(root, '..');
const ws = path.join(root, 'workspace', projectId);
const tePath = path.join(ws, 'TARGET_ENV.json');
if (!fs.existsSync(tePath)) {
  console.error('TARGET_ENV.json missing for', projectId);
  process.exit(2);
}

const run = (cmd, cwd = root) => {
  console.log('>', cmd);
  execSync(cmd, { cwd, stdio: 'inherit' });
};

const HIGH = 5,
  MED = 8;
function batchSize(s) {
  return s === 'medium' ? MED : HIGH;
}
function splitBatches(vulns) {
  const batches = [];
  let cur = [],
    limit = vulns.length ? batchSize(vulns[0].severity) : HIGH;
  for (const v of vulns) {
    const l = batchSize(v.severity);
    if (cur.length && (cur.length >= limit || l !== limit)) {
      batches.push(cur);
      cur = [];
    }
    limit = l;
    cur.push(v);
    if (cur.length >= limit) {
      batches.push(cur);
      cur = [];
    }
  }
  if (cur.length) batches.push(cur);
  return batches;
}

run(`node scripts/cursor-verify-helper.js export ${projectId}`, repoRoot);
const manifest = JSON.parse(fs.readFileSync(path.join(ws, '_cursor_verify', 'vuln_manifest.json'), 'utf8'));
const target = JSON.parse(fs.readFileSync(tePath, 'utf8'));
const batches = splitBatches(manifest.vulns);
const batchDir = path.join(ws, '_cursor_verify', 'batches');
fs.mkdirSync(batchDir, { recursive: true });
fs.mkdirSync(path.join(ws, '_remote_verify', 'exploits'), { recursive: true });
fs.mkdirSync(path.join(ws, '_remote_verify', 'chains'), { recursive: true });
batches.forEach((batch, i) => {
  fs.writeFileSync(
    path.join(batchDir, `batch_${String(i + 1).padStart(3, '0')}.json`),
    JSON.stringify({ batchNo: i + 1, totalBatches: batches.length, targetUrl: target.url, vulns: batch }, null, 2)
  );
});
console.log(JSON.stringify({ batches: batches.length, total: manifest.vulns.length }));

run(`node scripts/cursor-verify-http-batch.js ${projectId}`);
run(`node scripts/cursor-verify-finish-project.js ${projectId}`);

const pending = JSON.parse(execSync(`node scripts/cursor-verify-pending.js ${projectId}`, { cwd: root, encoding: 'utf8' }));
console.log(JSON.stringify({ projectId, pendingChm: pending.pendingChm, verify_status: pending.pendingChm === 0 ? 'completed' : 'running' }));
