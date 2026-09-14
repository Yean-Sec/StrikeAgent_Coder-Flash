/**
 * Pending CHM count + next batch files for Cursor verify orchestration.
 * Usage: node scripts/cursor-verify-pending.js <projectId>
 */
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const projectId = process.argv[2];
if (!projectId) {
  console.error('Usage: node cursor-verify-pending.js <projectId>');
  process.exit(1);
}

const db = new Database(path.join(__dirname, '..', 'data', 'code.db'), { readonly: true });
const p = db.prepare('SELECT workspace_path, project_name, target_url FROM projects WHERE id=?').get(projectId);
if (!p?.workspace_path) {
  console.error('project not found');
  process.exit(1);
}

const vulns = db
  .prepare(
    `SELECT v.id, v.title, v.severity FROM vulnerabilities v
     WHERE v.project_id=? AND v.severity IN ('critical','high','medium')
     ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, v.title`
  )
  .all(projectId);

const vv = new Map(
  db
    .prepare('SELECT vulnerability_id, remote_status FROM vulnerability_verifications WHERE project_id=?')
    .all(projectId)
    .map((r) => [r.vulnerability_id, r.remote_status])
);

const pending = vulns.filter((v) => {
  const rs = String(vv.get(v.id) || '').toLowerCase();
  return !rs || rs === 'unknown';
});

const batchDir = path.join(p.workspace_path, '_cursor_verify', 'batches');
let nextBatches = [];
if (fs.existsSync(batchDir)) {
  const files = fs.readdirSync(batchDir).filter((f) => f.startsWith('batch_') && f.endsWith('.json')).sort();
  for (const f of files) {
    const raw = JSON.parse(fs.readFileSync(path.join(batchDir, f), 'utf8'));
    const ids = (raw.vulns || []).map((x) => x.id);
    if (ids.some((id) => pending.find((p) => p.id === id))) {
      nextBatches.push({ file: f, batchNo: raw.batchNo, vulnCount: raw.vulns?.length || 0 });
    }
    if (nextBatches.length >= 10) break;
  }
}

console.log(
  JSON.stringify(
    {
      projectId,
      project_name: p.project_name,
      target_url: p.target_url,
      pendingChm: pending.length,
      totalChm: vulns.length,
      nextBatches,
    },
    null,
    2
  )
);
