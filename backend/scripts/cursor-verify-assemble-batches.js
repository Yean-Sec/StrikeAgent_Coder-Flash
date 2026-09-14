/**
 * Ensure each _cursor_verify/batches/batch_NNN.json has a matching
 * _remote_verify/exploits/batch_NNN_verify_cursor.json with all vuln IDs,
 * merging from any exploit JSON that references those IDs.
 *
 * Usage: node scripts/cursor-verify-assemble-batches.js <projectId>
 */
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const projectId = process.argv[2];
if (!projectId) {
  console.error('Usage: node cursor-verify-assemble-batches.js <projectId>');
  process.exit(1);
}

const db = new Database(path.join(__dirname, '..', 'data', 'code.db'), { readonly: true });
const row = db.prepare('SELECT workspace_path FROM projects WHERE id=?').get(projectId);
if (!row?.workspace_path) process.exit(1);

const ws = row.workspace_path;
const batchDir = path.join(ws, '_cursor_verify', 'batches');
const exploitDir = path.join(ws, '_remote_verify', 'exploits');

const byId = new Map();
for (const f of fs.readdirSync(exploitDir)) {
  if (!f.endsWith('.json') || f.endsWith('.tmp')) continue;
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(exploitDir, f), 'utf8'));
    const list = Array.isArray(raw) ? raw : raw.exploits || raw.results || [];
    for (const e of list) {
      const id = String(e.vulnerability_id || e.id || '').trim();
      if (id) byId.set(id, e);
    }
  } catch {
    /* skip */
  }
}

let assembled = 0;
let filled = 0;
for (const f of fs
  .readdirSync(batchDir)
  .filter((x) => /^batch_\d+\.json$/.test(x))
  .sort()) {
  const batch = JSON.parse(fs.readFileSync(path.join(batchDir, f), 'utf8'));
  const vulns = batch.vulns || [];
  const outName = f.replace('.json', '_verify_cursor.json');
  const outPath = path.join(exploitDir, outName);
  let existing = [];
  if (fs.existsSync(outPath)) {
    try {
      const raw = JSON.parse(fs.readFileSync(outPath, 'utf8'));
      existing = raw.exploits || [];
    } catch {
      existing = [];
    }
  }
  const map = new Map(existing.map((e) => [e.vulnerability_id, e]));
  for (const v of vulns) {
    if (map.has(v.id)) continue;
    const hit = byId.get(v.id);
    if (hit) {
      map.set(v.id, { ...hit, vulnerability_id: v.id, vulnerability: hit.vulnerability || v.title });
      filled++;
    }
  }
  const exploits = vulns.map((v) => map.get(v.id)).filter(Boolean);
  if (exploits.length === 0) continue;
  if (exploits.length < vulns.length) {
    // keep partial; don't overwrite with incomplete unless we added from byId
  }
  fs.writeFileSync(outPath, JSON.stringify({ exploits }, null, 2));
  assembled++;
}

console.log(JSON.stringify({ projectId, assembledBatchFiles: assembled, entriesFilledFromPool: filled }));
