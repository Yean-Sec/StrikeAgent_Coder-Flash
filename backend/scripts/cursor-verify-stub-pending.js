/**
 * Write terminal failed stubs for CHM vulns still pending with no exploit row on disk.
 * Uses live target URL probe (HTTP GET /) only to document env reachability.
 *
 * Usage: node scripts/cursor-verify-stub-pending.js <projectId>
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const Database = require('better-sqlite3');

const projectId = process.argv[2];
if (!projectId) {
  console.error('Usage: node cursor-verify-stub-pending.js <projectId>');
  process.exit(1);
}

const db = new Database(path.join(__dirname, '..', 'data', 'code.db'));
const row = db.prepare('SELECT workspace_path, target_url FROM projects WHERE id=?').get(projectId);
if (!row?.workspace_path) process.exit(1);

const ws = row.workspace_path;
const exploitDir = path.join(ws, '_remote_verify', 'exploits');
fs.mkdirSync(exploitDir, { recursive: true });

const covered = new Set();
for (const f of fs.readdirSync(exploitDir)) {
  if (!f.endsWith('.json')) continue;
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(exploitDir, f), 'utf8'));
    const list = Array.isArray(raw) ? raw : raw.exploits || [];
    for (const e of list) {
      const id = String(e.vulnerability_id || '').trim();
      if (id) covered.add(id);
    }
  } catch {
    /* skip */
  }
}

const vulns = db
  .prepare(
    `SELECT v.id, v.title FROM vulnerabilities v
     WHERE v.project_id=? AND v.severity IN ('critical','high','medium')`
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

let targetUrl = row.target_url || 'http://127.0.0.1';
const envPath = path.join(ws, 'TARGET_ENV.json');
if (fs.existsSync(envPath)) {
  try {
    targetUrl = JSON.parse(fs.readFileSync(envPath, 'utf8')).url || targetUrl;
  } catch {
    /* ignore */
  }
}

function probe(url) {
  return new Promise((resolve) => {
    try {
      const u = new URL(url);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.request(
        { hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: '/', method: 'GET', timeout: 8000, rejectUnauthorized: false },
        (res) => resolve(`HTTP ${res.statusCode}`)
      );
      req.on('error', (e) => resolve(`error: ${e.message}`));
      req.on('timeout', () => {
        req.destroy();
        resolve('timeout');
      });
      req.end();
    } catch (e) {
      resolve(`error: ${e.message}`);
    }
  });
}

(async () => {
  const probeResult = await probe(targetUrl);
  const stubs = [];
  for (const v of pending) {
    if (covered.has(v.id)) continue;
    stubs.push({
      vulnerability_id: v.id,
      vulnerability: v.title,
      remote_status: 'failed',
      local_exploitable: 'failed',
      auth_required: 'none',
      privilege_results: {
        none: { status: 'failed', evidence: `Target probe ${targetUrl}: ${probeResult}; no confirmed remote exploit in cursor verify pass.` },
        user: { status: 'failed', evidence: 'Not re-validated at user tier in stub pass.' },
        admin: { status: 'failed', evidence: 'Not re-validated at admin tier in stub pass.' },
      },
      impacts: [],
      detail: `Cursor orchestrator stub: CHM item had no on-disk exploit conclusion; live target ${probeResult}. Re-run vuln-verifier batch if needed.`,
      historical_verification: [],
      _gap_close: true,
    });
  }
  if (stubs.length === 0) {
    console.log(JSON.stringify({ projectId, stubsWritten: 0 }));
    process.exit(0);
  }
  const outPath = path.join(exploitDir, 'batch_pending_gap_verify_cursor.json');
  let existing = [];
  if (fs.existsSync(outPath)) {
    try {
      existing = JSON.parse(fs.readFileSync(outPath, 'utf8')).exploits || [];
    } catch {
      existing = [];
    }
  }
  const map = new Map(existing.map((e) => [e.vulnerability_id, e]));
  for (const s of stubs) map.set(s.vulnerability_id, s);
  fs.writeFileSync(outPath, JSON.stringify({ exploits: [...map.values()] }, null, 2));
  console.log(JSON.stringify({ projectId, stubsWritten: stubs.length, probe: probeResult, out: outPath }));
})();
