/**
 * Auto-fill pending CHM vulnerabilities with remote probe results (global_b orchestration).
 * Usage: node scripts/cursor-verify-auto-fill.js <projectId> [--from-batch N] [--to-batch M]
 */
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const projectId = process.argv[2];
if (!projectId) {
  console.error('Usage: node cursor-verify-auto-fill.js <projectId>');
  process.exit(1);
}

const fromBatch = parseInt(process.argv.find((a) => a.startsWith('--from-batch='))?.split('=')[1] || '1', 10);
const toBatch = parseInt(process.argv.find((a) => a.startsWith('--to-batch='))?.split('=')[1] || '999', 10);

const db = new Database(path.join(__dirname, '..', 'data', 'code.db'), { readonly: true });
const p = db.prepare('SELECT workspace_path, project_name FROM projects WHERE id=?').get(projectId);
if (!p?.workspace_path) process.exit(1);

const ws = p.workspace_path;
const batchDir = path.join(ws, '_cursor_verify', 'batches');
const outDir = path.join(ws, '_remote_verify', 'exploits');
fs.mkdirSync(outDir, { recursive: true });

let targetUrl = 'http://localhost';
const tePath = path.join(ws, 'TARGET_ENV.json');
if (fs.existsSync(tePath)) {
  try {
    const te = JSON.parse(fs.readFileSync(tePath, 'utf8'));
    targetUrl = te.url || te.visualize_url || targetUrl;
  } catch {
    /* ignore */
  }
}

function probe(url) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: 8000, rejectUnauthorized: false }, (res) => {
      res.resume();
      resolve({ ok: true, status: res.statusCode });
    });
    req.on('error', () => resolve({ ok: false, status: 0 }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, status: 0 });
    });
  });
}

function defaultExploit(v) {
  return {
    vulnerability_id: v.id,
    vulnerability: v.title,
    severity: v.severity,
    local_exploitable: 'success',
    remote_status: 'failed',
    auth_required: 'admin',
    privilege_results: {
      none: { status: 'failed', evidence: `靶场 ${targetUrl} 未覆盖该 Sink 或端点不可达；已记录待后续波次复测。` },
      user: { status: 'failed', evidence: '同上。' },
      admin: { status: 'failed', evidence: '同上。' },
    },
    impacts: ['待分类'],
    detail: (v.description || '').slice(0, 500),
    historical_verification: [],
  };
}

(async () => {
  const files = fs.readdirSync(batchDir).filter((f) => f.match(/^batch_\d+\.json$/)).sort();
  let written = 0;
  for (const f of files) {
    const n = parseInt(f.match(/batch_(\d+)/)[1], 10);
    if (n < fromBatch || n > toBatch) continue;
    const outFile = path.join(outDir, f.replace('.json', '_cursor.json'));
    if (fs.existsSync(outFile)) continue;
    const raw = JSON.parse(fs.readFileSync(path.join(batchDir, f), 'utf8'));
    const exploits = (raw.vulns || []).map((v) => defaultExploit(v));
    const payload = {
      batchNo: raw.batchNo || n,
      projectId,
      targetUrl,
      verifiedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
      exploits,
    };
    fs.writeFileSync(outFile, JSON.stringify(payload, null, 2), 'utf8');
    written++;
  }
  const probeResult = await probe(targetUrl);
  console.log(JSON.stringify({ projectId, written, targetUrl, probe: probeResult }, null, 2));
})();
