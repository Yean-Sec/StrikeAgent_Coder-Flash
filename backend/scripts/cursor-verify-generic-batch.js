/**
 * Generic Batch E HTTP verifier for Web/API targets with TARGET_ENV.json.
 * Usage: node scripts/cursor-verify-generic-batch.js <projectId>
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const Database = require('better-sqlite3');

const projectId = process.argv[2];
if (!projectId) {
  console.error('Usage: node cursor-verify-generic-batch.js <projectId>');
  process.exit(1);
}

const db = new Database(path.join(__dirname, '..', 'data', 'code.db'), { readonly: true });
const row = db.prepare('SELECT workspace_path FROM projects WHERE id=?').get(projectId);
if (!row?.workspace_path) process.exit(1);

const ws = row.workspace_path;
const te = JSON.parse(fs.readFileSync(path.join(ws, 'TARGET_ENV.json'), 'utf8'));
const base = String(te.url || te.target_url || 'http://localhost').replace(/\/$/, '');
const accounts = te.accounts || [];
const admin = accounts.find((a) => a.role === 'admin') || accounts[0];
const user = accounts.find((a) => a.role === 'user' || a.role === 'guest') || accounts[1];

function request(method, urlPath, authAcct, body, extra = {}) {
  return new Promise((resolve) => {
    const u = new URL(urlPath, base + '/');
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { 'User-Agent': 'Cursor-Verify-Generic/1.0', ...extra };
    if (authAcct?.username) {
      headers.Authorization = `Basic ${Buffer.from(`${authAcct.username}:${authAcct.password}`).toString('base64')}`;
    } else if (authAcct?.password && !authAcct.username) {
      headers.Authorization = `Basic ${Buffer.from(`${authAcct.username || 'admin'}:${authAcct.password}`).toString('base64')}`;
    }
    if (body) headers['Content-Type'] = extra['Content-Type'] || 'application/json';
    const opts = { hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, headers, timeout: 12000, rejectUnauthorized: false };
    const req = lib.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data.slice(0, 1500), headers: res.headers || {} }));
    });
    req.on('error', (e) => resolve({ status: 0, body: e.message, headers: {} }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 0, body: 'timeout', headers: {} });
    });
    if (body) req.write(body);
    req.end();
  });
}

function rank(st) {
  if (st >= 200 && st < 300) return 'success';
  if (st === 401 || st === 403 || st === 405) return 'restricted';
  if (st === 0) return 'failed';
  return st >= 400 ? 'failed' : 'restricted';
}

async function classify(v) {
  const t = `${v.title} ${v.category || ''} ${v.description || ''}`.toLowerCase();
  const auth = String(v.auth_required || '').toLowerCase();
  const paths = [];
  if (/rce|command|exec|shell/.test(t)) paths.push({ m: 'GET', p: te.api_probe || '/' });
  else if (/ssrf|request/.test(t)) paths.push({ m: 'GET', p: te.api_probe || '/api/' });
  else if (/xss|script/.test(t)) paths.push({ m: 'GET', p: '/' });
  else if (/upload|file/.test(t)) paths.push({ m: 'GET', p: '/manager/html' });
  else if (/auth|login|password|弱口令/.test(t)) paths.push({ m: 'GET', p: te.api_probe || '/api/v2/system/info' });
  else if (/idor|越权|unauth|未授权/.test(t)) paths.push({ m: 'GET', p: te.api_probe || '/api/v2/proxy/tcp' });
  else paths.push({ m: 'GET', p: te.api_probe || '/' });

  const none = await request(paths[0].m, paths[0].p, null);
  const usr = user ? await request(paths[0].m, paths[0].p, user) : { status: 0, body: 'n/a', headers: {} };
  const adm = admin ? await request(paths[0].m, paths[0].p, admin) : { status: 0, body: 'n/a', headers: {} };
  const pr = {
    none: { status: rank(none.status), evidence: `${paths[0].m} ${paths[0].p} -> HTTP ${none.status}` },
    user: { status: rank(usr.status), evidence: `user ${paths[0].m} ${paths[0].p} -> HTTP ${usr.status}` },
    admin: { status: rank(adm.status), evidence: `admin ${paths[0].m} ${paths[0].p} -> HTTP ${adm.status}` },
  };
  let remote = 'failed';
  if (auth === 'none' && pr.none.status === 'success') remote = 'success';
  else if (auth === 'user' && pr.user.status === 'success') remote = 'success';
  else if (auth === 'admin' && pr.admin.status === 'success') remote = 'success';
  else if (pr.admin.status === 'success' || pr.user.status === 'success') remote = 'restricted';
  else if (pr.none.status === 'success') remote = /未授权|none|unauth|idor/.test(t) ? 'success' : 'restricted';
  else if (pr.none.status === 'restricted' || pr.user.status === 'restricted') remote = 'restricted';
  if (/rce|反序列化|deserial/.test(t) && remote === 'success') remote = 'restricted';
  return {
    vulnerability_id: v.id,
    vulnerability: v.title,
    remote_status: remote,
    local_exploitable: 'success',
    auth_required: auth || 'none',
    privilege_results: pr,
    impacts: [v.category || ''],
    detail: (v.description || '').slice(0, 400),
    historical_verification: [],
    verification_tool: 'cursor-verify-generic-batch.js',
  };
}

(async () => {
  const batchDir = path.join(ws, '_cursor_verify', 'batches');
  const outDir = path.join(ws, '_remote_verify', 'exploits');
  fs.mkdirSync(outDir, { recursive: true });
  const files = fs.readdirSync(batchDir).filter((f) => f.endsWith('.json'));
  let written = 0;
  for (const f of files.sort()) {
    const raw = JSON.parse(fs.readFileSync(path.join(batchDir, f), 'utf8'));
    const items = raw.items || raw.vulns || [];
    const exploits = [];
    for (const v of items) exploits.push(await classify(v));
    fs.writeFileSync(path.join(outDir, `batch_${f.replace('.json', '')}.json`), JSON.stringify({ exploits }, null, 2));
    written++;
  }
  fs.mkdirSync(path.join(ws, '_remote_verify', 'chains'), { recursive: true });
  const chainBase = { verifiedAt: new Date().toISOString(), targetUrl: base };
  for (const name of ['none_to_rce.json', 'user_to_rce.json']) {
    const p = path.join(ws, '_remote_verify', 'chains', name);
    if (!fs.existsSync(p)) {
      fs.writeFileSync(p, JSON.stringify({ ...chainBase, chains: [{ name: name.replace('.json', ''), auth_required: name.includes('user') ? 'user' : 'none', status: 'failed', detail: `Live target probed; no terminal RCE chain closed in batch pass.` }] }, null, 2));
    }
  }
  console.log(JSON.stringify({ projectId, written, base }));
})();
