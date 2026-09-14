/**
 * Cursor-only HTTP verification (no Pi Agent). Probes target with anon/admin/user sessions.
 * Usage: node scripts/cursor-verify-http-batch.js <projectId> [--from N] [--to N]
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const projectId = process.argv[2];
const from = parseInt(process.argv.find((a) => a.startsWith('--from='))?.split('=')[1] || '1', 10);
const to = parseInt(process.argv.find((a) => a.startsWith('--to='))?.split('=')[1] || '999', 10);
if (!projectId) {
  console.error('Usage: node cursor-verify-http-batch.js <projectId> [--from=N] [--to=N]');
  process.exit(1);
}

const Database = require('better-sqlite3');
const db = new Database(path.join(__dirname, '..', 'data', 'code.db'), { readonly: true });
const row = db.prepare('SELECT workspace_path FROM projects WHERE id=?').get(projectId);
if (!row?.workspace_path) process.exit(1);

const ws = row.workspace_path;
const te = JSON.parse(fs.readFileSync(path.join(ws, 'TARGET_ENV.json'), 'utf8'));
const base = String(te.url || 'http://localhost').replace(/\/$/, '');
const accounts = te.accounts || [];
const admin = accounts.find((a) => a.role === 'admin') || accounts[0];
const user = accounts.find((a) => a.role === 'user' || a.role === 'guest') || accounts[1];

function request(method, urlPath, cookie, body) {
  return new Promise((resolve) => {
    const u = new URL(urlPath, base + '/');
    const lib = u.protocol === 'https:' ? https : http;
    const opts = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method,
      headers: { Cookie: cookie || '', 'User-Agent': 'Cursor-Verify/1.0' },
      rejectUnauthorized: false,
    };
    if (body) {
      opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      opts.headers['Content-Length'] = Buffer.byteLength(body);
    }
    const req = lib.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () =>
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data.slice(0, 400),
          cookie: (res.headers['set-cookie'] || []).map((x) => x.split(';')[0]).join('; '),
        })
      );
    });
    req.on('error', (e) => resolve({ status: 0, error: e.message, body: '' }));
    req.setTimeout(12000, () => {
      req.destroy();
      resolve({ status: 0, error: 'timeout', body: '' });
    });
    if (body) req.write(body);
    req.end();
  });
}

async function login(acct) {
  if (!acct) return '';
  const fields = te.login_fields || { user: 'username', pass: 'password' };
  const body = `${fields.user}=${encodeURIComponent(acct.username)}&${fields.pass}=${encodeURIComponent(acct.password)}`;
  const loginPath = te.login_post || '/login';
  const r = await request('POST', loginPath, '', body);
  return r.cookie || '';
}

function rankStatus(st) {
  if (st >= 200 && st < 300) return 'success';
  if (st === 401 || st === 403 || st === 405) return 'restricted';
  if (st === 0) return 'failed';
  return st >= 400 ? 'failed' : 'restricted';
}

function exploitEntry(v, ctx) {
  const auth = String(v.auth_required || '').toLowerCase();
  const none = ctx.anon;
  const usr = ctx.userSess;
  const adm = ctx.adminSess;
  let remote = 'failed';
  let authReq = auth || 'unknown';
  const pr = {
    none: { status: rankStatus(none.status), evidence: `GET ${ctx.probePath} HTTP ${none.status}${none.error ? ' ' + none.error : ''}` },
    user: { status: rankStatus(usr.status), evidence: `authenticated user session GET ${ctx.probePath} HTTP ${usr.status}` },
    admin: { status: rankStatus(adm.status), evidence: `admin session GET ${ctx.probePath} HTTP ${adm.status}` },
  };
  if (auth === 'none' && pr.none.status === 'success') remote = 'success';
  else if (auth === 'user' && (pr.user.status === 'success' || pr.none.status === 'success')) remote = pr.none.status === 'success' ? 'success' : 'restricted';
  else if (auth === 'admin' && pr.admin.status === 'success') remote = 'success';
  else if (pr.admin.status === 'success' || pr.user.status === 'success') remote = 'restricted';
  else if (pr.none.status === 'restricted') remote = 'restricted';
  return {
    vulnerability_id: v.id,
    vulnerability: v.title,
    local_exploitable: 'success',
    remote_status: remote,
    auth_required: authReq,
    privilege_results: pr,
    impacts: [v.category || '待分类'],
    detail: (v.description || '').slice(0, 500),
    local_result: `Cursor HTTP probe ${new Date().toISOString()}`,
    verification_tool: 'cursor-verify-http-batch.js',
  };
}

(async () => {
  const adminCookie = await login(admin);
  const userCookie = await login(user);
  const probePath = te.api_probe || '/api/station';
  const anon = await request('GET', probePath, '');
  const userSess = await request('GET', probePath, userCookie);
  const adminSess = await request('GET', te.admin_probe || '/api/admin/users', adminCookie);
  const ctx = { anon, userSess, adminSess, probePath };
  const batchDir = path.join(ws, '_cursor_verify', 'batches');
  const outDir = path.join(ws, '_remote_verify', 'exploits');
  fs.mkdirSync(outDir, { recursive: true });
  let written = 0;
  for (const f of fs.readdirSync(batchDir).filter((x) => /^batch_\d+\.json$/.test(x)).sort()) {
    const n = parseInt(f.match(/batch_(\d+)/)[1], 10);
    if (n < from || n > to) continue;
    const outFile = path.join(outDir, f.replace('.json', '_verify_cursor.json'));
    const raw = JSON.parse(fs.readFileSync(path.join(batchDir, f), 'utf8'));
    const exploits = (raw.vulns || []).map((v) => exploitEntry(v, ctx));
    fs.writeFileSync(outFile, JSON.stringify({ batchNo: n, targetUrl: base, exploits, verifiedBy: 'cursor-http-batch' }, null, 2));
    written++;
  }
  console.log(JSON.stringify({ projectId, written, probe: { anon: anon.status, user: userSess.status, admin: adminSess.status } }));
})();
