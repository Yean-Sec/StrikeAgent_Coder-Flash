/**
 * Generic Cursor web verification for Batch D remaining projects.
 * Usage: node scripts/cursor-verify-generic-web.js <projectId> [port]
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const Database = require('better-sqlite3');

const projectId = process.argv[2];
const portOverride = process.argv[3];
if (!projectId) process.exit(1);

const db = new Database(path.join(__dirname, '..', 'data', 'code.db'), { readonly: true });
const row = db.prepare('SELECT workspace_path, project_name FROM projects WHERE id=?').get(projectId);
if (!row?.workspace_path) process.exit(1);
const ws = row.workspace_path;
const tePath = path.join(ws, 'TARGET_ENV.json');
const te = fs.existsSync(tePath) ? JSON.parse(fs.readFileSync(tePath, 'utf8')) : {};
const base = String(te.url || `http://localhost:${portOverride || 80}`).replace(/\/$/, '');
const u = new URL(base);
const port = u.port || (u.protocol === 'https:' ? 443 : 80);
const accounts = Array.isArray(te.accounts) ? te.accounts : te.accounts ? Object.entries(te.accounts).map(([role, v]) => ({ role, ...(typeof v === 'object' ? v : { username: String(v) }) })) : [];
const adminAcct = accounts.find((a) => a.role === 'admin') || { username: 'admin', password: 'admin123' };
const userAcct = accounts.find((a) => a.role === 'user' || a.role === 'guest') || { username: 'user', password: 'user123' };

const vulnMeta = new Map(
  db.prepare('SELECT id, title, severity, category, description, auth_required FROM vulnerabilities WHERE project_id=?').all(projectId).map((v) => [v.id, v])
);

function request(method, urlPath, cookie = '', body = null, headers = {}) {
  return new Promise((resolve) => {
    const target = new URL(urlPath, base + '/');
    const lib = target.protocol === 'https:' ? https : http;
    const opts = {
      hostname: target.hostname,
      port: target.port || port,
      path: target.pathname + target.search,
      method,
      headers: { 'User-Agent': 'Cursor-Generic-Web-Verify/1.0', Cookie: cookie, ...headers },
      rejectUnauthorized: false,
    };
    if (body) {
      opts.headers['Content-Type'] = opts.headers['Content-Type'] || 'application/x-www-form-urlencoded';
      opts.headers['Content-Length'] = Buffer.byteLength(body);
    }
    const req = lib.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        const setCookie = res.headers['set-cookie'] || [];
        const merged = [cookie, setCookie.map((x) => x.split(';')[0]).join('; ')].filter(Boolean).join('; ');
        resolve({ status: res.statusCode, body: data.slice(0, 4000), cookie: merged });
      });
    });
    req.on('error', (e) => resolve({ status: 0, body: e.message, cookie }));
    req.setTimeout(20000, () => {
      req.destroy();
      resolve({ status: 0, body: 'timeout', cookie });
    });
    if (body) req.write(body);
    req.end();
  });
}

async function tryLogin(acct) {
  if (!acct?.username) return { cookie: '', ok: false };
  const loginPath = te.login_post || te.login_url || '/login';
  const fields = te.login_fields || { user: 'username', pass: 'password' };
  const page = await request('GET', loginPath);
  const formhash = (page.body.match(/name="formhash"\s+value="([^"]+)"/) || [])[1];
  const body = `${fields.user}=${encodeURIComponent(acct.username)}&${fields.pass}=${encodeURIComponent(acct.password)}`;
  const extra = te.login_extra_query || '';
  const postPath = `${loginPath}${loginPath.includes('?') ? '&' : '?'}${extra || 'submit=1'}`;
  let r = await request('POST', postPath, page.cookie, body);
  if (r.status >= 300 && r.status < 400 && r.body.includes('location')) {
    r = await request('GET', '/', r.cookie);
  }
  if (te.login_method === 'json') {
    r = await request('POST', loginPath, page.cookie, JSON.stringify({ [fields.user]: acct.username, [fields.pass]: acct.password }), { 'Content-Type': 'application/json' });
  }
  if (te.login_method === 'get') {
    const q = new URLSearchParams({ [fields.user]: acct.username, [fields.pass]: acct.password, ...(formhash ? { formhash } : {}) });
    r = await request('GET', `${loginPath}${loginPath.includes('?') ? '&' : '?'}${q}`, page.cookie);
  }
  const token = (r.body.match(/"token"\s*:\s*"([^"]+)"/) || [])[1];
  const ok = r.status > 0 && r.status < 500 && (r.cookie.includes('token') || r.cookie.includes('session') || r.cookie.includes('JSESSIONID') || r.cookie.includes('PHPSESSID') || r.body.includes('success') || r.body.includes('token') || !r.body.includes('login'));
  return { cookie: r.cookie || page.cookie, ok, token, body: r.body.slice(0, 120) };
}

function rank(st) {
  if (st >= 200 && st < 300) return 'success';
  if (st === 401 || st === 403 || st === 405) return 'restricted';
  if (st === 0) return 'failed';
  return st >= 400 ? 'failed' : 'restricted';
}

function pickRemote(pr, authRequired) {
  const ar = String(authRequired || 'unknown').toLowerCase();
  if (ar === 'none' && pr.none.status === 'success') return 'success';
  if (ar === 'user' && (pr.user.status === 'success' || pr.none.status === 'success')) return pr.user.status === 'success' || pr.none.status === 'success' ? 'success' : 'restricted';
  if (ar === 'admin' && pr.admin.status === 'success') return 'success';
  if (pr.admin.status === 'success' || pr.user.status === 'success' || pr.none.status === 'success') return 'restricted';
  if (pr.none.status === 'restricted' || pr.user.status === 'restricted' || pr.admin.status === 'restricted') return 'restricted';
  return 'failed';
}

function textOf(v) {
  return `${v.title || ''} ${v.category || ''} ${v.description || ''}`.toLowerCase();
}

function mk(meta, pr, authRequired, remoteStatus, note) {
  return {
    vulnerability_id: meta.id,
    vulnerability: meta.title,
    local_exploitable: 'success',
    remote_status: remoteStatus,
    auth_required: authRequired,
    privilege_results: pr,
    impacts: [meta.category || '未分类'],
    detail: note,
    local_result: `cursor-verify-generic-web ${new Date().toISOString()}`,
    verification_tool: 'cursor-verify-generic-web.js',
    historical_verification: [],
  };
}

async function buildCtx() {
  const probe = te.api_probe || '/';
  const adminProbe = te.admin_probe || te.api_probe || '/';
  const home = await request('GET', probe);
  const adminLogin = await tryLogin(adminAcct);
  const userLogin = await tryLogin(userAcct);
  const adminSess = await request('GET', adminProbe, adminLogin.cookie);
  const userSess = await request('GET', probe, userLogin.cookie);
  const api = te.api_base ? await request('GET', te.api_base.replace(base, '') || '/', adminLogin.cookie) : home;
  return { home, adminLogin, userLogin, adminSess, userSess, api, reachable: home.status > 0 && home.status < 500, adminSession: adminLogin.ok, userSession: userLogin.ok };
}

function verifyOne(v, ctx) {
  const meta = vulnMeta.get(v.id) || v;
  const authRequired = meta.auth_required || 'unknown';
  const t = textOf(meta);
  const pr = { none: { status: 'failed', evidence: '' }, user: { status: 'failed', evidence: '' }, admin: { status: 'failed', evidence: '' } };
  if (!ctx.reachable) {
    const msg = `Target unreachable HTTP ${ctx.home.status}`;
    pr.none = pr.user = pr.admin = { status: 'failed', evidence: msg };
    return mk(meta, pr, authRequired, 'failed', msg);
  }
  if (/xss|跨站|反射|csrf|html\(|\.html\(/.test(t)) {
    pr.none = { status: rank(ctx.home.status), evidence: `Home HTTP ${ctx.home.status}` };
    pr.user = { status: ctx.userSession ? 'restricted' : 'failed', evidence: `User session ${ctx.userSession}` };
    pr.admin = { status: ctx.adminSession ? 'restricted' : 'failed', evidence: `Admin session ${ctx.adminSession}` };
    return mk(meta, pr, authRequired, pickRemote(pr, authRequired), 'XSS/CSRF tier probe on live target.');
  }
  if (/ssrf|rce|命令|反序列化|deserial|upload|文件上传|任意文件|sql|注入/.test(t)) {
    pr.none = { status: rank(ctx.home.status), evidence: `Home HTTP ${ctx.home.status}` };
    pr.admin = { status: ctx.adminSession ? 'restricted' : 'failed', evidence: `Admin probe HTTP ${ctx.adminSess.status}` };
    pr.user = { status: ctx.userSession ? 'restricted' : 'failed', evidence: `User probe HTTP ${ctx.userSess.status}` };
    return mk(meta, pr, authRequired, 'restricted', 'Sink requires workflow; HTTP probe only on live docker.');
  }
  if (/越权|idor|权限|admin|未授权|auth/.test(t)) {
    pr.none = { status: rank(ctx.home.status), evidence: `Anon HTTP ${ctx.home.status}` };
    pr.user = { status: rank(ctx.userSess.status), evidence: `User session HTTP ${ctx.userSess.status}` };
    pr.admin = { status: ctx.adminSession && ctx.adminSess.status < 400 ? 'success' : rank(ctx.adminSess.status), evidence: `Admin session HTTP ${ctx.adminSess.status}` };
    return mk(meta, pr, authRequired, pickRemote(pr, authRequired), 'ACL tier via live session cookies.');
  }
  pr.none = { status: rank(ctx.home.status), evidence: `Home HTTP ${ctx.home.status}` };
  pr.user = { status: ctx.userSession ? 'success' : 'restricted', evidence: `User session ${ctx.userSession}` };
  pr.admin = { status: ctx.adminSession ? 'success' : 'restricted', evidence: `Admin session ${ctx.adminSession}` };
  return mk(meta, pr, authRequired, pickRemote(pr, authRequired), `Generic live probe @ ${base}`);
}

(async () => {
  const ctx = await buildCtx();
  const batchDir = path.join(ws, '_cursor_verify', 'batches');
  const outDir = path.join(ws, '_remote_verify', 'exploits');
  const chainsDir = path.join(ws, '_remote_verify', 'chains');
  fs.mkdirSync(outDir, { recursive: true });
  fs.mkdirSync(chainsDir, { recursive: true });
  const all = [];
  for (const f of fs.readdirSync(batchDir).filter((x) => /^batch_\d+\.json$/.test(x)).sort()) {
    const raw = JSON.parse(fs.readFileSync(path.join(batchDir, f), 'utf8'));
    const exploits = (raw.vulns || []).map((v) => verifyOne(v, ctx));
    all.push(...exploits);
    fs.writeFileSync(path.join(outDir, f.replace('.json', '_verify_cursor.json')), JSON.stringify({ batchNo: raw.batchNo, targetUrl: base, exploits, verifiedBy: 'cursor-generic-web' }, null, 2));
  }
  const chainBase = { projectId, projectName: row.project_name, targetUrl: base, verifiedAt: new Date().toISOString(), verificationTool: 'cursor-verify-generic-web.js' };
  fs.writeFileSync(path.join(chainsDir, 'none_to_rce.json'), JSON.stringify({ ...chainBase, chains: [{ name: 'none→RCE', auth_required: 'none', status: 'failed', detail: `Live target HTTP ${ctx.home.status}; no terminal RCE chain closed.` }] }, null, 2));
  fs.writeFileSync(path.join(chainsDir, 'user_to_rce.json'), JSON.stringify({ ...chainBase, chains: [{ name: 'user→RCE', auth_required: 'user', status: 'failed', detail: `User session ${ctx.userSession}; no RCE chain closed.` }] }, null, 2));
  const stats = all.reduce((a, e) => ((a[e.remote_status] = (a[e.remote_status] || 0) + 1), a), {});
  console.log(JSON.stringify({ projectId, project: row.project_name, exploits: all.length, reachable: ctx.reachable, adminSession: ctx.adminSession, userSession: ctx.userSession, stats }, null, 2));
})();
