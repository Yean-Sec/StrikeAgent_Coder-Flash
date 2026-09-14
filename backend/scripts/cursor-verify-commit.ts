/**
 * Cursor 会话验证结果回写：合并 _remote_verify/exploits/*.json → exploit_report + DB 状态
 * 用法: npx tsx scripts/cursor-verify-commit.ts <projectId>
 */
import db from '../src/db';
import fs from 'fs';
import path from 'path';
import { syncVerifiedFlags, syncFrontendRce, syncVerifyStatusFromCoverage } from '../src/runner';
import { syncExploitChains } from '../src/exploitChains';
import { filterComboChainsForPolicy } from '../src/chainRceFilter';
import { syncProjectVerificationItems } from '../src/verificationStore';

const partial = process.argv.includes('--partial');
const projectId = process.argv.slice(2).find((a) => !a.startsWith('-'));
if (!projectId) {
  console.error('Usage: npx tsx scripts/cursor-verify-commit.ts <projectId> [--partial]');
  process.exit(1);
}

const row = db.prepare('SELECT workspace_path, project_name FROM projects WHERE id = ?').get(projectId) as
  | { workspace_path: string | null; project_name: string }
  | undefined;
if (!row?.workspace_path) {
  console.error('Project not found or no workspace');
  process.exit(1);
}

const codeDir = row.workspace_path;
const exploitDir = path.join(codeDir, '_remote_verify', 'exploits');

function normTitle(s: string): string {
  return String(s || '')
    .toLowerCase()
    .replace(/\s+/g, '')
    .replace(/[^\p{L}\p{N}]/gu, '');
}

function readAllExploitFiles(): any[] {
  if (!fs.existsSync(exploitDir)) return [];
  const exploits: any[] = [];
  const files = fs.readdirSync(exploitDir).filter((f) => f.endsWith('.json'));
  files.sort((a, b) => {
    const pa = a.includes('batch_pending') || a.includes('pending_gap') ? 1 : 0;
    const pb = b.includes('batch_pending') || b.includes('pending_gap') ? 1 : 0;
    if (pa !== pb) return pa - pb;
    return a.localeCompare(b);
  });
  for (const f of files) {
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(exploitDir, f), 'utf8'));
      const list = Array.isArray(raw?.exploits)
        ? raw.exploits
        : Array.isArray(raw?.results)
          ? raw.results
        : Array.isArray(raw)
          ? raw
          : raw?.vulnerability || raw?.vulnerability_id
            ? [raw]
            : [];
      for (const e of list) {
        if (e && typeof e === 'object') {
          if (!e.vulnerability_id && e.vuln_id) e.vulnerability_id = e.vuln_id;
          if (!e.vulnerability_id && e.id) e.vulnerability_id = e.id;
        }
        exploits.push(e);
      }
    } catch {
      /* skip */
    }
  }
  return exploits;
}

function isDupRemediationEntry(e: any): boolean {
  const blob = [e.vulnerability, e.detail, e.local_result].join(' ');
  return /去重|修复建议|duplicate|非独立|跟随主项|同源\s*AI|remediation/i.test(blob);
}

function exploitRank(x: any): number {
  const remote = String(x.remote_status ?? '').toLowerCase().trim();
  if (x._gap_close) {
    // Orchestrator gap stubs must not override subagent / batch verify conclusions.
    if (remote === 'success') return 4;
    if (remote === 'restricted') return 3;
    return 1;
  }
  if (isDupRemediationEntry(x) && remote === 'failed') return 5;
  if (remote === 'success') return 4;
  if (remote === 'restricted') return 3;
  if (remote === 'failed') return 2;
  if (remote === 'skipped' || remote === 'unknown') return 0;
  if (x.local_exploitable === 'success' || x.remote_status === 'success') return 3;
  if (x.remote_status === 'restricted' || x.local_exploitable === 'restricted') return 2;
  if (x.remote_status === 'failed') return 1;
  return 0;
}

/** Prefer vulnerability_id; fall back to normalized title for legacy rows. */
function mergeExploits(items: any[]): any[] {
  const map = new Map<string, any>();
  for (const e of items) {
    const vid = String(e.vulnerability_id ?? e.id ?? '').trim();
    const key = vid || normTitle(e.vulnerability || e.name || '');
    if (!key) continue;
    const prev = map.get(key);
    if (!prev || exploitRank(e) > exploitRank(prev)) map.set(key, e);
  }
  return [...map.values()];
}

const exploits = mergeExploits(readAllExploitFiles());
const chainsDir = path.join(codeDir, '_remote_verify', 'chains');
let chains: any[] = [];
if (fs.existsSync(chainsDir)) {
  for (const f of fs.readdirSync(chainsDir)) {
    if (!f.endsWith('.json')) continue;
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(chainsDir, f), 'utf8'));
      if (Array.isArray(raw?.chains)) chains.push(...raw.chains);
      else if (raw?.name || raw?.chain_name || raw?.chain) chains.push(raw);
    } catch {
      /* skip */
    }
  }
}

chains = filterComboChainsForPolicy(chains) as any[];

const report = {
  summary: `Cursor 会话远程验证完成（${exploits.length} 条单漏洞结论，${chains.length} 条组合链）`,
  exploits,
  chains,
};
const serialized = JSON.stringify(report);

const tx = db.transaction(() => {
  db.prepare('UPDATE projects SET exploit_report = ? WHERE id = ?').run(serialized, projectId);
  syncExploitChains(projectId, report, serialized);
});
tx();

syncProjectVerificationItems(projectId, exploits, 'exploit-report');
syncVerifiedFlags(projectId);
syncFrontendRce(projectId);

const success = exploits.filter((e) => e.local_exploitable === 'success' || e.remote_status === 'success').length;
if (!partial) {
  syncVerifyStatusFromCoverage(projectId);
} else {
  // Cursor 会话 partial 回写：只同步 exploit_report/DB，不把项目标成「靶机验证中」(verify_status=running)
  db.prepare(`UPDATE projects SET verify_error=NULL, env_status='ready' WHERE id=?`).run(projectId);
}

const statusRow = db.prepare('SELECT verify_status FROM projects WHERE id=?').get(projectId) as
  | { verify_status: string }
  | undefined;

console.log(
  JSON.stringify(
    {
      projectId,
      project_name: row.project_name,
      totalExploits: exploits.length,
      remoteSuccess: success,
      chains: chains.length,
      verify_status: partial ? statusRow?.verify_status ?? 'unchanged' : 'completed',
    },
    null,
    2
  )
);
