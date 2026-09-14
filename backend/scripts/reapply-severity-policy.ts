/**
 * 对库内 high/critical 漏洞重跑 applySeverityPolicy，将命中低价值规则的条目封顶为 low/info，并刷新项目计数。
 * 用法：npx tsx scripts/reapply-severity-policy.ts
 */
import Database from 'better-sqlite3';
import path from 'path';
import { applySeverityPolicy, realTeamLabel } from '../src/severityPolicy';

const dbPath = path.join(__dirname, '..', 'data', 'code.db');
const db = new Database(dbPath);

const rows = db
  .prepare(
    `SELECT id, project_id, title, category, description, recommendation, code_snippet,
            taint_chain, auth_required, severity, severity_original, regrade_reason
     FROM vulnerabilities
     WHERE severity IN ('critical', 'high')`
  )
  .all() as any[];

console.log(`scanning high/critical: ${rows.length}`);

const upd = db.prepare(
  `UPDATE vulnerabilities
   SET severity = @severity,
       severity_original = COALESCE(severity_original, @orig),
       regrade_value = @regrade_value,
       regrade_reason = @regrade_reason
   WHERE id = @id`
);

const byRule = new Map<string, number>();
let changed = 0;
const sample: { id: string; title: string; from: string; to: string; rule: string }[] = [];

const tx = db.transaction(() => {
  for (const r of rows) {
    const policy = applySeverityPolicy({
      title: r.title,
      category: r.category,
      description: r.description,
      recommendation: r.recommendation,
      code_snippet: r.code_snippet,
      taint_chain: r.taint_chain,
      auth_required: r.auth_required,
      severity: r.severity,
      severity_original: r.severity_original,
      regrade_reason: r.regrade_reason,
    });
    if (!policy.changed) continue;
    changed++;
    byRule.set(policy.ruleId || '?', (byRule.get(policy.ruleId || '?') || 0) + 1);
    if (sample.length < 30) {
      sample.push({
        id: r.id,
        title: String(r.title || '').slice(0, 90),
        from: r.severity,
        to: policy.severity,
        rule: policy.ruleId || '',
      });
    }
    upd.run({
      id: r.id,
      severity: policy.severity,
      orig: policy.severityOriginal || r.severity,
      regrade_value: realTeamLabel(policy.severity),
      regrade_reason: policy.regradeReason,
    });
  }
});
tx();

console.log(`changed=${changed}`);
console.log('byRule', Object.fromEntries(byRule));
console.log('samples:');
for (const s of sample) console.log(`  [${s.rule}] ${s.from}->${s.to} ${s.title}`);

const projects = db.prepare(`SELECT DISTINCT project_id FROM vulnerabilities`).all() as { project_id: string }[];
const countStmt = db.prepare(
  `SELECT
     SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS c,
     SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) AS h,
     SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) AS m,
     SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) AS l,
     SUM(CASE WHEN severity='info' THEN 1 ELSE 0 END) AS i
   FROM vulnerabilities WHERE project_id=?`
);
const setCounts = db.prepare(
  `UPDATE projects SET count_critical=@c, count_high=@h, count_medium=@m, count_low=@l, count_info=@i WHERE id=@id`
);
const recount = db.transaction(() => {
  for (const p of projects) {
    const n = countStmt.get(p.project_id) as any;
    setCounts.run({
      id: p.project_id,
      c: n.c || 0,
      h: n.h || 0,
      m: n.m || 0,
      l: n.l || 0,
      i: n.i || 0,
    });
  }
});
recount();
console.log(`recounted projects=${projects.length}`);

db.close();
