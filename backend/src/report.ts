import db from './db';
import type { Project, Vulnerability, Severity } from './types';
import { deriveRemoteStatus } from './verificationStatus';

const SEV_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '提示',
};

const SEV_COLOR: Record<Severity, string> = {
  critical: '#c64545',
  high: '#cc785c',
  medium: '#d4a017',
  low: '#5db8a6',
  info: '#8e8b82',
};

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function esc(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtTime(ts: number | null): string {
  if (!ts) return '—';
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(
    d.getMinutes()
  )}`;
}

function donutChart(counts: Record<Severity, number>, total: number): string {
  if (total === 0) {
    return '<div class="empty">本次审计未发现漏洞</div>';
  }
  const r = 70;
  const cx = 90;
  const cy = 90;
  const circumference = 2 * Math.PI * r;
  let offset = 0;
  const segments = SEV_ORDER.filter((s) => counts[s] > 0)
    .map((s) => {
      const frac = counts[s] / total;
      const len = frac * circumference;
      const seg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${SEV_COLOR[s]}" stroke-width="28" stroke-dasharray="${len} ${circumference - len}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})"></circle>`;
      offset += len;
      return seg;
    })
    .join('');
  return `<svg width="180" height="180" viewBox="0 0 180 180">${segments}
    <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-size="32" font-weight="600" fill="#141413">${total}</text>
    <text x="${cx}" y="${cy + 20}" text-anchor="middle" font-size="13" fill="#6c6a64">漏洞总数</text>
  </svg>`;
}

function categoryBars(vulns: Vulnerability[]): string {
  const map = new Map<string, number>();
  for (const v of vulns) {
    const key = v.category || '其他';
    map.set(key, (map.get(key) || 0) + 1);
  }
  const entries = [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (entries.length === 0) return '<div class="empty">暂无分类数据</div>';
  const max = Math.max(...entries.map((e) => e[1]));
  return `<div class="bars">${entries
    .map(
      ([cat, n]) => `<div class="bar-row">
        <span class="bar-label">${esc(cat)}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${(n / max) * 100}%"></span></span>
        <span class="bar-value">${n}</span>
      </div>`
    )
    .join('')}</div>`;
}

const EXPLOIT_STATUS: Record<string, { text: string; color: string }> = {
  success: { text: '远程利用成功', color: '#c64545' },
  failed: { text: '远程验证失败', color: '#8e8b82' },
  restricted: { text: '源码确认 · 远程受限', color: '#d4a017' },
  unknown: { text: '待验证', color: '#8e8b82' },
};

function buildExploitSection(reportJson: string | null): string {
  if (!reportJson) return '';
  let report: any;
  try {
    report = JSON.parse(reportJson);
  } catch {
    return '';
  }
  const exploits: any[] = Array.isArray(report?.exploits) ? report.exploits : [];
  if (exploits.length === 0) return '';

  const cards = exploits
    .map((ex) => {
      const st = EXPLOIT_STATUS[deriveRemoteStatus(ex)] || EXPLOIT_STATUS.unknown;
      const versions: any[] = Array.isArray(ex.exploitable_versions)
        ? ex.exploitable_versions
        : [];
      const versionRows = versions
        .map(
          (v) => `<div class="ver-row">
            <span class="ver-tag">${esc(v.version)}</span>
            ${v.github_url ? `<a href="${esc(v.github_url)}">${esc(v.github_url)}</a>` : ''}
            ${v.note ? `<span class="ver-note">${esc(v.note)}</span>` : ''}
          </div>`
        )
        .join('');
      return `<section class="exp-card">
        <div class="exp-head">
          <span class="exp-badge" style="background:${st.color}">${st.text}</span>
          <h3 class="exp-title">${esc(ex.vulnerability)}</h3>
        </div>
        ${ex.local_result ? `<div class="vuln-block"><h4>验证过程与证据</h4><p>${esc(ex.local_result)}</p></div>` : ''}
        ${ex.detail ? `<div class="vuln-block"><h4>利用链细节</h4><p>${esc(ex.detail)}</p></div>` : ''}
        ${versionRows ? `<div class="vuln-block"><h4>可成功利用的历史版本</h4><div class="ver-list">${versionRows}</div></div>` : ''}
      </section>`;
    })
    .join('');

  const chains: any[] = Array.isArray(report?.chains) ? report.chains : [];
  const chainCards = chains
    .map((c) => {
      const st = EXPLOIT_STATUS[c.status || 'success'] || EXPLOIT_STATUS.success;
      const steps: any[] = Array.isArray(c.steps) ? c.steps : [];
      const versions: any[] = Array.isArray(c.exploitable_versions) ? c.exploitable_versions : [];
      const stepList = steps
        .map(
          (s) =>
            `<li>${s.vulnerability ? `<strong>${esc(s.vulnerability)}</strong> ` : ''}${esc(
              s.description || ''
            )}</li>`
        )
        .join('');
      const versionRows = versions
        .map(
          (v) => `<div class="ver-row"><span class="ver-tag">${esc(v.version)}</span>${
            v.github_url ? `<a href="${esc(v.github_url)}">${esc(v.github_url)}</a>` : ''
          }${v.note ? `<span class="ver-note">${esc(v.note)}</span>` : ''}</div>`
        )
        .join('');
      return `<section class="exp-card">
        <div class="exp-head">
          <span class="exp-badge" style="background:${st.color}">${st.text}</span>
          <h3 class="exp-title">${esc(c.name)}</h3>
        </div>
        ${c.impact ? `<div class="vuln-block"><h4>最终危害</h4><p>${esc(c.impact)}</p></div>` : ''}
        ${stepList ? `<div class="vuln-block"><h4>利用链步骤</h4><ol>${stepList}</ol></div>` : ''}
        ${c.detail ? `<div class="vuln-block"><h4>技术细节</h4><p>${esc(c.detail)}</p></div>` : ''}
        ${versionRows ? `<div class="vuln-block"><h4>可成功利用的历史版本</h4><div class="ver-list">${versionRows}</div></div>` : ''}
      </section>`;
    })
    .join('');

  return `<h2>利用链验证</h2>
    ${report.summary ? `<div class="exp-summary">${esc(report.summary)}</div>` : ''}
    ${chainCards ? `<h3 class="exp-subtitle">组合利用链（多漏洞串联）</h3>${chainCards}` : ''}
    ${cards ? `<h3 class="exp-subtitle">单个漏洞利用</h3>${cards}` : ''}`;
}

export function generateReport(projectId: string): string | null {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId) as
    | Project
    | undefined;
  if (!project) return null;

  const vulns = db
    .prepare('SELECT * FROM vulnerabilities WHERE project_id = ? ORDER BY CASE severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 ELSE 4 END')
    .all(projectId) as Vulnerability[];

  const counts: Record<Severity, number> = {
    critical: project.count_critical,
    high: project.count_high,
    medium: project.count_medium,
    low: project.count_low,
    info: project.count_info,
  };
  const total = vulns.length;

  const sourceLabel =
    project.source_type === 'github'
      ? `GitHub 仓库 ${esc(project.source_ref)}`
      : `${project.source_type.toUpperCase()} 压缩包`;

  const summaryCards = SEV_ORDER.map(
    (s) => `<div class="sev-card" style="border-top:3px solid ${SEV_COLOR[s]}">
      <div class="sev-num">${counts[s]}</div>
      <div class="sev-name">${SEV_LABEL[s]}</div>
    </div>`
  ).join('');

  const vulnSections = vulns
    .map((v, i) => {
      const sev = v.severity as Severity;
      return `<section class="vuln" id="vuln-${i + 1}">
      <div class="vuln-head">
        <span class="vuln-index">#${i + 1}</span>
        <span class="vuln-badge" style="background:${SEV_COLOR[sev]}">${SEV_LABEL[sev]}</span>
        <h3 class="vuln-title">${esc(v.title)}</h3>
      </div>
      <div class="vuln-meta">
        ${v.category ? `<span>类别：${esc(v.category)}</span>` : ''}
        ${v.file_path ? `<span>位置：${esc(v.file_path)}${v.line ? `:${v.line}` : ''}</span>` : ''}
      </div>
      ${v.description ? `<div class="vuln-block"><h4>问题描述</h4><p>${esc(v.description)}</p></div>` : ''}
      ${v.taint_chain ? `<div class="vuln-block"><h4>污点链（Source→Sink）</h4><pre>${esc(v.taint_chain)}</pre></div>` : ''}
      ${v.code_snippet ? `<div class="vuln-block"><h4>相关代码</h4><pre>${esc(v.code_snippet)}</pre></div>` : ''}
      ${v.recommendation ? `<div class="vuln-block"><h4>修复建议</h4><p>${esc(v.recommendation)}</p></div>` : ''}
    </section>`;
    })
    .join('');

  const exploitSection = buildExploitSection(project.exploit_report);

  const tocRows = vulns
    .map(
      (v, i) =>
        `<li><a href="#vuln-${i + 1}"><span class="toc-dot" style="background:${SEV_COLOR[v.severity as Severity]}"></span>${esc(v.title)}</a></li>`
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>代码审计报告 - ${esc(project.project_name)}</title>
<style>
  :root{ --canvas:#faf9f5; --ink:#141413; --body:#3d3d3a; --muted:#6c6a64; --primary:#cc785c; --card:#efe9de; --hairline:#e6dfd8; --dark:#181715; --surface-soft:#f5f0e8; --surface-cream-strong:#e8e0d2; }
  *{ box-sizing:border-box; }
  body{ margin:0; background:var(--canvas); color:var(--body); font-family:"PingFang SC","Microsoft YaHei",Inter,-apple-system,sans-serif; line-height:1.6; }
  .wrap{ max-width:960px; margin:0 auto; padding:48px 32px 96px; }
  header.report-head{ border-bottom:1px solid var(--hairline); padding-bottom:32px; margin-bottom:40px; }
  .brand{ display:flex; align-items:center; gap:10px; color:var(--primary); font-weight:600; letter-spacing:1.5px; font-size:12px; text-transform:uppercase; }
  .brand .spark{ width:14px; height:14px; background:var(--primary); clip-path:polygon(50% 0,60% 40%,100% 50%,60% 60%,50% 100%,40% 60%,0 50%,40% 40%); }
  h1{ font-family:"Georgia","Times New Roman",serif; font-weight:400; font-size:40px; letter-spacing:-1px; color:var(--ink); margin:18px 0 6px; }
  .subtitle{ color:var(--muted); font-size:15px; }
  .meta-grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-top:24px; }
  .meta-item{ font-size:14px; }
  .meta-item .k{ color:var(--muted); font-size:12px; }
  .meta-item .v{ color:var(--ink); font-weight:500; word-break:break-all; }
  h2{ font-family:"Georgia",serif; font-weight:400; font-size:26px; color:var(--ink); letter-spacing:-0.4px; margin:48px 0 20px; }
  .overview{ display:flex; gap:32px; align-items:center; flex-wrap:wrap; background:var(--card); border-radius:12px; padding:32px; }
  .sev-cards{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; flex:1; min-width:280px; }
  .sev-card{ background:var(--canvas); border-radius:8px; padding:16px 8px; text-align:center; }
  .sev-num{ font-size:28px; font-weight:600; color:var(--ink); }
  .sev-name{ font-size:13px; color:var(--muted); margin-top:4px; }
  .empty{ color:var(--muted); padding:24px; }
  .bars{ display:flex; flex-direction:column; gap:12px; }
  .bar-row{ display:flex; align-items:center; gap:12px; font-size:14px; }
  .bar-label{ width:140px; color:var(--ink); }
  .bar-track{ flex:1; height:10px; background:var(--hairline); border-radius:9999px; overflow:hidden; }
  .bar-fill{ display:block; height:100%; background:var(--primary); border-radius:9999px; }
  .bar-value{ width:32px; text-align:right; color:var(--muted); }
  .toc{ background:var(--card); border-radius:12px; padding:24px 32px; }
  .toc ul{ list-style:none; margin:0; padding:0; columns:2; }
  .toc li{ margin:6px 0; break-inside:avoid; }
  .toc a{ color:var(--body); text-decoration:none; font-size:14px; display:flex; align-items:center; gap:8px; }
  .toc a:hover{ color:var(--primary); }
  .toc-dot{ width:8px; height:8px; border-radius:50%; flex:none; }
  .vuln{ border:1px solid var(--hairline); border-radius:12px; padding:28px; margin-bottom:20px; background:#fff; }
  .vuln-head{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  .vuln-index{ color:var(--muted); font-weight:600; }
  .vuln-badge{ color:#fff; font-size:12px; font-weight:600; padding:3px 12px; border-radius:9999px; }
  .vuln-title{ font-size:19px; color:var(--ink); margin:0; font-weight:600; flex:1; min-width:200px; }
  .vuln-meta{ display:flex; gap:20px; flex-wrap:wrap; color:var(--muted); font-size:13px; margin:12px 0 4px; }
  .vuln-block{ margin-top:16px; }
  .vuln-block h4{ font-size:13px; color:var(--primary); margin:0 0 6px; font-weight:600; }
  .vuln-block p{ margin:0; color:var(--body); }
  .vuln-block pre{ background:var(--dark); color:#e6e0d8; padding:16px; border-radius:8px; overflow-x:auto; font-family:"JetBrains Mono",Consolas,monospace; font-size:13px; line-height:1.6; }
  .exp-subtitle{ font-family:"PingFang SC","Microsoft YaHei",sans-serif; font-size:16px; font-weight:600; color:var(--ink); margin:24px 0 12px; }
  .exp-summary{ background:var(--card); border-radius:8px; padding:16px 18px; margin-bottom:16px; line-height:1.7; }
  .exp-card{ border:1px solid var(--hairline); border-radius:12px; padding:24px; margin-bottom:16px; background:#fff; }
  .exp-head{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  .exp-badge{ color:#fff; font-size:12px; font-weight:600; padding:3px 12px; border-radius:9999px; }
  .exp-title{ font-size:17px; color:var(--ink); margin:0; }
  .ver-list{ display:flex; flex-direction:column; gap:8px; }
  .ver-row{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; padding:8px 10px; background:var(--surface-soft); border-radius:8px; }
  .ver-tag{ font-family:"JetBrains Mono",Consolas,monospace; font-size:12px; font-weight:600; color:var(--ink); background:var(--surface-cream-strong); padding:2px 8px; border-radius:6px; }
  .ver-row a{ color:var(--primary); font-size:13px; word-break:break-all; }
  .ver-note{ color:var(--muted); font-size:12px; }
  footer{ margin-top:48px; padding-top:24px; border-top:1px solid var(--hairline); color:var(--muted); font-size:13px; text-align:center; }
</style>
</head>
<body>
  <div class="wrap">
    <header class="report-head">
      <div class="brand"><span class="spark"></span>CODE 代码审计</div>
      <h1>${esc(project.project_name)} 安全审计报告</h1>
      <div class="subtitle">压缩包/来源：${esc(project.archive_name)}</div>
      <div class="meta-grid">
        <div class="meta-item"><div class="k">审计来源</div><div class="v">${sourceLabel}</div></div>
        <div class="meta-item"><div class="k">开始时间</div><div class="v">${fmtTime(project.started_at)}</div></div>
        <div class="meta-item"><div class="k">完成时间</div><div class="v">${fmtTime(project.finished_at)}</div></div>
        <div class="meta-item"><div class="k">漏洞总数</div><div class="v">${total}</div></div>
      </div>
    </header>

    <h2>漏洞概览</h2>
    <div class="overview">
      <div>${donutChart(counts, total)}</div>
      <div class="sev-cards">${summaryCards}</div>
    </div>

    <h2>漏洞类别分布</h2>
    ${categoryBars(vulns)}

    ${total > 0 ? `<h2>漏洞索引</h2><div class="toc"><ul>${tocRows}</ul></div>` : ''}

    ${total > 0 ? `<h2>漏洞详情</h2>${vulnSections}` : ''}

    ${exploitSection}

    <footer>本报告由 Code 基于本地 Pi 多智能体审计自动生成 · 生成时间 ${fmtTime(Date.now())}</footer>
  </div>
</body>
</html>`;
}
