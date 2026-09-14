import db from './db';
import type { Vulnerability } from './types';
import { deriveRemoteStatus } from './verificationStatus';

const SEV_LABEL: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '提示',
};

const AUTH_LABEL: Record<string, string> = {
  none: '无需登录',
  user: '需登录（普通用户）',
  admin: '需管理员',
};

function norm(s: string): string {
  return String(s || '')
    .replace(/\\([_*`[\]()#+\-.!|{}])/g, '$1')
    .replace(/['"“”‘’]/g, '')
    .replace(/\s+/g, '')
    .toLowerCase();
}

function matchExploit(title: string, reportJson: string | null): any | null {
  if (!reportJson) return null;
  let report: any;
  try {
    report = JSON.parse(reportJson);
  } catch {
    return null;
  }
  const exploits: any[] = Array.isArray(report?.exploits) ? report.exploits : [];
  const nt = norm(title);
  for (const ex of exploits) {
    const en = norm(ex?.vulnerability || '');
    if (!en) continue;
    if (en === nt || en.includes(nt) || nt.includes(en.slice(0, Math.min(en.length, 12)))) return ex;
  }
  return null;
}

function findVuln(projectId: string, title: string) {
  const rows = db
    .prepare(
      `SELECT v.*, p.project_name, p.system_name, p.source_version, p.target_url, p.exploit_report
       FROM vulnerabilities v JOIN projects p ON p.id = v.project_id
       WHERE v.project_id = ?`
    )
    .all(projectId) as (Vulnerability & {
    project_name?: string;
    system_name?: string | null;
    source_version?: string | null;
    target_url?: string | null;
    exploit_report?: string | null;
  })[];
  const nt = norm(title);
  return (
    rows.find((v) => {
      const vt = norm(v.title);
      return vt === nt || vt.includes(nt) || nt.includes(vt);
    }) || null
  );
}

/** 解析项目内漏洞标题（用于下载文件名等）。 */
export function resolveVulnTitle(projectId: string, title: string): string | null {
  return findVuln(projectId, title)?.title ?? null;
}

/** 从 exploit_report 提取单漏洞 POC 文本（验证过程 + 技术细节）。 */
export function buildPocText(projectId: string, title: string): string | null {
  const v = findVuln(projectId, title);
  if (!v) return null;
  const ex = matchExploit(v.title, v.exploit_report ?? null);
  if (!ex || deriveRemoteStatus(ex) !== 'success') return null;
  const lines: string[] = [
    `# POC: ${v.title}`,
    '',
    `项目: ${v.project_name || projectId}`,
    `严重度: ${SEV_LABEL[v.severity] || v.severity}`,
    `定位: ${v.file_path}${v.line ? ':' + v.line : ''}`,
    '',
  ];
  if (ex.auth_required) lines.push(`所需权限: ${AUTH_LABEL[String(ex.auth_required)] || ex.auth_required}`, '');
  if (ex.local_result) {
    lines.push('## 验证过程', String(ex.local_result), '');
  }
  if (ex.detail) {
    lines.push('## 技术细节', String(ex.detail), '');
  }
  if (v.target_url) lines.push(`靶机地址: ${v.target_url}`, '');
  return lines.join('\n').trim();
}

/** 生成单漏洞 Markdown 报告。 */
export function buildVulnMarkdown(projectId: string, title: string): string | null {
  const v = findVuln(projectId, title);
  if (!v) return null;
  const ex = matchExploit(v.title, v.exploit_report ?? null);
  const remoteStatus = ex ? deriveRemoteStatus(ex) : 'unknown';
  const verified = remoteStatus === 'success';
  const lines: string[] = [
    `# ${v.title}`,
    '',
    `- **项目**: ${v.project_name || projectId}`,
    v.system_name ? `- **系统**: ${v.system_name}` : '',
    v.source_version ? `- **版本**: ${v.source_version}` : '',
    `- **严重度**: ${SEV_LABEL[v.severity] || v.severity}`,
    v.regrade_value ? `- **实战等级**: ${v.regrade_value}` : '',
    v.category ? `- **类型**: ${v.category}` : '',
    `- **定位**: \`${v.file_path}${v.line ? ':' + v.line : ''}\``,
    v.auth_required
      ? `- **所需权限**: ${AUTH_LABEL[String(v.auth_required)] || v.auth_required}${v.auth_reason ? ' — ' + v.auth_reason : ''}`
      : ex?.auth_required
        ? `- **验证权限**: ${AUTH_LABEL[String(ex.auth_required)] || ex.auth_required}`
        : '',
    remoteStatus === 'success'
      ? '- **远程验证**: 成功'
      : remoteStatus === 'restricted'
        ? '- **远程验证**: 受限（源码/本地证据存在，但当前靶机未打通）'
        : remoteStatus === 'failed'
          ? '- **远程验证**: 失败'
          : '- **远程验证**: 待验证',
    '',
    '## 漏洞描述',
    '',
    v.description || '（无）',
    '',
  ].filter((l) => l !== '');

  if (v.taint_chain) {
    lines.push('## 污点链', '', v.taint_chain, '');
  }
  if (v.code_snippet) {
    lines.push('## 代码片段', '', '```', v.code_snippet, '```', '');
  }
  if (v.recommendation) {
    lines.push('## 修复建议', '', v.recommendation, '');
  }
  if (ex?.local_result) {
    lines.push('## 远程验证过程', '', String(ex.local_result), '');
  }
  if (ex?.detail) {
    lines.push('## 利用细节', '', String(ex.detail), '');
  }
  const hist = Array.isArray(ex?.historical_verification) ? ex.historical_verification : [];
  const okHist = hist.filter((h: any) => h?.status === 'success');
  if (okHist.length > 0) {
    lines.push('## 历史版本验证', '');
    for (const h of okHist) {
      lines.push(`- **${h.version || '?'}** (${h.status})${h.reason ? ': ' + h.reason : ''}`);
    }
    lines.push('');
  }
  lines.push('---', '', `*生成时间: ${new Date().toISOString()}*`);
  return lines.join('\n');
}
