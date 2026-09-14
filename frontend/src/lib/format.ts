import type { ProjectStatus, Severity, VerifyStatus } from './types';

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '提示',
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** 实战等级标签（五级）：与 severity 严格同义，仅 info 在实战语境下显示为「无」。 */
export const REALTEAM_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '无',
};

/** 由 severity 推导实战等级标签（regrade_value 缺失时的兜底：实战轴 = 二次评级后的 severity）。 */
export function realTeamLabel(sev: Severity): string {
  return REALTEAM_LABEL[sev] || '无';
}

export const STATUS_LABEL: Record<ProjectStatus, string> = {
  pending: '待开始',
  queued: '排队中',
  running: '审计中',
  paused: '已暂停',
  completed: '已完成',
  failed: '失败',
};

export const STATUS_COLOR: Record<ProjectStatus, string> = {
  pending: 'var(--muted)',
  queued: 'var(--accent-amber)',
  running: 'var(--accent-teal)',
  paused: 'var(--warning)',
  completed: 'var(--success)',
  failed: 'var(--error)',
};

/**
 * 综合审计阶段与靶机验证阶段，给出贯穿全流程的状态文案与颜色。
 * 审计未完成时展示审计阶段；审计完成后展示验证阶段。
 */
export function phaseStatus(
  status: ProjectStatus,
  verify: VerifyStatus
): { label: string; color: string } {
  if (status === 'completed') {
    switch (verify) {
      case 'none':
        return { label: '审计完成', color: 'var(--primary)' };
      case 'queued':
        return { label: '验证排队中', color: 'var(--accent-amber)' };
      case 'running':
        return { label: '靶机验证中', color: 'var(--accent-teal)' };
      case 'paused':
        return { label: '验证已暂停', color: 'var(--warning)' };
      case 'completed':
        return { label: '全部完成', color: 'var(--success)' };
      case 'failed':
        return { label: '验证失败', color: 'var(--error)' };
    }
  }
  switch (status) {
    case 'pending':
      return { label: '待开始', color: 'var(--muted)' };
    case 'queued':
      return { label: '审计排队中', color: 'var(--accent-amber)' };
    case 'running':
      return { label: '代码审计中', color: 'var(--accent-teal)' };
    case 'paused':
      return { label: '审计已暂停', color: 'var(--warning)' };
    case 'failed':
      return { label: '审计失败', color: 'var(--error)' };
  }
  return { label: '未知', color: 'var(--muted)' };
}

export function fmtTime(ts: number | null): string {
  if (!ts) return '—';
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(
    d.getMinutes()
  )}:${p(d.getSeconds())}`;
}

/** 年月日时分：YYYY-MM-DD HH:mm（null 返回 —）。 */
export function fmtDateMinute(ts: number | null | undefined): string {
  if (!ts) return '—';
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(
    d.getMinutes()
  )}`;
}

export function fmtRelative(ts: number | null): string {
  if (!ts) return '—';
  const diff = Date.now() - ts;
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s} 秒前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分钟前`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时前`;
  return `${Math.floor(h / 24)} 天前`;
}

/** 把毫秒耗时格式化为人类可读（如 1h2m / 3m20s / 45s），0 或无效返回 —。 */
export function fmtDuration(ms: number | null | undefined): string {
  if (!ms || ms <= 0) return '—';
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h${m}m`;
  if (m > 0) return `${m}m${sec}s`;
  return `${sec}s`;
}

export function totalVulns(p: {
  count_critical: number;
  count_high: number;
  count_medium: number;
  count_low: number;
  count_info: number;
}): number {
  return p.count_critical + p.count_high + p.count_medium + p.count_low + p.count_info;
}

/** 将漏洞标题转为安全的本地下载文件名（保留中文，去掉 Windows 非法字符）。 */
export function safeDownloadFilename(title: string, ext = 'md'): string {
  const stem = String(title || 'vuln-report')
    .replace(/[\\/:*?"<>|]/g, '_')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
  const base = stem || 'vuln-report';
  const suffix = ext.replace(/^\./, '');
  return `${base}.${suffix}`;
}
