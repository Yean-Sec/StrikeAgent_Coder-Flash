import axios from 'axios';
import { safeDownloadFilename } from './format';
import type {
  Project,
  Vulnerability,
  VulnRow,
  VulnPage,
  VulnQuery,
  AgentEvent,
  Monitor,
  DashboardData,
  Settings,
  DeletedProject,
  WebClassifyStatus,
  ImportScreenStatus,
  VerificationProgress,
  VerificationItem,
} from './types';

const http = axios.create({ baseURL: '/api', timeout: 30_000 });

// —— 轻量客户端读缓存（stale-while-revalidate，零新依赖）——
// 目的：切页 / 返回时先用上次结果"秒开"，同时后台校验刷新；并对并发相同请求去重
// （含 React.StrictMode 开发期双跑）。任意写请求（非 GET）成功后清空整表，保证增删改后读到最新。
interface ReadCacheRec {
  value: unknown;
  ts: number;
  inflight?: Promise<unknown>;
}
const readCache = new Map<string, ReadCacheRec>();
export function bustClientReadCache(): void {
  readCache.clear();
}
http.interceptors.response.use((resp) => {
  const method = (resp.config.method || 'get').toLowerCase();
  if (method !== 'get') bustClientReadCache();
  return resp;
});
function isAbortError(e: unknown): boolean {
  const err = e as { code?: string; name?: string; message?: string } | null;
  if (!err) return false;
  return (
    err.code === 'ERR_CANCELED' ||
    err.name === 'CanceledError' ||
    err.name === 'AbortError' ||
    /abort|cancel/i.test(String(err.message || ''))
  );
}

/**
 * stale-while-revalidate 读缓存。
 * 重要：带 AbortSignal 的请求【绝不】进入共享 inflight——否则 React StrictMode /
 * reload() 取消上一次请求时，后来者会复用已取消的 Promise，永远拿不到数据，
 * 详情页就会永久停在「正在加载…」骨架（project 为 null 且无 loadError）。
 */
function swrGet<T>(
  key: string,
  ttlMs: number,
  loader: () => Promise<T>,
  opts?: { signal?: AbortSignal }
): Promise<T> {
  const rec = readCache.get(key);
  // 有新鲜缓存时立刻返回（即便带 signal）：切页秒开；signal 只影响重新校验。
  if (rec && rec.ts > 0 && Date.now() - rec.ts < ttlMs) {
    return Promise.resolve(rec.value as T);
  }
  // 带取消信号：独立请求，成功则写缓存，取消则不污染共享 inflight。
  if (opts?.signal) {
    return loader()
      .then((v) => {
        readCache.set(key, { value: v, ts: Date.now() });
        return v;
      })
      .catch((e) => {
        if (isAbortError(e)) throw e;
        if (rec && rec.ts > 0) return rec.value as T;
        throw e;
      });
  }
  if (rec?.inflight) return rec.inflight as Promise<T>;
  const revalidate = (): Promise<T> => {
    const p = loader()
      .then((v) => {
        readCache.set(key, { value: v, ts: Date.now() });
        return v;
      })
      .catch((e) => {
        // 取消不算失败：清掉 inflight，让下一次真正重试；有旧值则回退。
        if (isAbortError(e)) {
          const cur = readCache.get(key);
          if (cur?.inflight === p) cur.inflight = undefined;
          throw e;
        }
        const prev = readCache.get(key);
        if (prev && prev.ts > 0) return prev.value as T;
        readCache.delete(key);
        throw e;
      })
      .finally(() => {
        const cur = readCache.get(key);
        if (cur?.inflight === p) cur.inflight = undefined;
      });
    readCache.set(key, { value: rec?.value, ts: rec?.ts ?? 0, inflight: p });
    return p;
  };
  if (rec && rec.ts > 0) {
    // 陈旧：后台校验刷新缓存，本次先返回旧值实现"秒开"。
    void revalidate();
    return Promise.resolve(rec.value as T);
  }
  return revalidate();
}

/** 新建审计页的"审计流程选项"（逐项目配置；后端缺省项沿用全局默认）。 */
export interface AuditOptions {
  auto_verify: boolean;
  verify_history: boolean;
  ai_dedup: boolean;
  ai_regrade: boolean;
  /** full 完整靶机 / none 仅代码审计。历史值 mini 由后端映射为 full。 */
  verify_runtime?: 'full' | 'none' | 'mini';
}

export interface ProjectListQuery {
  search?: string;
  status?: string;
  page?: number;
  pageSize?: number;
  groupBy?: string;
  includeCounts?: 0 | 1;
}

export interface ProjectListPage {
  items: Project[];
  total: number;
  page: number;
  pageSize: number;
  counts?: Record<string, number>;
}

export interface CompactProjectDetail {
  project: Project;
  vulnerabilities: Vulnerability[];
  vulnerabilityCount: number;
}

export interface RecyclePage {
  items: DeletedProject[];
  total: number;
  page: number;
  pageSize: number;
}

export type GithubAuditScope = 'all' | 'new_projects_only' | 'new_versions_only';

export type GithubDuplicateKind = 'none' | 'project' | 'version' | 'batch';

export interface GithubImportPreview {
  items: {
    index: number;
    url: string;
    projectName?: string;
    owner: string;
    repo: string;
    gitRef: string | null;
    kind: GithubDuplicateKind;
    kindLabel: string;
    existingMatches: {
      projectId: string;
      projectName: string;
      sourceVersion: string | null;
      gitRef: string | null;
      createdAt: number;
    }[];
  }[];
  summary: {
    total: number;
    newProjects: number;
    projectDuplicates: number;
    versionDuplicates: number;
    batchDuplicates: number;
    willAudit: Record<GithubAuditScope, number>;
  };
}

export const api = {
  dashboard: () =>
    swrGet<DashboardData>('dashboard', 5_000, () =>
      http.get<DashboardData>('/dashboard').then((r) => r.data)
    ),

  piHealth: () =>
    http
      .get<{ ok: boolean; path?: string; version?: string; error?: string; stale?: boolean }>(
        '/pi/health',
        { timeout: 8_000 }
      )
      .then((r) => r.data),

  /** 轻量后端存活探针（不跑 pi --version），用于区分「后端卡住」与「Pi 不可用」。 */
  backendHealth: () =>
    http.get<{ ok: boolean; ts?: number }>('/health', { timeout: 5_000 }).then((r) => r.data),

  listProjects: (params: ProjectListQuery) =>
    swrGet<ProjectListPage>(`projects:${JSON.stringify(params)}`, 3_000, () =>
      http.get<ProjectListPage>('/projects', { params }).then((r) => r.data)
    ),

  allVulnerabilities: (params?: VulnQuery) =>
    swrGet<VulnPage>(`vulns:${JSON.stringify(params ?? {})}`, 3_000, () =>
      http.get<VulnPage>('/vulnerabilities', { params }).then((r) => r.data)
    ),

  getProject: (id: string) =>
    http
      .get<{ project: Project; vulnerabilities: Vulnerability[] }>(`/projects/${id}`)
      .then((r) => r.data),

  getProjectCompact: (id: string, signal?: AbortSignal) =>
    swrGet<CompactProjectDetail>(
      `compact:${id}`,
      3_000,
      () =>
        http
          .get<CompactProjectDetail>(`/projects/${id}`, { params: { mode: 'compact' }, signal })
          .then((r) => r.data),
      { signal }
    ),

  getProjectSummary: (id: string) =>
    http
      .get<CompactProjectDetail>(`/projects/${id}`, { params: { mode: 'summary' } })
      .then((r) => r.data),

  getProjectExploitReport: (id: string, signal?: AbortSignal) =>
    http.get<unknown | null>(`/projects/${id}/exploit-report`, { signal }).then((r) => r.data),

  getProjectVerificationProgress: (id: string, signal?: AbortSignal) =>
    http
      .get<VerificationProgress>(`/projects/${id}/verification-progress`, { signal })
      .then((r) => r.data),

  getProjectVerificationItems: (id: string, signal?: AbortSignal) =>
    http
      .get<VerificationItem[]>(`/projects/${id}/verification-items`, { signal })
      .then((r) => r.data),

  projectEventArchiveUrl: (id: string) =>
    `/api/projects/${encodeURIComponent(id)}/events/archive`,

  getProjectVulnerability: (projectId: string, vulnerabilityId: string) =>
    http
      .get<Vulnerability>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`)
      .then((r) => r.data),

  getVulnerability: (id: string) =>
    http.get<VulnRow>(`/vulnerabilities/${id}`).then((r) => r.data),

  getEvents: (id: string, limit?: number) =>
    http
      .get<AgentEvent[]>(`/projects/${id}/events`, limit ? { params: { limit } } : undefined)
      .then((r) => r.data),

  /** 流程图阶段锚点（system 里程碑），不受 events?limit 截断影响。 */
  getEventAnchors: (id: string) =>
    http.get<AgentEvent[]>(`/projects/${id}/events/anchors`).then((r) => r.data),

  checkName: (name: string) =>
    http
      .get<{ available: boolean }>('/projects/check-name', { params: { name } })
      .then((r) => r.data.available),

  uploadProjects: (files: File[], names: string[], options?: AuditOptions, auditLanguage?: string) => {
    const fd = new FormData();
    files.forEach((f) => fd.append('files', f));
    fd.append('names', JSON.stringify(names));
    if (options) fd.append('options', JSON.stringify(options));
    if (auditLanguage) fd.append('audit_language', auditLanguage);
    // 多文件/大压缩包上传可能较慢；默认 axios 无超时，但代理层可能断连，显式放宽到 30 分钟
    return http
      .post<{ created: Project[] }>('/projects/upload', fd, { timeout: 30 * 60_000 })
      .then((r) => r.data);
  },

  githubPreview: (repos: { url: string; projectName?: string }[]) =>
    http.post<GithubImportPreview>('/projects/github/preview', { repos }).then((r) => r.data),

  githubProjects: (
    repos: { url: string; projectName?: string }[],
    options?: AuditOptions,
    auditScope?: GithubAuditScope,
    auditLanguage?: string
  ) =>
    http
      .post<{
        created: Project[];
        skipped?: GithubImportPreview['items'];
        auditScope?: GithubAuditScope;
      }>('/projects/github', { repos, options, auditScope, audit_language: auditLanguage })
      .then((r) => r.data),

  // 每批导入的 Web 端前置识别（勾选"只审计 Web 端"时触发）
  prescreenStatus: () =>
    http.get<ImportScreenStatus>('/projects/prescreen/status').then((r) => r.data),
  prescreenCancel: () =>
    http.post<{ ok: boolean }>('/projects/prescreen/cancel').then((r) => r.data),

  batchVersions: (
    id: string,
    opts: { years: number; topN: number; githubUrl?: string }
  ) =>
    http
      .post<{
        created: Project[];
        candidates: { tag: string; changeSize: number; publishedAt: number }[];
        skipped: string[];
      }>(`/projects/${id}/batch-versions`, opts)
      .then((r) => r.data),

  updateProject: (
    id: string,
    fields: {
      project_name?: string;
      source_version?: string | null;
      system_name?: string | null;
    }
  ) => http.patch<Project>(`/projects/${id}`, fields).then((r) => r.data),

  pause: (id: string) => http.post(`/projects/${id}/pause`).then((r) => r.data),
  resume: (id: string) => http.post(`/projects/${id}/resume`).then((r) => r.data),
  verify: (id: string, opts?: { verify_history?: boolean }) =>
    http.post(`/projects/${id}/verify`, opts ?? {}).then((r) => r.data),
  verifyOne: (id: string, title: string) =>
    http
      .post<{ ok: boolean; queued: boolean; pending: boolean }>(`/projects/${id}/verify-one`, { title })
      .then((r) => r.data),
  clearEnv: (id: string) => http.post(`/projects/${id}/env/clear`).then((r) => r.data),
  reconcileIdleContainers: (verifyPipeline = false) =>
    http
      .post<{
        ok: boolean;
        mode: 'default' | 'verify_pipeline';
        kept: string[];
        stopped: string[];
        errors: { projectId: string; error: string }[];
      }>('/projects/reconcile-idle-containers', { verifyPipeline })
      .then((r) => r.data),
  retryEnv: (id: string) => http.post(`/projects/${id}/env/retry`).then((r) => r.data),
  vulnPocUrl: (projectId: string, title: string) =>
    `/api/projects/${encodeURIComponent(projectId)}/vuln-poc?title=${encodeURIComponent(title)}`,
  vulnMdUrl: (projectId: string, title: string) =>
    `/api/projects/${encodeURIComponent(projectId)}/vuln-report.md?title=${encodeURIComponent(title)}`,
  downloadVulnReport: async (projectId: string, title: string) => {
    const res = await fetch(
      `/api/projects/${encodeURIComponent(projectId)}/vuln-report.md?title=${encodeURIComponent(title)}`
    );
    if (!res.ok) {
      let msg = `下载失败（HTTP ${res.status}）`;
      try {
        const body = await res.text();
        const j = JSON.parse(body);
        if (j?.error) msg = j.error;
      } catch {
        /* 非 JSON 错误体 */
      }
      throw new Error(msg);
    }
    const blob = await res.blob();
    const filename = safeDownloadFilename(title, 'md');
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
  fetchVulnPoc: (projectId: string, title: string) =>
    http
      .get<string>(`/projects/${projectId}/vuln-poc`, { params: { title }, responseType: 'text' as any })
      .then((r) => r.data as unknown as string),
  remove: (id: string) => http.delete(`/projects/${id}`).then((r) => r.data),
  reaudit: (id: string) => http.post(`/projects/${id}/reaudit`).then((r) => r.data),
  reverify: (id: string, opts?: { verify_history?: boolean }) =>
    http.post(`/projects/${id}/reverify`, opts ?? {}).then((r) => r.data),
  reverifyChain: (id: string) =>
    http.post(`/projects/${id}/reverify-chain`).then((r) => r.data),
  refull: (id: string) => http.post(`/projects/${id}/refull`).then((r) => r.data),
  reprocess: (id: string, chainVerify = false) =>
    http.post(`/projects/${id}/reprocess`, { chainVerify }).then((r) => r.data),
  runStage: (id: string, stage: string, mode: 'only' | 'from', verifyHistory?: boolean) =>
    http
      .post(`/projects/${id}/stage`, {
        stage,
        mode,
        ...(typeof verifyHistory === 'boolean' ? { verify_history: verifyHistory } : {}),
      })
      .then((r) => r.data),
  reingest: (id: string) =>
    http.post<{ count: number }>(`/projects/${id}/reingest`).then((r) => r.data),
  bulkPause: (ids: string[]) => http.post('/projects/bulk/pause', { ids }).then((r) => r.data),
  bulkResume: (ids: string[]) => http.post('/projects/bulk/resume', { ids }).then((r) => r.data),
  bulkDelete: (ids: string[]) => http.post('/projects/bulk/delete', { ids }).then((r) => r.data),
  bulkReaudit: (ids: string[]) =>
    http.post<{ count: number }>('/projects/bulk/reaudit', { ids }).then((r) => r.data),
  bulkReverify: (ids: string[], opts?: { verify_history?: boolean }) =>
    http
      .post<{ count: number; skipped: number }>('/projects/bulk/reverify', {
        ids,
        ...(typeof opts?.verify_history === 'boolean' ? { verify_history: opts.verify_history } : {}),
      })
      .then((r) => r.data),
  bulkReverifyChain: (ids: string[]) =>
    http
      .post<{ count: number; skipped: number }>('/projects/bulk/reverify-chain', { ids })
      .then((r) => r.data),
  bulkRefull: (ids: string[]) =>
    http.post<{ count: number }>('/projects/bulk/refull', { ids }).then((r) => r.data),
  bulkReprocess: (ids: string[]) =>
    http.post<{ count: number }>('/projects/bulk/reprocess', { ids }).then((r) => r.data),
  bulkReingest: (ids: string[]) =>
    http
      .post<{ count: number; totalVulns: number }>('/projects/bulk/reingest', { ids })
      .then((r) => r.data),

  reportUrl: (id: string, download = false) =>
    `/api/projects/${id}/report${download ? '?download=1' : ''}`,

  getSettings: () => http.get<Settings>('/settings').then((r) => r.data),
  saveSettings: (s: Partial<Settings>) =>
    http.put<Settings>('/settings', s).then((r) => r.data),

  // 回收站（记录所有删除，不支持还原）
  getRecycle: () => http.get<DeletedProject[]>('/recycle').then((r) => r.data),
  getRecyclePage: (params: { page: number; pageSize: number; search?: string }) =>
    http.get<RecyclePage>('/recycle', { params }).then((r) => r.data),
  clearRecycle: () =>
    http.delete<{ ok: boolean; cleared: number }>('/recycle').then((r) => r.data),

  // 批量 Web 端判定 + 清理
  classifyWebStart: () =>
    http
      .post<{ ok: boolean; total?: number; error?: string }>('/projects/classify-web/start')
      .then((r) => r.data),
  classifyWebStatus: () =>
    http.get<WebClassifyStatus>('/projects/classify-web/status').then((r) => r.data),
  classifyWebConfirmDelete: (ids: string[]) =>
    http
      .post<{ ok: boolean; deleted: number; failed: number }>(
        '/projects/classify-web/confirm-delete',
        { ids }
      )
      .then((r) => r.data),
  classifyWebCancel: () =>
    http.post<{ ok: boolean }>('/projects/classify-web/cancel').then((r) => r.data),

  listMonitors: () => http.get<Monitor[]>('/monitors').then((r) => r.data),
  createMonitor: (m: { repo_url: string; project_prefix?: string; interval_min?: number }) =>
    http.post<Monitor>('/monitors', m).then((r) => r.data),
  updateMonitor: (id: string, m: Partial<Monitor>) =>
    http.put<Monitor>(`/monitors/${id}`, m).then((r) => r.data),
  deleteMonitor: (id: string) => http.delete(`/monitors/${id}`).then((r) => r.data),
  checkMonitor: (id: string) => http.post<Monitor>(`/monitors/${id}/check`).then((r) => r.data),
};
