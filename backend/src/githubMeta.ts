import { execFileSync } from 'child_process';
import { getSetting } from './settings';

export function parseOwnerRepo(url: string): { owner: string; repo: string } | null {
  const m = url
    .trim()
    .replace(/\.git$/, '')
    .match(/github\.com[/:]([^/]+)\/([^/]+)/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2].replace(/\/+$/, '') };
}

/** 从 GitHub API 获取最新 release tag；无 release 时回退到最新 tag。 */
export async function fetchLatestRelease(
  url: string
): Promise<{ tag: string; name: string } | null> {
  const or = parseOwnerRepo(url);
  if (!or) return null;
  const token = getSetting('github_token').trim();
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'code-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const api = `https://api.github.com/repos/${or.owner}/${or.repo}/releases/latest`;
  try {
    const res = await fetch(api, { headers });
    if (res.status === 404) {
      const tagsRes = await fetch(
        `https://api.github.com/repos/${or.owner}/${or.repo}/tags`,
        { headers }
      );
      if (!tagsRes.ok) return null;
      const tags = (await tagsRes.json()) as any[];
      if (Array.isArray(tags) && tags.length > 0) {
        return { tag: tags[0].name, name: tags[0].name };
      }
      return null;
    }
    if (!res.ok) return null;
    const data = (await res.json()) as any;
    const tag = data.tag_name || data.name;
    return tag ? { tag, name: data.name || tag } : null;
  } catch {
    return null;
  }
}

function ghHeaders(): Record<string, string> {
  const token = getSetting('github_token').trim();
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'code-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export interface ReleaseInfo {
  tag: string;
  publishedAt: number; // 毫秒时间戳
}

/** 把 GitHub API 的失败响应翻译成清晰的中文错误（区分限流 / 认证 / 其它）。 */
function describeApiError(status: number, remaining: string | null, body: any): string {
  const msg = String(body?.message || '');
  if (status === 403 && (remaining === '0' || /rate limit/i.test(msg))) {
    return 'GitHub API 调用已达上限（匿名 60 次/小时）。请在「设置」中配置 GitHub Token 后重试。';
  }
  if (status === 401) return 'GitHub Token 无效或已过期，请在「设置」中检查 GitHub Token。';
  if (status === 404) return '仓库不存在或不可访问（私有仓库需在「设置」配置有权限的 GitHub Token）。';
  return `GitHub API 请求失败（HTTP ${status}${msg ? '：' + msg.slice(0, 80) : ''}）。`;
}

/**
 * 拉取仓库近 N 年内的版本（release 优先，无 release 回退 tags）。
 * 为了能给"窗口内最早一个版本"也计算相邻改动量，会**额外多取一个窗口前的版本**作为对比基线。
 * 返回按时间升序排列（旧→新），可能包含一个略早于窗口的基线版本。
 * 若 GitHub API 调用失败（如限流），通过 `error` 字段返回清晰原因（与"真的没有 release"区分）。
 */
export async function fetchReleasesInWindow(
  url: string,
  years: number
): Promise<{ inWindow: ReleaseInfo[]; baseline: ReleaseInfo | null; error?: string }> {
  const or = parseOwnerRepo(url);
  if (!or) return { inWindow: [], baseline: null, error: '无效的 GitHub 仓库地址' };
  const headers = ghHeaders();
  const since = Date.now() - years * 365 * 24 * 60 * 60 * 1000;

  // 收集全部版本（最多翻 5 页 = 500 个，足够覆盖常见仓库的几年）
  const all: ReleaseInfo[] = [];
  let apiError: string | null = null;
  try {
    for (let page = 1; page <= 5; page++) {
      const api = `https://api.github.com/repos/${or.owner}/${or.repo}/releases?per_page=100&page=${page}`;
      const res = await fetch(api, { headers });
      if (!res.ok) {
        // 仅首页失败才视为 API 错误（翻页途中失败说明前面已拿到数据）
        if (page === 1) {
          const body = await res.json().catch(() => ({}));
          apiError = describeApiError(res.status, res.headers.get('x-ratelimit-remaining'), body);
        }
        break;
      }
      const data = (await res.json()) as any[];
      if (!Array.isArray(data) || data.length === 0) break;
      for (const r of data) {
        if (r?.draft) continue;
        const tag = r?.tag_name || r?.name;
        const ts = r?.published_at ? Date.parse(r.published_at) : NaN;
        if (tag && Number.isFinite(ts)) all.push({ tag: String(tag), publishedAt: ts });
      }
      if (data.length < 100) break;
    }
  } catch (e: any) {
    apiError = `GitHub API 网络请求失败：${String(e?.message || e).slice(0, 80)}`;
  }

  // 无 release：回退到 tags（tags 无日期，需逐个取 commit 日期，开销大，限取前 60 个）
  if (all.length === 0) {
    try {
      const tagsRes = await fetch(
        `https://api.github.com/repos/${or.owner}/${or.repo}/tags?per_page=100`,
        { headers }
      );
      if (!tagsRes.ok) {
        const body = await tagsRes.json().catch(() => ({}));
        // releases 与 tags 都失败：以更具体的那个错误为准
        apiError =
          describeApiError(tagsRes.status, tagsRes.headers.get('x-ratelimit-remaining'), body) ||
          apiError;
      } else {
        apiError = null; // tags 拉到了，清除 releases 的失败标记
        const tags = (await tagsRes.json()) as any[];
        const slice = Array.isArray(tags) ? tags.slice(0, 60) : [];
        for (const t of slice) {
          const tag = t?.name;
          const sha = t?.commit?.sha;
          if (!tag || !sha) continue;
          try {
            const cRes = await fetch(
              `https://api.github.com/repos/${or.owner}/${or.repo}/commits/${sha}`,
              { headers }
            );
            if (!cRes.ok) continue;
            const c = (await cRes.json()) as any;
            const iso = c?.commit?.committer?.date || c?.commit?.author?.date;
            const ts = iso ? Date.parse(iso) : NaN;
            if (Number.isFinite(ts)) all.push({ tag: String(tag), publishedAt: ts });
          } catch {
            /* 跳过单个 tag 失败 */
          }
        }
      }
    } catch (e: any) {
      if (!apiError) apiError = `GitHub API 网络请求失败：${String(e?.message || e).slice(0, 80)}`;
    }
  }

  if (all.length === 0) {
    return { inWindow: [], baseline: null, error: apiError || undefined };
  }

  all.sort((a, b) => a.publishedAt - b.publishedAt); // 旧→新
  const inWindow = all.filter((r) => r.publishedAt >= since);
  // 取窗口内最早版本之前的一个版本作为对比基线（让最早的窗口版本也能算改动量）
  let baseline: ReleaseInfo | null = null;
  if (inWindow.length > 0) {
    const firstIdx = all.findIndex((r) => r.tag === inWindow[0].tag);
    if (firstIdx > 0) baseline = all[firstIdx - 1];
  }
  return { inWindow, baseline };
}

/** 两个 ref 之间的代码改动量（additions + deletions）。失败返回 null。 */
export async function compareChangeSize(
  url: string,
  base: string,
  head: string
): Promise<number | null> {
  const or = parseOwnerRepo(url);
  if (!or) return null;
  try {
    const api = `https://api.github.com/repos/${or.owner}/${or.repo}/compare/${encodeURIComponent(
      base
    )}...${encodeURIComponent(head)}`;
    const res = await fetch(api, { headers: ghHeaders() });
    if (!res.ok) return null;
    const data = (await res.json()) as any;
    const files = Array.isArray(data?.files) ? data.files : [];
    let sum = 0;
    for (const f of files) sum += (Number(f?.additions) || 0) + (Number(f?.deletions) || 0);
    return sum;
  } catch {
    return null;
  }
}

export interface VersionCandidate {
  tag: string;
  changeSize: number;
  publishedAt: number;
}

/** 版本号归一化（去前缀 v、空白、小写），用于排除"当前版本"。 */
function normVer(s: string): string {
  return String(s || '')
    .trim()
    .replace(/^v/i, '')
    .toLowerCase();
}

/**
 * 计算"近 N 年改动最大的 TopN 版本"：
 * 对窗口内版本按时间顺序逐对调用 compare，把相邻改动量记到较新版本上，
 * 按改动量降序排序，排除 excludeVersions（归一化匹配），取前 topN。
 */
export async function rankBiggestChangeVersions(
  url: string,
  years: number,
  topN: number,
  excludeVersions: string[] = []
): Promise<{
  candidates: VersionCandidate[];
  totalConsidered: number;
  hadReleases: boolean;
  error?: string;
}> {
  const { inWindow, baseline, error } = await fetchReleasesInWindow(url, years);
  if (error) {
    // API 失败（如限流）：把真实原因透传出去，避免误报"没有 release"
    return { candidates: [], totalConsidered: 0, hadReleases: false, error };
  }
  if (inWindow.length === 0) {
    return { candidates: [], totalConsidered: 0, hadReleases: false };
  }

  const excl = new Set(excludeVersions.map(normVer).filter(Boolean));
  // 构造对比序列：baseline(可选) + 窗口内版本（旧→新）
  const seq = baseline ? [baseline, ...inWindow] : [...inWindow];
  const scored: VersionCandidate[] = [];
  for (let i = 0; i < seq.length; i++) {
    const cur = seq[i];
    // baseline 本身不作为候选（它在窗口外）
    if (baseline && i === 0) continue;
    const prev = seq[i - 1];
    let changeSize = 0;
    if (prev) {
      const c = await compareChangeSize(url, prev.tag, cur.tag);
      changeSize = c ?? 0;
    }
    scored.push({ tag: cur.tag, changeSize, publishedAt: cur.publishedAt });
  }

  const candidates = scored
    .filter((c) => !excl.has(normVer(c.tag)))
    .sort((a, b) => b.changeSize - a.changeSize)
    .slice(0, topN);

  return { candidates, totalConsidered: scored.length, hadReleases: true };
}

/** 读取本地仓库 HEAD 的短 commit SHA（离线兜底）。 */
export function localGitVersion(dir: string): string | null {
  try {
    const sha = execFileSync('git', ['-C', dir, 'rev-parse', '--short', 'HEAD'], {
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
    if (!sha) return null;
    // 同时尝试取 HEAD 指向的 tag
    try {
      const tag = execFileSync('git', ['-C', dir, 'describe', '--tags', '--always'], {
        encoding: 'utf8',
        windowsHide: true,
      }).trim();
      if (tag && tag !== sha && !/^[0-9a-f]{7,}$/i.test(tag)) return tag;
    } catch {
      /* ignore */
    }
    return sha;
  } catch {
    return null;
  }
}

/**
 * 解析 GitHub 项目版本号：优先 release/tag，回退到本地 commit。
 * @param url 仓库地址
 * @param localDir 已克隆的本地目录（用于离线兜底）
 */
export async function resolveGithubVersion(
  url: string,
  localDir?: string
): Promise<string | null> {
  const release = await fetchLatestRelease(url);
  if (release?.tag) return release.tag;
  if (localDir) return localGitVersion(localDir);
  return null;
}
