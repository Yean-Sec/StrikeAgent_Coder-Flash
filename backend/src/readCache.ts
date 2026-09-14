/**
 * 后端只读查询的短时版本化 LRU 缓存。
 *
 * 每个 scope 独立维护版本号；写路径只提升受影响 scope 的版本，
 * 旧条目即刻失效，同时仍受全局 LRU 上限约束，避免搜索关键字造成无界增长。
 */
export type ReadCacheScope =
  | 'dashboard'
  | 'project-status-counts'
  | 'vulnerability-counts'
  | 'version-groups'
  | 'cve-library'
  // 项目详情页最重的只读接口（logs/runs 聚合、verification-progress、exploit-report）。
  // 短 TTL 去重高频轮询；相关写路径通过下方 invalidate* 一并提升版本。
  | 'project-detail';

interface CacheEntry {
  scope: ReadCacheScope;
  version: number;
  expiresAt: number;
  value: unknown;
}

const MAX_ENTRIES = 256;
const entries = new Map<string, CacheEntry>();
const versions = new Map<ReadCacheScope, number>();

function scopeVersion(scope: ReadCacheScope): number {
  return versions.get(scope) ?? 0;
}

function entryKey(scope: ReadCacheScope, key: string): string {
  return `${scope}\u0000${key}`;
}

function trimLru(): void {
  while (entries.size > MAX_ENTRIES) {
    const oldest = entries.keys().next().value as string | undefined;
    if (oldest === undefined) return;
    entries.delete(oldest);
  }
}

export function getCachedRead<T>(scope: ReadCacheScope, key: string): T | undefined {
  const fullKey = entryKey(scope, key);
  const entry = entries.get(fullKey);
  if (!entry) return undefined;
  if (entry.version !== scopeVersion(scope) || entry.expiresAt <= Date.now()) {
    entries.delete(fullKey);
    return undefined;
  }

  // Map 的插入顺序即 LRU 顺序；命中后移动到末尾。
  entries.delete(fullKey);
  entries.set(fullKey, entry);
  return entry.value as T;
}

export function setCachedRead<T>(
  scope: ReadCacheScope,
  key: string,
  value: T,
  ttlMs: number
): T {
  const fullKey = entryKey(scope, key);
  entries.delete(fullKey);
  entries.set(fullKey, {
    scope,
    version: scopeVersion(scope),
    expiresAt: Date.now() + Math.max(1, ttlMs),
    value,
  });
  trimLru();
  return value;
}

export function readThroughCache<T>(
  scope: ReadCacheScope,
  key: string,
  ttlMs: number,
  load: () => T
): T {
  const cached = getCachedRead<T>(scope, key);
  if (cached !== undefined) return cached;
  return setCachedRead(scope, key, load(), ttlMs);
}

export function invalidateReadScopes(...scopes: ReadCacheScope[]): void {
  const unique = new Set(scopes);
  for (const scope of unique) {
    versions.set(scope, scopeVersion(scope) + 1);
  }

  // 版本号已保证正确性；同步移除对应条目以尽快释放大对象。
  for (const [key, entry] of entries) {
    if (unique.has(entry.scope)) entries.delete(key);
  }
}

/** 项目创建、删除、状态或可搜索元数据变化。 */
export function invalidateProjectStatusReads(): void {
  invalidateReadScopes('project-status-counts', 'dashboard', 'version-groups', 'project-detail');
}

/** 漏洞增删、等级、verified/auth/frontend_rce 等派生字段变化。 */
export function invalidateVulnerabilityReads(): void {
  invalidateReadScopes(
    'vulnerability-counts',
    'dashboard',
    'version-groups',
    'cve-library',
    'project-detail'
  );
}

/** exploit_report 或物化利用链变化。 */
export function invalidateExploitReads(): void {
  invalidateReadScopes(
    'vulnerability-counts',
    'dashboard',
    'version-groups',
    'cve-library',
    'project-detail'
  );
}
