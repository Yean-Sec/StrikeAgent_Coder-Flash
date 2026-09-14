export type ExploitStatus = 'success' | 'failed' | 'restricted' | 'unknown';
export type AuthTier = 'none' | 'user' | 'admin';
export type PrivilegeStatus = ExploitStatus | 'skipped';

export type PrivilegeResult = {
  status: PrivilegeStatus;
  evidence?: string;
};

export type PrivilegeResults = Partial<Record<AuthTier, PrivilegeResult>>;

export interface VerificationLike {
  local_exploitable?: unknown;
  remote_status?: unknown;
  remote_exploitable?: unknown;
  status?: unknown;
  privilege_results?: unknown;
  local_result?: unknown;
  detail?: unknown;
  evidence?: unknown;
  auth_required?: unknown;
}

  const SUCCESS_VALUES = new Set([
  'success',
  'true',
  'true_positive',
  'verified_true_positive',
  'hit',
  'confirmed',
  'verified',
  'verified_rce',
  'rce_confirmed',
  'confirmed_with_evidence',
  'exploited',
  'exploitable',
  'confirmed_accessible',
  'confirmed_reachable',
  'pass',
  'passed',
  'pwned',
]);

const RESTRICTED_VALUES = new Set([
  'restricted',
  'conditional',
  'partial',
  'partially_verified',
  'confirmed_with_limitations',
  'confirmed_theoretically',
  'partially_exploitable',
  'partial_success',
  'limited',
  'partially confirmed',
  'partially verified',
  'partially_confirmed',
  'code-verified',
  'verified_by_code_analysis',
  'verified by code analysis',
  'verified-nottriggerable',
  'codeconfirmed_remoteendpointnotexposed',
  'confirmed (code-level)',
  'source_code_verified',
  'verified_source_code',
  'source-code-verified',
  'code_verified',
  'partially_working',
  'partially_confirmed',
  'code_confirmed_env_blocked',
  'confirmed_accessible_but_blocked',
  'blocking_issue',
]);

const FAILED_VALUES = new Set([
  'failed',
  'false',
  'false_positive',
  'falsepositive',
  'fail',
  'miss',
  'blocked',
  'not_achieved',
  'not achieved',
  'not_exploitable',
  'unexploitable',
]);

const CODE_ONLY_HINT =
  /code[-_\s]?(?:level|verified|confirmed|analysis)|源码|代码(?:层|分析|确认)|无(?:路由|入口)|未暴露|not\s*triggerable|endpoint\s*not\s*exposed/i;
const REMOTE_SUCCESS_HINT =
  /(?:http|接口|端点|远程|靶机|请求|响应|回显|payload|poc|curl|浏览器)[\s\S]{0,120}(?:成功|命中|触发|利用|200|201|302|回显)|(?:成功|命中|触发|利用)[\s\S]{0,80}(?:http|接口|端点|远程|靶机|请求|响应|回显|payload|poc)/i;

export function normalizeExploitStatus(raw: unknown): ExploitStatus {
  const value = String(raw ?? '').toLowerCase().trim();
  if (SUCCESS_VALUES.has(value)) return 'success';
  if (RESTRICTED_VALUES.has(value)) return 'restricted';
  if (FAILED_VALUES.has(value)) return 'failed';
  return 'unknown';
}

export function normalizePrivilegeStatus(raw: unknown): PrivilegeStatus {
  const value = String(raw ?? '').toLowerCase().trim();
  if (value === 'skipped' || value === 'not_tested' || value === 'untested' || value === 'n/a' || value === 'na') {
    return 'skipped';
  }
  return normalizeExploitStatus(raw);
}

export function normalizePrivilegeResults(raw: unknown): PrivilegeResults | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const result: PrivilegeResults = {};
  let found = false;
  for (const tier of ['none', 'user', 'admin'] as const) {
    const cell = (raw as Record<string, unknown>)[tier];
    if (!cell || typeof cell !== 'object') continue;
    const value = cell as Record<string, unknown>;
    const status = normalizePrivilegeStatus(value.status);
    const evidence = value.evidence == null ? undefined : String(value.evidence).slice(0, 1200);
    result[tier] = evidence ? { status, evidence } : { status };
    found = true;
  }
  return found ? result : undefined;
}

export function deriveMinimumAuth(
  privilegeResults: PrivilegeResults | undefined,
  fallback: unknown
): AuthTier | 'unknown' {
  if (privilegeResults) {
    for (const tier of ['none', 'user', 'admin'] as const) {
      if (privilegeResults[tier]?.status === 'success') return tier;
    }
    return 'unknown';
  }
  const value = String(fallback ?? '').toLowerCase().trim();
  return value === 'none' || value === 'user' || value === 'admin' ? value : 'unknown';
}

export function deriveRemoteStatus(entry: VerificationLike): ExploitStatus {
  const privilegeResults = normalizePrivilegeResults(entry.privilege_results);
  if (privilegeResults) {
    const tested = Object.values(privilegeResults).filter((cell): cell is PrivilegeResult => !!cell && cell.status !== 'skipped');
    if (tested.some((cell) => cell.status === 'success')) return 'success';
    if (tested.some((cell) => cell.status === 'restricted')) return 'restricted';
    if (tested.length > 0 && tested.every((cell) => cell.status === 'failed')) return 'failed';
    return 'unknown';
  }

  const explicit = entry.remote_status ?? entry.remote_exploitable;
  if (explicit != null && String(explicit).trim()) return normalizeExploitStatus(explicit);

  const rawStatus = entry.local_exploitable ?? entry.status;
  const localStatus = normalizeExploitStatus(rawStatus);
  if (localStatus !== 'success') return localStatus;

  const text = [rawStatus, entry.local_result, entry.detail, entry.evidence]
    .filter((value) => value != null)
    .map(String)
    .join(' ');
  if (CODE_ONLY_HINT.test(text) && !REMOTE_SUCCESS_HINT.test(text)) return 'restricted';
  return REMOTE_SUCCESS_HINT.test(text) ? 'success' : 'restricted';
}

export function isRemoteVerified(entry: VerificationLike): boolean {
  return deriveRemoteStatus(entry) === 'success';
}
