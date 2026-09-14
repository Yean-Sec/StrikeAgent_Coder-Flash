import { normalizeExploitStatus, type ExploitStatus } from './verificationStatus';

/**
 * 统一磁盘组合链产物形态：
 * - nested `{ chain: { name, … } }` → flatten
 * - `chain_name` / string `chain` → `name`
 * - `chain_steps` → `steps`
 * - 缺失 status 时从 verification_results / privilege_results / 文本启发式推导
 */
export function normalizeChainArtifact(raw: unknown): Record<string, unknown> | null {
  if (!raw || typeof raw !== 'object') return null;
  let obj = raw as Record<string, unknown>;

  // 嵌套 { chain: { … } }
  if (obj.chain && typeof obj.chain === 'object' && !Array.isArray(obj.chain)) {
    const nested = obj.chain as Record<string, unknown>;
    obj = { ...obj, ...nested };
    delete obj.chain;
  }

  // 部分链验证技能以 string `chain` 写入链标识；与嵌套对象 `chain` 区分处理。
  const stringChain = typeof obj.chain === 'string' ? obj.chain : undefined;
  const name = String(obj.name ?? obj.chain_name ?? stringChain ?? obj.title ?? '').trim();
  if (!name) return null;

  // 单漏洞 exploit 对象（有 vulnerability_id / vulnerability，且不像链）不走链归一
  const hasVulnId = !!(obj.vulnerability_id || obj.vuln_id);
  const hasVulnTitle = typeof obj.vulnerability === 'string' && String(obj.vulnerability).trim();
  const looksLikeExploit =
    (hasVulnId || hasVulnTitle) &&
    obj.steps == null &&
    obj.chain_steps == null &&
    obj.impact == null &&
    !obj.chain_name;
  if (looksLikeExploit) return null;

  const steps = obj.steps ?? obj.chain_steps;
  const out: Record<string, unknown> = {
    ...obj,
    name,
  };
  if (out.chain_id == null) {
    const rawChainId = out.chainId ?? out.candidate_id;
    if (rawChainId != null && String(rawChainId).trim()) out.chain_id = String(rawChainId).trim();
  }
  delete out.chain_name;
  if (steps != null) {
    out.steps = steps;
    delete out.chain_steps;
  }

  if (!String(out.impact ?? '').trim() && out.summary != null) {
    const summary = coerceText(out.summary).trim();
    if (summary) out.impact = summary.slice(0, 500);
  }

  out.status = deriveChainStatus(out);
  return out;
}

function normalizedFieldStatus(value: unknown): ExploitStatus {
  const normalized = normalizeExploitStatus(value);
  if (normalized !== 'unknown') return normalized;
  const text = String(value ?? '').toLowerCase().trim();
  if (
    /(?:source[_\s-]*code[_\s-]*(?:confirmed|verified).{0,80}(?:blocked|environment)|code[_\s-]*confirmed[_\s-]*env[_\s-]*blocked|partial[_\s-]*(?:failure|success)|partially[_\s-]*(?:working|verified|confirmed)|blocking[_\s-]*issue|inconclusive)/.test(
      text
    )
  ) {
    return 'restricted';
  }
  if (/(?:rce[_\s-]*confirmed|exploitable|fully[_\s-]*verified|confirmed[_\s-]*(?:accessible|reachable)|\bpass(?:ed)?\b)/.test(text)) {
    return 'success';
  }
  if (/(?:not[_\s-]*(?:achieved|reachable|possible)|unverified|\bnot achieved\b)/.test(text)) {
    return 'failed';
  }
  return 'unknown';
}

function stepStatus(entry: Record<string, unknown>): ExploitStatus | null {
  const nestedChain =
    entry.exploit_chain && typeof entry.exploit_chain === 'object'
      ? (entry.exploit_chain as Record<string, unknown>)
      : undefined;
  const steps = entry.steps ?? entry.chain_steps ?? nestedChain?.steps;
  if (!Array.isArray(steps)) return null;
  const statuses = steps
    .filter((step): step is Record<string, unknown> => !!step && typeof step === 'object')
    .map((step) => normalizedFieldStatus(step.status ?? step.result ?? step.verdict))
    .filter((status) => status !== 'unknown');
  if (statuses.length === 0) return null;
  if (statuses.some((status) => status === 'failed')) return 'failed';
  if (statuses.some((status) => status === 'restricted')) return 'restricted';
  return statuses.every((status) => status === 'success') ? 'success' : null;
}

function coerceText(v: unknown): string {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'object') {
    try {
      return JSON.stringify(v);
    } catch {
      return String(v);
    }
  }
  return String(v);
}

function deriveChainStatus(entry: Record<string, unknown>): ExploitStatus {
  // RCE proof is decisive even when a subagent forgot the generic status field.
  if (entry.rce_confirmed === true || entry.rce_confirmed === 'true') return 'success';
  const rceProof = entry.rce_proof;
  if (rceProof && typeof rceProof === 'object') {
    const proofText = coerceText(rceProof).toLowerCase();
    if (
      /(?:uid=\d+|www-data|root\b|command[_\s-]*executed|whoami)/.test(proofText) &&
      /(?:id\b|whoami|cmd|command|output|shell)/.test(proofText)
    ) {
      return 'success';
    }
  }

  // Different skills write different final-result keys. Prefer explicit final verdicts
  // over individual step results, because a chain can reach a sink but remain blocked
  // before a real remote RCE trigger.
  const explicitFields = [
    entry.status,
    entry.remote_status,
    entry.result,
    entry.verdict,
    entry.verification_result,
    entry.verification_status,
    entry.final_status,
    entry.overall_status,
    entry.overall_verdict,
  ];
  for (const explicit of explicitFields) {
    if (explicit == null || !String(explicit).trim()) continue;
    const normalized = normalizedFieldStatus(explicit);
    if (normalized !== 'unknown') return normalized;
  }

  const priv = entry.privilege_results;
  if (priv && typeof priv === 'object') {
    const cells = Object.values(priv as Record<string, any>).filter(
      (c) => c && typeof c === 'object' && c.status != null
    );
    if (cells.some((c) => normalizeExploitStatus(c.status) === 'success')) return 'success';
    if (cells.some((c) => normalizeExploitStatus(c.status) === 'restricted')) return 'restricted';
    if (cells.length > 0 && cells.every((c) => normalizeExploitStatus(c.status) === 'failed')) {
      return 'failed';
    }
  }

  const fromSteps = stepStatus(entry);
  if (fromSteps && fromSteps !== 'success') return fromSteps;

  const text = [
    coerceText(entry.detail),
    coerceText(entry.local_result),
    coerceText((entry.verification_results as any)?.summary),
    coerceText((entry.exploit_chain as any)?.summary),
    coerceText((entry.exploit_chain as any)?.steps),
    coerceText(entry.rce_proof),
    coerceText(entry.summary),
  ]
    .join(' ')
    .toLowerCase();

  if (
    /source[_\s-]*code[_\s-]*(?:confirmed|verified).{0,80}(?:blocked|environment)|环境(?:受限|阻断)|partial[_\s-]*(?:failure|success)/.test(
      text
    )
  ) {
    return 'restricted';
  }
  if (/验证失败|无法成立|不可利用|不可行|阻断|blocked|failed|false\s*positive|not[_\s-]*achieved/.test(text)) {
    return 'failed';
  }
  if (/部分|受限|restricted|partial|环境限制|sandbox|沙箱|inconclusive/.test(text)) {
    return 'restricted';
  }
  if (/true\s*positive|验证成功|链验证成功|完全打通|rce\s*(confirmed|success)|成功达成|exploitable/.test(text)) {
    return 'success';
  }

  return fromSteps || 'unknown';
}

/** 判断对象是否像组合链产物（供读盘入口分流）。 */
export function looksLikeChainArtifact(raw: unknown): boolean {
  return normalizeChainArtifact(raw) != null;
}
