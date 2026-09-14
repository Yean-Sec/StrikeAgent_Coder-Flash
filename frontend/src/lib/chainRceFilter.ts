/**
 * 组合链展示/过滤（与 backend/src/chainRceFilter.ts 保持同步）
 */

export type ChainLike = {
  name?: unknown;
  chain_name?: unknown;
  impact?: unknown;
  final_impact?: unknown;
  detail?: unknown;
  auth_required?: unknown;
};

const NON_RCE_TERMINAL = [
  '破坏可追溯',
  '掩盖审计',
  '杀作业',
  '终止作业',
  '拒绝服务',
  'denial of service',
  '调度破坏',
  '断开合法',
  '监控面污染',
  '情报收集',
  '未授权读',
  '信息泄露',
  '越权读',
  'dos',
];

const RCE_TERMINAL_POSITIVE = [
  '远程代码执行',
  '代码执行',
  '命令执行',
  'getshell',
  'get shell',
  'webshell',
  'web shell',
  '完全接管',
  '接管服务器',
  '服务器接管',
  '任意代码执行',
  '任意命令',
  '反弹shell',
  '反弹 shell',
  '写入并执行',
  '植入后门',
  'remote code execution',
  'code execution',
  'command execution',
  'arbitrary code',
  '供应链 rce',
  'class.forname',
  '恶意 jar',
];

function impactNegatesRce(text: string): boolean {
  return /未达成|未实现|无法构成|不构成|没有达成|无.*真阳性|未组成.{0,12}(rce|代码执行|命令执行)/i.test(
    text
  );
}

export function isRceTerminalChain(c: ChainLike | null | undefined): boolean {
  if (!c || typeof c !== 'object') return false;
  const impact = String(c.impact ?? c.final_impact ?? '').trim();
  const name = String(c.name ?? c.chain_name ?? '').trim();
  const focus = `${impact} ${name}`.toLowerCase();
  if (!focus.trim()) return false;
  if (impactNegatesRce(focus)) return false;

  const hasPositive = RCE_TERMINAL_POSITIVE.some((k) => focus.includes(k.toLowerCase()))
    || /\brce\b/i.test(impact)
    || /\brce\b/i.test(name)
    || /(实现|达成|获得).{0,16}(rce|代码执行|命令执行|getshell)/i.test(focus);

  if (!hasPositive) return false;

  const looksNonRce = NON_RCE_TERMINAL.some((k) => focus.includes(k.toLowerCase()));
  if (looksNonRce) {
    const achieved = /(实现|达成|获得|验证成功).{0,20}(rce|代码执行|命令执行|getshell|接管)/i.test(
      focus
    );
    if (!achieved) return false;
  }
  return true;
}

export function isAllowedChainAuth(c: ChainLike | null | undefined): boolean {
  const auth = String(c?.auth_required ?? '')
    .toLowerCase()
    .trim();
  if (auth === 'admin') return false;
  if (auth === 'user' || auth === 'none') return true;
  const text = `${c?.name ?? ''} ${c?.impact ?? ''}`.toLowerCase();
  if (/管理员|admin\s*起点|需.*admin|后台登录/.test(text)) return false;
  return true;
}

export function filterComboChainsForPolicy(chains: unknown[]): unknown[] {
  if (!Array.isArray(chains)) return [];
  return chains.filter(
    (c) => isRceTerminalChain(c as ChainLike) && isAllowedChainAuth(c as ChainLike)
  );
}

export function isRceChain(c: ChainLike): boolean {
  return isRceTerminalChain(c) && isAllowedChainAuth(c);
}
