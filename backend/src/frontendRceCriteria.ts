/**
 * 「前台 RCE」口径（frontend_rce=1）：
 * 远程靶机 HTTP 验证通过 + 标题级 RCE 类（排除 DoS/SSRF 等）+ 下列之一：
 *   A) auth_required=none（无权限）
 *   B) 项目 reg_default_open=1 且 auth_required=user（注册默认开放下的普通用户 RCE）
 */
import { deriveRemoteStatus } from './verificationStatus';

export function normTitleKey(s: string): string {
  return String(s || '')
    .replace(/\\([_*`[\]()#+\-.!|{}])/g, '$1')
    .replace(/['"“”‘’]/g, '')
    .replace(/\s+/g, '')
    .toLowerCase();
}

export function isRceClass(v: {
  title?: string;
  category?: string;
  description?: string;
}): boolean {
  const s = `${v.title || ''} ${v.category || ''} ${v.description || ''}`.toLowerCase();
  return isRceClassText(s);
}

/**
 * 前台 RCE 标签：仅用标题+类型，避免 description 连带误判 DoS 等为 RCE。
 * 判定顺序修正：先看是否有明确的 RCE 正信号（中/英文都认），有正信号即算 RCE 类，
 * 不再被 "未授权访问/ssrf/csrf" 等排除词【在英文 rce 前瞻下】误否决——
 * 旧实现 `未授权访问(?!.*rce)` 只认英文 rce，会把"未授权访问…命令执行/代码执行"这类
 * 真前台 RCE 误判为非 RCE（假阴性）。仅当标题本质是 DoS/资源耗尽、且 RCE 词来自
 * 否定式描述（"并非命令注入而是进程耗尽"）时才排除。
 */
export function isRceClassStrictTitle(v: { title?: string | null; category?: string | null }): boolean {
  const s = `${v.title || ''} ${v.category || ''}`.toLowerCase();
  // 无明确 RCE 正信号 → 直接判非 RCE 类（SSRF/CSRF/XSS/信息泄露/JWT 等纯类别不含 RCE 词自然落这里）
  if (!isRceClassText(s)) return false;
  // 有 RCE 词，但标题本质是 DoS/资源耗尽、RCE 词出现在否定语境里 → 仍排除
  const dosContext =
    /拒绝服务|\bdos\b|磁盘耗尽|cpu.{0,6}耗尽|内存耗尽|资源耗尽|进程表?耗尽|栈溢出/i.test(s);
  const rceNegated =
    /(?:并非|而非|不是|非|无法|未能|不构成).{0,12}(?:命令注入|命令执行|代码执行|远程代码|\brce\b)/i.test(s);
  if (dosContext && rceNegated) return false;
  return true;
}

function isRceClassText(s: string): boolean {
  // 「存储型 XSS（…模板注入）」这类文案不是 RCE；纯 XSS 直接排除
  const xssFramed =
    /(?:存储型|反射型|dom)\s*xss|\bxss\b|跨站脚本/i.test(s) &&
    !/\brce\b|远程代码|命令执行|命令注入|代码执行|webshell|getshell/i.test(s);
  if (xssFramed) return false;

  if (
    /\brce\b|远程代码执行|任意代码执行|代码执行|命令执行|命令注入|command\s*inject|command\s*execution|code\s*execution|arbitrary\s*code|os\s*command|webshell|web\s*shell/.test(
      s
    )
  )
    return true;
  // SSTI：仅当真模板/表达式注入；排除 XSS 文案里挂的「模板注入」括号说明
  if (/ssti|模板注入|template\s*injection/.test(s)) return true;
  if (
    /(反序列化|deserial|unserialize)/.test(s) &&
    /(\brce\b|代码执行|对象注入|object\s*injection|pop\s*chain|pop\s*gadget|远程代码|任意.{0,6}执行|getshell)/.test(
      s
    )
  )
    return true;
  // 文件上传/写入：必须写到可执行/webshell 结果。
  // 旧规则用裸 \.php 会把源码路径「playlist.php … .m3u 文件写入」误判成 RCE。
  if (
    /(文件上传|任意上传|arbitrary\s*upload|文件写入|任意文件写入|arbitrary\s*file\s*write|file\s*upload)/.test(
      s
    )
  ) {
    if (/(\brce\b|代码执行|webshell|web\s*shell|getshell|任意代码)/.test(s)) return true;
    // 结果是写入/创建 PHP 文件，而不是标题里碰巧出现的源码路径 xxx.php
    if (
      /(?:写入|创建|上传|生成).{0,40}(?:php\s*文件|\.php\b|webshell)|(?:php\s*文件|webshell).{0,24}(?:写入|创建|上传|生成)/i.test(
        s
      )
    )
      return true;
  }
  return false;
}

export function isStrictHttpRemoteVerified(localResult: unknown): { ok: boolean; reason: string } {
  const r = String(localResult || '').trim();
  if (!r || r.length < 60) {
    return { ok: false, reason: '验证记录过短或为空' };
  }
  const reject: Array<[RegExp, string]> = [
    [/远程验证未产出|子智能体遗漏|落盘失败/i, '远程验证未产出或落盘失败'],
    [/源码分析确认|【源码分析|代码审计确认|静态分析|静态追踪/i, '仅为源码/静态分析'],
    [/Java\s*沙箱|沙箱验证|BackupVerify\.java|模拟验证|harness/i, 'Java/沙箱模拟非 HTTP 靶机'],
    [/^success$/i, '仅有 success 无过程'],
    [/^验证成功\.?$/i, '仅有「验证成功」无 HTTP 证据'],
    [/GET\s+\/source\/src\//i, '仅拉取源码文件非漏洞利用'],
    [/Console Locked|需要PIN解锁/i, '调试控制台 PIN 锁定，未证明 RCE'],
    [/mini:\/\//i, '最小运行时伪远程，非 Compose HTTP 靶机'],
    [/官方.{0,24}-cli\s*镜像|php:8\.3-cli|mode\s*=\s*mini/i, '最小运行时官方 CLI 镜像 PoC，非 HTTP 靶机'],
  ];
  for (const [re, why] of reject) {
    if (re.test(r)) return { ok: false, reason: why };
  }
  // 必须出现真实 HTTP 交互痕迹（请求行 / 靶机 URL / curl / 状态码 / 中文 HTTP 请求响应表述），
  // 否则可能是纯代码叙述——这是"是否真的打过靶机"的底线信号。
  // 另外放行「时间盲注/侧信道」证据：文本明确给出耗时对比数据 + sleep 类注入语句，
  // 属于无回显但可通过时间差证明的远程命令执行（例如靠 $(sleep N) 使响应延迟可测量地增长），
  // 不应被要求额外出现字面量 HTTP 状态码/方法才算数。
  const httpInteraction =
    /HTTP\s*(?:\/1\.[01]\s*)?\d{3}/i.test(r) ||
    /http:\/\/(?:localhost|127\.0\.0\.1):\d+/i.test(r) ||
    /\b(?:POST|GET|PUT|DELETE)\s+\/[a-zA-Z0-9/_?=&.\-{}]+/i.test(r) ||
    /\bcurl\b/i.test(r) ||
    /HTTP\s*(?:请求|响应)/i.test(r) ||
    (/(?:耗时|延迟|响应时间)/i.test(r) && /sleep\s*\d+|时间旁路|时间盲注|\bblind\b/i.test(r));
  // 必须出现"利用真正成功/拿到危害证据"的正向信号——仅有请求痕迹不够，
  // 避免把"发过请求但被拦/报错/仅代码可达"的记录误算作前台 RCE。
  const successSignal =
    /HTTP\s*(?:\/1\.[01]\s*)?(?:200|201|202|204|301|302)\b/i.test(r) ||
    /返回\s*(?:HTTP\s*)?(?:200|201|202|204|301|302)/i.test(r) ||
    /(?:验证成功|利用成功|执行成功|注入成功|上传成功|写入成功|包含成功|复现成功|攻击成功|远程代码执行成功|成功(?:利用|执行|注入|写入|上传|获取|读取|验证|拿到|返回|加载|创建|实现|完成|复现|证明))/i.test(
      r
    ) ||
    /File uploaded successfully/i.test(r) ||
    /RCE_SUCCESS|TEEMII_RCE|teemii_rce|POC_INJECTED|VULN_VERIFIED|RCE_CONFIRMED|\bpwned\b|PROOF/i.test(r) ||
    /uid=\d+\(|gid=\d+\(|\broot@|\bwhoami\b/i.test(r) ||
    /UNION\s+SELECT[\s\S]{0,120}(?:@@version|database\(\)|user\(\)|MySQL|root@)/i.test(r) ||
    /\/tmp\/[\w.\-]*(?:rce|poc|pwned|proof|vuln)/i.test(r) ||
    /ExploitAgent\.dll[\s\S]{0,80}(?:Upload|上传|6144)/i.test(r) ||
    /IndexedDB[\s\S]{0,200}(?:注入|plugins|localforage)/i.test(r);
  if (!httpInteraction) {
    return { ok: false, reason: 'local_result 无 HTTP 请求/响应痕迹（疑似仅代码分析）' };
  }
  if (!successSignal) {
    return { ok: false, reason: 'local_result 无利用成功的正向证据（仅有请求痕迹不足以证明 RCE）' };
  }
  return { ok: true, reason: 'HTTP 靶机验证' };
}

export function matchExploitByTitle(
  title: string,
  exploits: any[],
  preferredAuth?: string | null
): any | null {
  const nt = normTitleKey(title);
  const candidates: any[] = [];
  for (const ex of exploits) {
    const en = normTitleKey(ex?.vulnerability || '');
    if (!en) continue;
    // 收紧匹配，避免"前 12 字符相同"把不同漏洞的 exploit 误配进来：
    // 1) 完全相等；2) 短标题是长标题子串且短标题足够长(>=10)；
    // 3) 两侧公共前缀完全一致且前缀足够长(>=16)。
    let hit = false;
    if (en === nt) {
      hit = true;
    } else {
      const shorter = en.length <= nt.length ? en : nt;
      const longer = en.length <= nt.length ? nt : en;
      if (shorter.length >= 10 && longer.includes(shorter)) {
        hit = true;
      } else {
        const plen = Math.min(en.length, nt.length, 24);
        if (plen >= 16 && en.slice(0, plen) === nt.slice(0, plen)) hit = true;
      }
    }
    if (hit) candidates.push(ex);
  }
  if (candidates.length === 0) return null;
  if (preferredAuth != null && preferredAuth !== '') {
    const pref = String(preferredAuth).toLowerCase();
    const hit = candidates.find((c) => String(c.auth_required || '').toLowerCase() === pref);
    if (hit) return hit;
  }
  return candidates[0];
}

type VulnLike = {
  title?: string | null;
  category?: string | null;
  auth_required?: string | null;
  verified?: number;
};

function baseRemoteRceOk(vuln: VulnLike, exploit: any | null): boolean {
  if (vuln.verified !== 1) return false;
  if (!exploit || deriveRemoteStatus(exploit) !== 'success') return false;
  if (!isRceClassStrictTitle(vuln)) return false;
  return isStrictHttpRemoteVerified(exploit.local_result).ok;
}

/** 无权限 + 远程 HTTP 验证 RCE */
export function qualifiesStrictUnauthHttpRce(vuln: VulnLike, exploit: any | null): boolean {
  if (!baseRemoteRceOk(vuln, exploit)) return false;
  if (String(exploit.auth_required || '').toLowerCase() !== 'none') return false;
  if (String(vuln.auth_required || '').toLowerCase() !== 'none') return false;
  return true;
}

/** 注册默认开放 + 普通用户权限 + 远程 HTTP 验证 RCE */
export function qualifiesRegOpenUserHttpRce(
  vuln: VulnLike,
  exploit: any | null,
  regDefaultOpen: boolean
): boolean {
  if (!regDefaultOpen) return false;
  if (String(vuln.auth_required || '').toLowerCase() !== 'user') return false;
  if (!baseRemoteRceOk(vuln, exploit)) return false;
  const exAuth = String(exploit.auth_required || '').toLowerCase();
  // 验证记录有时落在 auth=none（如 IndexedDB 注入），漏洞本身仍属 user 权限 RCE
  if (exAuth !== 'user' && exAuth !== 'none') return false;
  return true;
}

/** frontend_rce=1：无权限 RCE 或（注册开放 + user 权限 RCE），均需远程 HTTP 验证 */
export function qualifiesFrontendRce(
  vuln: VulnLike,
  exploits: any[],
  regDefaultOpen: boolean
): boolean {
  return frontendRceKind(vuln, exploits, regDefaultOpen) != null;
}

export type FrontendRceKind = 'none' | 'user';

/** user 路径：优先 auth=user 且 HTTP 通过的 exploit，否则同标题 auth=none 的 HTTP 验证记录 */
export function pickUserPathExploit(title: string, exploits: any[]): any | null {
  const exUser = matchExploitByTitle(title, exploits, 'user');
  if (
    exUser &&
    deriveRemoteStatus(exUser) === 'success' &&
    isStrictHttpRemoteVerified(exUser.local_result).ok
  ) {
    return exUser;
  }
  const exNone = matchExploitByTitle(title, exploits, 'none');
  if (
    exNone &&
    deriveRemoteStatus(exNone) === 'success' &&
    isStrictHttpRemoteVerified(exNone.local_result).ok
  ) {
    return exNone;
  }
  return exUser || exNone || null;
}

export function frontendRceKind(
  vuln: VulnLike,
  exploits: any[],
  regDefaultOpen: boolean
): FrontendRceKind | null {
  const exNone = matchExploitByTitle(vuln.title || '', exploits, 'none');
  if (qualifiesStrictUnauthHttpRce(vuln, exNone)) return 'none';
  if (regDefaultOpen && String(vuln.auth_required || '').toLowerCase() === 'user') {
    const exUser = pickUserPathExploit(vuln.title || '', exploits);
    if (qualifiesRegOpenUserHttpRce(vuln, exUser, true)) return 'user';
  }
  return null;
}

export function pickFrontendRceExploit(
  title: string,
  exploits: any[],
  kind: FrontendRceKind
): any | null {
  if (kind === 'user') return pickUserPathExploit(title, exploits);
  return matchExploitByTitle(title, exploits, 'none');
}
