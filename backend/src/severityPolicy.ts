import type { Severity } from './types';

export interface SeverityPolicyInput {
  title?: unknown;
  category?: unknown;
  description?: unknown;
  recommendation?: unknown;
  code_snippet?: unknown;
  snippet?: unknown;
  taint_chain?: unknown;
  auth_required?: unknown;
  severity?: unknown;
  severity_original?: unknown;
  /**
   * 兼容字段：历史流程曾用它做“高危保护”的基线。现已去除高危保护，
   * 红队二次验证的实战评级不再被强制拉回，这里仅保留以兼容旧调用点。
   */
  policy_baseline_severity?: unknown;
  regrade_reason?: unknown;
}

export interface SeverityPolicyResult {
  severity: Severity;
  severityOriginal: Severity | null;
  regradeReason: string | null;
  changed: boolean;
  ruleId: string | null;
  reason: string | null;
  /** 兼容字段：高危保护已移除，恒为 false。 */
  protected: boolean;
}

interface PolicyContext {
  title: string;
  category: string;
  description: string;
  regradeReason: string;
  primary: string;
  full: string;
}

interface PolicyRule {
  id: string;
  target: Severity;
  reason: string;
  matches: (ctx: PolicyContext) => boolean;
}

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const REAL_TEAM_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '无',
};

function text(value: unknown): string {
  return String(value ?? '').replace(/\s+/g, ' ').trim();
}

export function normalizeSeverity(value: unknown): Severity {
  const raw = text(value).toLowerCase();
  if (raw === 'critical' || raw.includes('严重') || raw.includes('crit')) return 'critical';
  if (raw === 'high' || raw.includes('高危') || raw.includes('high')) return 'high';
  if (
    raw === 'medium' ||
    raw === 'moderate' ||
    raw.includes('中危') ||
    raw.includes('medium') ||
    raw.includes('moderate')
  ) {
    return 'medium';
  }
  if (raw === 'low' || raw.includes('低危') || raw.includes('low')) return 'low';
  return 'info';
}

export function realTeamLabel(severity: unknown): string {
  return REAL_TEAM_LABEL[normalizeSeverity(severity)];
}

function makeContext(input: SeverityPolicyInput): PolicyContext {
  const title = text(input.title);
  const category = text(input.category);
  const description = text(input.description);
  const regradeReason = text(input.regrade_reason);
  const primary = [title, category].filter(Boolean).join(' ');
  const full = [
    title,
    category,
    description,
    text(input.recommendation),
    text(input.code_snippet),
    text(input.snippet),
    text(input.taint_chain),
    text(input.auth_required),
  ]
    .filter(Boolean)
    .join(' ');
  return { title, category, description, regradeReason, primary, full };
}

function matchesAny(value: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(value));
}

function capSeverity(current: Severity, maximum: Severity): Severity {
  return SEVERITY_RANK[current] > SEVERITY_RANK[maximum] ? maximum : current;
}

function appendReason(existing: unknown, marker: string, reason: string): string {
  const previous = text(existing);
  if (previous.includes(marker)) return previous;
  return previous ? `${previous}\n${marker} ${reason}` : `${marker} ${reason}`;
}

/* ---------------------------------------------------------------------------
 * 低价值降级规则（“没有实战价值的洞”封顶）。
 * 这些规则只做封顶（cap），绝不升级；不匹配则完全保持红队评级现状。
 * ------------------------------------------------------------------------- */

const RESOURCE_STABILITY_PATTERNS = [
  /内存泄漏|线程泄漏|连接泄漏|连接池耗尽|文件描述符泄漏|句柄泄漏|进程泄漏|后台进程泄漏|僵尸进程|孤儿进程|进程表(?:耗尽|打满|泄漏)|线程池泄漏/i,
  /超时后.{0,30}(?:进程|线程|任务|后台进程).{0,30}(?:未退出|未终止|残留|泄漏)/i,
  /无界线程池|无限线程池|任务队列(?:无限|无界|堆积)|缓存(?:无限|无界)增长/i,
  /日志(?:无限|无界)增长|临时文件.{0,40}(?:未及时清理|长期保留|堆积)/i,
  /CPU\s*(?:高占用|耗尽|打满)|内存耗尽|内存溢出|\bOOM\b|Out\s*Of\s*Memory/i,
  /请求体.{0,60}(?:无上限|无限制).{0,60}(?:内存|OOM|耗尽)/i,
  /磁盘耗尽|磁盘写满|普通\s*Zip\s*Bomb|解压炸弹|压缩炸弹/i,
  /无限循环|死循环|递归过深|无界递归|栈溢出|Stack\s*Overflow/i,
  /慢查询.{0,50}(?:资源|连接|线程|占用|耗尽)/i,
  /(?:SSE|WebSocket).{0,70}(?:连接.{0,20}(?:无上限|无限制|无限积累|永不超时)|无连接数上限|资源耗尽)/i,
  /缺少.{0,25}(?:HTTP|数据库|外部命令|外部请求)?.{0,20}超时|无超时|未设置超时|永久阻塞/i,
  /\bReDoS\b|正则.{0,40}(?:灾难性回溯|拒绝服务|CPU)|Catastrophic\s*Backtracking/i,
  /Panic|未捕获异常|Unhandled\s*Exception/i,
  /\bDoS\b|DDoS|拒绝服务|服务不可用|资源耗尽/i,
];

const DEV_SERVER_CONFIG_PATTERNS = [
  /内置开发服务器|Built-in\s*(?:Development\s*)?Server/i,
  /\bphp\s+-S\b|php\s+artisan\s+serve|django(?:\.manage)?\s+runserver/i,
  /(?:生产环境|Dockerfile|容器).{0,40}(?:开发服务器|内置服务器|artisan\s+serve)/i,
  /(?:开发服务器|内置服务器|artisan\s+serve).{0,40}(?:生产|Dockerfile|容器)/i,
  /Not\s*Production-Ready|非生产级(?:Web)?服务器|不适合生产/i,
];

const CONFIG_INFO_PATTERNS = [
  /缺少.{0,30}(?:X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy|安全响应头)/i,
  /(?:X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy).{0,25}(?:缺失|未设置)/i,
  /CSP.{0,35}(?:缺失|未配置|过宽)|Content-Security-Policy.{0,30}(?:缺失|未设置)/i,
  /Cookie.{0,45}(?:Secure|HttpOnly|SameSite).{0,30}(?:缺失|缺少|未设置|不安全)/i,
  /Cookie.{0,30}(?:缺失|缺少|未设置).{0,30}(?:Secure|HttpOnly|SameSite)/i,
  /(?:Server\s*Banner|服务器横幅|框架版本|版本号|技术栈|服务指纹).{0,30}(?:泄露|暴露)/i,
  /(?:调试错误栈|堆栈信息|绝对路径|详细错误|详细报错).{0,30}(?:泄露|暴露)/i,
  /(?:Swagger|OpenAPI|API\s*文档).{0,30}(?:公开|暴露)/i,
  /Source\s*Map.{0,30}(?:公开|暴露|泄露)|robots\.txt|构建信息|目录结构暴露/i,
  /(?:内网|开发环境|测试环境|localhost).{0,50}(?:TLS|SSL|加密套件).{0,30}(?:弱|过时|不安全)/i,
  /日志.{0,30}(?:普通请求参数|非敏感参数|一般参数)/i,
  ...DEV_SERVER_CONFIG_PATTERNS,
];

const WEAK_CONTROL_PATTERNS = [
  /缺少(?:速率限制|限流)|未配置(?:速率限制|限流)|无(?:速率限制|限流)|Rate\s*Limit/i,
  /(?:限流|速率限制).{0,25}(?:功能)?(?:已禁用|未启用|关闭)/i,
  /用户名枚举|账户枚举|账号枚举/i,
  /密码策略.{0,30}(?:偏弱|过弱|不足)|密码复杂度.{0,25}(?:不足|缺失|过低)/i,
  /验证码.{0,25}(?:缺失|未启用|可绕过)|缺少验证码/i,
  /防爆破.{0,25}(?:不足|缺失|未启用)|暴力破解防护.{0,25}(?:不足|缺失)/i,
  /会话过期时间.{0,25}(?:过长|未限制)|Token.{0,35}(?:登出后|注销后).{0,20}(?:未吊销|仍有效)/i,
  /重放保护.{0,35}(?:不足|缺失)|Replay\s*Protection/i,
  /CORS.{0,45}(?:过宽|通配|任意来源|配置不当|缺失)|跨域.{0,35}(?:过宽|通配|任意来源)/i,
  // CSRF 缺防护 / formhash 被注释 / 登出 CSRF：实战多为强制下线，封顶 low
  /CSRF.{0,50}(?:缺失|未启用|无防护|被注释|已禁用|注释禁用|未携带|未附加|未提交|未校验|未包含)|缺少\s*CSRF|无\s*CSRF\s*(?:Token|防护|校验)|未(?:携带|包含|附加)\s*CSRF/i,
  /(?:登出|logout).{0,50}CSRF|CSRF.{0,50}(?:登出|logout|强制下线)/i,
  /formhash.{0,40}(?:注释|禁用|被注释|验证被)/i,
  /开放重定向|Open\s*Redirect/i,
  /Host\s*Header.{0,40}(?:信任|注入|未校验)/i,
];

/**
 * 强影响护栏：命中这些"真高危"语义时，下方【新增】的低价值封顶规则一律不生效，
 * 避免把"硬编码密钥可伪造令牌 / Host 头注入致 LFI / CORS 携带凭据脱敏数据"等真漏洞误压级。
 * 仅作用于新增规则（credential-lifecycle / transport-tls / configuration-headers / cors-open），
 * 不影响既有规则的既定行为。
 */
const STRONG_IMPACT_GUARD = [
  /\bRCE\b|远程代码执行|任意代码执行|代码执行|命令执行|命令注入|get\s*shell|webshell|web\s*shell/i,
  /SQL\s*注入|反序列化|SSTI|模板注入|\bXXE\b|对象注入/i,
  /任意文件\s*(?:读取|写入|读写|删除|上传|包含)|路径穿越|目录穿越|\bLFI\b|\bRFI\b/i,
  /脱库|拖库|批量(?:导出|下载)[^。\n]{0,6}(?:用户|数据)|越权[^。\n]{0,6}(?:获取|读取|修改|删除|访问)|他人(?:数据|信息|订单|账户|账号)/i,
  /接管|完全(?:接管|控制)|提权|权限提升|身份伪造/i,
  // 伪造/仿冒 身份·令牌·会话（中间可夹"任意/长期有效"等词）——凭据可被伪造即真高危
  /(?:伪造|仿冒|冒充)[^。\n]{0,12}(?:身份|用户|管理员|令牌|token|凭据|凭证|会话|session|jwt|cookie|请求)/i,
  /密码重置[^。\n]{0,6}(?:劫持|投毒|接管)|账号接管|account\s*takeover/i,
  // 硬编码密钥/口令（正反语序都算）：可离线破解或直接伪造凭据，属真高危
  /硬编码[^。\n]{0,10}(?:密钥|密码|口令|token|凭据|凭证|secret|key|私钥|api\s*key)/i,
  /(?:密钥|密码|口令|token|凭据|凭证|secret|私钥|api\s*key)[^。\n]{0,6}硬编码/i,
];

/**
 * 凭据/会话生命周期缺陷：令牌永不过期、无吊销/撤销机制、会话时长过长——
 * 纯生命周期问题（无账号接管或凭据放大），实战价值有限，封顶 low。
 */
const CREDENTIAL_LIFECYCLE_PATTERNS = [
  /(?:令牌|token|凭证|凭据|会话|session|jwt|bearer|cookie).{0,24}(?:永不过期|永久有效|不过期|无过期时间|未设(?:置|定)?过期|缺(?:少|失).{0,6}过期|长期有效|无有效期|无失效时间|不(?:会)?失效|无(?:主动)?(?:失效|撤销|吊销)机制)/i,
  /(?:永不过期|永久有效|无过期时间|未设(?:置|定)过期|无有效期).{0,20}(?:令牌|token|凭证|凭据|会话|session|jwt|bearer)/i,
  /(?:登出|注销|logout).{0,16}(?:令牌|token|会话|session)?.{0,8}(?:未|不|没有).{0,4}(?:吊销|失效|撤销|回收|清除)/i,
  /(?:会话|session).{0,6}(?:过期时间|有效期|超时时间|生命周期).{0,10}(?:过长|过久|未限制|太长)/i,
];

/**
 * 传输层未强制加密：未强制 HTTPS、SSL/HTTPS 重定向关闭、凭证明文传输配置——
 * 属部署/配置层，无直接可利用后果，封顶 low。
 */
const TRANSPORT_TLS_PATTERNS = [
  /(?:未|不|没有|缺(?:少|失)?|默认(?:未|不|关闭|禁用)).{0,6}强制.{0,6}HTTPS/i,
  /HTTPS.{0,10}(?:强制)?.{0,8}(?:默认)?(?:关闭|禁用|未开启|未强制|不开启)/i,
  /强制\s*HTTPS.{0,10}(?:关闭|禁用|默认关闭|未开启)/i,
  /\b(?:APP_FORCE_HTTPS|force_login_ssl|force_ssl|REDIRECT_TO_HTTPS)\b/i,
  /(?:HTTPS|SSL|TLS).{0,8}(?:重定向|跳转).{0,8}(?:缺失|未|禁用|关闭|默认关闭)/i,
  /(?:缺(?:少|失)?|未|没有).{0,6}(?:HTTPS|SSL|TLS).{0,6}(?:强制)?(?:跳转|重定向)/i,
  /(?:凭证|密码|会话|cookie).{0,10}(?:明文|未加密).{0,6}(?:传输|传送)/i,
];

/**
 * 缺安全响应头 / CSP（含点击劫持面）——扩展匹配（缺失/缺少、正反语序）。
 * 无可利用 XSS 或凭据泄露时属低价值配置，定为 info。CSP "注入" 类不在此列（另属真漏洞）。
 */
const CONFIG_HEADER_EXT_PATTERNS = [
  /(?:缺(?:少|失)|未设置|未配置|没有|缺乏).{0,20}(?:X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy|HSTS|Strict-Transport-Security|Content-Security-Policy|\bCSP\b|安全响应头|安全(?:响应)?头部)/i,
  /(?:X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy|Content-Security-Policy|\bCSP\b|HSTS|安全响应头).{0,12}(?:缺(?:少|失)|未设置|未配置|不完整)/i,
  /点击劫持|clickjacking/i,
];

/**
 * CORS 过宽/回显 Origin——仅在【不涉及凭据与敏感数据窃取】时封顶 low。
 * 携带凭据 + 敏感数据跨域窃取的完整链属真高危（CORS_CREDENTIAL_GUARD 命中即不降级）。
 */
const CORS_EXT_PATTERNS = [
  /CORS.{0,45}(?:过宽|通配|任意来源|配置不当|配置错误|错误配置|缺陷|缺失|反射\s*Origin|回显\s*Origin|Origin\s*反射)/i,
  /Access-Control-Allow-Origin.{0,20}(?:\*|反射|回显|任意)/i,
  /跨域.{0,30}(?:过宽|通配|任意来源|配置错误|配置不当)/i,
];
const CORS_CREDENTIAL_GUARD =
  /携带(?:认证)?凭据|allow-credentials|with\s*credentials|凭据泄露|凭证泄露|敏感(?:数据|信息)|窃取|token\s*泄露|Cookie\s*泄露|认证凭据|credentials\s*[:=]?\s*true/i;

/**
 * Sink 级 SSRF / 不安全 HTTP 客户端原语：只描述底层库函数缺陷，
 * 未给出「用户可控 URL → HTTP 入口」的完整打点链。实战意义有限，封顶 low。
 * 若标题已点名具体入口/可控参数（$_GET、Controller、iconnew 等），则不命中本规则。
 */
const SINK_PRIMITIVE_SSRF_PATTERNS = [
  /核心(?:网络)?函数.{0,80}(?:无协议|协议限制|跟随重定向|FOLLOWLOCATION|SSL\s*禁用)/i,
  /无协议限制.{0,40}跟随重定向/i,
  /_?dfsockopen[—–\-].{0,40}核心/i,
  /curl(?:\\_|\s*_|_|\s+)?file(?:\\_|\s*_|_|\s+)?get(?:\\_|\s*_|_|\s+)?contents.{0,120}(?:核心函数|无协议|跟随重定向|SSL)/i,
  /dzz(?:\\_|\s*_|_|\s+)?file(?:\\_|\s*_|_|\s+)?get(?:\\_|\s*_|_|\s+)?contents.{0,120}(?:核心函数|无协议|跟随重定向|SSL)/i,
  /curl(?:\\_|\s*_|_|\s+)?exec(?:\\_|\s*_|_|\s+)?redir[—–\-].{0,60}(?:重定向|未校验|IP)/i,
  /CURLOPT_FOLLOWLOCATION.{0,50}SSRF/i,
  /自定义重定向.{0,40}(?:未校验|未验证).{0,20}(?:IP|目标)/i,
  /HTTP\s*客户端.{0,40}(?:无协议限制|未限制协议|跟随重定向)/i,
];

/** 仅当【标题】点名具体 HTTP 入口/可控参数时，才视为完整打点链（不看 description 里的可达性讨论）。 */
const SSRF_ENTRY_IN_TITLE = [
  /\$_(?:GET|POST|REQUEST|COOKIE|FILES)/i,
  /\b(?:iconnew|FileUrl|file_url|imageurl|image_url|remote_url|callback|webhook)\b/i,
  /BBCode|parseflv|imagetolocal|getStream/i,
  /(?:Controller|Servlet|Handler)\b/i,
  /admin\/[^\s]+\.php|user\/[^\s]+\.php/i,
  /(?:URL|url|链接|地址).{0,20}(?:参数|可控)/i,
  /(?:用户|外部|请求).{0,12}(?:可控|传入|提供).{0,20}(?:URL|url|链接)/i,
  /class(?:\\_|_)image\.php/i,
];


const LOW_IMPACT_FRONTEND_PATTERNS = [
  /反射型\s*XSS|Reflected\s*XSS/i,
  /console\.log.{0,45}(?:普通|非敏感|调试)数据/i,
  /localStorage.{0,45}(?:非敏感|普通配置|界面配置)/i,
  /target\s*=\s*["']?_blank["']?.{0,40}(?:noopener|noreferrer).{0,20}(?:缺失|未设置)/i,
  /客户端参数校验.{0,45}(?:缺失|不足).{0,40}服务端.{0,20}(?:已校验|有校验)/i,
  /仅客户端.{0,30}(?:崩溃|卡死|拒绝服务)|页面(?:崩溃|卡死)/i,
  /前端依赖.{0,30}(?:版本旧|过时).{0,50}(?:未确认|没有确认|不可达)/i,
  /DOM\s*污染.{0,60}(?:无危险\s*Sink|没有危险\s*Sink|不可利用|纯理论)/i,
];

const THEORETICAL_PATTERNS = [
  /(?:仅|纯).{0,12}(?:理论|假设|代码质量)|理论性(?:风险|问题)/i,
  /输入.{0,20}(?:不可控|无法控制|不受外部控制)|仅由内部数据触发/i,
  /(?:受影响功能|漏洞涉及功能|存在缺陷的功能).{0,20}(?:未启用|已禁用)|代码(?:路径)?.{0,20}(?:不可达|未调用)/i,
  /受影响功能.{0,25}(?:未启用|不可达)|CVE.{0,45}(?:功能未启用|代码不可达|无法触发)/i,
  /未确认.{0,20}(?:可达|可利用|受影响)|没有确认.{0,20}(?:可达|可利用)/i,
  /敏感函数.{0,35}(?:参数不可控|输入不可控)|参数完全不可控/i,
  /使用弃用\s*API|Deprecated\s*API|异常处理不足/i,
  /潜在竞态.{0,60}(?:无法|不能).{0,25}(?:影响安全状态|权限|认证)/i,
  /整数溢出.{0,50}(?:输入不可控|无法由外部触发)/i,
  /(?:unwrap|空指针|NullPointer).{0,45}(?:内部数据|不可控|无法由外部触发)/i,
];

const POLICY_RULES: readonly PolicyRule[] = [
  {
    id: 'low.resource-stability',
    target: 'low',
    reason: '纯资源或稳定性问题，不产生代码执行、数据读写、权限突破或敏感信息影响',
    matches: (ctx) => matchesAny(ctx.primary, RESOURCE_STABILITY_PATTERNS),
  },
  {
    id: 'low.weak-control',
    target: 'low',
    reason: '弱防护未形成账号接管、敏感操作或数据泄露等直接利用后果',
    matches: (ctx) => matchesAny(ctx.primary, WEAK_CONTROL_PATTERNS),
  },
  {
    id: 'low.sink-ssrf-primitive',
    target: 'low',
    reason:
      '仅为 HTTP 客户端/SSRF Sink 原语缺陷（无协议限制、跟随重定向等），未证明用户可控 URL 经 HTTP 入口可达；实战价值按 low 封顶',
    matches: (ctx) => {
      if (!matchesAny(ctx.title, SINK_PRIMITIVE_SSRF_PATTERNS) && !matchesAny(ctx.primary, SINK_PRIMITIVE_SSRF_PATTERNS)) {
        return false;
      }
      // 仅标题点名具体入口/可控参数时保留原级；description 里的「可达性讨论」不构成例外
      if (matchesAny(ctx.title, SSRF_ENTRY_IN_TITLE)) return false;
      return true;
    },
  },
  {
    id: 'low.frontend',
    target: 'low',
    reason: '前端低影响问题未形成持久化执行、账号接管或敏感数据影响',
    matches: (ctx) => matchesAny(ctx.primary, LOW_IMPACT_FRONTEND_PATTERNS),
  },
  {
    id: 'info.configuration',
    target: 'info',
    reason: '低价值安全配置或纯信息暴露，未包含凭据和可利用链',
    matches: (ctx) => matchesAny(ctx.primary, CONFIG_INFO_PATTERNS),
  },
  {
    id: 'low.credential-lifecycle',
    target: 'low',
    reason:
      '仅令牌/会话生命周期缺陷（永不过期、无吊销/撤销、会话时长过长），未证明可直接账号接管或凭据伪造，实战价值按 low 封顶',
    matches: (ctx) =>
      !matchesAny(ctx.primary, STRONG_IMPACT_GUARD) &&
      matchesAny(ctx.primary, CREDENTIAL_LIFECYCLE_PATTERNS),
  },
  {
    id: 'low.transport-tls',
    target: 'low',
    reason:
      '仅传输层未强制加密（未强制 HTTPS/SSL 重定向关闭），属部署配置弱点，无直接可利用后果，封顶 low',
    matches: (ctx) =>
      !matchesAny(ctx.primary, STRONG_IMPACT_GUARD) &&
      matchesAny(ctx.primary, TRANSPORT_TLS_PATTERNS),
  },
  {
    id: 'low.cors-open',
    target: 'low',
    reason:
      'CORS 过宽/回显 Origin，但未证明携带凭据 + 敏感数据的完整跨域窃取链，按 low 封顶（涉及凭据/敏感数据窃取的不在此列）',
    matches: (ctx) =>
      !matchesAny(ctx.primary, STRONG_IMPACT_GUARD) &&
      !CORS_CREDENTIAL_GUARD.test(ctx.full) &&
      matchesAny(ctx.primary, CORS_EXT_PATTERNS),
  },
  {
    id: 'info.security-headers',
    target: 'info',
    reason: '仅缺少安全响应头/CSP（含点击劫持面），无可利用 XSS 或凭据泄露，定为 info',
    matches: (ctx) =>
      !matchesAny(ctx.primary, STRONG_IMPACT_GUARD) &&
      matchesAny(ctx.primary, CONFIG_HEADER_EXT_PATTERNS),
  },
  {
    id: 'info.theoretical',
    target: 'info',
    reason: '仅理论、不可达或不受外部输入控制，缺少现实攻击路径',
    matches: (ctx) => matchesAny(ctx.full, THEORETICAL_PATTERNS),
  },
];

function findPolicyRule(ctx: PolicyContext): PolicyRule | null {
  return POLICY_RULES.find((rule) => rule.matches(ctx)) ?? null;
}

/**
 * 确定性严重度护栏（已去除高危保护）：
 * 1. 红队二次验证的实战评级为准，本函数不再把高危类别强制拉回原等级；
 * 2. 仅对明确命中的低价值类别做封顶（cap），绝不升级；
 * 3. 不匹配则完全保持红队评级现状。
 */
export function applySeverityPolicy(input: SeverityPolicyInput): SeverityPolicyResult {
  const current = normalizeSeverity(input.severity);
  const originalRaw = text(input.severity_original);
  const original = originalRaw ? normalizeSeverity(originalRaw) : null;
  const ctx = makeContext(input);

  const rule = findPolicyRule(ctx);
  if (!rule) {
    return {
      severity: current,
      severityOriginal: original,
      regradeReason: text(input.regrade_reason) || null,
      changed: false,
      ruleId: null,
      reason: null,
      protected: false,
    };
  }

  const finalSeverity = capSeverity(current, rule.target);
  const changed = finalSeverity !== current;
  const marker = `[自动降级:${rule.id}]`;
  return {
    severity: finalSeverity,
    severityOriginal: changed ? original ?? current : original,
    regradeReason: changed
      ? appendReason(input.regrade_reason, marker, rule.reason)
      : text(input.regrade_reason) || null,
    changed,
    ruleId: rule.id,
    reason: rule.reason,
    protected: false,
  };
}
