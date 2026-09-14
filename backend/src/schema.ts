export const AUDIT_LANGUAGES = [
  'java',
  'go',
  'python',
  'php',
  'jsts',
  'rust',
  'ruby',
  'csharp',
  'c',
  'cpp',
  'solidity',
] as const;
export type AuditLanguage = (typeof AUDIT_LANGUAGES)[number];

export const AUDIT_LANGUAGE_LABELS: Record<string, string> = {
  java: 'Java',
  go: 'Go',
  python: 'Python',
  php: 'PHP',
  jsts: 'JavaScript/TypeScript',
  rust: 'Rust',
  ruby: 'Ruby',
  csharp: 'C#/.NET',
  c: 'C',
  cpp: 'C++',
  solidity: 'Solidity',
};

export function isAuditLanguage(v: string): v is AuditLanguage {
  return (AUDIT_LANGUAGES as readonly string[]).includes(v);
}

/**
 * 每语言最多 4 路专项。CWE 面不减，相近漏洞合并进同一路。
 * 不含万能 `*-security-auditor` 收口桶。CWE 编号写在各路 mission 里。
 */
export const SUBAGENTS_BY_LANG: Record<AuditLanguage, readonly string[]> = {
  java: [
    'java-rce-security-guard',
    'java-sql-injection-guard',
    'java-file-security-auditor',
    'java-auth-audit-expert',
  ],
  go: [
    'go-rce-security-guard',
    'go-sql-injection-guard',
    'go-file-security-auditor',
    'go-auth-audit-expert',
  ],
  python: [
    'python-rce-security-guard',
    'python-sql-injection-guard',
    'python-file-security-auditor',
    'python-auth-audit-expert',
  ],
  php: [
    'php-command-executor',
    'php-file-system-auditor',
    'php-security-guard',
    'php-auth-auditor',
  ],
  jsts: [
    'jsts-rce-security-guard',
    'jsts-sql-injection-guard',
    'jsts-file-security-auditor',
    'jsts-auth-audit-expert',
  ],
  rust: [
    'rust-rce-security-guard',
    'rust-sql-injection-guard',
    'rust-memory-safety-auditor',
    'rust-auth-audit-expert',
  ],
  ruby: [
    'ruby-rce-security-guard',
    'ruby-sql-injection-guard',
    'ruby-file-security-auditor',
    'ruby-auth-audit-expert',
  ],
  csharp: [
    'csharp-rce-security-guard',
    'csharp-sql-injection-guard',
    'csharp-file-security-auditor',
    'csharp-auth-audit-expert',
  ],
  c: [
    'c-memory-corruption-auditor',
    'c-system-file-auditor',
    'c-injection-auditor',
    'c-concurrency-race-auditor',
  ],
  cpp: [
    'cpp-memory-corruption-auditor',
    'cpp-system-file-auditor',
    'cpp-injection-auditor',
    'cpp-concurrency-race-auditor',
  ],
  solidity: [
    'solidity-reentrancy-auditor',
    'solidity-access-control-auditor',
    'solidity-arithmetic-auditor',
    'solidity-oracle-manipulation-auditor',
  ],
};

export function subagentsForLanguage(lang: string): string[] {
  if (!isAuditLanguage(lang)) return [];
  return [...SUBAGENTS_BY_LANG[lang]];
}

const SUBAGENT_MISSION: Record<string, string> = {
  'java-rce-security-guard':
    'CWE-78/CWE-94/CWE-917 代码执行面：Runtime.exec、ProcessBuilder、ScriptEngine、GroovyShell；SpEL/OGNL/EL/MVEL/JNDI/LDAP；Nacos/Apollo 远程配置进表达式或 JNDI 数据源。',
  'java-sql-injection-guard':
    'CWE-89/CWE-918 注入面：Statement/MyBatis `${}`/JPA nativeQuery/JdbcTemplate 拼接；URL/HttpClient/RestTemplate/OkHttp 对用户 URL 的 SSRF。',
  'java-file-security-auditor':
    'CWE-22/CWE-434 文件面：路径穿越、任意读写上传、Zip Slip（ZipEntry/JarFile 解压到 webroot）。',
  'java-auth-audit-expert':
    'CWE-287/CWE-862/CWE-502/CWE-798 信任面：认证绕过/IDOR/Filter 漏挂；ObjectInputStream/XStream/Jackson 多态/SnakeYAML；硬编码密钥、Actuator 未鉴权。',
  'go-rce-security-guard':
    'CWE-78/CWE-94/CWE-1336 代码执行面：os/exec、syscall.Exec、plugin.Open；text/template、html/template 未转义或用户可控模板串。',
  'go-sql-injection-guard':
    'CWE-89/CWE-918 注入面：database/sql 拼接、GORM 裸 SQL；net/http、http.Get 对用户 URL 的 SSRF。',
  'go-file-security-auditor':
    'CWE-22/CWE-502 文件与解码面：os.Open/WriteFile、http.Dir、filepath.Join；encoding/gob、json.Unmarshal 进 interface{}、yaml.Unmarshal。',
  'go-auth-audit-expert':
    'CWE-287/CWE-862/CWE-798/CWE-362/CWE-400 信任与并发面：JWT/IDOR/中间件漏挂；硬编码密钥、TLS 跳过校验；无界 goroutine、channel 死锁 DoS。',
  'python-rce-security-guard':
    'CWE-78/CWE-94/CWE-1336 代码执行面：os.system/subprocess；Jinja2/Mako/Django 模板 SSTI、eval/exec。',
  'python-sql-injection-guard':
    'CWE-89/CWE-918 注入面：cursor.execute 拼接、SQLAlchemy text()、Django extra/raw；requests/urllib/httpx SSRF（含 file:// 与云元数据）。',
  'python-file-security-auditor':
    'CWE-22/CWE-434/CWE-502 文件与反序列化面：open/send_file/Path.joinpath；zipfile/tarfile.extractall；pickle.loads、yaml.load、marshal、shelve。',
  'python-auth-audit-expert':
    'CWE-287/CWE-862/CWE-798 信任面：Django/Flask 装饰器漏挂、越权；DEBUG=True、SECRET_KEY 硬编码。',
  'php-command-executor':
    'CWE-78/CWE-94/CWE-77 代码执行面：eval/system/passthru/proc_open/assert/preg_replace /e；Twig/Smarty SSTI；用户数据写入 .env/git/docker/k8s 后被执行。',
  'php-file-system-auditor':
    'CWE-98/CWE-22/CWE-434 文件面：include/require/php://filter LFI/RFI；fopen/move_uploaded_file/ZipArchive 路径穿越与上传。',
  'php-security-guard':
    'CWE-89/CWE-918 注入面：mysqli_query/PDO/`$wpdb->query` 拼接；file_get_contents/curl/fsockopen 对用户 URL 的 SSRF。',
  'php-auth-auditor':
    'CWE-287/CWE-862/CWE-502/CWE-798 信任面：会话固定/IDOR/未授权入口；unserialize/phar://；display_errors、弱 session、硬编码口令。',
  'jsts-rce-security-guard':
    'CWE-78/CWE-1336 代码执行面：child_process.exec/eval/Function/vm；EJS/Pug/Handlebars/Nunjucks SSTI。',
  'jsts-sql-injection-guard':
    'CWE-89/CWE-943/CWE-918 注入面：拼接 SQL、knex.raw、mongoose `$where`、prisma.$queryRaw；fetch/axios SSRF（含 169.254.169.254）。',
  'jsts-file-security-auditor':
    'CWE-22/CWE-434 文件面：fs.readFile、path.join、express.static、multer 路径穿越与任意上传。',
  'jsts-auth-audit-expert':
    'CWE-287/CWE-862/CWE-502/CWE-1321/CWE-798 信任面：JWT/越权/CORS；node-serialize 反序列化；lodash merge/`__proto__` 原型污染；硬编码密钥。',
  'rust-rce-security-guard':
    'CWE-78 命令执行。Sink：std::process::Command、Command::new("sh")。',
  'rust-sql-injection-guard':
    'CWE-89/CWE-918/CWE-22 注入与文件面：sqlx/diesel 拼接；reqwest/hyper SSRF；std::fs/tokio::fs 路径穿越。',
  'rust-memory-safety-auditor':
    'CWE-119/CWE-787/CWE-416/CWE-400 unsafe 越界/UAF；unwrap/expect/panic 可被外部输入触发导致 DoS。',
  'rust-auth-audit-expert':
    'CWE-862/CWE-798/CWE-502 信任面：extractor 漏用/IDOR；硬编码密钥、TLS 跳过；serde/bincode 不安全解码。',
  'ruby-rce-security-guard':
    'CWE-78/CWE-94/CWE-1336 代码执行面：system/exec/eval/`%x`；ERB/Slim/Haml SSTI。',
  'ruby-sql-injection-guard':
    'CWE-89/CWE-918 注入面：where("...#{id}")、find_by_sql、Arel.sql；Net::HTTP/open-uri/Faraday SSRF。',
  'ruby-file-security-auditor':
    'CWE-22/CWE-502/CWE-915 文件与对象面：File.read/send_file；Marshal/YAML/Oj.load；strong parameters 失效、批量赋值。',
  'ruby-auth-audit-expert':
    'CWE-862/CWE-798 信任面：before_action 漏挂、IDOR、Pundit 漏授权；secret_key_base 硬编码。',
  'csharp-rce-security-guard':
    'CWE-78/CWE-1336 代码执行面：Process.Start、CSharpCodeProvider、PowerShell；用户可控 Razor/视图名。',
  'csharp-sql-injection-guard':
    'CWE-89/CWE-918/CWE-611 注入面：SqlCommand 拼接、FromSqlRaw；HttpClient SSRF；XmlDocument/XmlReader XXE。',
  'csharp-file-security-auditor':
    'CWE-22/CWE-502 文件与反序列化面：Path.Combine/ZipFile；BinaryFormatter、TypeNameHandling、ObjectStateFormatter。',
  'csharp-auth-audit-expert':
    'CWE-862/CWE-798 信任面：Authorize 漏挂、JWT 误用、IDOR；连接字符串/密钥硬编码。',
  'c-memory-corruption-auditor':
    'CWE-119/CWE-787/CWE-125/CWE-416 缓冲区溢出、越界读写、UAF、double-free。',
  'c-system-file-auditor':
    'CWE-78/CWE-22/CWE-269/CWE-250 命令注入与文件路径；权限/能力丢落失败、ioctl 未校验、内核模块输入信任。',
  'c-injection-auditor':
    'CWE-134/CWE-89/CWE-327 格式化字符串、SQL/LDAP 拼接；弱随机、自制密码、非恒定时间比较。',
  'c-concurrency-race-auditor':
    'CWE-362/CWE-190/CWE-400/CWE-476 竞态与 TOCTOU；整数溢出、未检查 malloc、空指针、无限递归 DoS。',
  'cpp-memory-corruption-auditor':
    'CWE-119/CWE-416/CWE-843 越界、UAF、迭代器失效、类型混淆、错误智能指针生命周期。',
  'cpp-system-file-auditor':
    'CWE-78/CWE-22/CWE-269 命令注入与路径；权限丢落、驱动 ioctl、硬件接口输入信任。',
  'cpp-injection-auditor':
    'CWE-134/CWE-89/CWE-327 格式化与 SQL/命令拼接；弱密码学、非恒定时间比较。',
  'cpp-concurrency-race-auditor':
    'CWE-362/CWE-190/CWE-400 数据竞争、死锁；RAII/异常安全失败、整数溢出、未处理异常导致泄漏或 DoS。',
  'solidity-reentrancy-auditor':
    'CWE-841 SWC-107 重入（call/transfer/send 回调、CEI、非可重入锁）以及错误状态机、未更新存储、无界循环、强制发送 ETH 卡住合约。',
  'solidity-access-control-auditor':
    'CWE-284 SWC-105/115 访问控制：onlyOwner 漏挂、tx.origin、未初始化代理、delegatecall 权限。',
  'solidity-arithmetic-auditor':
    'CWE-190 SWC-101 溢出/下溢、除零、精度截断、份额计算错误。',
  'solidity-oracle-manipulation-auditor':
    'CWE-20/CWE-400 预言机与价格操纵（即时 AMM、单区块预言机、闪电贷）以及 Gas DoS。',
};

export function subagentMission(type: string): string {
  return SUBAGENT_MISSION[type] || '该语言对应类别的专项漏洞审计';
}

export const VULN_SCHEMA = {
  type: 'object',
  properties: {
    summary: {
      type: 'string',
      description: '本次审计的中文总体结论概述',
    },
    vulnerabilities: {
      type: 'array',
      description: '发现的所有安全漏洞列表',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string', description: '漏洞标题（中文）' },
          severity: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low', 'info'],
            description: '危害等级',
          },
          category: { type: 'string', description: '漏洞类别，如 SQL注入、XSS、命令注入等' },
          file: { type: 'string', description: '存在漏洞的相对文件路径' },
          line: { type: 'integer', description: '漏洞所在行号，未知填 0' },
          description: { type: 'string', description: '漏洞详细描述与成因（中文）' },
          recommendation: { type: 'string', description: '修复建议（中文）' },
          snippet: { type: 'string', description: '相关代码片段' },
          taint_chain: {
            type: 'string',
            description:
              '完整污点链（数据流类漏洞必填，适用于任意语言/框架）：从用户可控输入入口(Source)逐跳追踪到危险操作(Sink)，标注每一跳的“文件:行/函数”，用 → 连接；Source 与 Sink 的具体 API 按目标语言对应（如 PHP unserialize/include、Java ObjectInputStream/Runtime.exec、Python pickle.loads/os.system、Go os/exec、Node fs/child_process）。格式示例（仅示意，按实际语言替换）：入口 → 取参 → 中间传递/拼接(文件:行) → 危险操作(文件:行)。必须给出可逐跳复核的真实路径，不能只写结论；纯配置/硬编码类（无数据流）可留空。',
          },
        },
        required: ['title', 'severity', 'description'],
      },
    },
  },
  required: ['vulnerabilities'],
};

/**
 * 鉴权判定的通用防误判规则（代码层：审计/去重/评级/代码验证共用）。
 * 核心：同一 Sink 往往有【多条到达路径】，auth_required 必须取所有可达路径中的【最低权限】，
 * 而不是只看那条"看起来正常/声明了权限"的主入口。语言/框架无关。
 */
const AUTH_MULTIPATH_RULE = `  ⚠ **鉴权取最低权限、勿被主入口误导（防"误判需登录"）**：同一个危险操作(Sink)常有**多条跨文件到达路径**，其中很可能存在**未授权的旁路入口**——例如：另一处同义/别名入口、路由错位/批处理/合并接口(batch/bulk)把子请求当作已鉴权、schema/类型校验被绕过后走进同一底层、被公开(无鉴权)包装器复用的内部函数、注册/回调/webhook/RSS/REST 等匿名端点、或"正常入口有 permission_callback 但另一入口没有"。**auth_required 必须取【所有能到达该 Sink 的路径中权限最低的那一条】**：只要**存在任意一条无需登录即可到达 Sink 的路径**，就填 \`none\`，绝不能因为"主入口/常见入口需要 edit_posts 之类权限"就标成 user/admin。判 user/admin 前，必须用 Grep/Read 反向枚举**每一条**到达 Sink 的调用路径并逐条确认它们**都**有真正生效的鉴权；只要有一条没核实到或对匿名开放，就按 none 处理。**存疑一律往低权限判（none 优先），把是否真需登录交给远程实测复核。**`;

/**
 * 远程验证阶段的鉴权独立复核规则：**不信任代码层标注的 auth_required**。
 * 代码阶段的 auth_required 只是线索，可能把"其实未授权可达"误标成 user/admin；
 * 远程实测必须先以【匿名/零权限】打，打通就是 none，只有匿名确实失败才升级到登录态。
 */
function authRemoteIndependentRule(dir: string): string {
  return `# ⚠ 鉴权【不信任代码层标注、以真实源码+远程环境为准】
漏洞在代码审计阶段可能已被标注 auth_required（none/user/admin），但那来自**代码层静态判定，只是线索、可能误判**（常见是把"其实存在未授权旁路可达"的漏洞误标成需登录）。**远程验证时严禁直接采信任何代码层的"是否需要登录"结论**，必须以真实源码 + 远程环境自己重新判定：
1. **一律先用匿名/零权限实打**：不管代码层标注是 user 还是 admin，**都先在完全不登录、不带任何 Cookie/Token/Session 的状态下**发起真实利用请求。若匿名即可触发并产生真实危害 → auth_required 判 \`none\`（哪怕代码层标了 user/admin）。
2. **只有匿名确实失败，才升级到登录态复测**：先用普通账号（含开放注册自助获取的账号）再打；仍不行才用更高权限。auth_required 填**实际打通时所用的最低权限**。
3. **结合真实源码复核入口**：匿名失败时，回到 ${dir} 源码用 Grep/Read 反向枚举到达该 Sink 的**所有**跨文件路径，确认是否真有一条无鉴权旁路被你漏测（同义/别名入口、路由错位·批处理/合并接口、schema 绕过、公开包装器、注册/回调/webhook/REST 匿名端点）；有则据此再打一次。
4. **auth_required 与 local_result 必须一致且以远程实测为最终结论**：代码层说 user 但你匿名打通了，就写 none 并在 local_result 说明"代码层标注为需登录，实测匿名旁路可达"；反之代码层说 none 但你实测确需登录才写 user/admin，并说明卡在哪个鉴权环节。`;
}

/**
 * 历史版本验证结果 schema（单漏洞与组合链共用）。
 * 当前版本打不通/受限时，基于 git 提交记录定位该漏洞的"修复/防御引入提交"，
 * 推断修复之前的历史 release 是否存在该漏洞，并对代表版本做实测验证。
 */
const HISTORICAL_VERIFICATION_SCHEMA = {
  type: 'array',
  description:
    '历史版本验证结果：基于 git 提交记录定位该漏洞的修复/防御引入提交，判断并验证修复之前的历史版本是否可利用（当前版本打不通时尤为重要）。',
  items: {
    type: 'object',
    properties: {
      version: { type: 'string', description: '历史版本号或 tag（如 1.7.0）' },
      github_url: { type: 'string', description: '该版本对应的 GitHub 地址（tag/release 链接）' },
      status: {
        type: 'string',
        enum: ['success', 'failed', 'restricted', 'unknown'],
        description: '该历史版本的验证结果：success 可利用、failed 不可利用、restricted 受限、unknown 未知',
      },
      method: {
        type: 'string',
        enum: ['git_analysis', 'live_target'],
        description: '验证方式：git_analysis=基于提交记录与防御代码差异分析推断；live_target=真实搭建该版本靶机实测',
      },
      fix_commit: {
        type: 'string',
        description: '引入该漏洞防御/修复的 git 提交哈希或说明（用于界定可利用版本范围）',
      },
      reason: {
        type: 'string',
        description: '判定依据（中文）：基于哪个提交/防御代码差异得出，或真实搭靶实测的过程与证据',
      },
    },
    required: ['version', 'status'],
  },
};

export const EXPLOIT_SCHEMA = {
  type: 'object',
  properties: {
    summary: {
      type: 'string',
      description: '本次利用验证的中文总体结论概述',
    },
    exploits: {
      type: 'array',
      description: '针对每个漏洞的利用验证结果',
      items: {
        type: 'object',
        properties: {
          vulnerability_id: {
            type: 'string',
            description: '对应数据库漏洞的稳定 ID；输入清单提供时必须原样回填',
          },
          vulnerability: { type: 'string', description: '对应的漏洞标题（中文）' },
          local_exploitable: {
            type: 'string',
            enum: ['success', 'failed', 'restricted', 'unknown'],
            description: '本地环境利用结果：success 成功、failed 失败、restricted 受权限限制、unknown 未知',
          },
          remote_status: {
            type: 'string',
            enum: ['success', 'failed', 'restricted', 'unknown'],
            description:
              '远程靶机权威结论：仅至少一个权限档真实动态触发成功时为 success；源码确认但无入口/环境不满足必须为 restricted',
          },
          local_result: { type: 'string', description: '本地利用验证的过程与结果说明（中文）' },
          auth_required: {
            type: 'string',
            enum: ['none', 'user', 'admin'],
            description:
              '触发该漏洞【实际成功利用所需的最低权限】，必须与 privilege_results / local_result 一致：' +
              'none=从零权限/匿名状态即可直接触发，整个验证过程未使用任何账号、Cookie、Token、Session；' +
              'user=需要一个已登录的普通账号（含开放注册自助获取）才能触发；admin=只有管理员或特定高权限角色账号才能触发。' +
              '按权限降级测试的结果取【成功的最低档】：无权限成功→none；无权限失败但普通用户成功→user；仅管理员成功→admin。' +
              '只要 privilege_results.none.status=success 就必须填 none，严禁在无权限已打通时仍填 user/admin。',
          },
          privilege_results: {
            type: 'object',
            description:
              '【权限降级测试】的逐档结果矩阵：分别在 无权限(none)、普通用户(user)、管理员(admin) 三种权限下实测该漏洞能否触发。' +
              '每一档如实标 status（success 成功 / failed 失败 / restricted 受限 / skipped 未测试 / unknown 未知）。' +
              'auth_required 应由本矩阵按“成功的最低档”派生（none<user<admin）。',
            properties: {
              none: {
                type: 'object',
                description: '无权限/匿名（不带任何账号、Cookie、Token、Session）下的实测结果',
                properties: {
                  status: {
                    type: 'string',
                    enum: ['success', 'failed', 'restricted', 'skipped', 'unknown'],
                    description: '无权限下的验证结果',
                  },
                  evidence: { type: 'string', description: '简短中文证据/说明（可选）' },
                },
                required: ['status'],
              },
              user: {
                type: 'object',
                description: '普通登录用户（含开放注册自助获取账号）下的实测结果',
                properties: {
                  status: {
                    type: 'string',
                    enum: ['success', 'failed', 'restricted', 'skipped', 'unknown'],
                    description: '普通用户权限下的验证结果',
                  },
                  evidence: { type: 'string', description: '简短中文证据/说明（可选）' },
                },
                required: ['status'],
              },
              admin: {
                type: 'object',
                description: '管理员/高权限角色账号下的实测结果',
                properties: {
                  status: {
                    type: 'string',
                    enum: ['success', 'failed', 'restricted', 'skipped', 'unknown'],
                    description: '管理员权限下的验证结果',
                  },
                  evidence: { type: 'string', description: '简短中文证据/说明（可选）' },
                },
                required: ['status'],
              },
            },
          },
          impacts: {
            type: 'array',
            description:
              '该漏洞被成功利用后可造成的【多种危害/能力】列表。' +
              '一个漏洞往往不止一种危害，需逐项列全（如：任意文件写入、任意文件读取、信息泄露、命令执行、越权访问、凭据泄露、SSRF 等），' +
              '供后端组合链阶段按“能力→前置条件”拼接多漏洞利用链。仅在该漏洞远程验证成功/受限时填写。',
            items: { type: 'string' },
          },
          exploitable_versions: {
            type: 'array',
            description: '该漏洞可成功利用的历史版本及其 GitHub 地址',
            items: {
              type: 'object',
              properties: {
                version: { type: 'string', description: '可被利用的版本号或 tag' },
                github_url: { type: 'string', description: '对应版本的 GitHub 地址' },
                note: { type: 'string', description: '说明（中文）' },
              },
              required: ['version'],
            },
          },
          detail: { type: 'string', description: '利用链与技术细节（中文）' },
          historical_verification: HISTORICAL_VERIFICATION_SCHEMA,
        },
        required: ['vulnerability', 'remote_status'],
      },
    },
    chains: {
      type: 'array',
      description:
        '通过组合多个漏洞达成的组合利用链（如未授权 RCE、权限提升链等）。每条链由多个步骤串联，是单个漏洞无法独立达成的更高危害。',
      items: {
        type: 'object',
        properties: {
          chain_id: {
            type: ['string', 'integer'],
            description: '本轮候选清单中的唯一链编号，例如 chain-01',
          },
          name: { type: 'string', description: '利用链名称（中文）' },
          impact: { type: 'string', description: '该利用链最终达成的危害，如 未授权RCE、完全接管等（中文）' },
          auth_required: {
            type: 'string',
            enum: ['none', 'user', 'admin'],
            description:
              '触发该组合链【实际所需】的起始权限级别，必须与 steps/detail 真实验证过程一致：' +
              'none=匿名/零权限即可走完整条链；user=需已登录普通账号（含开放注册自助获取）。' +
              '组合链阶段只收 none/user → RCE；若起点需管理员请勿写入本数组（admin 链会被后端丢弃）。' +
              '步骤中出现登录普通账号则填 user，严禁在这种情况下仍填 none。',
          },
          status: {
            type: 'string',
            enum: ['success', 'failed', 'restricted'],
            description:
              '该组合利用链在本地靶机的最终验证结果：success=真实打通 RCE；failed=实测证伪/不可行；restricted=部分打通但被环境或必要前置条件阻断。不得省略或填写 unknown。',
          },
          steps: {
            type: 'array',
            description: '利用链的有序步骤',
            items: {
              type: 'object',
              properties: {
                vulnerability: { type: 'string', description: '该步骤利用的漏洞标题（中文）' },
                description: { type: 'string', description: '该步骤的动作与作用（中文）' },
              },
              required: ['description'],
            },
          },
          detail: { type: 'string', description: '整条利用链的技术细节与验证证据（中文）' },
          exploitable_versions: {
            type: 'array',
            description: '该利用链可成功利用的历史版本及其 GitHub 地址',
            items: {
              type: 'object',
              properties: {
                version: { type: 'string', description: '可被利用的版本号或 tag' },
                github_url: { type: 'string', description: '对应版本的 GitHub 地址' },
                note: { type: 'string', description: '说明（中文）' },
              },
              required: ['version'],
            },
          },
          historical_verification: HISTORICAL_VERIFICATION_SCHEMA,
        },
        required: ['chain_id', 'name', 'auth_required', 'status'],
      },
    },
  },
  required: ['exploits'],
};

/**
 * 收尾补全提示词：当主控跑完子智能体却没生成可利用清单时，
 * 强制其基于 JSON/ 已有发现汇总落盘高召回原始清单（不重新扫描、不做去重/验证/定级）。
 * 去重、代码级验证、定级校准由外层系统流水线统一完成。
 */
export function buildFinalizePrompt(dir: string): string {
  return `你此前已对 ${dir} 启动该语言专项子智能体审计，各类型发现已保存在 ${dir}/JSON/ 目录下，但你**尚未生成可利用清单**（缺少 directly_exploitable_vulns.json）。

请**直接读取 ${dir}/JSON/ 下已有的全部发现**（不要重新扫描整个项目），立即汇总落盘——**注意：不要在这里做语义去重、不要做代码级真伪验证、不要做定级校准**（这些由外层系统流水线统一完成）。你只需把 JSON/ 里的高召回发现**完整、逐条**汇总成可利用清单：
1. **必须落盘 \`directly_exploitable_vulns.json\` 到 ${dir} 根目录**：逐条列出 JSON/ 中所有"无需登录/有条件无需登录即可触发且有真实危害"的发现，每条含 id/category/name/severity/endpoint/payload/root_cause/taint_chain/file 字段。
   - **不准合并不同端点/不同 Sink/不同触发条件**；条目数应与 JSON/ 中的高召回发现量级相当，**明显偏少说明漏抄了，必须补全**。
   - ⚠ 必须是**严格合法的 JSON 数组**：字符串内双引号转义为 \\"（如 \`点击\\"添加\\"按钮\`），换行用 \\n，无尾随逗号、不要 markdown 包裹；建议编程序列化生成并读回校验。
2. （可选）如有余力再写 \`MD-Vulnerability/*.md\` 深度报告与 \`Audit_Summary.md\`，但不得为此牺牲上面清单的召回完整性。

# 关键边界：只产出单个独立漏洞，严禁组合利用链
- \`directly_exploitable_vulns.json\` 与最终 JSON 的 vulnerabilities 中，**每一条都必须是一个独立漏洞点**（单一根因/单一 Source→Sink）。
- **严禁**把"漏洞A → 漏洞B → RCE"这类串联多个不同漏洞的组合利用链作为一条记录；遇到这种情况请**拆成各自独立的单漏洞条目**分别列出。组合利用链的串联与验证属于后续靶机验证阶段，本步不要输出组合链。

完成落盘后，最后严格按指定 JSON Schema 输出**高召回的完整原始漏洞清单**（覆盖所有 critical/high/medium，每条均为单个独立漏洞，不得只给子集、不得自行去重或剔除）。所有文本用简体中文。`;
}

/**
 * 「跨语言融合漏洞」审计提示词：在各语言专项子智能体已落盘 JSON/ 之后运行。
 * 目标是补上单语言子智能体天然看不到的**跨语言边界**漏洞：污点从 A 语言运行时流入 B(甚至 C) 语言运行时才构成缺陷。
 * 产出两类：① 构成单个缺陷的跨语言污点链 → 作为单漏洞写入 JSON/cross-language-fusion-auditor.json；
 *          ② 需串联多个独立漏洞的跨语言利用链 → 仅作为候选写入 JSON/cross_language_chain_candidates.json（不入库，供靶机组合验证阶段优先尝试）。
 */
export function buildFusionPrompt(dir: string, langs: { label: string; ratio: number }[]): string {
  const langLine =
    langs.length > 0
      ? langs.map((l) => `${l.label}(约${Math.round(l.ratio * 100)}%)`).join('、')
      : '（多语言）';
  return `此前对 ${dir} 的审计中，各**单语言**专项子智能体已把发现写入 ${dir}/JSON/。但单语言子智能体各自只看自己那门语言，**看不到污点跨越语言边界后才构成的漏洞**。本轮你要专门补这一类「跨语言融合漏洞」。

# 本项目语言构成
${langLine}

# 你的任务：只挖「跨语言边界」相关的漏洞（不要重复单语言子智能体已覆盖的纯单语言问题）
## 第一步：枚举跨语言边界（用 Grep/Read / grep 先列全集）
系统性找出不同语言运行时之间传递数据/控制的所有边界，至少覆盖：
1. **子进程/命令调用跨运行时**：A 语言用 \`exec/spawn/subprocess/ProcessBuilder/os/exec/Command\` 调起 B 语言解释器或脚本（如 Node 调 \`python x.py\`、PHP 调 \`shell_exec('python ...')\`、Go 调 \`node script.js\`），参数/环境变量/stdin 是否含外部输入。
2. **共享存储/文件/配置**：一语言写、另一语言读的同一 文件 / 目录 / 数据库表 / 缓存(Redis) / 消息队列 / 配置文件 / 环境变量——写入端未净化、读取端当作可信数据（含二阶注入、反序列化、路径/命令拼接）。
3. **服务间 HTTP/RPC/gRPC/WebSocket**：一语言的服务把外部输入透传给另一语言的内部服务，内部服务因"来自内网/同源"而少校验（SSRF 落地、鉴权真空、注入透传）。
4. **FFI / 原生扩展 / 绑定**：一语言通过 FFI/CGO/JNI/N-API/ctypes 调另一语言或原生库，边界处的长度/类型/内存假设被打破。
5. **模板/序列化跨语言**：一语言序列化(JSON/YAML/pickle/PHP serialize/protobuf)后由另一语言反序列化，或共享模板/表达式被另一端求值。

## 第二步：沿边界追污点，区分两类产物
- **单个缺陷（一个 Source→Sink，只是跨了语言）**：例如「Node 接口把用户传入的文件名原样写进共享配置文件 → Python worker 读取该配置并 \`os.system\` 拼接执行」。这类**逐条作为单漏洞**写入 \`${dir}/JSON/cross-language-fusion-auditor.json\`，字段与其它子智能体一致（title/severity/category/file_path/line/description/recommendation/taint_chain），其中：
  - \`taint_chain\` 必须**逐跳**标注每一跳的**语言 + 文件:行/函数**，并明确写清在哪一跳跨越了语言边界、跨界时哪个校验/转义缺失。
  - \`description\` 本身也要内嵌这条逐跳链与绕过推演，标题用「具体入口/边界 —— 根因」范式。
- **需要串联多个独立漏洞的跨语言利用链**（A漏洞+B漏洞[+C漏洞]才达成 RCE/接管）：**不要**作为单漏洞入库，而是写入 \`${dir}/JSON/cross_language_chain_candidates.json\`（严格合法 JSON 数组），每条含：\`name\`(链名)、\`impact\`(危害)、\`languages\`(涉及语言数组)、\`steps\`(每步：语言/漏洞点/文件:行/所需前置)、\`rationale\`(为何能串通)。这份仅作为**候选线索**交给后续靶机组合验证阶段实测，本阶段不做靶机验证。

# 硬性要求
1. **只报跨语言相关的发现**：纯单语言问题留给对应子智能体，不在此重复。
2. 至少完整走一遍第一步的边界枚举，即使某类边界不存在也要确认过（在终端简述）。
3. \`cross-language-fusion-auditor.json\` 与 \`cross_language_chain_candidates.json\` 都必须是**严格合法 JSON 数组**：字符串内双引号转义为 \\"，换行用 \\n，无尾随逗号、不要 markdown 包裹；建议编程序列化并读回校验。若某类为空则写 \`[]\`。
4. 所有描述性文本一律**简体中文**（函数名/文件名/参数名等代码标识符可保留原文）。
5. 本阶段**不做**去重 / 代码级验证 / 定级校准（由外层系统流水线统一完成），也**不搭靶机、不发 Payload**——纯静态源码分析。

完成落盘后，按指定 JSON Schema 输出本轮**跨语言单漏洞**发现的汇总（只含上面第①类单漏洞，第②类候选链不放进 vulnerabilities）。所有文本用简体中文。`;
}

/**
 * 多智能体审计主控：只分配 4 路方向并收口，自己不挖洞。
 * 与 4 路专项 Pi 同时拉起，合计 5 个进程。
 */
export function buildAuditOrchestratorPrompt(dir: string, language: string, agents: string[]): string {
  const lang = AUDIT_LANGUAGE_LABELS[language] || language;
  const n = agents.length;
  const lanes = agents
    .map((t, i) => `${i + 1}. \`${t}\`：${subagentMission(t)} → 必须写入 \`${dir}/JSON/${t}.json\``)
    .join('\n');
  return `你是代码审计【主控调度】。本会话只负责把 **${lang}** 的审计方向分配给 ${n} 路专项子智能体，并在它们落盘后汇总。禁止自己逐文件挖洞。

# 分配方案（必须按此 ${n} 路并发，不得增删、不得合并、不得改名）
${lanes}

# 执行
1. 立即确认上述 ${n} 路方向已分配完毕。后端已为每一路拉起独立 Pi，**不要再调用 Task/Agent 重复派发**（重复派发会多开进程、浪费配额）。
2. 轮询 \`${dir}/JSON/<类型>.json\`：${n} 个文件都存在且是合法 JSON（空数组 \`[]\` 也算该路完成）才进入汇总。大约每 30 秒用 ls/Read 检查一次，保持有输出。
3. 某路迟迟未落盘时，在终端标明缺哪一路，**不要自己顶上那一路去扫源码**。
4. ${n} 路齐了之后，读取各 JSON，按 JSON Schema 输出合并汇总。不要去重、不要代码级验证、不要定级校准、不要搭靶机、不要输出组合利用链。

# 硬性
- 你是分配与收口，不是第 ${n + 1} 路挖洞员。
- title/category/description/recommendation/taint_chain 用简体中文。
- vulnerabilities 是高召回原始清单，宁多勿漏。`;
}

/**
 * 单路专项审计提示词：后端为每一类型单独 spawn 一路 Pi。
 */
export function buildSpecialtyAgentPrompt(dir: string, agentType: string): string {
  const jsonPath = `${dir}/JSON/${agentType}.json`;
  return `你是代码安全审计员，本会话只负责专项「${agentType}」。

# 任务
对目录 ${dir} 中的源码做静态安全审计，范围仅限：${subagentMission(agentType)}。

# 产物
源码目录 ${dir} 只读。禁止改源码、禁止使用 MCP。
结果必须写入 \`${jsonPath}\`：顶层数组，或含 findings/vulnerabilities/issues 的对象。0 发现也要写合法空数组 \`[]\`。

# 硬性要求
- 只负责这一类；逐端点 × 逐 Sink × 逐触发条件成条，严禁合并抽样。
- 数据流类漏洞必须有逐跳 taint_chain（文件:行/函数）。
- title/category/description/recommendation/taint_chain 用简体中文。
- 不要去重、不要代码级验证、不要定级校准、不要搭靶机、不要输出组合利用链。

完成后按 JSON Schema 输出本路发现汇总。vulnerabilities 是高召回原始清单，宁多勿漏。`;
}

/**
 * 「精准补跑缺失子智能体」提示词（兼容旧调用）。后端现已按缺失类型各拉一路 Pi。
 */
export function buildSubagentRerunPrompt(
  dir: string,
  agents: { type: string; file: string }[]
): string {
  const list = agents
    .map((a, i) => `${i + 1}. \`${a.type}\` → \`${dir}/${a.file}\``)
    .join('\n');
  return `此前审计中，下列专项尚未落盘有效 JSON。请按清单亲自完成静态发现并写入指定文件。禁止 MCP。0 发现也要写空数组。不要去重或代码级验证。

${list}

全部落盘后按 JSON Schema 汇总本次补跑发现。`;
}

/**
 * 构建「覆盖率深度补判」提示词（后端强制覆盖率闸专用·逐成员·单子智能体精准回炉）。
 * 当某个子智能体的 `enum.json` 里存在"已列入全集却没判定 verdict"的成员时，
 * 后端只重派这一个子智能体，携带它自己没判完的成员清单，逼它逐个判完（尤其可达高危的）。
 * 语言/类别无关：成员定位与类别名均由 enum.json 透传，不含任何硬编码函数/框架名。
 */
export function buildCoverageGapPrompt(
  dir: string,
  agentType: string,
  members: { category: string; symbol: string; loc: string; tier: string }[]
): string {
  const list = members
    .map(
      (m, i) =>
        `${i + 1}. [${m.category}]${m.tier === 'critical_high' ? '（可达高危·必判）' : ''} ${m.symbol}${
          m.loc ? ` @ ${m.loc}` : ''
        }`
    )
    .join('\n');
  return `此前你（子智能体 \`${agentType}\`）在 ${dir} 的审计中，把下列成员**列入了枚举全集清单 \`JSON/${agentType}.enum.json\`，但没有给它们判定 verdict（既没成条也没标安全）**——这是被跳过的硬性覆盖率闸，属于漏判/漏挖，必须现在逐个判完。只处理下面这些未判成员，不要重跑已判定的，不要做去重 / 代码级验证 / 定级校准（这些由外层系统流水线统一完成）。

# 你尚未判定的枚举成员（逐个判完）
${list}

# 执行要求（务必逐条遵守）
1. 对上面**每一个**成员，回到其 \`loc\` 处读源码，套用你负责类别的缺陷判据逐个判定，**不得抽样、不得"其余同理"带过**。
2. **标注了「可达高危·必判」的成员优先且必须判**（可达 RCE / 注入生效 / 任意文件读写 / 鉴权或授权绕过 / 越权拿他人数据 / 脱库 / SSRF 打内网 / 反序列化执行）：确认有缺陷的**每一个都单独成条**（含逐跳 \`taint_chain\`，标注“文件:行/函数”），追加写入你的 \`JSON/${agentType}.json\`。
3. 回到 \`JSON/${agentType}.enum.json\`，给这些成员逐个回填 \`verdict\`：有缺陷标 \`defect\`（并已成条），确认安全标 \`safe\` 并给一句代码级理由（参数化 / 已转义 / 输入不可控 / 路径不可达等，指出文件:行）。
4. 判定默认取向：**找不到"确实生效的防御代码(文件:行)"就应判 defect 成条**，不要因为"看起来没问题""上层可能已处理"就标 safe。
5. 最后按 JSON Schema 输出本次补判新增发现的汇总（简体中文）。`;
}

/** AI 红队实战二次评级输出 schema。 */
export const REGRADE_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string', description: '本次实战二次评级的总体结论（中文）' },
    ratings: {
      type: 'array',
      description: '对每个漏洞的实战二次评级结果',
      items: {
        type: 'object',
        properties: {
          index: { type: 'integer', description: '对应输入漏洞清单中的序号（从 1 开始）' },
          title: { type: 'string', description: '对应的漏洞标题，用于核对（中文）' },
          title_cn: {
            type: 'string',
            description:
              '该漏洞的简体中文标题（必填）：把原标题忠实翻译/规范为简体中文，保持技术含义与定位不变，**不得保留英文**（专有名词如函数名/类名/文件名可保留原样，其余一律中文）',
          },
          category_cn: {
            type: 'string',
            description:
              '该漏洞类别的简体中文表述（必填）：如 命令注入、SQL注入、路径穿越、反序列化、资源耗尽、不安全默认配置、信息泄露 等，**不得用英文**',
          },
          adjusted_severity: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low', 'info'],
            description: '结合红队实战利用价值后的客观严重度',
          },
          red_team_value: {
            type: 'string',
            enum: ['严重', '高危', '中危', '低危', '无'],
            description:
              '红队实战等级（五级，与 adjusted_severity 一一对应）：严重=未授权即可完全接管/大规模脱库/未授权RCE；高危=有严重危害但需一定前置(如登录低权/后台RCE)；中危=有真实危害但范围或条件受限；低危=危害有限或门槛很高；无=基本无实战价值(纯理论/自我攻击/鸡肋配置)',
          },
          reason: {
            type: 'string',
            description: '二次评级理由（中文）：从攻击者可达性、前置条件、真实危害、利用稳定性角度说明为何上调/下调/维持',
          },
          auth_required: {
            type: 'string',
            enum: ['none', 'user', 'admin'],
            description:
              '触发该漏洞【实际所需】的最低权限级别（沿数据流核对入口到 Sink 之间是否存在有效鉴权环节）：' +
              'none=匿名/未登录即可触发（前台/未授权）；user=需已登录普通账号；admin=需管理员/高权限角色。以真实鉴权代码为准，勿泛泛猜测。' +
              '⚠ 同一 Sink 常有多条到达路径，auth_required 取【所有可达路径中权限最低的一条】：只要存在任意一条未授权旁路（同义入口/路由错位·批处理/schema 绕过/公开包装器/匿名端点）到达 Sink 就填 none；判 user/admin 前须确认每一条到达路径都有生效鉴权。存疑往低判（none 优先）。',
          },
          auth_reason: {
            type: 'string',
            description: '鉴权判定理由（中文，简短）：入口处有无登录/权限校验、在哪个文件:行、为何判为该级别；判 user/admin 时须说明已核实所有到达路径都有生效鉴权。',
          },
        },
        required: ['index', 'title_cn', 'category_cn', 'adjusted_severity', 'red_team_value', 'reason'],
      },
    },
  },
  required: ['ratings'],
};

interface RegradeBrief {
  title: string;
  severity: string;
  category: string;
  file_path: string;
  line: number | null;
  description: string;
}

/**
 * 构建「红队实战二次评级」提示词。
 * 让 AI 站在真实红队攻击者视角，对每个已发现/已代码级验证的漏洞，
 * 按实战利用价值重新客观定级，纠正被夸大的高危/严重评级。
 */
export function buildRegradePrompt(dir: string, vulns: RegradeBrief[]): string {
  const list = vulns
    .map(
      (v, i) =>
        `${i + 1}. [当前评级:${v.severity}] ${v.title}（${v.category || '未分类'}）—— ${
          v.file_path
        }${v.line ? ':' + v.line : ''}\n   ${(v.description || '').replace(/\s+/g, ' ').slice(0, 280)}`
    )
    .join('\n');

  return `你是一名资深红队专家（OSCP/实战渗透背景）。下面是对项目 ${dir} 进行代码级安全审计后得到的漏洞清单。
请你**站在真实红队攻击者的实战视角**，对【每一个】漏洞的严重程度做客观的二次评级。

# 评级原则（双向校准，不要只降不升、也不要只升不降）
评级**既可能被高估、也可能被低估**。你的任务是**按真实红队实战利用价值做客观的双向校准**，让每个漏洞的等级与其真实危害相匹配——不是一味地降级，也不是一味地升级：
- **应下调**：需要管理员权限/极端前置条件才能触发、仅信息泄露无实质危害、纯理论 DoS、需受害者高度配合等，实战价值偏低的；
- **应上调**：被低估的真高危——例如未授权即可触发、污点链直达严重危害（RCE/脱库/任意文件读写/完全接管）、利用稳定且门槛低，但当前却被标成 medium/low 的；
- **维持原级**：证据不足以支持调整，或当前评级已与真实危害匹配的。
保持克制与客观：**只有证据支持时才调整等级**。注意：本环节只**调整等级**，不会删除、合并或新增任何漏洞。

# 抗过度降级（重要·避免把蓝本级真高危压成噪声）
最大的质量损失来自"把真漏洞压级"而非高估。务必遵守：
- **未授权即可触发**、且污点链直达严重危害（RCE / 任意文件读写 / 脱库 / 越权拿敏感数据 / 完全接管）的，保持 **high/critical**，不得因为"清单里同类很多/标题相似"就批量降级。
- **critical 保级**：原评级为 critical 且"未授权或低门槛即可达成 RCE / 任意文件写 / 完全接管 / 大规模脱库"的，**维持 critical**；只有当你能举出代码级证据证明它实际需要高权限前置或存在生效防御时，才可降为 high，并在 reason 写明依据。**不要把一批 critical 普遍压成 high。**
- 认证绕过 / 路径穿越 / 越权(IDOR) / **带完整入口的** SSRF / 反序列化等，只要**未授权或低门槛可达且有真实危害**，不要压到 low/info；需登录/权限但危害真实的属"有条件真阳性"，定 medium 起步而非 low。
- **例外·必须降到 low**：① 仅描述底层 HTTP 客户端/SSRF Sink 原语（无协议限制、FOLLOWLOCATION 等）却**无具体 HTTP 入口与用户可控 URL 证据**的；② 登出 CSRF / 仅缺 CSRF·formhash 且危害仅为强制下线的。这两类**不要**因为类别叫 SSRF/CSRF 就保 high/critical。
- 只有当该漏洞**确需管理员且仅自身功能滥用**、或**仅信息泄露无放大**、或**纯理论**时，才下调到 low/info，并在 reason 写明依据。
- 切勿因为"这一批漏洞数量多"就倾向于整体降级——每条独立按其真实可达性与危害定级。

# 实战评级准则
对每个漏洞，综合以下维度判断其**红队实战利用价值**与**客观严重度**：
1. **攻击者可达性**：是否未授权即可触发？还是需要登录/管理员/特定角色？需要的权限越高，实战价值越低。
2. **前置条件**：是否依赖非默认配置、特定插件/版本、特殊环境、用户交互？条件越苛刻，价值越低。
3. **真实危害**：能否直接 RCE / 拿 shell / 读写任意文件 / 脱库 / 横向 / 提权？还是仅有限信息泄露、自我 XSS、理论 DoS？
4. **利用稳定性与门槛**：利用是否稳定可复现、门槛是否低？

# 评级映射（实战导向，按真实危害双向校准）
- **critical**：未授权或低门槛即可达成 RCE / 完全接管 / 大规模脱库等顶级危害，稳定可利用。
- **high**：有真实严重危害（RCE/越权拿敏感数据/任意文件写等），但需要一定前置条件（如需登录低权账号）。
- **medium**：有真实危害但范围或条件受限（如需较高权限、影响有限、需用户交互的存储型 XSS 等）。
- **low**：危害有限或利用门槛很高（如需管理员的自身功能滥用、轻微信息泄露）。
- **info**：基本无实战价值（纯理论、配置类建议、需极端前提、自我攻击等）——例如单纯"无登录频率限制/无验证码/无 CORS 限制/Token 不过期/调试信息/缺安全响应头"且未放大其它漏洞的，一律降到 low 或 info。

# 仅依据本地源码定级（禁止联网）
**不要进行任何联网搜索**（不要去查 CVE、公开 PoC/EXP、NVD/官方 CVSS 评分等外部信息）。
定级只能基于本项目 ${dir} 的实际源码与上面提供的漏洞信息，从"针对本项目源码的真实可达性"出发判断，不得引用外部 CVE/CVSS 作为依据。

# 必要时可查证源码
如果对某个漏洞的可达性/前置条件没有把握，可以用工具阅读 ${dir} 下对应源码核实后再定级（只读，不要修改、不要部署）。

# 待二次评级的漏洞清单（共 ${vulns.length} 个）
${list}

# 输出要求
严格按照指定 JSON Schema 输出一个对象。ratings 数组必须**覆盖上面每一个漏洞**（按 index 一一对应，不得遗漏、不得新增）。
- adjusted_severity：你校准后的客观严重度（critical/high/medium/low/info）。
- red_team_value：红队实战利用价值（高/中/低/无）。
- title_cn：该漏洞的**简体中文标题**（忠实翻译/规范原标题，保持技术含义与定位不变；函数名/类名/文件名等专有名词可保留，其余一律中文，**不得整条用英文**）。
- category_cn：该漏洞类别的**简体中文表述**（如 命令注入、路径穿越、反序列化、资源耗尽、不安全默认配置、信息泄露 等，不得用英文）。
- reason：用简体中文简明说明定级依据（攻击者视角：可达性、前置条件、真实危害、稳定性），尤其要解释每一次"下调"的理由。
**语言硬性要求：title_cn / category_cn / reason 全部必须是简体中文，严禁出现整句英文标题或英文类别词。**

# 一致性硬性要求（adjusted_severity 必须与 red_team_value 五级一一对应）
评级必须**真正改变严重度档位**，让漏洞落到与其实战价值匹配的档里——**绝不能"实战价值是中危，却因为原来判成高危就仍留在高危档"**。按下表严格一一对应（两者五级完全同义）：
- red_team_value=严重 → adjusted_severity = **critical**（未授权即可完全接管/大规模脱库/未授权 RCE）；
- red_team_value=高危 → adjusted_severity = **high**；
- red_team_value=中危 → adjusted_severity = **medium**；
- red_team_value=低危 → adjusted_severity = **low**；
- red_team_value=无 → adjusted_severity = **info**。
RCE / 命令执行 / SSTI / 反序列化等类型**不设硬性下限**：若需高权限、复杂前置或利用不稳定，按真实实战价值客观定级即可（可降至 medium/low/info），并在 reason 写明依据。
绝不能出现 severity 与 red_team_value 不对应的情况（例如 severity=high 但 red_team_value=中危/低危/无）。`;
}

/** AI 语义去重输出 schema。 */
export const AI_DEDUP_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string', description: '本批去重的总体结论（中文）' },
    duplicate_groups: {
      type: 'array',
      description:
        '重复分组：每一组代表「指向同一个底层漏洞的多条重复上报」。不存在重复时返回空数组。',
      items: {
        type: 'object',
        properties: {
          keep_index: {
            type: 'integer',
            description: '本组中应保留的代表条目序号（从 1 开始）：选信息最完整、定位最准、严重度最高的一条',
          },
          duplicate_indexes: {
            type: 'array',
            items: { type: 'integer' },
            description:
              '【纯重复·会被删除】仅措辞/中英文不同，但与代表条目【同一 sink + 同一触发条件 + 同一参数 + 同一漏洞类型】，属完全等价的重复上报（从 1 开始，不含 keep_index）。这些会被合并删除。',
          },
          variant_indexes: {
            type: 'array',
            items: { type: 'integer' },
            description:
              '【同点不同利用面·会被保留】与代表条目落在【同一文件同一代码点/根因】，但触发条件 / 参数 / 利用路径 / 会造成的漏洞类型【不同】——即同一个漏洞点的不同「利用面」（一个点可能引发多种漏洞情况）。这些【不会被删除】，而是与代表条目一起归为同一簇（cluster）各自独立保留、逐面验证（从 1 开始，不含 keep_index）。拿不准时归到这里，不要放进 duplicate_indexes。',
          },
          merged_title: { type: 'string', description: '可选：归并后更准确的统一标题（中文）' },
          reason: {
            type: 'string',
            description:
              '判定依据（中文）：说明 duplicate_indexes 为何是纯重复（同 sink/触发/参数），以及 variant_indexes 各自是同点的什么不同利用面。',
          },
        },
        required: ['keep_index', 'duplicate_indexes'],
      },
    },
  },
  required: ['duplicate_groups'],
};

interface DedupBrief {
  title: string;
  severity: string;
  category: string;
  file_path: string;
  line: number | null;
  description: string;
}

/**
 * 构建「AI 语义去重」提示词：对一批候选漏洞，识别哪些条目其实指向同一个底层漏洞
 * （不同子智能体用不同措辞/中英文/不同严重度重复上报），归并为一组并保留最佳代表。
 * 原则：保守去重——只有高度确信是同一漏洞才合并，拿不准一律保留，避免误删不同漏洞。
 */
export function buildDedupPrompt(dir: string, vulns: DedupBrief[]): string {
  const list = vulns
    .map(
      (v, i) =>
        `${i + 1}. [${v.severity}] ${v.title}（${v.category || '未分类'}）—— ${v.file_path}${
          v.line ? ':' + v.line : ''
        }\n   ${(v.description || '').replace(/\s+/g, ' ').slice(0, 240)}`
    )
    .join('\n');

  return `你是资深代码审计专家。下面是多个专项子智能体各自上报的【候选漏洞】。请你做一次【语义级去重与利用面归并】。核心区分两件事：① **纯重复**（同一漏洞的重复上报，只是措辞/语言不同）→ 合并删除；② **同一代码点的不同利用面**（一个 sink/代码点可能引发多种漏洞情况）→ 【保留】并归为同一簇（cluster）。

# 目标目录（可只读查证源码）
${dir}

# 关键理念：漏洞是一个「面」不是一个「点」
同一个危险代码点（同一 sink / 同一函数），常常可以通过**不同的触发条件、不同的参数、不同的入口、不同的前置状态**被利用，从而造成**不同的漏洞情况**（例如同一处 \`str_replace('../','',$f)\` 弱过滤 + 文件操作，既可任意写、又可任意读、又可任意删；同一 AJAX 端点渲染的不同字段各自 XSS）。这些是**同一个点的多个利用面**，必须**各自独立保留**，绝不能压成一条——否则后续验证只会验其中一个面，漏掉其余。

# 三分类判定
把清单中的条目分成三类：
1. **纯重复（duplicate_indexes → 删除）**：两条只是**语言不同（中/英）或措辞不同**，但指向**完全相同的 sink 调用点 + 相同触发条件 + 相同参数 + 相同漏洞类型 + 相同根因与污点链**。例如 "LogViewer::tail() has zero path validation" 与 "Unvalidated File Open in LogViewer::tail()" → 纯重复，合并。
2. **同点不同利用面（variant_indexes → 保留、归簇）**：落在**同一文件的同一代码点/根因**，但**触发条件 / 参数字段 / 利用路径 / 造成的漏洞类型不同**。例如同一 define_pages_editor.php 的弱路径过滤既致「任意写(save)」又致「任意读(edit)」又致「任意删」→ 三个利用面，全部保留，归为一簇。
3. **不同漏洞点（不成组）**：不同函数 / 不同 sink / 不同根因 → 各自独立，不放进任何组。

# 红线（务必遵守）
- **只有确信是纯措辞重复**（同 sink 同触发同参数）才放进 duplicate_indexes 删除；**拿不准一律放 variant_indexes 保留**（覆盖优先，宁可多留）。
- 同一代码点的**不同利用面**绝不放进 duplicate_indexes（那会被删除、丢面）。
- 跨文件、不同 sink、不同根因 → 不要成组。
- 必要时用工具读取 ${dir} 下对应源码核实（只读，不要修改、不要部署）。

# 代表条目（keep_index）的选择
每组选**信息最完整、定位最准确、严重度最高**的一条作为 keep_index。duplicate_indexes 会被删除；variant_indexes 会与 keep_index 一起作为同簇的不同利用面全部保留。

# 候选漏洞清单（共 ${vulns.length} 个）
${list}

# 输出要求（非常重要，务必遵守）
- 完成分析后，你**必须通过结构化输出（StructuredOutput）提交最终结果**，且只提交一个符合指定 JSON Schema 的对象。**绝对不要只用 markdown 表格或自然语言罗列分组**——那样程序读不到、结果会被全部丢弃（等于白做）。
- duplicate_groups：列出**所有存在纯重复或多利用面**的分组；每组给出 keep_index、duplicate_indexes（纯重复·删）、variant_indexes（同点不同面·留）、reason。
- 没有纯重复也没有多利用面的条目不必成组；无任何分组时返回空数组 []。
- 序号必须是上面清单中的真实序号（1~${vulns.length}），keep_index 不得出现在自己的 duplicate_indexes/variant_indexes 中。所有文本用简体中文。`;
}

/** 代码级真实性验证输出 schema。 */
export const CODE_VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      description: '对每个候选漏洞的代码级验证结论',
      items: {
        type: 'object',
        properties: {
          index: { type: 'integer', description: '对应输入候选清单的序号（从 1 开始）' },
          title: { type: 'string', description: '漏洞标题（用于核对）' },
          verdict: {
            type: 'string',
            enum: ['true_positive', 'conditional', 'false_positive', 'design_decision'],
            description:
              'true_positive=确认真实漏洞；conditional=真实但需前置条件（需登录/特定配置等，仍算真漏洞）；false_positive=误报；design_decision=有意设计/可接受，非漏洞',
          },
          verified_severity: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low', 'info'],
            description: '代码级验证后的客观严重度',
          },
          file: { type: 'string', description: '准确文件路径（沿用或修正候选所给）' },
          line: { type: 'integer', description: '行号，未知填 0' },
          reason: {
            type: 'string',
            description: '验证依据（中文）：污点链是否可达、防御是否生效、为何判定此 verdict',
          },
          auth_required: {
            type: 'string',
            enum: ['none', 'user', 'admin'],
            description:
              '触发该漏洞【实际所需】的最低权限级别（沿污点链核对是否存在有效鉴权环节后判定）：' +
              'none=从匿名/未登录状态即可触发，Source 入口无任何鉴权（无登录校验、无 Session/Token 检查、路由对未认证开放）；' +
              'user=需要一个已登录的普通账号才能到达该 Sink；admin=需要管理员或特定高权限角色。' +
              '判定依据必须是"数据流入口到 Sink 之间是否有真正生效的鉴权/登录/权限校验"，而非泛泛猜测。' +
              '⚠ 同一 Sink 常有多条跨文件到达路径，auth_required 取【所有可达路径中权限最低的一条】：只要存在任意一条未授权旁路（同义/别名入口、路由错位·批处理/合并接口、schema 校验被绕过、公开无鉴权包装器、注册/回调/webhook/REST 匿名端点）到达 Sink 就填 none；判 user/admin 前须用 Grep/Read 反向枚举每一条到达路径并确认它们【都】有生效鉴权。存疑一律往低判（none 优先），把是否真需登录交给远程实测复核。',
          },
          auth_reason: {
            type: 'string',
            description:
              '鉴权判定理由（中文，简短）：说明数据流入口处有无登录/鉴权校验、在哪个文件:行、为何判为该权限级别；判 user/admin 时须说明已核实所有到达该 Sink 的路径都有生效鉴权。',
          },
          // ① 省 token · 合并验证+评级：开启 merge_verify_regrade 时，验证顺带产出以下字段，
          // 使流水线可跳过独立的二次评级 pass。默认关闭时这些字段留空、不影响原流程。
          title_cn: {
            type: 'string',
            description:
              '【合并评级时填写】该漏洞的简体中文标题：把原标题忠实转为简体中文（函数/类/文件名等标识符可保留），其余不得保留英文',
          },
          category_cn: {
            type: 'string',
            description:
              '【合并评级时填写】漏洞类别的简体中文表述：如 命令注入、SQL注入、路径穿越、反序列化、信息泄露 等，不得用英文',
          },
          red_team_value: {
            type: 'string',
            enum: ['严重', '高危', '中危', '低危', '无'],
            description:
              '【合并评级时填写】红队实战等级（五级，与 verified_severity 一一对应）：严重=未授权即可完全接管/大规模脱库/未授权RCE；高危=有严重危害但需一定前置；中危=真实危害但范围/条件受限；低危=危害有限或门槛很高；无=基本无实战价值',
          },
        },
        required: ['index', 'verdict'],
      },
    },
  },
  required: ['results'],
};

interface VerifyBrief {
  title: string;
  severity: string;
  category: string;
  file_path: string;
  line: number | null;
  description: string;
}

/**
 * 构建「代码级真实性验证」提示词：对一批子智能体上报的候选漏洞逐条核验真伪。
 * 原则：宁可保留不可漏判；需权限/前置条件的归 conditional（仍是真漏洞），不要当误报丢弃。
 */
export function buildCodeVerifyPrompt(dir: string, vulns: VerifyBrief[]): string {
  const list = vulns
    .map(
      (v, i) =>
        `${i + 1}. [${v.severity}] ${v.title}（${v.category || '未分类'}）—— ${v.file_path}${
          v.line ? ':' + v.line : ''
        }\n   ${(v.description || '').replace(/\s+/g, ' ').slice(0, 300)}`
    )
    .join('\n');

  return `你是资深代码审计专家。下面是各专项子智能体上报的【候选漏洞】，请对每一个做严格的【代码级真实性验证】。

# 目标目录（可只读查证源码）
${dir}

# 验证方法（对每条逐一执行）
1. 重走完整污点链 Source（用户可控输入入口）→ Sink（危险操作），确认是否真实可达。
2. 逐段核对中间是否存在有效防御（输入校验/转义/白名单/类型检查/权限校验/参数化查询等）。
3. 必要时用工具读取 ${dir} 下对应源码核实（只读，不要修改、不要部署）。

# 判定（verdict）
- true_positive：确认真实漏洞，污点链可达且无有效防御。
- conditional：漏洞真实存在，但利用需要前置条件（需登录/管理员、特定配置、特定插件/版本等）——**仍属真漏洞，必须保留**，用 verified_severity 体现其受限程度（如需授权 → medium/low）。
- false_positive：误报（防御已生效/路径不可达/对代码机制理解有误）。
- design_decision：有意的设计决策或可接受风险，非漏洞。

# 重要原则（务必遵守）
- **宁可保留，不可漏判**：只有当你确信防御有效或路径不可达时才判 false_positive；拿不准的一律归 conditional 保留。
- **不要因为"需要权限/有前置条件"就判 false_positive 或丢弃**——那属于 conditional（真漏洞）。
- **逐条独立核验，不要跨条目合并**：每个 index 是一个独立的 (Source×Sink×触发条件) 三元组，即使多条标题相似、落在同类缺陷上，也要各自独立给结论；不同端点/不同 Sink 调用点的同类漏洞都是真漏洞，不得因"看着重复"而判误报。
- **未授权可达直达严重危害的**（RCE/任意文件读写/脱库/越权）→ verified_severity 保持 high/critical。
- 每条都必须给出 reason（验证依据）。

# 候选漏洞清单（共 ${vulns.length} 个）
${list}

# 输出要求（务必遵守）
完成核验后，**必须通过结构化输出（StructuredOutput）提交一个符合指定 JSON Schema 的对象**，不要只用 markdown 表格汇报（否则程序读不到、结果会丢失）。results 数组必须**覆盖上面每一个候选**（按 index 一一对应，不得遗漏、不得新增）。所有文本用简体中文。`;
}

const LOW_VALUE_SEVERITY_POLICY_GUIDANCE = `
# 低价值漏洞封顶策略（只降不升）
> **已去除高危保护**：不再有"某类漏洞必须保持或提高等级"的硬性护栏，也没有 DoS 保护例外。请你站在真实红队攻击者的实战视角，对每个漏洞按其**真实可达性与危害**客观定级——高危与否完全由实战价值决定，不因类别标签自动获得保级。下列规则仅对**明确无实战价值**的低价值类别做封顶（只封顶、绝不据此升级）。
1. **纯资源与稳定性**：内存/线程/连接/进程泄漏、OOM、普通资源耗尽、普通 DoS/Zip Bomb、超时、ReDoS、无限循环等，最高 low。
2. **纯配置与普通信息**：安全响应头、无利用链 CSP、非认证 Cookie 属性、Banner/版本/路径/普通错误栈、正常鉴权接口的 Swagger、无密钥 Source Map 等，定为 info。
3. **弱防护与低影响前端**：未形成直接后果的限流/验证码/密码策略/CORS/开放重定向/Host Header，以及反射型 XSS、客户端崩溃、无危险 Sink 的理论 DOM 污染，最高 low。
4. **CSRF / 登出 CSRF**：仅缺 CSRF Token、formhash 被注释、强制登出/骚扰型下线，**无账号接管或敏感状态篡改证明**的，最高 **low**（不要标高危/严重）。
5. **Sink 级 SSRF / 不安全 HTTP 客户端原语**：仅指出 \`curl_*\` / \`dfsockopen\` / \`file_get_contents\` 等**底层函数**无协议限制、FOLLOWLOCATION、SSL 校验关闭，但**没有证明**「用户可控 URL 经具体 HTTP 入口打到该 Sink」的完整链，一律 **low**。\`auth_required=none\` 若只因「函数内部无鉴权」而非「匿名 HTTP 可触发」，不得据此标严重/高危。有明确入口（如 \`$_GET['iconnew']\`、Controller 参数）的打点链按入口权限客观定级，不在本条封顶之列。
6. **理论不可达/代码质量**：输入不可控、受影响功能未启用、代码不可达、只有“可能/理论上”而无现实攻击路径的问题，定为 info。
只调整严重度，不删除代码级验证结果；low/info 仍可作为组合利用链候选。`;

/**
 * 代码级验证单路工人提示词：本路只核一组，用全局 index 落盘。
 * 与二次评级同一套工人池：每路 batchSize 条，最多同时 concurrency 路。
 */
export function buildCodeVerifyWorkerPrompt(
  dir: string,
  groupFile: string,
  outFile: string,
  count: number,
  groupNo: number,
  groupTotal: number,
  opts: { merged?: boolean; lean?: boolean } = {}
): string {
  const merged = opts.merged === true;
  const lean = opts.lean === true;
  const mergedFields = merged
    ? `
- \`title_cn\`：该漏洞的简体中文标题（把原标题忠实转为简体中文，函数/类/文件名等标识符可保留，其余不得保留英文）。
- \`category_cn\`：类别的简体中文表述（如 命令注入、路径穿越、反序列化；不得用英文）。
- \`red_team_value\`：红队实战五级（严重/高危/中危/低危/无，与 verified_severity 一一对应）。`
    : '';
  const mergedNote = merged
    ? `\n\n# ⚙ 本路合并二次评级\n本路验证**顺带完成红队实战二次评级**：\`verified_severity\` 必须结合"攻击者真实可达性、前置条件、真实危害、利用稳定性"客观定级（纠正夸大/低估），并额外产出 \`title_cn\`/\`category_cn\`/\`red_team_value\`。\n${LOW_VALUE_SEVERITY_POLICY_GUIDANCE}`
    : '';
  const endgame = lean
    ? `写入 \`${outFile}\` 后：若已成功落盘则无需再输出 StructuredOutput；仅当落盘失败/缺漏时，才补输出这些缺漏项的 {results:[...]}。`
    : `写入 \`${outFile}\` 后，再输出 {results:[...]} 覆盖本路全部 index 作为兜底。`;

  return `你是资深代码审计验证员。这是第 ${groupNo}/${groupTotal} 路代码级真实性验证${merged ? '（并顺带红队实战二次评级）' : ''}，本路只核 ${count} 个候选。

# 你的角色
本路独立完成这 ${count} 条，不要派 Task/Agent 子智能体，也不要去核清单以外的 index。核完立刻落盘。

# 目标目录（只读查证源码，不要修改/部署）
${dir}

# 本路待验证清单
${groupFile}
该文件是 JSON 数组，每项含 **全局 index**、title、severity、category、file、line、description、taint_chain、cluster_id。**必须覆盖本文件每一个 index，不得遗漏/跳过/合并。**

# ⚠ 利用面簇（cluster_id）：同点多面，逐面独立验证
带有相同 \`cluster_id\` 的条目是**同一代码点的不同利用面**。必须对每个利用面各自独立验证，严禁因为"同一个点/看着相似"就合并、跳过、或把某一面的结论套到其它面上。

# 落盘（后端只读磁盘）
核完后把结果写入 \`${outFile}\`，内容是**严格合法 JSON 数组**（不是外包一层对象），每个元素字段：
- \`index\`：清单里的**全局序号**（必填，不要改成本路 1..${count}）。
- \`title\`：漏洞标题（核对用）。
- \`verdict\`：\`true_positive\` / \`conditional\`（真实但需前置条件，**仍算真漏洞**）/ \`false_positive\` / \`design_decision\`。
- \`verified_severity\`：critical/high/medium/low/info。
- \`file\`、\`line\`：准确定位（沿用或修正）。
- \`reason\`：验证依据（中文）——污点链是否可达、防御是否生效、为何这样判。
- \`auth_required\`：none/user/admin（取所有可达路径中权限最低的一条）。
${AUTH_MULTIPATH_RULE}
- \`auth_reason\`：鉴权判定理由（中文，简短）。${mergedFields}
⚠ 严格 JSON：引号转义、无尾逗号、不要 markdown 包裹。${mergedNote}

# 验证与判定原则
1. **复用已有污点链快速核验，不要从零重追**：只抽查关键跳与阻断点；仅当污点链明显不完整、断裂或存疑时才补读源码。
2. **宁可保留，不可漏判**：只有确信防御有效或路径不可达才判 false_positive；拿不准一律 conditional。
3. 净化“看起来存在”不等于有效：只改变类型/容器却保留可控字节的包装不算净化；存在旁路直达 Sink 即 conditional。
4. 不要因"需要权限/有前置条件"就判 false_positive——那属于 conditional。
5. 未授权可达直达严重危害（RCE/任意文件读写/脱库/越权）→ verified_severity 保持 high/critical。

# 结束
${endgame}
用简体中文汇报本路核了多少条、真阳性/误报各多少。`;
}

/**
 * AI 智能去重单路工人提示词：本路只比对一组（已按文件装箱），用全局 index 落盘。
 * 与二次评级同一套工人池：每路约 batchSize 条，最多同时 concurrency 路。
 */
export function buildDedupWorkerPrompt(
  dir: string,
  groupFile: string,
  outFile: string,
  count: number,
  groupNo: number,
  groupTotal: number,
  opts: { lean?: boolean } = {}
): string {
  const lean = opts.lean === true;
  const endgame = lean
    ? `写入 \`${outFile}\` 后：若已成功落盘则无需再输出 StructuredOutput；仅当落盘失败时才补输出 {duplicate_groups:[...]}。`
    : `写入 \`${outFile}\` 后，再输出 {duplicate_groups:[...]} 作为兜底。`;
  return `你是资深代码审计去重员。这是第 ${groupNo}/${groupTotal} 路语义去重，本路只比对 ${count} 个候选。

# 核心理念：漏洞是一个「面」不是一个「点」
同一危险代码点常可经不同触发条件 / 参数 / 入口被利用，造成不同漏洞情况。这些是同一点的多个利用面，必须各自独立保留，绝不能压成一条。

# 你的角色
本路独立完成本组，不要派 Task/Agent 子智能体，也不要去比对清单以外的 index。比完立刻落盘。

# 目标目录（只读查证源码，不要修改/部署）
${dir}

# 本路待去重清单
${groupFile}
该文件是 JSON 数组，每项含 **全局 index**、title、severity、category、file、line、description。

# ⚠ 三分类红线
- **只在同一文件内比对**：不同文件的候选一律不成组。
- **纯重复 → duplicate_indexes（删除）**：只是中英文/措辞不同，但同一 sink + 同一触发条件 + 同一参数 + 同一漏洞类型 + 同一根因。
- **同点不同利用面 → variant_indexes（保留、归簇）**：同一文件同一代码点/根因，但触发条件 / 参数 / 利用路径 / 漏洞类型不同。
- **拿不准一律放 variant_indexes 保留**（宁可多留，绝不放进 duplicate_indexes）。
- 不同函数/不同 sink/不同根因 → 各自独立，不成组。

# 落盘（后端只读磁盘）
比完后把结果写入 \`${outFile}\`，内容是**严格合法 JSON 数组**（不是外包一层对象），每个元素是一组：
- \`keep_index\`：代表项的**全局 index**（选信息最全、定位最准、严重度最高的一条）。
- \`duplicate_indexes\`：该组【纯重复·会删除】项的**全局 index** 数组。
- \`variant_indexes\`：该组【同点不同利用面·会保留】项的**全局 index** 数组。
- \`reason\`：判定依据（中文）。
没有任何纯重复也没有多利用面就写入空数组 \`[]\`。索引必须是清单里的真实全局 index。⚠ 严格 JSON：引号转义、无尾逗号、不要 markdown 包裹。

# 结束
${endgame}
用简体中文汇报本路合并纯重复多少条、识别多少个利用面簇。`;
}

/**
 * 红队二次评级单路工人提示词：本路只评一组，用全局 index 落盘。
 * 与去重/代码级验证共用工人池：每路 batchSize 条，最多同时 concurrency 路。
 */
export function buildRegradeWorkerPrompt(
  dir: string,
  groupFile: string,
  outFile: string,
  count: number,
  groupNo: number,
  groupTotal: number
): string {
  return `你是资深红队专家。这是第 ${groupNo}/${groupTotal} 路二次评级，本路只评 ${count} 个漏洞。

# 你的角色
本路独立完成这 ${count} 条，不要派 Task/Agent 子智能体，也不要去评清单以外的 index。评完立刻落盘。

# 目标目录（只读查证源码，不要修改/部署）
${dir}

# 本路待评级清单
${groupFile}
该文件是 JSON 数组，每项含 **全局 index**、title、severity、category、file、line、description。**必须覆盖本文件每一个 index，不得遗漏/合并。**

# 落盘（后端只读磁盘）
评完后把结果写入 \`${outFile}\`，内容是**严格合法 JSON 数组**（不是外包一层对象），每个元素字段：
- \`index\`：清单里的**全局序号**（必填，不要改成本路 1..${count}）。
- \`title\`：原标题（核对用）。
- \`title_cn\`：简体中文标题（代码标识符可保留）。
- \`category_cn\`：类别的简体中文（如 命令注入、路径穿越；不得用英文）。
- \`adjusted_severity\`：critical/high/medium/low/info。
- \`red_team_value\`：严重/高危/中危/低危/无（与 adjusted_severity 一一对应）。
- \`auth_required\`：none/user/admin（取所有可达路径中权限最低的一条）。
${AUTH_MULTIPATH_RULE}
- \`auth_reason\`：鉴权判定理由（中文，简短）。
- \`reason\`：评级理由（中文）。
⚠ 严格 JSON：引号转义、无尾逗号、不要 markdown 包裹。

# 评级尺度
- 严重：未授权即可完全接管/大规模脱库/未授权 RCE；高危：有严重危害但需一定前置（如登录低权/后台 RCE）；中危：有真实危害但范围或条件受限；低危：危害有限或门槛很高；无：基本无实战价值。
${LOW_VALUE_SEVERITY_POLICY_GUIDANCE}
- 只调整等级、不新增/删除漏洞。

# 结束
写入 \`${outFile}\` 后，再输出 {ratings:[...]} 覆盖本路全部 index 作为兜底。用简体中文汇报本路评了多少条、调整了多少条。`;
}

/**
 * 构建发送给 Pi Agent 的完整审计提示词。
 * 在用户可配置的核心提示词基础上，追加审计目标与结构化输出要求。
 */
/** 后端按源码占比检测出的多语言调度计划（注入主控 prompt，强制其对次要语言也派高危子集）。 */
export interface LangDispatchPlan {
  /** 主导语言 key（如 php / jsts / python）。 */
  primary: string;
  /** 主导语言中文名（如 PHP）。 */
  primaryLabel: string;
  /** 主导语言应派的完整专项子智能体清单。 */
  primaryAgents: string[];
  /** 次要语言（占比>=阈值）：只派高危子集。 */
  secondaries: { lang: string; label: string; ratio: number; agents: string[] }[];
  /** 通用 3 个（前端/API + 逻辑Bug/DoS + 跨文件数据流可达性），与语言无关始终派。 */
  universal: string[];
}

/** 渲染多语言调度计划文本块；无 plan 或无次要语言时给出对应说明，供 buildPrompt 注入。 */
function langDispatchBlock(plan?: LangDispatchPlan): string {
  if (!plan) return '';
  const pct = (r: number) => `${Math.round(r * 100)}%`;
  const primaryLine = `- **主导语言 ${plan.primaryLabel}**：派**完整专项子智能体**（共 ${plan.primaryAgents.length} 个）——${plan.primaryAgents
    .map((a) => `\`${a}\``)
    .join('、')}`;
  const secLines =
    plan.secondaries.length === 0
      ? '- **次要语言**：无（本项目未检出占比达阈值的其它语言）'
      : plan.secondaries
          .map(
            (s) =>
              `- **次要语言 ${s.label}（源码占比约 ${pct(s.ratio)}）**：只派**高危方向子集**（RCE / 文件读取写入包含 / 路径穿越 / SQL 注入 / 鉴权 / 反序列化，共 ${s.agents.length} 个）——${s.agents
                .map((a) => `\`${a}\``)
                .join('、')}`
          )
          .join('\n');
  const universalLine = `- **通用（与语言无关，始终派）**：${plan.universal
    .map((a) => `\`${a}\``)
    .join(
      '、'
    )}——其中 \`dataflow-reachability-auditor\` 以每个危险 Sink 为锚点反向枚举所有跨文件入口/写入者，专抓"净化写在入口层、危险构造藏在被复用底层"及"输入在 A 文件注入、Sink 在 B 文件拼接"的跨文件漏报。`;
  return `
# 多语言调度计划（后端已按源码占比检测·最高优先级·必须严格执行）
本项目为**多语言融合项目**。后端已按源码体量占比检测出下列语言构成，你在第二步调度子智能体时**必须严格按此计划派发**，不得只派主导语言而漏掉次要语言（这是次要语言漏洞被漏报的头号原因）：
${primaryLine}
${secLines}
${universalLine}

**硬性要求**：
1. 以「阻塞/等待返回」方式完成本会话负责的全部专项，并确认 \`JSON/<子智能体类型>.json\` 均已落盘，再进入后续流程。严禁只处理主导语言的那一套。
2. 每个子智能体的结果**固定写入以其类型命名的文件** \`JSON/<子智能体类型>.json\`（如 \`jsts-rce-security-guard\` → \`JSON/jsts-rce-security-guard.json\`），供后端自动核对漏跑并精准补跑。
3. 次要语言只在上述高危方向发力即可，但在这些方向上同样要**逐端点/逐Sink/逐触发条件穷举、严禁合并或抽样**。
4. 若某语言源码分散在多个子目录/服务中，需覆盖全部子目录，不要只扫一个入口目录。
`;
}

export function buildPrompt(corePrompt: string, dir: string, language = 'php', resultsDir?: string): string {
  const out = resultsDir || dir;
  const lang = AUDIT_LANGUAGE_LABELS[language] || language;
  const agents = subagentsForLanguage(language);
  const n = agents.length;
  const missions = agents
    .map((t) => `- \`${t}\`：${subagentMission(t)} → 必须写入 \`${out}/JSON/${t}.json\``)
    .join('\n');
  return `${corePrompt}

# 审计任务
对目录 ${dir} 中的 **${lang}** 源码做静态安全审计。本项目只审这一种语言。

# 产物目录
源码目录 ${dir} 只读。所有产物写入 ${out}。禁止改源码、禁止使用 MCP。

# 本会话范围
后端会为下列 ${n} 路专项各自拉起独立进程。若你被指派其中一路，只处理自己那一类并写入对应 \`JSON/<类型>.json\`：
${missions}

# 硬性要求
- 只负责自己那一类；逐端点 × 逐 Sink × 逐触发条件成条，严禁合并抽样。
- 数据流类漏洞必须有逐跳 taint_chain（文件:行/函数）。
- title/category/description/recommendation/taint_chain 用简体中文。
- 结果写入指定 JSON 文件：顶层数组，或含 findings/vulnerabilities/issues 的对象。0 发现也要写合法空数组。
- 不要去重、不要代码级验证、不要定级校准、不要搭靶机、不要输出组合利用链。

# 验收
\`JSON/<类型>.json\` 落盘后，按 JSON Schema 输出汇总。vulnerabilities 是高召回原始清单，宁多勿漏。
`;
}

/**
 * 构建「靶机环境预搭建」提示词（与代码审计并行执行，只搭建不利用）。
 * 仅调用 Docker 环境搭建 把本地靶机环境拉起来并保持运行，
 * 不进行任何漏洞利用——利用验证在审计完成后的独立阶段进行。
 */
export interface EnvSpec {
  /** 该项目专属的宿主端口（唯一，避免多项目抢同一端口串台）。 */
  port: number;
  /** 该项目专属的 docker compose 项目名（唯一，作为容器归属与清理的锚点）。 */
  projectName: string;
  /** 审计目标的确切版本（如 1.8.0-beta.29）；用于锁定靶机版本，杜绝拉最新。 */
  version?: string;
  /** 系统名（如 grav），仅用于提示。 */
  systemName?: string;
}

/**
 * 生成「靶机环境硬性规格」文本块：版本锁定 + 端口隔离 + compose 项目名隔离 + 产物落工作区。
 * buildEnvPrompt（预搭建）与 buildVerifyPrompt（兜底重搭）共用，保证两处规格一致。
 */
function envSpecBlock(dir: string, spec: EnvSpec): string {
  const verLine = spec.version
    ? `**${spec.systemName ? spec.systemName + ' ' : ''}${spec.version}**`
    : '工作目录中现有源码所对应的那个确切版本';
  return `# 环境规格
1. **用当前工作区源码搭建**：靶机必须运行 ${verLine}，即**直接使用 ${dir} 下现有源码**构建运行。
   - Compose 中应用服务使用 \`build:\` 指向本工作区即可；不要改去拉别的版本、官方预构建应用镜像或 git clone 主分支。
   - 为了把服务跑起来，允许改本工作区里的配置、Dockerfile、compose、初始化脚本等；不必管 Git 是否干净、HEAD 是否对得上标签。
   - 依赖（vendor）、插件、主题若缺失，安装与当前源码约束兼容的版本即可。
2. **端口隔离**：宿主访问端口必须使用 **${spec.port}**，靶机地址即 \`http://localhost:${spec.port}\`。不要使用 8080 等其它端口，也**不得复用其它端口上已存在的、不属于本项目的容器**。
3. **容器归属隔离**：必须使用 compose 项目名 **${spec.projectName}**（例如 \`docker compose -p ${spec.projectName} up -d\`，或在 compose 文件中设置 \`name: ${spec.projectName}\`）。这样容器才带 \`com.docker.compose.project=${spec.projectName}\` 标签，便于后续识别与清理。
4. **产物落本工作区**：生成的 \`docker-compose.yml\` / \`Dockerfile\` / \`.env\` 等必须写在 ${dir} 内，不要写到别处。
5. 搭建完成后用 \`http://localhost:${spec.port}\` 自测首页可访问即可。`;
}

export function buildEnvPrompt(dir: string, spec: EnvSpec): string {
  return `用 Docker / docker compose 为下面的项目源码搭建本地可访问的靶机运行环境。这一步与代码审计并行进行，目的是提前把环境准备好，**只搭建、不做漏洞利用验证**。

# 目标目录
${dir}

${envSpecBlock(dir, spec)}

# 任务要求
1. 按上面的规格用 docker / docker compose 把该项目运行起来，处理好依赖、数据库、初始化与配置。
2. 尽量准备可用的高权限（管理员）和低权限测试账号；验证码、限流等挡路时，用配置、环境变量或必要的本地改动去掉即可。
3. 持续确认服务健康，确认靶机地址 \`http://localhost:${spec.port}\` 可访问、账号可正常登录。
4. 搭建完成后**让容器保持运行**（不要 docker compose down/stop），便于后续利用验证阶段直接复用。
5. **不要进行任何漏洞利用或攻击验证**——那是后续独立阶段的工作。

# 硬性要求：把靶机交接信息写入 ${dir}/TARGET_ENV.json
后续的**利用验证是另一个独立会话，看不到你这里的输出**，只能靠这个文件拿到登录凭据。因此你**必须**在项目根目录写入 \`TARGET_ENV.json\`（严格合法 JSON，字符串内引号转义），结构如下：
\`\`\`json
{
  "mode": "external",
  "url": "http://localhost:${spec.port}",
  "login_url": "http://localhost:${spec.port}/admin/login",
  "compose_project": "${spec.projectName}",
  "compose_file": "docker-compose.code.yml",
  "version": "${spec.version || ''}",
  "source_version": "从本工作区源码读取的确切版本，必须与 version 完全相同",
  "source_commit": "git rev-parse HEAD 的完整提交哈希；无 Git 时填写 null",
  "source_fingerprint": "无 Git 时源码目录 SHA-256；有 Git 时填写 null",
  "build_provenance": "local-source",
  "runtime_version": "实际运行时版本，必须与 source_version 完全相同",
  "runtime_version_proof": {
    "type": "http",
    "target": "http://localhost:${spec.port}/公开版本接口",
    "contains": "必须在实时响应/日志/文件中出现的版本或提交文本"
  },
  "accounts": [
    { "role": "admin", "username": "admin", "password": "实际可登录的密码" },
    { "role": "user",  "username": "user",  "password": "实际可登录的密码" }
  ],
  "registration": { "exists": true, "default_open": true, "note": "注册入口URL / 判定依据（是否默认开放、是否需管理员审核或邀请码）" },
  "notes": "登录方式 / 特殊说明（如何携带会话、CSRF token 获取方式等）"
}
\`\`\`
要求：account 里的用户名密码**必须是你已实测能成功登录的**；至少提供一个管理员账号；写完后读回确认该文件能被 JSON 解析。版本字段尽量填写当前工作区能读到的值，缺了也不要为此判定搭建失败。

# 额外：判定「注册功能」（用于识别前台/未授权 RCE，务必如实填写 registration 字段）
在搭建/访问靶机时顺带判定该系统是否面向**匿名访客**开放自助注册：
- \`registration.exists\`：系统是否存在用户自助注册功能（true/false）。
- \`registration.default_open\`：在**默认安装配置**下，匿名访客是否**无需管理员审核/邀请码**即可自行注册并登录为普通用户（true/false）。若注册默认关闭、需管理员开启、需邀请码或需审核，填 false。
- 判定以**默认配置下的真实可注册性**为准（可实际走一遍注册流程验证），并在 note 里说明依据与注册入口。

# 结束语
完成后用简体中文简要说明：靶机地址、运行版本、已创建的账号、当前服务状态，并确认 TARGET_ENV.json 已写入。`;
}

/**
 * 非 Web 项目（Android/库/CLI）沙箱环境预搭建：生成 _harness/ PoC 沙箱，不搭 HTTP 靶机。
 */
export function buildHarnessEnvPrompt(dir: string, spec: EnvSpec): string {
  const verLine = spec.version
    ? `**${spec.systemName ? spec.systemName + ' ' : ''}${spec.version}**`
    : '工作目录中现有源码所对应的那个确切版本';
  return `为下面的**非 Web 项目**搭建**沙箱验证环境**（形态 B/C/Android）。这一步与代码审计并行，**只搭建沙箱、不做漏洞利用验证**。

# 目标目录
${dir}

# 项目形态（必读）
此项目**不是** PHP/Node Web 站点，**禁止**：
- 强行搭建 HTTP 服务器、nginx/apache 站点
- 使用 AskUserQuestion 等待用户选择（自行按 Android/库/CLI 最佳实践决策）
- 因「没有 Web 入口」而放弃——应编写 Harness 沙箱脚本

# 版本
靶机/沙箱必须针对 ${verLine} 的现有源码（${dir}），不要 clone 其它版本。允许为跑通沙箱改本工作区文件。

# 任务要求
1. 在 \`${dir}/_harness/\` 下编写**极简可执行 PoC 沙箱**（任选可行方案）：
   - Android：Robolectric/JUnit 单测、Kotlin main、或 adb/am start DeepLink 脚本（附 README 命令）
   - 库/组件：test_harness.js / Main.java 引入目标库并接收 payload
   - CLI：编译可执行文件 + 示例调用命令
2. 沙箱应能验证常见漏洞类型：exported Activity/DeepLink、Backup 路径穿越、WebView、SSRF(OkHttp mock)、反序列化入口等（按源码实际存在项编写，不必全覆盖）。
3. 执行一次 **smoke 自检**（编译/运行最小用例），确认沙箱可运行。
4. **不要**进行任何漏洞利用验证——那是后续独立阶段。

# 硬性要求：写入 ${dir}/TARGET_ENV.json
后续验证会话**看不到你的对话**，只能靠此文件。必须写入（严格合法 JSON）：
\`\`\`json
{
  "mode": "harness",
  "url": "harness://local",
  "project_shape": "android",
  "harness_dir": "_harness",
  "smoke_command": "可选：一条可执行的 smoke 命令（如 cd _harness && ...）",
  "entry_commands": ["示例：如何运行某个 PoC"],
  "version": "${spec.version || ''}",
  "source_version": "${spec.version || '当前源码确切版本'}",
  "source_commit": "git rev-parse HEAD 完整值；无 Git 时 null",
  "source_fingerprint": "无 Git时源码 SHA-256；有 Git 时 null",
  "build_provenance": "local-source",
  "runtime_version": "${spec.version || '当前源码确切版本'}",
  "runtime_version_proof": {
    "type": "file",
    "target": "_harness/VERSION_PROOF.txt",
    "contains": "源码版本或完整提交"
  },
  "notes": "沙箱说明、依赖（JDK/Android SDK 等）、限制"
}
\`\`\`
- \`mode\` 必须为 \`"harness"\`
- \`url\` 固定 \`"harness://local"\`（无 HTTP 端口）
- 版本字段尽量填写，缺了也不要为此判定搭建失败
- 不要求 accounts / login_url

# 结束语
完成后用简体中文说明：已在 _harness/ 生成哪些脚本、smoke 是否通过、TARGET_ENV.json 已写入。`;
}

/**
 * Harness 沙箱单漏洞验证主控 prompt（无组合链、无 HTTP 靶机）。
 */
export function buildHarnessVerifyMasterPrompt(
  corePrompt: string,
  dir: string,
  vulns: VulnBrief[],
  envInfo: string,
  resultsDir: string,
  concurrency: number,
  doneTitles: string[] = []
): string {
  const list = vulns
    .map(
      (v, i) =>
        `${i + 1}. [${v.severity}] ${v.title} —— ${v.file_path}${v.line ? ':' + v.line : ''}\n   ${(
          v.description || ''
        ).slice(0, 200)}`
    )
    .join('\n');
  const doneBlock =
    doneTitles.length > 0
      ? `\n# 已在上次验证完成、本轮跳过的漏洞（共 ${doneTitles.length} 个，不要重复验证）\n${doneTitles
          .map((t, i) => `${i + 1}. ${t}`)
          .join('\n')}\n`
      : '';
  const exploitsDir = `${resultsDir}/exploits`;
  const harnessBlock = envInfo
    ? `# 沙箱环境（TARGET_ENV.json，直接使用）
${envInfo}
`
    : `# 沙箱环境
读取 \`${dir}/TARGET_ENV.json\` 与 \`${dir}/_harness/\` 目录，在沙箱脚本上执行 PoC，**禁止** curl HTTP 靶机或搭建 Web 服务。
`;
  return `${corePrompt}

# 你的角色：沙箱验证【主控】——只做派发、编排、汇总
本项目为**非 Web 形态**（Android/库/CLI），在 \`_harness/\` 沙箱上验证漏洞，**不使用 HTTP 靶机**，**不运行组合链验证**。

${harnessBlock}

# 待验证目标目录
${dir}

# 沙箱验证须知
- **禁止** curl/http 访问 localhost 靶机、禁止 docker compose 搭 Web 站
- 在 _harness/ 中编写或调用 PoC：单测、脚本、adb Intent 等
- 每条漏洞必须给出可复核的执行过程与输出证据（写入 local_result）
- 无法在本机运行 Android 模拟器时，可运行 Robolectric/单元级 PoC；仍无法执行则标 restricted 并说明原因

# 待验证漏洞（共 ${vulns.length} 个 严重/高危/中危）
${list}
${doneBlock}

# 落盘要求（后端只读磁盘）
每个子智能体把本组结果写入 \`${exploitsDir}/<唯一名>.json\`（JSON 数组），字段：
\`vulnerability\`, \`local_exploitable\`（success/failed/restricted/unknown）, \`local_result\`, \`auth_required\`, \`detail\`, \`exploitable_versions\`, \`historical_verification\`（[]）

${EXPLOIT_GUIDE}

# 执行流程
1. 阅读 TARGET_ENV.json 与 _harness/ 现有脚本。
2. 分组并发验证（建议同时约 ${concurrency} 个子智能体，严重/高危每组 ≤${VERIFY_BATCH_HIGH_EXPORT}、中危 ≤${VERIFY_BATCH_MED_EXPORT}）。
3. 子智能体必须在沙箱上实测，结果落盘到 \`${exploitsDir}/\`。
4. 完成后 StructuredOutput 输出 {exploits, chains: [], summary} 兜底。

# 结束语
用简体中文汇报：共验证多少、success/restricted/failed 各多少，结果目录 ${resultsDir}。`;
}

/** Harness 沙箱补验/单批 prompt（后端 retry 或单漏洞验证用）。 */
export function buildHarnessVerifyBatchPrompt(
  corePrompt: string,
  dir: string,
  batch: VulnBrief[],
  envInfo: string,
  batchNo: number,
  totalBatches: number
): string {
  const list = batch
    .map(
      (v, i) =>
        `${i + 1}. [${v.severity}] ${v.title} —— ${v.file_path}${v.line ? ':' + v.line : ''}\n   ${(
          v.description || ''
        ).slice(0, 200)}`
    )
    .join('\n');
  const harnessBlock = envInfo
    ? `# 沙箱环境（TARGET_ENV.json）
${envInfo}
`
    : `# 沙箱环境
读取 \`${dir}/TARGET_ENV.json\` 与 \`${dir}/_harness/\`，**禁止** curl HTTP 靶机。
`;
  return `${corePrompt}

# 使用的技能：单漏洞远程验证（沙箱单漏洞逐条验证）
本批在 **Harness 沙箱**（非 Web 靶机）上验证，调用 **单漏洞远程验证** 技能。

# 待验证目标目录
${dir}

${harnessBlock}

# 本批待验证漏洞（第 ${batchNo}/${totalBatches} 批，共 ${batch.length} 个）
**必须对下面每一个漏洞在沙箱上实测并给出结论。**
${list}

${EXPLOIT_GUIDE}

# 输出
StructuredOutput：{ exploits: [...], chains: [], summary }；同时把结果落盘到 \`${dir}/_harness_verify/exploits/\`。`;
}

interface VulnBrief {
  id?: string;
  title: string;
  severity: string;
  category?: string;
  file_path: string;
  line: number | null;
  description: string;
}

/**
 * 构建漏洞验证提示词（独立会话）。
 * 验证阶段重新起一个会话，因此把审计阶段已发现的漏洞清单注入提示词，
 * 据此搭靶机并做利用验证。
 */
export function buildVerifyPrompt(
  corePrompt: string,
  dir: string,
  vulns: VulnBrief[],
  envInfo = '',
  spec?: EnvSpec
): string {
  const envBlock = envInfo
    ? `# 靶机登录凭据（来自环境搭建阶段的 TARGET_ENV.json，请直接使用）
以下是搭建靶机时创建的可登录账号与地址，**直接拿来登录使用**；若发现凭据失效，再读取 \`${dir}/TARGET_ENV.json\` 或容器配置核对：
\`\`\`json
${envInfo}
\`\`\`
`
    : `# 靶机登录凭据（重要）
本次没有读到环境搭建交接文件。请**自己接手获取登录凭据**：
1. 先读取 \`${dir}/TARGET_ENV.json\`（若存在）拿到账号与地址；
2. 若文件不存在或凭据无效，则检查正在运行的容器配置/数据库/初始化脚本，找出或重置出一个可用的管理员账号；
3. 实在无法获取时，重新用 Docker 搭建环境并创建高/低权限账号，再继续验证。
不要因为"拿不到账号"就跳过需要登录的漏洞。
`;
  const list =
    vulns.length === 0
      ? '（审计阶段未发现漏洞）'
      : vulns
          .slice(0, 60)
          .map(
            (v, i) =>
              `${i + 1}. [${v.severity}] ${v.title} —— ${v.file_path}${
                v.line ? ':' + v.line : ''
              }\n   ${(v.description || '').slice(0, 200)}`
          )
          .join('\n');

  return `${corePrompt}

# 待验证目标目录
${dir}

# 靶机环境（重要）
靶机环境**可能已在代码审计期间并行搭建好并处于运行中**。请**优先复用已运行的靶机**：
- 先用 \`docker ps\` 等方式检查是否已有本项目对应的、正在运行的容器与可访问地址，有则直接拿来做利用验证，不要重复搭建。
- 仅当没有可用的运行中靶机，或已有环境不健康时，才重新用 Docker 搭建（这也是并行搭建失败时的兜底重试）。
${
  spec
    ? `\n# 若需重新搭建靶机，必须遵守以下规格（与预搭建一致，杜绝版本/端口串台）\n${envSpecBlock(
        dir,
        spec
      )}\n`
    : ''
}
${envBlock}
# 审计阶段已发现的漏洞清单（共 ${vulns.length} 个）
${list}

# 关键步骤：登录后实测，不要止步于"代码确认"
很多漏洞需要一定权限才能触发（如后台功能、文件上传、配置修改、定时任务等）。**靶机环境搭建时已经创建了高/低权限测试账号并移除了验证码/频率限制**，你必须充分利用它们，把验证做"实"：

1. **先登录再测**：对需要权限的漏洞，**实际用对应账号登录拿到会话/Cookie/Token**（管理员漏洞用管理员账号，普通用户漏洞用低权限账号），再带着登录态发起真实利用请求。不要因为"需要登录/需要管理员"就直接判 restricted。
2. **真正执行利用闭环**：要实际把动作做完并观察结果——例如真的上传恶意文件并访问、真的提交注入 payload 并取回证据、真的修改配置并触发危险代码路径、真的发起越权请求并确认拿到了不该拿的数据。只"读源码确认代码路径存在"**不算**验证成功。
3. **结论判定标准**（务必基于真实执行结果）：
   - success：带登录态实际执行后**确有真实危害**（拿到 shell/敏感数据/越权操作生效/稳定 DoS 等），并给出可复现的请求与证据。
   - failed：实际执行后被防御拦截或无法复现（说明卡在哪个防御）。
   - restricted：**仅当**你已**实际登录并尝试执行**，但因当前版本特定防御（黑名单、白名单、CSRF/nonce、配置项等）确实无法完成时才用，并在 local_result 里写清"用了哪个账号、执行了什么、被什么挡住"。**严禁**把"还没动手、只看了代码"写成 restricted。
   - unknown：仅在环境异常、无法测试时使用。
4. 凡是需要权限的漏洞，local_result 必须体现**真实的登录与执行过程**（用的账号、发出的请求、服务端响应/证据），而不是停留在源码分析。
5. **如实标注权限级别（auth_required）**：验证完成后必须在 auth_required 中如实填写触发该漏洞【实际需要】的权限级别——完全无需任何账号/登录才填 none；只要 local_result 里出现"登录""使用/以某账号""管理员身份"等字样，就必须填 user 或 admin，**不得**因为漏洞本身"看起来门槛低"就填 none，也不得让 auth_required 与 local_result 的叙述自相矛盾。

${authRemoteIndependentRule(dir)}

# 关键步骤：历史版本验证（对【每个单漏洞】和【每条组合链】都必须做）
当前最新版本可能已经修了某个漏洞或加了防御，导致本地打不通——但这**不代表历史版本也打不通**。某个防御可能是在某个版本才引入的，更早的版本依然可被利用。因此在完成当前版本验证后，对**每一个**单漏洞与**每一条**组合链，都要追加历史版本验证：

1. **用 git 提交记录定位修复/防御的引入点**：
   - github 来源项目：直接用 ${dir} 本地仓库的 git 历史（\`git log\`/\`git blame\`/\`git diff\`），定位该漏洞对应的"修复提交 / 防御引入提交"（fix_commit），据此界定"修复之前"哪些 release 仍存在该漏洞。
   - 非 git 来源（压缩包）：根据项目名/系统名找到其上游 GitHub 仓库，用同样方式分析其 git 历史。找不到上游仓库时退化为基于版本与防御代码差异的判断，并在 reason 中注明。
2. **先圈定候选池：近 3 年内发布的【全部】版本**：用 \`git tag\` 配合发布日期（\`git log -1 --format=%ci <tag>\` 或 GitHub release 日期）列出该项目**最近 3 年内发布的所有 release tag**作为候选池，3 年以前的老版本一律不纳入；近 3 年内无更早版本时说明即可。
3. **由你（AI）从候选池中决策挑选最多 5 个版本做验证**：依据 git 提交记录，**优先挑选相对上一版本改动较大的那些版本**（改动文件多、提交量大，尤其是触及该漏洞相关代码/防御逻辑的版本），它们最可能引入或移除该漏洞的防御。**所选版本总数严格不超过 5 个**（按需选 1~5 个，不要硬凑满 5 个）。
4. **混合验证（git 分析 + 代表版本实打）**：先用代码差异分析判断每个选中版本是否存在/未防御该漏洞（method=git_analysis）；再从中挑 1~2 个最有代表性的版本**真实 checkout 并搭建该版本的 docker 靶机实测利用**（method=live_target），给出实打证据。
5. 将上述结果写入对应漏洞/链的 \`historical_verification\` 数组：每个版本一条，含 version、github_url、status、method、fix_commit、reason。

# 输出要求
完成利用验证后，必须严格按照指定的 JSON Schema 输出最终结果，仅输出一个 JSON 对象。
所有文本字段一律使用简体中文，语言专业、自然、具体。

1. exploits：对每个尝试利用的【单个漏洞】给出结论。先说明在本地靶机是否利用成功（success/failed/restricted/unknown）；
   并**如实填写 auth_required**（none/user/admin，必须与 local_result 描述的真实验证过程一致，不得矛盾——local_result 里写了"登录/账号/管理员"就不能填 none）；
   并在 historical_verification 中给出该漏洞在历史版本的验证结果（见上一节，必填，逐版本列出）；
   若本地受限无法成功，请同时在 exploitable_versions 中汇总其可成功利用的版本号与对应 GitHub 地址。
2. chains：把需要【组合多个漏洞】才能达成的利用链单独整理到 chains 中（如未授权 RCE 链、权限提升链等），
   每条链给出名称、最终危害 impact、**起始权限级别 auth_required**（同上原则，与 steps/detail 一致）、验证结果 status、
   有序步骤 steps（每步对应一个漏洞与动作）、技术细节 detail、
   以及 historical_verification（该组合链在历史版本的验证结果，必填，逐版本列出）与可利用历史版本。
   单个漏洞即可达成的利用只放在 exploits，不要放进 chains。`;
}

/* ---------------- 远程验证：分批「单漏洞全覆盖实打」 + 组合链（共用靶机，串行） ---------------- */

/** 靶机凭据块（验证阶段复用：地址 + 账号）。 */
function credBlock(dir: string, envInfo: string): string {
  return envInfo
    ? `# 靶机登录凭据（来自环境搭建阶段 TARGET_ENV.json，直接使用）
\`\`\`json
${envInfo}
\`\`\`
若凭据失效，再读取 \`${dir}/TARGET_ENV.json\` 或容器配置核对。`
    : `# 靶机登录凭据
未读到交接文件。请读取 \`${dir}/TARGET_ENV.json\`，或检查正在运行的容器配置/数据库找出可用管理员账号；不要因为"拿不到账号"就跳过需要登录的漏洞。`;
}

/** 登录实打要求（与完整验证一致：必须真正执行利用闭环，不能止步于代码确认）。 */
const EXPLOIT_GUIDE = `# 关键：登录后实测，不要止步于"代码确认"
靶机搭建时已创建高/低权限账号并移除验证码/频率限制，必须充分利用：
1. **先登录再测**：需要权限的漏洞，实际用对应账号登录拿到会话/Cookie/Token 后再带登录态发起真实利用请求；不要因"需要登录/管理员"就直接判 restricted。
2. **真正执行利用闭环**：真的上传并访问恶意文件、真的提交注入 payload 取回证据、真的改配置触发危险路径、真的发越权请求确认拿到不该拿的数据。只"读源码确认路径存在"**不算**成功。
3. **结论判定**（基于真实执行结果）：
   - success：实际执行后确有真实危害（拿 shell/敏感数据/越权生效/稳定 DoS 等），给出可复现请求与证据。
   - failed：实际执行后被防御拦截或无法复现。
   - restricted：已**实际登录并尝试执行**，但因当前版本特定防御确实无法完成，需写清"用了哪个账号、执行了什么、被什么挡住"。严禁把"只看了代码"写成 restricted。
   - unknown：仅环境异常无法测试时使用。
4. **权限降级矩阵（privilege_results）必填**：对每个验证成功/受限的漏洞，都要**逐档实测** 无权限(none)→普通用户(user)→管理员(admin) 三种权限下能否触发，如实写入 \`privilege_results:{none:{status,evidence?},user:{...},admin:{...}}\`（status ∈ success/failed/restricted/skipped/unknown）。**先用无权限打，再依次升级**。
5. **如实标注权限级别（auth_required = 成功的最低档）**：auth_required 取 privilege_results 中 success 的最低档（none<user<admin）——无权限成功→none；无权限失败但普通用户成功→user；仅管理员成功→admin。不得与 local_result / privilege_results 矛盾。
6. **多危害能力清单（impacts）必填**：逐项列出该漏洞成功后的所有危害/能力（任意文件写入/读取、命令执行、信息泄露、越权、凭据泄露、SSRF 等），一个漏洞往往不止一种，务必列全，供后端组合链阶段按能力拼接。`;

/** 历史版本验证要求（git 定位修复点 + 代表版本实打）。 */
function historyGuide(dir: string): string {
  return `# 关键：历史版本验证（对本批每个漏洞都要做）
当前版本可能已修复/加防御导致打不通，但更早版本可能仍可利用：
1. 用 git 历史（\`git log\`/\`git blame\`/\`git diff\`）定位该漏洞的"修复/防御引入提交"(fix_commit)；非 git 来源则找上游 GitHub 仓库同样分析，找不到则基于版本与防御代码差异判断并注明。
2. **先圈定候选池：近 3 年内发布的【全部】版本**。用 \`git tag\` 配合发布日期（\`git log -1 --format=%ci <tag>\` 或 GitHub release 日期）列出该项目**最近 3 年内发布的所有 release tag**作为候选历史版本池；**3 年以前的老版本一律不纳入**（年代久远、现实意义低）。若近 3 年内没有更早的版本，说明即可。
3. **再由你（AI）从候选池中决策挑选最多 5 个版本做验证**：依据 git 提交记录，**优先挑选相对上一版本改动较大的那些版本**（改动文件多、提交量大，尤其是触及该漏洞相关代码/防御逻辑的版本）——这些版本最可能引入或移除该漏洞的防御，验证价值最高。**所选版本总数严格不超过 5 个**（按实际需要选 1~5 个，不要盲目遍历全部候选，也不要硬凑满 5 个）。
4. 混合验证：对选中的版本先用代码差异分析是否未防御该漏洞(method=git_analysis)；再从中挑 1~2 个最有代表性的版本真实 checkout 实测(method=live_target)。
   ⚠ 若需为历史版本另起靶机，**务必使用唯一的随机高位端口（如 20000~60000 间随机取值）与独立的 compose 项目名**，**绝不要动当前正在复用的靶机、也不要与其它并行验证子智能体抢占同一端口**；历史靶机用完即 \`down\` 释放资源。
5. 结果写入每个漏洞的 \`historical_verification\`（逐版本：version/github_url/status/method/fix_commit/reason）；并把可成功利用的版本汇总进 \`exploitable_versions\`。`;
}

interface VerifyResultBrief {
  vulnerability: string;
  local_exploitable: string;
  /** 该漏洞成功后可提供的多种危害/能力（来自 单漏洞远程验证 第五步 impact），用于组合链按“能力→前置条件”拼接。 */
  impacts?: string[];
  /** 成功利用所需的最低权限（none/user/admin）。 */
  auth_required?: string;
}

/** 关闭历史版本验证时的说明：只验证当前版本，节约时间。最高优先级，覆盖核心提示词里任何相反指示。 */
const NO_HISTORY_NOTE = `# 仅验证当前版本（已关闭"历史版本验证" · 最高优先级，覆盖前文任何相反指示）
本次审计**已明确关闭历史版本验证**。无论前文（含上面的核心提示词）是否提到 github / 历史版本 / 旧版本利用，**一律忽略这些指示**：
- **只针对当前版本**靶机做利用验证；**严禁**对任何其他历史版本做分析、git 回溯、checkout、搭建或验证，也**不要去 github 查看/尝试历史版本**。
- 每个漏洞/链的 \`historical_verification\` 直接返回空数组 \`[]\`，\`exploitable_versions\` 也留空。`;

/** 远程验证：严重/高危每子智能体固定条数；中危每子智能体固定条数（仅远程 Web 靶机验证使用）。 */
export const VERIFY_BATCH_HIGH_EXPORT = 5;
export const VERIFY_BATCH_MED_EXPORT = 8;

/** 远程验证单批条数：critical/high → 5，medium → 8，其余 CHM 外等级回退为 5。 */
export function remoteVerifyBatchSize(severity: string): number {
  const s = String(severity || '').toLowerCase();
  if (s === 'medium') return VERIFY_BATCH_MED_EXPORT;
  return VERIFY_BATCH_HIGH_EXPORT;
}

/** 按严重度把待验证漏洞拆成固定大小批次（不混用不同 batchSize 的严重度）。 */
export function splitRemoteVerifyBatches(vulns: VulnBrief[]): VulnBrief[][] {
  const batches: VulnBrief[][] = [];
  let cur: VulnBrief[] = [];
  let curLimit = vulns.length > 0 ? remoteVerifyBatchSize(vulns[0].severity) : VERIFY_BATCH_HIGH_EXPORT;
  for (const v of vulns) {
    const limit = remoteVerifyBatchSize(v.severity);
    if (cur.length > 0 && (cur.length >= curLimit || limit !== curLimit)) {
      batches.push(cur);
      cur = [];
    }
    curLimit = limit;
    cur.push(v);
    if (cur.length >= curLimit) {
      batches.push(cur);
      cur = [];
    }
  }
  if (cur.length) batches.push(cur);
  return batches;
}

/** 生成远程验证主控用的「强制分组计划」文案（注入 prompt，便于主控按组派发子智能体）。 */
export function formatRemoteVerifyBatchPlan(batches: VulnBrief[][]): string {
  if (batches.length === 0) return '（无待验证漏洞）';
  return batches
    .map((batch, i) => {
      const limit = remoteVerifyBatchSize(batch[0]?.severity || 'high');
      const sevLabel =
        limit === VERIFY_BATCH_MED_EXPORT ? `中危 · 每组 ${VERIFY_BATCH_MED_EXPORT} 条` : `严重/高危 · 每组 ${VERIFY_BATCH_HIGH_EXPORT} 条`;
      const titles = batch
        .map((v, j) => `   ${j + 1}. [ID=${v.id || `legacy-${j + 1}`}] [${v.severity}] ${v.title}`)
        .join('\n');
      return `### 第 ${i + 1} 组（本组 ${batch.length} 个 · ${sevLabel}）
${titles}`;
    })
    .join('\n\n');
}

const REMOTE_VERIFY_SUBAGENT_RULES = `# ⚠ 远程单漏洞验证 · 子智能体硬性规则（仅远程 Web 靶机验证 · 务必逐字转达每个子智能体）
1. **必须对每个漏洞在靶机上真实发请求验证，禁止只读源码就判成功。
2. **每组固定条数（强制，不得塞入更多）**：
   - **严重 / 高危**：每个子智能体**恰好验证 ${VERIFY_BATCH_HIGH_EXPORT} 个**漏洞（本组不足 ${VERIFY_BATCH_HIGH_EXPORT} 条时验完本组全部即可）。
   - **中危**：每个子智能体**恰好验证 ${VERIFY_BATCH_MED_EXPORT} 个**漏洞（本组不足 ${VERIFY_BATCH_MED_EXPORT} 条时验完本组全部即可）。
3. **禁止**把多个分组的漏洞塞进同一个子智能体；**禁止**一漏洞派一个子智能体（除非该组只有 1 条且为末组余数）。
4. 子智能体必须对本组**每一个**漏洞登录靶机实打并原样回填 vulnerability_id；remote_status 只能是 success / failed / restricted（禁止 unknown 落盘结束）。**仅源码确认但远程未触发必须填 restricted，严禁填 success**。`;

/**
 * 分批「单漏洞全覆盖」验证 prompt：对本批**每一个**漏洞都必须登录靶机实打并给结论，
 * 不得挑选/跳过/合并。组合链不在此处理（最后统一做）。
 * @param remoteWeb 为 true 时使用远程 Web 靶机强制批次规则（严重/高危 3 条、中危 5 条、必须实测）。
 */
export function buildVerifyBatchPrompt(
  corePrompt: string,
  dir: string,
  batch: VulnBrief[],
  envInfo: string,
  spec: EnvSpec | undefined,
  batchNo: number,
  totalBatches: number,
  includeHistory = true,
  remoteWeb = false
): string {
  const list = batch
    .map(
      (v, i) =>
        `${i + 1}. [ID=${v.id || `legacy-${i + 1}`}] [${v.severity}] ${v.title} —— ${v.file_path}${v.line ? ':' + v.line : ''}\n   ${(
          v.description || ''
        ).slice(0, 200)}`
    )
    .join('\n');
  const batchLimit = batch.length > 0 ? remoteVerifyBatchSize(batch[0].severity) : VERIFY_BATCH_HIGH_EXPORT;
  const remoteHead = remoteWeb
    ? `# 本批：远程 Web 靶机单漏洞验证（无 Skill）
本批是**远程 Web 靶机**上的单漏洞验证。
本批共 ${batch.length} 个漏洞（第 ${batchNo}/${totalBatches} 批；严重/高危每组 ${VERIFY_BATCH_HIGH_EXPORT} 条、中危每组 ${VERIFY_BATCH_MED_EXPORT} 条；本批上限 ${batchLimit} 条）。**必须对本批每一个漏洞逐一实测**，不得跳过。**本批不做组合利用链**。

${REMOTE_VERIFY_SUBAGENT_RULES}
`
    : `# 本批：单漏洞逐条验证（无 Skill）
本批是**单个漏洞的逐条验证**：逐条做权限降级（管理员→普通用户→无权限）与假阳性取证。**本批不做组合利用链**（组合链由后续独立阶段处理）。
`;
  return `${corePrompt}

${remoteHead}

# 待验证目标目录
${dir}

# 靶机环境（已就绪，直接复用，请勿重搭）
靶机已在运行中。先用 \`docker ps\` 确认本项目容器在跑、用凭据里的地址确认可访问，**直接复用它做利用验证，不要重新搭建**（重搭会打断其它批次共用的同一靶机）。仅当确认靶机已不可用时，才按下面规格重搭。

# ⚠ 并发验证须知（重要）
当前有**多个验证子智能体在并发**对**同一个靶机**做利用验证。为避免互相干扰、污染彼此的测试结果：
- **严禁执行破坏性的全局操作**：不要重启/停止/删除靶机容器（\`docker restart/stop/down/rm\`）、不要清空或重建数据库、不要做全局配置重置或数据初始化。
- 利用尽量做成**局部、可自愈**：用你自己专属的测试数据（如带随机后缀的用户名/文件名），用完尽量清理；不要依赖"全库只有我一条数据"这种假设。
- 若某个利用**必须**改变全局状态才能验证，请在 local_result 中注明，并尽量在验证后恢复原状。
${spec ? `\n# 万一需重搭，必须遵守以下规格（与预搭建一致）\n${envSpecBlock(dir, spec)}\n` : ''}
${credBlock(dir, envInfo)}

# 本批待验证漏洞（第 ${batchNo}/${totalBatches} 批，共 ${batch.length} 个）
**必须对下面每一个漏洞逐一登录靶机实打并给出结论，禁止挑选、跳过、合并或只验证其中一部分。**
${list}

${EXPLOIT_GUIDE}

${authRemoteIndependentRule(dir)}

${includeHistory ? historyGuide(dir) : NO_HISTORY_NOTE}

# 输出要求
严格按指定 JSON Schema，通过 StructuredOutput 提交一个对象：
- exploits 数组必须**覆盖本批上面每一个漏洞**（${batch.length} 条，按顺序一一对应，不得遗漏/新增/合并），每条含 vulnerability_id（原样回填）、vulnerability、local_exploitable（源码/本地证据）、remote_status（远程权威结论）、local_result、**如实填写的 auth_required（必须与 privilege_results/local_result 一致，不得矛盾）**、${
    includeHistory
      ? 'historical_verification（必填）、exploitable_versions（受限时）'
      : 'historical_verification（留空数组 []）'
  }。
- **本阶段不要输出组合链**，chains 留空数组 []（组合链在后续统一阶段处理）。
所有文本用简体中文。`;
}

/**
 * 远程组合利用链验证「主控」prompt：每条链派一个子智能体（组合利用验证），结果落盘 chains/。
 */
export function buildChainPrompt(
  corePrompt: string,
  dir: string,
  verified: VerifyResultBrief[],
  envInfo: string,
  spec: EnvSpec | undefined,
  includeHistory = true,
  allVulnsBrief: string[] = [],
  crossLangCandidates: string[] = [],
  resultsDir?: string
): string {
  const list =
    verified.length === 0
      ? '（无已验证的单漏洞）'
      : verified
          .map((v, i) => `${i + 1}. [${v.local_exploitable || 'unknown'}] ${v.vulnerability}`)
          .join('\n');
  const pool =
    allVulnsBrief.length === 0
      ? '（无）'
      : allVulnsBrief.map((s, i) => `${i + 1}. ${s}`).join('\n');
  // 能力图：每个已远程验证漏洞“提供的危害/能力”（impact），供按“能力→前置条件”拼接组合链。
  const capabilityRows = verified
    .filter((v) => Array.isArray(v.impacts) && v.impacts.length > 0)
    .map(
      (v) =>
        `- [${v.auth_required || '?'}｜${v.local_exploitable || 'unknown'}] ${v.vulnerability} → 提供能力：${v
          .impacts!.join('、')}`
    );
  const capabilityBlock =
    capabilityRows.length === 0
      ? ''
      : `
# 🧩 已验证漏洞的【多危害能力清单】（组合拼图·务必据此发散）
下列是各漏洞远程验证阶段实测确认的**多种危害/能力**（一个漏洞往往不止一种危害）。组合链的本质是**把一个漏洞的某种能力当作另一个漏洞的前置条件**去拼接：例如「漏洞A 的任意文件写入」+「漏洞B 的文件被加载/执行」= RCE，或「漏洞C 的信息泄露拿到凭据/路径」+「漏洞D 的受限写入」= RCE。
${capabilityRows.join('\n')}

**拼接要求（强制）**：
- 逐一考察每个能力能作为哪些漏洞的**前置条件**（写入→被加载/执行、泄露→凭据/路径/密钥、越权→拿到本不该有的写权限、SSRF→打内网服务再触达 sink 等），穷尽 A→B、A→B→C 多跳组合。
- **同一个漏洞的不同危害要分别考虑**，不要因为它"已被单独验证过"就只用其中一种能力。
- 仍需在靶机上**真实实测**每条候选链，禁止仅凭能力清单纸面推断成功；打不通的按 failed/restricted 如实标注。
`;
  const crossLangBlock =
    crossLangCandidates.length === 0
      ? ''
      : `
# 🔗 优先验证：审计阶段已识别的【跨语言候选利用链】（最高优先·多语言融合项目专属）
下列候选链由跨语言融合审计给出——污点跨越多种语言运行时才达成，是本项目最易被漏掉却危害最高的一类。请**优先为每一条各派一个子智能体**去靶机实测（仍走 组合利用验证），验证其能否真正串通到 RCE / 完全接管：
${crossLangCandidates.map((s, i) => `${i + 1}. ${s}`).join('\n')}
（以上为静态分析的候选线索，需在靶机上实测确认；打不通的按 failed/restricted 如实标注。）
`;
  const base = resultsDir || `${dir}/_remote_verify`;
  const chainsDir = `${base}/chains`;
  const manifestFile = `${chainsDir}/_manifest.json`;
  return `${corePrompt}

# 你的角色：远程组合链验证【主控】——只做派发、编排、汇总（仅远程 Web 靶机验证）
本阶段是**组合利用链**验证。你**绝不**自己一条一条串行验证整条链；你负责从候选池构造候选链，并为**每一条链各派一个**验证子智能体。

# ⛔ 硬性目标限定：只要 RCE / 完全接管 终点的组合链（其余一律不产出）
本阶段**只构造、只验证、只上报以 RCE（命令执行/代码执行/getshell/webshell/写入并执行）或完全接管服务器为最终危害的组合链**。
- **严禁**把"信息泄露链 / 敏感配置泄露 / 源码泄露 / 越权(IDOR) / SSRF 探测 / 权限提升(未到 RCE)"等**非 RCE 终点**的链作为组合链上报——哪怕它验证成功，也**不要写入 chains**。
- 一条链只有当它**真正串到 RCE / 完全接管**才算数：impact 必须明确写清 RCE/getshell/完全接管类危害。
- **没有能打通到 RCE 的组合链就返回空数组 chains: []**，绝不用信息泄露等"凑数链"填充。后端也会强制过滤掉非 RCE 终点的链。

# 组合利用链（只做 none/user → RCE，禁止 admin → RCE；禁止调用 Skill）
# ⚠ 组合链子智能体硬性规则（务必逐字转达每个子智能体）
1. **每条组合利用链 = 恰好一个子智能体**；禁止一条链派多个子智能体，也禁止一个子智能体验证多条链。
2. **必须在靶机上实测该链**；禁止只读源码就判成功；禁止调用 Skill。
3. **本阶段只覆盖两类起点的 RCE 链（都必须穷尽构造并实测）**：
   - **无权限(auth_required=none) → RCE / 完全接管**（最高优先）；
   - **低权限(auth_required=user) → RCE / 完全接管**——**先实测目标是否开放注册/可自助获取普通账号**（访问 /register、/signup 等注册面并尝试走完注册）；若可得，则"普通注册用户"即攻击者零成本可得起点，此类链危害**等价于无权限链**。
4. **⛔ 严禁管理员起点链**：禁止构造、实测、上报「管理员/高权限登录后 → 配置注入/插件上传/模板/反序列化 → RCE」等 \`auth_required=admin\` 组合链。靶机即便提供了管理员凭据，也**不得**用其起跳组合链；管理员后台功能滥用不算本阶段目标。
5. **穷尽组合**：从总漏洞全集发散所有可串联到 RCE 的路径（多突破口 × 多中间跳 × 多间接触发），凡起点为 none/user 且终点为 RCE 的，一律入候选池并派发实测；禁止只试少数几条就收工。
6. 完成后把**该链 alone** 写入 \`${chainsDir}/<唯一名>.json\`（严格合法 JSON：**单个 chain 对象**或只含 1 个元素的数组）。
   - \`auth_required\` **只允许** none 或 user：无需账号=none；需普通账号（含开放注册自助获取）=user（并在 detail 注明是否开放注册）。**出现 admin 起点的链直接丢弃、不落盘。**
7. **链起点权限【不信任代码层标注、以远程实测为准】**：单漏洞清单里的 auth_required 只是代码层线索、可能把"其实未授权可达"的起跳点误标成 user/admin。构造链时**先假设起点无权限并尝试匿名触达首个环节**：若某个被标为 user/admin 的漏洞其实存在未授权旁路（同义/别名入口、路由错位·批处理/合并接口、schema 绕过、公开包装器、注册/回调/webhook/REST 匿名端点），则该链起点按 **none** 计。判起点为 user 前，须确认匿名确实打不通首环节。

# 待验证目标目录
${dir}

# 靶机环境（已就绪，直接复用，请勿重搭）
靶机仍在运行，直接复用做组合链验证。
${spec ? `\n# 万一需重搭，必须遵守以下规格\n${envSpecBlock(dir, spec)}\n` : ''}
${credBlock(dir, envInfo)}

# ⚠ 并发验证须知（所有链子智能体共用同一靶机）
- **严禁** restart/stop/down/rm 当前复用靶机；利用尽量局部、可自愈；历史版本另起靶机须用随机高位端口与独立 compose 项目名。

# 组合链候选池 = 【总漏洞全集】（不要只从"已验证单漏洞"里找链！）
候选池里可能有**同一代码点的多个利用面**（触发条件/参数/漏洞类型不同的条目）——它们各自都是可入链的独立能力，串链时应逐个考虑，不要因"看着相似"而只取其一。
${pool}

# 参考：已完成单漏洞验证的命中状态（仅作参考，不要限制候选池）
${list}
${capabilityBlock}
${crossLangBlock}
# 任务：构造候选链并逐条亲自实测（穷尽 none/user → RCE）
从**上面的总漏洞全集**里挑选可串联的漏洞，**穷尽**构造多条组合利用链。**只收两类起点，终点必须是 RCE**：
- **无权限起点链**：none → RCE / 完全接管（最高优先）。
- **低权限起点链**：user → RCE / 完全接管。**务必先探测目标是否开放注册/可自助获取普通账号**；只要可得，就把"普通登录用户可触达的上传/导入/配置/模板/反序列化等"漏洞作为链的起跳点，构造并实测 低权限→RCE 链。
- **⛔ 禁止高权限/管理员起点链**：admin → RCE **一律不构造、不派发、不落盘**。不要用靶机管理员账号登录后测后台→shell；那不是本阶段目标。

# 覆盖门禁（绝不可跳过）
1. **先枚举、再验证**：在派发任何验证子智能体前，先穷尽列出本轮全部候选链，立即写入 \`${manifestFile}\`。该文件必须是严格合法 JSON 数组，元素格式为 \`{ "chain_id": "chain-01", "name": "...", "impact": "...", "auth_required": "none|user", "steps": [...] }\`，编号连续且唯一。
2. **清单是本轮分母**：清单中的每一项都必须亲自实测并获得一个结果文件；禁止验了部分链后提前结束、禁止只汇总成功链。每条链验证完成后必须落盘。
3. **结果必须三态闭合**：每个 \`${chainsDir}/<唯一名>.json\` 顶层必须带对应的 \`chain_id\`、\`name\`、\`auth_required\` 和 \`status\`，其中 status **只能**是：
   - \`success\`：已在靶机真实打通至 RCE/完全接管，detail 必须给出命令/HTTP/回显证据；
   - \`failed\`：已实测证伪或确认链路不可行，detail 必须写明阻断步骤与证据；
   - \`restricted\`：已验证部分链路但受靶机、版本、权限或必要前置条件限制，detail 必须写明已达成部分和限制。
   **禁止**省略 status、禁止 \`unknown\`、禁止把没有结果的链从清单或输出中删除。
4. 全部链完成后，逐项核对 \`${manifestFile}\`：每个 chain_id 都有对应可解析结果且三态之一；发现缺失时先补验该 chain_id，完成对账后才能结束。

对**每一条**候选链（仅 none / user 起点，且终点是 RCE）：
1. 亲自实测该链，指令中覆盖：该链的 name/impact/steps/目标、并发须知、落盘路径 \`${chainsDir}/<唯一名>.json\`、以及「禁止 admin 起点」。
2. 逐条推进直到穷尽可想到的 none/user→RCE 组合。
3. 全部链落盘后，可选合并写入 \`${base}/chains.json\`（chain 对象数组）作为兜底。

${includeHistory ? historyGuide(dir) : NO_HISTORY_NOTE}

# 输出要求
StructuredOutput 兜底：{ exploits: [], chains: [...], summary }，chains 必须逐项覆盖 \`${manifestFile}\` 中的全部 chain_id；同时以磁盘 \`${chainsDir}/\` 为准。
每条 chain 含 chain_id、name、impact、**auth_required（仅 none 或 user）**、status（仅 success/failed/restricted）、steps、detail、${
    includeHistory ? 'historical_verification（必填）、exploitable_versions' : 'historical_verification（留空 []）'
  }。
- **chains 只放 RCE / 完全接管 终点、且起点为 none/user 的组合链**：信息泄露/越权/SSRF/权限提升(未到 RCE)、以及 **admin → RCE** 等**一律不要写入**（后端会强制丢弃）。没有能到 RCE 的链就 \`chains: []\`。
- 单个漏洞即可达成的利用**不要**放进 chains。所有文本用简体中文。`;
}

export type ChainRetryTarget = {
  chain_id: string;
  name: string;
  impact?: string;
  auth_required?: string;
  steps?: unknown;
  detail?: string;
};

/** 组合链覆盖门禁发现缺失/unknown 结果后的定向补验 prompt。 */
export function buildChainRetryPrompt(
  corePrompt: string,
  dir: string,
  target: ChainRetryTarget,
  envInfo: string,
  spec: EnvSpec | undefined,
  artifactPath: string
): string {
  return `${corePrompt}

# 你的角色：组合链覆盖门禁补验执行者
本轮组合链验证的候选清单中有一条链未获得有效终态。你只能验证下面指定的这一条链，不要重新枚举候选池、不要验证其它链。

# 指定链
${JSON.stringify(target, null, 2)}

# 目标目录
${dir}

# 靶机环境（已就绪，直接复用，请勿重搭）
${spec ? `\n# 万一需重搭，必须遵守以下规格\n${envSpecBlock(dir, spec)}\n` : ''}
${credBlock(dir, envInfo)}

# 强制要求
1. 先再对这一条链做真实靶机实测；禁止使用管理员起点。
2. 必须在验证后写入 \`${artifactPath}\`，严格合法 JSON，且只含这一个链对象。
3. 顶层必须原样保留 \`chain_id: "${target.chain_id}"\`，并包含 \`name\`、\`auth_required\`、\`status\`、\`steps\`、\`detail\`。
4. \`status\` 只能为 \`success\`、\`failed\` 或 \`restricted\`：真实打通 RCE 才能 success；已证伪填 failed；已验证部分但受环境/前置条件限制填 restricted。**禁止 unknown，禁止省略结论。**
5. detail 要记录 HTTP/命令/回显、实际阻断点或受限原因，使后端可归纳结论。

StructuredOutput 兜底：{ exploits: [], chains: [该链结果], summary: "..." }。`;
}

/**
 * 远程验证「主控」提示词（A3 架构）：由**一个** Pi Agent 会话统一编排整轮远程验证，
 * 内部通过 组合利用验证 技能【派生多个验证子智能体并发】实测（共享同一靶机与同一份 codegraph 索引，
 * 显著降低内存/进程数），每个子智能体把自己那一组的结果**落盘到磁盘文件**，主控最后汇总。
 * 后端只启动这一个主控进程，并通过轮询磁盘结果目录实现实时进度。
 *
 * @param resultsDir 结果落盘目录（绝对路径，形如 <codeDir>/_remote_verify）：
 *   - 单漏洞结果写入 `${resultsDir}/exploits/<唯一名>.json`（每个文件是一个 exploit 对象数组）
 *   - 组合链结果写入 `${resultsDir}/chains.json`（一个 chain 对象数组）
 * @param doneTitles 续跑场景：上次已验证完成、本轮应跳过的漏洞标题。
 */
export function buildRemoteVerifyMasterPrompt(
  corePrompt: string,
  dir: string,
  vulns: VulnBrief[],
  poolBrief: string[],
  envInfo: string,
  spec: EnvSpec | undefined,
  includeHistory: boolean,
  resultsDir: string,
  concurrency: number,
  doneTitles: string[] = []
): string {
  const list = vulns
    .map(
      (v, i) =>
        `${i + 1}. [ID=${v.id || `legacy-${i + 1}`}] [${v.severity}] ${v.title} —— ${v.file_path}${v.line ? ':' + v.line : ''}\n   ${(
          v.description || ''
        ).slice(0, 200)}`
    )
    .join('\n');
  const pool = poolBrief.length === 0 ? '（无）' : poolBrief.map((s, i) => `${i + 1}. ${s}`).join('\n');
  const doneBlock =
    doneTitles.length > 0
      ? `\n# 已在上次验证完成、本轮跳过的漏洞（共 ${doneTitles.length} 个，不要重复验证）\n${doneTitles
          .map((t, i) => `${i + 1}. ${t}`)
          .join('\n')}\n`
      : '';
  const exploitsDir = `${resultsDir}/exploits`;
  const chainsFile = `${resultsDir}/chains.json`;
  const batches = splitRemoteVerifyBatches(vulns);
  const batchPlan = formatRemoteVerifyBatchPlan(batches);
  return `${corePrompt}

# 你的角色：远程验证【主控】——只做阶段一（单漏洞）的派发、编排、汇总，不亲自逐条串行验证
本次**远程 Web 靶机**验证由你（主控）统一编排**阶段一**：
- **阶段一 单漏洞验证**：按下方【强制分组计划】为**每一组各派一个**验证子智能体（一组 = 一个子智能体 = 固定条数）。**禁止**一漏洞一子智能体；**禁止**把多组合并到一个子智能体。
- **组合利用链验证不在本会话进行**：阶段二（组合利用验证 · 一链一子智能体）由**后端**在全部 ${vulns.length} 个单漏洞均有 success/failed/restricted 结论后**自动启动**。你**禁止**在本会话调用 组合利用验证、禁止写入 \`${chainsFile}\`、禁止派发组合链子智能体。
你**绝不**自己一条一条串行验证。所有子智能体**共享同一个已就绪靶机**。

${REMOTE_VERIFY_SUBAGENT_RULES}

# 待验证目标目录
${dir}

# 靶机环境（已就绪，直接复用，请勿重搭）
靶机已在运行中。先用 \`docker ps\` 确认本项目容器在跑、用凭据里的地址确认可访问，**直接复用它做利用验证，不要重新搭建**（重搭会打断所有子智能体共用的同一靶机）。仅当确认靶机已不可用时，才按下面规格重搭。
${spec ? `\n# 万一需重搭，必须遵守以下规格（与预搭建一致）\n${envSpecBlock(dir, spec)}\n` : ''}
${credBlock(dir, envInfo)}

# ⚠ 并发验证须知（所有子智能体共用同一靶机，务必在派发指令中逐字转达）
- **严禁破坏性的全局操作**：不要重启/停止/删除靶机容器（\`docker restart/stop/down/rm\`）、不要清空或重建数据库、不要做全局配置重置或数据初始化。
- 利用尽量做成**局部、可自愈**：用带随机后缀的测试数据（用户名/文件名），用完尽量清理；不要依赖"全库只有我一条数据"的假设。
- 若某利用**必须**改变全局状态才能验证，需在结果 local_result 中注明并尽量恢复原状。
- 历史版本若需另起靶机，**务必用唯一的随机高位端口（20000~60000）与独立 compose 项目名**，绝不动当前复用的靶机、也不要与其它子智能体抢占同一端口，用完即 \`down\`。

# 待验证漏洞全集（共 ${vulns.length} 个 严重/高危/中危；每一个都必须被某个子智能体实测，禁止遗漏/跳过/合并）
清单中可能存在**指向同一代码点、但触发条件/参数/利用路径/漏洞类型不同**的多个条目——它们是**同一个点的不同利用面**（一个 sink 可引发多种漏洞情况）。**必须对每一条各自实测其特定利用面与危害**，**严禁**因为"标题相似/同一处代码"就判为重复而跳过、合并、或把某条的结论直接套用到另一条。
${list}
${doneBlock}

# 📋 强制分组计划（共 ${batches.length} 组 · 每组 = 一个 单漏洞远程验证 子智能体）
/backend 已按严重度拆好组；你派发子智能体时必须**严格按组**执行，不得自行改组或合并：
${batchPlan}

# 🎯 硬性要求：结果必须【落盘到磁盘】，供后端读取汇总
后端**不读你的对话输出**，只读磁盘文件。因此每完成一组后，**必须把结果写入磁盘**：

1. **单漏洞验证结果目录**：\`${exploitsDir}/\`
   - 每完成一个漏洞就立即单独原子落盘，禁止等整组结束才一起写：先写 \`${exploitsDir}/<vulnerability_id>.json.tmp\`，JSON 序列化并读回校验成功后再 rename 为 \`${exploitsDir}/<vulnerability_id>.json\`。后端忽略 \`.tmp\`，因此不会读到半文件。
   - 每个最终 \`.json\` 文件是一个**严格合法的单元素 JSON 数组**，元素字段：
     \`vulnerability_id\`（清单中的稳定 ID，必须原样回填）、\`vulnerability\`（漏洞标题，须与上面清单一致）、\`local_exploitable\`（源码/本地证据，只能 success/failed/restricted/unknown）、\`remote_status\`（**远程权威结论，只能 success/failed/restricted；仅权限矩阵至少一档真实动态触发成功才可填 success；源码确认但无入口、未在 HTTP 靶机触发、环境不满足均填 restricted**）、\`local_result\`（过程与证据，中文）、\`auth_required\`（none/user/admin，填**成功利用所需的最低权限**）、\`privilege_results\`（**权限降级矩阵**，见下）、\`impacts\`（**多危害能力清单**，见下）、\`detail\`（技术细节）、\`exploitable_versions\`（受限时给可利用版本）、\`historical_verification\`（${includeHistory ? '必填，逐版本 version/github_url/status/method/fix_commit/reason' : '留空数组 []'}）。
   - **\`privilege_results\`（务必逐档实测回填）**：对象 \`{ none:{status,evidence?}, user:{status,evidence?}, admin:{status,evidence?} }\`，分别记录在【无权限/匿名】【普通用户(含开放注册自助账号)】【管理员】三种权限下的实测结果；status 取 success/failed/restricted/skipped/unknown。**必须先用无权限打，再依次升级**，如实记录每一档能否成功。\`auth_required\` 必须等于本矩阵中【success 的最低档】（none<user<admin）。
   - **\`impacts\`（多危害能力清单）**：数组，逐项列出该漏洞成功后能造成的所有危害/能力（如「任意文件写入」「任意文件读取」「信息泄露」「命令执行」「越权访问」「凭据泄露」「SSRF」等）。一个漏洞往往不止一种危害，务必列全，供后端组合链阶段按能力拼接。
   - ⚠ 严格 JSON：字符串内双引号转义为 \\"，换行用 \\n，无尾随逗号、不要 markdown 包裹；建议编程序列化后读回校验。
2. **组合链结果文件**：\`${chainsFile}\` —— **本会话不要写入**（留空，由后端阶段二处理）。

${EXPLOIT_GUIDE}

${authRemoteIndependentRule(dir)}
（务必把本节全文逐字转达给每个 单漏洞远程验证 子智能体：清单里的 auth_required 只是代码层线索，一律先匿名实打，实测结论覆盖代码层标注。）

# 执行流程（务必按此编排）
1. 确认靶机可用（\`docker ps\` + 访问首页 + 用凭据登录）。
2. **阶段一（单漏洞远程验证）**：**严格按上方「强制分组计划」**逐组亲自实测（严重/高危每组 **${VERIFY_BATCH_HIGH_EXPORT}** 条、中危每组 **${VERIFY_BATCH_MED_EXPORT}** 条；末组不足时验完该组全部即可）。建议同时推进不超过 ${concurrency} 组。每组必须覆盖：上方「远程单漏洞验证 · 硬性规则」全文、本组漏洞清单、上面的"登录后实测"要求、"每完成一个漏洞立即按 vulnerability_id 原子落盘"的要求。
3. **阶段一完成门槛（StructuredOutput 前必自检）**：
   - 合并 \`${exploitsDir}/\` 下全部 JSON 后，必须**覆盖清单中的全部 ${vulns.length} 个漏洞标题**（标题与清单一致，禁止遗漏/合并）。
   - 每个漏洞必须原样回填 \`vulnerability_id\`；\`remote_status\` 只能是 **success / failed / restricted**，**禁止** unknown；若有遗漏或 unknown，继续补验，**不得**结束本会话。
   - 可用脚本/读盘核对：\`node -e "..."\` 或直接统计 JSON 条目数与标题集合。
4. 全部单漏洞落盘且自检通过后，输出 {exploits, chains: [], summary} 作为兜底（chains 必须为空数组 []）。

${includeHistory ? historyGuide(dir) : NO_HISTORY_NOTE}

# 结束语
全部单漏洞落盘并输出 StructuredOutput 后，用简体中文简要汇报：共验证多少漏洞、success/restricted/failed 各多少、共处理 ${batches.length} 组、结果已写入 ${exploitsDir}（组合链由后端后续按「一链一会话」自动启动）。`;
}

/* ------------------------- 项目形态语义判定（是否含 Web 端） ------------------------- */

/** 轻量“是否含 Web 端”判定的 JSON Schema（供 --json-schema 约束）。 */
export const WEB_CLASSIFY_SCHEMA = {
  type: 'object',
  properties: {
    has_web: {
      type: 'boolean',
      description: '该仓库是否为“可部署的 Web 应用 / 含 Web 端”（用于决定是否搭建 Web 靶机做远程验证）',
    },
    project_kind: {
      type: 'string',
      description:
        '项目形态：web / cli / library / mobile_app / desktop / miniprogram / middleware / plugin / wordlist / unknown 之一',
    },
    has_registration: {
      type: 'boolean',
      description:
        '该 Web 应用是否提供“用户自助注册”功能（匿名访客可自行注册账号的入口/接口）。非 Web 端项目填 false。',
    },
    register_default_on: {
      type: 'boolean',
      description:
        '在默认安装/初始配置下，用户自助注册是否对匿名访客开放（无需管理员手动开启即可注册）。无注册功能或无法判断时填 false。',
    },
    reason: { type: 'string', description: '一句话中文理由（含 Web 端与注册功能的判定依据）' },
  },
  required: ['has_web', 'has_registration', 'register_default_on'],
} as const;

/**
 * 让 Pi Agent 结合 CodeGraph 与文件阅读，从整体结构语义判定项目是否含可部署的 Web 端。
 * 关键：区分“真实可部署的 Web 应用”与“仅含 Web 样本素材的字典/payload/webshell 集合”（如 SecLists）。
 */
export function buildWebClassifyPrompt(codeDir: string): string {
  return `你是“项目形态判定”专家。请判断位于下面工作区的这个代码仓库是否是一个【可部署的 Web 应用 / 含 Web 端】的项目，用于决定后续是否需要为它搭建 Web 靶机做远程利用验证。

# 待判定仓库目录
${codeDir}

# 判定为「含 Web 端」= has_web: true
- 存在真实、可运行的 Web 服务或站点：如 PHP 站点、Laravel/Symfony/ThinkPHP/Django/Flask/Spring Boot/Express/Koa/Next/Nuxt 等 Web 框架应用；含前端页面或后台管理；或对外提供 HTTP(S) 接口的服务端。

# 判定为「无 Web 端」= has_web: false
- 字典 / 爆破字典 / payload / webshell / POC / 漏洞样本集合（典型如 **SecLists**）：这类仓库里**虽然**可能含 index.php、templates/、web.xml、各种脚本样本，但它们只是**被审计的“素材样本”**，并非可部署的 Web 应用本体。
- 纯 CLI 工具、纯类库 / SDK / 框架组件、移动 App（Android/iOS）、桌面应用、小程序、中间件 / 内核模块等本身不提供 Web 服务的项目。

# 判定方法（重要）
- 使用 Grep/Read 工具与必要的文件阅读，聚焦仓库**根部与整体结构**（顶层目录布局、有无统一入口/框架骨架/依赖清单、README 说明的项目定位），而**不要**因为个别**深层嵌套的样本文件**（如 \`Payloads/.../index.php\`、\`Web-Shells/.../web.xml\`）就误判为 Web 应用。
- 判断“这是一个 Web 应用”还是“这是一堆包含 Web 素材的资料/字典”。

# 若判定为「含 Web 端」，再判定注册功能（has_registration / register_default_on）
- **has_registration**：该应用是否存在**用户自助注册**功能——即匿名访客可自行创建账号的入口。判定依据可包括：注册路由/控制器（如 \`register\`、\`signup\`、\`RegisterController\`、\`/api/register\`）、注册相关视图/表单、创建用户的 service/model 调用等。仅“后台由管理员添加用户”而无自助注册的，填 false。
- **register_default_on**：在**默认安装/初始配置**下，注册是否对匿名访客开放。注意区分“代码里有注册功能”和“默认是否启用”：许多系统有注册功能但默认关闭（需管理员在后台开启，或由配置项 / 环境变量 / 数据库设置 like \`allow_registration\`、\`user_registration\`、\`enable_signup\` 控制）。
  - 若代码/默认配置显示注册**默认开启**（或没有任何开关、路由直接可访问）→ true；
  - 若默认关闭、需管理员手动开启、或需邀请码/白名单 → false；
  - 无法确定时保守填 false。
- 非 Web 端项目（has_web=false）：has_registration 与 register_default_on 均填 false。

# 输出（严格）
只输出一个 JSON 对象，不要 markdown、不要多余文字：
{ "has_web": true 或 false, "project_kind": "web|cli|library|mobile_app|desktop|miniprogram|middleware|plugin|wordlist|unknown", "has_registration": true 或 false, "register_default_on": true 或 false, "reason": "一句话中文理由" }`;
}

/* ------------------------- 主导/次要语言语义判定 ------------------------- */

const LANG_MIX_ENUM = [
  'java',
  'go',
  'python',
  'php',
  'jsts',
  'rust',
  'ruby',
  'csharp',
  'c',
  'cpp',
  'solidity',
] as const;

/** 轻量语言占比判定 JSON Schema（供 --json-schema）。token 与子智能体调度键一致。 */
export const LANG_MIX_SCHEMA = {
  type: 'object',
  properties: {
    primary: {
      type: 'string',
      enum: [...LANG_MIX_ENUM],
      description:
        '主导语言。必须是第一方应用源码体量最大的可调度语言：java / go / python / php / jsts / rust / ruby / csharp / c / cpp / solidity。jsts = JavaScript+TypeScript+Vue 合并。',
    },
    secondaries: {
      type: 'array',
      items: { type: 'string', enum: [...LANG_MIX_ENUM] },
      description:
        '次要语言列表（不含 primary）。仅列入第一方源码占比达到阈值、且确有专项审计价值的语言。',
    },
    ratios: {
      type: 'object',
      additionalProperties: { type: 'number' },
      description:
        '各可调度语言占比，0–1 小数或 0–100 百分数均可。不要把 HTML/CSS/Shell/JSON、node_modules、dist、min.js、static 打包资源算进去。',
    },
    reason: {
      type: 'string',
      description: '一句话中文理由：为何该语言是主导、哪些目录被当成第一方源码、哪些被排除。',
    },
  },
  required: ['primary', 'secondaries', 'reason'],
} as const;

export function buildLangMixPrompt(codeDir: string, secondaryThresholdPct: number): string {
  return `你是“项目语言构成判定”专家。请判断下面工作区里【第一方应用源码】的主导语言与次要语言，供后续按语言派发安全审计子智能体。

# 待判定仓库目录
${codeDir}

# 可调度语言 token（primary / secondaries / ratios 的键只能用这些）
- java, go, python, php, jsts, rust, ruby, csharp, c, cpp, solidity
- jsts = JavaScript + TypeScript + JSX/TSX + Vue 合并为一种

# 必须按「第一方应用源码」判断，禁止按裸文件体积
- 算进去：业务后端、真实前端工程源码（src/、未压缩的 ts/tsx/vue）、与产品一起维护的服务。
- 不要算：node_modules / vendor / dist / build / target / min.js / *.bundle.js / hashed chunk、resources/static 或 public 下的第三方/打包 JS、字典、样本、文档、HTML/CSS/Shell/JSON。
- 典型误判：Java Spring 项目 resources/static 里塞了几 MB 打包 JS → 主导仍应是 java，打包 JS 不是 jsts 第一方源码。
- 前后端单体：后端 Java/Go/PHP 与前端 Vue/React 源码都算第一方；谁是主导看第一方源码体量与产品主入口，不要被静态资源带偏。

# 次要语言
- 仅当某可调度语言的第一方源码占比 ≥ ${secondaryThresholdPct}% 且不是 primary 时，才放入 secondaries。
- 达不到阈值的语言可以写进 ratios，但不要放进 secondaries。

# 方法
使用 Grep/Read 与必要的目录/文件阅读，看顶层布局、构建文件（pom.xml / package.json / go.mod 等）和第一方源码目录，而不是扫一遍所有 .js。

# 输出（严格）
只输出一个 JSON 对象，不要 markdown：
{ "primary": "java|go|python|php|jsts|rust|ruby|csharp|c|cpp|solidity", "secondaries": ["jsts"], "ratios": { "java": 0.7, "jsts": 0.3 }, "reason": "一句话中文理由" }`;
}

/* ------------------------- 注册功能语义判定（Pi Agent） ------------------------- */

/** “是否有用户自助注册 / 默认是否开放”判定的 JSON Schema。 */
export const REGISTRATION_CLASSIFY_SCHEMA = {
  type: 'object',
  properties: {
    has_registration: {
      type: 'boolean',
      description: '该 Web 应用是否提供“用户自助注册”功能（匿名访客可自行注册账号的入口/接口）。',
    },
    register_default_on: {
      type: 'boolean',
      description:
        '在默认安装/初始配置下，用户自助注册是否对匿名访客开放（无需管理员手动开启即可注册）。无注册功能或无法判断时填 false。',
    },
    reason: { type: 'string', description: '一句话中文理由（指出注册入口/路由与默认开关依据）' },
  },
  required: ['has_registration'],
} as const;

/**
 * 让 Pi Agent 结合 CodeGraph 与文件阅读，专门判定该 Web 应用是否有用户自助注册、默认是否开放。
 * 用于「已确认含 Web 端、但注册功能尚未识别」的项目做专项回填（与 Web 判定同样走 Pi Agent，不用机械规则）。
 */
export function buildRegistrationClassifyPrompt(codeDir: string): string {
  return `你是“Web 应用注册功能判定”专家。下面工作区里的项目**已确认是一个可部署的 Web 应用**。请你判断它是否提供【用户自助注册】功能，以及在默认安装配置下注册是否对匿名访客开放。

# 待判定仓库目录
${codeDir}

# has_registration —— 是否存在用户自助注册功能
- 用 Grep/Read 工具与文件阅读，定位**注册相关**的路由/控制器/视图/服务：
  - 路由/接口：如 \`/register\`、\`/signup\`、\`/user/register\`、\`/api/register\`、\`/join\`、\`/account/create\` 等；
  - 控制器/方法：如 \`RegisterController\`、\`SignupController\`、\`createAccount\`、\`doRegister\`、\`store\`（users）等；
  - 视图/模板：注册表单页面（register/signup 视图）；
  - 数据层：向用户表插入新用户的 create/insert 调用。
- **有**匿名访客可自行创建账号的入口 → has_registration = true；
- 仅**后台由管理员添加用户**、或完全没有注册入口 → false。

# register_default_on —— 默认安装下注册是否对匿名访客开放
- 区分“代码里有注册功能”和“默认是否启用”：许多系统有注册但默认关闭，由配置项/环境变量/数据库设置控制（如 \`allow_registration\`、\`user_registration\`、\`enable_signup\`、\`registration_enabled\`、\`CUSTOMERS_APPROVAL\` 等）。
- 请查这些开关的**默认值**（默认配置文件、安装脚本 seed、迁移默认值、常量默认）：
  - 默认开启，或根本没有开关、注册路由默认可直接访问 → true；
  - 默认关闭、需管理员手动开启、或需邀请码/白名单/审核 → false；
  - 无法确定时保守填 false。

# 输出（严格）
只输出一个 JSON 对象，不要 markdown、不要多余文字：
{ "has_registration": true 或 false, "register_default_on": true 或 false, "reason": "一句话中文理由" }`;
}
