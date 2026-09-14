import db from './db';

// 漏洞审计：仅做全栈静态代码审计
export const AUDIT_PROMPT =
  '你是代码安全审计员。只做静态发现并落盘 JSON，不要去重、不要代码级验证、不要搭靶机。';

// 漏洞验证：先搭靶机环境，再做利用链验证。
// 注意：是否验证历史版本完全由「历史版本验证」开关控制（见 schema.ts 的 historyGuide / NO_HISTORY_NOTE），
// 这里的核心提示词【不要】再硬编码任何"打历史版本/查 github 历史版本"的指示，否则会在用户关闭历史验证时与之冲突。
// 技能中立的核心验证提示词：具体调用哪个技能由下方分步指示决定——
// 单漏洞逐条验证用 vuln-verifier；组合利用链（0 权限到 RCE）用 vuln-chain-exploiter。
export const VERIFY_PROMPT = `针对已发现的漏洞，在已搭建的本地靶机上做真实利用验证与取证。
分步：先确认 Docker 靶机可达并登录；再逐条验证单漏洞；最后尝试无权限/低权限到 RCE 的组合利用。禁止只读源码就判成功。组合链不要从管理员权限起步。`;

// 旧版默认提示词。用于 initSettings 自愈迁移：
// 若用户从未自定义（存库值恰为某个旧默认），则自动升级为新默认。
const LEGACY_AUDIT_PROMPTS = [
  '你是代码审计主控。针对用户指定的单一语言，自己撰写并并发派发 5 路子智能体（命令执行、SQL注入、文件操作、权限、其余Web漏洞），只做静态发现并落盘 JSON，不要去重、不要代码级验证、不要搭靶机。',
  '你是代码审计主控。针对用户指定的单一语言，自己撰写并并发派发该语言至少 5 路专项子智能体（如 PHP 的 unserialize/include、Java 的 ObjectInputStream/Runtime.exec），只做静态发现并落盘 JSON，不要去重、不要代码级验证、不要搭靶机。',
];
const LEGACY_VERIFY_PROMPTS = [
  `依次调用技能 docker-env-login-and-acl-e2e 搭建本地靶机环境，并启动 vuln-chain-exploiter 技能。
根据上面已发现的漏洞，针对搭建好的本地靶机地址进行利用验证。`,
  `依次调用技能 docker-env-login-and-acl-e2e 搭建本地靶机环境，并启动 vuln-chain-exploiter 技能。
根据上面已发现的漏洞，针对搭建好的本地靶机地址进行利用验证，如果无权限无法利用成功，你可以通过 github 查看历史版本看能否成功利用，意思是用已发现的漏洞能否打历史版本，而不是去查找历史漏洞，并且给出这些能成功利用的版本的 github 地址。`,
];

export const DEFAULT_COMMAND =
  'pi --mode json --no-session --no-context-files --provider anthropic {prompt}';

const LEGACY_DEFAULT_COMMANDS = [
  'claude -p {prompt} --add-dir {dir} --output-format stream-json --include-partial-messages --verbose --json-schema {schema} --permission-mode bypassPermissions --dangerously-skip-permissions',
];

// 最大并发审计数上限（同时启动的 Pi Agent 数）。每个审计都是完整仓库 + 多子智能体 + 靶机，
// 并发越高越吃 CPU/内存/网络，请按机器配置量力而行。
export const MAX_CONCURRENCY_CEILING = 10;
/** 批量 Web 端语义判定并发上限（与代码审计槽位独立计数）。 */
export const CLASSIFY_CONCURRENCY_CEILING = 50;

const DEFAULTS: Record<string, string> = {
  audit_prompt: AUDIT_PROMPT,
  verify_prompt: VERIFY_PROMPT,
  default_command: DEFAULT_COMMAND,
  max_concurrency: '5',
  github_token: '',
  poll_interval: '5',
  // Pi 可执行文件路径（库键仍为 claude_path，以免旧设置丢失）
  claude_path: '',
  // 新建审计完成后是否自动进入靶机验证：'1' 代码审计+靶机验证（默认）/ '0' 仅代码审计
  auto_verify: '1',
  // 远程验证形态：full 整栈 Compose（默认）/ none 仅代码审计。历史 mini 已下线。
  verify_runtime: 'full',
  // 最小运行时单洞 docker run 超时（秒）
  mini_verify_timeout_sec: '120',
  // 审计完成后是否用 AI 对每个漏洞做红队实战二次评级：'1' 开启（默认）/ '0' 关闭
  ai_regrade: '1',
  // 子智能体审计完成后、代码级验证前，是否用 AI 对候选漏洞做语义级去重（合并不同子智能体对同一漏洞的重复上报）：'1' 开启（默认）/ '0' 关闭
  ai_dedup: '1',
  // AI 去重是否保留「同一代码点的不同利用面」（variant）：'1' 开启（默认）——只删纯措辞重复，
  // 同点多面各自保留并归簇(cluster_id)逐面验证，避免"一个点只验一个面"漏面；'0' 退回旧行为（同点即合并成一条）。
  dedup_keep_variants: '1',
  // 靶机验证阶段是否对"其他历史版本"做验证：'1' 开启（默认）/ '0' 仅验证当前版本（更快，只发现当前系统）
  verify_history: '1',
  // 单个 Pi Agent 阶段（审计/验证）的硬性最长运行时间（分钟），超出则自动终止并标记失败
  stage_timeout_min: '90',
  // 连续无任何输出的空闲超时（分钟），用于检测卡死的进程并自动终止
  idle_timeout_min: '25',
  // 单漏洞远程验证独立端到端预算：默认硬上限 15 分钟、无输出 5 分钟。
  // 亦用于遗漏补验批次：硬上限 ≈ 批内洞数 × 本值（保底 45 分钟，封顶 120 分钟）。
  single_verify_timeout_min: '15',
  single_verify_idle_timeout_min: '5',
  // 结果收尾宽限（分钟）：已拿到完整结构化结果后，进程仍不退出则等待这么久后主动收尾（视为正常完成）
  settle_timeout_min: '2',
  // 与代码审计并行的"靶机环境预搭建"最大并发数（审计仍在跑时；验证独占阶段与 burst 对齐）
  env_concurrency: '3',
  // 远程/沙箱验证日志里的建议并发（去重/代码级验证/二次评级改走 regrade_*）
  code_verify_concurrency: '5',
  // 核验层（AI 去重 / 代码级验证 / 二次评级）共用：每路这么多条，最多同时这么多路 Pi
  regrade_batch_size: '10',
  regrade_concurrency: '10',
  // 旧键：AI 去重提示词建议并发；现已改走 regrade_concurrency，保留读取兼容
  ai_dedup_concurrency: '20',
  // 远程靶机验证+靶机搭建：跨项目同时运行的 Pi Agent 进程总数上限（默认 3，与审计 5 合计 8）
  remote_verify_concurrency: '5',
  // 当全部项目代码审计已结束、队列里只剩靶机验证时，临时抬高的远程验证并发（默认 5）
  remote_verify_burst_concurrency: '5',
  // 保护 Web 服务：开启时常态最多同时启动 3 个重型主控，内存/事件循环压力高时进一步降到 1~2。
  protect_web_resources: '1',
  // 旧键：保留读取兼容，新安装请用 remote_verify_concurrency
  verify_global_concurrency: '5',
  // 【去重后端重复验证】信任审计技能已产出的「可直接利用清单」(directly_exploitable_vulns.json)：
  // 这些漏洞技能内部已做过代码级验证，开启后后端代码级验证将跳过它们、仅验证其余原始发现，
  // 避免对同一批漏洞验证两遍。默认 '1' 开启（省一半重复验证；其余原始发现仍全量核验，不降召回）；'0' 全量重验。
  trust_skill_verified: '0',
  // 【省 token · ② 验证环节模型分级】代码验证层（AI去重/代码级验证/二次评级，channel==='codeverify'）
  // 专用命令模板。留空=沿用 default_command（现状，不改变行为）；填写后可把这些"有界核验"任务
  // 路由到更便宜/更小的模型（如 haiku 档），单位 token 成本更低。占位符与 default_command 一致
  // （{prompt}/{dir}/{schema}），远程靶机验证(channel==='remoteverify')不受影响。
  verify_command: '',
  // 【省 token · ① 合并验证+评级】'1' 时代码级验证顺带按红队实战价值定级并产出中文标题/类别，
  // 流水线随后跳过独立的"二次评级"Pi Agent pass（少一整轮 fan-out）。默认 '0'=保持现状（验证、评级分两轮）。
  merge_verify_regrade: '0',
  // 【省 token · ③④ 精简验证提示词】'1' 时：主控派发不再把候选原文逐字塞进指令（改为让子智能体按
  // index 自行读 input.json），且落盘成功后不再额外输出一份 StructuredOutput 兜底。默认 '0'=保持现状。
  lean_verify_prompt: '0',
  // 【省 token · ⑤ AI 去重门控】候选数低于该阈值时直接跳过整个 AI 语义去重 Pi Agent pass（机械去重仍生效）。
  // 0=始终跑 AI 去重（现状，不改变行为）。
  ai_dedup_min_candidates: '0',
  // 旧键：验证分组建议条数；现已改走 regrade_batch_size，保留读取兼容
  code_verify_batch_size: '0',
  // 一键上传 CVE 时自动填入 MITRE CVE 表单的联系邮箱（cveform-legacy.mitre.org 的 requester email）
  cve_email: '',
  // 批量「Web 端语义判定」并发（与代码审计 max_concurrency 独立，不占审计槽）。
  classify_concurrency: '20',
  // 【多语言融合】次要语言占比阈值（百分比）：源码体量占比 >= 该值的非主导语言，也会派其"高危方向"
  // 专项子智能体（RCE/文件读写包含/路径穿越/SQL/鉴权/反序列化）并纳入覆盖核对。默认 15。
  audit_secondary_lang_threshold: '15',
  // 【多语言融合】跨语言融合审计开关：'1' 开启（默认）——多语言(>=2 种达阈值)项目在子智能体审计后追加
  // 一轮跨语言边界漏洞审计（子进程/共享存储/服务间调用/FFI），并把候选跨语言利用链喂给靶机组合验证；'0' 关闭。
  cross_language_fusion: '0',
  // 启动时是否自动续跑上次残留的 running/queued 任务。默认关闭：中断任务只标为 paused，
  // 避免「杀了 Pi / 重启后端」后再次批量 spawn 孤儿进程；需要续跑时在设置中开启，或在列表里点「继续」。
  auto_resume_orphans_on_startup: '0',
  // 全局 Pi 任务总闸：'0' 时禁止入队/调度/spawn（含审计、验证、监控触发），并可用于一键停摆。
  // 默认 '1'；用户明确要求停掉全部任务后应置 '0'，直到在设置中重新开启。
  claude_jobs_enabled: '1',
  // 【MCP 完成账本】'1' 开启（默认）：spawn Pi 时注入内置 Code MCP（--mcp-config
  // --strict-mcp-config），让子智能体/主控通过结构化工具显式声明审计与验证结论，形成权威账本。
  // 覆盖通道：main（子智能体审计）、codeverify（去重/代码级验证/二次评级）、remoteverify（远程验证）。
  // 覆盖门禁按「账本 ∪ 磁盘」判定，消除"改名/没写文件→误判未审计"与组合链"结果与日志对不上"。
  // '0' 关闭：完全回退到纯磁盘即真相的现状行为，不注入任何 MCP 配置。
  mcp_ledger_enabled: '0',
  // MCP 桥接进程回调后端的内部入库地址（仅 localhost）。留空时按 PORT 推导 http://127.0.0.1:<PORT>。
  mcp_backend_url: '',
  // 【运行日志保留】project_run_logs（Pi Agent 原始 stdout/stderr）以前从不清理，单表可膨胀到数 GB，
  // 使 SQLite 写入/checkpoint 变慢并拖累所有 /api/*。下面两项定义滚动保留策略（滚动清道夫 + 维护脚本共用）：
  //   run_log_keep_runs_per_project：每个项目只保留最近多少个 run（其余 run 可删，这是控库体积的主力）。
  //   run_log_keep_days：仅当 keep_runs=0 时作为时间窗口退化策略。
  // 正在运行/排队中的项目日志一律不删。默认每项目最近 2 个 run。
  run_log_keep_days: '3',
  run_log_keep_runs_per_project: '2',
  // 滚动清道夫扫描间隔（毫秒）。0 = 关闭滚动清理（仅保留手动维护脚本）。
  // 默认 5 分钟：清道夫已改为异步分批+轮转，不再冻 HTTP，可更勤快地消化历史膨胀。
  run_log_janitor_interval_ms: '300000',
  // 【单 run 行数硬上限】单次 Pi Agent 运行的原始日志行数上限；0 = 不限。历史上出现过单个 run
  // 产出 40 万行（保留策略「每项目留 N 个 run」在这种失控 run 面前压不住）。达到上限后写入端
  // 只追加一条截断标记、丢弃后续行，从源头封住膨胀。维护脚本也据此回溯裁剪已有超限 run。
  run_log_max_rows_per_run: '20000',
};

export function getSetting(key: string): string {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as
    | { value: string }
    | undefined;
  if (row) return row.value;
  return DEFAULTS[key] ?? '';
}

export function getAllSettings(): Record<string, string> {
  const rows = db.prepare('SELECT key, value FROM settings').all() as {
    key: string;
    value: string;
  }[];
  const stored: Record<string, string> = {};
  for (const r of rows) stored[r.key] = r.value;
  return { ...DEFAULTS, ...stored };
}

export function setSetting(key: string, value: string): void {
  db.prepare(
    `INSERT INTO settings (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(key, value);
}

export function setSettings(values: Record<string, string>): void {
  const tx = db.transaction((entries: [string, string][]) => {
    for (const [k, v] of entries) setSetting(k, v);
  });
  tx(Object.entries(values).map(([k, v]) => [k, String(v ?? '')]));
}

export function initSettings(): void {
  for (const [k, v] of Object.entries(DEFAULTS)) {
    const exists = db.prepare('SELECT 1 FROM settings WHERE key = ?').get(k);
    if (!exists) setSetting(k, v);
  }
  // 自愈迁移：旧默认的 verify_prompt 硬编码了历史版本指示，会与「关闭历史验证」冲突。
  // 仅当用户从未自定义（存库值恰为某个旧默认）时，升级为不含历史指示的新默认；用户自定义的不动。
  const curVerifyPrompt = getSetting('verify_prompt').trim();
  if (curVerifyPrompt !== VERIFY_PROMPT && LEGACY_VERIFY_PROMPTS.some((p) => p.trim() === curVerifyPrompt)) {
    setSetting('verify_prompt', VERIFY_PROMPT);
    console.log('[code] 已将旧默认验证提示词升级为新版（移除硬编码的历史版本指示，改由开关控制）');
  }
  const curAuditPrompt = getSetting('audit_prompt').trim();
  if (
    curAuditPrompt !== AUDIT_PROMPT &&
    (curAuditPrompt.includes('multi-language-comprehensive-auditor') ||
      curAuditPrompt.includes('调用技能') ||
      LEGACY_AUDIT_PROMPTS.some((p) => p.trim() === curAuditPrompt))
  ) {
    setSetting('audit_prompt', AUDIT_PROMPT);
    console.log('[code] 已将旧默认审计提示词升级为语言专项子智能体版');
  }
  const curDefaultCmd = getSetting('default_command').trim();
  if (
    curDefaultCmd !== DEFAULT_COMMAND &&
    LEGACY_DEFAULT_COMMANDS.some((c) => c.trim() === curDefaultCmd)
  ) {
    setSetting('default_command', DEFAULT_COMMAND);
    console.log('[code] 已将旧默认 Claude Code 启动命令升级为 Pi 模板');
  }
  const regradeMigrated = db.prepare('SELECT 1 FROM settings WHERE key = ?').get('_migrated_ai_regrade_on');
  if (!regradeMigrated) {
    if (getSetting('ai_regrade') === '0') {
      setSetting('ai_regrade', '1');
      console.log('[code] 已将默认二次评级开关恢复为开启（流水线已接回代码级验证之后）');
    }
    setSetting('_migrated_ai_regrade_on', '1');
  }
  // 自动纠正历史上被设置成过大的并发值（如 10），避免单机资源耗尽
  const cur = parseInt(getSetting('max_concurrency'), 10);
  if (Number.isFinite(cur) && cur > MAX_CONCURRENCY_CEILING) {
    setSetting('max_concurrency', String(MAX_CONCURRENCY_CEILING));
    console.log(
      `[code] 并发数 ${cur} 超过安全上限，已自动调整为 ${MAX_CONCURRENCY_CEILING}`
    );
  }
  // 迁移：旧库仅有 verify_global_concurrency 时写入 remote_verify_concurrency
  const hasRemote = db.prepare('SELECT 1 FROM settings WHERE key = ?').get('remote_verify_concurrency');
  if (!hasRemote) {
    const legacy = parseInt(getSetting('verify_global_concurrency'), 10);
    const v = legacy === 10 || !Number.isFinite(legacy) ? 3 : Math.min(Math.max(1, legacy), 12);
    setSetting('remote_verify_concurrency', String(v));
  }
  // 注意：不要在启动时强制把远程验证并发 2/3 顶到 5。
  // 该「对齐突发并发」的每次启动迁移会覆盖用户主动设的低并发（如 2），
  // 使单机同时跑 ~5 个项目 × 每项目 ~5 个子智能体 + 多套重型 Docker 栈，
  // 直接把 11G 内存顶到 OOM 而杀后端。用户设定的并发值必须跨重启保留。
  // 迁移：靶机搭建并发 2→3（审计并行预搭建时）
  if (getSetting('env_concurrency') === '2') {
    setSetting('env_concurrency', '3');
    console.log('[code] env_concurrency 已从 2 调整为 3');
  }
  // 迁移：批量 Web 判定并发独立化（旧库空值曾沿用 max_concurrency，现默认 20）
  if (!getSetting('classify_concurrency')) {
    setSetting('classify_concurrency', DEFAULTS.classify_concurrency);
  }
  if (getSetting('verify_runtime') === 'mini') {
    setSetting('verify_runtime', 'full');
    console.log('[code] 已将全局 verify_runtime 从最小运行时升级为完整靶机');
  }
}
