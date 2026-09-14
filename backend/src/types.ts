export type ProjectStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type SourceType = 'zip' | 'github';

export interface Project {
  id: string;
  project_name: string;
  archive_name: string;
  source_type: SourceType;
  source_ref: string;
  source_version: string | null;
  system_name: string | null;
  workspace_path: string | null;
  /** 靶机环境预搭建状态：none 未开始 / building 搭建中 / ready 就绪 / failed 失败。 */
  env_status: EnvStatus;
  /** 预搭建好的靶机访问地址（如 http://localhost:8080）。 */
  target_url: string | null;
  status: ProjectStatus;
  error_message: string | null;
  monitor_id: string | null;
  count_critical: number;
  count_high: number;
  count_medium: number;
  count_low: number;
  count_info: number;
  exploit_report: string | null;
  verify_status: VerifyStatus;
  verify_started_at: number | null;
  verify_finished_at: number | null;
  verify_error: string | null;
  /** github 项目指定克隆的 tag（多版本批量审计用）；为空则克隆默认分支。 */
  git_ref: string | null;
  /** 代码审计累计真实耗时（毫秒，跨多次运行累加，暂停期间不计）。 */
  audit_duration_ms: number;
  /** 远程验证累计真实耗时（毫秒）。 */
  verify_duration_ms: number;
  /** 项目级审计流程选项（NULL=沿用全局默认；1/0）。 */
  opt_auto_verify: number | null;
  opt_verify_history: number | null;
  opt_ai_dedup: number | null;
  opt_ai_regrade: number | null;
  /** 远程验证形态：full 完整靶机 / none 仅代码审计；历史值 mini 解析为 full；空=旧项目按 auto_verify 推断。 */
  opt_verify_runtime: string | null;
  /** 用户手动选择的审计语言（java/go/python/php/jsts/rust/ruby/csharp/c/cpp/solidity）。 */
  audit_language: string | null;
  /** 是否存在用户自助注册功能（NULL=未知）。 */
  has_registration: number | null;
  /** 导入/CodeGraph 识别：是否含 Web 端（NULL=待识别，1=有，0=无）。 */
  has_web: number | null;
  /** 默认安装配置下注册是否对匿名访客开放（NULL=未知）。 */
  reg_default_open: number | null;
  /** 注册默认开放 + 普通用户权限下存在验证成功的 RCE 类漏洞。 */
  frontend_rce: number;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
}

/** 回收站记录：项目被删除时的快照（不支持还原，仅留痕）。 */
export interface DeletedProject {
  id: string;
  project_name: string;
  source_type: string;
  source_ref: string;
  archive_name: string;
  /** 归一化来源展示：github→URL，压缩包→archive_name。 */
  source_link: string;
  has_web: number | null;
  vuln_count: number;
  /** 删除原因：manual / bulk / auto_non_web。 */
  reason: string;
  /** 附加说明（如 LLM 判定理由）。 */
  detail: string;
  deleted_at: number;
}

export type VerifyStatus =
  | 'none'
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed';

export type EnvStatus = 'none' | 'building' | 'ready' | 'failed';

/** 事件所属阶段：审计 / 验证（含并行的环境预搭建）。 */
export type EventPhase = 'audit' | 'verify';

export type RedTeamValue = '高' | '中' | '低' | '无' | '';

export interface Vulnerability {
  id: string;
  project_id: string;
  title: string;
  severity: Severity;
  /** AI 实战二次评级前的原始严重度（用于对照展示），未评级时为 null。 */
  severity_original: Severity | null;
  /** 红队实战利用价值：高 / 中 / 低 / 无。 */
  regrade_value: RedTeamValue | null;
  /** 二次评级的理由（中文）。 */
  regrade_reason: string | null;
  category: string;
  file_path: string;
  line: number | null;
  description: string;
  recommendation: string;
  code_snippet: string;
  /** 污点链：从用户可控输入(Source)逐跳到危险操作(Sink)的完整数据流路径。 */
  taint_chain: string;
  /** 远程靶机验证成功（持久化列）。 */
  verified?: number;
  /** 触发所需权限：none/user/admin。 */
  auth_required?: string | null;
  auth_reason?: string | null;
  created_at: number;
}

export interface AgentEvent {
  id: string;
  project_id: string;
  ts: number;
  kind: string;
  agent: string;
  tool: string;
  text: string;
  raw: string;
  phase: EventPhase;
}

export interface Monitor {
  id: string;
  repo_url: string;
  project_prefix: string;
  last_release_tag: string | null;
  interval_min: number;
  enabled: number;
  last_checked: number | null;
  last_triggered: number | null;
  created_at: number;
}
