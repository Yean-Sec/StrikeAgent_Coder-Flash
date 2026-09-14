export type ProjectStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ProjectKindInfo {
  kind: string;
  kind_label: string;
  has_web: boolean | null;
  web_label: string;
}

export interface Project {
  id: string;
  project_name: string;
  archive_name: string;
  source_type: 'zip' | 'github';
  source_ref: string;
  source_version: string | null;
  system_name: string | null;
  workspace_path: string | null;
  env_status: EnvStatus;
  /** 用户指定的单一审计语言（11 选 1）。 */
  audit_language?: string | null;
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
  git_ref: string | null;
  audit_duration_ms: number;
  verify_duration_ms: number;
  opt_auto_verify: number | null;
  opt_verify_history: number | null;
  opt_ai_dedup: number | null;
  opt_ai_regrade: number | null;
  /** 远程验证形态：full 完整靶机 / none 仅代码审计。历史值 mini 视为完整靶机。 */
  opt_verify_runtime?: string | null;
  /**
   * 利用报告中是否确有「已开启历史验证」且产出非空 historical_verification。
   * 列表由后端计算；单独开了开关或单独有伪历史字段都不算。
   */
  has_history_verify?: number | null;
  has_registration: number | null;
  reg_default_open: number | null;
  /** 导入/CodeGraph 识别：是否含 Web 端（NULL=待识别）。 */
  has_web: number | null;
  frontend_rce: number;
  /** 项目类型与是否含 Web 端（后端运行时识别）。 */
  project_kind?: ProjectKindInfo | null;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
}

export type VerifyStatus =
  | 'none'
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed';

export type EnvStatus = 'none' | 'building' | 'ready' | 'failed';

/** 回收站记录（删除留痕，不支持还原）。 */
export interface DeletedProject {
  id: string;
  project_name: string;
  source_type: string;
  source_ref: string;
  archive_name: string;
  source_link: string;
  has_web: number | null;
  vuln_count: number;
  reason: string;
  detail: string;
  deleted_at: number;
}

/** 批量 Web 端判定的候选（判为非 Web，待确认删除）。 */
export interface WebClassifyCandidate {
  id: string;
  name: string;
  source_link: string;
  reason: string;
}

/** 批量 Web 端判定进度状态。 */
/** 每批导入的 Web 端前置识别进度（勾选"只审计 Web 端"时触发）。 */
export interface ImportScreenStatus {
  phase: 'idle' | 'screening' | 'done';
  total: number;
  done: number;
  running: number;
  concurrency: number;
  /** 判定为含 Web 端、已暂停待手动继续的数量 */
  web: number;
  /** 判定为无 Web 端、已移入回收站的数量 */
  deleted: number;
  /** 判定失败（已暂停，不自动开审）的数量 */
  failed: number;
  cancelled: boolean;
}

export interface WebClassifyStatus {
  phase: 'idle' | 'classifying' | 'awaiting_confirm' | 'deleting' | 'done';
  total: number;
  done: number;
  running: number;
  /** 本批任务启动时锁定的并发上限（与代码审计并发独立） */
  concurrency?: number;
  startedAt: number;
  cancelled: boolean;
  web: number;
  nonWeb: WebClassifyCandidate[];
  failed: string[];
  skipped: string[];
  deleted: number;
  error?: string;
}

export type EventPhase = 'audit' | 'verify';

export interface ExploitVersion {
  version: string;
  github_url?: string;
  note?: string;
}

export type ExploitStatus = 'success' | 'failed' | 'restricted' | 'unknown';

/** 历史版本验证结果：基于 git 提交记录定位修复点后，对历史版本的可利用性判断/实测。 */
export interface HistoricalVersionResult {
  version: string;
  github_url?: string;
  status: ExploitStatus;
  method?: 'git_analysis' | 'live_target';
  fix_commit?: string;
  reason?: string;
}

/** 触发该漏洞/链条真实所需的权限级别：none=完全无需账号登录；user=需普通账号；admin=需管理员/高权限账号。 */
export type AuthRequired = 'none' | 'user' | 'admin';

/** 权限降级矩阵每一档的实测状态。 */
export type PrivilegeStatus = 'success' | 'failed' | 'restricted' | 'skipped' | 'unknown';

/** vuln-verifier 权限降级测试结果矩阵：无权限/普通用户/管理员三档各自成功或失败。 */
export interface PrivilegeResults {
  none?: { status: PrivilegeStatus; evidence?: string };
  user?: { status: PrivilegeStatus; evidence?: string };
  admin?: { status: PrivilegeStatus; evidence?: string };
}

export interface ExploitItem {
  vulnerability_id?: string;
  vulnerability: string;
  local_exploitable?: ExploitStatus;
  /** 远程靶机权威结论；源码确认但当前应用不可触达为 restricted。 */
  remote_status?: ExploitStatus;
  local_result?: string;
  exploitable_versions?: ExploitVersion[];
  historical_verification?: HistoricalVersionResult[];
  detail?: string;
  /** 成功利用所需的最低权限（由 privilege_results 派生）。 */
  auth_required?: AuthRequired;
  /** 权限降级三档矩阵（远程验证逐档实测结果）。 */
  privilege_results?: PrivilegeResults;
  /** 该漏洞成功后可造成的多种危害/能力清单。 */
  impacts?: string[];
}

export interface ChainStep {
  vulnerability?: string;
  description?: string;
  /** 子智能体逐步验证结论（success / failed / restricted 等） */
  result?: string;
  evidence?: { details?: string; url_accessed?: string; http_status?: number };
}

export interface ExploitChain {
  name: string;
  impact?: string;
  status?: ExploitStatus;
  steps?: ChainStep[];
  detail?: string;
  local_result?: string;
  exploitable_versions?: ExploitVersion[];
  historical_verification?: HistoricalVersionResult[];
  auth_required?: AuthRequired;
}

export interface ExploitReport {
  summary: string;
  exploits: ExploitItem[];
  chains?: ExploitChain[];
}

export interface VerificationProgress {
  total: number;
  pending: number;
  queued: number;
  running: number;
  success: number;
  restricted: number;
  failed: number;
  timeout: number;
  concluded: number;
}

export interface VerificationItem {
  vulnerability_id: string;
  vulnerability_title: string;
  state: 'pending' | 'queued' | 'running' | 'success' | 'restricted' | 'failed' | 'timeout';
  code_status: ExploitStatus;
  remote_status: ExploitStatus;
  auth_required: AuthRequired | 'unknown';
  privilege_results?: PrivilegeResults;
  local_result: string;
  detail: string;
  source_file?: string | null;
  attempt_count: number;
  queued_at?: number | null;
  started_at?: number | null;
  finished_at?: number | null;
  updated_at: number;
  error?: string | null;
}

export interface VulnRow extends Vulnerability {
  project_name: string;
  verified?: number;
}

/** /vulnerabilities 服务端分页响应。 */
export interface VulnPage {
  items: VulnRow[];
  total: number;
  page: number;
  pageSize: number;
  counts: {
    all: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    verified: number;
    frontend_rce: number;
  };
}

export interface VulnQuery {
  page?: number;
  pageSize?: number;
  severity?: string;
  verified?: '0' | '1';
  frontend_rce?: '0' | '1';
  category?: string;
  search?: string;
}

export type RedTeamValue = '严重' | '高危' | '中危' | '低危' | '无';

export interface Vulnerability {
  id: string;
  project_id: string;
  title: string;
  severity: Severity;
  severity_original?: Severity | null;
  regrade_value?: RedTeamValue | null;
  regrade_reason?: string | null;
  category: string;
  file_path: string;
  line: number | null;
  description: string;
  recommendation: string;
  code_snippet: string;
  taint_chain?: string;
  /** 远程靶机验证成功标记（持久化列）。 */
  verified?: number;
  /** 前台 RCE：远程 HTTP 验证通过的 RCE；含 none 或 reg_default_open+user。 */
  frontend_rce?: number;
  /** 拿到前台 RCE 的时间（毫秒时间戳）：syncFrontendRce 置位时写入，历史数据用项目 verify_finished_at 回填。 */
  frontend_rce_at?: number | null;
  /** 触发该漏洞所需权限（代码级验证/二次评级判定）：none/user/admin/null 未判定。 */
  auth_required?: AuthRequired | null;
  /** 鉴权判定理由。 */
  auth_reason?: string | null;
  /** 利用面簇标识：同一代码点的多个利用面共享同一 cluster_id；无簇为 null。 */
  cluster_id?: string | null;
  /** 簇内角色：primary=代表面 / variant=其余利用面。 */
  cluster_role?: 'primary' | 'variant' | null;
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
  phase?: EventPhase;
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

export interface DashboardData {
  totalProjects: number;
  running: number;
  byStatus: Record<string, number>;
  severityTotals: Record<Severity, number>;
  totalVulns: number;
  verifiedSeverityTotals: Record<Severity, number>;
  auditCategoryTotals: Record<string, number>;
  verifiedCategoryTotals: Record<string, number>;
  verifiedVulns: number;
  frontendRceVulns: number;
  /** 审计 + 靶机验证均完成（与 /projects?status=all_done 一致） */
  allDoneProjects: number;
  runningProjects: Project[];
  verifyingProjects: Project[];
}

export interface Settings {
  audit_prompt: string;
  verify_prompt: string;
  default_command: string;
  max_concurrency: string;
  github_token: string;
  poll_interval: string;
  /** Pi 可执行文件路径（库键仍为 claude_path，以免旧设置丢失） */
  claude_path: string;
  auto_verify: string;
  verify_runtime?: string;
  mini_verify_timeout_sec?: string;
  ai_regrade: string;
  ai_dedup: string;
  /** AI 去重是否保留「同一代码点的不同利用面」：'1' 开启（默认）/ '0' 旧行为（同点即合并） */
  dedup_keep_variants: string;
  stage_timeout_min: string;
  idle_timeout_min: string;
  single_verify_timeout_min: string;
  single_verify_idle_timeout_min: string;
  settle_timeout_min: string;
  code_verify_concurrency: string;
  remote_verify_concurrency: string;
  remote_verify_burst_concurrency: string;
  protect_web_resources: string;
  verify_global_concurrency: string;
  trust_skill_verified: string;
  verify_command: string;
  merge_verify_regrade: string;
  lean_verify_prompt: string;
  ai_dedup_min_candidates: string;
  /** 旧键：AI 去重提示词建议并发；现已改走 regrade_concurrency */
  ai_dedup_concurrency: string;
  /** 旧键：验证分组建议条数；现已改走 regrade_batch_size */
  code_verify_batch_size: string;
  /** 核验层（去重 / 代码级验证 / 二次评级）每路条数（默认 10） */
  regrade_batch_size: string;
  /** 核验层最多同时开这么多路 Pi（默认 10，封顶 10；一轮最多 batch×conc 个） */
  regrade_concurrency: string;
  /** 批量 Web 端语义判定并发；空=沿用代码审计并发数 */
  classify_concurrency: string;
  cve_email: string;
  /** 多语言融合：次要语言占比阈值（百分比，默认 15）——占比>=该值的非主导语言也派高危子集 */
  audit_secondary_lang_threshold: string;
  /** 多语言融合：跨语言融合审计开关（'1' 开启/默认，'0' 关闭） */
  cross_language_fusion: string;
  /**
   * 启动时是否自动续跑上次残留的 running/queued 任务。
   * '0'（默认）只标为暂停；'1' 恢复旧行为自动 spawn Pi 续跑。
   */
  auto_resume_orphans_on_startup: string;
  /**
   * 全局 Pi 任务总闸。'0' 时禁止一切入队/调度/spawn（含监控触发）；
   * 需重新开审时在设置中改回 '1'。
   */
  claude_jobs_enabled: string;
}
