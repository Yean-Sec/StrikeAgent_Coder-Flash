import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_FILE = 'code.db';
const LEGACY_DB_FILE = 'strike-agent.db';

function migrateLegacyDbIfNeeded(dataDir: string, dbFile: string, legacyFile: string): void {
  const nextPath = path.join(dataDir, dbFile);
  if (fs.existsSync(nextPath)) return;
  const legacyPath = path.join(dataDir, legacyFile);
  if (!fs.existsSync(legacyPath)) return;
  const suffixes = ['', '-wal', '-shm'];
  for (const suffix of suffixes) {
    const from = legacyPath + suffix;
    const to = nextPath + suffix;
    if (!fs.existsSync(from)) continue;
    try {
      fs.renameSync(from, to);
    } catch {
      fs.copyFileSync(from, to);
      try {
        fs.unlinkSync(from);
      } catch {
        /* keep copy if unlink fails */
      }
    }
  }
}

migrateLegacyDbIfNeeded(DATA_DIR, DB_FILE, LEGACY_DB_FILE);

const db = new Database(path.join(DATA_DIR, DB_FILE));
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('busy_timeout = 5000');
db.pragma('temp_store = MEMORY');
db.pragma('cache_size = -65536');
db.pragma('mmap_size = 268435456');

db.exec(`
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  project_name TEXT NOT NULL UNIQUE,
  archive_name TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  source_version TEXT,
  system_name TEXT,
  workspace_path TEXT,
  env_status TEXT NOT NULL DEFAULT 'none',
  target_url TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  error_message TEXT,
  monitor_id TEXT,
  count_critical INTEGER NOT NULL DEFAULT 0,
  count_high INTEGER NOT NULL DEFAULT 0,
  count_medium INTEGER NOT NULL DEFAULT 0,
  count_low INTEGER NOT NULL DEFAULT 0,
  count_info INTEGER NOT NULL DEFAULT 0,
  exploit_report TEXT,
  verify_status TEXT NOT NULL DEFAULT 'none',
  verify_started_at INTEGER,
  verify_finished_at INTEGER,
  verify_error TEXT,
  git_ref TEXT,
  audit_duration_ms INTEGER NOT NULL DEFAULT 0,
  verify_duration_ms INTEGER NOT NULL DEFAULT 0,
  opt_auto_verify INTEGER,
  opt_verify_history INTEGER,
  opt_ai_dedup INTEGER,
  opt_ai_regrade INTEGER,
  opt_verify_runtime TEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  severity_original TEXT,
  regrade_value TEXT,
  regrade_reason TEXT,
  category TEXT NOT NULL DEFAULT '',
  file_path TEXT NOT NULL DEFAULT '',
  line INTEGER,
  description TEXT NOT NULL DEFAULT '',
  recommendation TEXT NOT NULL DEFAULT '',
  code_snippet TEXT NOT NULL DEFAULT '',
  taint_chain TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_events (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  agent TEXT NOT NULL DEFAULT '',
  tool TEXT NOT NULL DEFAULT '',
  text TEXT NOT NULL DEFAULT '',
  raw TEXT NOT NULL DEFAULT '',
  phase TEXT NOT NULL DEFAULT 'audit',
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- 进程原始流日志：agent_events 供 UI 展示；这里按 run_id + seq 永久保留
-- prompt/stdout/stderr/meta，代码审计和远程验证共用，便于完整事后排查。
CREATE TABLE IF NOT EXISTS project_run_logs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  phase TEXT NOT NULL DEFAULT 'audit',
  channel TEXT NOT NULL DEFAULT 'main',
  stream TEXT NOT NULL,
  seq INTEGER NOT NULL,
  content TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS monitors (
  id TEXT PRIMARY KEY,
  repo_url TEXT NOT NULL,
  project_prefix TEXT NOT NULL DEFAULT '',
  last_release_tag TEXT,
  interval_min INTEGER NOT NULL DEFAULT 5,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_checked INTEGER,
  last_triggered INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deleted_projects (
  id TEXT PRIMARY KEY,
  project_name TEXT NOT NULL DEFAULT '',
  source_type TEXT NOT NULL DEFAULT '',
  source_ref TEXT NOT NULL DEFAULT '',
  archive_name TEXT NOT NULL DEFAULT '',
  source_link TEXT NOT NULL DEFAULT '',
  has_web INTEGER,
  vuln_count INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  deleted_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS exploit_chains (
  project_id TEXT NOT NULL,
  chain_order INTEGER NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  impact TEXT NOT NULL DEFAULT '',
  auth_required TEXT NOT NULL DEFAULT 'unknown',
  status TEXT NOT NULL DEFAULT 'success',
  payload_json TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, chain_order),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- 记录哪些历史 exploit_report 已完成物化；无效旧 JSON 也会留标记，避免反复解析。
CREATE TABLE IF NOT EXISTS exploit_chain_sync (
  project_id TEXT PRIMARY KEY,
  report_fingerprint TEXT NOT NULL,
  synced_at INTEGER NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerability_verifications (
  project_id TEXT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  vulnerability_title TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'pending',
  code_status TEXT NOT NULL DEFAULT 'unknown',
  remote_status TEXT NOT NULL DEFAULT 'unknown',
  auth_required TEXT NOT NULL DEFAULT 'unknown',
  privilege_results_json TEXT,
  local_result TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  source_file TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  queued_at INTEGER,
  started_at INTEGER,
  finished_at INTEGER,
  updated_at INTEGER NOT NULL,
  error TEXT,
  PRIMARY KEY (project_id, vulnerability_id),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vuln_project ON vulnerabilities(project_id);
CREATE INDEX IF NOT EXISTS idx_deleted_at ON deleted_projects(deleted_at);
CREATE INDEX IF NOT EXISTS idx_exploit_chain_status_auth
  ON exploit_chains(status, auth_required, project_id);
CREATE INDEX IF NOT EXISTS idx_verification_project_state
  ON vulnerability_verifications(project_id, state, remote_status);
CREATE INDEX IF NOT EXISTS idx_verification_vulnerability
  ON vulnerability_verifications(vulnerability_id);
`);

// 旧库迁移：补充新增列
const projectCols = db.prepare('PRAGMA table_info(projects)').all() as { name: string }[];
const ensureCol = (name: string, ddl: string) => {
  if (!projectCols.some((c) => c.name === name)) db.exec(`ALTER TABLE projects ADD COLUMN ${ddl}`);
};
ensureCol('source_version', 'source_version TEXT');
ensureCol('system_name', 'system_name TEXT');
ensureCol('env_status', "env_status TEXT NOT NULL DEFAULT 'none'");
ensureCol('target_url', 'target_url TEXT');
ensureCol('exploit_report', 'exploit_report TEXT');
ensureCol('verify_status', "verify_status TEXT NOT NULL DEFAULT 'none'");
ensureCol('verify_started_at', 'verify_started_at INTEGER');
ensureCol('verify_finished_at', 'verify_finished_at INTEGER');
ensureCol('verify_error', 'verify_error TEXT');
// 多版本批量审计：github 项目指定克隆的 tag（为空则克隆默认分支）
ensureCol('git_ref', 'git_ref TEXT');
// 项目「注册功能」检测：是否存在注册、是否默认开启（NULL=未知/未检测），以及是否构成"前台 RCE"
ensureCol('has_registration', 'has_registration INTEGER');
ensureCol('reg_default_open', 'reg_default_open INTEGER');
ensureCol('frontend_rce', 'frontend_rce INTEGER NOT NULL DEFAULT 0');
// 耗时统计：代码审计 / 远程验证 的累计真实耗时（毫秒，跨多次运行累加，暂停期间不计）
ensureCol('audit_duration_ms', 'audit_duration_ms INTEGER NOT NULL DEFAULT 0');
ensureCol('verify_duration_ms', 'verify_duration_ms INTEGER NOT NULL DEFAULT 0');
// 项目级审计流程选项（NULL = 沿用全局默认）：在「新建审计」页逐项目配置
ensureCol('opt_auto_verify', 'opt_auto_verify INTEGER');
ensureCol('opt_verify_history', 'opt_verify_history INTEGER');
ensureCol('opt_ai_dedup', 'opt_ai_dedup INTEGER');
ensureCol('opt_ai_regrade', 'opt_ai_regrade INTEGER');
ensureCol('opt_verify_runtime', 'opt_verify_runtime TEXT');
ensureCol('has_web', 'has_web INTEGER');
ensureCol('audit_language', 'audit_language TEXT');

// 旧库迁移：vulnerabilities 表补充「红队实战二次评级」相关列
const vulnCols = db.prepare('PRAGMA table_info(vulnerabilities)').all() as { name: string }[];
const ensureVulnCol = (name: string, ddl: string) => {
  if (!vulnCols.some((c) => c.name === name))
    db.exec(`ALTER TABLE vulnerabilities ADD COLUMN ${ddl}`);
};
ensureVulnCol('severity_original', 'severity_original TEXT');
ensureVulnCol('regrade_value', 'regrade_value TEXT');
ensureVulnCol('regrade_reason', 'regrade_reason TEXT');
// 污点链：从用户可控输入(Source)逐跳追踪到危险操作(Sink)的完整数据流路径
ensureVulnCol('taint_chain', "taint_chain TEXT NOT NULL DEFAULT ''");
// 远程靶机验证成功标记（持久化派生列）：避免每次请求解析所有 exploit_report 做标题匹配。
// 由 runner 在验证/落库时维护、启动时一次性回填。
ensureVulnCol('verified', 'verified INTEGER NOT NULL DEFAULT 0');
// 前台 RCE：远程 HTTP 验证通过的 RCE（none 或 reg_default_open+user），见 frontendRceCriteria.ts
ensureVulnCol('frontend_rce', 'frontend_rce INTEGER NOT NULL DEFAULT 0');
// 前台 RCE「拿到时间」：该漏洞被标记为前台 RCE 的时刻（syncFrontendRce 置位时写入，
// 历史数据用项目 verify_finished_at 回填）。用于前台 RCE 视图按时间倒序展示。
ensureVulnCol('frontend_rce_at', 'frontend_rce_at INTEGER');
// 漏洞级「触发所需权限」（代码级验证/二次评级阶段判定）：none/user/admin/NULL 未判定。
ensureVulnCol('auth_required', 'auth_required TEXT');
ensureVulnCol('auth_reason', "auth_reason TEXT NOT NULL DEFAULT ''");
// 利用面簇：AI 去重把"同一代码点的不同利用面"保留为独立行并挂同一 cluster_id 关联，
// cluster_role=primary（代表面）/variant（其余利用面）；无簇的普通漏洞为 NULL。供前端折叠展示"1 点 N 面"。
ensureVulnCol('cluster_id', 'cluster_id TEXT');
ensureVulnCol('cluster_role', 'cluster_role TEXT');

// 旧库迁移：agent_events 增加 phase（审计阶段 audit / 验证阶段 verify），并回填历史数据
const eventCols = db.prepare('PRAGMA table_info(agent_events)').all() as { name: string }[];
if (!eventCols.some((c) => c.name === 'phase')) {
  db.exec("ALTER TABLE agent_events ADD COLUMN phase TEXT NOT NULL DEFAULT 'audit'");
  // 回填：以各项目"漏洞验证"标记事件的时间为界，其后事件归为 verify 阶段
  const projs = db.prepare('SELECT id FROM projects').all() as { id: string }[];
  const findMarker = db.prepare(
    "SELECT MIN(ts) AS t FROM agent_events WHERE project_id = ? AND kind='system' AND text LIKE '%漏洞验证%'"
  );
  const setVerify = db.prepare(
    "UPDATE agent_events SET phase='verify' WHERE project_id = ? AND ts >= ?"
  );
  const tx = db.transaction(() => {
    for (const p of projs) {
      const m = findMarker.get(p.id) as { t: number | null };
      if (m?.t) setVerify.run(p.id, m.t);
    }
  });
  tx();
}

// 性能索引（放在列迁移之后，以便引用新增列）：支撑万项目 / 百万漏洞下的分页、聚合与过滤。
db.exec(`
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity, created_at);
CREATE INDEX IF NOT EXISTS idx_vuln_verified ON vulnerabilities(verified);
CREATE INDEX IF NOT EXISTS idx_vuln_category ON vulnerabilities(category);
CREATE INDEX IF NOT EXISTS idx_vuln_verified_severity ON vulnerabilities(verified, severity);
CREATE INDEX IF NOT EXISTS idx_vuln_verified_category ON vulnerabilities(verified, category);
CREATE INDEX IF NOT EXISTS idx_vuln_cluster ON vulnerabilities(project_id, cluster_id);
CREATE INDEX IF NOT EXISTS idx_vuln_project_severity_created
  ON vulnerabilities(project_id, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_frontend_rce_created
  ON vulnerabilities(frontend_rce, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_frontend_rce_at
  ON vulnerabilities(frontend_rce, frontend_rce_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_verified_auth_created
  ON vulnerabilities(verified, auth_required, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_auth_severity_created
  ON vulnerabilities(auth_required, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_verified_project
  ON vulnerabilities(verified, project_id);
CREATE INDEX IF NOT EXISTS idx_event_project_ts ON agent_events(project_id, ts);
CREATE INDEX IF NOT EXISTS idx_event_completion ON agent_events(project_id, kind, phase, ts);
CREATE UNIQUE INDEX IF NOT EXISTS idx_run_log_run_seq ON project_run_logs(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_run_log_project_ts ON project_run_logs(project_id, ts);
CREATE INDEX IF NOT EXISTS idx_run_log_project_phase ON project_run_logs(project_id, phase, ts);
CREATE INDEX IF NOT EXISTS idx_proj_status ON projects(status);
CREATE INDEX IF NOT EXISTS idx_proj_verify_status ON projects(verify_status);
CREATE INDEX IF NOT EXISTS idx_proj_created ON projects(created_at);
CREATE INDEX IF NOT EXISTS idx_proj_system ON projects(system_name);
CREATE INDEX IF NOT EXISTS idx_proj_status_created
  ON projects(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proj_verify_status_created
  ON projects(verify_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proj_frontend_rce_created
  ON projects(frontend_rce, created_at DESC);
-- idx_event_project_ts 已覆盖 project_id 前缀查询，删除旧单列索引以减少约 38MB 空间和事件写放大。
DROP INDEX IF EXISTS idx_event_project;
`);

export default db;
