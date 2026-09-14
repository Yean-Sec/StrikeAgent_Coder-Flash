import fs from 'fs';
import path from 'path';

export type ProjectShape = 'web' | 'harness';

export type TargetEnvMode = 'web' | 'harness' | 'external' | 'mini' | 'unknown';

export interface RuntimeVersionProof {
  type: 'http' | 'container-log' | 'file';
  /** http URL, container name, or workspace-relative file path. */
  target: string;
  /** Literal text that must be observed at validation time. */
  contains: string;
}

export interface TargetEnvContract extends Record<string, unknown> {
  mode?: string;
  managed?: string;
  url?: string;
  login_url?: string;
  compose_project?: string;
  compose_file?: string;
  version?: string;
  source_version?: string;
  source_commit?: string | null;
  source_fingerprint?: string | null;
  build_provenance?: string;
  runtime_version?: string;
  runtime_version_proof?: RuntimeVersionProof;
  harness_dir?: string;
  smoke_command?: string;
}

const HARNESS_TARGET_URL = 'harness://local';
const MINI_TARGET_URL = 'mini://local';

export function harnessTargetUrl(): string {
  return HARNESS_TARGET_URL;
}

export function miniTargetUrl(): string {
  return MINI_TARGET_URL;
}

export function isHarnessTargetUrl(url: string | null | undefined): boolean {
  return String(url || '').startsWith('harness://');
}

export function isMiniTargetUrl(url: string | null | undefined): boolean {
  return String(url || '').startsWith('mini://');
}

function existsFile(base: string, rel: string): boolean {
  try {
    return fs.statSync(path.join(base, rel)).isFile();
  } catch {
    return false;
  }
}

function existsDir(base: string, rel: string): boolean {
  try {
    return fs.statSync(path.join(base, rel)).isDirectory();
  } catch {
    return false;
  }
}

function findAndroidManifest(codeDir: string): string | null {
  const skip = new Set(['node_modules', '.git', 'build', '.gradle', '.codegraph']);
  const stack = [codeDir];
  while (stack.length) {
    const cur = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.name === 'AndroidManifest.xml' && e.isFile()) return path.join(cur, e.name);
      if (e.isDirectory() && !skip.has(e.name)) stack.push(path.join(cur, e.name));
    }
  }
  return null;
}

export function hasTypicalWebRoot(codeDir: string): boolean {
  if (existsFile(codeDir, 'index.php')) return true;
  if (existsFile(codeDir, 'public/index.php')) return true;
  if (existsFile(codeDir, 'artisan') && existsFile(codeDir, 'composer.json')) return true;
  if (existsFile(codeDir, 'manage.py') && existsDir(codeDir, 'templates')) return true;
  if (existsFile(codeDir, 'package.json')) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(codeDir, 'package.json'), 'utf8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps.express || deps.koa || deps.fastify || deps.next) return true;
    } catch {
      /* ignore */
    }
  }
  if (existsFile(codeDir, 'docker-compose.yml') || existsFile(codeDir, 'docker-compose.yaml')) {
    try {
      const txt = fs.readFileSync(
        path.join(codeDir, existsFile(codeDir, 'docker-compose.yml') ? 'docker-compose.yml' : 'docker-compose.yaml'),
        'utf8'
      );
      if (/nginx|apache|php|wordpress|mysql|8080|:80/i.test(txt)) return true;
    } catch {
      /* ignore */
    }
  }
  return false;
}

function readProjectProfile(codeDir: string): Record<string, unknown> | null {
  const p = path.join(codeDir, 'JSON', 'project_profile.json');
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

function profileSuggestsHarness(profile: Record<string, unknown>): boolean {
  const lang = String(profile.primary_language || '').toLowerCase();
  const desc = String(profile.description || '').toLowerCase();
  if (/kotlin|java|android/.test(lang)) return true;
  if (/android|apk|移动端|手机应用/.test(desc)) return true;
  const fw = profile.frameworks;
  if (fw && typeof fw === 'object') {
    const blob = JSON.stringify(fw).toLowerCase();
    if (/jetpack|android|compose|robolectric/.test(blob)) return true;
  }
  return false;
}

/** 保守检测：仅明确非 Web 项目才走 Harness，默认 web。 */
export function detectProjectShape(codeDir: string): ProjectShape {
  if (!codeDir || !fs.existsSync(codeDir)) return 'web';

  const profile = readProjectProfile(codeDir);
  if (profile && profileSuggestsHarness(profile) && !hasTypicalWebRoot(codeDir)) {
    return 'harness';
  }

  const hasGradle =
    existsFile(codeDir, 'build.gradle') ||
    existsFile(codeDir, 'build.gradle.kts') ||
    existsFile(codeDir, 'settings.gradle') ||
    existsFile(codeDir, 'settings.gradle.kts');
  const manifest = findAndroidManifest(codeDir);
  if (manifest && hasGradle && !hasTypicalWebRoot(codeDir)) return 'harness';

  if (manifest && !hasTypicalWebRoot(codeDir) && profileSuggestsHarness(profile || {})) {
    return 'harness';
  }

  return 'web';
}

export function targetEnvPath(codeDir: string): string {
  return path.join(codeDir, 'TARGET_ENV.json');
}

export function readTargetEnv(codeDir: string): TargetEnvContract | null {
  try {
    const o = JSON.parse(fs.readFileSync(targetEnvPath(codeDir), 'utf8'));
    return o && typeof o === 'object' ? (o as TargetEnvContract) : null;
  } catch {
    return null;
  }
}

export function readTargetEnvMode(codeDir: string): TargetEnvMode {
  const env = readTargetEnv(codeDir);
  const mode = String(env?.mode || env?.managed || '').toLowerCase();
  if (mode === 'harness') return 'harness';
  if (mode === 'mini') return 'mini';
  if (mode === 'external') return 'external';
  if (mode === 'web' || (env?.url && !isHarnessTargetUrl(String(env.url)) && !isMiniTargetUrl(String(env.url)))) return 'web';
  if (isHarnessTargetUrl(String(env?.url || ''))) return 'harness';
  if (isMiniTargetUrl(String(env?.url || ''))) return 'mini';
  return 'unknown';
}

const LOCAL_COMPOSE_CANDIDATES = [
  'docker-compose.code.yml',
  'docker-compose.code.yaml',
  'docker-compose.strikeagent.yml',
  'docker-compose.strikeagent.yaml',
  'docker-compose.yml',
  'docker-compose.yaml',
];

/**
 * StrikeAgent / 产品侧可生命周期管理的本地 Compose 合同：
 * TARGET_ENV 声明了 compose_project，且工作区存在对应 compose 文件。
 * 这类靶机允许产品在验证时 compose start 复用；但 mode=external 时禁止 idle stop。
 */
export function hasLocalComposeContract(codeDir: string): boolean {
  const env = readTargetEnv(codeDir);
  if (!env) return false;
  if (!String(env.compose_project || '').trim()) return false;
  const named = String(env.compose_file || '').trim();
  if (named && existsFile(codeDir, named)) return true;
  return LOCAL_COMPOSE_CANDIDATES.some((f) => existsFile(codeDir, f));
}

/**
 * 纯外部靶机（mode=external 且无本地 compose 合同）：
 * 不要求 compose 项目标签，产品侧禁止搭建/停删，只能等外部自行拉起。
 * 带 compose 合同的 mode=external 不算「纯外部」——验证时可由产品 compose start，
 * 但空闲 stop 仍须走 shouldPreserveExternalContainers（禁止 idle stop）。
 */
export function isExternallyManagedTarget(codeDir: string): boolean {
  if (readTargetEnvMode(codeDir) !== 'external') return false;
  return !hasLocalComposeContract(codeDir);
}

/**
 * Cursor/Agent 自建靶机（TARGET_ENV.mode=external，含带 compose 合同）：
 * 产品侧禁止 idle stop / 资源回收 stop，避免验证暂停或后端重启后靶场被误停「又崩」。
 * 用户主动「清除靶机」走独立 destroy 路径，不受此约束。
 */
export function shouldPreserveExternalContainers(codeDir: string): boolean {
  return readTargetEnvMode(codeDir) === 'external';
}

export function harnessDir(codeDir: string, env?: Record<string, unknown> | null): string {
  const rel = String(env?.harness_dir || '_harness').replace(/^[/\\]+/, '');
  return path.join(codeDir, rel);
}
