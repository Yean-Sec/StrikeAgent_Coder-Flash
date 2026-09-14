/**
 * 多语言审计调度用的语言占比探测。
 *
 * 生产路径只认两种权威来源（由 runner 编排顺序）：
 *  1. Pi 语义判定（区分第一方源码 vs 打包/静态资源里的 JS）
 *  2. GitHub 官方 [Linguist](https://github.com/github-linguist/linguist)
 *
 * 二者都得不到可调度主导语言时，审计必须失败，禁止启发式扩展名扫盘回退。
 * `detectLanguageMixHeuristic` 仅供单测 / `forceHeuristic`。
 */
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

/** 扩展名 → 语言 token（与 runner 子智能体语言键一致；启发式回退用）。 */
export const EXT_TO_LANG: Record<string, string> = {
  '.php': 'php',
  '.py': 'python',
  '.go': 'go',
  '.java': 'java',
  '.rs': 'rust',
  '.rb': 'ruby',
  '.cs': 'csharp',
  '.js': 'jsts',
  '.jsx': 'jsts',
  '.mjs': 'jsts',
  '.cjs': 'jsts',
  '.ts': 'jsts',
  '.tsx': 'jsts',
  '.vue': 'jsts',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.cxx': 'cpp',
  '.cc': 'cpp',
  '.c++': 'cpp',
  '.hpp': 'cpp',
  '.hh': 'cpp',
  '.hxx': 'cpp',
  '.ipp': 'cpp',
  '.tcc': 'cpp',
  '.sol': 'solidity',
};

/**
 * GitHub Linguist 语言名 → 本系统调度 token。
 * 未列出的语言（Shell/Makefile/HTML/CSS…）不参与专家调度占比（重新归一化）。
 */
export const LINGUIST_LANG_TO_TOKEN: Record<string, string> = {
  Java: 'java',
  Go: 'go',
  Python: 'python',
  PHP: 'php',
  Rust: 'rust',
  Ruby: 'ruby',
  'C#': 'csharp',
  C: 'c',
  'C++': 'cpp',
  Solidity: 'solidity',
  // 前端族合并为 jsts（与 EXT_TO_LANG / 子智能体键一致）
  JavaScript: 'jsts',
  TypeScript: 'jsts',
  Vue: 'jsts',
  'Vue HTML': 'jsts',
  TSX: 'jsts',
  JSX: 'jsts',
  CoffeeScript: 'jsts',
};

/** 有专项子智能体、可参与调度的语言 token。 */
export const SCHEDULABLE_LANG_TOKENS = [
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
export type SchedulableLang = (typeof SCHEDULABLE_LANG_TOKENS)[number];
const SCHEDULABLE_SET = new Set<string>(SCHEDULABLE_LANG_TOKENS);

const LANG_ALIASES: Record<string, string> = {
  javascript: 'jsts',
  typescript: 'jsts',
  js: 'jsts',
  ts: 'jsts',
  node: 'jsts',
  nodejs: 'jsts',
  vue: 'jsts',
  jsx: 'jsts',
  tsx: 'jsts',
  java: 'java',
  go: 'go',
  golang: 'go',
  python: 'python',
  php: 'php',
  rust: 'rust',
  ruby: 'ruby',
  csharp: 'csharp',
  'c#': 'csharp',
  'c#/.net': 'csharp',
  dotnet: 'csharp',
  c: 'c',
  cpp: 'cpp',
  'c++': 'cpp',
  solidity: 'solidity',
};

export function normalizeLangToken(raw: unknown): SchedulableLang | null {
  if (typeof raw !== 'string') return null;
  const key = raw.trim().toLowerCase();
  if (!key) return null;
  const mapped = LANG_ALIASES[key] || (SCHEDULABLE_SET.has(key) ? key : null);
  return mapped && SCHEDULABLE_SET.has(mapped) ? (mapped as SchedulableLang) : null;
}

export const LANG_MIX_CACHE_REL = path.join('_pipeline', 'lang_mix.json');

export function langMixCachePath(codeDir: string): string {
  return path.join(codeDir, LANG_MIX_CACHE_REL);
}

export function writeLangMixCache(codeDir: string, mix: LanguageMix): void {
  const file = langMixCachePath(codeDir);
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(mix, null, 2) + '\n', 'utf8');
  } catch {
    /* 缓存失败不阻断：调用方仍持有 mix */
  }
}

export function readLangMixCache(codeDir: string): LanguageMix | null {
  try {
    const raw = JSON.parse(fs.readFileSync(langMixCachePath(codeDir), 'utf8'));
    const primary = normalizeLangToken(raw?.primary);
    if (!primary) return null;
    const ratios: Record<string, number> = {};
    if (raw?.ratios && typeof raw.ratios === 'object') {
      for (const [k, v] of Object.entries(raw.ratios)) {
        const tok = normalizeLangToken(k);
        const n = Number(v);
        if (tok && Number.isFinite(n) && n > 0) ratios[tok] = n > 1 ? n / 100 : n;
      }
    }
    const secondaries = Array.isArray(raw?.secondaries)
      ? raw.secondaries.map(normalizeLangToken).filter((l: string | null): l is SchedulableLang => !!l && l !== primary)
      : [];
    const sourceRaw =
      raw?.source === 'linguist' || raw?.source === 'pi' || raw?.source === 'claude' ? raw.source : null;
    if (!sourceRaw) return null;
    const source = sourceRaw === 'claude' ? 'pi' : sourceRaw;
    return {
      primary,
      secondaries,
      ratios: Object.keys(ratios).length ? ratios : { [primary]: 1 },
      source,
      reason: typeof raw?.reason === 'string' ? raw.reason : undefined,
    };
  } catch {
    return null;
  }
}

/** 把 Pi Agent 结构化输出收成 LanguageMix；无效则 null。 */
export function languageMixFromPiJson(raw: any, secondaryThreshold: number): LanguageMix | null {
  if (!raw || typeof raw !== 'object') return null;
  const primary = normalizeLangToken(raw.primary);
  if (!primary) return null;
  const ratios: Record<string, number> = {};
  if (raw.ratios && typeof raw.ratios === 'object' && !Array.isArray(raw.ratios)) {
    for (const [k, v] of Object.entries(raw.ratios)) {
      const tok = normalizeLangToken(k);
      const n = Number(v);
      if (tok && Number.isFinite(n) && n > 0) ratios[tok] = n > 1 ? n / 100 : n;
    }
  }
  const tot = Object.values(ratios).reduce((a, b) => a + b, 0);
  if (tot > 0) {
    for (const k of Object.keys(ratios)) ratios[k] = ratios[k] / tot;
  } else {
    ratios[primary] = 1;
  }
  let secondaries: string[] = [];
  if (Array.isArray(raw.secondaries) && raw.secondaries.length) {
    secondaries = (raw.secondaries as unknown[])
      .map(normalizeLangToken)
      .filter((l): l is SchedulableLang => !!l && l !== primary);
  } else {
    secondaries = Object.keys(ratios)
      .filter((l) => l !== primary && (ratios[l] || 0) >= secondaryThreshold)
      .sort((a, b) => (ratios[b] || 0) - (ratios[a] || 0));
  }
  return {
    primary,
    secondaries,
    ratios,
    source: 'pi',
    reason: typeof raw.reason === 'string' ? raw.reason : undefined,
  };
}

/** 启发式回退：跳过的目录名。 */
export const LANG_SCAN_SKIP_DIRS = new Set([
  'node_modules',
  'vendor',
  'bower_components',
  'jspm_packages',
  'site-packages',
  'venv',
  'Pods',
  'Carthage',
  'dist',
  'build',
  'target',
  'out',
  'bin',
  'obj',
  '__pycache__',
  'coverage',
  'htmlcov',
  '.turbo',
  'storybook-static',
  'static',
  'wwwroot',
  'staticfiles',
  'collected_static',
  'webroot',
  'public',
  'JSON',
  'MD-Vulnerability',
  '_ai_dedup',
  '_code_verify',
  '_regrade',
  '_pipeline',
  '_remote_verify',
]);

/** @deprecated 使用 LANG_SCAN_SKIP_DIRS */
export const LANG_SCAN_SKIP = LANG_SCAN_SKIP_DIRS;

export function shouldSkipLangScanDir(name: string): boolean {
  if (!name || name.startsWith('.')) return true;
  return LANG_SCAN_SKIP_DIRS.has(name);
}

export function isBundledOrGeneratedSourceFile(fileName: string): boolean {
  const base = path.basename(fileName);
  const lower = base.toLowerCase();
  if (/\.min\.(m?js|cjs)$/i.test(lower)) return true;
  if (/\.(bundle|chunk|vendor)\.(m?js|cjs)$/i.test(lower)) return true;
  if (/\.worker\.(m?js|cjs)$/i.test(lower)) return true;
  if (/\.worker-[a-z0-9_-]+\.(m?js|cjs)$/i.test(lower)) return true;
  if (/^(vendor|chunk|runtime|polyfills)[-.].+\.(m?js|cjs)$/i.test(lower)) return true;
  if (/^.+-[a-zA-Z0-9_]{8,}\.(m?js|cjs)$/.test(base)) return true;
  return false;
}

export interface LanguageMix {
  primary: string | null;
  secondaries: string[];
  ratios: Record<string, number>;
  /** pi = 语义判定；linguist = GitHub Linguist；heuristic 仅测试。读缓存时旧值 claude 会归一成 pi。 */
  source?: 'pi' | 'linguist' | 'heuristic';
  reason?: string;
  error?: string;
}

export interface DetectLanguageMixOptions {
  secondaryThreshold: number;
  fallbackPrimary?: string | null | (() => string | null);
  hasSubagents?: (lang: string) => boolean;
  /** 覆盖 `github-linguist` 可执行文件路径（默认 PATH / 常见 gem bin） */
  linguistBin?: string;
  /** 为 true 时跳过 Linguist，仅用启发式（测试用） */
  forceHeuristic?: boolean;
}

export type LinguistJson = Record<string, { size: number; percentage?: string }>;

/** 解析 `github-linguist --json` 输出为调度用字节表（已映射并合并 jsts）。 */
export function linguistJsonToTokenBytes(raw: LinguistJson): Record<string, number> {
  const bytes: Record<string, number> = {};
  for (const [name, info] of Object.entries(raw || {})) {
    const token = LINGUIST_LANG_TO_TOKEN[name];
    if (!token) continue;
    const size = Number(info?.size) || 0;
    if (size <= 0) continue;
    bytes[token] = (bytes[token] || 0) + size;
  }
  return bytes;
}

function resolveFallbackPrimary(
  fallback: DetectLanguageMixOptions['fallbackPrimary']
): string | null {
  if (typeof fallback === 'function') return fallback();
  return fallback ?? null;
}

function mixFromBytes(
  bytes: Record<string, number>,
  opts: DetectLanguageMixOptions,
  source: 'linguist' | 'heuristic'
): LanguageMix {
  const total = Object.values(bytes).reduce((a, b) => a + b, 0);
  if (total === 0) {
    const fallback = resolveFallbackPrimary(opts.fallbackPrimary);
    return {
      primary: fallback,
      secondaries: [],
      ratios: fallback ? { [fallback]: 1 } : {},
      source,
    };
  }
  const ratios: Record<string, number> = {};
  for (const [k, v] of Object.entries(bytes)) ratios[k] = v / total;
  const sorted = Object.keys(ratios).sort((a, b) => ratios[b] - ratios[a]);
  const primary = sorted[0];
  const thr = opts.secondaryThreshold;
  const hasSub = opts.hasSubagents ?? (() => true);
  const secondaries = sorted.slice(1).filter((l) => ratios[l] >= thr && hasSub(l));
  return { primary, secondaries, ratios, source };
}

/** 解析 github-linguist 可执行文件。显式路径不存在则视为未安装（不回落到 PATH）。 */
export function resolveLinguistBin(explicit?: string): string | null {
  if (explicit) {
    if (explicit === 'github-linguist') {
      try {
        execFileSync('which', ['github-linguist'], { stdio: 'ignore' });
        return 'github-linguist';
      } catch {
        return null;
      }
    }
    return fs.existsSync(explicit) ? explicit : null;
  }
  const fromEnv = process.env.LINGUIST_BIN || process.env.GITHUB_LINGUIST_BIN;
  if (fromEnv && fs.existsSync(fromEnv)) return fromEnv;
  const candidates = [
    'github-linguist',
    '/usr/local/bin/github-linguist',
    '/usr/bin/github-linguist',
    path.join('/var/lib/gems/3.3.0/gems/github-linguist-9.7.0/bin/github-linguist'),
  ];
  // also scan /var/lib/gems/*/gems/github-linguist-*/bin/github-linguist
  try {
    const gemsRoot = '/var/lib/gems';
    for (const ver of fs.readdirSync(gemsRoot)) {
      const gemsDir = path.join(gemsRoot, ver, 'gems');
      if (!fs.existsSync(gemsDir)) continue;
      for (const g of fs.readdirSync(gemsDir)) {
        if (!g.startsWith('github-linguist-')) continue;
        const bin = path.join(gemsDir, g, 'bin', 'github-linguist');
        if (fs.existsSync(bin)) candidates.push(bin);
      }
    }
  } catch {
    /* ignore */
  }
  for (const c of candidates) {
    if (c === 'github-linguist') {
      try {
        execFileSync('which', ['github-linguist'], { stdio: 'ignore' });
        return 'github-linguist';
      } catch {
        continue;
      }
    }
    if (fs.existsSync(c)) return c;
  }
  return null;
}

/** git -C 通用参数：绕过「可疑仓库所有权」(root 扫 kali 属主工作区时常见)。 */
function gitArgs(codeDir: string, args: string[]): string[] {
  return ['-c', `safe.directory=${codeDir}`, '-C', codeDir, ...args];
}

function isGitRepo(dir: string): boolean {
  try {
    const gitPath = path.join(dir, '.git');
    if (!fs.existsSync(gitPath)) return false;
    const st = fs.statSync(gitPath);
    if (st.isFile() || st.isDirectory()) {
      execFileSync('git', gitArgs(dir, ['rev-parse', '--is-inside-work-tree']), {
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 15_000,
      });
      // 还须至少有一个 commit，否则 Linguist/rugged 打不开
      execFileSync('git', gitArgs(dir, ['rev-parse', 'HEAD']), {
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 15_000,
      });
      return true;
    }
  } catch {
    /* not a usable repo */
  }
  return false;
}

/**
 * 保证 codeDir 可作为 Linguist 输入的 Git 仓库。
 * 已有可用 .git+HEAD 则不动；否则 init + 全量 commit（尊重仓库内 .gitattributes）。
 */
export function ensureGitRepoForLinguist(codeDir: string): void {
  if (isGitRepo(codeDir)) return;
  const abs = path.resolve(codeDir);
  execFileSync('git', gitArgs(abs, ['init']), {
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 60_000,
  });
  execFileSync('git', gitArgs(abs, ['add', '-A']), {
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 600_000,
  });
  execFileSync(
    'git',
    gitArgs(abs, [
      '-c',
      'user.email=linguist@localhost',
      '-c',
      'user.name=linguist',
      'commit',
      '--allow-empty',
      '-m',
      'linguist-index',
    ]),
    {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 600_000,
      env: {
        ...process.env,
        GIT_AUTHOR_DATE: '1970-01-01T00:00:00Z',
        GIT_COMMITTER_DATE: '1970-01-01T00:00:00Z',
      },
    }
  );
}

/** 本系统审计中间目录：不得污染 Linguist 占比（写入 `.git/info/attributes`，不改项目源码）。 */
const AUDIT_ARTIFACT_ATTR_BLOCK = `# strike-agent-langmix (do not edit)
JSON/** linguist-vendored
MD-Vulnerability/** linguist-vendored
_ai_dedup/** linguist-vendored
_code_verify/** linguist-vendored
_regrade/** linguist-vendored
_pipeline/** linguist-vendored
_remote_verify/** linguist-vendored
.codegraph/** linguist-vendored
`;

function resolveGitDir(codeDir: string): string | null {
  const gitPath = path.join(codeDir, '.git');
  try {
    if (!fs.existsSync(gitPath)) return null;
    const st = fs.statSync(gitPath);
    if (st.isDirectory()) return gitPath;
    if (st.isFile()) {
      const raw = fs.readFileSync(gitPath, 'utf8');
      const m = raw.match(/^\s*gitdir:\s*(.+)\s*$/m);
      if (!m) return null;
      const target = m[1].trim();
      return path.isAbsolute(target) ? target : path.resolve(codeDir, target);
    }
  } catch {
    /* ignore */
  }
  return null;
}

/** 把审计产物目录标成 linguist-vendored，避免 `_code_verify/*.ts` 等把主导语言拧偏。 */
export function ensureLocalLinguistAttributes(codeDir: string): void {
  const gitDir = resolveGitDir(codeDir);
  if (!gitDir) return;
  const infoDir = path.join(gitDir, 'info');
  const attrsFile = path.join(infoDir, 'attributes');
  try {
    fs.mkdirSync(infoDir, { recursive: true });
    let cur = '';
    try {
      cur = fs.readFileSync(attrsFile, 'utf8');
    } catch {
      cur = '';
    }
    if (cur.includes('strike-agent-langmix')) return;
    const next = cur.trimEnd() ? `${cur.trimEnd()}\n\n${AUDIT_ARTIFACT_ATTR_BLOCK}` : AUDIT_ARTIFACT_ATTR_BLOCK;
    fs.writeFileSync(attrsFile, next.endsWith('\n') ? next : `${next}\n`, 'utf8');
  } catch {
    /* 忽略：无写权限时 Linguist 仍可跑，最多少计审计目录 */
  }
}

/**
 * Rugged/libgit2 在「目录属主 ≠ 当前用户」时会拒绝打开仓库（常见于 root 跑服务、
 * 工作区属 kali）。与 `git -c safe.directory=*` 对齐，确保全局允许任意目录。
 */
export function ensureLinguistSafeDirectory(): void {
  try {
    const out = execFileSync('git', ['config', '--global', '--get-all', 'safe.directory'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (out.split(/\r?\n/).some((l) => l.trim() === '*')) return;
  } catch {
    /* 尚无配置 */
  }
  try {
    execFileSync('git', ['config', '--global', '--add', 'safe.directory', '*'], {
      stdio: 'ignore',
    });
  } catch {
    /* 无写权限时由上层把 Linguist 失败当成判定失败 */
  }
}

/** 调用官方 github-linguist --json，返回原始 JSON。 */
export function runGithubLinguist(codeDir: string, bin?: string): LinguistJson {
  const linguist = resolveLinguistBin(bin);
  if (!linguist) {
    throw new Error(
      '未找到 github-linguist。请安装：sudo gem install github-linguist（rugged 需 --use-system-libraries）'
    );
  }
  ensureLinguistSafeDirectory();
  ensureGitRepoForLinguist(codeDir);
  ensureLocalLinguistAttributes(codeDir);
  const abs = path.resolve(codeDir);
  const out = execFileSync(linguist, ['--json', abs], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    timeout: 600_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const parsed = JSON.parse(out.trim() || '{}') as LinguistJson;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('github-linguist 返回了非对象 JSON');
  }
  return parsed;
}

/** 本地启发式（仅单测 / forceHeuristic；生产路径禁止调用）。 */
export function detectLanguageMixHeuristic(
  codeDir: string,
  opts: DetectLanguageMixOptions
): LanguageMix {
  const bytes: Record<string, number> = {};
  const stack = [codeDir];
  const MAX_FILES = 200_000;
  let scanned = 0;

  while (stack.length) {
    const cur = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!shouldSkipLangScanDir(e.name)) stack.push(path.join(cur, e.name));
        continue;
      }
      if (!e.isFile()) continue;
      if (isBundledOrGeneratedSourceFile(e.name)) continue;
      const lang = EXT_TO_LANG[path.extname(e.name).toLowerCase()];
      if (!lang) continue;
      if (++scanned > MAX_FILES) break;
      try {
        bytes[lang] = (bytes[lang] || 0) + fs.statSync(path.join(cur, e.name)).size;
      } catch {
        /* ignore */
      }
    }
  }
  return mixFromBytes(bytes, opts, 'heuristic');
}

/**
 * GitHub Linguist 占比。失败或未映射到可调度语言时返回 primary=null 并带 error。
 * 默认不再回退启发式（forceHeuristic 仅单测）。
 */
export function detectLanguageMix(
  codeDir: string,
  opts: DetectLanguageMixOptions
): LanguageMix {
  if (opts.forceHeuristic) {
    return detectLanguageMixHeuristic(codeDir, opts);
  }
  try {
    const raw = runGithubLinguist(codeDir, opts.linguistBin);
    const bytes = linguistJsonToTokenBytes(raw);
    const mix = mixFromBytes(bytes, { ...opts, fallbackPrimary: undefined }, 'linguist');
    if (mix.primary) return mix;
    return {
      primary: null,
      secondaries: [],
      ratios: {},
      source: 'linguist',
      error: 'GitHub Linguist 未映射到可调度语言（仅 HTML/CSS/Shell 等）',
    };
  } catch (err: any) {
    const msg = String(err?.message || err).slice(0, 400);
    if (process.env.LANGMIX_DEBUG === '1') {
      console.warn('[langMix] github-linguist failed:', msg);
    }
    return {
      primary: null,
      secondaries: [],
      ratios: {},
      error: `GitHub Linguist 不可用：${msg}`,
    };
  }
}
