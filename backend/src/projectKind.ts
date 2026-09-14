import fs from 'fs';
import path from 'path';
import { hasTypicalWebRoot } from './projectShape';
import { codegraphSignalsWeb } from './codegraphWeb';

export type ProjectKind =
  | 'web'
  | 'mobile_app'
  | 'desktop'
  | 'miniprogram'
  | 'cli'
  | 'middleware'
  | 'plugin'
  | 'library'
  | 'unknown';

export interface ProjectKindInfo {
  kind: ProjectKind;
  kind_label: string;
  has_web: boolean | null;
  web_label: string;
}

const KIND_LABEL: Record<ProjectKind, string> = {
  web: 'Web 应用',
  mobile_app: '移动 App',
  desktop: '桌面应用',
  miniprogram: '小程序',
  cli: 'CLI 工具',
  middleware: '中间件',
  plugin: '插件/扩展',
  library: '库/组件',
  unknown: '待识别',
};

function existsFile(base: string, rel: string): boolean {
  try {
    return fs.statSync(path.join(base, rel)).isFile();
  } catch {
    return false;
  }
}

function readJsonFile(file: string): Record<string, unknown> | null {
  try {
    const o = JSON.parse(fs.readFileSync(file, 'utf8'));
    return o && typeof o === 'object' ? (o as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** 在工作区中查找 project_profile.json（含一层子目录）。 */
export function findProjectProfile(codeDir: string): Record<string, unknown> | null {
  if (!codeDir || !fs.existsSync(codeDir)) return null;
  const candidates = [
    path.join(codeDir, 'JSON', 'project_profile.json'),
    path.join(codeDir, 'project_profile.json'),
  ];
  try {
    for (const e of fs.readdirSync(codeDir, { withFileTypes: true })) {
      if (!e.isDirectory() || e.name.startsWith('.') || e.name === 'node_modules') continue;
      candidates.push(path.join(codeDir, e.name, 'JSON', 'project_profile.json'));
      candidates.push(path.join(codeDir, e.name, 'project_profile.json'));
    }
  } catch {
    /* ignore */
  }
  for (const p of candidates) {
    const o = readJsonFile(p);
    if (o) return o;
  }
  return null;
}

function findAndroidManifest(codeDir: string): boolean {
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
      if (e.name === 'AndroidManifest.xml' && e.isFile()) return true;
      if (e.isDirectory() && !skip.has(e.name)) stack.push(path.join(cur, e.name));
    }
  }
  return false;
}

function readPkgJson(codeDir: string): Record<string, unknown> | null {
  return readJsonFile(path.join(codeDir, 'package.json'));
}

function isMiniprogram(codeDir: string): boolean {
  if (!existsFile(codeDir, 'project.config.json')) return false;
  const app = readJsonFile(path.join(codeDir, 'app.json'));
  return !!(app && Array.isArray(app.pages));
}

function isElectronDesktop(codeDir: string): boolean {
  const pkg = readPkgJson(codeDir);
  if (!pkg) return false;
  const deps = { ...(pkg.dependencies as object), ...(pkg.devDependencies as object) } as Record<string, unknown>;
  return !!(deps.electron || deps['electron-builder']);
}

function isCliTool(codeDir: string, profile: Record<string, unknown> | null): boolean {
  const t = String(profile?.type || profile?.project_type || '').toLowerCase();
  if (/cli|command.?line|命令行|控制台工具/.test(t)) return true;
  if (existsFile(codeDir, 'cmd/main.go') || existsFile(codeDir, 'main.go')) {
    if (!hasTypicalWebRoot(codeDir)) return true;
  }
  if (existsFile(codeDir, 'setup.py')) {
    const txt = (() => {
      try {
        return fs.readFileSync(path.join(codeDir, 'setup.py'), 'utf8');
      } catch {
        return '';
      }
    })();
    if (/console_scripts|entry_points/.test(txt) && !hasTypicalWebRoot(codeDir)) return true;
  }
  const pkg = readPkgJson(codeDir);
  if (pkg?.bin && !hasTypicalWebRoot(codeDir)) {
    const deps = { ...(pkg.dependencies as object), ...(pkg.devDependencies as object) } as Record<string, unknown>;
    if (!deps.express && !deps.next && !deps.koa) return true;
  }
  return false;
}

function isWordPressPlugin(codeDir: string): boolean {
  const tryFile = (rel: string) => {
    try {
      const head = fs.readFileSync(path.join(codeDir, rel), 'utf8').slice(0, 4000);
      return /Plugin Name:/i.test(head);
    } catch {
      return false;
    }
  };
  return tryFile('index.php') || tryFile(`${path.basename(codeDir)}.php`);
}

function isLibrary(codeDir: string, profile: Record<string, unknown> | null): boolean {
  const t = String(profile?.type || '').toLowerCase();
  if (/library|component|依赖包|sdk|framework library/.test(t)) return true;
  const pkg = readPkgJson(codeDir);
  if (pkg && !pkg.bin && !hasTypicalWebRoot(codeDir)) {
    const deps = { ...(pkg.dependencies as object), ...(pkg.devDependencies as object) } as Record<string, unknown>;
    if (!deps.express && !deps.next && !deps.koa && !deps.electron) {
      if (String(pkg.main || '').trim() || existsFile(codeDir, 'src/index.ts')) return true;
    }
  }
  if (existsFile(codeDir, 'pom.xml') && !hasTypicalWebRoot(codeDir)) {
    try {
      const pom = fs.readFileSync(path.join(codeDir, 'pom.xml'), 'utf8');
      if (/packaging>\s*jar\s*</.test(pom) && !/spring-boot-starter-web/.test(pom)) return true;
    } catch {
      /* ignore */
    }
  }
  return false;
}

function isMiddleware(codeDir: string, profile: Record<string, unknown> | null): boolean {
  const t = String(profile?.type || profile?.description || '').toLowerCase();
  if (/middleware|中间件|nginx module|redis module|tomcat valve|filter plugin/.test(t)) return true;
  return false;
}

function profileHasWeb(profile: Record<string, unknown> | null): boolean {
  if (!profile) return false;
  if (profile.has_frontend === true || profile.has_backend_admin === true) return true;
  const blob = [
    profile.type,
    profile.project_type,
    profile.description,
    profile.deployment,
  ]
    .filter(Boolean)
    .map(String)
    .join(' ')
    .toLowerCase();
  if (/web application|web app|web站点|网站|http service|php.*site|nginx|apache/.test(blob)) return true;
  return false;
}

function profileKindHint(profile: Record<string, unknown> | null): ProjectKind | null {
  if (!profile) return null;
  const blob = [
    profile.type,
    profile.project_type,
    profile.description,
    profile.primary_language,
    profile.language,
  ]
    .filter(Boolean)
    .map(String)
    .join(' ')
    .toLowerCase();
  if (/web application|web app|web站点|网站/.test(blob)) return 'web';
  if (/android|apk|ios|mobile app|移动端|手机应用|kotlin.*app/.test(blob)) return 'mobile_app';
  if (/desktop|electron|桌面|wpf|winforms|qt app/.test(blob)) return 'desktop';
  if (/小程序|miniprogram|wechat/.test(blob)) return 'miniprogram';
  if (/cli|command line|命令行/.test(blob)) return 'cli';
  if (/middleware|中间件/.test(blob)) return 'middleware';
  if (/plugin|插件|extension|扩展/.test(blob)) return 'plugin';
  if (/library|sdk|组件|依赖包|framework library/.test(blob)) return 'library';
  return null;
}

function finish(kind: ProjectKind, hasWeb: boolean): ProjectKindInfo {
  return {
    kind,
    kind_label: KIND_LABEL[kind],
    has_web: hasWeb,
    web_label: hasWeb ? '含 Web 端' : '无 Web 端',
  };
}

/** 识别项目形态与是否含可部署 Web 入口（只读，运行时计算）。 */
export function detectProjectKind(codeDir: string): ProjectKindInfo {
  if (!codeDir || !fs.existsSync(codeDir)) {
    return { kind: 'unknown', kind_label: KIND_LABEL.unknown, has_web: null, web_label: 'Web 端待识别' };
  }

  const profile = findProjectProfile(codeDir);
  const webRoot = hasTypicalWebRoot(codeDir);
  const hasWeb = webRoot || profileHasWeb(profile);

  if (webRoot || profileKindHint(profile) === 'web') {
    return finish('web', true);
  }

  if (findAndroidManifest(codeDir) || profileKindHint(profile) === 'mobile_app') {
    return finish('mobile_app', hasWeb);
  }

  if (isMiniprogram(codeDir) || profileKindHint(profile) === 'miniprogram') {
    return finish('miniprogram', hasWeb);
  }

  if (isElectronDesktop(codeDir) || profileKindHint(profile) === 'desktop') {
    return finish('desktop', hasWeb);
  }

  if (isWordPressPlugin(codeDir) || profileKindHint(profile) === 'plugin') {
    return finish('plugin', hasWeb);
  }

  if (isMiddleware(codeDir, profile) || profileKindHint(profile) === 'middleware') {
    return finish('middleware', hasWeb);
  }

  if (isCliTool(codeDir, profile) || profileKindHint(profile) === 'cli') {
    return finish('cli', hasWeb);
  }

  if (isLibrary(codeDir, profile) || profileKindHint(profile) === 'library') {
    return finish('library', hasWeb);
  }

  if (hasWeb) return finish('web', true);

  const hint = profileKindHint(profile);
  if (hint) return finish(hint, hasWeb);

  return { kind: 'unknown', kind_label: KIND_LABEL.unknown, has_web: hasWeb, web_label: hasWeb ? '含 Web 端' : '无 Web 端' };
}

/**
 * 结合文件特征与 CodeGraph 索引识别 Web 端（导入解压/克隆并建图后调用）。
 */
export function resolveProjectKindWithCodegraph(codeDir: string): ProjectKindInfo {
  const base = detectProjectKind(codeDir);
  if (base.has_web === true) return base;
  const cg = codegraphSignalsWeb(codeDir);
  if (cg === true) {
    return {
      ...base,
      kind: base.kind === 'unknown' ? 'web' : base.kind,
      kind_label: base.kind === 'unknown' ? KIND_LABEL.web : base.kind_label,
      has_web: true,
      web_label: '含 Web 端',
    };
  }
  return base;
}

/** 项目是否含 Web 端（仅 has_web===true 为真；未识别 workspace 视为无）。 */
export function projectHasWeb(codeDir: string | null | undefined): boolean {
  if (!codeDir || !fs.existsSync(codeDir)) return false;
  return resolveProjectKindWithCodegraph(codeDir).has_web === true;
}

/** 优先使用入库的 has_web，否则回退到工作区 + CodeGraph 识别。 */
export function projectHasWebForProject(project: {
  workspace_path?: string | null;
  has_web?: number | null;
}): boolean {
  if (project.has_web === 1) return true;
  if (project.has_web === 0) return false;
  return projectHasWeb(project.workspace_path);
}

export function attachProjectKind<T extends { workspace_path?: string | null; has_web?: number | null }>(
  project: T
): T & { project_kind: ProjectKindInfo } {
  if (project.has_web === 1) {
    return {
      ...project,
      project_kind: {
        kind: 'web',
        kind_label: KIND_LABEL.web,
        has_web: true,
        web_label: '含 Web 端',
      },
    };
  }
  if (project.has_web === 0) {
    return {
      ...project,
      project_kind: {
        kind: 'unknown',
        kind_label: KIND_LABEL.unknown,
        has_web: false,
        web_label: '无 Web 端',
      },
    };
  }
  const ws = project.workspace_path;
  if (!ws || !fs.existsSync(ws)) {
    return {
      ...project,
      project_kind: {
        kind: 'unknown',
        kind_label: KIND_LABEL.unknown,
        has_web: null,
        web_label: 'Web 端待识别',
      },
    };
  }
  return { ...project, project_kind: resolveProjectKindWithCodegraph(ws) };
}
