import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

/**
 * 明确“非真实 Web 端”的目录段：字典/爆破库/payload/webshell/POC/样本集合等。
 * 这类仓库（如 SecLists）会内含 index.php / templates/ / web.xml 等样本文件，
 * 但它们只是被审计的“素材”，并非可部署的 Web 应用根，必须从 Web 判定中剔除。
 */
const EXCLUDE_SEGMENTS = new Set([
  'payload',
  'payloads',
  'web-shell',
  'web-shells',
  'webshell',
  'webshells',
  'shell',
  'shells',
  'wordlist',
  'wordlists',
  'seclists',
  'fuzz',
  'fuzzing',
  'fuzzdb',
  'exploit',
  'exploits',
  'poc',
  'pocs',
  'cve',
  'cves',
  'cheatsheet',
  'cheatsheets',
  'cheat-sheet',
  'cheat-sheets',
  'nuclei-templates',
  'node_modules',
  'vendor',
  'third_party',
  'third-party',
]);

/** 路径任一目录段落在排除名单里 → 视为样本/素材，不作为 Web 信号。 */
function isExcludedPath(p: string): boolean {
  const segs = p.toLowerCase().split(/[\\/]+/).filter(Boolean);
  for (const s of segs) {
    if (EXCLUDE_SEGMENTS.has(s)) return true;
  }
  return false;
}

/** 通过 CodeGraph 索引判断项目是否含 Web 端；无索引返回 null。 */
export function codegraphSignalsWeb(codeDir: string): boolean | null {
  const dbPath = path.join(codeDir, '.codegraph', 'codegraph.db');
  if (!fs.existsSync(dbPath)) return null;
  try {
    const db = new Database(dbPath, { readonly: true, fileMustExist: true });
    try {
      // 拉取候选 Web 信号文件（含样本），再在 JS 里按目录段排除素材，避免
      // SecLists 这类字典/payload 仓库里的嵌套 index.php / templates / web.xml 误判为 Web。
      const candidates = db
        .prepare(
          `SELECT path FROM files WHERE
            lower(path) GLOB '*/index.php' OR
            lower(path) GLOB 'index.php' OR
            lower(path) GLOB '*/public/*' OR
            lower(path) GLOB '*/static/*' OR
            lower(path) GLOB '*/templates/*' OR
            lower(path) GLOB '*/views/*' OR
            lower(path) GLOB '*/pages/*' OR
            lower(path) GLOB '*/routes/*' OR
            lower(path) GLOB '*/controllers/*' OR
            lower(path) GLOB '*/middleware/*' OR
            lower(path) LIKE '%docker-compose%' OR
            lower(path) LIKE '%nginx.conf%' OR
            lower(path) LIKE '%httpd.conf%' OR
            lower(path) LIKE '%web.config%' OR
            lower(path) LIKE '%web.xml%' OR
            lower(path) LIKE '%.blade.php' OR
            lower(path) LIKE '%.cshtml' OR
            lower(path) LIKE '%application.yml' OR
            lower(path) LIKE '%application.yaml' OR
            lower(path) LIKE '%next.config%' OR
            lower(path) LIKE '%nuxt.config%' OR
            lower(path) LIKE '%vite.config%' OR
            lower(path) LIKE '%angular.json'
          LIMIT 1000`
        )
        .all() as { path: string }[];
      const fileHit = candidates.some((r) => r.path && !isExcludedPath(r.path));
      if (fileHit) return true;

      // 代码级信号：路由/控制器装饰器、app/router/server 等入口符号（真实代码结构，样本仓库通常无）。
      const nodeHit = db
        .prepare(
          `SELECT 1 FROM nodes WHERE
            lower(decorators) LIKE '%route%' OR
            lower(decorators) LIKE '%mapping%' OR
            lower(decorators) LIKE '%controller%' OR
            lower(decorators) LIKE '%httpget%' OR
            lower(decorators) LIKE '%httppost%' OR
            lower(decorators) LIKE '%app.get%' OR
            lower(decorators) LIKE '%app.post%' OR
            lower(qualified_name) LIKE '%controller%' OR
            lower(qualified_name) LIKE '%.routes.%' OR
            lower(name) IN ('app', 'router', 'application', 'server')
          LIMIT 1`
        )
        .get();
      if (nodeHit) return true;

      return false;
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}
