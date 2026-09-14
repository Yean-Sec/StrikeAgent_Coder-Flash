import fs from 'fs';
import path from 'path';
import { workspaceFor } from './ingest';

/** 代码层审计/验证产物归档根目录：按项目 id 隔离，不与上传源码混放。 */
export const AUDIT_RESULTS_DIR = path.join(__dirname, '..', 'data', 'results');

export const RESULT_DIRS = [
  'JSON',
  'MD漏洞复现',
  'MD-Vulnerability',
  'POC',
  '_pipeline',
  '_ai_dedup',
  '_code_verify',
  '_regrade',
  '_mcp',
  '_remote_verify',
];

const RESULT_FILES = [
  'directly_exploitable_vulns.json',
  'final_output_ready.json',
  'Audit_Summary.md',
];

const ROOT_REPORT_RE = /^(全局漏洞总结报告|Audit_Summary)/i;

export interface HarvestMeta {
  projectId: string;
  projectName?: string | null;
  archiveName?: string | null;
  workspacePath: string;
}

export interface HarvestResult {
  dest: string;
  copied: string[];
}

export function resultsDirFor(projectId: string): string {
  return path.join(AUDIT_RESULTS_DIR, projectId);
}

function resolvedPath(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

function jsonArtifactCount(root: string): number {
  const dir = path.join(root, 'JSON');
  if (!fs.existsSync(dir)) return 0;
  try {
    return fs.readdirSync(dir).filter((f) => f.toLowerCase().endsWith('.json')).length;
  } catch {
    return 0;
  }
}

function copyPath(src: string, dest: string): boolean {
  if (!fs.existsSync(src)) return false;
  try {
    if (fs.existsSync(dest) && resolvedPath(src) === resolvedPath(dest)) return true;
  } catch {
    /* 继续实拷 */
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.cpSync(src, dest, { recursive: true, force: true });
  return true;
}

export function ensureArtifactRoot(projectId: string): string {
  const dest = resultsDirFor(projectId);
  fs.mkdirSync(dest, { recursive: true });
  return dest;
}

function linkDirIntoWorkspace(wsItem: string, destItem: string): void {
  fs.mkdirSync(destItem, { recursive: true });
  if (fs.existsSync(wsItem)) {
    let st: fs.Stats;
    try {
      st = fs.lstatSync(wsItem);
    } catch {
      return;
    }
    if (st.isSymbolicLink()) {
      try {
        if (resolvedPath(wsItem) === resolvedPath(destItem)) return;
      } catch {
        /* 坏链：替换 */
      }
      fs.rmSync(wsItem, { force: true });
    } else if (st.isDirectory()) {
      fs.cpSync(wsItem, destItem, { recursive: true, force: true });
      fs.rmSync(wsItem, { recursive: true, force: true });
    } else {
      fs.rmSync(wsItem, { force: true });
    }
  }
  try {
    fs.symlinkSync(destItem, wsItem, process.platform === 'win32' ? 'junction' : 'dir');
  } catch {
    /* 无法建链时后端仍以 dest 为准，结束时 harvest 再合并 */
  }
}

/**
 * 确保 data/results/<id>/ 存在，并把工作区里的产物目录链过去。
 * Pi cwd 仍是源码树（codegraph），相对路径 JSON/ 实际写到产物目录。
 */
export function ensureArtifactLayout(projectId: string, workspacePath: string): string {
  const dest = ensureArtifactRoot(projectId);
  if (!workspacePath || !fs.existsSync(workspacePath)) return dest;
  try {
    if (resolvedPath(workspacePath) === resolvedPath(dest)) return dest;
  } catch {
    /* ignore */
  }
  for (const name of RESULT_DIRS) {
    linkDirIntoWorkspace(path.join(workspacePath, name), path.join(dest, name));
  }
  return dest;
}

/**
 * 读/写审计产物的根目录。优先 data/results/<id>（与源码分离）；
 * 审计进行中若结果目录尚空、工作区仍有 JSON，则回退工作区。
 */
export function artifactRootFor(projectId: string, workspacePath?: string | null): string {
  ensureArtifactRoot(projectId);
  return resolveArtifactRoot(projectId, workspacePath) || resultsDirFor(projectId);
}

function writeManifest(dest: string, meta: HarvestMeta, copied: string[]): void {
  const manifest = {
    project_id: meta.projectId,
    project_name: meta.projectName || '',
    archive_name: meta.archiveName || '',
    harvested_at: Date.now(),
    copied,
  };
  fs.writeFileSync(path.join(dest, 'MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
}

/**
 * 把工作区里的扫描 JSON / 漏洞报告拷到 data/results/<projectId>/，
 * 并写 MANIFEST.json（含项目标识）。不碰源码目录。
 */
export function harvestAuditResults(meta: HarvestMeta): HarvestResult {
  const dest = resultsDirFor(meta.projectId);
  fs.mkdirSync(dest, { recursive: true });
  const copied: string[] = [];
  const srcRoot = meta.workspacePath;

  for (const name of RESULT_DIRS) {
    if (copyPath(path.join(srcRoot, name), path.join(dest, name))) copied.push(name);
  }
  for (const name of RESULT_FILES) {
    if (copyPath(path.join(srcRoot, name), path.join(dest, name))) copied.push(name);
  }
  try {
    for (const name of fs.readdirSync(srcRoot)) {
      if (!ROOT_REPORT_RE.test(name)) continue;
      if (!name.toLowerCase().endsWith('.md') && !name.toLowerCase().endsWith('.json')) continue;
      if (copyPath(path.join(srcRoot, name), path.join(dest, name))) copied.push(name);
    }
  } catch {
    /* ignore */
  }

  writeManifest(dest, meta, copied);
  return { dest, copied };
}

/**
 * 读审计产物时的根目录：优先已归档的 data/results/<id>；
 * 源码工作区里若还有更多 JSON（链失败时的相对写入）则回退工作区。
 */
export function resolveArtifactRoot(projectId: string, workspacePath?: string | null): string | null {
  const ws =
    workspacePath && fs.existsSync(workspacePath) ? workspacePath : workspaceFor(projectId);
  const results = resultsDirFor(projectId);
  const wsLive = ws && fs.existsSync(ws) ? ws : '';
  const wsCount = wsLive ? jsonArtifactCount(wsLive) : 0;
  const resCount = jsonArtifactCount(results);
  const resultsReady =
    fs.existsSync(path.join(results, 'MANIFEST.json')) || resCount > 0 || fs.existsSync(path.join(results, 'JSON'));

  if (resCount > 0 && resCount >= wsCount) return results;
  if (wsCount > 0) return wsLive;
  if (resultsReady) return results;
  if (wsLive) return wsLive;
  if (fs.existsSync(results)) return results;
  return null;
}

export function hasHarvestedResults(projectId: string): boolean {
  const dir = resultsDirFor(projectId);
  return fs.existsSync(path.join(dir, 'MANIFEST.json')) || jsonArtifactCount(dir) > 0;
}
