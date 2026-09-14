import path from 'path';
import fs from 'fs';
import AdmZip from 'adm-zip';
import { simpleGit } from 'simple-git';
import { getSetting } from './settings';
import { parseOwnerRepo } from './githubMeta';

export const WORKSPACE_DIR = path.join(__dirname, '..', 'workspace');
export const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');

for (const d of [WORKSPACE_DIR, UPLOAD_DIR]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

export function workspaceFor(projectId: string): string {
  return path.join(WORKSPACE_DIR, projectId);
}

async function extractZip(archivePath: string, destDir: string): Promise<void> {
  const zip = new AdmZip(archivePath);
  const root = path.resolve(destDir);
  let written = 0;

  // `extractAllTo` 直接把条目名交给 Windows 文件系统；一个带 `:*?` 等非法字符
  // 的条目就会使整个压缩包报 `ADM-ZIP: Invalid filename`，连其余源码也无法恢复。
  // 审计只需要可安全落盘的源码：逐条解压、跳过 Windows 非法名和 Zip Slip 条目。
  for (const entry of zip.getEntries()) {
    const name = entry.entryName.replace(/\\/g, '/');
    if (!name || name.endsWith('/')) continue;
    if (process.platform === 'win32' && isWindowsInvalidGitPath(name)) continue;

    const out = path.resolve(destDir, ...name.split('/'));
    if (out === root || !out.startsWith(root + path.sep)) continue;
    try {
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, entry.getData());
      written++;
    } catch {
      // 单个不可写/损坏条目不应放弃可恢复的其余源码；最后用 written 兜底。
    }
  }
  if (written === 0) {
    throw new Error('压缩包没有可安全解压的源码文件（可能已损坏或仅含 Windows 非法路径）');
  }
}

/** 递归清除只读属性：Windows 下 git 的 .git/objects pack 文件常为只读，直接删除会抛 EPERM。 */
function clearReadOnly(target: string): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(target);
  } catch {
    return;
  }
  try {
    fs.chmodSync(target, st.isDirectory() ? 0o777 : 0o666);
  } catch {
    /* ignore */
  }
  if (st.isDirectory()) {
    let entries: string[] = [];
    try {
      entries = fs.readdirSync(target);
    } catch {
      return;
    }
    for (const e of entries) clearReadOnly(path.join(target, e));
  }
}

/**
 * 稳健删除目录：重新克隆/解压前清空旧内容时使用。Windows 上目录刚被杀掉的进程持有过句柄
 * （被杀进程收尾未完成、防病毒软件正在扫描新写入的文件、上一次被中止的 git clone 遗留的
 * 只读 pack 对象等）会导致一次性 `fs.rmSync` 抛 EPERM——这些锁通常几秒内自行释放，
 * 因此做“清只读属性 + 多次退避重试”而不是让调用方直接因瞬时占用而整体失败。
 */
async function removeDirRobust(dest: string, attempts = 4): Promise<boolean> {
  for (let i = 0; i < attempts; i++) {
    if (!fs.existsSync(dest)) return true;
    try {
      await fs.promises.rm(dest, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      if (!fs.existsSync(dest)) return true;
    } catch {
      /* 继续下面的只读清除重试 */
    }
    try {
      clearReadOnly(dest);
      await fs.promises.rm(dest, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      if (!fs.existsSync(dest)) return true;
    } catch {
      /* 仍失败，进入下一轮退避 */
    }
    if (i < attempts - 1) await new Promise((r) => setTimeout(r, 1200 * (i + 1)));
  }
  return !fs.existsSync(dest);
}

/** Windows 禁止的文件名字符（含控制字符），会导致 git checkout 报 invalid path。 */
function isWindowsInvalidGitPath(p: string): boolean {
  return /[<>:"|?*\x00-\x1f]/.test(p) || /(?:^|\/)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(p);
}

function isCheckoutInvalidPathError(msg: string): boolean {
  return /invalid path|Clone succeeded, but checkout failed/i.test(msg);
}

/**
 * Windows 上 git 无法检出含 ? * <> 等字符的路径（连 archive/read-tree 也会失败）。
 * 回退：下载 GitHub zipball，用 AdmZip 解压并跳过非法文件名。
 */
async function materializeGithubZipball(url: string, destDir: string, ref?: string): Promise<void> {
  const or = parseOwnerRepo(url);
  if (!or) {
    throw new Error('仓库含 Windows 非法路径且无法解析为 GitHub 地址，无法 zipball 回退');
  }
  const token = getSetting('github_token').trim();
  const refPart = (ref || '').trim() || 'HEAD';
  const api = `https://api.github.com/repos/${or.owner}/${or.repo}/zipball/${encodeURIComponent(refPart)}`;
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'code-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(api, { headers, redirect: 'follow' });
  if (!res.ok) {
    throw new Error(`GitHub zipball 下载失败（HTTP ${res.status}），无法绕过 Windows 非法路径`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  const tmpZip = path.join(UPLOAD_DIR, `zipball-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.zip`);
  fs.writeFileSync(tmpZip, buf);
  try {
    if (fs.existsSync(destDir) && !(await removeDirRobust(destDir))) {
      throw new Error(`工作区目录仍被占用，无法清理后写入 zipball：${destDir}`);
    }
    fs.mkdirSync(destDir, { recursive: true });
    const zip = new AdmZip(tmpZip);
    const root = path.resolve(destDir);
    let wrote = 0;
    for (const entry of zip.getEntries()) {
      let name = entry.entryName.replace(/\\/g, '/');
      if (!name || name.endsWith('/')) continue;
      // GitHub zipball 顶层为 owner-repo-sha/
      const parts = name.split('/');
      if (parts.length < 2) continue;
      name = parts.slice(1).join('/');
      if (!name || isWindowsInvalidGitPath(name)) continue;
      const out = path.resolve(destDir, ...name.split('/'));
      if (out !== root && !out.startsWith(root + path.sep)) continue;
      fs.mkdirSync(path.dirname(out), { recursive: true });
      if (!entry.isDirectory) {
        fs.writeFileSync(out, entry.getData());
        wrote += 1;
      }
    }
    if (wrote === 0) throw new Error('GitHub zipball 解压后无有效文件');
  } finally {
    try {
      fs.unlinkSync(tmpZip);
    } catch {
      /* ignore */
    }
  }
}

async function cloneRepo(url: string, destDir: string, ref?: string): Promise<void> {
  const token = getSetting('github_token').trim();
  let cloneUrl = url.trim();
  if (token && /^https:\/\/github\.com\//i.test(cloneUrl)) {
    cloneUrl = cloneUrl.replace(
      /^https:\/\/github\.com\//i,
      `https://${token}@github.com/`
    );
  }
  fs.mkdirSync(path.dirname(destDir), { recursive: true });
  const options = [
    '--depth',
    '1',
    // 指定 tag/分支克隆（多版本批量审计：按版本 tag 检出对应源码）
    ...(ref ? ['--branch', ref] : []),
    // core.longpaths=true 解决 Windows MAX_PATH(260) 限制导致的 checkout 失败（超长文件名）
    '--config',
    'core.longpaths=true',
    // 高并发/弱网下提升容忍度，缓解大仓库克隆超时（curl 28）
    '--config',
    'http.postBuffer=524288000',
    '--config',
    'http.lowSpeedLimit=1000',
    '--config',
    'http.lowSpeedTime=120',
    // 强制 HTTP/1.1，规避部分代理在 HTTP/2 多路复用下大仓库传输被重置（Connection was reset）
    '--config',
    'http.version=HTTP/1.1',
  ];

  const maxAttempts = 3;
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      if (fs.existsSync(destDir) && !(await removeDirRobust(destDir))) {
        throw new Error(
          `工作区目录仍被占用，无法清理后重新克隆：${destDir}（可能是上一次被中止的 clone 或索引进程未完全释放，请稍后重试）`
        );
      }
      await simpleGit().clone(cloneUrl, destDir, options);
      return;
    } catch (err) {
      lastErr = err;
      const msg = String((err as any)?.message || err);
      // Windows：仓库含 ? * <> 等非法文件名时，git clone/checkout 必失败 → GitHub zipball 回退
      if (process.platform === 'win32' && isCheckoutInvalidPathError(msg) && parseOwnerRepo(url)) {
        if (fs.existsSync(destDir) && !(await removeDirRobust(destDir))) {
          throw new Error(`工作区目录仍被占用，无法清理后走 zipball 回退：${destDir}`);
        }
        await materializeGithubZipball(url, destDir, ref);
        return;
      }
      // 仅对网络类瞬时错误重试
      const retriable = /Recv failure|RPC failed|curl 28|timed out|Connection|reset|early EOF|unable to access/i.test(
        msg
      );
      if (!retriable || attempt === maxAttempts) break;
      await new Promise((r) => setTimeout(r, attempt * 5000));
    }
  }
  const lastMsg = String((lastErr as any)?.message || lastErr || '');
  // git clone 连不上 GitHub 时改走 zipball，避免整次审计直接失败
  if (
    parseOwnerRepo(url) &&
    /Recv failure|RPC failed|curl 28|timed out|Connection|reset|early EOF|unable to access|Could not connect/i.test(
      lastMsg
    )
  ) {
    try {
      if (fs.existsSync(destDir) && !(await removeDirRobust(destDir))) {
        throw lastErr;
      }
      await materializeGithubZipball(url, destDir, ref);
      return;
    } catch {
      /* zipball 也失败则仍抛原始 clone 错误 */
    }
  }
  throw lastErr;
}

/**
 * 将项目源准备到工作区目录。返回最终用于审计的代码目录。
 */
export async function prepareSource(
  projectId: string,
  sourceType: 'zip' | 'github',
  sourceRef: string,
  gitRef?: string | null
): Promise<string> {
  const dest = workspaceFor(projectId);

  // 工作区已存在有效内容时直接复用：暂停后恢复 / 后端重启 / 离线场景无需重复下载或解压
  if (hasUsableContent(dest)) {
    // 保留上传原包直到项目被显式清理：工作区可能被手工/磁盘清理，续跑需要可重建源码。
    return collapseSingleRoot(dest);
  }

  if (fs.existsSync(dest) && !(await removeDirRobust(dest))) {
    // Windows 上目录刚被杀掉的进程持有过句柄、防病毒软件正在扫描、上次中止的
    // clone/解压留下只读对象等，都会让删除瞬时受阻；removeDirRobust 已做退避重试，
    // 仍失败说明确有其它进程长期占用（如残留的 docker 挂载/codegraph 索引进程），
    // 给出可定位的中文报错而不是让裸 EPERM 直接把审计打成失败。
    throw new Error(
      `工作区目录仍被占用，无法清理后重新准备源码：${dest}（请确认没有残留的 Docker 容器/索引进程占用该目录，稍后重试）`
    );
  }

  if (sourceType === 'github') {
    await cloneRepo(sourceRef, dest, gitRef || undefined);
  } else {
    if (!fs.existsSync(sourceRef)) {
      throw new Error(
        `上传源码包已丢失，无法恢复工作区：${sourceRef}。请重新上传原始 ${sourceType.toUpperCase()} 包后再继续审计`
      );
    }
    fs.mkdirSync(dest, { recursive: true });
    await extractZip(sourceRef, dest);
    // 原包随项目保存，供覆盖补跑、重启后恢复及工作区丢失后的源码重建使用。
    // 项目删除时由 purgeProject 调用 removeUploadArchive 统一回收。
  }

  return collapseSingleRoot(dest);
}

/** 工作区是否已有可用源码（排除 .git / __MACOSX 后仍有内容）。 */
function hasUsableContent(dir: string): boolean {
  try {
    if (!fs.existsSync(dir)) return false;
    const entries = fs
      .readdirSync(dir)
      .filter((n) => n !== '.git' && !n.startsWith('__MACOSX'));
    return entries.length > 0;
  } catch {
    return false;
  }
}

/** 若解压/克隆后只有单个顶层目录，返回该目录以便审计聚焦真实代码根。 */
function collapseSingleRoot(dir: string): string {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const visible = entries.filter((e) => !e.name.startsWith('__MACOSX'));
    if (visible.length === 1 && visible[0].isDirectory()) {
      return path.join(dir, visible[0].name);
    }
  } catch {
    /* ignore */
  }
  return dir;
}

/**
 * 删除上传的压缩包（仅 zip/rar 来源）。github 来源的 sourceRef 是 URL，直接跳过。
 * 安全限制：只删除位于 uploads 目录内的文件，避免误删工作区或其它路径。
 */
export function removeUploadArchive(sourceType: string, sourceRef: string): void {
  if (sourceType !== 'zip') return;
  if (!sourceRef) return;
  try {
    const resolved = path.resolve(sourceRef);
    const uploadRoot = path.resolve(UPLOAD_DIR) + path.sep;
    if (!resolved.startsWith(uploadRoot)) return;
    if (fs.existsSync(resolved)) fs.rmSync(resolved, { force: true });
  } catch {
    /* 压缩包清理失败不影响主流程 */
  }
}

/** 异步尝试删除一次（含只读清除兜底）。返回是否已删除干净。 */
async function tryRemoveOnceAsync(dest: string): Promise<boolean> {
  try {
    await fs.promises.rm(dest, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    // 清除只读属性后再删一次（git 只读对象文件导致的 EPERM）
    try {
      clearReadOnly(dest);
      await fs.promises.rm(dest, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      /* 仍失败：交由后台退避重试 */
    }
  }
  return !fs.existsSync(dest);
}

/** 同步尝试删除一次（开机清扫等仍可用）。返回是否已删除干净。 */
function tryRemoveOnce(dest: string): boolean {
  try {
    fs.rmSync(dest, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    try {
      clearReadOnly(dest);
      fs.rmSync(dest, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      /* 仍失败 */
    }
  }
  return !fs.existsSync(dest);
}

// 后台退避重试中的路径（避免对同一目录重复排队）
const pendingWorkspaceDeletions = new Set<string>();
// 退避节奏（毫秒）：覆盖到约 3 分钟，足够让被杀进程 / git / docker / codegraph 句柄释放
const DELETE_RETRY_BACKOFF = [2000, 5000, 15000, 45000, 90000];
// 工作区删除并发上限：批量 purge 时并行删盘，又不把磁盘打满
const WORKSPACE_DELETE_CONCURRENCY = 4;
const workspaceDeleteQueue: string[] = [];
let workspaceDeleteActive = 0;

/**
 * 后台退避重试删除：Windows 上删除瞬间目录常被句柄占用（stopForDelete 杀进程是异步的、
 * .git 只读对象、codegraph 索引等），异步删一次可能 EPERM。此处在稍后句柄释放时再删，
 * 最终仍失败的由开机 sweepOrphanWorkspaces 兜底。
 */
function scheduleDeletionRetry(dest: string): void {
  if (pendingWorkspaceDeletions.has(dest)) return;
  pendingWorkspaceDeletions.add(dest);
  let attempt = 0;
  const run = (): void => {
    if (!fs.existsSync(dest)) {
      pendingWorkspaceDeletions.delete(dest);
      return;
    }
    void tryRemoveOnceAsync(dest).then((ok) => {
      if (ok) {
        pendingWorkspaceDeletions.delete(dest);
        console.log(`[cleanup] 延迟重试后已删除残留工作区: ${path.basename(dest)}`);
        return;
      }
      if (attempt >= DELETE_RETRY_BACKOFF.length) {
        pendingWorkspaceDeletions.delete(dest);
        console.warn(
          `[cleanup] 工作区多次重试仍无法删除，将在下次启动清扫: ${path.basename(dest)}`
        );
        return;
      }
      const delay = DELETE_RETRY_BACKOFF[attempt++];
      const t = setTimeout(run, delay);
      if (typeof t.unref === 'function') t.unref();
    });
  };
  const t = setTimeout(run, DELETE_RETRY_BACKOFF[attempt++]);
  if (typeof t.unref === 'function') t.unref();
}

function pumpWorkspaceDeleteQueue(): void {
  while (workspaceDeleteActive < WORKSPACE_DELETE_CONCURRENCY && workspaceDeleteQueue.length > 0) {
    const dest = workspaceDeleteQueue.shift()!;
    workspaceDeleteActive += 1;
    void (async () => {
      try {
        if (!fs.existsSync(dest)) return;
        const ok = await tryRemoveOnceAsync(dest);
        if (!ok) scheduleDeletionRetry(dest);
      } catch (e: any) {
        console.warn(`[cleanup] 工作区删除异常 ${path.basename(dest)}: ${e?.message || e}`);
        scheduleDeletionRetry(dest);
      } finally {
        workspaceDeleteActive -= 1;
        pumpWorkspaceDeleteQueue();
      }
    })();
  }
}

/**
 * 排队异步删除工作区（限并发）。调用方立即返回，不阻塞 HTTP / 批量 purge。
 * 失败转入退避重试，最终由开机清扫兜底。
 */
export function removeWorkspace(projectId: string): void {
  const dest = workspaceFor(projectId);
  if (!fs.existsSync(dest)) return;
  if (pendingWorkspaceDeletions.has(dest) || workspaceDeleteQueue.includes(dest)) return;
  workspaceDeleteQueue.push(dest);
  pumpWorkspaceDeleteQueue();
}

/** 同步删除（仅开机清扫等需要立刻完成的路径使用）。 */
export function removeWorkspaceSync(projectId: string): void {
  const dest = workspaceFor(projectId);
  if (!fs.existsSync(dest)) return;
  if (!tryRemoveOnce(dest)) scheduleDeletionRetry(dest);
}

/**
 * 异步删除并等待结果：与同步版语义一致（删完再返回是否成功、失败转退避重试），
 * 但用 fs.promises.rm 让出事件循环，避免大目录（含 node_modules / codegraph 索引）
 * 的递归删除把主线程冻结数十秒——常驻清道夫应走此路径。
 */
export async function removeWorkspaceAwait(projectId: string): Promise<boolean> {
  const dest = workspaceFor(projectId);
  if (!fs.existsSync(dest)) return true;
  const ok = await tryRemoveOnceAsync(dest);
  if (!ok) scheduleDeletionRetry(dest);
  return ok;
}
