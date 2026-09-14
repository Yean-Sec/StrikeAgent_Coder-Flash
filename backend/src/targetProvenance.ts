import crypto from 'crypto';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { readTargetEnv, type RuntimeVersionProof, type TargetEnvContract } from './projectShape';
import type { Project } from './types';

export const PROVENANCE_LABELS = {
  provenance: 'com.code.build-provenance',
  sourceVersion: 'com.code.source-version',
  sourceCommit: 'com.code.source-commit',
  sourceFingerprint: 'com.code.source-fingerprint',
} as const;

/** 历史靶场产物（旧 OCI / compose 命名）仍可读。 */
export const LEGACY_PROVENANCE_LABELS = {
  provenance: 'com.strikeagent.build-provenance',
  sourceVersion: 'com.strikeagent.source-version',
  sourceCommit: 'com.strikeagent.source-commit',
  sourceFingerprint: 'com.strikeagent.source-fingerprint',
} as const;

const COMPOSE_CANDIDATES = [
  'docker-compose.code.yml',
  'docker-compose.code.yaml',
  'docker-compose.strikeagent.yml',
  'docker-compose.strikeagent.yaml',
  'docker-compose.yml',
  'docker-compose.yaml',
  'compose.yml',
  'compose.yaml',
] as const;

function labelValue(labels: Record<string, string>, key: keyof typeof PROVENANCE_LABELS): string | undefined {
  return labels[PROVENANCE_LABELS[key]] ?? labels[LEGACY_PROVENANCE_LABELS[key]];
}

function curlBin(): string {
  return process.platform === 'win32' ? 'curl.exe' : 'curl';
}

export interface ProvenanceEvidence {
  dbVersion: string | null;
  gitRef: string | null;
  workspaceHead: string | null;
  workspaceTags: string[];
  trackedChanges: string[];
  sourceFingerprint: string | null;
  contract: TargetEnvContract | null;
  composeFile: string | null;
  runningContainers: string[];
  matchingImageId: string | null;
  runtimeProofObserved: string | null;
}

export interface ProvenanceValidation {
  ok: boolean;
  errors: string[];
  evidence: ProvenanceEvidence;
}

export interface ProvenanceCommandRunner {
  run(command: string, args: string[], options?: { cwd?: string; timeout?: number }): string;
}

const defaultRunner: ProvenanceCommandRunner = {
  run(command, args, options) {
    return execFileSync(command, args, {
      cwd: options?.cwd,
      timeout: options?.timeout ?? 15_000,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
    }).trim();
  },
};

export function normalizeVersionToken(raw: string | null | undefined): string {
  return String(raw || '')
    .trim()
    .replace(/^v(?=\d)/i, '')
    .replace(/\s+/g, '')
    .toLowerCase();
}

export function versionsMatch(
  leftRaw: string | null | undefined,
  rightRaw: string | null | undefined
): boolean {
  const left = normalizeVersionToken(leftRaw);
  const right = normalizeVersionToken(rightRaw);
  if (!left || !right) return false;
  if (left === right) return true;
  const hex = /^[0-9a-f]+$/;
  if (!hex.test(left) || !hex.test(right)) return false;
  const short = left.length <= right.length ? left : right;
  const long = left.length <= right.length ? right : left;
  return short.length >= 7 && long.startsWith(short);
}

function safeRun(
  runner: ProvenanceCommandRunner,
  command: string,
  args: string[],
  options?: { cwd?: string; timeout?: number }
): string | null {
  try {
    return runner.run(command, args, options);
  } catch {
    return null;
  }
}

function resolveWithinWorkspace(codeDir: string, relative: string): string | null {
  const root = path.resolve(codeDir);
  const candidate = path.resolve(root, relative);
  if (candidate === root || candidate.startsWith(root + path.sep)) return candidate;
  return null;
}

function composePath(codeDir: string, contract: TargetEnvContract): string | null {
  const declared = String(contract.compose_file || '').trim();
  if (declared) {
    const resolved = resolveWithinWorkspace(codeDir, declared);
    return resolved && fs.existsSync(resolved) ? resolved : null;
  }
  for (const name of COMPOSE_CANDIDATES) {
    const candidate = path.join(codeDir, name);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function sourceFingerprint(codeDir: string): string {
  const hash = crypto.createHash('sha256');
  const excludedDirNames = new Set([
    '.git',
    'node_modules',
    'vendor',
    'target',
    'build',
    'dist',
    '.gradle',
    '_remote_verify',
    '_harness_verify',
    '_mini_verify',
    'docker-target',
    // 运行期易变：Laravel/Hyperf 日志、视图缓存、pid、代理类等。
    'storage',
    'runtime',
    '.codegraph',
    '_ai_dedup',
    '_mcp',
    '_pipeline',
    '_regrade',
    '_code_verify',
    '_strikeagent',
    'JSON',
    // 验证/复现阶段产物：POC 代码、漏洞复现 MD、批次总结报告目录。
    // 这些目录在建靶时不存在，验证过程中才生成，绝不能计入源码指纹，
    // 否则每次验证都会改变指纹并导致后续组合链验证被 provenance 校验拦截。
    'POC',
    'MD漏洞复现',
    'MD-Vulnerability',
  ]);
  const excludedRelDirs = new Set(['bootstrap/cache']);
  const excludedFiles = new Set([
    'TARGET_ENV.json',
    'docker-compose.yml',
    'docker-compose.yaml',
    'docker-compose.code.yml',
    'docker-compose.code.yaml',
    'docker-compose.strikeagent.yml',
    'docker-compose.strikeagent.yaml',
    'Dockerfile',
    'Dockerfile.strikeagent',
    'Dockerfile.strikeagent-api',
    'Dockerfile.strikeagent-ws',
    '.dockerignore',
    '.env',
    'Audit_Summary.md',
    'directly_exploitable_vulns.json',
    'final_output_ready.json',
    '_summary.txt',
    '_summary_text.txt',
    '_so_summary.txt',
  ]);
  // 顶层「全局漏洞总结报告*.md」「_xxx」等验证阶段生成的临时/汇总文件，
  // 后缀批次号不固定，用前缀匹配兜底，避免每批次产生新文件名又漂移指纹。
  const isGeneratedSummaryFile = (name: string, rel: string): boolean => {
    if (rel.includes('/')) return false; // 仅限工作区顶层
    return name.startsWith('全局漏洞总结报告');
  };
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(codeDir, full).replace(/\\/g, '/');
      if (entry.isDirectory()) {
        if (
          excludedDirNames.has(entry.name) ||
          excludedRelDirs.has(rel) ||
          rel === 'bootstrap/cache' ||
          rel.endsWith('/bootstrap/cache')
        ) {
          continue;
        }
        walk(full);
      } else if (entry.isFile()) {
        if (excludedFiles.has(entry.name) || excludedFiles.has(path.basename(rel))) continue;
        if (isGeneratedSummaryFile(entry.name, rel)) continue;
        files.push(full);
      }
    }
  };
  walk(codeDir);
  files.sort((a, b) => a.localeCompare(b));
  for (const file of files) {
    hash.update(path.relative(codeDir, file).replace(/\\/g, '/'));
    hash.update('\0');
    hash.update(fs.readFileSync(file));
    hash.update('\0');
  }
  return hash.digest('hex');
}

function runtimeProofText(
  proof: RuntimeVersionProof,
  codeDir: string,
  contract: TargetEnvContract,
  composeContainers: string[],
  runner: ProvenanceCommandRunner
): string | null {
  if (!proof.target || !proof.contains) return null;
  if (proof.type === 'http') {
    let base: URL;
    try {
      base = new URL(String(contract.url || ''));
    } catch {
      return null;
    }
    // 候选证明地址（均须同源）：先用声明的 proof.target；再回退到声明的 login_url。
    // 许多应用把裸 "/" 302 到形如 "http:///index.php" 的空 host 畸形地址，curl -L 跟进后
    // 直接 "Empty reply from server"，而真正带版本横幅的入口（login_url）稳定可达。
    const candidates: string[] = [];
    const pushSameOrigin = (raw: string | null | undefined) => {
      const value = String(raw || '').trim();
      if (!value) return;
      try {
        const u = new URL(value);
        const normalized = u.toString();
        if (u.origin === base.origin && !candidates.includes(normalized)) candidates.push(normalized);
      } catch {
        /* 非法 URL 直接忽略 */
      }
    };
    pushSameOrigin(proof.target);
    pushSameOrigin(contract.login_url);
    if (!candidates.length) return null;
    let firstBody: string | null = null;
    let sawBody = false;
    for (const url of candidates) {
      const body = safeRun(runner, curlBin(), ['-fsSL', '--max-time', '10', url], {
        timeout: 15_000,
      });
      if (!sawBody) {
        firstBody = body;
        sawBody = true;
      }
      if (body && body.includes(proof.contains)) return body;
    }
    // 没有任何候选命中横幅：返回首个响应（可能为 null），让调用方如实报告失败。
    return firstBody;
  }
  if (proof.type === 'container-log') {
    if (!composeContainers.includes(proof.target)) return null;
    return safeRun(runner, 'docker', ['logs', '--tail', '500', proof.target], {
      timeout: 15_000,
    });
  }
  if (proof.type === 'file') {
    const file = resolveWithinWorkspace(codeDir, proof.target);
    if (!file) return null;
    try {
      return fs.readFileSync(file, 'utf8');
    } catch {
      return null;
    }
  }
  return null;
}

function composeProjectName(projectId: string): string {
  return projectId.toLowerCase().replace(/[^a-z0-9_-]/g, '');
}

/**
 * Collect and validate DB → workspace → image → runtime provenance.
 *
 * This is deliberately fail-closed. Missing evidence is an error; no result is
 * inferred from a reachable URL alone.
 */
export interface ProvenanceOptions {
  /**
   * 是否要求靶机【当前正在运行】（运行中容器 + 镜像标签 + 实时运行时证明）。
   * 默认 true（运行期校验，最严格）。入队门控应传 false：靶机在验证任务启动后才由
   * ensureTargetUp 拉起，入队阶段靶机通常已被 stopTargetEnvironment 停掉，此时只校验
   * 「审计源码 == 将要构建/运行的源码」这类静态凭据；实时运行时证明留待 isTargetFullyReady
   * 在 ensureTargetUp 之后强制。
   */
  requireLiveTarget?: boolean;
}

export function validateTargetProvenance(
  project: Pick<Project, 'id' | 'source_version' | 'git_ref'>,
  codeDir: string,
  runner: ProvenanceCommandRunner = defaultRunner,
  opts: ProvenanceOptions = {}
): ProvenanceValidation {
  const requireLiveTarget = opts.requireLiveTarget !== false;
  const errors: string[] = [];
  const contract = readTargetEnv(codeDir);
  const evidence: ProvenanceEvidence = {
    dbVersion: project.source_version,
    gitRef: project.git_ref,
    workspaceHead: null,
    workspaceTags: [],
    trackedChanges: [],
    sourceFingerprint: null,
    contract,
    composeFile: null,
    runningContainers: [],
    matchingImageId: null,
    runtimeProofObserved: null,
  };

  if (!contract) {
    errors.push('缺少或无法解析 TARGET_ENV.json');
    return { ok: false, errors, evidence };
  }
  const mode = String(contract.mode || '').toLowerCase();
  if (mode !== 'external' && mode !== 'harness' && mode !== 'mini') {
    errors.push('TARGET_ENV.mode 必须为 external、harness 或 mini');
  }
  if (contract.build_provenance !== 'local-source') {
    errors.push('build_provenance 必须为 local-source');
  }
  const dbVersion = String(project.source_version || project.git_ref || '').trim();
  const contractVersion = String(contract.source_version || '').trim();
  const runtimeVersion = String(contract.runtime_version || contract.version || '').trim();
  if (!dbVersion) errors.push('projects.source_version/git_ref 缺失');
  if (!contractVersion) errors.push('TARGET_ENV.source_version 缺失');
  if (!runtimeVersion) errors.push('TARGET_ENV.runtime_version/version 缺失');
  if (dbVersion && contractVersion && !versionsMatch(dbVersion, contractVersion)) {
    errors.push(`DB 审计版本 ${dbVersion} 与 TARGET_ENV.source_version ${contractVersion} 不一致`);
  }
  if (contractVersion && runtimeVersion && !versionsMatch(contractVersion, runtimeVersion)) {
    errors.push(`源码版本 ${contractVersion} 与运行版本 ${runtimeVersion} 不一致`);
  }

  const head = safeRun(runner, 'git', ['rev-parse', 'HEAD'], { cwd: codeDir });
  if (head) {
    evidence.workspaceHead = head.toLowerCase();
    const tags = safeRun(runner, 'git', ['tag', '--points-at', 'HEAD'], { cwd: codeDir });
    evidence.workspaceTags = tags ? tags.split(/\r?\n/).map((tag) => tag.trim()).filter(Boolean) : [];
    const status = safeRun(
      runner,
      'git',
      ['status', '--porcelain', '--untracked-files=no'],
      { cwd: codeDir }
    );
    if (status == null) {
      errors.push('无法读取 Git 工作区状态');
    } else if (status) {
      evidence.trackedChanges = status.split(/\r?\n/).filter(Boolean);
      errors.push('工作区存在已跟踪源码修改，拒绝将修改后源码冒充审计版本');
    }
    const expectedRef = String(project.git_ref || project.source_version || '').trim();
    const refMatches =
      versionsMatch(expectedRef, head) ||
      evidence.workspaceTags.some((tag) => versionsMatch(expectedRef, tag));
    if (!expectedRef || !refMatches) {
      errors.push(`DB 审计版本/引用 ${expectedRef || '(空)'} 无法解析到工作区 HEAD ${head}`);
    }
    const declaredCommit = String(contract.source_commit || '').trim();
    if (!declaredCommit || declaredCommit.toLowerCase() !== head.toLowerCase()) {
      errors.push('TARGET_ENV.source_commit 与工作区 HEAD 不一致');
    }
  } else {
    let fingerprint: string | null = null;
    try {
      fingerprint = sourceFingerprint(codeDir);
      evidence.sourceFingerprint = fingerprint;
    } catch {
      errors.push('非 Git 源码指纹计算失败');
    }
    const declared = String(contract.source_fingerprint || '').trim().toLowerCase();
    if (!fingerprint || !declared || declared !== fingerprint) {
      errors.push('TARGET_ENV.source_fingerprint 与当前非 Git 源码不一致');
    }
  }

  const proof = contract.runtime_version_proof;
  if (!proof || typeof proof !== 'object') {
    errors.push('缺少 runtime_version_proof');
  }

  if (mode === 'external') {
    const expectedProject = composeProjectName(project.id);
    if (String(contract.compose_project || '') !== expectedProject) {
      errors.push(`compose_project 必须为 ${expectedProject}`);
    }
    const compose = composePath(codeDir, contract);
    evidence.composeFile = compose;
    if (!compose) {
      errors.push('缺少有效的本地 Compose 文件');
    } else {
      try {
        const text = fs.readFileSync(compose, 'utf8');
        if (!/(?:^|\n)\s*build\s*:/m.test(text)) {
          errors.push('Compose 未声明本地 build:');
        }
      } catch {
        errors.push('Compose 文件无法读取');
      }
    }

    // 运行中容器 + 镜像来源标签属于「靶机当前在跑」的实时凭据：入队阶段靶机通常已停，
    // 这些检查留待 isTargetFullyReady 在 ensureTargetUp 之后强制，避免把「靶机没开着」
    // 误判成「无可用审计结果」而永久阻断重跑。
    if (requireLiveTarget) {
      const containerIds = safeRun(
        runner,
        'docker',
        ['ps', '-q', '--filter', `label=com.docker.compose.project=${expectedProject}`]
      );
      const ids = containerIds ? containerIds.split(/\s+/).filter(Boolean) : [];
      if (!ids.length) errors.push('未找到该 Compose 项目的运行中容器');
      for (const id of ids) {
        const inspected = safeRun(
          runner,
          'docker',
          ['inspect', '--format', '{{json .}}', id]
        );
        if (!inspected) continue;
        try {
          const container = JSON.parse(inspected);
          const name = String(container.Name || '').replace(/^\//, '') || id;
          evidence.runningContainers.push(name);
          const imageId = String(container.Image || '');
          const imageJson = safeRun(
            runner,
            'docker',
            ['image', 'inspect', '--format', '{{json .Config.Labels}}', imageId]
          );
          const labels = imageJson ? (JSON.parse(imageJson) as Record<string, string> | null) : null;
          if (!labels) continue;
          const commitOk = head
            ? labelValue(labels, 'sourceCommit')?.toLowerCase() === head.toLowerCase()
            : labelValue(labels, 'sourceFingerprint')?.toLowerCase() ===
              evidence.sourceFingerprint?.toLowerCase();
          if (
            labelValue(labels, 'provenance') === 'local-source' &&
            versionsMatch(labelValue(labels, 'sourceVersion'), contractVersion) &&
            commitOk
          ) {
            evidence.matchingImageId = imageId;
          }
        } catch {
          /* malformed inspect output becomes a missing image proof */
        }
      }
      if (!evidence.matchingImageId) {
        errors.push('运行应用镜像缺少与工作区一致的 Code 来源标签');
      }
    }
  }

  if (proof && typeof proof === 'object') {
    // 实时抓取运行时证明（HTTP 横幅 / 容器日志 / 文件）同样只在要求靶机在跑时执行。
    if (requireLiveTarget) {
      const observed = runtimeProofText(
        proof,
        codeDir,
        contract,
        evidence.runningContainers,
        runner
      );
      evidence.runtimeProofObserved = observed;
      if (observed == null || !observed.includes(proof.contains)) {
        errors.push('运行时版本证明不可读取或未包含预期内容');
      }
    }
    if (
      proof.contains &&
      runtimeVersion &&
      !proof.contains.includes(runtimeVersion) &&
      !proof.contains.includes(String(contract.source_commit || ''))
    ) {
      errors.push('runtime_version_proof.contains 未绑定运行版本或源码提交');
    }
  }

  return { ok: errors.length === 0, errors, evidence };
}

export function formatProvenanceErrors(result: ProvenanceValidation): string {
  return result.errors.join('；');
}
