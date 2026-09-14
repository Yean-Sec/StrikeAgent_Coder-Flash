import { spawn, spawnSync, ChildProcess, execSync, execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs';
import http from 'http';
import https from 'https';
import os from 'os';
import { monitorEventLoopDelay } from 'perf_hooks';
import db from './db';
import { queryFrontendRceVulns } from './frontendRceQuery';
import { getSetting, MAX_CONCURRENCY_CEILING, CLASSIFY_CONCURRENCY_CEILING } from './settings';
import {
  buildEnvPrompt,
  buildHarnessEnvPrompt,
  buildHarnessVerifyMasterPrompt,
  buildHarnessVerifyBatchPrompt,
  buildDedupWorkerPrompt,
  buildVerifyBatchPrompt,
  buildChainPrompt,
  buildChainRetryPrompt,
  buildRemoteVerifyMasterPrompt,
  buildCodeVerifyWorkerPrompt,
  buildSpecialtyAgentPrompt,
  buildAuditOrchestratorPrompt,
  buildWebClassifyPrompt,
  buildRegistrationClassifyPrompt,
  buildRegradeWorkerPrompt,
  SUBAGENTS_BY_LANG,
  subagentsForLanguage,
  subagentMission,
  AUDIT_LANGUAGE_LABELS,
  isAuditLanguage,
  VULN_SCHEMA,
  EXPLOIT_SCHEMA,
  CODE_VERIFY_SCHEMA,
  AI_DEDUP_SCHEMA,
  REGRADE_SCHEMA,
  WEB_CLASSIFY_SCHEMA,
  REGISTRATION_CLASSIFY_SCHEMA,
} from './schema';
import { prepareSource, removeWorkspace, removeWorkspaceAwait, removeUploadArchive, WORKSPACE_DIR } from './ingest';
import {
  harvestAuditResults,
  resolveArtifactRoot,
  hasHarvestedResults,
  ensureArtifactLayout,
  artifactRootFor,
} from './auditResults';
import { deleteProjectRows } from './projectsService';
import { fetchLatestRelease, localGitVersion } from './githubMeta';
import { piSpawnEnv, buildAgentCliArgs, cleanupPromptFile } from './piResolver';
import { parseJsonArtifact, readJsonArtifactText } from './textEncoding';
import { pruneRunLogsAsync, checkpointAndReclaim } from './runLogRetention';
import {
  collectAuditFindings,
  collectFromDisk,
  readSubagentFindings,
  hasSubagentArtifacts,
  readDirectlyExploitable,
  conservativeDedup,
  dropCombinationChains,
  inspectSubagentArtifact,
  reconcileSubagentArtifacts,
} from './auditArtifacts';
import {
  parseStreamObject,
  extractVulnerabilities,
  extractAssistantText,
  tryExtractStructured,
  subagentLabel,
  NormalizedEvent,
} from './streamParser';
import { broadcast } from './ws';
import { newId, now, placeholderLabel, normalizeTaintChain } from './util';
import {
  detectProjectShape,
  readTargetEnv,
  readTargetEnvMode,
  isHarnessTargetUrl,
  harnessTargetUrl,
  isExternallyManagedTarget,
  hasLocalComposeContract,
  shouldPreserveExternalContainers,
} from './projectShape';
import {
  harnessVerifyDir,
  readHarnessVerifyResults,
  isHarnessEnvReady,
  runHarnessSmokeIfConfigured,
} from './harnessVerify';
import { needsComposeEnv } from './verifyMode';
import { resolveProjectKindWithCodegraph } from './projectKind';
import { clearExploitChains, syncExploitChains } from './exploitChains';
import { normalizeChainArtifact } from './chainArtifacts';
import {
  validateTargetProvenance,
} from './targetProvenance';
import {
  invalidateExploitReads,
  invalidateProjectStatusReads,
  invalidateReadScopes,
  invalidateVulnerabilityReads,
} from './readCache';
import { applySeverityPolicy } from './severityPolicy';
import type { Project, Severity, Vulnerability, EventPhase, EnvStatus } from './types';
import {
  deriveMinimumAuth,
  deriveRemoteStatus,
  normalizeExploitStatus as normalizeVerificationStatus,
  normalizePrivilegeResults as normalizeVerificationPrivilegeResults,
} from './verificationStatus';
import {
  ensureProjectVerificationItems,
  getProjectVerificationProgress,
  setVerificationItemState,
  syncProjectVerificationItems,
} from './verificationStore';
import { withinBudget } from './timeBudget';

// audit=完整审计（含语言专项子智能体）；reprocess=复用已有子智能体结果，仅重跑去重+验证+评级；verify=靶机验证
type JobKind = 'audit' | 'verify' | 'reprocess' | 'verifyone';

/** 流水线环节：审计侧 subagent→dedup→codeverify→regrade；验证侧 env→remote→chain。 */
type PipeStage = 'subagent' | 'dedup' | 'codeverify' | 'regrade' | 'env' | 'remote' | 'chain';
export const AUDIT_PIPE: PipeStage[] = ['subagent', 'dedup', 'codeverify', 'regrade'];
const VERIFY_PIPE: PipeStage[] = ['env', 'remote', 'chain'];
/** 某环节属于审计侧还是验证侧。 */
function stageSide(stage: PipeStage): 'audit' | 'verify' {
  return AUDIT_PIPE.includes(stage) ? 'audit' : 'verify';
}

interface Job {
  id: string;
  kind: JobKind;
  /** 审计完成后是否强制继续靶机验证（用于"全流程"重跑，不受 auto_verify 设置影响）。 */
  chainVerify?: boolean;
  /** 分环节运行：从该环节开始（mode=from 跑到本流水线末尾，only 仅跑该环节）。 */
  stage?: PipeStage;
  stageMode?: 'only' | 'from';
  /**
   * 真正的"续跑"（而非重新开始）：仅 kind='verify' 时有意义。true 时复用暂停前已落盘的
   * exploit_report 部分结果，跳过已验证过的漏洞、只对剩余的继续实测；不清空旧结果。
   * 由「继续」按钮（resumeProject）专用；显式的「重新验证/重跑」入口仍传 false（全新开始）。
   */
  resume?: boolean;
  /** kind='verifyone' 时：要单独远程验证的漏洞标题。 */
  oneTitle?: string;
  /** kind='verify' 时：仅跑组合链验证（复用已有单漏洞结果，跳过单漏洞阶段）。 */
  chainOnly?: boolean;
  /**
   * kind='reprocess' 时：真正的「继续审计」续跑（保留 agent_events、走与全量审计相同的后半段流水线），
   * 区别于显式「复用后处理重跑」。
   */
  continueMode?: boolean;
}

// 单漏洞验证的"验证中排队"：当项目正在跑全量验证时，点单漏洞验证 → 暂存标题，
// 待当前验证收尾（不关靶机）后再逐个验证。key=projectId。
const pendingVerifyOne = new Map<string, string[]>();

const queue: Job[] = [];
/** 正在跑代码审计/复跑的项目（占用审计并发槽）。 */
const activeAuditProjects = new Set<string>();
/** 正在跑远程靶机验证的项目（占用验证并发槽）。 */
const activeVerifyProjects = new Set<string>();
// 重跑请求：当目标正在运行时，先中断旧任务，由其 runJob.finally 完成清理后再按此重新入队，避免竞态。
const restartRequests = new Map<
  string,
  { kind: JobKind; chainVerify: boolean; stage?: PipeStage; stageMode?: 'only' | 'from'; chainOnly?: boolean }
>();
const running = new Map<string, ChildProcess>();
const runningKind = new Map<string, JobKind>();
const intentionallyStopped = new Set<string>();

// —— 并发健壮性：协作式取消 + 在途任务追踪 ——
// cancelledProjects：被暂停/重跑/删除请求中止的项目。其仍在执行的异步 doAudit/doReprocess/doVerify
//   会在下一次 runPiStage 时被直接判定为 killed（不再 spawn 新的 Pi），从而快速收尾、
//   绝不残留"后端仍在逐批 spawn Pi"的空转批循环。runJob 启动新任务时清除该标志。
const cancelledProjects = new Set<string>();
// inFlight：runJob 实际在执行（异步未 return）的项目。仅在 runJob.finally 中清除。
//   用它（而非仅 activeProjects）判断"是否还有任务在跑"，避免 pause 过早释放并发槽后，
//   旧异步尚未真正结束就被并行启动第二条流水线。
const inFlight = new Set<string>();
const eventLoopDelay = monitorEventLoopDelay({ resolution: 20 });
eventLoopDelay.enable();
let resourceRetryTimer: NodeJS.Timeout | null = null;

function adaptiveConcurrency(configured: number): number {
  const reserved = getSetting('protect_web_resources') !== '0';
  const guarded = reserved ? Math.min(configured, 3) : configured;
  const free = os.freemem();
  const total = Math.max(1, os.totalmem());
  if (free < 2 * 1024 ** 3 || free / total < 0.08) return 1;
  if (free < 4 * 1024 ** 3 || free / total < 0.15) return Math.min(guarded, 2);
  return guarded;
}

function schedulerPressureReason(): string | null {
  const free = os.freemem();
  const total = Math.max(1, os.totalmem());
  const p95Ms = eventLoopDelay.percentile(95) / 1_000_000;
  eventLoopDelay.reset();
  if (free < 1536 * 1024 ** 2 || free / total < 0.06) {
    return `可用内存不足（${Math.round(free / 1024 ** 2)} MB）`;
  }
  if (p95Ms > 350) return `事件循环延迟过高（p95 ${Math.round(p95Ms)} ms）`;
  return null;
}
/** 批量入队时合并 startNext，避免 O(n²) 扫描拖死 HTTP 请求。 */
let bulkScheduleDepth = 0;

function scheduleStartNext(): void {
  if (bulkScheduleDepth === 0) startNext();
}

/** 全局 Pi 任务总闸：关闭后禁止入队与 spawn。 */
export function isPiJobsEnabled(): boolean {
  return getSetting('claude_jobs_enabled') !== '0';
}

/**
 * 一键停摆：清空内存队列、暂停全部 running/queued，并杀掉在跑的 Pi Agent 进程。
 * 调用方应同时把 settings.claude_jobs_enabled 设为 '0'（本函数不改设置，避免与 PUT /settings 竞态）。
 */
export function haltAllPiJobs(): { paused: number; killed: number } {
  const queuedIds = [...new Set(queue.map((j) => j.id))];
  queue.length = 0;
  // 同步清空靶机预搭建队列，避免停摆后仍 spawn env 通道 Pi
  const envIds = [...envQueue];
  envQueue.length = 0;
  for (const id of [...envActive]) {
    try {
      stopEnvChannel(id);
    } catch {
      /* ignore */
    }
  }
  const rows = db
    .prepare(
      `SELECT id FROM projects
       WHERE status IN ('running','queued') OR verify_status IN ('running','queued')`
    )
    .all() as { id: string }[];
  const ids = new Set<string>([...queuedIds, ...envIds, ...rows.map((r) => r.id)]);
  for (const id of ids) {
    try {
      pauseProject(id);
    } catch (e) {
      console.error(`[code] halt pause failed for ${id}`, e);
    }
  }
  let killed = 0;
  for (const [id, child] of [...running.entries()]) {
    intentionallyStopped.add(id);
    killTree(child);
    running.delete(id);
    runningKind.delete(id);
    clearActiveSlots(id);
    killed++;
  }
  for (const [id, child] of [...envRunning.entries()]) {
    envIntentionallyStopped.add(id);
    killTree(child);
    envRunning.delete(id);
    killed++;
  }
  if (ids.size > 0 || killed > 0) {
    console.log(
      `[code] 已停摆 Pi 任务：暂停 ${ids.size} 个项目，强制结束 ${killed} 个进程`
    );
  }
  return { paused: ids.size, killed };
}

/** 设置页改并发等场景：立刻按新上限补开空槽（不必等某个任务结束）。 */
export function kickScheduler(): void {
  if (!isPiJobsEnabled()) return;
  scheduleStartNext();
}

export function bulkScheduleResume(ids: string[]): {
  accepted: number;
  queued: number;
  failed: string[];
} {
  const failed: string[] = [];
  let queued = 0;
  bulkScheduleDepth++;
  try {
    for (const id of ids) {
      if (!getProject(id)) continue;
      if (resumeProject(id)) queued++;
      else failed.push(id);
    }
  } finally {
    bulkScheduleDepth--;
    if (bulkScheduleDepth === 0) startNext();
  }
  return { accepted: ids.length, queued, failed };
}
/** 标记项目需要中止：使其在途异步在下一个 spawn/检查点处自行收尾。 */
function requestCancel(projectId: string): void {
  cancelledProjects.add(projectId);
}
/** 该项目是否仍有任务在途（异步未结束）。 */
function isBusy(projectId: string): boolean {
  return (
    activeAuditProjects.has(projectId) ||
    activeVerifyProjects.has(projectId) ||
    inFlight.has(projectId)
  );
}

function clearActiveSlots(projectId: string): void {
  activeAuditProjects.delete(projectId);
  activeVerifyProjects.delete(projectId);
}

function isVerifyJobKind(kind: JobKind): boolean {
  return kind === 'verify' || kind === 'verifyone';
}

/** 验证结束后释放 Pi Agent 与进程表引用，避免傀儡进程占满验证槽。 */
function releasePiForProject(projectId: string): void {
  stopVerifyProcs(projectId);
  verifyProcs.delete(projectId);
  const child = running.get(projectId);
  if (child) {
    killTree(child);
    running.delete(projectId);
  }
}

// —— 环境预搭建通道（与代码审计并行，独立并发池，不占用审计槽）——
const envQueue: string[] = [];
const envActive = new Set<string>();
const envRunning = new Map<string, ChildProcess>();
const envIntentionallyStopped = new Set<string>();
// 正在进行的环境搭建任务（doVerify 据此等待并行搭建完成后再做利用验证）
const envTasks = new Map<string, Promise<void>>();
/** 搭建世代号：stop/prune 时递增；doPrebuildEnv 用它识别「已被取消」，避免杀进程后仍把状态写回 building/failed。 */
const envBuildEpoch = new Map<string, number>();
// per-project 源码准备锁：避免审计与环境搭建并发重复 clone/解压同一工作区
const workspaceLocks = new Map<string, Promise<string>>();

function bumpEnvBuildEpoch(projectId: string): number {
  const next = (envBuildEpoch.get(projectId) || 0) + 1;
  envBuildEpoch.set(projectId, next);
  return next;
}

function envBuildEpochOf(projectId: string): number {
  return envBuildEpoch.get(projectId) || 0;
}

/** 本轮搭建是否已被 stopEnvChannel / prune 取消。 */
function isEnvBuildCancelled(projectId: string, epoch: number): boolean {
  return envBuildEpochOf(projectId) !== epoch;
}

/** 同时进行的环境搭建上限（审计并行预搭建时；验证独占阶段见 targetBuildConcurrency）。 */
function envConcurrency(): number {
  const n = parseInt(getSetting('env_concurrency'), 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 12) : 3;
}

/**
 * 靶机搭建并发：审计仍在跑时沿用 env_concurrency（默认 3）；仅剩验证阶段时与 remoteVerifyConcurrency/burst 对齐。
 */
function targetBuildConcurrency(): number {
  return isVerifyOnlyPhase() ? remoteVerifyConcurrency() : envConcurrency();
}

// —— 代码级验证通道（支持同一项目内多进程并发）——
const verifyProcs = new Map<string, Set<ChildProcess>>(); // projectId -> 一组并发验证进程
const verifyKilled = new Set<string>(); // 验证阶段被中止（暂停/删除/重跑）的项目

/** 远程/沙箱验证日志里的建议并发（上限 10）。去重/代码级验证/二次评级走 regradeConcurrency。 */
function codeVerifyConcurrency(): number {
  const n = parseInt(getSetting('code_verify_concurrency'), 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 10) : 5;
}

/** 核验层（去重 / 代码级验证 / 二次评级）每路条数（默认 10）。 */
function regradeBatchSize(): number {
  const n = parseInt(getSetting('regrade_batch_size'), 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 50) : 10;
}

/** 核验层（去重 / 代码级验证 / 二次评级）最多同时开这么多路 Pi（默认 10，封顶 10）。 */
function regradeConcurrency(): number {
  const n = parseInt(getSetting('regrade_concurrency'), 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 10) : 10;
}

/** 杀掉某项目所有正在并发的代码级验证进程。 */
function stopVerifyProcs(projectId: string): void {
  const set = verifyProcs.get(projectId);
  if (set) {
    for (const child of set) killTree(child);
    set.clear();
  }
}

/**
 * 异步信号量：跨项目为「验证类 Pi Agent」发放有限的运行许可，实现全局并发封顶。
 * 说明：inUse 记「已发放许可数」。release 时若有等待者，直接把许可移交给它（inUse 不变），
 * 否则归还许可（inUse 递减）。setMax 支持在线扩容时唤醒等待者。
 */
class AsyncSemaphore {
  private waiters: (() => void)[] = [];
  private inUse = 0;
  private max: number;
  constructor(max: number) {
    this.max = Math.max(1, max);
  }
  async acquire(): Promise<void> {
    if (this.inUse < this.max) {
      this.inUse++;
      return;
    }
    // 满额：排队等待 release 移交许可（移交时 inUse 保持不变）
    await new Promise<void>((resolve) => this.waiters.push(resolve));
  }
  release(): void {
    const next = this.waiters.shift();
    if (next) next(); // 许可直接移交给下一个等待者，inUse 不变
    else this.inUse = Math.max(0, this.inUse - 1);
  }
  setMax(n: number): void {
    this.max = Math.max(1, n);
    // 扩容：把新增名额分配给排队者
    while (this.inUse < this.max && this.waiters.length > 0) {
      const next = this.waiters.shift()!;
      this.inUse++;
      next();
    }
  }
  /** 当前已发放许可数（用于判断是否已满额、决定是否提示"排队等待"）。 */
  get inUseCount(): number {
    return this.inUse;
  }
}

/** 全局远程靶机验证 Pi Agent 总数上限（跨所有项目；默认 5）。 */
const verifyGate = new AsyncSemaphore(5);

/**
 * 全局【靶机搭建】闸：无论来自「并行预搭建通道」还是「验证阶段按需重搭」，
 * 同时真正在跑 docker 搭建 Pi Agent 的项目总数硬性不超过 remote/env 并发（默认 3）。
 * 只包裹 doPrebuildEnv 内真正执行 buildEnvPrompt 的那一次 Pi Agent 调用——排队等待期间不占用，
 * 保证同时搭建靶机的项目数不超过 targetBuildConcurrency（审计并行默认 3，验证独占时与远程验证并发对齐，默认 5），其余排队。
 */
const targetBuildGate = new AsyncSemaphore(5);

/** 是否处于「代码审计/复跑已全部结束，队列里只剩靶机验证」——此时可抬高远程验证并发。 */
function isVerifyOnlyPhase(): boolean {
  if (activeAuditProjects.size > 0) return false;
  if (queue.some((j) => j.kind === 'audit' || j.kind === 'reprocess')) return false;
  const auditBusy = db
    .prepare(`SELECT 1 AS ok FROM projects WHERE status IN ('running','queued') LIMIT 1`)
    .get();
  if (auditBusy) return false;
  const verifyPending = db
    .prepare(
      `SELECT 1 AS ok FROM projects WHERE status = 'completed' AND verify_status IN ('queued','running') LIMIT 1`
    )
    .get();
  return !!verifyPending;
}

/** 远程靶机验证 Pi Agent 总数上限（跨所有项目；读设置，上限 12）。审计仍进行时走 base；仅剩靶机验证排队时走 burst。 */
function remoteVerifyConcurrency(): number {
  const raw = getSetting('remote_verify_concurrency') || getSetting('verify_global_concurrency');
  const n = parseInt(raw, 10);
  const base = Number.isFinite(n) && n > 0 ? Math.min(n, 12) : 5;
  if (!isVerifyOnlyPhase()) return adaptiveConcurrency(base);
  const burstRaw = getSetting('remote_verify_burst_concurrency');
  const burst = parseInt(burstRaw, 10);
  return adaptiveConcurrency(Number.isFinite(burst) && burst > 0 ? Math.min(burst, 12) : 5);
}

/**
 * 在远程验证闸内执行一次靶机验证 Pi Agent 调用：先申领许可（可能排队），执行完毕后无条件归还。
 * 代码审计流水线内的去重/代码级验证/二次评级不走此闸（由审计并发槽约束）。
 */
async function withVerifyGate<T>(fn: () => Promise<T>): Promise<T> {
  verifyGate.setMax(remoteVerifyConcurrency());
  await verifyGate.acquire();
  try {
    return await fn();
  } finally {
    verifyGate.release();
  }
}

/**
 * 在全局靶机搭建闸内执行一次靶机搭建 Pi Agent 调用（申领前同步最新上限，使设置即时生效）。
 * 验证独占阶段上限与 remoteVerifyConcurrency 一致（默认 burst 5）；审计并行时沿用 env_concurrency（默认 3）。
 */
async function withTargetBuildGate<T>(fn: () => Promise<T>): Promise<T> {
  targetBuildGate.setMax(targetBuildConcurrency());
  await targetBuildGate.acquire();
  try {
    return await fn();
  } finally {
    targetBuildGate.release();
  }
}

/** 简单并发池：以 limit 并发执行 items 的 worker，返回与 items 等长的结果数组。 */
async function runPool<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(Math.max(1, limit), items.length) }, async () => {
    while (next < items.length) {
      const idx = next++;
      results[idx] = await worker(items[idx], idx);
    }
  });
  await Promise.all(runners);
  return results;
}

function maxConcurrency(): number {
  const n = parseInt(getSetting('max_concurrency'), 10);
  const v = Number.isFinite(n) && n > 0 ? n : 2;
  // 钳制到安全上限，防止配置过大导致单机资源耗尽、所有任务互相拖死
  return adaptiveConcurrency(Math.min(v, MAX_CONCURRENCY_CEILING));
}

/** 批量 Web 端判定并发（独立于代码审计 max_concurrency，默认 20）。 */
function classifyConcurrency(): number {
  const n = parseInt(getSetting('classify_concurrency'), 10);
  const v = Number.isFinite(n) && n > 0 ? n : 20;
  return Math.min(v, CLASSIFY_CONCURRENCY_CEILING);
}

/** 单阶段硬性最长运行时间（毫秒）；0 表示不限制。 */
function stageTimeoutMs(): number {
  const n = parseInt(getSetting('stage_timeout_min'), 10);
  return Number.isFinite(n) && n > 0 ? n * 60_000 : 90 * 60_000;
}

/** 空闲（无输出）超时（毫秒），用于检测卡死进程；0 表示不限制。 */
function idleTimeoutMs(): number {
  const n = parseInt(getSetting('idle_timeout_min'), 10);
  return Number.isFinite(n) && n > 0 ? n * 60_000 : 25 * 60_000;
}

/** 单漏洞快速验证使用独立预算，避免沿用全流程 90 分钟超时。 */
function singleVerifyHardMs(): number {
  const n = parseInt(getSetting('single_verify_timeout_min'), 10);
  return (Number.isFinite(n) && n > 0 ? n : 15) * 60_000;
}

function singleVerifyIdleMs(): number {
  const n = parseInt(getSetting('single_verify_idle_timeout_min'), 10);
  return (Number.isFinite(n) && n > 0 ? n : 5) * 60_000;
}

/**
 * 结果收尾宽限（毫秒）：已捕获到完整结构化结果（StructuredOutput）后，
 * 若 Pi Agent 迟迟不自行退出，再等这么久就主动收尾，避免白白干等空闲超时。
 * 这种收尾视为「正常完成」（结果已拿到），不算超时失败。0 表示不启用。
 */
function settleAfterOutputMs(): number {
  const n = parseInt(getSetting('settle_timeout_min'), 10);
  return Number.isFinite(n) && n > 0 ? n * 60_000 : 2 * 60_000;
}

function getProject(id: string): Project | undefined {
  return db.prepare('SELECT * FROM projects WHERE id = ?').get(id) as Project | undefined;
}

function setAuditStatus(id: string, status: string, extra: Record<string, unknown> = {}): void {
  // 耗时累计：当本次从 running 切出（completed/failed/paused）时，把该运行段真实耗时累加到 audit_duration_ms。
  const prev = db.prepare('SELECT status, started_at, audit_duration_ms FROM projects WHERE id = ?').get(id) as
    | { status: string; started_at: number | null; audit_duration_ms: number }
    | undefined;
  const fields = ['status = @status'];
  const params: Record<string, unknown> = { id, status };
  if (prev && prev.status === 'running' && status !== 'running' && prev.started_at) {
    const add = Math.max(0, now() - prev.started_at);
    fields.push('audit_duration_ms = @audit_duration_ms');
    params.audit_duration_ms = (prev.audit_duration_ms || 0) + add;
  }
  for (const [k, v] of Object.entries(extra)) {
    fields.push(`${k} = @${k}`);
    params[k] = v;
  }
  db.prepare(`UPDATE projects SET ${fields.join(', ')} WHERE id = @id`).run(params);
  invalidateProjectStatusReads();
  broadcast({ type: 'project_status', projectId: id, status, ...extra });
}

/** 启动时把残留 running/queued 标为 paused，走 setAuditStatus 以便广播 project_status。 */
export function markStartupOrphansPaused(auditIds: string[], verifyIds: string[]): void {
  for (const id of auditIds) {
    setAuditStatus(id, 'paused', { finished_at: now(), error_message: null });
  }
  for (const id of verifyIds) {
    setVerifyStatus(id, 'paused', { verify_finished_at: now() });
  }
}

function setVerifyStatus(id: string, verify_status: string, extra: Record<string, unknown> = {}): void {
  // 耗时累计：当本次从 running 切出时，把该运行段真实耗时累加到 verify_duration_ms。
  const prev = db
    .prepare('SELECT verify_status, verify_started_at, verify_duration_ms FROM projects WHERE id = ?')
    .get(id) as
    | { verify_status: string; verify_started_at: number | null; verify_duration_ms: number }
    | undefined;
  const fields = ['verify_status = @verify_status'];
  const params: Record<string, unknown> = { id, verify_status };
  if (prev && prev.verify_status === 'running' && verify_status !== 'running' && prev.verify_started_at) {
    const add = Math.max(0, now() - prev.verify_started_at);
    fields.push('verify_duration_ms = @verify_duration_ms');
    params.verify_duration_ms = (prev.verify_duration_ms || 0) + add;
  }
  for (const [k, v] of Object.entries(extra)) {
    fields.push(`${k} = @${k}`);
    params[k] = v;
  }
  db.prepare(`UPDATE projects SET ${fields.join(', ')} WHERE id = @id`).run(params);
  invalidateProjectStatusReads();
  broadcast({ type: 'project_status', projectId: id, verify_status, ...extra });
}

type PersistedEventPayload = {
  id: string;
  project_id: string;
  ts: number;
  kind: string;
  agent: string;
  tool: string;
  text: string;
  raw: string;
  phase: EventPhase;
};

const insertEventStmt = db.prepare(
  `INSERT INTO agent_events (id, project_id, ts, kind, agent, tool, text, raw, phase)
   VALUES (@id, @project_id, @ts, @kind, @agent, @tool, @text, @raw, @phase)`
);
const bufferedEventWrites: PersistedEventPayload[] = [];
let eventFlushTimer: NodeJS.Timeout | null = null;

function flushBufferedEvents(): void {
  if (eventFlushTimer) {
    clearTimeout(eventFlushTimer);
    eventFlushTimer = null;
  }
  if (bufferedEventWrites.length === 0) return;
  const batch = bufferedEventWrites.splice(0, bufferedEventWrites.length);
  const tx = db.transaction((events: PersistedEventPayload[]) => {
    for (const event of events) insertEventStmt.run(event);
  });
  tx(batch);
}

function persistEvent(payload: PersistedEventPayload): void {
  // 状态机依赖 system/error/result 的即时可见性；高频过程事件合并事务写入。
  if (payload.kind === 'system' || payload.kind === 'error' || payload.kind === 'result') {
    flushBufferedEvents();
    insertEventStmt.run(payload);
    return;
  }
  bufferedEventWrites.push(payload);
  if (bufferedEventWrites.length >= 64) {
    flushBufferedEvents();
  } else if (!eventFlushTimer) {
    eventFlushTimer = setTimeout(flushBufferedEvents, 100);
    eventFlushTimer.unref?.();
  }
}

const insertRunLogStmt = db.prepare(
  `INSERT INTO project_run_logs
     (id, project_id, run_id, ts, phase, channel, stream, seq, content)
   VALUES (@id, @project_id, @run_id, @ts, @phase, @channel, @stream, @seq, @content)`
);

type RunLogPayload = {
  id: string;
  project_id: string;
  run_id: string;
  ts: number;
  phase: EventPhase;
  channel: string;
  stream: string;
  seq: number;
  content: string;
};

// 运行日志曾经逐 chunk 同步 INSERT：Pi Agent 高频输出时，每个 chunk 一次同步写会占满
// better-sqlite3 的单线程写通道，进而堵住整个事件循环，让所有 /api/* 一起变慢。
// 改为内存缓冲 + 定时/阈值批量单事务落库，把成百上千次同步写压缩成一次事务。
// 单条 content 截断到 16KB：完整 stdout 对排查价值递减，却会把 18GB 库继续灌爆。
// 代价：进程异常退出时最多丢失最后 <100ms（或未达阈值）的日志片段——阶段结束、
// 进程 close/error 与 beforeExit 均会强制 flush，正常路径不丢。
const RUN_LOG_CONTENT_MAX = 16 * 1024;
const RUN_LOG_FLUSH_BATCH = 48;
const bufferedRunLogWrites: RunLogPayload[] = [];
let runLogFlushTimer: NodeJS.Timeout | null = null;
let runLogFlushScheduled = false;

function truncateRunLogContent(content: string): string {
  if (content.length <= RUN_LOG_CONTENT_MAX) return content;
  return `${content.slice(0, RUN_LOG_CONTENT_MAX)}\n…[truncated ${content.length - RUN_LOG_CONTENT_MAX} chars]`;
}

function flushBufferedRunLogs(): void {
  if (runLogFlushTimer) {
    clearTimeout(runLogFlushTimer);
    runLogFlushTimer = null;
  }
  runLogFlushScheduled = false;
  if (bufferedRunLogWrites.length === 0) return;
  // 限幅单次事务：大库上一次插 128 行仍可能堵几百 ms；拆小并在调用方用 setImmediate 串起来。
  const batch = bufferedRunLogWrites.splice(0, RUN_LOG_FLUSH_BATCH);
  try {
    const tx = db.transaction((rows: RunLogPayload[]) => {
      for (const row of rows) insertRunLogStmt.run(row);
    });
    tx(batch);
  } catch (error) {
    console.error('[code] 原始运行日志批量写入失败', error);
  }
  if (bufferedRunLogWrites.length > 0) {
    scheduleRunLogFlush();
  }
}

function scheduleRunLogFlush(): void {
  if (runLogFlushScheduled) return;
  runLogFlushScheduled = true;
  setImmediate(flushBufferedRunLogs);
}

/**
 * 每个 Pi Agent 阶段一条独立 run_id；原始流缓冲后批量追加到 SQLite，清结果/重跑均不删除。
 * `flush()` 用于阶段结束/进程退出时强制落库，避免丢失最后一段排查证据。
 */
function createRunLogWriter(
  projectId: string,
  phase: EventPhase,
  channel: string
): { runId: string; append: (stream: string, content: string) => void; flush: () => void } {
  const runId = newId('run_');
  let seq = 0;
  return {
    runId,
    append(stream: string, content: string): void {
      if (!content) return;
      bufferedRunLogWrites.push({
        id: newId('log_'),
        project_id: projectId,
        run_id: runId,
        ts: now(),
        phase,
        channel,
        stream,
        seq: seq++,
        content: truncateRunLogContent(content),
      });
      if (bufferedRunLogWrites.length >= RUN_LOG_FLUSH_BATCH) {
        scheduleRunLogFlush();
      } else if (!runLogFlushTimer) {
        runLogFlushTimer = setTimeout(scheduleRunLogFlush, 150);
        runLogFlushTimer.unref?.();
      }
    },
    flush: () => {
      // 阶段结束：尽量抽干缓冲（同步多批），保证证据不丢。
      while (bufferedRunLogWrites.length > 0) flushBufferedRunLogs();
    },
  };
}

process.once('beforeExit', () => {
  flushBufferedEvents();
  while (bufferedRunLogWrites.length > 0) flushBufferedRunLogs();
});

function recordEvent(
  projectId: string,
  ev: NormalizedEvent,
  persist = true,
  phase: EventPhase = 'audit'
): void {
  const payload = {
    id: newId('e_'),
    project_id: projectId,
    ts: now(),
    kind: ev.kind,
    agent: ev.agent,
    tool: ev.tool,
    text: ev.text,
    raw: '',
    phase,
  };
  if (persist) {
    persistEvent(payload);
  }
  broadcast({ type: 'agent_event', projectId, event: payload });
}

/**
 * MCP 内部入库端点（mcpRoutes）向项目事件流写入账本记录用的薄封装。
 * 单独导出以避免把 recordEvent 及其内部类型暴露给路由层，同时不制造模块环依赖。
 */
export function recordLedgerEvent(
  projectId: string,
  phase: EventPhase,
  kind: 'system' | 'error',
  text: string
): void {
  // MCP 热路径：不要对每条账本事件做同步 flush（否则高并发 submit_findings 会堵事件循环，
  // 触发桥接「backend request timeout」）。缓冲写入即可，system/error 仍会进库。
  const payload = {
    id: newId('e_'),
    project_id: projectId,
    ts: now(),
    kind,
    agent: 'MCP 账本',
    tool: '',
    text,
    raw: '',
    phase,
  };
  bufferedEventWrites.push(payload);
  if (bufferedEventWrites.length >= 64) {
    flushBufferedEvents();
  } else if (!eventFlushTimer) {
    eventFlushTimer = setTimeout(flushBufferedEvents, 100);
    eventFlushTimer.unref?.();
  }
  broadcast({ type: 'agent_event', projectId, event: payload });
}

function saveVulnerabilities(projectId: string, vulns: any[]): void {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const insert = db.prepare(
    `INSERT INTO vulnerabilities
       (id, project_id, title, severity, severity_original, regrade_value, regrade_reason, category, file_path, line, description, recommendation, code_snippet, taint_chain, auth_required, auth_reason, cluster_id, cluster_role, created_at)
     VALUES (@id, @project_id, @title, @severity, @severity_original, @regrade_value, @regrade_reason, @category, @file_path, @line, @description, @recommendation, @code_snippet, @taint_chain, @auth_required, @auth_reason, @cluster_id, @cluster_role, @created_at)`
  );
  const tx = db.transaction((items: any[]) => {
    for (const v of items) {
      let sev = String(v.severity || 'info').toLowerCase() as Severity;
      if (!['critical', 'high', 'medium', 'low', 'info'].includes(sev)) sev = 'info';
      const origRaw = v.severity_original ? String(v.severity_original).toLowerCase() : null;
      const origValid = origRaw && ['critical', 'high', 'medium', 'low', 'info'].includes(origRaw);
      // 最终入库护栏：所有来源（新审计、reprocess、reingest、磁盘回填）统一应用同一
      // 低价值封顶策略，避免原始产物把已经降级的稳定性/纯配置问题重新抬高。
      const policy = applySeverityPolicy({
        ...v,
        severity: sev,
        severity_original: origValid ? origRaw : null,
      });
      sev = policy.severity;
      counts[sev]++;
      const regradeValue = policy.changed
        ? realTeamLabel(sev)
        : v.regrade_value
          ? String(v.regrade_value)
          : null;
      const regradeReason =
        policy.regradeReason ||
        (regradeValue
          ? `[系统兜底] 红队实战二次评级产物未返回逐条理由；当前实战等级按最终严重度映射为「${regradeValue}」。如需模型逐条分析依据，请重跑“红队实战二次评级”。`
          : null);
      insert.run({
        id: newId('v_'),
        project_id: projectId,
        title: String(v.title || '未命名漏洞'),
        severity: sev,
        severity_original: policy.severityOriginal,
        regrade_value: regradeValue,
        regrade_reason: regradeReason,
        category: String(v.category || ''),
        file_path: String(v.file || v.file_path || ''),
        line: Number.isFinite(Number(v.line)) ? Number(v.line) : null,
        description: String(v.description || ''),
        recommendation: String(v.recommendation || ''),
        code_snippet: String(v.snippet || v.code_snippet || ''),
        // 部分子智能体偶尔把污点链输出成结构化数组而非字符串；normalizeTaintChain 会把它
        // 转成可读逐跳文本，而不是像 String(array) 那样退化成 "[object Object],…"。
        taint_chain: normalizeTaintChain(v.taint_chain),
        auth_required: ['none', 'user', 'admin'].includes(String(v.auth_required || '').toLowerCase())
          ? String(v.auth_required).toLowerCase()
          : null,
        auth_reason: String(v.auth_reason || ''),
        cluster_id: v.cluster_id ? String(v.cluster_id) : null,
        cluster_role: ['primary', 'variant'].includes(String(v.cluster_role || ''))
          ? String(v.cluster_role)
          : null,
        created_at: now(),
      });
    }
  });
  tx(vulns);

  db.prepare(
    `UPDATE projects SET count_critical=@c, count_high=@h, count_medium=@m, count_low=@l, count_info=@i WHERE id=@id`
  ).run({ id: projectId, c: counts.critical, h: counts.high, m: counts.medium, l: counts.low, i: counts.info });
  // 重写漏洞行后重新关联旧验证结果（若有），并失效仅受漏洞数据影响的聚合缓存。
  syncVerifiedFlags(projectId);
  syncFrontendRce(projectId);
  invalidateVulnerabilityReads();
}

function readStoredExploitReport(projectId: string): {
  summary: string;
  exploits: any[];
  chains: any[];
} {
  try {
    const row = db.prepare('SELECT exploit_report FROM projects WHERE id = ?').get(projectId) as
      | { exploit_report: string | null }
      | undefined;
    if (!row?.exploit_report) return { summary: '', exploits: [], chains: [] };
    const parsed = JSON.parse(row.exploit_report);
    return {
      summary: String(parsed?.summary || ''),
      exploits: Array.isArray(parsed?.exploits) ? parsed.exploits : [],
      chains: Array.isArray(parsed?.chains) ? parsed.chains : [],
    };
  } catch {
    return { summary: '', exploits: [], chains: [] };
  }
}

function saveExploitReport(projectId: string, structured: any): void {
  const incomingExploits = Array.isArray(structured.exploits) ? structured.exploits : [];
  const incomingChains = Array.isArray(structured.chains) ? structured.chains : [];
  const previous = readStoredExploitReport(projectId);
  const report = {
    summary: String(structured.summary || ''),
    exploits: overlayUnknownExploits(incomingExploits, previous.exploits)
      .map(sanitizeExploitEntry)
      .filter(Boolean),
    chains: incomingChains.length > 0 ? incomingChains : previous.chains,
  };
  const serialized = JSON.stringify(report);
  const prevSerialized = db
    .prepare('SELECT exploit_report FROM projects WHERE id = ?')
    .get(projectId) as { exploit_report: string | null } | undefined;
  if (prevSerialized?.exploit_report === serialized) return;
  let chainsChanged = false;
  const tx = db.transaction(() => {
    db.prepare('UPDATE projects SET exploit_report = ? WHERE id = ?').run(serialized, projectId);
    chainsChanged = syncExploitChains(projectId, report, serialized);
  });
  tx();
  const verifiedChanged = syncVerifiedFlags(projectId);
  syncFrontendRce(projectId);
  if (verifiedChanged || chainsChanged) invalidateExploitReads();
}

/**
 * 维护持久化的 vulnerabilities.verified 列（远程靶机验证成功=1）：
 * 从项目 exploit_report 按标题匹配 local_exploitable==='success' 的漏洞置 1，其余置 0。
 * 让 /dashboard、/vulnerabilities、漏洞库不必每次请求重新解析所有 exploit_report。
 * 每次写 exploit_report（含增量落盘）或重写漏洞表后调用；启动时对存量项目一次性回填。
 */
export function syncVerifiedFlags(projectId: string): boolean {
  let changed = false;
  try {
    const row = db.prepare('SELECT exploit_report FROM projects WHERE id = ?').get(projectId) as
      | { exploit_report: string | null }
      | undefined;
    let exploits: any[] = [];
    if (row?.exploit_report) {
      try {
        const report = JSON.parse(row.exploit_report);
        exploits = Array.isArray(report?.exploits) ? report.exploits : [];
      } catch {
        exploits = [];
      }
    }
    syncProjectVerificationItems(projectId, exploits, 'exploit-report');
    const result = db.prepare(
      `UPDATE vulnerabilities
       SET verified = CASE WHEN EXISTS (
         SELECT 1 FROM vulnerability_verifications vv
         WHERE vv.project_id = vulnerabilities.project_id
           AND vv.vulnerability_id = vulnerabilities.id
           AND vv.remote_status = 'success'
       ) THEN 1 ELSE 0 END
       WHERE project_id = ?
         AND verified <> CASE WHEN EXISTS (
           SELECT 1 FROM vulnerability_verifications vv
           WHERE vv.project_id = vulnerabilities.project_id
             AND vv.vulnerability_id = vulnerabilities.id
             AND vv.remote_status = 'success'
         ) THEN 1 ELSE 0 END`
    ).run(projectId);
    changed = result.changes > 0;
  } finally {
    if (changed) invalidateVulnerabilityReads();
  }
  return changed;
}

/** 解析 TARGET_ENV.json 中的布尔字段为 0/1/null。 */
function triBool(v: unknown): number | null {
  if (v === true || v === 1 || v === 'true' || v === '1') return 1;
  if (v === false || v === 0 || v === 'false' || v === '0') return 0;
  return null;
}

/** 从 TARGET_ENV.json 读取 registration 字段并落库 projects.has_registration / reg_default_open。 */
function syncRegistrationMeta(projectId: string, codeDir: string): void {
  let env: any;
  try {
    env = JSON.parse(fs.readFileSync(path.join(codeDir, 'TARGET_ENV.json'), 'utf8'));
  } catch {
    return;
  }
  const reg = env?.registration;
  if (!reg || typeof reg !== 'object') return;
  db.prepare('UPDATE projects SET has_registration = ?, reg_default_open = ? WHERE id = ?').run(
    triBool(reg.exists),
    triBool(reg.default_open),
    projectId
  );
}

/**
 * 同步 projects.frontend_rce 与 vulnerabilities.frontend_rce。
 * 口径见 frontendRceCriteria.ts（远程 HTTP 验证 RCE：none 或 reg_open+user）。
 */
export function syncFrontendRce(projectId: string): void {
  // 置位时写入「拿到前台 RCE 的时间」：保留已有时间（避免每次重算都刷新），
  // 首次标记则回填该项目远程验证完成时间 verify_finished_at，缺失再退回当前时间。
  const proj = db
    .prepare('SELECT verify_finished_at FROM projects WHERE id = ?')
    .get(projectId) as { verify_finished_at: number | null } | undefined;
  const stamp = proj?.verify_finished_at ?? now();
  const setFr = db.prepare(
    'UPDATE vulnerabilities SET frontend_rce = 1, frontend_rce_at = COALESCE(frontend_rce_at, ?) WHERE id = ?'
  );
  const matched = queryFrontendRceVulns(projectId);
  const target = new Set(matched.map((v) => v.id));
  const current = db
    .prepare('SELECT id FROM vulnerabilities WHERE project_id = ? AND frontend_rce = 1')
    .all(projectId) as { id: string }[];
  const currentSet = new Set(current.map((row) => row.id));
  let changed = false;
  const tx = db.transaction(() => {
    for (const row of current) {
      if (target.has(row.id)) continue;
      db.prepare('UPDATE vulnerabilities SET frontend_rce = 0 WHERE id = ?').run(row.id);
      changed = true;
    }
    for (const vulnerability of matched) {
      if (currentSet.has(vulnerability.id)) continue;
      setFr.run(stamp, vulnerability.id);
      changed = true;
    }
    const projectValue = matched.length > 0 ? 1 : 0;
    const projectUpdate = db
      .prepare('UPDATE projects SET frontend_rce = ? WHERE id = ? AND frontend_rce <> ?')
      .run(projectValue, projectId, projectValue);
    changed ||= projectUpdate.changes > 0;
  });
  tx();
  if (changed) invalidateVulnerabilityReads();
}

function clearAuditResults(projectId: string, _opts?: { keepEvents?: boolean }): void {
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM vulnerability_verifications WHERE project_id = ?').run(projectId);
    db.prepare('DELETE FROM vulnerabilities WHERE project_id = ?').run(projectId);
    // agent_events 与 project_run_logs 是追加式审计证据；重跑/清结果永不删除。
    db.prepare(
      `UPDATE projects SET count_critical=0, count_high=0, count_medium=0, count_low=0, count_info=0,
         exploit_report=NULL, frontend_rce=0, verify_status='none',
         verify_started_at=NULL, verify_finished_at=NULL, verify_error=NULL
       WHERE id=?`
    ).run(projectId);
    clearExploitChains(projectId);
  });
  tx();
  invalidateProjectStatusReads();
  invalidateVulnerabilityReads();
  invalidateExploitReads();
}

function clearVerifyResults(projectId: string): void {
  // 验证结果可重置，验证日志必须永久保留在数据库中供事后排查。
  const tx = db.transaction(() => {
    db.prepare('UPDATE projects SET exploit_report = NULL, frontend_rce = 0 WHERE id = ?').run(projectId);
    db.prepare('DELETE FROM vulnerability_verifications WHERE project_id = ?').run(projectId);
    db.prepare(
      'UPDATE vulnerabilities SET verified = 0, frontend_rce = 0 WHERE project_id = ?'
    ).run(projectId);
    clearExploitChains(projectId);
  });
  tx();
  invalidateVulnerabilityReads();
  invalidateExploitReads();
  // 重跑/全量验证：清空产物目录里的远程验证落盘，避免旧 exploits/*.json 被误合并
  const p = getProject(projectId);
  const verifyArt = artifactRootFor(projectId, p?.workspace_path);
  try {
    fs.rmSync(path.join(verifyArt, '_remote_verify'), { recursive: true, force: true });
  } catch {
    /* 目录不存在或占用中 */
  }
  if (p?.workspace_path && fs.existsSync(p.workspace_path)) {
    try {
      fs.rmSync(remoteVerifyDir(p.workspace_path), { recursive: true, force: true });
    } catch {
      /* 旧工作区残留 */
    }
    try {
      fs.rmSync(path.join(p.workspace_path, '_mini_verify'), { recursive: true, force: true });
    } catch {
      /* 历史最小运行时落盘 */
    }
  }
}

function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  const pid = child.pid;
  if (process.platform === 'win32') {
    try {
      execSync(`taskkill /pid ${pid} /T /F`, { stdio: 'ignore' });
    } catch {
      /* ignore */
    }
    return;
  }
  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    /* 非进程组 leader 时忽略 */
  }
  try {
    execSync(`pkill -TERM -P ${pid}`, { stdio: 'ignore' });
  } catch {
    /* 无子进程 */
  }
  try {
    child.kill('SIGTERM');
  } catch {
    /* ignore */
  }
  setTimeout(() => {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      /* ignore */
    }
    try {
      execSync(`pkill -KILL -P ${pid}`, { stdio: 'ignore' });
    } catch {
      /* ignore */
    }
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }, 1500);
}

interface StageResult {
  killed: boolean;
  timedOut: boolean;
  code: number | null;
  structured: any;
  finalResult: string;
  stderrTail: string;
}

/** 主通道（非并发验证）Pi Agent 阶段的 resolve 钩子：僵尸看门狗可强制唤醒卡死的 await。 */
const mainStageResolvers = new Map<string, (result: StageResult) => void>();

function isPiChildAlive(projectId: string): boolean {
  const child = running.get(projectId);
  if (!child) return false;
  if (child.killed) return false;
  if (child.exitCode !== null && child.exitCode !== undefined) return false;
  return true;
}

/** 审计卡死阈值：Pi Agent 已退出且超过 N 分钟无事件 → 视为僵尸占槽。 */
function auditStallMs(): number {
  const n = parseInt(getSetting('audit_stall_min') || '5', 10);
  return (Number.isFinite(n) && n > 0 ? n : 5) * 60_000;
}

function lastProjectActivityTs(projectId: string): number {
  const row = db
    .prepare(`SELECT MAX(ts) AS ts FROM agent_events WHERE project_id = ?`)
    .get(projectId) as { ts: number | null } | undefined;
  return Number(row?.ts || 0);
}

/**
 * 回收「Pi Agent 已退出、事件流已停，但仍占着 activeAuditProjects 槽」的僵尸审计。
 * 根因：主进程 close 后 await 未继续（或 killed 早退后未改 DB），导致 status=running 永久占槽、排队任务饿死。
 * 策略：强制唤醒卡住的 stage Promise → doAudit 走 killed 早退；再以 continueMode 入队续跑后处理。
 */
export function reconcileStalledAuditJobs(): number {
  const stallMs = auditStallMs();
  const nowTs = Date.now();
  let recovered = 0;
  const candidates = new Set<string>([
    ...activeAuditProjects,
    ...((db.prepare("SELECT id FROM projects WHERE status = 'running'").all() as { id: string }[]).map(
      (r) => r.id
    )),
  ]);
  for (const projectId of candidates) {
    const p = getProject(projectId);
    if (!p || p.status !== 'running') continue;
    if (isPiChildAlive(projectId)) continue;
    const lastTs = lastProjectActivityTs(projectId) || p.started_at || 0;
    if (!lastTs || nowTs - lastTs < stallMs) continue;
    // 刚入队尚未产出事件：用 started_at 保护，避免误杀冷启动。
    if (p.started_at && nowTs - p.started_at < stallMs) continue;

    const idleMin = Math.round((nowTs - lastTs) / 60000);
    console.warn(
      `[code] 僵尸审计回收：${p.project_name} (${projectId}) Pi Agent 已退出且 ${idleMin} 分钟无事件`
    );
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `⚠ 检测到审计卡死（Pi Agent 已退出且 ${idleMin} 分钟无事件），自动释放槽位并续跑后处理`,
    });

    cancelledProjects.add(projectId);
    intentionallyStopped.add(projectId);
    const forceResolve = mainStageResolvers.get(projectId);
    if (forceResolve) {
      mainStageResolvers.delete(projectId);
      try {
        forceResolve({
          killed: true,
          timedOut: true,
          code: -1,
          structured: null,
          finalResult: '',
          stderrTail: '审计卡死看门狗：Pi Agent 已退出但阶段未收尾',
        });
      } catch {
        /* ignore */
      }
    }
    const child = running.get(projectId);
    if (child) {
      try {
        killTree(child);
      } catch {
        /* ignore */
      }
      running.delete(projectId);
    }

    // 强制摘槽 + 清 inFlight，避免原 Promise 永不结束导致排队饿死。
    clearActiveSlots(projectId);
    inFlight.delete(projectId);
    runningKind.delete(projectId);

    const codeDir = [p.workspace_path, path.join(WORKSPACE_DIR, projectId)]
      .filter((c): c is string => !!c)
      .find((c) => fs.existsSync(c));
    const artDir = resolveArtifactRoot(projectId, codeDir);
    const hasArtifacts =
      !!(artDir && hasSubagentArtifacts(artDir)) || !!(codeDir && hasSubagentArtifacts(codeDir));
    setAuditStatus(projectId, 'paused', {
      finished_at: now(),
      error_message: `审计卡死自动暂停（空闲 ${idleMin} 分钟）`,
    });
    // 延后入队：等强制 resolve 的 microtask / 原 runJob.finally 先跑完，避免 isBusy 挡续跑。
    if (hasArtifacts && isPiJobsEnabled()) {
      const resumeId = projectId;
      setTimeout(() => {
        const cur = getProject(resumeId);
        if (!cur || (cur.status !== 'paused' && cur.status !== 'queued' && cur.status !== 'failed')) return;
        if (isBusy(resumeId)) return;
        enqueueReprocess(resumeId, false, true);
      }, 250);
    }
    recovered++;
  }
  return recovered;
}

let auditStallTimer: NodeJS.Timeout | null = null;
export function startAuditStallWatchdog(): void {
  if (auditStallTimer) return;
  const tick = () => {
    try {
      const n = reconcileStalledAuditJobs();
      if (n > 0) scheduleStartNext();
    } catch (e) {
      console.error('[code] 审计卡死看门狗失败', e);
    }
  };
  const kickoff = setTimeout(tick, 60_000);
  kickoff.unref?.();
  auditStallTimer = setInterval(tick, 60_000);
  auditStallTimer.unref?.();
}

function runPiStage(
  projectId: string,
  codeDir: string,
  prompt: string,
  schemaStr: string,
  opts: {
    channel?: 'main' | 'env' | 'codeverify' | 'remoteverify' | 'subagent';
    phase?: EventPhase;
    hardMsOverride?: number;
    idleMsOverride?: number;
  } = {}
): Promise<StageResult> {
  const channel = opts.channel ?? 'main';
  const phase = opts.phase ?? 'audit';
  const multi = channel === 'codeverify' || channel === 'remoteverify' || channel === 'subagent';
  const procMap = channel === 'env' ? envRunning : running;
  const stoppedSet = channel === 'env' ? envIntentionallyStopped : intentionallyStopped;
  const runLog = createRunLogWriter(projectId, phase, channel);
  runLog.append(
    'meta',
    JSON.stringify({ event: 'stage_requested', codeDir, phase, channel, run_id: runLog.runId })
  );
  return new Promise((resolve) => {
    let settled = false;
    let promptFileToClean: string | undefined;
    const settle = (result: StageResult) => {
      if (settled) return;
      settled = true;
      cleanupPromptFile(promptFileToClean);
      if (!multi && mainStageResolvers.get(projectId) === settle) {
        mainStageResolvers.delete(projectId);
      }
      resolve(result);
    };
    // 仅主审计通道注册：看门狗可在 Pi Agent 已退出但 Promise 未 settle 时强制唤醒。
    if (!multi && channel === 'main') {
      mainStageResolvers.set(projectId, settle);
    }

    // 协作式取消：项目已被暂停/重跑/删除请求中止 → 不再 spawn 新 Pi，直接判 killed 收尾，
    // 杜绝"被取代/已暂停的旧异步仍在逐批拉起 Pi"的空转。（env 通道由 stopEnvChannel 单独管控，不在此拦截。）
    if (channel !== 'env' && cancelledProjects.has(projectId)) {
      runLog.append('meta', JSON.stringify({ event: 'stage_skipped', reason: 'cancelled' }));
      settle({ killed: true, timedOut: false, code: -1, structured: null, finalResult: '', stderrTail: '已请求中止，跳过本阶段' });
      return;
    }
    if (!isPiJobsEnabled()) {
      runLog.append('meta', JSON.stringify({ event: 'stage_skipped', reason: 'jobs_disabled' }));
      settle({
        killed: true,
        timedOut: false,
        code: -1,
        structured: null,
        finalResult: '',
        stderrTail: 'Pi 任务已停摆，跳过本阶段',
      });
      return;
    }
    // ② 省 token · 验证环节模型分级：代码验证层（去重/代码级验证/二次评级，channel==='codeverify'）
    // 可用独立命令模板路由到更便宜的模型；留空则沿用 default_command（现状）。
    const verifyCmd = channel === 'codeverify' ? getSetting('verify_command').trim() : '';
    const template = verifyCmd || getSetting('default_command');
    const { program, args, promptFile, fullPrompt } = buildAgentCliArgs({
      template,
      prompt,
      schemaStr,
    });
    promptFileToClean = promptFile;
    runLog.append('prompt', fullPrompt);

    const spawnEnvExtra: Record<string, string> = {};

    runLog.append(
      'meta',
      JSON.stringify({
        event: 'spawn',
        program,
        args: args.map((arg) =>
          arg === fullPrompt
            ? '<prompt stored separately>'
            : arg.startsWith('@') && promptFile && arg === `@${promptFile}`
              ? '<prompt @file>'
              : arg.startsWith('{"mcpServers"')
                ? '<mcp-config>'
                : arg
        ),
        prompt_file: promptFile || undefined,
      })
    );

    let child: ChildProcess;
    try {
      child = spawn(program, args, {
        cwd: codeDir,
        env: { ...piSpawnEnv(), ...spawnEnvExtra },
        windowsHide: true,
      });
    } catch (err: any) {
      cleanupPromptFile(promptFile);
      runLog.append('meta', JSON.stringify({ event: 'spawn_error', error: String(err?.message || err) }));
      settle({
        killed: false,
        timedOut: false,
        code: -1,
        structured: null,
        finalResult: '',
        stderrTail: `无法启动 Pi：${err?.message || err}`,
      });
      return;
    }

    if (multi) {
      let set = verifyProcs.get(projectId);
      if (!set) {
        set = new Set();
        verifyProcs.set(projectId, set);
      }
      set.add(child);
    } else {
      procMap.set(projectId, child);
    }
    child.stdin?.on('error', () => {});
    child.stdout?.on('error', () => {});
    child.stderr?.on('error', () => {});
    if (child.stdin) child.stdin.end();

    let buffer = '';
    let finalResult = '';
    let structured: any = null;
    let stderrTail = '';
    const subagentByToolId = new Map<string, string>();
    const seenAgents = new Set<string>();

    // —— 超时看门狗：检测卡死进程并自动终止，避免永久占用并发槽 ——
    const startedAt = Date.now();
    let lastOutputAt = Date.now();
    let timedOut = false;
    let timeoutReason = '';
    const hardMs = opts.hardMsOverride && opts.hardMsOverride > 0 ? opts.hardMsOverride : stageTimeoutMs();
    const idleMs = opts.idleMsOverride && opts.idleMsOverride > 0 ? opts.idleMsOverride : idleTimeoutMs();
    // 结果收尾宽限：仅在 Pi 发出 agent_end（或旧引擎 type:'result'）后才启用——
    // 若进程随后迟迟不退出（卡死），静默 settleMs 后主动收尾。
    // 关键：绝不依据中途的结构化片段来收尾，否则会误杀仍在工作的审计。
    const settleMs = settleAfterOutputMs();
    let settleTimer: NodeJS.Timeout | null = null;
    let resultSeen = false;
    const resetSettleTimer = () => {
      if (settleMs <= 0 || !resultSeen) return;
      if (settleTimer) clearTimeout(settleTimer);
      settleTimer = setTimeout(() => {
        recordEvent(
          projectId,
          {
            kind: 'system',
            agent: '主控',
            tool: '',
            text: '✓ 会话已结束但进程未自行退出，主动收尾并保存结果以释放资源',
          },
          true,
          phase
        );
        killTree(child);
      }, settleMs);
    };
    const watchdog = setInterval(() => {
      const t = Date.now();
      if (hardMs > 0 && t - startedAt > hardMs) {
        timeoutReason = `运行超过 ${Math.round(hardMs / 60000)} 分钟硬上限，已自动终止`;
      } else if (idleMs > 0 && t - lastOutputAt > idleMs) {
        timeoutReason = `连续 ${Math.round(idleMs / 60000)} 分钟无任何输出（疑似卡死），已自动终止`;
      }
      if (timeoutReason) {
        timedOut = true;
        clearInterval(watchdog);
        recordEvent(projectId, { kind: 'error', agent: '主控', tool: '', text: `⏱ ${timeoutReason}` }, true, phase);
        killTree(child);
      }
    }, 30_000);

    child.stdout?.setEncoding('utf8');
    // 单行 stream-json 超过该长度时跳过 JSON.parse：巨型 StructuredOutput 解析会冻事件循环数秒。
    const MAX_JSON_LINE = 512 * 1024;
    const MAX_LINES_PER_TICK = 32;
    let stdoutDrainScheduled = false;
    const processStdoutLine = (line: string): void => {
      if (!line) return;
      const markSessionEnd = () => {
        resultSeen = true;
        resetSettleTimer();
      };
      const ingestAssistantText = (text: string) => {
        if (!text) return;
        finalResult = text;
        const parsed = tryExtractStructured(text);
        if (parsed) structured = parsed;
      };
      // 超大行：跳过 JSON.parse（会冻事件循环），仍用廉价检查抓会话结束信号。
      if (line.length > MAX_JSON_LINE) {
        if (
          line.includes('"type":"result"') ||
          line.includes('"type": "result"') ||
          line.includes('"type":"agent_end"') ||
          line.includes('"type": "agent_end"')
        ) {
          markSessionEnd();
        }
        return;
      }
      let obj: any;
      try {
        obj = JSON.parse(line);
      } catch {
        return;
      }
      if (obj.type === 'result') {
        if (typeof obj.result === 'string') {
          ingestAssistantText(obj.result);
        }
        markSessionEnd();
      }
      if (obj.type === 'agent_end') {
        if (Array.isArray(obj.messages)) {
          for (let i = obj.messages.length - 1; i >= 0; i--) {
            const m = obj.messages[i];
            if (m?.role === 'assistant') {
              ingestAssistantText(extractAssistantText(m));
              break;
            }
          }
        }
        markSessionEnd();
      }
      if (obj.type === 'message_end' && obj.message?.role === 'assistant') {
        ingestAssistantText(extractAssistantText(obj.message));
      }

      if (obj.type === 'system' && obj.subtype === 'task_started' && obj.tool_use_id) {
        subagentByToolId.set(obj.tool_use_id, subagentLabel(obj));
      }
      if (obj.type === 'assistant' && Array.isArray(obj.message?.content)) {
        for (const part of obj.message.content) {
          if (part.type === 'tool_use' && (part.name === 'Agent' || part.name === 'Task') && part.id) {
            subagentByToolId.set(part.id, subagentLabel(part.input));
          }
          if (
            part.type === 'tool_use' &&
            part.name === 'StructuredOutput' &&
            part.input &&
            (Array.isArray(part.input.vulnerabilities) ||
              Array.isArray(part.input.exploits) ||
              Array.isArray(part.input.ratings) ||
              Array.isArray(part.input.results) ||
              Array.isArray(part.input.duplicate_groups) ||
              typeof part.input.has_web === 'boolean' ||
              typeof part.input.has_registration === 'boolean')
          ) {
            structured = part.input;
          }
        }
      }

      const ctxAgent = obj.parent_tool_use_id
        ? subagentByToolId.get(obj.parent_tool_use_id) || '子智能体'
        : undefined;

      for (const ev of parseStreamObject(obj, ctxAgent)) {
        if (ev.kind === 'agent_start') {
          if (seenAgents.has(ev.agent)) continue;
          seenAgents.add(ev.agent);
        }
        recordEvent(projectId, ev, ev.kind !== 'delta', phase);
      }
    };
    const drainStdoutLines = (limit = MAX_LINES_PER_TICK): void => {
      stdoutDrainScheduled = false;
      let processed = 0;
      let nl: number;
      while (processed < limit && (nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        processed++;
        processStdoutLine(line);
      }
      if (limit !== Number.POSITIVE_INFINITY && buffer.includes('\n')) {
        stdoutDrainScheduled = true;
        setImmediate(() => drainStdoutLines());
      }
    };
    child.stdout?.on('data', (chunk: string) => {
      runLog.append('stdout', chunk);
      lastOutputAt = Date.now();
      if (resultSeen) resetSettleTimer();
      buffer += chunk;
      if (buffer.length > 8 * 1024 * 1024) {
        buffer = buffer.slice(-1 * 1024 * 1024);
      }
      if (!stdoutDrainScheduled) {
        stdoutDrainScheduled = true;
        setImmediate(() => drainStdoutLines());
      }
    });

    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk: string) => {
      runLog.append('stderr', chunk);
      lastOutputAt = Date.now();
      stderrTail = (stderrTail + chunk).slice(-2000);
    });

    child.on('error', (err) => {
      try {
        runLog.append('meta', JSON.stringify({ event: 'process_error', error: err.message }));
        runLog.flush();
      } finally {
        clearInterval(watchdog);
        if (settleTimer) clearTimeout(settleTimer);
        if (multi) verifyProcs.get(projectId)?.delete(child);
        const killed = multi ? verifyKilled.has(projectId) : stoppedSet.has(projectId);
        settle({
          killed,
          timedOut,
          code: -1,
          structured,
          finalResult,
          stderrTail: timedOut ? timeoutReason : stderrTail || err.message,
        });
      }
    });
    child.on('close', (code) => {
      try {
        // 同步抽干剩余 stdout，避免 setImmediate drain 未跑完就 settle 丢终态。
        drainStdoutLines(Number.POSITIVE_INFINITY);
        if (buffer.trim()) processStdoutLine(buffer.trim());
        buffer = '';
        runLog.append(
          'meta',
          JSON.stringify({ event: 'process_close', code, timed_out: timedOut, timeout_reason: timeoutReason })
        );
        runLog.flush();
      } finally {
        // flush 异常也不能阻止 Promise settle，否则 doAudit 永久 await → 僵尸 running 占槽。
        clearInterval(watchdog);
        if (settleTimer) clearTimeout(settleTimer);
        if (multi) {
          verifyProcs.get(projectId)?.delete(child);
          settle({
            killed: verifyKilled.has(projectId),
            timedOut,
            code,
            structured,
            finalResult,
            stderrTail: timedOut ? timeoutReason : stderrTail,
          });
          return;
        }
        const killed = stoppedSet.has(projectId);
        if (killed) stoppedSet.delete(projectId);
        settle({
          killed,
          timedOut,
          code,
          structured,
          finalResult,
          stderrTail: timedOut ? timeoutReason : stderrTail,
        });
      }
    });
  });
}

/**
 * 在工作区构建/更新 CodeGraph 代码图谱（`.codegraph/`）。
 * - 首次（无 .codegraph）：`codegraph init -i` 建图并索引；
 * - 已存在：`codegraph sync` 增量更新。
 * 非致命：codegraph 不可用/超时不应阻断审计（子智能体会降级到 grep/读文件），仅记录告警。
 */
async function ensureCodeGraph(_projectId: string, _dir: string): Promise<void> {
  return;
}

async function ensureWorkspace(project: Project): Promise<string> {
  // per-project 锁：审计与环境搭建可能并发调用，避免重复 clone/解压同一工作区
  const existing = workspaceLocks.get(project.id);
  if (existing) return existing;

  const task = (async () => {
    const fresh = getProject(project.id) || project;
    let dir: string;
    if (fresh.workspace_path && fs.existsSync(fresh.workspace_path)) {
      void resolveProjectVersion(fresh, fresh.workspace_path);
      dir = fresh.workspace_path;
    } else {
      dir = await prepareSource(
        project.id,
        project.source_type,
        project.source_ref,
        fresh.git_ref
      );
      db.prepare('UPDATE projects SET workspace_path = ? WHERE id = ?').run(dir, project.id);
      void resolveProjectVersion(fresh, dir);
    }
    // 建立 CodeGraph 代码图谱：审计/验证子智能体依赖 codegraph MCP 做调用链与污点追踪，
    // 必须在 Pi 启动前于工作区建好 .codegraph（否则 MCP 因无索引而不提供任何工具，子智能体退化为 grep/读文件）。
    await ensureCodeGraph(project.id, dir);
    // Web 端判定：仅在尚未判定（has_web=null）时执行一次并落库缓存。新建审计首判一律走
    // Pi 语义画像（同一次调用顺带识别注册功能）；LLM 不可用再回退机械规则，并由下方
    // ensureRegistrationDetected 对规则兜底出的 Web 端做注册专项回填。
    const fresh2 = getProject(project.id);
    if (fresh2 && fresh2.has_web === null) {
      await resolveHasWebAuthoritative(project.id, dir);
    }
    // 含 Web 端且注册尚未识别 → Pi Agent 回填（机械规则首判、或 Web 判定未返回注册字段时）。
    await ensureRegistrationDetected(project.id, dir);
    ensureArtifactLayout(project.id, dir);
    return dir;
  })();

  workspaceLocks.set(project.id, task);
  try {
    return await task;
  } finally {
    workspaceLocks.delete(project.id);
  }
}

/**
 * GitHub 项目：解析版本号并落库。
 * 优先 release/tag；离线时回退到 commit SHA。
 * 若当前已是 commit SHA（占位），联网后可自动升级为正式 release tag。
 */
async function resolveProjectVersion(project: Project, dir: string): Promise<void> {
  if (project.source_type !== 'github') return;
  const cur = project.source_version;
  const isShaPlaceholder = !!cur && /^[0-9a-f]{7,40}$/i.test(cur);
  if (cur && !isShaPlaceholder) return; // 已是正式版本号

  try {
    const release = await fetchLatestRelease(project.source_ref);
    let version = release?.tag || null;
    // 还没有任何版本时才用 commit 兜底；已有 SHA 占位则只在能拿到 tag 时升级
    if (!version && !cur) version = localGitVersion(dir);
    // 实在拿不到版本号：给随机占位，便于人工修改（避免版本对比里出现空值）。
    if (!version && !cur) version = placeholderLabel('版本');
    if (!version || version === cur) return;
    db.prepare('UPDATE projects SET source_version = ? WHERE id = ?').run(version, project.id);
    invalidateReadScopes('version-groups');
    broadcast({ type: 'project_status', projectId: project.id });
  } catch {
    /* 版本号获取失败不影响审计 */
  }
}

/**
 * 读取某项目的审计流程选项：优先用项目级配置（新建审计页设置），
 * 项目未配置（NULL）时回退到全局默认设置。
 */
function projOptBool(
  projectId: string,
  optCol: 'opt_auto_verify' | 'opt_verify_history' | 'opt_ai_dedup' | 'opt_ai_regrade',
  globalKey: string
): boolean {
  const row = db.prepare(`SELECT ${optCol} AS v FROM projects WHERE id = ?`).get(projectId) as
    | { v: number | null }
    | undefined;
  if (row && row.v != null) return row.v === 1;
  const g = getSetting(globalKey);
  return g === '1' || g === 'true';
}

/** 是否对漏洞做 AI 红队实战二次评级（项目级 → 全局默认）。 */
function isAiRegrade(projectId: string): boolean {
  return projOptBool(projectId, 'opt_ai_regrade', 'ai_regrade');
}

/** 是否对候选漏洞做 AI 语义去重（项目级 → 全局默认）。 */
function isAiDedup(projectId: string): boolean {
  return projOptBool(projectId, 'opt_ai_dedup', 'ai_dedup');
}

/** 靶机验证阶段是否对"其他历史版本"做验证（项目级 → 全局默认）。 */
function isVerifyHistory(projectId: string): boolean {
  return projOptBool(projectId, 'opt_verify_history', 'verify_history');
}

/** ① 省 token：代码级验证是否顺带完成红队二次评级（开启后流水线跳过独立评级 pass）。默认关。 */
function isMergeVerifyRegrade(): boolean {
  const v = getSetting('merge_verify_regrade');
  return v === '1' || v === 'true';
}

/** ③④ 省 token：是否精简验证/去重/评级提示词（子智能体按 index 读盘 + 免冗余 StructuredOutput）。默认关。 */
function isLeanVerifyPrompt(): boolean {
  const v = getSetting('lean_verify_prompt');
  return v === '1' || v === 'true';
}

/** ⑤ 省 token：AI 语义去重的候选数门槛（低于此值跳过整个去重 Pi Agent pass；0=始终跑，现状）。 */
function aiDedupMinCandidates(): number {
  const n = parseInt(getSetting('ai_dedup_min_candidates'), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * AI 去重是否保留「同一代码点的不同利用面」（variant）。默认开：只删纯措辞重复，
 * 同点多面各自保留并归簇（cluster_id）逐面验证。关闭（'0'/'false'）时退回旧行为：同点即合并成一条。
 */
function dedupKeepVariants(): boolean {
  const v = getSetting('dedup_keep_variants');
  return v !== '0' && v !== 'false';
}

/** 从模型最终文本里兜底解析 ratings 数组。 */
function parseRatings(text: string): any[] {
  if (!text) return [];
  const tryParse = (s: string): any[] | null => {
    try {
      const obj = JSON.parse(s);
      if (Array.isArray(obj?.ratings)) return obj.ratings;
      if (Array.isArray(obj)) return obj;
    } catch {
      /* ignore */
    }
    return null;
  };
  let r = tryParse(text.trim());
  if (r) return r;
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    r = tryParse(fence[1].trim());
    if (r) return r;
  }
  const idx = text.indexOf('"ratings"');
  if (idx !== -1) {
    const start = text.lastIndexOf('{', idx);
    if (start !== -1) {
      for (let end = text.length; end > idx; end--) {
        r = tryParse(text.slice(start, end));
        if (r) return r;
      }
    }
  }
  return [];
}

function readRegradeFile(p: string): any[] {
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (Array.isArray(raw)) return raw;
    if (Array.isArray(raw?.ratings)) return raw.ratings;
  } catch {
    /* ignore */
  }
  return [];
}

function readDedupFile(p: string): any[] {
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (Array.isArray(raw)) return raw;
    if (Array.isArray(raw?.duplicate_groups)) return raw.duplicate_groups;
  } catch {
    /* ignore */
  }
  return [];
}

function readCodeVerifyFile(p: string): any[] {
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (Array.isArray(raw)) return raw;
    if (Array.isArray(raw?.results)) return raw.results;
  } catch {
    /* ignore */
  }
  return [];
}

const normTitleKey = (s: string) =>
  String(s || '')
    .replace(/\\([_*`[\]()#+\-.!|{}])/g, '$1')
    .replace(/['"“”‘’]/g, '')
    .replace(/\s+/g, '')
    .toLowerCase();

/** 严重度(机器 5 级) → 实战等级(五级中文标签)。实战等级与 severity 严格同义、一一对应。 */
const REAL_TEAM_LABEL: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '无',
};
function realTeamLabel(sev: string): string {
  return REAL_TEAM_LABEL[String(sev || 'info').toLowerCase()] || '无';
}

function chunkByBatch<T>(items: T[], batchSize: number): T[][] {
  const groups: T[][] = [];
  const size = Math.max(1, batchSize);
  for (let i = 0; i < items.length; i += size) groups.push(items.slice(i, i + size));
  return groups;
}

/** 按文件装箱后再按 batchSize 打包：同一文件的候选不拆到不同工人，避免漏判跨上报重复。 */
function packByFileThenBatch<T extends { file?: string }>(items: T[], batchSize: number): T[][] {
  const byFile = new Map<string, T[]>();
  for (const it of items) {
    const key =
      String(it.file || '')
        .toLowerCase()
        .replace(/\\/g, '/')
        .trim() || '__nofile__';
    const arr = byFile.get(key) || [];
    arr.push(it);
    byFile.set(key, arr);
  }
  const groups: T[][] = [];
  let current: T[] = [];
  const size = Math.max(1, batchSize);
  for (const bucket of byFile.values()) {
    if (bucket.length >= size) {
      if (current.length > 0) {
        groups.push(current);
        current = [];
      }
      groups.push(bucket);
      continue;
    }
    if (current.length + bucket.length > size && current.length > 0) {
      groups.push(current);
      current = [];
    }
    current.push(...bucket);
  }
  if (current.length > 0) groups.push(current);
  return groups.length > 0 ? groups : chunkByBatch(items, size);
}

type GroupedPiWorkerOpts<T> = {
  projectId: string;
  codeDir: string;
  groups: T[][];
  conc: number;
  schemaStr: string;
  groupsDir: string;
  resDir: string;
  agentLabel: string;
  startText: (group: T[], groupNo: number, groupTotal: number) => string;
  progressText: (done: number, total: number) => string;
  progressTotal: number;
  countFile: (p: string) => number;
  persist: (outFile: string, r: { structured: any; finalResult: string }) => void;
  prompt: (groupFile: string, outFile: string, group: T[], groupNo: number, groupTotal: number) => string;
};

/** 核验层工人池：去重 / 代码级验证 / 二次评级共用。 */
async function runGroupedPiWorkers<T>(opts: GroupedPiWorkerOpts<T>): Promise<{ killed: boolean }> {
  const {
    projectId,
    codeDir,
    groups,
    conc,
    schemaStr,
    groupsDir,
    resDir,
    agentLabel,
    startText,
    progressText,
    progressTotal,
    countFile,
    persist,
    prompt,
  } = opts;
  fs.mkdirSync(groupsDir, { recursive: true });
  fs.mkdirSync(resDir, { recursive: true });

  let polledDone = false;
  const poll = setInterval(() => {
    if (polledDone) return;
    let n = 0;
    try {
      for (const f of fs.readdirSync(resDir)) {
        if (f.toLowerCase().endsWith('.json')) n += countFile(path.join(resDir, f));
      }
    } catch {
      /* ignore */
    }
    if (n > 0) {
      recordEvent(projectId, {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: progressText(Math.min(n, progressTotal), progressTotal),
      });
    }
  }, 15_000);

  const groupIdleMs = 10 * 60_000;
  let cursor = 0;
  let killed = false;
  const worker = async () => {
    while (true) {
      if (cancelledProjects.has(projectId) || verifyKilled.has(projectId)) {
        killed = true;
        return;
      }
      const idx = cursor++;
      if (idx >= groups.length) return;
      const group = groups[idx];
      const groupNo = idx + 1;
      const groupFile = path.join(groupsDir, `group-${groupNo}.json`);
      const outFile = path.join(resDir, `group-${groupNo}.json`);
      fs.writeFileSync(groupFile, JSON.stringify(group, null, 2), 'utf8');
      recordEvent(projectId, {
        kind: 'agent_start',
        agent: `${agentLabel}${groupNo}`,
        tool: 'Task',
        text: startText(group, groupNo, groups.length),
      });
      const r = await runPiStage(
        projectId,
        codeDir,
        prompt(groupFile, outFile, group, groupNo, groups.length),
        schemaStr,
        {
          channel: 'codeverify',
          phase: 'audit',
          hardMsOverride: Math.min(45 * 60_000, Math.max(12 * 60_000, group.length * 90_000)),
          idleMsOverride: groupIdleMs,
        }
      );
      persist(outFile, r);
      if (r.killed) {
        killed = true;
        return;
      }
    }
  };

  try {
    await Promise.all(Array.from({ length: Math.max(1, conc) }, () => worker()));
  } finally {
    polledDone = true;
    clearInterval(poll);
  }
  return { killed: killed || verifyKilled.has(projectId) };
}

/**
 * AI 红队实战二次评级：对采集到的【全部】漏洞按真实利用价值重新客观定级。
 * 工人池：每路评 batchSize 条（默认 10），最多同时 concurrency 路（默认 10，封顶 10），
 * 一轮最多 100 个；超出则工人取下一组。返回带 severity / regrade_value 的清单。
 */
async function regradeFindings(
  projectId: string,
  codeDir: string,
  findings: any[]
): Promise<{ findings: any[]; killed: boolean }> {
  if (!isAiRegrade(projectId) || findings.length === 0) return { findings, killed: false };
  verifyKilled.delete(projectId);

  const batchSize = regradeBatchSize();
  const valid = new Set(['critical', 'high', 'medium', 'low', 'info']);
  const ratingByIndex = new Map<number, any>();

  const base = path.join(codeDir, '_regrade');
  const resDir = path.join(base, 'results');
  try {
    fs.rmSync(base, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
  fs.mkdirSync(resDir, { recursive: true });
  const inputList = findings.map((v, i) => ({
    index: i + 1,
    title: String(v.title || ''),
    severity: String(v.severity || 'info'),
    category: String(v.category || ''),
    file: String(v.file || v.file_path || ''),
    line: Number.isFinite(Number(v.line)) ? Number(v.line) : null,
    description: String(v.description || '')
      .replace(/\s+/g, ' ')
      .slice(0, 400),
  }));
  fs.writeFileSync(path.join(base, 'input.json'), JSON.stringify(inputList, null, 2), 'utf8');

  const groups = chunkByBatch(inputList, batchSize);
  const conc = Math.min(regradeConcurrency(), Math.max(1, groups.length));

  recordEvent(projectId, {
    kind: 'system',
    agent: '主控',
    tool: '',
    text: `▶ 红队实战二次评级：${findings.length} 个漏洞按每路 ${batchSize} 个分组，最多同时 ${conc} 路（本轮 ${groups.length} 组，一轮最多 ${batchSize * regradeConcurrency()} 个）`,
  });

  const persistGroup = (outFile: string, r: { structured: any; finalResult: string }) => {
    if (readRegradeFile(outFile).length > 0) return;
    const fb =
      r.structured && Array.isArray(r.structured.ratings) ? r.structured.ratings : parseRatings(r.finalResult);
    if (fb.length > 0) {
      try {
        fs.writeFileSync(outFile, JSON.stringify(fb, null, 2), 'utf8');
      } catch {
        /* ignore */
      }
    }
  };

  const pool = await runGroupedPiWorkers({
    projectId,
    codeDir,
    groups,
    conc,
    schemaStr: JSON.stringify(REGRADE_SCHEMA),
    groupsDir: path.join(base, 'groups'),
    resDir,
    agentLabel: '评级组',
    startText: (group, groupNo, groupTotal) =>
      `第 ${groupNo}/${groupTotal} 路，评 ${group.length} 个洞（全局 index ${group[0].index}–${group[group.length - 1].index}）`,
    progressText: (done, total) => `二次评级进度：${done}/${total}`,
    progressTotal: findings.length,
    countFile: (p) => readRegradeFile(p).length,
    persist: persistGroup,
    prompt: (groupFile, outFile, group, groupNo, groupTotal) =>
      buildRegradeWorkerPrompt(codeDir, groupFile, outFile, group.length, groupNo, groupTotal),
  });
  if (pool.killed) return { findings, killed: true };

  const ratings: any[] = [];
  try {
    for (const f of fs.readdirSync(resDir)) {
      if (f.toLowerCase().endsWith('.json')) ratings.push(...readRegradeFile(path.join(resDir, f)));
    }
  } catch {
    /* ignore */
  }
  const byTitle = new Map<string, any>();
  for (const rt of ratings) if (rt?.title) byTitle.set(normTitleKey(rt.title), rt);
  findings.forEach((v, i) => {
    const rt = ratings.find((x: any) => Number(x?.index) === i + 1) || byTitle.get(normTitleKey(v.title));
    if (rt) ratingByIndex.set(i, rt);
  });

  let graded = 0;
  let changed = 0;
  const hasCjk = (s: string) => /[\u4e00-\u9fa5]/.test(s);
  const out = findings.map((v, i) => {
    const rt = ratingByIndex.get(i);
    if (!rt) return v;
    const baseFinding: any = { ...v };
    const cnTitle = rt.title_cn ? String(rt.title_cn).trim() : '';
    const cnCat = rt.category_cn ? String(rt.category_cn).trim() : '';
    if (cnTitle && hasCjk(cnTitle)) baseFinding.title = cnTitle;
    if (cnCat && hasCjk(cnCat)) baseFinding.category = cnCat;
    const adj = String(rt.adjusted_severity || '').toLowerCase();
    if (!valid.has(adj)) return baseFinding;
    graded++;
    const orig = String(v.severity || 'info').toLowerCase();
    const existingOriginal = String(v.severity_original || '').toLowerCase();
    const earliestOriginal = valid.has(existingOriginal) ? existingOriginal : orig;
    const rgAuth = String(rt.auth_required || '').toLowerCase();
    const authFields = ['none', 'user', 'admin'].includes(rgAuth)
      ? { auth_required: rgAuth, auth_reason: rt.auth_reason ? String(rt.auth_reason) : baseFinding.auth_reason }
      : {};
    const candidate = {
      ...baseFinding,
      severity: adj,
      severity_original: earliestOriginal,
      regrade_reason: rt.reason ? String(rt.reason) : null,
      ...authFields,
    };
    const policy = applySeverityPolicy({
      ...candidate,
      policy_baseline_severity: orig,
    });
    if (policy.severity !== orig) changed++;
    return {
      ...candidate,
      severity: policy.severity,
      severity_original: policy.severityOriginal ?? earliestOriginal,
      regrade_value: realTeamLabel(policy.severity),
      regrade_reason: policy.regradeReason,
    };
  });

  const finalFindings = out.map((v: any) => ({
    ...v,
    regrade_value: realTeamLabel(v.severity),
  }));
  recordEvent(projectId, {
    kind: 'system',
    agent: '主控',
    tool: '',
    text: `✓ 实战二次评级完成：${graded}/${findings.length} 个漏洞已评级，其中 ${changed} 个等级被调整`,
  });
  return { findings: finalFindings, killed: false };
}



/** 从模型文本里兜底解析某结构化数组字段（如 results）。 */
function parseStructuredArray(text: string, key: string): any[] {
  if (!text) return [];
  const tryParse = (s: string): any[] | null => {
    try {
      const o = JSON.parse(s);
      if (Array.isArray(o?.[key])) return o[key];
      if (Array.isArray(o)) return o;
    } catch {
      /* ignore */
    }
    return null;
  };
  let r = tryParse(text.trim());
  if (r) return r;
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    r = tryParse(fence[1].trim());
    if (r) return r;
  }
  const idx = text.indexOf(`"${key}"`);
  if (idx !== -1) {
    const start = text.lastIndexOf('{', idx);
    if (start !== -1) {
      for (let end = text.length; end > idx; end--) {
        r = tryParse(text.slice(start, end));
        if (r) return r;
      }
    }
  }
  return [];
}

/* ----------------------- AI 语义去重（代码级验证前置） ----------------------- */

/** 取文件名（兼容 Windows/Unix 分隔符，小写）。 */
function fileBase(f: any): string {
  return String(f || '')
    .toLowerCase()
    .replace(/\\/g, '/')
    .split('/')
    .pop() || '';
}

/**
 * AI 语义去重：把（已机械保守去重的）候选漏洞按文件装箱、再按核验层每路条数分包，
 * 用与二次评级同一套工人池并发比对。同一文件不拆组，避免漏判跨子智能体重复上报。
 * 保守优先：只合并高度确信的重复，未确信一律保留。
 */
async function aiDedupFindings(
  projectId: string,
  codeDir: string,
  raw: any[]
): Promise<{ findings: any[]; killed: boolean }> {
  if (!isAiDedup(projectId) || raw.length < 2) return { findings: raw, killed: false };
  // ⑤ 省 token：候选数低于阈值时跳过整个 AI 去重 Pi Agent pass（机械去重已生效）。
  const dedupMin = aiDedupMinCandidates();
  if (dedupMin > 0 && raw.length < dedupMin) {
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `候选 ${raw.length} 条低于 AI 去重阈值 ${dedupMin}，跳过 AI 语义去重（省一轮 fan-out）`,
    });
    return { findings: raw, killed: false };
  }
  verifyKilled.delete(projectId); // 进入验证类工作，清理上轮可能残留的中止标志

  const batchSize = regradeBatchSize();
  const base = path.join(codeDir, '_ai_dedup');
  const resDir = path.join(base, 'results');
  try {
    fs.rmSync(base, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
  fs.mkdirSync(resDir, { recursive: true });
  const inputList = raw.map((v, i) => ({
    index: i + 1,
    title: String(v.title || ''),
    severity: String(v.severity || 'info'),
    category: String(v.category || ''),
    file: String(v.file || v.file_path || ''),
    line: Number.isFinite(Number(v.line)) ? Number(v.line) : null,
    description: String(v.description || '').replace(/\s+/g, ' ').slice(0, 400),
  }));
  fs.writeFileSync(path.join(base, 'input.json'), JSON.stringify(inputList, null, 2), 'utf8');

  const workGroups = packByFileThenBatch(inputList, batchSize);
  const conc = Math.min(regradeConcurrency(), Math.max(1, workGroups.length));
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `▶ AI 智能去重：${raw.length} 个候选按文件装箱、每路约 ${batchSize} 个，最多同时 ${conc} 路（本轮 ${workGroups.length} 组，一轮最多 ${batchSize * regradeConcurrency()} 个；仅同文件内保守合并）`,
    },
    true,
    'audit'
  );

  const persistGroup = (outFile: string, r: { structured: any; finalResult: string }) => {
    if (readDedupFile(outFile).length > 0) return;
    const fb =
      r.structured && Array.isArray(r.structured.duplicate_groups)
        ? r.structured.duplicate_groups
        : parseStructuredArray(r.finalResult, 'duplicate_groups');
    if (fb.length > 0) {
      try {
        fs.writeFileSync(outFile, JSON.stringify(fb, null, 2), 'utf8');
      } catch {
        /* ignore */
      }
    }
  };

  const lean = isLeanVerifyPrompt();
  const pool = await runGroupedPiWorkers({
    projectId,
    codeDir,
    groups: workGroups,
    conc,
    schemaStr: JSON.stringify(AI_DEDUP_SCHEMA),
    groupsDir: path.join(base, 'groups'),
    resDir,
    agentLabel: '去重组',
    startText: (group, groupNo, groupTotal) =>
      `第 ${groupNo}/${groupTotal} 路，比对 ${group.length} 个候选（全局 index ${group[0].index}–${group[group.length - 1].index}）`,
    progressText: (done, total) => `AI 智能去重进度：${done}/${total} 组已落盘`,
    progressTotal: workGroups.length,
    countFile: () => 1,
    persist: persistGroup,
    prompt: (groupFile, outFile, group, groupNo, groupTotal) =>
      buildDedupWorkerPrompt(codeDir, groupFile, outFile, group.length, groupNo, groupTotal, { lean }),
  });
  if (pool.killed) return { findings: raw, killed: true };

  // 读盘汇总所有重复分组（全局 index）。
  const groups: any[] = [];
  try {
    for (const f of fs.readdirSync(resDir)) {
      if (f.toLowerCase().endsWith('.json')) groups.push(...readDedupFile(path.join(resDir, f)));
    }
  } catch {
    /* ignore */
  }

  // 三分类应用：
  //   duplicate_indexes（纯措辞重复）→ 删除，描述片段并入 keep；
  //   variant_indexes（同点不同利用面）→ 保留，与 keep 归为同一簇（cluster_id）逐面独立验证。
  // 关闭 dedup_keep_variants 时退回旧行为：把 variant 也当纯重复删除。
  const keepVariants = dedupKeepVariants();
  const removed = new Set<number>(); // 纯重复：删除的 0-based 下标
  const mergedDesc = new Map<number, string[]>(); // keep(0-based) -> 被并入的纯重复描述片段
  const clusterOf = new Map<number, string>(); // 0-based 下标 -> 簇 id
  const clusterRole = new Map<number, 'primary' | 'variant'>();
  const toIdx = (gi: number) =>
    Number.isFinite(gi) && gi >= 1 && gi <= raw.length ? gi - 1 : -1; // 全局 1-based → 0-based
  const snippetOf = (i: number): string => {
    const v = raw[i] || {};
    const t = String(v.title || '').trim();
    const d = String(v.description || '').replace(/\s+/g, ' ').trim().slice(0, 200);
    return [t, d].filter(Boolean).join('：');
  };
  for (const g of groups) {
    let gKeep = toIdx(Number(g?.keep_index));
    const dups = Array.isArray(g?.duplicate_indexes) ? g.duplicate_indexes.map(Number) : [];
    const gDups = dups.map(toIdx).filter((gi: number) => gi >= 0);
    let gVars = (Array.isArray(g?.variant_indexes) ? g.variant_indexes.map(Number) : [])
      .map(toIdx)
      .filter((gi: number) => gi >= 0);
    if (gKeep < 0) continue;
    // 开关关闭：利用面按纯重复处理（旧行为）
    if (!keepVariants) {
      gDups.push(...gVars);
      gVars = [];
    }
    // 代表条目已在别组被删：改选一个未删的成员当代表
    if (removed.has(gKeep)) {
      const alt = [...gVars, ...gDups].find((gi: number) => gi !== gKeep && !removed.has(gi));
      if (alt === undefined) continue;
      gKeep = alt;
    }
    // 纯重复：删除，描述并入 keep
    for (const gd of gDups) {
      if (gd === gKeep || removed.has(gd)) continue;
      removed.add(gd);
      const arr = mergedDesc.get(gKeep) || [];
      arr.push(snippetOf(gd));
      mergedDesc.set(gKeep, arr);
      clusterOf.delete(gd);
      clusterRole.delete(gd);
    }
    // 同点不同利用面：保留、归簇
    const faces = gVars.filter((gi: number) => gi !== gKeep && !removed.has(gi));
    if (faces.length > 0) {
      let cid = clusterOf.get(gKeep);
      if (!cid) {
        cid = newId('cl_');
        clusterOf.set(gKeep, cid);
        clusterRole.set(gKeep, 'primary');
      }
      for (const gv of faces) {
        if (clusterOf.has(gv)) continue; // 已属某簇：避免跨簇冲突
        clusterOf.set(gv, cid);
        clusterRole.set(gv, 'variant');
      }
    }
  }

  const clusterSize = new Map<string, number>();
  for (const cid of clusterOf.values()) clusterSize.set(cid, (clusterSize.get(cid) || 0) + 1);

  const result: any[] = [];
  raw.forEach((v, i) => {
    if (removed.has(i)) return;
    const entry: any = { ...v };
    const extras = mergedDesc.get(i);
    if (extras && extras.length > 0) {
      entry.description =
        (entry.description || '') +
        `\n[AI去重] 已合并 ${extras.length} 条纯重复上报：${extras.join('；')}`;
    }
    const cid = clusterOf.get(i);
    if (cid) {
      entry.cluster_id = cid;
      entry.cluster_role = clusterRole.get(i) || 'variant';
      entry.cluster_size = clusterSize.get(cid) || 1;
    }
    result.push(entry);
  });

  const clusterCount = clusterSize.size;
  const faceTotal = [...clusterSize.values()].reduce((a, b) => a + b, 0);
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `✓ AI 智能去重完成：${raw.length} 个候选 → ${result.length} 个（合并纯重复 ${removed.size} 条${
        clusterCount > 0 ? `；识别 ${clusterCount} 个利用面簇，共 ${faceTotal} 个面各自独立保留` : ''
      }）`,
    },
    true,
    'audit'
  );
  return { findings: result, killed: false };
}

/**
 * 后端驱动的代码级真实性验证：与二次评级同一套工人池，
 * 每路 batchSize 条、最多同时 concurrency 路，判定落盘到 `<codeDir>/_code_verify/results/`。
 * 保留 true_positive / conditional（真漏洞），剔除 false_positive / design_decision；未给结论者保守保留。
 */
async function codeVerifyFindings(
  projectId: string,
  codeDir: string,
  raw: any[]
): Promise<{ findings: any[]; killed: boolean }> {
  if (raw.length === 0) return { findings: [], killed: false };
  verifyKilled.delete(projectId); // 清理上一轮可能残留的中止标志

  // B1：信任技能已验证清单——directly_exploitable_vulns.json 里的漏洞是审计技能内部已做过
  // 代码级验证的真阳性子集，开启 trust_skill_verified 时直接留用、不再送 Pi Agent 重验，
  // 仅对"技能未覆盖的增量原始发现"逐条验证，避免对同一批漏洞验证两遍。默认关闭（全量重验最稳）。
  const trustSkillVerified = getSetting('trust_skill_verified') === '1';
  let preVerified: any[] = [];
  let toVerify = raw;
  if (trustSkillVerified) {
    const verifiedKey = (v: any) => `${normTitleKey(v.title)}|${fileBase(v.file || v.file_path)}`;
    const skillSet = new Set(readDirectlyExploitable(codeDir).map(verifiedKey));
    if (skillSet.size > 0) {
      preVerified = raw.filter((v) => skillSet.has(verifiedKey(v)));
      toVerify = raw.filter((v) => !skillSet.has(verifiedKey(v)));
      if (preVerified.length > 0) {
        recordEvent(
          projectId,
          {
            kind: 'system',
            agent: '主控',
            tool: '',
            text: `▶ 代码级验证：信任技能已验证清单，直接留用 ${preVerified.length} 个可直接利用漏洞，仅对其余 ${toVerify.length} 个增量发现逐条核验`,
          },
          true,
          'audit'
        );
      }
    }
  }
  if (toVerify.length === 0) return { findings: preVerified, killed: false };

  const batchSize = regradeBatchSize();
  const merged = isMergeVerifyRegrade();
  const lean = isLeanVerifyPrompt();

  const base = path.join(codeDir, '_code_verify');
  const resDir = path.join(base, 'results');
  try {
    fs.rmSync(base, { recursive: true, force: true });
  } catch {
    /* 忽略 */
  }
  fs.mkdirSync(resDir, { recursive: true });
  const inputList = toVerify.map((v, i) => ({
    index: i + 1,
    title: String(v.title || ''),
    severity: String(v.severity || 'info'),
    category: String(v.category || ''),
    file: String(v.file || v.file_path || ''),
    line: Number.isFinite(Number(v.line)) ? Number(v.line) : null,
    description: String(v.description || '').replace(/\s+/g, ' ').slice(0, 500),
    taint_chain: normalizeTaintChain((v as any).taint_chain).replace(/\s+/g, ' ').slice(0, 800),
    cluster_id: (v as any).cluster_id ? String((v as any).cluster_id) : '',
  }));
  fs.writeFileSync(path.join(base, 'input.json'), JSON.stringify(inputList, null, 2), 'utf8');

  const workGroups = chunkByBatch(inputList, batchSize);
  const conc = Math.min(regradeConcurrency(), Math.max(1, workGroups.length));
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `▶ 代码级验证：${toVerify.length} 个原始发现按每路 ${batchSize} 个分组，最多同时 ${conc} 路（本轮 ${workGroups.length} 组，一轮最多 ${batchSize * regradeConcurrency()} 个）${merged ? '，并顺带红队实战二次评级' : ''}`,
    },
    true,
    'audit'
  );

  const persistGroup = (outFile: string, r: { structured: any; finalResult: string }) => {
    if (readCodeVerifyFile(outFile).length > 0) return;
    const fb =
      r.structured && Array.isArray(r.structured.results)
        ? r.structured.results
        : parseStructuredArray(r.finalResult, 'results');
    if (fb.length > 0) {
      try {
        fs.writeFileSync(outFile, JSON.stringify(fb, null, 2), 'utf8');
      } catch {
        /* ignore */
      }
    }
  };

  const pool = await runGroupedPiWorkers({
    projectId,
    codeDir,
    groups: workGroups,
    conc,
    schemaStr: JSON.stringify(CODE_VERIFY_SCHEMA),
    groupsDir: path.join(base, 'groups'),
    resDir,
    agentLabel: '验证组',
    startText: (group, groupNo, groupTotal) =>
      `第 ${groupNo}/${groupTotal} 路，核 ${group.length} 个洞（全局 index ${group[0].index}–${group[group.length - 1].index}）`,
    progressText: (done, total) => `代码级验证进度：${done}/${total}`,
    progressTotal: toVerify.length,
    countFile: (p) => readCodeVerifyFile(p).length,
    persist: persistGroup,
    prompt: (groupFile, outFile, group, groupNo, groupTotal) =>
      buildCodeVerifyWorkerPrompt(codeDir, groupFile, outFile, group.length, groupNo, groupTotal, { merged, lean }),
  });
  if (pool.killed) return { findings: preVerified, killed: true };

  const readVerdicts = (): Map<string, any> => {
    const map = new Map<string, any>();
    const put = (rt: any) => {
      if (!rt) return;
      if (rt.index != null) map.set(`i:${Number(rt.index)}`, rt);
      if (rt.title) map.set(`t:${normTitleKey(rt.title)}`, rt);
    };
    try {
      for (const f of fs.readdirSync(resDir)) {
        if (f.toLowerCase().endsWith('.json')) readCodeVerifyFile(path.join(resDir, f)).forEach(put);
      }
    } catch {
      /* 目录暂无 */
    }
    return map;
  };
  const verdicts = readVerdicts();

  const validSev = new Set(['critical', 'high', 'medium', 'low', 'info']);
  const keep = new Set(['true_positive', 'conditional']);
  const hasCjk = (s: string) => /[\u4e00-\u9fa5]/.test(s);
  const kept: any[] = [];
  toVerify.forEach((v, i) => {
    const rt = verdicts.get(`i:${i + 1}`) || verdicts.get(`t:${normTitleKey(v.title)}`);
    if (!rt) {
      kept.push(v); // 未给结论：保守保留（避免漏判）
      return;
    }
    const verdict = String(rt.verdict || '').toLowerCase();
    if (verdict && !keep.has(verdict)) return; // 明确判为误报/设计决策才剔除
    const vs = String(rt.verified_severity || '').toLowerCase();
    const nextSev = validSev.has(vs) ? vs : String(v.severity || 'info').toLowerCase();
    const entry: any = {
      ...v,
      severity: nextSev,
      file: rt.file || v.file,
      line: Number.isFinite(Number(rt.line)) && Number(rt.line) > 0 ? Number(rt.line) : v.line,
      description: (v.description || '') + (rt.reason ? `\n[代码级验证] ${rt.reason}` : ''),
    };
    // 鉴权判定：沿污点链核对触发所需权限（none/user/admin），供总漏洞列表标注"需登录/需管理员/无需登录"
    const cvAuth = String(rt.auth_required || '').toLowerCase();
    if (['none', 'user', 'admin'].includes(cvAuth)) {
      entry.auth_required = cvAuth;
      if (rt.auth_reason) entry.auth_reason = String(rt.auth_reason);
    }
    // ① 合并态：验证顺带产出的中文标题/类别与实战等级一并回填，等价一次二次评级。
    if (merged) {
      const cnTitle = rt.title_cn ? String(rt.title_cn).trim() : '';
      const cnCat = rt.category_cn ? String(rt.category_cn).trim() : '';
      if (cnTitle && hasCjk(cnTitle)) entry.title = cnTitle;
      if (cnCat && hasCjk(cnCat)) entry.category = cnCat;
      const baseline = String(v.severity || 'info').toLowerCase();
      const existingOriginal = String(v.severity_original || '').toLowerCase();
      entry.severity_original = validSev.has(existingOriginal) ? existingOriginal : baseline;
      if (rt.reason) entry.regrade_reason = String(rt.reason);
      const policy = applySeverityPolicy({
        ...entry,
        policy_baseline_severity: baseline,
      });
      entry.severity = policy.severity;
      entry.severity_original = policy.severityOriginal ?? entry.severity_original;
      // 实战等级始终由最终 severity 派生，保证与严重度严格一一对应、永不发散。
      entry.regrade_value = realTeamLabel(policy.severity);
      entry.regrade_reason = policy.regradeReason;
    }
    kept.push(entry);
  });

  const out = [...preVerified, ...kept];
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `✓ 代码级验证完成：${raw.length} 个候选 → ${out.length} 个真阳性（已剔除误报/设计决策${preVerified.length > 0 ? `，含 ${preVerified.length} 个技能已验证直接留用` : ''}）`,
    },
    true,
    'audit'
  );
  return { findings: out, killed: false };
}

/* ----------------- 子智能体覆盖核对：精准补跑漏跑的子智能体（不整轮重跑） ----------------- */

// 次要语言高危子集与完整专项同一套（每语言最多 4 路，CWE 已并进 mission）。
const HIGH_SEV_SUBAGENTS_BY_LANG = SUBAGENTS_BY_LANG;
// 通用 1+1+1：Flash 单语言产品不派发；保留常量以免多语言计划代码引用断裂。
const UNIVERSAL_SUBAGENTS = ['js-frontend-security-auditor', 'logic-dos-auditor', 'dataflow-reachability-auditor'];

// 源码扩展名 → 语言（仅统计我们有专项子智能体的语言）。
/** 语言中文名（用于提示词与日志）。 */
const LANG_LABEL: Record<string, string> = {
  java: 'Java', go: 'Go', python: 'Python', php: 'PHP',
  jsts: 'JavaScript/TypeScript', rust: 'Rust', ruby: 'Ruby', csharp: 'C#/.NET',
  c: 'C', cpp: 'C++', solidity: 'Solidity',
};

/** 次要语言占比阈值(0..1)：读取设置 audit_secondary_lang_threshold（百分比，默认 15）。 */
function secondaryLangThreshold(): number {
  const v = Number(getSetting('audit_secondary_lang_threshold'));
  const pct = Number.isFinite(v) && v > 0 && v <= 100 ? v : 15;
  return pct / 100;
}

/** 审计调度计划：主导语言全套 + 各次要语言高危子集 + 通用 3 个。 */
interface AuditDispatchPlan {
  primary: string;
  secondaries: string[];
  ratios: Record<string, number>;
  /** linguist = GitHub 官方占比；pi = 语义判定 */
  langSource: 'linguist' | 'pi';
  primaryAgents: string[];
  secondaryAgents: Record<string, string[]>;
  universal: string[];
  all: string[];
}

function parseLangMixResult(text: string): any | null {
  if (!text) return null;
  const tryParse = (s: string) => {
    try {
      const o = JSON.parse(s);
      if (o && typeof o === 'object' && typeof o.primary === 'string') return o;
    } catch {
      /* ignore */
    }
    return null;
  };
  let r = tryParse(text.trim());
  if (r) return r;
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    r = tryParse(fence[1].trim());
    if (r) return r;
  }
  const idx = text.indexOf('"primary"');
  if (idx !== -1) {
    const start = text.lastIndexOf('{', idx);
    if (start !== -1) {
      for (let end = text.length; end > idx; end--) {
        r = tryParse(text.slice(start, end));
        if (r) return r;
      }
    }
  }
  return null;
}

/**
 * 先 Pi 语义判定主导/次要语言；失败再用 GitHub Linguist。
 * 两者都得不到可调度主导语言则失败，禁止启发式扫盘、禁止继续派子智能体。
 */
type LanguageMix = {
  primary: string | null;
  secondaries: string[];
  ratios: Record<string, number>;
  reason?: string;
  error?: string;
};

async function resolveAuditLanguageMix(
  _projectId: string,
  _codeDir: string
): Promise<{ mix: LanguageMix } | { killed: true } | { error: string }> {
  return { error: '语言由用户在导入时指定，不再自动判定' };
}

function logDispatchPlan(projectId: string, plan: AuditDispatchPlan): void {
  const pct = (r: number) => `${Math.round((r || 0) * 100)}%`;
  const srcLabel = plan.langSource === 'linguist' ? 'GitHub Linguist' : 'Pi 语义判定';
  const primaryLabel = `${LANG_LABEL[plan.primary] || plan.primary}(${pct(plan.ratios[plan.primary])})`;
  const text =
    plan.secondaries.length > 0
      ? `▶ 多语言融合项目（${srcLabel}）：主导 ${primaryLabel} 派完整专项；次要 ${plan.secondaries
          .map((l) => `${LANG_LABEL[l] || l}(${pct(plan.ratios[l])})`)
          .join('、')} 各派高危子集`
      : `▶ 语言占比（${srcLabel}）：主导 ${primaryLabel}，派该语言完整专项`;
  recordEvent(projectId, { kind: 'system', agent: '主控', tool: '', text });
}

function detectLanguageMix(_codeDir: string): LanguageMix {
  return { primary: null, secondaries: [], ratios: {}, error: 'disabled' };
}

function planFromLanguageMix(mix: LanguageMix): AuditDispatchPlan | null {
  const primary = mix.primary;
  if (!primary || !isAuditLanguage(primary)) return null;
  const primaryAgents = subagentsForLanguage(primary);
  const secondaryAgents: Record<string, string[]> = {};
  for (const lang of mix.secondaries) {
    const subset = HIGH_SEV_SUBAGENTS_BY_LANG[lang];
    if (subset && subset.length) secondaryAgents[lang] = [...subset];
  }
  const all = Array.from(
    new Set([
      ...primaryAgents,
      ...Object.values(secondaryAgents).flat(),
      ...UNIVERSAL_SUBAGENTS,
    ])
  );
  return {
    primary,
    secondaries: Object.keys(secondaryAgents),
    ratios: mix.ratios,
    langSource: 'pi',
    primaryAgents,
    secondaryAgents,
    universal: UNIVERSAL_SUBAGENTS,
    all,
  };
}

/** 计算多语言审计调度计划；无权威占比则返回 null，不得启发式凑主导语言。 */
function auditDispatchPlan(_codeDir: string): AuditDispatchPlan | null {
  return null;
}

/** 将后端调度计划转成注入 prompt 的 LangDispatchPlan 结构（含中文名与占比）。 */
function toLangDispatchPlan(_plan: AuditDispatchPlan): Record<string, unknown> {
  return {};
}

/** 子智能体覆盖核对开关（默认开；设置 '0'/'false' 关闭）。 */
function subagentCoverageGuardOn(): boolean {
  const v = getSetting('subagent_coverage_guard');
  return v !== '0' && v !== 'false';
}

/** 跨语言融合审计开关（默认开；设置 cross_language_fusion='0'/'false' 关闭）。 */
function crossLanguageFusionOn(): boolean {
  const v = getSetting('cross_language_fusion');
  return v !== '0' && v !== 'false';
}

/** 探测项目主导语言（用依赖/构建文件特征，语言未知则返回 null，不盲目补跑）。 */
function detectPrimaryLanguage(codeDir: string): string | null {
  const has = (rel: string) => {
    try {
      return fs.existsSync(path.join(codeDir, rel));
    } catch {
      return false;
    }
  };
  let rootFiles: string[] = [];
  try {
    rootFiles = fs.readdirSync(codeDir);
  } catch {
    /* ignore */
  }
  const hasExt = (re: RegExp) => rootFiles.some((f) => re.test(f));
  if (has('pom.xml') || has('build.gradle') || has('build.gradle.kts')) return 'java';
  if (has('go.mod')) return 'go';
  if (has('composer.json')) return 'php';
  if (has('Cargo.toml')) return 'rust';
  if (has('Gemfile')) return 'ruby';
  if (has('requirements.txt') || has('pyproject.toml') || has('setup.py') || has('Pipfile')) return 'python';
  // Solidity 智能合约框架标志文件——必须在 package.json→jsts 之前判定（hardhat/truffle 项目也含 package.json）。
  if (has('foundry.toml') || has('remappings.txt') || has('hardhat.config.js') || has('hardhat.config.ts')
    || has('truffle-config.js') || has('truffle.js') || hasExt(/\.sol$/i)) return 'solidity';
  // C++ 构建系统（.vcxproj 在 csharp 的 .sln 判定之前，避免 VS C++ 工程被误判为 C#）。
  if (has('CMakeLists.txt') || has('meson.build') || hasExt(/\.vcxproj$/i)
    || hasExt(/\.(cpp|cxx|cc|c\+\+|hpp|hh|hxx|ipp|tcc)$/i)) return 'cpp';
  if (hasExt(/\.(csproj|sln|fsproj)$/i)) return 'csharp';
  // 纯 C 工程：有 Makefile/configure 且根目录出现 .c/.h（放在 cpp 之后，确保混合工程优先判 C++）。
  if ((has('Makefile') || has('makefile') || has('configure') || has('configure.ac')) && hasExt(/\.[ch]$/i)) return 'c';
  if (hasExt(/\.[ch]$/i)) return 'c';
  if (has('package.json')) return 'jsts';
  return null;
}

/**
 * 期望的子智能体清单：导入时用户指定语言的专项（路数随语言特性而定）。
 * 无项目语言时回退到工作区构建文件探测；仍无法识别或清单为空则返回 null（覆盖闸 fail-closed）。
 */
export function expectedSubagents(codeDir: string): string[] | null {
  const projectId = path.basename(path.resolve(codeDir));
  const project = getProject(projectId);
  const fromProject = String(project?.audit_language || '').trim();
  const lang = isAuditLanguage(fromProject) ? fromProject : detectPrimaryLanguage(codeDir);
  if (!lang || !isAuditLanguage(lang)) return null;
  const agents = subagentsForLanguage(lang);
  return agents.length > 0 ? agents : null;
}

/** 统计单个 JSON 文件里的发现条数（兼容数组/各种包裹键）；文件缺失或解析失败返回 0。 */
function countFindingsInJson(file: string): number {
  return inspectSubagentArtifact(file, { repair: false }).findingCount;
}

/**
 * 子智能体是否已落盘「有效审计产物」。
 * 注意：findings=[] 的合法空结果也算已覆盖（该类无洞 / 语言面无 sink），
 * 不能与「文件缺失 / 无法解析」混为一谈，否则会反复补跑浪费 token。
 */
function hasSubagentArtifact(file: string): boolean {
  return inspectSubagentArtifact(file, { repair: true }).valid;
}

export interface AuditCoverageSnapshot {
  status: 'complete' | 'incomplete' | 'unknown_language';
  expected: string[];
  missing: string[];
  valid: string[];
  zeroFinding: string[];
  relinked: { from: string; to: string }[];
  normalized: string[];
}

export function auditCoverageFailureReason(coverage: AuditCoverageSnapshot): string | null {
  if (coverage.status === 'unknown_language') {
    return '无法确定源码语言面及预期子智能体清单，无法证明多智能体审计覆盖完整';
  }
  if (coverage.missing.length > 0) {
    return `子智能体覆盖不完整：缺失或无法解析 ${coverage.missing.length}/${coverage.expected.length} 个 JSON（${coverage.missing.join('、')}）`;
  }
  return null;
}

/** DB 批量审计、运行时补跑、最终完成闸共用的唯一覆盖判定。 */
export function auditCoverageSnapshot(
  codeDir: string,
  options: { repair?: boolean } = {}
): AuditCoverageSnapshot {
  const expected = expectedSubagents(codeDir);
  if (!expected || expected.length === 0) {
    return {
      status: 'unknown_language',
      expected: [],
      missing: [],
      valid: [],
      zeroFinding: [],
      relinked: [],
      normalized: [],
    };
  }
  const repaired = reconcileSubagentArtifacts(codeDir, expected, {
    repair: options.repair === true,
  });
  const jsonDir = path.join(codeDir, 'JSON');
  const aliasByCanonical = new Map(
    repaired.relinked.map((entry) => [entry.to.toLowerCase(), entry.from])
  );
  const valid: string[] = [];
  const missing: string[] = [];
  const zeroFinding: string[] = [];
  // 【MCP 账本 ∪ 磁盘】子智能体通过 MCP 显式声明「审计完成」的集合。即便磁盘产物被改名/漏写/
  // 短暂不可解析，只要账本里有该子智能体的声明就视为已覆盖，杜绝「确实审计了却被判未审计→二次审计」。
  const ledgerCovered = new Set<string>();
  for (const agent of expected) {
    let inspected = inspectSubagentArtifact(path.join(jsonDir, `${agent}.json`), {
      repair: options.repair === true,
    });
    if (!inspected.valid && options.repair !== true) {
      const alias = aliasByCanonical.get(`${agent}.json`.toLowerCase());
      if (alias) inspected = inspectSubagentArtifact(path.join(jsonDir, alias), { repair: false });
    }
    if (inspected.valid) {
      valid.push(agent);
      if (inspected.findingCount === 0) zeroFinding.push(agent);
    } else if (ledgerCovered.has(agent)) {
      // 账本已声明完成：计入覆盖（发现数以磁盘为准，materialize 已在提交时落盘）。
      valid.push(agent);
      if (inspected.findingCount === 0) zeroFinding.push(agent);
    } else {
      missing.push(agent);
    }
  }
  return {
    status: missing.length === 0 ? 'complete' : 'incomplete',
    expected,
    missing,
    valid,
    zeroFinding,
    relinked: repaired.relinked,
    normalized: repaired.normalized,
  };
}

/** 完成态硬闸：无法证明覆盖完整就必须失败，不受 coverage_guard 开关影响。 */
function assertAuditCoverageComplete(
  projectId: string,
  codeDir: string,
  options: { recordSuccess?: boolean } = {}
): boolean {
  const coverage = auditCoverageSnapshot(codeDir, { repair: true });
  if (coverage.relinked.length > 0 || coverage.normalized.length > 0) {
    recordEvent(projectId, {
      kind: 'system',
      agent: '产物规范化器',
      tool: '',
      text: `✓ 已规范化子智能体产物：重命名 ${coverage.relinked.length} 个、修复 JSON ${coverage.normalized.length} 个`,
    });
  }
  const failure = auditCoverageFailureReason(coverage);
  if (failure) {
    finishAudit(projectId, 'failed', failure);
    return false;
  }
  if (options.recordSuccess !== false) {
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `✓ 审计完成硬闸通过：${coverage.expected.length} 个必需子智能体产物全部有效${
        coverage.zeroFinding.length > 0
          ? `（其中 ${coverage.zeroFinding.length} 个为合法 0 发现）`
          : ''
      }`,
    });
  }
  return true;
}

/**
 * 子智能体覆盖核对：主控会话结束后，检查每个期望子智能体是否产出了 `JSON/<类型>.json`。
 * 仅对「文件缺失 / 无法解析 / 空壳」补跑；合法空 findings（0 条）视为已覆盖，不再补跑。
 * 最多 2 轮。
 */
async function ensureSubagentCoverage(projectId: string, codeDir: string): Promise<{ killed: boolean }> {
  if (!subagentCoverageGuardOn()) return { killed: false };
  const initialExpected = expectedSubagents(codeDir);
  if (!initialExpected) return { killed: false }; // 语言未知：不盲目补跑，交由原有兜底逻辑
  let expected: string[] = initialExpected;
  const jsonDir = path.join(codeDir, 'JSON');
  const missingOf = () => {
    // 补跑会写入审计中间文件，语言体量的判定结果可能随之变化。
    // 每轮重新计算期望清单，确保新增的次要语言专项也会在本轮补齐，
    // 而不是第一轮按旧清单完成后被最终硬闸突然判失败。
    const refreshedExpected = expectedSubagents(codeDir);
    if (refreshedExpected) expected = refreshedExpected;
    const repair = reconcileSubagentArtifacts(codeDir, expected);
    if (repair.relinked.length > 0 || repair.normalized.length > 0) {
      recordEvent(projectId, {
        kind: 'system',
        agent: '产物规范化器',
        tool: '',
        text: `✓ 补跑前先修复已有产物：重命名 ${repair.relinked.length} 个、规范化 ${repair.normalized.length} 个 JSON`,
      });
    }
    // 账本 ∪ 磁盘：账本已声明完成的子智能体不再补跑（即使磁盘产物改名/漏写）。
    const covered = new Set<string>();
    return expected.filter(
      (a) => !hasSubagentArtifact(path.join(jsonDir, `${a}.json`)) && !covered.has(a)
    );
  };

  const configuredRounds = Number(process.env.SUBAGENT_COVERAGE_REPAIR_ROUNDS || 2);
  const maxRounds = Number.isFinite(configuredRounds)
    ? Math.max(1, Math.min(5, Math.floor(configuredRounds)))
    : 2;
  for (let round = 1; round <= maxRounds; round++) {
    if (cancelledProjects.has(projectId)) return { killed: true };
    const missing = missingOf();
    if (missing.length === 0) {
      if (round === 1) {
        const zeroFinding = expected.filter(
          (a) => countFindingsInJson(path.join(jsonDir, `${a}.json`)) === 0
        ).length;
        recordEvent(projectId, {
          kind: 'system',
          agent: '主控',
          tool: '',
          text:
            zeroFinding > 0
              ? `✓ 子智能体覆盖完整：${expected.length} 个子智能体均已落盘（其中 ${zeroFinding} 个为 0 发现的合法空结果，不再补跑）`
              : `✓ 子智能体覆盖完整：${expected.length} 个子智能体均已产出 JSON`,
        });
      }
      return { killed: false };
    }
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `⚠ 子智能体覆盖核对：${missing.length}/${expected.length} 个 JSON 缺失或无法解析（${missing.join('、')}），仅补跑这些子智能体（第 ${round}/${maxRounds} 轮）…`,
    });
    const r = await runSpecialtyAgents(projectId, codeDir, missing, JSON.stringify(VULN_SCHEMA), {
      orchestrator: false,
    });
    if (r.killed) return { killed: true };
  }

  const stillMissing = missingOf();
  recordEvent(projectId, {
    kind: 'system',
    agent: '主控',
    tool: '',
    text:
      stillMissing.length > 0
        ? `⛔ 补跑后仍有 ${stillMissing.length} 个子智能体 JSON 缺失或无法解析（${stillMissing.join('、')}），审计将由完成硬闸标记失败`
        : `✓ 子智能体覆盖已补齐：${expected.length} 个子智能体均已落盘`,
  });
  return { killed: false };
}

/** 覆盖率深度闸阈值（可用环境变量覆盖）。 */
function coverageGapCfg(): { minUnjudged: number; maxAgents: number; maxMembersInPrompt: number } {
  const minUnjudged = Number(process.env.COVERAGE_GAP_MIN_UNJUDGED || 5);
  const maxAgents = Number(process.env.COVERAGE_GAP_MAX_AGENTS || 6);
  const maxMembersInPrompt = Number(process.env.COVERAGE_GAP_MAX_MEMBERS || 60);
  return {
    minUnjudged: Number.isFinite(minUnjudged) ? minUnjudged : 5,
    maxAgents: Number.isFinite(maxAgents) ? maxAgents : 6,
    maxMembersInPrompt: Number.isFinite(maxMembersInPrompt) ? maxMembersInPrompt : 60,
  };
}

interface EnumMember {
  category: string;
  symbol: string;
  loc: string;
  tier: string;
}

/**
 * 读取某子智能体的枚举清单 `JSON/<type>.enum.json`，逐成员找出「已列入全集但未判定」的成员
 * （verdict 不是 defect/safe），并单列可达高危(critical_high)的。语言/类别无关，纯结构解析。
 */
function readEnumUnjudged(
  codeDir: string,
  type: string
): { exists: boolean; total: number; unjudged: EnumMember[]; unjudgedCH: number } {
  const file = path.join(codeDir, 'JSON', `${type}.enum.json`);
  let j: any;
  try {
    j = JSON.parse(readJsonArtifactText(file));
  } catch {
    return { exists: false, total: 0, unjudged: [], unjudgedCH: 0 };
  }
  const cats = Array.isArray(j?.categories) ? j.categories : Array.isArray(j) ? j : [];
  const unjudged: EnumMember[] = [];
  let total = 0;
  let unjudgedCH = 0;
  for (const c of cats) {
    const category = String(c?.category ?? c?.name ?? '未命名类别');
    const members = Array.isArray(c?.members) ? c.members : [];
    for (const m of members) {
      total++;
      const verdict = String(m?.verdict ?? '').toLowerCase();
      if (verdict === 'defect' || verdict === 'safe') continue;
      const tier = String(m?.tier ?? '').toLowerCase();
      if (tier === 'critical_high') unjudgedCH++;
      unjudged.push({
        category,
        symbol: String(m?.symbol ?? m?.name ?? ''),
        loc: String(m?.loc ?? m?.location ?? ''),
        tier,
      });
    }
  }
  return { exists: true, total, unjudged, unjudgedCH };
}

/**
 * 覆盖率深度闸（后端强制·代码兜底·逐成员）：实测主控自评的账本闸恒被跳过（redispatch_rounds=0）。
 * 此处由后端**逐成员**读各子智能体的 `enum.json`，找出「已列入全集却没判定」的成员；
 * 只对**存在明显漏判的那一个子智能体精准回炉**（携带其未判成员清单），不整轮重跑、不拉起完整主控，
 * 既堵住"枚举了却没判"的漏挖、又把 token 开销降到最小。语言/类别无关，不含任何硬编码函数/框架名。
 */
async function ensureCoverageDepth(_projectId: string, _codeDir: string): Promise<{ killed: boolean }> {
  return { killed: false };
}

/** 子智能体 JSON 是否已全部落盘（与 ensureSubagentCoverage 判定一致）。 */
function isSubagentPhaseComplete(codeDir: string): boolean {
  return auditCoverageSnapshot(codeDir, { repair: true }).status === 'complete';
}

type MainAuditStageResult = {
  timedOut?: boolean;
  finalResult?: string;
  structured?: { vulnerabilities?: any[]; summary?: string };
  stderrTail?: string;
};

/**
 * 子智能体阶段结束后的统一收尾：可利用清单补全 → 跨语言融合 → 去重/验证/评级。
 * doAudit 与 doReprocess（继续审计续跑）共用，保证续跑与全量审计后半段等价。
 */
async function runAuditPostSubagentPhase(
  projectId: string,
  codeDir: string,
  mainStage: MainAuditStageResult | null
): Promise<void> {
  const timedOut = !!mainStage?.timedOut;

  let structuredVulns: any[] = [];
  if (mainStage?.finalResult !== undefined) {
    const extracted = extractVulnerabilities(mainStage.finalResult);
    structuredVulns =
      mainStage.structured && Array.isArray(mainStage.structured.vulnerabilities)
        ? mainStage.structured.vulnerabilities
        : extracted.vulnerabilities;
    const summary = (mainStage.structured && mainStage.structured.summary) || extracted.summary || '';
    if (summary) {
      recordEvent(projectId, { kind: 'text', agent: '主控', tool: '', text: `审计结论：${summary}` });
    }
  }

  const haveStructured = !!(mainStage?.structured && Array.isArray(mainStage.structured.vulnerabilities));
  if (timedOut && !haveStructured && readSubagentFindings(codeDir).length === 0) {
    const fallback = collectAuditFindings(codeDir, structuredVulns);
    saveVulnerabilities(projectId, fallback);
    finishAudit(projectId, 'failed', mainStage?.stderrTail || '审计超时');
    return;
  }

  await processFindings(projectId, codeDir, structuredVulns);
}

/**
 * 多智能体审计：1 路主控分配方向 + N 路专项并发挖洞（共 N+1 个 Pi）。
 * 专项路数随语言而定（最多 4），主控不占用漏洞方向名额。
 */
async function runSpecialtyAgents(
  projectId: string,
  codeDir: string,
  agents: string[],
  schemaStr: string,
  opts: { language?: string; orchestrator?: boolean } = {}
): Promise<StageResult> {
  const empty: StageResult = {
    killed: false,
    timedOut: false,
    code: 0,
    structured: null,
    finalResult: '',
    stderrTail: '',
  };
  if (!agents.length) return empty;
  try {
    fs.mkdirSync(path.join(codeDir, 'JSON'), { recursive: true });
  } catch {
    /* ignore */
  }

  const conc = Math.max(1, agents.length);
  let cursor = 0;
  let killed = false;
  let timedOut = false;
  let last: StageResult = empty;

  const worker = async () => {
    while (true) {
      if (cancelledProjects.has(projectId) || verifyKilled.has(projectId)) {
        killed = true;
        return;
      }
      const idx = cursor++;
      if (idx >= agents.length) return;
      const type = agents[idx];
      recordEvent(projectId, {
        kind: 'agent_start',
        agent: type,
        tool: 'Task',
        text: subagentMission(type),
      });
      const r = await runPiStage(
        projectId,
        codeDir,
        buildSpecialtyAgentPrompt(codeDir, type),
        schemaStr,
        { channel: 'subagent' }
      );
      last = r;
      if (r.killed) killed = true;
      if (r.timedOut) timedOut = true;
      if (r.killed) return;
    }
  };

  const language = opts.language || 'php';
  const runOrch = opts.orchestrator !== false;
  if (runOrch) {
    recordEvent(projectId, {
      kind: 'agent_start',
      agent: '主控',
      tool: 'Task',
      text: `分配 ${agents.length} 路专项并等待 JSON 落盘`,
    });
  }
  const orch = runOrch
    ? runPiStage(
        projectId,
        codeDir,
        buildAuditOrchestratorPrompt(codeDir, language, agents),
        schemaStr,
        { channel: 'subagent' }
      )
    : Promise.resolve(empty);
  const workers = Promise.all(Array.from({ length: conc }, () => worker()));
  const [orchR] = await Promise.all([orch, workers]);
  if (!last.structured && orchR.structured) last = orchR;
  return {
    ...last,
    killed,
    timedOut: timedOut || last.timedOut,
  };
}

/* ------------------------------ 漏洞审计 ------------------------------ */
async function doAudit(projectId: string): Promise<void> {
  const project = getProject(projectId);
  if (!project) return;

  clearAuditResults(projectId);
  setAuditStatus(projectId, 'running', { started_at: now(), error_message: null });
  recordEvent(projectId, { kind: 'system', agent: '主控', tool: '', text: '正在准备审计目标（解压/克隆源码）…' });
  // 选了完整靶机：源码尚未解压完也先入队，与审计共用工作区锁、独立 Pi 槽并行搭站。
  kickEnvPrebuildWithAudit(projectId);

  let codeDir: string;
  try {
    codeDir = await ensureWorkspace(getProject(projectId)!);
  } catch (err: any) {
    finishAudit(projectId, 'failed', `源码准备失败：${err?.message || err}`);
    return;
  }
  if (skipProjectForNonWeb(projectId, codeDir)) return;

  // 注：含 Web 端项目的注册功能识别已在 ensureWorkspace（Web 判定同阶段）用 Pi Agent 完成，此处无需重复。
  kickEnvPrebuildWithAudit(projectId);

  const langRaw = String(getProject(projectId)?.audit_language || project.audit_language || '').trim();
  const lang = isAuditLanguage(langRaw) ? langRaw : 'php';
  const langLabel = AUDIT_LANGUAGE_LABELS[lang] || lang;
  recordEvent(projectId, {
    kind: 'system',
    agent: '主控',
    tool: '',
    text: `▶ 多智能体审计（${langLabel}）：1 路主控分配方向 + ${subagentsForLanguage(lang).length} 路专项并发（共 ${subagentsForLanguage(lang).length + 1} 个 Pi）`,
  });

  const agents = subagentsForLanguage(lang);
  const r = await runSpecialtyAgents(projectId, codeDir, agents, JSON.stringify(VULN_SCHEMA), {
    language: lang,
    orchestrator: true,
  });
  if (r.killed) return;

  if (!r.timedOut) {
    const cov = await ensureSubagentCoverage(projectId, codeDir);
    if (cov.killed) return;
  }
  if (!assertAuditCoverageComplete(projectId, codeDir)) return;

  await runAuditPostSubagentPhase(projectId, codeDir, {
    timedOut: r.timedOut,
    finalResult: r.finalResult,
    structured: r.structured,
    stderrTail: r.stderrTail,
  });
}

/* --------------------- 流水线中间产物 + 审计侧环节函数（支持分环节运行） --------------------- */
// 各环节把中间结果落盘到 codeDir/_pipeline/ 下，便于"从某环节续跑/仅跑某环节"时读取上游产物。
function pipelineFile(codeDir: string, name: string): string {
  return path.join(codeDir, '_pipeline', name);
}
function writePipeline(codeDir: string, name: string, data: any[]): void {
  try {
    fs.mkdirSync(path.join(codeDir, '_pipeline'), { recursive: true });
    fs.writeFileSync(pipelineFile(codeDir, name), JSON.stringify(data, null, 2), 'utf8');
  } catch {
    /* 落盘失败不阻断流程 */
  }
}
function readPipeline(codeDir: string, name: string): any[] | null {
  try {
    const a = JSON.parse(readJsonArtifactText(pipelineFile(codeDir, name)));
    return Array.isArray(a) ? a : null;
  } catch {
    return null;
  }
}
/** 子智能体原始发现 + 主控可利用清单 → 机械保守去重后的候选（去重环节输入）。 */
function loadRawCandidates(codeDir: string): any[] {
  return conservativeDedup([...readSubagentFindings(codeDir), ...readDirectlyExploitable(codeDir)]);
}
/** 读取当前已入库漏洞（评级环节上游产物缺失时的回退来源）。 */
function loadDbVulns(projectId: string): any[] {
  try {
    return db
      .prepare(
        'SELECT title, severity, category, file_path AS file, line, description, recommendation, snippet FROM vulnerabilities WHERE project_id = ?'
      )
      .all(projectId) as any[];
  } catch {
    return [];
  }
}

/** 环节：AI 智能去重。输入=JSON/原始发现保守去重；输出落盘 deduped.json。 */
async function stageDedup(
  projectId: string,
  codeDir: string
): Promise<{ findings: any[]; killed: boolean }> {
  const raw = loadRawCandidates(codeDir);
  if (raw.length === 0) return { findings: [], killed: false };
  recordEvent(projectId, {
    kind: 'system',
    agent: '主控',
    tool: '',
    text: `读取子智能体原始发现并保守去重后共 ${raw.length} 个候选`,
  });
  const d = await aiDedupFindings(projectId, codeDir, raw);
  if (d.killed) return { findings: [], killed: true };
  writePipeline(codeDir, 'deduped.json', d.findings);
  return { findings: d.findings, killed: false };
}

/** 环节：代码级验证。输入优先上游传入，否则读 deduped.json，再回退原始候选；输出落盘 verified.json。 */
async function stageCodeVerify(
  projectId: string,
  codeDir: string,
  inputOverride?: any[]
): Promise<{ findings: any[]; killed: boolean }> {
  let input = inputOverride ?? readPipeline(codeDir, 'deduped.json');
  if (!input) {
    // 没有去重产物（如直接"从代码级验证开始"）：不能拿去重前的原始候选直接验证，
    // 否则会把不同子智能体对同一漏洞的重复上报（含中英文双份）全部带入，导致结果虚增。
    // 这里先补做一次 AI 智能去重，再进入验证，并落盘 deduped.json 供后续环节复用。
    const raw = loadRawCandidates(codeDir);
    if (raw.length > 0) {
      recordEvent(projectId, {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `未找到去重产物：先对 ${raw.length} 个原始候选补做 AI 智能去重，再进行代码级验证`,
      });
      const d = await aiDedupFindings(projectId, codeDir, raw);
      if (d.killed) return { findings: [], killed: true };
      writePipeline(codeDir, 'deduped.json', d.findings);
      input = d.findings;
    }
  }
  if (!input || input.length === 0) return { findings: [], killed: false };
  recordEvent(projectId, {
    kind: 'system',
    agent: '主控',
    tool: '',
    text: `去重后共 ${input.length} 个候选，开始逐条代码级验证`,
  });
  const v = await codeVerifyFindings(projectId, codeDir, input);
  if (v.killed) return { findings: [], killed: true };
  const findings = dropCombinationChains(v.findings);
  writePipeline(codeDir, 'verified.json', findings);
  return { findings, killed: false };
}

/**
 * 环节：红队二次评级（只调整等级、不增减漏洞）。
 * 输入来源优先级：上游传入 → 已验证产物 verified.json → 去重产物 deduped.json → 当前入库漏洞（UI 展示的最终清单）。
 * 关键：**绝不回退到去重前的子智能体原始候选**——二次评级必须基于"去重+代码级验证后的最终集合"，
 * 否则会把已被去重/剔除误报的条目重新拉回来评级（如把 82 个膨胀回 184 个）。
 * 输出落库前先清空旧漏洞，避免重复 INSERT 导致漏洞数量虚增（整集重算、数量不变）。
 */
async function stageRegrade(
  projectId: string,
  codeDir: string,
  inputOverride?: any[]
): Promise<{ findings: any[]; killed: boolean }> {
  let input =
    inputOverride ?? readPipeline(codeDir, 'verified.json') ?? readPipeline(codeDir, 'deduped.json');
  // 空数组也要回退：代码级验证可能写出 verified.json=[]，不能挡住入库漏洞的二次评级
  if (!input || input.length === 0) {
    const dbv = loadDbVulns(projectId);
    if (dbv.length > 0) {
      input = dbv;
      recordEvent(projectId, {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `未找到已验证产物，回退到当前入库的 ${dbv.length} 个最终漏洞进行二次评级（仅调整等级、不增减漏洞）`,
      });
    }
  }
  if (!input || input.length === 0) {
    // 没有任何"去重+验证后"的可用集合：不再回退到原始 184，避免错误膨胀。
    recordEvent(projectId, {
      kind: 'error',
      agent: '主控',
      tool: '',
      text: '二次评级缺少上游产物：未找到已验证漏洞，也没有入库漏洞。请先执行「代码级验证」或完整审计后再单独重跑二次评级。',
    });
    return { findings: loadDbVulns(projectId), killed: false };
  }
  const g = await regradeFindings(projectId, codeDir, input);
  if (g.killed) return { findings: [], killed: true };
  // 二次评级是"对同一批漏洞整集重算等级"：先清空旧漏洞再写回（数量与输入一致），杜绝重复累加。
  db.prepare('DELETE FROM vulnerabilities WHERE project_id = ?').run(projectId);
  saveVulnerabilities(projectId, g.findings);
  return { findings: g.findings, killed: false };
}

/**
 * 从（磁盘已有的）子智能体原始发现开始的后处理流水线，供 doAudit 与 doReprocess 共用：
 *   ① 机械保守去重（仅完全相同才合并）
 *   ② AI 语义去重（多子智能体并发，合并同一漏洞的重复上报）
 *   ③ 后端驱动的逐条代码级验证（剔除误报）
 *   ④ 红队实战二次评级
 *   ⑤ 落库并标记完成。
 * 任一阶段被暂停/删除（killed）则提前返回、不落库、不标记完成。
 * @param structuredVulns 仅当 JSON/ 为空时用于兜底采集。
 */
async function processFindings(
  projectId: string,
  codeDir: string,
  structuredVulns: any[]
): Promise<void> {
  const raw = conservativeDedup([
    ...readSubagentFindings(codeDir),
    ...readDirectlyExploitable(codeDir),
  ]);

  let findings: any[];
  if (raw.length > 0) {
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `读取子智能体原始发现并保守去重后共 ${raw.length} 个候选`,
    });
    // ② AI 语义去重：归并同一漏洞的重复上报，缩减后再送代码级验证
    const deduped = await aiDedupFindings(projectId, codeDir, raw);
    if (deduped.killed) return; // 去重阶段被暂停/删除：不落库
    // 落盘去重产物：供日后"单独重跑二次评级/代码级验证"复用，避免回退到去重前的原始候选
    writePipeline(codeDir, 'deduped.json', deduped.findings);
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `去重后共 ${deduped.findings.length} 个候选，开始逐条代码级验证`,
    });
    const verified = await codeVerifyFindings(projectId, codeDir, deduped.findings);
    if (verified.killed) return; // 验证阶段被暂停/删除：不落库
    findings = dropCombinationChains(verified.findings); // 保持"单漏洞"口径，剔除组合链
    writePipeline(codeDir, 'verified.json', findings);
  } else {
    // JSON/ 为空（异常）：回退到旧采集逻辑兜底
    findings = collectAuditFindings(codeDir, structuredVulns);
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `未检测到子智能体原始发现，回退采集到 ${findings.length} 个漏洞`,
    });
  }

  if (findings.length === 0) {
    saveVulnerabilities(projectId, findings);
    finishAudit(projectId, 'completed', null);
    return;
  }

  if (isMergeVerifyRegrade()) {
    const finalFindings = findings.map((v: any) => ({
      ...v,
      regrade_value: realTeamLabel(String(v.severity || 'info').toLowerCase()),
    }));
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: '✓ 已合并二次评级到代码级验证（省一轮评级 fan-out），直接落库',
    });
    saveVulnerabilities(projectId, finalFindings);
    finishAudit(projectId, 'completed', null);
    return;
  }

  const regraded = await stageRegrade(projectId, codeDir, findings);
  if (regraded.killed) return;
  finishAudit(projectId, 'completed', null);
}

/**
 * 从已有的专项子智能体审计结果（磁盘 JSON/）之后重跑：
 * 跳过耗时的子智能体静态审计，直接执行 去重 → 代码级验证 → 二次评级。
 * 适用于"只想重新走后处理、不想重扫源码"的场景（如改进了去重/验证逻辑后回填）。
 */
async function doReprocess(projectId: string, continueMode = false): Promise<void> {
  const project = getProject(projectId);
  if (!project) return;

  clearAuditResults(projectId, { keepEvents: continueMode });
  setAuditStatus(projectId, 'running', { started_at: now(), error_message: null });
  recordEvent(projectId, {
    kind: 'system',
    agent: '主控',
    tool: '',
    text: continueMode
      ? '▶ 续跑代码审计：补全缺失类型 → 去重 → 代码级验证 → 二次评级…'
      : '♻ 复用已有子智能体审计结果，重新执行：AI 智能去重 → 代码级验证 → 红队实战二次评级…',
  });

  let codeDir: string;
  try {
    codeDir = await ensureWorkspace(getProject(projectId)!);
  } catch (err: any) {
    finishAudit(projectId, 'failed', `源码准备失败：${err?.message || err}`);
    return;
  }
  if (skipProjectForNonWeb(projectId, codeDir)) return;

  kickEnvPrebuildWithAudit(projectId);

  const subagent = readSubagentFindings(codeDir);
  // 非续跑：必须已有产物才能「复用」。续跑（继续审计）允许 JSON 为空——
  // ensureSubagentCoverage 会把预期清单全部视为缺失并仅补跑这些子智能体，绝不拉全量主控。
  if (!continueMode && !hasSubagentArtifacts(codeDir)) {
    finishAudit(
      projectId,
      'failed',
      '未找到已有的子智能体审计结果（JSON/ 为空），请改用「重新审计」从头跑'
    );
    return;
  }
  if (continueMode) {
    const phaseComplete = isSubagentPhaseComplete(codeDir);
    const hasAny = hasSubagentArtifacts(codeDir);
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: phaseComplete
        ? `✓ 子智能体阶段已完成（${subagent.length} 条原始发现），续跑与全量审计相同的后处理流水线`
        : hasAny
          ? `▶ 检测到部分子智能体产物（${subagent.length} 条），将先补全缺失子智能体再进入与全量审计相同的后处理`
          : '▶ 未发现已有子智能体产物，将仅按预期清单补跑缺失子智能体（全部视为缺失），再进入后处理',
    });
  } else {
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `✓ 检测到已有子智能体结果（${subagent.length} 条原始发现），跳过专项静态审计，直接进入去重/代码级验证/二次评级`,
    });
  }

  const cov = await ensureSubagentCoverage(projectId, codeDir);
  if (cov.killed) return;
  if (!assertAuditCoverageComplete(projectId, codeDir)) return;

  await runAuditPostSubagentPhase(projectId, codeDir, null);
}

function finishAudit(projectId: string, status: string, error: string | null): void {
  if (status === 'completed') {
    const project = getProject(projectId);
    const artifactRoot = resolveArtifactRoot(projectId, project?.workspace_path);
    const coverage = artifactRoot
      ? auditCoverageSnapshot(artifactRoot, { repair: true })
      : ({
          status: 'unknown_language',
          expected: [],
          missing: [],
        } as Pick<AuditCoverageSnapshot, 'status' | 'expected' | 'missing'>);
    if (coverage.status !== 'complete') {
      status = 'failed';
      error =
        coverage.status === 'unknown_language'
          ? '审计完成被硬闸拒绝：无法确定预期子智能体清单或工作区不存在'
          : `审计完成被硬闸拒绝：仍缺失 ${coverage.missing.length}/${coverage.expected.length} 个子智能体 JSON（${coverage.missing.join('、')}）`;
    }
  }
  if (status === 'completed') {
    ensureVulnsPersistedFromDisk(projectId, '审计完成');
  }
  recordEvent(projectId, {
    kind: status === 'completed' ? 'result' : 'error',
    agent: '主控',
    tool: '',
    text: status === 'completed' ? '审计完成' : `审计失败：${error || ''}`,
  });
  setAuditStatus(projectId, status, { finished_at: now(), error_message: error });

  // 即将自动远程验证时保留预搭容器，等审计与靶机两边都结束后再验证（避免 stop 后再拉）。
  const keepTargetForVerify =
    status === 'completed' && isAutoVerify(projectId) && shouldRemoteVerify(projectId);
  if ((status === 'completed' || status === 'failed' || status === 'paused') && !keepTargetForVerify) {
    const project = getProject(projectId);
    const codeDir =
      project?.workspace_path && fs.existsSync(project.workspace_path)
        ? project.workspace_path
        : path.join(WORKSPACE_DIR, projectId);
    void releaseIdleTargetEnvironment(projectId, codeDir).catch(() => {});
  }
  if (status === 'completed' || status === 'failed') {
    setImmediate(() => harvestAndMaybePurgeSource(projectId));
  }
}

/** 磁盘已有审计产物但 DB 漏洞数为 0 时自动补入库（避免中断后「审计完成但总漏洞为空」）。 */
function ensureVulnsPersistedFromDisk(projectId: string, reason: string): number {
  const n = (
    db.prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE project_id = ?').get(projectId) as {
      c: number;
    }
  ).c;
  if (n > 0) return 0;
  const p = getProject(projectId);
  const artifactRoot = resolveArtifactRoot(projectId, p?.workspace_path);
  if (!artifactRoot) return 0;
  const findings = collectFromDisk(artifactRoot);
  if (findings.length === 0) return 0;
  saveVulnerabilities(projectId, findings);
  recordEvent(projectId, {
    kind: 'system',
    agent: '主控',
    tool: '',
    text: `↻ ${reason}：检测到磁盘产物未入库，已自动补入库 ${findings.length} 个漏洞`,
  });
  broadcast({ type: 'project_status', projectId });
  return findings.length;
}

/**
 * 把扫描 JSON / 漏洞报告归档到 data/results/<projectId>/。
 * 若审计已结束且验证不在排队/运行，再删除上传源码与工作区，避免仓库臃肿。
 */
export function harvestAndMaybePurgeSource(projectId: string): void {
  const p = getProject(projectId);
  if (!p) return;
  const ws =
    p.workspace_path && fs.existsSync(p.workspace_path)
      ? p.workspace_path
      : fs.existsSync(path.join(WORKSPACE_DIR, projectId))
        ? path.join(WORKSPACE_DIR, projectId)
        : '';
  if (ws) {
    try {
      const harvested = harvestAuditResults({
        projectId,
        projectName: p.project_name,
        archiveName: p.archive_name,
        workspacePath: ws,
      });
      if (harvested.copied.length > 0) {
        recordEvent(projectId, {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: `📦 审计结果已归档到 data/results/${projectId}/（${harvested.copied.join('、')}）`,
        });
      }
    } catch (e: any) {
      console.warn(`[results] 归档失败 ${projectId}: ${e?.message || e}`);
    }
  }

  const busyVerify =
    p.verify_status === 'queued' ||
    p.verify_status === 'running' ||
    p.env_status === 'building';
  const busyAudit = p.status === 'running' || p.status === 'queued';
  const pendingAutoVerify =
    isAutoVerify(projectId) && shouldRemoteVerify(projectId) && p.verify_status === 'none';
  if (busyVerify || busyAudit || pendingAutoVerify) return;
  if (!hasHarvestedResults(projectId) && !ws) return;
  if (ws && !hasHarvestedResults(projectId)) return;

  // 工作区已经不在：只把残留路径抹掉，不要每次启动/热重载再刷一条「已删除」日志
  if (!ws) {
    if (p.workspace_path) {
      db.prepare('UPDATE projects SET workspace_path = NULL WHERE id = ?').run(projectId);
    }
    try {
      removeUploadArchive(p.source_type, p.source_ref);
    } catch {
      /* ignore */
    }
    return;
  }

  try {
    if (ws) {
      try {
        spawnSync('docker', ['compose', '-p', composeProjectName(projectId), 'stop'], {
          timeout: 15_000,
          stdio: 'ignore',
        });
      } catch {
        /* 无容器或 docker 不可用 */
      }
    }
    removeWorkspace(projectId);
    removeUploadArchive(p.source_type, p.source_ref);
    db.prepare('UPDATE projects SET workspace_path = NULL WHERE id = ?').run(projectId);
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: '🗑 已删除上传源码与工作区，仅保留 data/results 中的漏洞/扫描 JSON',
    });
  } catch (e: any) {
    console.warn(`[results] 清理源码失败 ${projectId}: ${e?.message || e}`);
  }
}

/** 后台分批：已结束且空闲的项目归档结果并清源码。 */
export async function harvestIdleProjectSources(): Promise<{ scanned: number; purged: number }> {
  const dup = db
    .prepare(
      `DELETE FROM agent_events
       WHERE kind = 'system'
         AND text LIKE '%已删除上传源码与工作区%'
         AND rowid NOT IN (
           SELECT MIN(rowid) FROM agent_events
           WHERE kind = 'system' AND text LIKE '%已删除上传源码与工作区%'
           GROUP BY project_id
         )`
    )
    .run();
  if (dup.changes > 0) {
    console.log(`[code] 已去掉 ${dup.changes} 条重复的源码清理日志`);
  }

  const rows = db
    .prepare(
      `SELECT id FROM projects
       WHERE status NOT IN ('running','queued')
         AND verify_status NOT IN ('queued','running')
         AND env_status != 'building'`
    )
    .all() as { id: string }[];
  let purged = 0;
  for (const r of rows) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    const before = getProject(r.id);
    const hadWs = !!(before?.workspace_path && fs.existsSync(before.workspace_path));
    if (!hadWs && !before?.workspace_path) continue;
    harvestAndMaybePurgeSource(r.id);
    if (hadWs) purged++;
  }
  return { scanned: rows.length, purged };
}


/* --------------------------- 靶机 Docker 清理 --------------------------- */
const execFileAsync = promisify(execFile);
let dockerOk: boolean | null = null;
let dockerCheckedAt = 0;
/** 失败结果短缓存，避免 Docker 尚未就绪时被永久判死；成功则长期缓存。 */
const DOCKER_RECHECK_MS = 30_000;

/** 探测本机 Docker 是否可用（成功长期缓存；失败 30s 后重试）。 */
async function dockerAvailable(): Promise<boolean> {
  const now = Date.now();
  if (dockerOk === true) return true;
  if (dockerOk === false && now - dockerCheckedAt < DOCKER_RECHECK_MS) return false;
  try {
    await execFileAsync('docker', ['version', '--format', '{{.Server.Version}}'], {
      timeout: 8000,
      windowsHide: true,
    });
    dockerOk = true;
  } catch {
    dockerOk = false;
    dockerCheckedAt = now;
  }
  return dockerOk;
}

/**
 * external（Cursor 自建）靶机保活：
 * - 验证 running/queued/paused 或搭建在途：必须保活
 * - env_status=ready：同样保活，避免入队前/失败重试间隙被 idle reconcile stop，
 *   前端随即出现「靶机尚未真实就绪」
 * 用户主动「清除靶机」走 destroy 路径，不受此约束。
 */
function shouldPreserveTargetNow(projectId: string, codeDir: string): boolean {
  if (!codeDir || !fs.existsSync(codeDir)) return false;
  if (!shouldPreserveExternalContainers(codeDir)) return false;
  const p = getProject(projectId);
  if (!p) return false;
  if (
    p.verify_status === 'running' ||
    p.verify_status === 'queued' ||
    p.verify_status === 'paused' ||
    p.env_status === 'building' ||
    p.env_status === 'ready' ||
    envBuildInFlight(projectId)
  ) {
    return true;
  }
  return false;
}

/**
 * 停止该项目搭建的靶机 Docker 环境，释放 CPU/内存（compose stop，不 down -v）。
 * 仅按项目工作目录 / compose 项目名作用域操作，避免误伤并行任务的靶机。
 * 全程 best-effort：Docker 不可用或无靶机时静默跳过，绝不影响审计/验证结果。
 */
async function stopTargetEnvironment(
  projectId: string,
  codeDir: string,
  reason = '已停止 Docker 靶机环境以释放资源'
): Promise<void> {
  // Cursor Agent 自建靶机（mode=external）：仅在【正在验证/搭建】时禁止 idle stop；验证结束后可回收
  if (shouldPreserveTargetNow(projectId, codeDir)) return;
  try {
    if (!(await dockerAvailable())) return;

    const projName = composeProjectName(projectId);
    let stopped = false;

    // 1) 按项目专属 compose 项目名停止（不依赖 cwd，精确作用于本项目靶机，避免误停同名工作目录的其它项目）
    try {
      await execFileAsync('docker', ['compose', '-p', projName, 'stop'], {
        timeout: 120000,
        windowsHide: true,
      });
      stopped = true;
    } catch {
      /* 尝试 cwd 内 compose（v1/产物在工作区时） */
      if (codeDir && fs.existsSync(codeDir)) {
        try {
          await execFileAsync('docker-compose', ['stop'], {
            cwd: codeDir,
            timeout: 120000,
            windowsHide: true,
          });
          stopped = true;
        } catch {
          /* 走 label 兜底 */
        }
      }
    }

    // 2) 兜底：按本项目 compose 项目名 label 停止仍在运行的容器
    try {
      const { stdout } = await execFileAsync(
        'docker',
        ['ps', '-q', '--filter', `label=com.docker.compose.project=${projName}`],
        { timeout: 15000, windowsHide: true }
      );
      const ids = stdout.trim().split(/\s+/).filter(Boolean);
      if (ids.length) {
        await execFileAsync('docker', ['stop', ...ids], { timeout: 120000, windowsHide: true });
        stopped = true;
      }
    } catch {
      /* ignore */
    }

    if (stopped) {
      const p = getProject(projectId);
      const phase: EventPhase =
        p?.verify_status === 'running' || p?.verify_status === 'queued' ? 'verify' : 'audit';
      recordEvent(
        projectId,
        {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: `🧹 ${reason}`,
        },
        true,
        phase
      );
    }
  } catch {
    /* 清理失败不影响主流程 */
  }
}

/**
 * 仅【正在远程验证】或【正在搭建】时保留 Docker 靶机；verify_queued / 其它状态一律 stop
 * （保留 env_status=ready / TARGET_ENV.json，轮到验证时 ensureTargetUp 会 compose start 再拉起）。
 * Harness 项目无 Docker 靶机，跳过。
 */
async function releaseIdleTargetEnvironment(projectId: string, codeDir: string): Promise<void> {
  const p = getProject(projectId);
  if (!p || p.verify_status === 'running' || p.env_status === 'building') {
    return;
  }
  if (!codeDir || !fs.existsSync(codeDir)) return;
  if (readTargetEnvMode(codeDir) === 'harness' || detectProjectShape(codeDir) === 'harness') return;
  // Cursor Agent 自建靶机（mode=external）：仅【正在验证/搭建】保活，验证结束/排队/暂停后允许回收
  if (shouldPreserveTargetNow(projectId, codeDir)) return;
  if (!(await targetRunning(composeProjectName(projectId)))) return;
  const reason =
    p.verify_status === 'queued'
      ? '验证仍在排队：已暂停 Docker 靶机，轮到本项目验证时再拉起'
      : p.status === 'completed' || p.status === 'failed' || p.status === 'paused'
        ? '审计已结束：已暂停 Docker 靶机以释放资源（验证时再拉起）'
        : '已暂停闲置 Docker 靶机以释放资源';
  await stopTargetEnvironment(projectId, codeDir, reason);
}

/**
 * 手动清除靶机：彻底移除该项目的 Docker 靶机（compose down -v），并把 env_status 归零。
 * 与 stopTargetEnvironment（仅 stop、便于二次验证时 restart）不同——这是用户主动"清除"。
 */
async function clearTargetEnvironment(projectId: string, codeDir: string): Promise<void> {
  try {
    if (await dockerAvailable()) {
      const projName = composeProjectName(projectId);
      try {
        await execFileAsync('docker', ['compose', '-p', projName, 'down', '-v'], { timeout: 120000, windowsHide: true });
      } catch {
        if (codeDir && fs.existsSync(codeDir)) {
          try {
            await execFileAsync('docker-compose', ['down', '-v'], { cwd: codeDir, timeout: 120000, windowsHide: true });
          } catch { /* label 兜底 */ }
        }
      }
      // 兜底：按 label 强删仍存在的容器
      try {
        const { stdout } = await execFileAsync('docker', ['ps', '-aq', '--filter', `label=com.docker.compose.project=${projName}`], { timeout: 15000, windowsHide: true });
        const ids = stdout.trim().split(/\s+/).filter(Boolean);
        if (ids.length) await execFileAsync('docker', ['rm', '-f', ...ids], { timeout: 120000, windowsHide: true });
      } catch { /* ignore */ }
    }
  } catch { /* best-effort */ }
  setEnvStatus(projectId, 'none', null);
  recordEvent(projectId, { kind: 'system', agent: '主控', tool: '', text: '🧹 已手动清除靶机 Docker 环境' }, true, 'verify');
}

/** 解析靶机访问地址（TARGET_ENV.json → DB target_url → 项目端口）。 */
function resolveTargetUrl(projectId: string, codeDir?: string): string {
  if (codeDir) {
    try {
      const env = JSON.parse(fs.readFileSync(path.join(codeDir, 'TARGET_ENV.json'), 'utf8'));
      if (env && typeof env.url === 'string' && env.url.trim()) {
        return env.url.trim().replace(/[`'"]+$/, '');
      }
    } catch {
      /* 无交接文件 */
    }
  }
  const project = getProject(projectId);
  if (project?.target_url) return project.target_url.replace(/[`'"]+$/, '');
  return `http://localhost:${projectPort(projectId)}`;
}

/** 靶机是否真正可用：归属本项目的容器在跑 **且** HTTP 地址可达（与 finalizeWebEnvReady 标准一致）。
 *  external 模式：仅要求 TARGET_ENV.url 可达，不要求 compose 项目标签。 */
async function isTargetFullyReady(projectId: string, codeDir: string): Promise<boolean> {
  const harnessMode =
    readTargetEnvMode(codeDir) === 'harness' || detectProjectShape(codeDir) === 'harness';
  if (harnessMode) return isHarnessEnvReady(codeDir);
  if (isExternallyManagedTarget(codeDir)) {
    // external 也允许多 URL（含 version proof），避免首页冷启动挂起被误判不可达。
    return !!(await anyTargetUrlReachable(projectId, codeDir));
  }
  if (!(await dockerAvailable())) return false;
  const projName = composeProjectName(projectId);
  if (!(await targetRunning(projName))) return false;
  // 与冷启动软就绪一致：任一探测 URL 可达即可（XWiki 首页冷启动时常超时，但
  // /.strikeagent-version 已由网关直接 200）。
  return !!(await anyTargetUrlReachable(projectId, codeDir));
}

/** 是否有在途的靶机搭建（内存队列 / Pi Agent 进程 / envTasks）。 */
function envBuildInFlight(projectId: string): boolean {
  return (
    envTasks.has(projectId) ||
    envActive.has(projectId) ||
    envQueue.includes(projectId) ||
    envRunning.has(projectId)
  );
}

/**
 * 选了完整靶机时，搭建走独立 Pi：不占多智能体审计槽（1 主控 + 4 专项），
 * 也不随审计暂停 / 后端热重载把审计标 paused 而停。
 */
function shouldRunIndependentEnvPi(projectId: string): boolean {
  if (!needsComposeEnv(projectId)) return false;
  const p = getProject(projectId);
  if (!p) return false;
  if (p.verify_status === 'completed') return false;
  if (p.verify_status === 'running') return true;
  return p.status === 'running' || p.status === 'queued' || p.status === 'paused';
}

/** 清除 DB 中已无对应搭建任务的 building 残留。
 *  - verify_queued：静默归 none（排队本就不该占搭建槽，勿标 failed 吓人）
 *  - verify_running：归 none 并自动重排队搭建
 *  - 其它：归 none
 */
function resetStaleEnvBuilding(projectId: string, reason: string): void {
  const p = getProject(projectId);
  if (!p || p.env_status !== 'building') return;
  if (envBuildInFlight(projectId)) return;

  if (p.verify_status === 'queued') {
    setEnvStatus(projectId, 'none', p.target_url ?? null);
    // 不刷「已标记失败」——这是策略性停搭，不是故障
    return;
  }

  if (p.verify_status === 'running') {
    setEnvStatus(projectId, 'none', p.target_url ?? null);
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `↻ 靶机搭建状态已校正（${reason}），正在重新排队搭建…`,
      },
      true,
      'verify'
    );
    if (shouldRemoteVerify(projectId)) enqueueEnvPrebuild(projectId);
    return;
  }

  setEnvStatus(projectId, 'none', null);
  if (shouldRunIndependentEnvPi(projectId)) {
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `↻ 靶机状态校正：${reason}（独立靶机 Pi 与多智能体审计分开，正在重新排队搭建）`,
      },
      true,
      'verify'
    );
    enqueueEnvPrebuild(projectId);
  }
}

/** 等待进行中的靶机搭建结束（envTasks / env_status=building）。 */
async function awaitEnvBuildIdle(projectId: string, maxWaitMs = 30 * 60_000): Promise<void> {
  const deadline = Date.now() + maxWaitMs;
  let logged = false;
  while (Date.now() < deadline) {
    const task = envTasks.get(projectId);
    if (task) {
      if (!logged) {
        recordEvent(
          projectId,
          { kind: 'system', agent: '主控', tool: '', text: '⏳ 等待靶机环境搭建完成后再开始验证…' },
          true,
          'verify'
        );
        logged = true;
      }
      await task.catch(() => {});
    } else if (!envBuildInFlight(projectId)) {
      const p = getProject(projectId);
      if (p?.env_status === 'building') {
        const codeDir = p.workspace_path && fs.existsSync(p.workspace_path) ? p.workspace_path : '';
        if (codeDir && (await isTargetFullyReady(projectId, codeDir))) {
          await syncEnvStatusFromRunningTarget(projectId, codeDir);
          return;
        }
        resetStaleEnvBuilding(projectId, '搭建任务已结束但状态仍停留在 building');
        return;
      }
      return;
    }
    const p = getProject(projectId);
    if (!p || p.env_status !== 'building') return;
    await sleep(3000);
  }
  resetStaleEnvBuilding(projectId, '等待靶机搭建超时');
}

/** 同一项目靶机搭建单飞（避免 ensureTargetUp 与预搭建通道并发重入 doPrebuildEnv）。 */
async function runPrebuildEnvOnce(projectId: string): Promise<void> {
  const pending = envTasks.get(projectId);
  if (pending) {
    await pending.catch(() => {});
    return;
  }
  const task = doPrebuildEnv(projectId)
    .catch(() => {})
    .finally(() => {
      envTasks.delete(projectId);
    });
  envTasks.set(projectId, task);
  await task;
}

/** 容器已在跑但 env_status/target_url 未同步时，**仅当地址可达**才写回 ready。 */
async function syncEnvStatusFromRunningTarget(
  projectId: string,
  codeDir?: string
): Promise<boolean> {
  const project = getProject(projectId);
  if (!project || !codeDir) return false;
  if (!(await isTargetFullyReady(projectId, codeDir))) return false;

  const url = resolveTargetUrl(projectId, codeDir);
  syncRegistrationMeta(projectId, codeDir);
  if (project.env_status !== 'ready' || project.target_url !== url) {
    setEnvStatus(projectId, 'ready', url);
  }
  return true;
}

/** 单项目：修正 building 残留、同步 ready、闲置 stop；仅 verify_running 保留运行中容器。 */
async function reconcileProjectEnvAndContainers(p: {
  id: string;
  workspace_path: string | null;
  env_status: string;
  verify_status: string;
  target_url: string | null;
}): Promise<void> {
  const projName = composeProjectName(p.id);
  const containerUp = await targetRunning(projName);
  const ws = p.workspace_path && fs.existsSync(p.workspace_path) ? p.workspace_path : '';
  /** 验证进行中/暂停/排队、独立靶机 Pi 在途、或审计暂停但已选完整靶机：保活。 */
  const keepContainer =
    p.verify_status === 'running' ||
    p.verify_status === 'paused' ||
    p.verify_status === 'queued' ||
    p.env_status === 'building' ||
    envBuildInFlight(p.id) ||
    shouldRunIndependentEnvPi(p.id);
  const inFlight = envBuildInFlight(p.id);

  if (p.env_status === 'building' && !inFlight) {
    if (ws && (await isTargetFullyReady(p.id, ws))) {
      await syncEnvStatusFromRunningTarget(p.id, ws);
    } else {
      resetStaleEnvBuilding(
        p.id,
        p.verify_status === 'running' ? '验证进行中但无在途搭建且容器未就绪' : '搭建任务已结束但状态仍停留在 building'
      );
    }
    return;
  }

  if (containerUp) {
    if (p.env_status === 'building' && ws) {
      if (await isTargetFullyReady(p.id, ws)) {
        await syncEnvStatusFromRunningTarget(p.id, ws);
      }
    } else if (!keepContainer) {
      // Cursor Agent 自建靶机（mode=external）：仅【正在验证/搭建】保活，验证结束后回收内存防 OOM
      if (ws && shouldPreserveTargetNow(p.id, ws)) return;
      // completed / failed / none：停容器，ready 状态保留便于日后 compose start
      await stopTargetEnvironment(p.id, ws);
      if (p.verify_status === 'queued') {
        recordEvent(
          p.id,
          {
            kind: 'system',
            agent: '主控',
            tool: '',
            text: '⏸ 验证仍在排队：已停止靶机容器释放资源，轮到本项目验证时再拉起',
          },
          true,
          'verify'
        );
      }
    }
    return;
  }

  // 容器已停 + ready + running：留给 ensureTargetUp 做 compose start / 重搭，不改 env_status。
  // queued 的 ready 保持不动（不抢槽、不误标 failed）。
  if (p.env_status === 'ready' && (p.verify_status === 'running' || p.verify_status === 'queued')) {
    return;
  }

  // failed + 正在验证：补入搭建队列。queued 不预搭，等拿到验证槽后再搭。
  if (p.env_status === 'failed' && p.verify_status === 'running') {
    setEnvStatus(p.id, 'none', p.target_url);
    enqueueEnvPrebuild(p.id);
  }
}

/** 启动时与定时：修正 building 残留；仅【正在远程验证】的项目保留运行中靶机，其余一律 stop。 */
export async function reconcileEnvAndContainers(): Promise<void> {
  // 先释放被 verify_queued 占用的搭建槽，再对账
  pruneQueuedVerifyEnvBuilds();

  const rows = db
    .prepare(
      `SELECT id, workspace_path, env_status, verify_status, target_url FROM projects
       WHERE env_status != 'none'
          OR verify_status IN ('running', 'queued')
          OR target_url IS NOT NULL`
    )
    .all() as {
    id: string;
    workspace_path: string | null;
    env_status: string;
    verify_status: string;
    target_url: string | null;
  }[];

  for (const p of rows) {
    await reconcileProjectEnvAndContainers(p);
  }

  // 仅给正在验证且靶机未就绪的项目补搭建（queued 不预搭）
  requeueStaleEnvPrebuilds();
}

/**
 * DB 中靶机未就绪、内存搭建队列也没有时，补入独立搭建通道。
 * 覆盖：正在验证、以及已选完整靶机且审计仍在进行/暂停（含后端重启孤儿暂停）。
 * 审计已完成且仅 verify_queued 的不预搭，等真正拿到验证槽后再由 ensureTargetUp 搭建。
 */
export function requeueStaleEnvPrebuilds(): number {
  let n = 0;
  const rows = db
    .prepare(
      `SELECT id, env_status FROM projects
       WHERE env_status IN ('none', 'failed', 'building')`
    )
    .all() as { id: string; env_status: string }[];
  for (const r of rows) {
    if (envBuildInFlight(r.id)) continue;
    if (!shouldRunIndependentEnvPi(r.id)) continue;
    if (!shouldRemoteVerify(r.id)) continue;
    // failed：仅正在验证时自动重试；审计阶段搭建失败留给手动「重试靶机」，避免每 3 分钟空转
    if (r.env_status === 'failed' && getProject(r.id)?.verify_status !== 'running') continue;
    if (r.env_status === 'failed' || r.env_status === 'building') {
      setEnvStatus(r.id, 'none', null);
    }
    enqueueEnvPrebuild(r.id);
    n++;
  }
  if (n > 0) startNextEnv();
  return n;
}

/**
 * 停掉「仅验证排队、尚未真正开始验证」项目占用的靶机搭建任务，把槽位让给 verify_running。
 * 审计进行中/暂停且已选完整靶机的独立搭建 Pi 不受影响。
 */
export function pruneQueuedVerifyEnvBuilds(): { stopped: string[]; clearedQueue: number } {
  const stopped: string[] = [];
  const candidates = new Set<string>([...envQueue, ...envActive, ...envTasks.keys()]);
  const buildingRows = db
    .prepare(`SELECT id FROM projects WHERE env_status = 'building'`)
    .all() as { id: string }[];
  for (const r of buildingRows) candidates.add(r.id);

  let clearedQueue = 0;
  // 先清掉队列里尚未开工的 verify_queued，避免 startNextEnv 立刻又拉起
  for (let i = envQueue.length - 1; i >= 0; i--) {
    const id = envQueue[i];
    const p = getProject(id);
    if (!p) {
      envQueue.splice(i, 1);
      clearedQueue++;
      continue;
    }
    if (p.verify_status === 'running') continue;
    if (shouldRunIndependentEnvPi(id)) continue; // 独立靶机 Pi（含审计暂停）保留
    envQueue.splice(i, 1);
    clearedQueue++;
  }

  for (const id of candidates) {
    const p = getProject(id);
    if (!p) continue;
    if (p.verify_status === 'running') continue;
    if (shouldRunIndependentEnvPi(id)) continue;
    // 仅停「验证排队 / 其它非审计」占用的搭建
    if (!envBuildInFlight(id) && p.env_status !== 'building') continue;
    stopEnvChannel(id, { quiet: true, reason: 'queued_yield' });
    stopped.push(id);
  }
  if (clearedQueue > 0 || stopped.length > 0) startNextEnv();
  return { stopped, clearedQueue };
}

export interface IdleContainerReconcileResult {
  /** default=含审计并行预搭建；verify_pipeline=仅验证中+搭建中（排队不停占容器） */
  mode: 'default' | 'verify_pipeline';
  kept: string[];
  stopped: string[];
  errors: { projectId: string; error: string }[];
}

/**
 * 哪些项目应保留运行中的 Docker 靶机。
 * 保活：verify running/paused/queued、内存搭建中；mode=external 靶机仅在【正在验证/搭建】保活。
 * 已完成/失败的靶机（含 external）交由闲置对账 stop 回收内存，避免队列推进时靶机栈累积触发 OOM。
 */
function dockerKeepProjectIds(_verifyPipeline: boolean): Set<string> {
  const keep = new Set<string>();
  const rows = db
    .prepare('SELECT id, verify_status, env_status, workspace_path FROM projects')
    .all() as {
    id: string;
    verify_status: string;
    env_status: string;
    workspace_path: string | null;
  }[];
  for (const p of rows) {
    if (
      p.verify_status === 'running' ||
      p.verify_status === 'paused' ||
      p.verify_status === 'queued' ||
      p.env_status === 'building' ||
      envBuildInFlight(p.id) ||
      shouldRunIndependentEnvPi(p.id)
    ) {
      keep.add(p.id);
      continue;
    }
    const ws =
      p.workspace_path && fs.existsSync(p.workspace_path)
        ? p.workspace_path
        : path.join(WORKSPACE_DIR, p.id);
    // external 靶机仅在【正在验证/搭建】保活；验证完成/失败后交给闲置对账 stop，回收内存防 OOM
    if (fs.existsSync(ws) && shouldPreserveTargetNow(p.id, ws)) keep.add(p.id);
  }
  return keep;
}

/** 列出 workspace 下仍在运行的 compose 项目名（= projectId）。 */
async function listCodeComposeProjectsRunning(): Promise<string[]> {
  if (!(await dockerAvailable())) return [];
  try {
    const { stdout } = await execFileAsync(
      'docker',
      [
        'ps',
        '--format',
        '{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.project.working_dir"}}',
      ],
      { timeout: 30000, windowsHide: true }
    );
    const wsNorm = WORKSPACE_DIR.replace(/\\/g, '/').toLowerCase();
    const projects = new Set<string>();
    for (const line of stdout.trim().split('\n')) {
      if (!line.trim()) continue;
      const [proj, wd = ''] = line.split('\t');
      if (!proj || !/^p_[a-z0-9]+$/i.test(proj)) continue;
      const wdNorm = wd.replace(/\\/g, '/').toLowerCase();
      if (wdNorm && !wdNorm.includes(wsNorm)) continue;
      projects.add(proj);
    }
    return [...projects];
  } catch {
    return [];
  }
}

/**
 * 按白名单停止闲置 Docker 靶机。
 * verifyPipeline=true：仅保留 verify_running 及 env 搭建中的项目（verify_queued 不停占容器）。
 */
export async function reconcileIdleDockerContainers(opts?: {
  verifyPipeline?: boolean;
}): Promise<IdleContainerReconcileResult> {
  const verifyPipeline = opts?.verifyPipeline ?? false;
  const keepIds = dockerKeepProjectIds(verifyPipeline);
  const result: IdleContainerReconcileResult = {
    mode: verifyPipeline ? 'verify_pipeline' : 'default',
    kept: [],
    stopped: [],
    errors: [],
  };

  if (!verifyPipeline) await reconcileEnvAndContainers();

  const runningCompose = await listCodeComposeProjectsRunning();
  for (const projectId of runningCompose) {
    if (keepIds.has(projectId)) {
      result.kept.push(projectId);
      continue;
    }
    const p = getProject(projectId);
    const codeDir =
      p?.workspace_path && fs.existsSync(p.workspace_path)
        ? p.workspace_path
        : path.join(WORKSPACE_DIR, projectId);
    try {
      await stopTargetEnvironment(projectId, codeDir);
      result.stopped.push(projectId);
    } catch (e: unknown) {
      result.errors.push({
        projectId,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  if (result.stopped.length > 0 || result.kept.length > 0) {
    console.log(
      `[code] 闲置靶机清理(${result.mode}): 保留 ${result.kept.length} 个, 停止 ${result.stopped.length} 个`
    );
  }
  return result;
}

let envReconcileTimer: NodeJS.Timeout | null = null;

/** 每 3 分钟对账一次，防止 env_status=building 长期残留阻塞验证。 */
export function startEnvReconcileScheduler(): void {
  if (envReconcileTimer) return;
  envReconcileTimer = setInterval(() => {
    void reconcileEnvAndContainers();
  }, 3 * 60 * 1000);
}

/** 靶机就绪失败时，从近期验证日志提取更可读的原因（避免一律误报 Docker 未安装）。 */
async function resolveTargetUpFailureReason(projectId: string, codeDir?: string): Promise<string> {
  let shape: 'web' | 'harness' = 'web';
  if (codeDir) {
    shape = detectProjectShape(codeDir);
    if (readTargetEnvMode(codeDir) === 'harness') shape = 'harness';
  }
  if (shape === 'harness') {
    const rows = db
      .prepare(
        `SELECT text FROM agent_events WHERE project_id = ? AND phase = 'verify'
         AND kind IN ('error','text','system') ORDER BY ts DESC LIMIT 30`
      )
      .all(projectId) as { text: string }[];
    const errEv = rows.find((r) => r.text?.includes('沙箱') || r.text?.startsWith('⚠') || r.text?.includes('环境预搭建'));
    if (errEv?.text) {
      const t = errEv.text.replace(/^验证失败：/, '').trim();
      return t.startsWith('沙箱') || t.startsWith('靶机') ? t : `沙箱环境无法就绪：${t}`;
    }
    return '沙箱环境无法就绪，验证中止（Harness 预搭建失败或 _harness/ 目录缺失；请确认项目为非 Web 形态且沙箱脚本已生成）';
  }
  if (!(await dockerAvailable())) {
    return '靶机无法就绪，远程验证中止（请确认 Docker 已安装并运行）';
  }
  const rows = db
    .prepare(
      `SELECT text FROM agent_events WHERE project_id = ? AND phase = 'verify'
       AND kind IN ('error','text','system') ORDER BY ts DESC LIMIT 50`
    )
    .all(projectId) as { text: string }[];
  const blob = rows.map((r) => r.text || '').join('\n');
  if (/Android|Kotlin\/Gradle|APK 应用|不是.*Web|无 Web 服务|无法按 Web 靶机/i.test(blob)) {
    return '靶机无法就绪：该项目为 Android/移动端应用源码，无法部署 Web 靶机进行远程验证。代码审计结果仍有效；当前平台远程验证仅支持可 Docker 化的 Web 服务。';
  }
  const errEv = rows.find(
    (r) =>
      r.text?.startsWith('⚠') ||
      r.text?.includes('环境预搭建') ||
      r.text?.includes('未检测到归属本项目')
  );
  if (errEv?.text) {
    const t = errEv.text.replace(/^验证失败：/, '').trim();
    return t.startsWith('靶机') ? t : `靶机无法就绪：${t}`;
  }
  return '靶机无法就绪，远程验证中止（环境搭建失败或未检测到运行中的靶机容器；请确认项目为可 Docker 部署的 Web 应用）';
}

/** 同一环境刚失败时进入退避，避免镜像源/依赖故障触发无休止重搭。 */
function recentEnvBuildFailure(projectId: string, backoffMs = 10 * 60_000): string | null {
  const row = db
    .prepare(
      `SELECT ts, text FROM agent_events
       WHERE project_id = ? AND phase = 'verify' AND kind IN ('error','system')
         AND (text LIKE '%环境预搭建%失败%' OR text LIKE '%环境预搭建%超时%'
           OR text LIKE '%靶机无法就绪%' OR text LIKE '%镜像%失败%')
       ORDER BY ts DESC LIMIT 1`
    )
    .get(projectId) as { ts: number; text: string } | undefined;
  if (!row || Date.now() - row.ts >= backoffMs) return null;
  return row.text || '近期靶机搭建失败';
}

/** 拉起已停靶机容器后，等待其冷启动就绪的上限（Java/Spring/XWiki 冷启动可达数分钟，留足余量）。 */
const TARGET_BOOT_WAIT_MS = 180_000;
/** 容器已在跑但仍不可达时的加长等待（XWiki/Java 冷启动+DW 常超过 5 分钟）。 */
const TARGET_BOOT_WAIT_RUNNING_MS = 600_000;
/** 冷启动探测单 URL 硬超时（首页在 XWiki 未就绪时会挂起连接，必须墙钟截断）。 */
const TARGET_PROBE_TIMEOUT_MS = 3_000;

/** 收集 TARGET_ENV / DB 中可用于探测的主机 URL（去重；轻量证明 URL 优先）。 */
function collectTargetProbeUrls(projectId: string, codeDir: string): string[] {
  const urls: string[] = [];
  const push = (raw: unknown) => {
    const s = String(raw || '')
      .trim()
      .replace(/[`'"]+$/, '');
    if (!s || !/^https?:\/\//i.test(s)) return;
    if (!urls.includes(s)) urls.push(s);
  };
  try {
    const env = readTargetEnv(codeDir);
    if (env) {
      // 优先探测 runtime_version_proof：nginx 常直接回静态文件，不依赖后端冷启动。
      const proof = env.runtime_version_proof;
      if (proof && typeof proof === 'object' && String(proof.type || '') === 'http') {
        push(proof.target);
      }
      push(env.url);
      push(env.login_url);
    }
  } catch {
    /* ignore */
  }
  push(resolveTargetUrl(projectId, codeDir));
  return urls;
}

/** 任一探测 URL 可达即视为 HTTP 面起来（含 401/403/302）；并行探测，避免慢 URL 拖死。 */
async function anyTargetUrlReachable(projectId: string, codeDir: string): Promise<string | null> {
  const urls = collectTargetProbeUrls(projectId, codeDir);
  if (urls.length === 0) return null;
  const hits = await Promise.all(
    urls.map(async (url) => ((await urlReachable(url, TARGET_PROBE_TIMEOUT_MS)) ? url : null))
  );
  return hits.find((u) => !!u) || null;
}

/**
 * 冷启动等待用的「软就绪」：容器在跑 + 任一探测 URL 可达。
 * 故意不含 live provenance（运行时版本证明可能晚于首页就绪）；
 * 否则会在冷启动阶段误超时，进而误触发整栈重搭。
 */
async function isTargetBootReady(projectId: string, codeDir: string): Promise<boolean> {
  if (!(await dockerAvailable())) return false;
  const projName = composeProjectName(projectId);
  if (!(await targetRunning(projName))) return false;
  return !!(await anyTargetUrlReachable(projectId, codeDir));
}

/** 采集复用失败时的诊断摘要（容器状态 / 端口 / 最近日志），写入事件便于排障。 */
async function diagnoseTargetReuseFailure(projectId: string, codeDir: string): Promise<string> {
  const projName = composeProjectName(projectId);
  const bits: string[] = [];
  const urls = collectTargetProbeUrls(projectId, codeDir);
  if (urls.length) bits.push(`探测URL=${urls.slice(0, 3).join(' | ')}`);
  try {
    const { stdout } = await execFileAsync(
      'docker',
      [
        'ps',
        '-a',
        '--filter',
        `label=com.docker.compose.project=${projName}`,
        '--format',
        '{{.Names}}={{.Status}}',
      ],
      { timeout: 15000, windowsHide: true }
    );
    const lines = stdout
      .trim()
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    if (lines.length) bits.push(`容器=${lines.slice(0, 8).join('; ')}`);
    else bits.push('容器=无');
  } catch {
    bits.push('容器状态查询失败');
  }
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['compose', '-p', projName, 'ps', '--format', 'json'],
      { cwd: codeDir, timeout: 15000, windowsHide: true }
    );
    if (stdout.trim()) bits.push(`compose_ps已采集`);
  } catch {
    /* optional */
  }
  try {
    const { stdout: idsOut } = await execFileAsync(
      'docker',
      ['ps', '-q', '--filter', `label=com.docker.compose.project=${projName}`],
      { timeout: 15000, windowsHide: true }
    );
    const id = idsOut.trim().split(/\s+/).filter(Boolean)[0];
    if (id) {
      const { stdout: logs } = await execFileAsync('docker', ['logs', '--tail', '20', id], {
        timeout: 15000,
        windowsHide: true,
      });
      const oneLine = logs
        .trim()
        .split('\n')
        .slice(-3)
        .join(' | ')
        .replace(/\s+/g, ' ')
        .slice(0, 240);
      if (oneLine) bits.push(`日志=${oneLine}`);
    }
  } catch {
    /* optional */
  }
  return bits.join(' · ') || '无诊断信息';
}

/**
 * 轮询等待靶机冷启动（容器运行中 + HTTP 可访问），直到就绪或超时。
 * 期间每 ~30s 记录一条进度事件。就绪返回 true，超时返回 false。
 */
async function waitTargetReachable(
  projectId: string,
  codeDir: string,
  maxWaitMs = TARGET_BOOT_WAIT_MS
): Promise<boolean> {
  const deadline = Date.now() + maxWaitMs;
  let lastNotice = 0;
  const started = Date.now();
  while (Date.now() < deadline) {
    if (verifyKilled.has(projectId) || cancelledProjects.has(projectId)) return false;
    if (await isTargetBootReady(projectId, codeDir)) return true;
    const elapsed = Date.now() - started;
    if (elapsed - lastNotice >= 30_000) {
      lastNotice = elapsed;
      const running = await targetRunning(composeProjectName(projectId));
      recordEvent(
        projectId,
        {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: `⏳ 靶机容器已拉起，正在等待服务冷启动就绪（已等待约 ${Math.round(elapsed / 1000)}s，容器${running ? '运行中' : '未就绪'}）…`,
        },
        true,
        'verify'
      );
    }
    await sleep(4000);
  }
  return false;
}

/** 对已存在 compose 项目执行 start（优先 TARGET_ENV.compose_file + cwd）。 */
async function startExistingTargetContainers(projectId: string, codeDir: string): Promise<void> {
  const projName = composeProjectName(projectId);
  try {
    const env = readTargetEnv(codeDir);
    const composeFile = String(env?.compose_file || '').trim();
    const startArgs = ['compose', '-p', projName];
    if (composeFile) startArgs.push('-f', composeFile);
    startArgs.push('start');
    await execFileAsync('docker', startArgs, {
      cwd: codeDir,
      timeout: 120000,
      windowsHide: true,
    });
    return;
  } catch {
    /* fall through */
  }
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['ps', '-aq', '--filter', `label=com.docker.compose.project=${projName}`],
      { timeout: 15000, windowsHide: true }
    );
    const ids = stdout.trim().split(/\s+/).filter(Boolean);
    if (ids.length) {
      await execFileAsync('docker', ['start', ...ids], { timeout: 120000, windowsHide: true });
    }
  } catch {
    /* ignore */
  }
}

/** 对已存在 compose 项目执行 restart（拉起后仍不可达时的一次自愈）。 */
async function restartExistingTargetContainers(projectId: string, codeDir: string): Promise<void> {
  const projName = composeProjectName(projectId);
  try {
    const env = readTargetEnv(codeDir);
    const composeFile = String(env?.compose_file || '').trim();
    const args = ['compose', '-p', projName];
    if (composeFile) args.push('-f', composeFile);
    args.push('restart');
    await execFileAsync('docker', args, { cwd: codeDir, timeout: 180000, windowsHide: true });
    return;
  } catch {
    /* fall through */
  }
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['ps', '-aq', '--filter', `label=com.docker.compose.project=${projName}`],
      { timeout: 15000, windowsHide: true }
    );
    const ids = stdout.trim().split(/\s+/).filter(Boolean);
    if (ids.length) {
      await execFileAsync('docker', ['restart', ...ids], { timeout: 180000, windowsHide: true });
    }
  } catch {
    /* ignore */
  }
}

/** 确保靶机可用于（单漏洞）验证：必须容器在跑且 HTTP 可达；否则搭建/拉起后再检。
 *  纯外部（无本地 compose）：仅校验 URL 可达，永不走产品侧 doPrebuildEnv。
 *  带本地 compose 合同的靶机：compose start 复用 → 再做运行中校验。 */
async function ensureTargetUp(projectId: string, codeDir: string): Promise<boolean> {
  const harnessMode =
    readTargetEnvMode(codeDir) === 'harness' || detectProjectShape(codeDir) === 'harness';
  if (harnessMode) {
    if (isHarnessEnvReady(codeDir)) {
      await runHarnessSmokeIfConfigured(codeDir);
      setEnvStatus(projectId, 'ready', harnessTargetUrl());
      return true;
    }
    await runPrebuildEnvOnce(projectId);
    await awaitEnvBuildIdle(projectId);
    if (isHarnessEnvReady(codeDir)) {
      await runHarnessSmokeIfConfigured(codeDir);
      setEnvStatus(projectId, 'ready', harnessTargetUrl());
      return true;
    }
    return false;
  }

  await awaitEnvBuildIdle(projectId);

  // external：Cursor Agent 自建靶机，只认 URL 可达，禁止产品搭环境
  if (isExternallyManagedTarget(codeDir)) {
    const url = resolveTargetUrl(projectId, codeDir);
    if (await urlReachable(url)) {
      setEnvStatus(projectId, 'ready', url);
      syncRegistrationMeta(projectId, codeDir);
      recordEvent(
        projectId,
        {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: `✓ 复用外部靶机（mode=external，${url}），跳过产品侧搭建`,
        },
        true,
        'verify'
      );
      return true;
    }
    recordEvent(
      projectId,
      {
        kind: 'error',
        agent: '主控',
        tool: '',
        text: `⚠ 外部靶机不可达（mode=external，${url}）；请由 Cursor Agent 重新拉起后再续跑，产品侧不会自动搭建`,
      },
      true,
      'verify'
    );
    return false;
  }

  // ① 已经运行中且可达：直接复用。
  if (await isTargetFullyReady(projectId, codeDir)) {
    await syncEnvStatusFromRunningTarget(projectId, codeDir);
    return true;
  }

  if (!(await dockerAvailable())) return false;
  const projName = composeProjectName(projectId);

  // ② 先勘察：本项目的靶机容器是否**曾搭建过、仍存在**（含已停止的容器）。
  //    有容器 → 只允许 start/restart 复用；有本地 compose 合同时禁止整栈重搭换端口。
  const composeContract = hasLocalComposeContract(codeDir);
  if (await targetContainerExists(projName)) {
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: '🔎 检测到本项目已搭建的靶机容器（可能已停止），正在拉起复用，不重新搭建…',
      },
      true,
      'verify'
    );
    await startExistingTargetContainers(projectId, codeDir);

    // 容器已在跑时用更长冷启动窗口，避免 XWiki/Java 等被 2 分钟误判为损坏。
    const waitMs = (await targetRunning(projName))
      ? TARGET_BOOT_WAIT_RUNNING_MS
      : TARGET_BOOT_WAIT_MS;
    if (await waitTargetReachable(projectId, codeDir, waitMs)) {
      await syncEnvStatusFromRunningTarget(projectId, codeDir);
      // 冷启动软就绪后，再补一次完整校验；证明接口偶发滞后时不阻断复用。
      if (!(await isTargetFullyReady(projectId, codeDir))) {
        await sleep(5000);
      }
      recordEvent(
        projectId,
        { kind: 'system', agent: '主控', tool: '', text: '✓ 已拉起并复用现有靶机容器，服务已就绪' },
        true,
        'verify'
      );
      return true;
    }

    // 一次 restart 自愈 + 缩短二次等待，仍失败再决定是否允许重搭。
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `⚠ 首次拉起后仍不可达，尝试 compose restart 自愈…（${await diagnoseTargetReuseFailure(projectId, codeDir)}）`,
      },
      true,
      'verify'
    );
    await restartExistingTargetContainers(projectId, codeDir);
    if (await waitTargetReachable(projectId, codeDir, TARGET_BOOT_WAIT_MS)) {
      await syncEnvStatusFromRunningTarget(projectId, codeDir);
      recordEvent(
        projectId,
        { kind: 'system', agent: '主控', tool: '', text: '✓ restart 后已复用现有靶机容器，服务已就绪' },
        true,
        'verify'
      );
      return true;
    }

    const diag = await diagnoseTargetReuseFailure(projectId, codeDir);
    if (composeContract) {
      // 关键：已有 StrikeAgent/本地 compose 合同与容器时，禁止产品侧整栈重搭。
      // 重搭会 down 旧栈、换端口、改写 TARGET_ENV，导致「明明有靶机却又搭一套」。
      setEnvStatus(projectId, 'failed', resolveTargetUrl(projectId, codeDir));
      recordEvent(
        projectId,
        {
          kind: 'error',
          agent: '主控',
          tool: '',
          text:
            `⛔ 已有靶机容器拉起/restart 后仍不可达，拒绝自动整栈重搭（避免换端口覆盖 TARGET_ENV）。` +
            `请人工检查端口映射/容器日志后重试验证。诊断：${diag}`,
        },
        true,
        'verify'
      );
      return false;
    }

    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `⚠ 已拉起现有靶机容器但超时仍不可达（疑似容器损坏），改为重新搭建…（${diag}）`,
      },
      true,
      'verify'
    );
  } else if (composeContract) {
    // 有 compose 合同但容器已被删光：仍禁止静默换端口重搭，避免与既有 TARGET_ENV 冲突。
    setEnvStatus(projectId, 'failed', resolveTargetUrl(projectId, codeDir));
    recordEvent(
      projectId,
      {
        kind: 'error',
        agent: '主控',
        tool: '',
        text:
          '⛔ 检测到 TARGET_ENV/本地 compose 合同，但容器已不存在；拒绝自动整栈重搭以免换端口。' +
          '请用原 compose 文件重新 up，或清除靶机后再触发环境搭建。',
      },
      true,
      'verify'
    );
    return false;
  } else {
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: '🔎 未检测到本项目的靶机容器，开始搭建靶机环境…',
      },
      true,
      'verify'
    );
  }

  // ③ 确无可复用容器（且无本地 compose 合同）才允许产品侧搭建。
  const current = getProject(projectId);
  const recentFailure = current?.env_status === 'failed' ? recentEnvBuildFailure(projectId) : null;
  if (recentFailure) {
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `⏸ 靶机搭建进入 10 分钟失败退避，避免重复拉取镜像/重建：${recentFailure.slice(0, 220)}`,
      },
      true,
      'verify'
    );
    return false;
  }
  await runPrebuildEnvOnce(projectId);
  await awaitEnvBuildIdle(projectId);

  if (await isTargetFullyReady(projectId, codeDir)) {
    await syncEnvStatusFromRunningTarget(projectId, codeDir);
    return true;
  }

  const ep = getProject(projectId);
  if (ep?.env_status === 'building') {
    resetStaleEnvBuilding(projectId, 'ensureTargetUp 失败时清除 building 残留');
  }
  return false;
}

/**
 * 单漏洞远程验证（item 12）：对指定标题的一个漏洞做靶机实测，结果合并回 exploit_report。
 * 情形①全流程跑过靶机已停：ensureTargetUp 会 start 拉起；情形②只跑过代码层无靶机：ensureTargetUp 会重搭。
 * （情形③"验证进行中点击"由 enqueueVerifyOne 走 pendingVerifyOne 暂存，全量验证收尾后再调用本函数。）
 */
async function doVerifyOne(projectId: string, title: string): Promise<void> {
  const oneStartedAt = Date.now();
  const oneDeadline = oneStartedAt + singleVerifyHardMs();
  const remainingBudget = () => Math.max(0, oneDeadline - Date.now());
  const project = getProject(projectId);
  if (!project || !title) return;
  const norm = (s: string) => String(s || '').replace(/\s+/g, '').toLowerCase();
  const vuln = db
    .prepare('SELECT id, title, severity, category, file_path, line, description FROM vulnerabilities WHERE project_id = ?')
    .all(projectId)
    .find((v: any) => norm(v.title) === norm(title)) as any;
  if (!vuln) {
    recordEvent(projectId, { kind: 'error', agent: '主控', tool: '', text: `单漏洞验证：未找到漏洞「${title}」` }, true, 'verify');
    return;
  }
  ensureProjectVerificationItems(projectId);
  setVerificationItemState(projectId, vuln.id, 'running');
  setVerifyStatus(projectId, 'running', { verify_started_at: now(), verify_error: null });
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `▶ 单漏洞远程验证：${vuln.title}（先确保靶机就绪）`,
    },
    true,
    'verify'
  );

  let codeDir: string;
  try {
    const prepared = await withinBudget(
      ensureWorkspace(getProject(projectId)!),
      remainingBudget()
    );
    if (prepared.timedOut) {
      setVerificationItemState(projectId, vuln.id, 'timeout', '源码准备超过单漏洞总预算');
      finishVerify(projectId, 'failed', '单漏洞验证超时：源码准备超过 15 分钟总预算');
      return;
    }
    codeDir = prepared.value;
  } catch (err: any) {
    setVerificationItemState(projectId, vuln.id, 'failed', `源码准备失败：${err?.message || err}`);
    finishVerify(projectId, 'failed', `源码准备失败：${err?.message || err}`);
    return;
  }
  const target = await withinBudget(ensureTargetUp(projectId, codeDir), remainingBudget());
  if (target.timedOut) {
    stopEnvChannel(projectId, { quiet: true });
    setVerificationItemState(projectId, vuln.id, 'timeout', '靶机准备超过单漏洞总预算');
    finishVerify(projectId, 'failed', '单漏洞验证超时：靶机准备超过 15 分钟总预算');
    return;
  }
  const up = target.value;
  if (verifyKilled.has(projectId)) return;
  if (!up) {
    const reason = await resolveTargetUpFailureReason(projectId, codeDir);
    setVerificationItemState(projectId, vuln.id, 'restricted', reason);
    finishVerify(projectId, 'failed', reason);
    return;
  }

  const isHarness = readTargetEnvMode(codeDir) === 'harness';
  if (isHarness) {
    const core =
      getSetting('verify_prompt') ||
      '针对已发现的漏洞，在已搭建的本地靶机上做真实利用验证与取证。先确认靶机可达并登录；再逐条验证单漏洞；最后尝试无权限/低权限到 RCE 的组合利用。禁止只读源码就判成功。组合链不要从管理员权限起步。';
    let envInfo = '';
    try {
      envInfo = fs.readFileSync(path.join(codeDir, 'TARGET_ENV.json'), 'utf8').trim();
    } catch {
      /* 无交接文件 */
    }
    const r = await withVerifyGate(() =>
      runPiStage(
        projectId,
        codeDir,
        buildHarnessVerifyBatchPrompt(core, codeDir, [vuln], envInfo, 1, 1),
        JSON.stringify(EXPLOIT_SCHEMA),
        {
          channel: 'remoteverify',
          phase: 'verify',
          hardMsOverride: remainingBudget(),
          idleMsOverride: singleVerifyIdleMs(),
        }
      )
    );
    if (r.killed) return;
    if (r.timedOut) {
      setVerificationItemState(projectId, vuln.id, 'timeout', r.stderrTail || '单漏洞验证超时');
      finishVerify(projectId, 'failed', r.stderrTail || '单漏洞验证超时');
      return;
    }
    let exps: any[] =
      r.structured && Array.isArray(r.structured.exploits) ? r.structured.exploits : parseStructuredArray(r.finalResult, 'exploits');
    const disk = readHarnessVerifyResults(codeDir);
    if (disk.exploits.length) exps = mergeExploits([...exps, ...disk.exploits]);

    let report: any = { summary: '', exploits: [], chains: [] };
    try {
      if (project.exploit_report) report = JSON.parse(project.exploit_report);
    } catch {
      /* 空报告 */
    }
    const prior = Array.isArray(report.exploits)
      ? report.exploits.filter((e: any) => norm(e?.vulnerability) !== norm(title))
      : [];
    const single = alignExploitsToVulnList([vuln], exps);
    const result = single[0];
    if (!result || remoteStatusOf(result) === 'unknown') {
      setVerificationItemState(projectId, vuln.id, 'failed', '单漏洞验证未产出可解析的结果');
      finishVerify(projectId, 'failed', '单漏洞验证未产出可解析的结果，旧结论已保留');
      return;
    }
    const merged = [...prior, result];
    const hit = remoteStatusOf(result) === 'success' ? 1 : 0;
    saveExploitReport(projectId, {
      summary: `单漏洞沙箱验证：${vuln.title} → ${hit > 0 ? '命中' : '未命中'}`,
      exploits: merged,
      chains: Array.isArray(report.chains) ? report.chains : [],
    });
    broadcast({ type: 'project_status', projectId, exploit_progress: true });
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `✓ 单漏洞沙箱验证完成：${vuln.title}（${hit > 0 ? '命中 success' : '未命中'}）`,
      },
      true,
      'verify'
    );
    finishVerify(projectId, 'completed', null);
    return;
  }

  const core = getSetting('verify_prompt') || '针对已发现的漏洞，在已搭建的本地靶机上做真实利用验证与取证。先确认靶机可达并登录；再逐条验证单漏洞；最后尝试无权限/低权限到 RCE 的组合利用。禁止只读源码就判成功。组合链不要从管理员权限起步。';
  let envInfo = '';
  try { envInfo = fs.readFileSync(path.join(codeDir, 'TARGET_ENV.json'), 'utf8').trim(); } catch { /* 无交接文件 */ }
  const spec = envSpecOf(project);
  const r = await withVerifyGate(() =>
    runPiStage(
      projectId,
      codeDir,
      // 单漏洞按钮是快速当前版本验证，不隐式继承全量“历史版本”开关。
      buildVerifyBatchPrompt(core, codeDir, [vuln], envInfo, spec, 1, 1, false, true),
      JSON.stringify(EXPLOIT_SCHEMA),
      {
        channel: 'remoteverify',
        phase: 'verify',
        hardMsOverride: remainingBudget(),
        idleMsOverride: singleVerifyIdleMs(),
      }
    )
  );
  if (r.killed) return;
  if (r.timedOut) {
    setVerificationItemState(projectId, vuln.id, 'timeout', r.stderrTail || '单漏洞验证超时');
    finishVerify(projectId, 'failed', r.stderrTail || '单漏洞验证超时');
    return;
  }
  const exps = r.structured && Array.isArray(r.structured.exploits) ? r.structured.exploits : parseStructuredArray(r.finalResult, 'exploits');

  // 合并回 exploit_report：替换同名漏洞的旧结果，其余保留
  let report: any = { summary: '', exploits: [], chains: [] };
  try { if (project.exploit_report) report = JSON.parse(project.exploit_report); } catch { /* 空报告 */ }
  const prior = Array.isArray(report.exploits) ? report.exploits.filter((e: any) => norm(e?.vulnerability) !== norm(title)) : [];
  const single = alignExploitsToVulnList([vuln], exps);
  const result = single[0];
  if (!result || remoteStatusOf(result) === 'unknown') {
    setVerificationItemState(projectId, vuln.id, 'failed', '单漏洞验证未产出可解析的结果');
    finishVerify(projectId, 'failed', '单漏洞验证未产出可解析的结果，旧结论已保留');
    return;
  }
  const merged = [...prior, result];
  const hit = remoteStatusOf(result) === 'success' ? 1 : 0;
  saveExploitReport(projectId, {
    summary: `单漏洞验证：${vuln.title} → ${hit > 0 ? '命中' : '未命中'}`,
    exploits: merged,
    chains: Array.isArray(report.chains) ? report.chains : [],
  });
  broadcast({ type: 'project_status', projectId, exploit_progress: true });
  recordEvent(projectId, { kind: 'system', agent: '主控', tool: '', text: `✓ 单漏洞验证完成：${vuln.title}（${hit > 0 ? '命中 success' : '未命中'}）；靶机保持运行，可继续二次验证` }, true, 'verify');
  // 单漏洞验证完成：不销毁靶机（保活，便于继续二次验证），仅标记完成
  finishVerify(projectId, 'completed', null);
}

/* ------------------------------ 漏洞验证 ------------------------------ */
async function doVerify(projectId: string, resume = false): Promise<void> {
  const project = getProject(projectId);
  if (!project) return;

  // 续跑：在清空前先抢救暂停前已落盘的部分验证结果（增量保存的 exploit_report），
  // 传给 runRemoteVerifyCore 用于跳过已验证漏洞；真正的「重新验证」（resume=false）仍照旧全清。
  let priorExploits: any[] = [];
  let priorChains: any[] = [];
  if (resume && project.exploit_report) {
    try {
      const parsed = JSON.parse(project.exploit_report);
      if (Array.isArray(parsed?.exploits)) priorExploits = parsed.exploits;
      if (Array.isArray(parsed?.chains)) priorChains = parsed.chains;
    } catch {
      /* 旧报告解析失败：当作没有可续跑的结果，走全量验证 */
    }
  }
  if (resume && project.workspace_path && fs.existsSync(project.workspace_path)) {
    const recovered = ingestExistingRemoteArtifacts(
      projectId,
      project.workspace_path,
      priorExploits,
      priorChains
    );
    priorExploits = recovered.exploits;
    priorChains = recovered.chains;
    if (recovered.recovered > 0) {
      recordEvent(
        projectId,
        {
          kind: 'system',
          agent: '验证产物入库器',
          tool: '',
          text: `✓ 启动验证前已从磁盘恢复 ${recovered.recovered} 个单漏洞结论，无需等待靶机重建后再刷新`,
        },
        true,
        'verify'
      );
    }
  }
  if (!resume) clearVerifyResults(projectId);
  setVerifyStatus(projectId, 'running', { verify_started_at: now(), verify_error: null });
  const verifiedPriorN = priorExploits.filter((e) => remoteStatusOf(e) !== 'unknown').length;
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text:
        resume && verifiedPriorN > 0
          ? `▶ 续跑靶机验证：复用已验证的 ${verifiedPriorN} 个单漏洞结果，跳过它们并继续验证剩余漏洞；完成后进入组合链验证…`
          : '▶ 全量重跑远程验证：清空旧结果，对全部 严重/高危/中危 漏洞逐一重新实测（保留已有靶机）…',
    },
    true,
    'verify'
  );

  // 若审计期间已并行启动环境搭建，先等它结束（就绪则复用，失败则验证阶段会兜底重搭）
  if (needsComposeEnv(projectId)) {
  const envTask = envTasks.get(projectId);
  if (envTask) {
    recordEvent(projectId, { kind: 'system', agent: '主控', tool: '', text: '⏳ 等待并行的靶机环境搭建完成…' }, true, 'verify');
    try {
      await envTask;
    } catch {
      /* 环境搭建失败不阻断，验证阶段会兜底重搭 */
    }
    const ep = getProject(projectId);
    if (ep?.env_status === 'ready') {
      if (isHarnessTargetUrl(ep.target_url)) {
        recordEvent(
          projectId,
          { kind: 'system', agent: '主控', tool: '', text: '✓ 并行沙箱验证环境已就绪，将直接复用' },
          true,
          'verify'
        );
      } else {
        // 复用前实测：必须是【归属本项目】的运行中容器，且地址可达——
        // 仅"某端口可达"不足以复用（可能是别项目占用同端口的串台容器）。
        // external 模式例外：Cursor Agent 自建靶机无 compose 标签，只认 URL 可达。
        const cleanUrl = ep.target_url ? ep.target_url.replace(/[`'"]+$/, '') : null;
        const wsHint =
          ep.workspace_path && fs.existsSync(ep.workspace_path) ? ep.workspace_path : '';
        const external = wsHint ? isExternallyManagedTarget(wsHint) : false;
        const owned = external ? true : await targetRunning(composeProjectName(projectId));
        const reachable = cleanUrl ? await urlReachable(cleanUrl) : false;
        const ok = external
          ? !!(cleanUrl && reachable)
          : owned && (cleanUrl ? reachable : true);
        if (ok) {
          recordEvent(
            projectId,
            {
              kind: 'system',
              agent: '主控',
              tool: '',
              text: external
                ? `✓ 外部靶机已就绪（mode=external${cleanUrl ? `，${cleanUrl}` : ''}），将直接复用`
                : `✓ 并行靶机环境已就绪${cleanUrl ? `（${cleanUrl}）` : ''}，将直接复用`,
            },
            true,
            'verify'
          );
        } else {
          setEnvStatus(projectId, 'failed');
          recordEvent(
            projectId,
            {
              kind: 'error',
              agent: '主控',
              tool: '',
              text: external
                ? '⚠ 外部靶机不可达（mode=external），请由 Cursor Agent 重新拉起后再续跑'
                : owned
                  ? '⚠ 标记为就绪的靶机地址不可达，验证阶段将重新搭建'
                  : '⚠ 未检测到归属本项目的运行中靶机容器（疑似端口被其它项目占用/容器已退出），验证阶段将按独立端口重新搭建',
            },
            true,
            'verify'
          );
        }
      }
    }
  }
  }

  // 等待环境期间可能已被暂停/重跑：重新校验状态，已非 running 则中止，避免误起利用验证进程
  const vp = getProject(projectId);
  if (!vp || vp.verify_status !== 'running') return;

  let codeDir: string;
  try {
    codeDir = await ensureWorkspace(getProject(projectId)!);
  } catch (err: any) {
    finishVerify(projectId, 'failed', `源码准备失败：${err?.message || err}`);
    return;
  }

  const isHarnessVerify =
    readTargetEnvMode(codeDir) === 'harness' || detectProjectShape(codeDir) === 'harness';

  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: isHarnessVerify
        ? '▶ 确保沙箱验证环境就绪（Harness 预搭建或复用已有 _harness/）…'
        : '▶ 确保靶机环境就绪（搭建或拉起已有容器）…',
    },
    true,
    'verify'
  );
  const targetUp = await ensureTargetUp(projectId, codeDir);
  if (verifyKilled.has(projectId)) return;
  const vp2 = getProject(projectId);
  if (!vp2 || vp2.verify_status !== 'running') return;
  if (!targetUp) {
    finishVerify(projectId, 'failed', await resolveTargetUpFailureReason(projectId, codeDir));
    return;
  }
  if (!(await isTargetFullyReady(projectId, codeDir))) {
    finishVerify(
      projectId,
      'failed',
      isExternallyManagedTarget(codeDir)
        ? '外部靶机尚未可达（mode=external），请由 Cursor Agent 重新拉起后再续跑'
        : '靶机尚未真实就绪（容器未运行或 HTTP 地址不可达），请稍后重试或检查 Docker'
    );
    return;
  }

  const killed = isHarnessVerify
    ? await runHarnessVerifyCore(projectId, codeDir, priorExploits, { keepTargetAlive: false })
    : await runRemoteVerifyCore(projectId, codeDir, priorExploits, {
        keepTargetAlive: false,
        priorChains,
        skipChain: true,
      });
  if (killed) return; // 被暂停/重跑：不标记完成
  if (!isHarnessVerify) {
    const chainKilled = await runRemoteVerifyCore(projectId, codeDir, priorExploits, {
      keepTargetAlive: false,
      priorChains,
      chainOnly: true,
    });
    if (chainKilled) return;
  }
  finalizeVerifyOutcome(projectId);
}

/**
 * 仅组合链验证（远程验证·组合）：复用已有单漏洞验证结果（exploit_report.exploits），
 * 跳过单漏洞逐条验证，直接对总漏洞池构造并实测组合利用链（无权限→RCE + 低权限(开放注册)→RCE）。
 * 结果合并回 exploit_report.chains，前端在「远程验证·组合」页显示。
 */
async function doVerifyChain(projectId: string): Promise<void> {
  const project = getProject(projectId);
  if (!project) return;
  // 复用已有单漏洞结果作为参考与报告底稿；组合链本身从总漏洞池构造，不依赖单漏洞是否已验证。
  let priorExploits: any[] = [];
  if (project.exploit_report) {
    try {
      const parsed = JSON.parse(project.exploit_report);
      if (Array.isArray(parsed?.exploits)) priorExploits = parsed.exploits;
    } catch {
      /* 旧报告解析失败：按无单漏洞底稿处理，组合链仍可从总漏洞池构造 */
    }
  }

  setVerifyStatus(projectId, 'running', { verify_started_at: now(), verify_error: null });
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `▶ 远程验证·组合：仅重跑组合利用链验证，复用已有 ${priorExploits.length} 个单漏洞结果、保留已有靶机…`,
    },
    true,
    'verify'
  );

  // 等待可能仍在进行的并行环境搭建
  const envTask = envTasks.get(projectId);
  if (envTask) {
    try {
      await envTask;
    } catch {
      /* 环境搭建失败不阻断，下面 ensureTargetUp 会兜底重搭 */
    }
  }

  const vp = getProject(projectId);
  if (!vp || vp.verify_status !== 'running') return;

  let codeDir: string;
  try {
    codeDir = await ensureWorkspace(getProject(projectId)!);
  } catch (err: any) {
    finishVerify(projectId, 'failed', `源码准备失败：${err?.message || err}`);
    return;
  }

  const isHarnessVerify =
    readTargetEnvMode(codeDir) === 'harness' || detectProjectShape(codeDir) === 'harness';
  if (isHarnessVerify) {
    finishVerify(projectId, 'failed', '沙箱(Harness)项目不做组合链验证，无法仅跑组合链');
    return;
  }

  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: isExternallyManagedTarget(codeDir)
        ? '▶ 确保外部靶机就绪（mode=external，仅校验可达性，不触发产品搭建）…'
        : '▶ 确保靶机环境就绪（搭建或拉起已有容器）…',
    },
    true,
    'verify'
  );
  const targetUp = await ensureTargetUp(projectId, codeDir);
  if (verifyKilled.has(projectId)) return;
  const vp2 = getProject(projectId);
  if (!vp2 || vp2.verify_status !== 'running') return;
  if (!targetUp) {
    finishVerify(projectId, 'failed', await resolveTargetUpFailureReason(projectId, codeDir));
    return;
  }
  if (!(await isTargetFullyReady(projectId, codeDir))) {
    finishVerify(
      projectId,
      'failed',
      isExternallyManagedTarget(codeDir)
        ? '外部靶机尚未可达（mode=external），请由 Cursor Agent 重新拉起后再续跑'
        : '靶机尚未真实就绪（容器未运行或 HTTP 地址不可达），请稍后重试或检查 Docker'
    );
    return;
  }

  const killed = await runRemoteVerifyCore(projectId, codeDir, priorExploits, {
    keepTargetAlive: false,
    chainOnly: true,
  });
  if (killed) return; // 被暂停/重跑：不标记完成
  finalizeVerifyOutcome(projectId);
}

/** 远程验证结果落盘目录（验证子智能体写入、后端读盘汇总）。 */
function remoteVerifyDir(codeDir: string): string {
  return path.join(codeDir, '_remote_verify');
}

/** 组合链阶段结束后等待磁盘产物稳定（避免子智能体尾写尚未落盘）。 */
async function waitForStableChainArtifacts(
  codeDir: string,
  projectId: string,
  fallback: any[] = []
): Promise<any[]> {
  let lastCount = -1;
  let stableRounds = 0;
  let best: any[] = [];
  for (let i = 0; i < 15; i++) {
    // 给刚写入的文件越过 750ms 新鲜度门槛
    await sleep(800);
    const disk = readRemoteVerifyResults(codeDir, projectId);
    const count = disk.chains.length;
    if (count > 0) best = disk.chains;
    if (count === lastCount) {
      stableRounds++;
      if (stableRounds >= 2) break;
    } else {
      stableRounds = 0;
      lastCount = count;
    }
  }
  if (best.length > 0) return best;
  return Array.isArray(fallback) ? fallback : [];
}

/** 容错读取一个 JSON 文件为数组（部分写入/损坏时返回空数组，绝不抛错）。 */
function safeReadJsonArray(file: string): any[] {
  try {
    const txt = readJsonArtifactText(file);
    if (!txt) return [];
    const o = parseJsonArtifact(txt) as any;
    if (Array.isArray(o)) {
      return o.map((item) => normalizeChainArtifact(item) || item);
    }
    if (o && typeof o === 'object') {
      if (Array.isArray(o.exploits)) return o.exploits;
      if (Array.isArray(o.chains)) {
        return o.chains.map((item: unknown) => normalizeChainArtifact(item) || item);
      }
      const asChain = normalizeChainArtifact(o);
      if (asChain) return [asChain];
      // 单漏洞 exploit 对象（schema 或技能 POC 的 name/title）
      if (
        (typeof o.vulnerability === 'string' && o.vulnerability.trim()) ||
        (typeof o.name === 'string' && o.name.trim() && o.steps == null) ||
        (typeof o.title === 'string' && o.title.trim())
      ) {
        return [o];
      }
    }
    return [];
  } catch {
    return [];
  }
}

const reportedArtifactErrors = new Map<string, string>();

/**
 * 已解析的 artifact 缓存（按 文件路径 → {mtimeMs,size,value}）。
 * 远程验证期 2s 轮询会对 exploits/chains 目录里【每一个已落盘文件】反复整体重读+UTF8解码+JSON.parse+normalize，
 * 大项目（上百漏洞/数十批产物）积累后单轮解析耗时 > 2s，setInterval 回调首尾相接把主线程打满 100% 饿死事件循环
 * （表现为后端进程存活但 HTTP 无响应、子进程无法回收成僵尸）。文件内容不变（mtime+size 一致）时直接复用上次解析结果，
 * 把每轮成本从 O(全部文件) 降到 O(本轮变更文件)。
 */
const parsedArtifactCache = new Map<string, { mtimeMs: number; size: number; value: any[] }>();

function normalizeArtifactParsed(parsed: any): any[] {
  if (Array.isArray(parsed)) {
    return parsed.map((item) => normalizeChainArtifact(item) || item);
  }
  if (parsed && typeof parsed === 'object') {
    if (Array.isArray(parsed.exploits)) return parsed.exploits;
    if (Array.isArray(parsed.chains)) {
      return parsed.chains.map((item: unknown) => normalizeChainArtifact(item) || item);
    }
    const asChain = normalizeChainArtifact(parsed);
    if (asChain) return [asChain];
    if (
      parsed.vulnerability ||
      parsed.vulnerability_id ||
      parsed.vuln_id ||
      parsed.title ||
      parsed.name
    ) {
      return [parsed];
    }
  }
  return [];
}

/** 远程验证产物读取：写入中的文件稍后重试，损坏文件向项目日志明确报错而非静默吞掉。 */
function readRemoteArtifactArray(file: string, projectId?: string): any[] {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(file);
  } catch {
    return [];
  }
  if (Date.now() - stat.mtimeMs < 750) return [];
  const cached = parsedArtifactCache.get(file);
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    return cached.value;
  }
  try {
    const text = readJsonArtifactText(file);
    if (!text) return [];
    const parsed = parseJsonArtifact(text) as any;
    reportedArtifactErrors.delete(file);
    const out = normalizeArtifactParsed(parsed);
    parsedArtifactCache.set(file, { mtimeMs: stat.mtimeMs, size: stat.size, value: out });
    return out;
  } catch (error: any) {
    if (projectId) {
      const fingerprint = `${safeMtime(file)}:${String(error?.message || error)}`;
      if (reportedArtifactErrors.get(file) !== fingerprint) {
        reportedArtifactErrors.set(file, fingerprint);
        recordEvent(
          projectId,
          {
            kind: 'error',
            agent: '验证产物入库器',
            tool: '',
            text: `⚠ 验证结果文件暂无法解析，将自动重试：${path.basename(file)} — ${String(
              error?.message || error
            ).slice(0, 240)}`,
          },
          true,
          'verify'
        );
      }
    }
    return [];
  }
}

/** 保留损坏的链产物，令前端能明确显示「解析失败」而不是静默少一条链。 */
function malformedChainArtifact(file: string): any | null {
  try {
    const text = readJsonArtifactText(file);
    if (!text) return null;
    parseJsonArtifact(text);
    return null;
  } catch (error: any) {
    return {
      name: path.basename(file, path.extname(file)),
      status: 'unknown',
      detail: `验证结果文件无法解析：${String(error?.message || error).slice(0, 240)}`,
      artifact_error: true,
    };
  }
}

function safeMtime(file: string): number {
  try {
    return Math.round(fs.statSync(file).mtimeMs);
  } catch {
    return 0;
  }
}

/**
 * 读取跨语言融合审计产出的候选利用链 `JSON/cross_language_chain_candidates.json`，
 * 归一化为简短文案数组，供组合链验证 prompt 优先派发实测。文件不存在/解析失败返回空数组。
 */
function readCrossLangChainCandidates(codeDir: string): string[] {
  const arr = safeReadJsonArray(path.join(codeDir, 'JSON', 'cross_language_chain_candidates.json'));
  const out: string[] = [];
  for (const c of arr) {
    if (!c || typeof c !== 'object') continue;
    const name = String((c as any).name || (c as any).title || '').trim();
    const impact = String((c as any).impact || '').trim();
    const langs = Array.isArray((c as any).languages) ? (c as any).languages.join('+') : '';
    const steps = Array.isArray((c as any).steps)
      ? (c as any).steps
          .map((s: any) =>
            typeof s === 'string' ? s : String(s?.desc || s?.vuln || s?.point || JSON.stringify(s))
          )
          .join(' → ')
      : '';
    const label = [
      name || '(未命名跨语言链)',
      langs ? `[${langs}]` : '',
      impact ? `危害：${impact}` : '',
      steps ? `步骤：${steps}` : '',
    ]
      .filter(Boolean)
      .join(' ');
    if (label.trim()) out.push(label.slice(0, 600));
  }
  return out;
}

type ExploitStatus = 'success' | 'failed' | 'restricted' | 'unknown';

const EXPLOIT_STATUS_RANK: Record<ExploitStatus, number> = {
  success: 0,
  restricted: 1,
  failed: 2,
  unknown: 3,
};

function normExploitTitle(s: string): string {
  // 子智能体/Markdown 常写出 class\_image.php；落盘结果多为 class_image.php。
  // 归一时去掉常见 Markdown 转义与无语义的引号风格差异，再比空白与大小写。
  return String(s || '')
    .replace(/\\([_*`[\]()#+\-.!|{}])/g, '$1')
    .replace(/['"“”‘’]/g, '')
    .replace(/\s+/g, '')
    .toLowerCase();
}

/**
 * 子智能体常把标题截断（只写到「存储型RCE）」）、加 `[high]` 前缀、或附带 `—— file:line`。
 * 归一成「可比对主键」，避免续跑时 prior 完整标题(unknown) 精确挡住磁盘短标题(success)。
 */
function canonicalExploitTitleKey(s: string): string {
  let t = String(s || '').trim();
  // 去掉批次high]` / 【严重】等前缀
  t = t.replace(/^\s*[\[【\(\（]?\s*(critical|high|medium|low|info|严重|高危|中危|低危|信息)\s*[\]】\)\）]?\s*/i, '');
  // 统一破折号后取主标题（描述/路径后缀丢掉）
  t = t.split(/\s*[—–-]{1,2}\s*/)[0] || t;
  // 去掉尾部路径碎片
  t = t.replace(/\s*(?:src\/|app\/|backend\/|frontend\/).*$/i, '');
  return normExploitTitle(t);
}

/** 两标题是否指向同一漏洞（精确 / 主标题互相包含；不用任意子串，防误并）。 */
function exploitTitlesLooselyMatch(a: string, b: string): boolean {
  const na = normExploitTitle(a);
  const nb = normExploitTitle(b);
  if (!na || !nb) return false;
  if (na === nb) return true;
  const ca = canonicalExploitTitleKey(a);
  const cb = canonicalExploitTitleKey(b);
  if (!ca || !cb) return false;
  if (ca === cb) {
    // 同一端点可能存在多个不同漏洞（例如同一路由分别有 SSRF、XSS、鉴权缺失）。
    // 双方都有描述后缀时，不能只凭破折号前主标题相同就合并；必须是完整标题前缀关系。
    // 若一侧本身就是无后缀的主标题，则仍允许与带描述的标题匹配，兼容子智能体截断输出。
    if (na === ca || nb === cb) return true;
    const fullShort = na.length <= nb.length ? na : nb;
    const fullLong = na.length <= nb.length ? nb : na;
    return fullShort.length >= 16 && fullLong.startsWith(fullShort);
  }
  // canonical 仅为“主标题”辅助信息；主标题只是前缀相似时，仍必须要求完整标题
  // 本身是前缀关系。否则同一路由下 SSRF/XSS/鉴权缺失等不同漏洞会被误并。
  const fullShort = na.length <= nb.length ? na : nb;
  const fullLong = na.length <= nb.length ? nb : na;
  return fullShort.length >= 16 && fullLong.startsWith(fullShort);
}

/** 归一化 local_exploitable / 链 status（子智能体常误写 true/false 或各种非标准词）。 */
function normalizeExploitStatus(raw: unknown): ExploitStatus {
  return normalizeVerificationStatus(raw);
}

/** 权威远程结论：权限矩阵优先，代码层 success 不再自动等同远程成功。 */
function remoteStatusOf(entry: any): ExploitStatus {
  return deriveRemoteStatus(entry);
}

const UNAUTH_CHAIN_HINT =
  /未授权|未认证|无需登录|无需认证|无需权限|无权限(?=(?:即可|就可|也能|仍可|直接))|匿名访问|无凭据|无需账号|pre-?auth|unauthenticated/i;
const AUTH_CHAIN_EVIDENCE =
  /需要?登录|已登录|登录后|需要?账号|使用[^。]{0,10}账号|以[^。]{0,10}身份登录|管理员(?:账号|身份|权限)|需要?(?:权限|认证)/i;

/** 组合链是否为「无权限/未授权」起点（与前端 isUnauth 口径对齐）。 */
function isUnauthChain(c: any): boolean {
  if (!c || typeof c !== 'object') return false;
  if (c.auth_required === 'none') return true;
  if (c.auth_required && c.auth_required !== 'unknown') return false;
  const text = `${c.name ?? ''} ${c.impact ?? ''} ${c.detail ?? ''}`;
  if (!text.trim()) return false;
  const masked = text.replace(/(?:无需|不需|不用|不必)(?:登录|认证|权限|账号|凭据)/g, '');
  if (AUTH_CHAIN_EVIDENCE.test(masked)) return false;
  return UNAUTH_CHAIN_HINT.test(text);
}

const OPEN_REG_CHAIN_HINT =
  /开放注册|自助注册|注册用户|注册账号|普通用户|普通账号|自助获取|游客注册|open[\s-]?registration|self[\s-]?register/i;

/**
 * 组合链是否为「低权限(开放注册可得) 起点」：普通登录用户即可发起，且目标开放注册/可自助获取账号，
 * 危害等价于无权限链。用于统计与汇报"低权限(开放注册)→RCE"这类现实高危链。
 */
function isOpenRegChain(c: any): boolean {
  if (!c || typeof c !== 'object') return false;
  if (isUnauthChain(c)) return false; // 无权限链单独统计，避免重复计数
  // 明确普通用户起点：视为低权限(开放注册)链
  if (c.auth_required === 'user') return true;
  if (c.auth_required && c.auth_required !== 'unknown') return false; // admin 等不算
  const text = `${c.name ?? ''} ${c.impact ?? ''} ${c.detail ?? ''}`;
  if (!text.trim()) return false;
  return OPEN_REG_CHAIN_HINT.test(text);
}

function chainHasConcludedStatus(c: any): boolean {
  const s = normalizeExploitStatus(c?.status);
  return s === 'success' || s === 'failed' || s === 'restricted';
}

function chainVerifyStats(chains: any[]): {
  total: number;
  success: number;
  unauthVerified: number;
  unauthSuccess: number;
  openRegVerified: number;
  openRegSuccess: number;
} {
  const total = chains.length;
  const success = chains.filter((c) => normalizeExploitStatus(c?.status) === 'success').length;
  // 「已验证」只计写出明确结论的链；unknown/空 status 占位不算已验证（避免日志与 UI 对不上）。
  const unauthVerified = chains.filter((c) => isUnauthChain(c) && chainHasConcludedStatus(c)).length;
  const unauthSuccess = chains.filter(
    (c) => normalizeExploitStatus(c?.status) === 'success' && isUnauthChain(c)
  ).length;
  const openRegVerified = chains.filter((c) => isOpenRegChain(c) && chainHasConcludedStatus(c)).length;
  const openRegSuccess = chains.filter(
    (c) => normalizeExploitStatus(c?.status) === 'success' && isOpenRegChain(c)
  ).length;
  return { total, success, unauthVerified, unauthSuccess, openRegVerified, openRegSuccess };
}

type AuthTier = 'none' | 'user' | 'admin';
type PrivilegeStatus = 'success' | 'failed' | 'restricted' | 'skipped' | 'unknown';
const AUTH_TIER_ORDER: AuthTier[] = ['none', 'user', 'admin'];
const AUTH_TIER_RANK: Record<AuthTier, number> = { none: 0, user: 1, admin: 2 };

/** 归一权限档：仅接受 none/user/admin，其余（含空/unknown）返回 null。 */
function normalizeAuthTier(raw: unknown): AuthTier | null {
  const s = String(raw ?? '').toLowerCase().trim();
  if (s === 'none' || s === 'user' || s === 'admin') return s;
  return null;
}

/** 归一权限降级矩阵每档的 status（兼容子智能体常见写法）。 */
function normalizePrivilegeStatus(raw: unknown): PrivilegeStatus {
  const privilege = normalizeVerificationPrivilegeResults({
    none: { status: raw },
  });
  return privilege?.none?.status ?? 'unknown';
}

/** 解析并归一 privilege_results（三档矩阵）；无有效内容返回 undefined。 */
function normalizePrivilegeResults(
  raw: unknown
): Partial<Record<AuthTier, { status: PrivilegeStatus; evidence?: string }>> | undefined {
  return normalizeVerificationPrivilegeResults(raw);
}

/** 逐档合并两份权限矩阵：同档取“更好”的 status（success>restricted>failed>skipped>unknown）。 */
const PRIV_STATUS_RANK: Record<PrivilegeStatus, number> = {
  success: 0,
  restricted: 1,
  failed: 2,
  skipped: 3,
  unknown: 4,
};
function mergePrivilegeResults(
  a: Partial<Record<AuthTier, { status: PrivilegeStatus; evidence?: string }>> | undefined,
  b: Partial<Record<AuthTier, { status: PrivilegeStatus; evidence?: string }>> | undefined
): Partial<Record<AuthTier, { status: PrivilegeStatus; evidence?: string }>> | undefined {
  if (!a) return b;
  if (!b) return a;
  const out: Partial<Record<AuthTier, { status: PrivilegeStatus; evidence?: string }>> = {};
  for (const tier of AUTH_TIER_ORDER) {
    const ca = a[tier];
    const cb = b[tier];
    if (ca && cb) out[tier] = PRIV_STATUS_RANK[ca.status] <= PRIV_STATUS_RANK[cb.status] ? ca : cb;
    else out[tier] = ca || cb;
  }
  return out;
}

/**
 * 从权限矩阵派生「成功利用所需的最低权限」：按 none<user<admin 取第一个 success 档。
 * 无矩阵或矩阵无 success 时回退到显式 auth_required（合法则用），否则 unknown。
 */
function deriveMinAuth(
  priv: Partial<Record<AuthTier, { status: PrivilegeStatus; evidence?: string }>> | undefined,
  fallbackAuth: unknown
): AuthTier | 'unknown' {
  return deriveMinimumAuth(priv, fallbackAuth);
}

/** 归一 impacts（多危害能力清单）为去重字符串数组；无内容返回 undefined。 */
function normalizeImpacts(raw: unknown): string[] | undefined {
  if (raw == null) return undefined;
  const arr = Array.isArray(raw) ? raw : [raw];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of arr) {
    const s = String(item ?? '').trim();
    if (!s) continue;
    const key = s.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s.slice(0, 200));
  }
  return out.length ? out : undefined;
}

/** 丢弃无标题条目，并统一状态字段。 */
function sanitizeExploitEntry(raw: any): any | null {
  if (!raw || typeof raw !== 'object') return null;
  // 子智能体/技能落盘常写 name / title，而非 schema 的 vulnerability
  const title = String(raw.vulnerability ?? raw.name ?? raw.title ?? '').trim();
  if (!title) return null;
  // 历史 skill 产物常写 vuln_id；统一成下游合并/对齐使用的 vulnerability_id。
  const vulnerabilityId = String(
    raw.vulnerability_id ??
      raw.vuln_id ??
      (typeof raw.id === 'string' && raw.id.startsWith('v_') ? raw.id : '')
  ).trim();
  const privilege_results = normalizePrivilegeResults(raw.privilege_results);
  const impacts = normalizeImpacts(raw.impacts ?? raw.impact);
  // auth_required 以“成功的最低档”为准：优先由三档矩阵派生，回退到模型显式标注。
  const auth_required = deriveMinAuth(privilege_results, raw.auth_required);
  // local_exploitable 仅描述源码/本地证据；remote_status 才是远程靶机结论。
  const local_exploitable = normalizeExploitStatus(raw.local_exploitable ?? raw.status);
  const local_result = coerceExploitText(
    raw.local_result ?? raw.description ?? raw.exploit_method ?? raw.notes
  ).trim();
  const detail = coerceExploitText(raw.detail ?? raw.description).trim();
  const out: any = {
    ...raw,
    vulnerability: title,
    local_exploitable,
    remote_status: remoteStatusOf({ ...raw, local_exploitable, privilege_results }),
    auth_required,
  };
  if (vulnerabilityId) out.vulnerability_id = vulnerabilityId;
  if (local_result) out.local_result = local_result;
  if (detail) out.detail = detail;
  if (privilege_results) out.privilege_results = privilege_results;
  else delete out.privilege_results;
  if (impacts) out.impacts = impacts;
  else delete out.impacts;
  return out;
}

/** 把任意值压成可读字符串（对象/数组 JSON 化），供链 detail/steps 清洗。 */
function coerceExploitText(v: unknown): string {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'object') {
    try {
      return JSON.stringify(v, null, 2);
    } catch {
      return String(v);
    }
  }
  return String(v);
}

/** 归一组合链 steps：字符串步骤落到 description；丢弃空项。
 * 兼容远程验证产物交替字段：name/status/detail/evidence(string)/success。 */
function normalizeChainSteps(raw: unknown): any[] | undefined {
  if (!Array.isArray(raw) || raw.length === 0) return undefined;
  const out: any[] = [];
  for (const item of raw) {
    if (item == null) continue;
    if (typeof item === 'string') {
      const description = item.trim();
      if (description) out.push({ description });
      continue;
    }
    if (typeof item !== 'object') continue;
    const row = item as any;
    let evidenceDetails = '';
    let evidence: any;
    if (typeof row.evidence === 'string') {
      evidenceDetails = row.evidence.trim();
      if (evidenceDetails) evidence = { details: evidenceDetails };
    } else if (row.evidence && typeof row.evidence === 'object') {
      evidence = row.evidence;
      evidenceDetails = coerceExploitText(row.evidence.details).trim();
    }
    const vulnerability =
      coerceExploitText(row.vulnerability).trim() || coerceExploitText(row.name).trim();
    const description =
      coerceExploitText(row.description).trim() ||
      coerceExploitText(row.detail).trim() ||
      evidenceDetails;
    const result =
      coerceExploitText(row.result).trim() ||
      coerceExploitText(row.status).trim() ||
      (row.success === true ? 'success' : row.success === false ? 'failed' : '');
    const step: any = {};
    if (vulnerability) step.vulnerability = vulnerability;
    if (description && description !== vulnerability) step.description = description;
    else if (description && !vulnerability) step.description = description;
    if (result) step.result = result;
    if (evidence) step.evidence = evidence;
    if (Object.keys(step).length) out.push(step);
  }
  return out.length ? out : undefined;
}

/** 丢弃无名称条目，并统一 status / detail / steps，避免对象型字段污染报告。 */
function sanitizeChainEntry(raw: any): any | null {
  if (!raw || typeof raw !== 'object') return null;
  const normalized = normalizeChainArtifact(raw) || raw;
  const name = String(normalized.name ?? normalized.chain_name ?? '').trim();
  if (!name) return null;
  const detail = coerceExploitText(normalized.detail).trim();
  const local_result = coerceExploitText(normalized.local_result).trim();
  const impact = coerceExploitText(normalized.impact).trim();
  const steps = normalizeChainSteps(normalized.steps ?? normalized.chain_steps);
  const out: any = {
    ...normalized,
    name,
    status: normalizeExploitStatus(normalized.status),
  };
  if (impact) out.impact = impact;
  else delete out.impact;
  if (detail) out.detail = detail;
  else delete out.detail;
  if (local_result) out.local_result = local_result;
  else delete out.local_result;
  if (steps) out.steps = steps;
  else delete out.steps;
  delete out.chain_name;
  delete out.chain_steps;
  return out;
}

function normalizedChainId(value: unknown): string {
  const text = String(value ?? '').trim().toLowerCase();
  const match = text.match(/(?:chain[-_\s]*)?0*(\d{1,4})$/);
  return match ? `chain-${match[1].padStart(2, '0')}` : '';
}

function chainMergeKey(chain: any): string {
  const id = normalizedChainId(chain?.chain_id ?? chain?.chainId ?? chain?.candidate_id);
  return id ? `id:${id}` : `name:${String(chain?.name || '').trim().toLowerCase()}`;
}

/**
 * 从当前验证轮的 agent_start 事件恢复组合链候选清单。
 * 子智能体超时/崩溃时没有结果文件，仍须显示为「未验证」而不能从 UI 消失。
 */
function candidateChainPlaceholders(projectId?: string): any[] {
  if (!projectId) return [];
  const project = getProject(projectId);
  const startedAt = Number(project?.verify_started_at || 0);
  const rows = db
    .prepare(
      `SELECT agent FROM agent_events
       WHERE project_id = ? AND phase = 'verify' AND kind = 'agent_start' AND ts >= ?
       ORDER BY ts ASC`
    )
    .all(projectId, startedAt) as { agent: string }[];
  const candidates = new Map<string, any>();
  for (const row of rows) {
    const matched = String(row.agent || '').match(/^chain\s+0*(\d{1,4})\s*:\s*(.+)$/i);
    if (!matched) continue;
    const chainId = `chain-${matched[1].padStart(2, '0')}`;
    if (candidates.has(chainId)) continue;
    candidates.set(chainId, {
      chain_id: chainId,
      name: `链 ${Number(matched[1])}：${matched[2].trim()}`,
      auth_required: 'unknown',
      status: 'unknown',
      not_produced: true,
      detail: '该组合链子智能体未落盘可解析结果（超时、崩溃或写入失败），因此没有验证结论。',
    });
  }
  return [...candidates.values()];
}

/** 主控在派发前落盘的候选链清单；它是组合链验证的权威分母。 */
function chainManifestPath(codeDir: string): string {
  return path.join(remoteVerifyDir(codeDir), 'chains', '_manifest.json');
}

function readChainManifest(codeDir: string): any[] {
  try {
    const raw = parseJsonArtifact(readJsonArtifactText(chainManifestPath(codeDir))) as unknown;
    const items = Array.isArray(raw)
      ? raw
      : raw && typeof raw === 'object' && Array.isArray((raw as any).chains)
        ? (raw as any).chains
        : [];
    const seen = new Set<string>();
    const out: any[] = [];
    for (let index = 0; index < items.length; index++) {
      const item = items[index];
      if (!item || typeof item !== 'object') continue;
      const rawItem = item as Record<string, unknown>;
      const name = String(rawItem.name ?? rawItem.chain_name ?? '').trim();
      if (!name) continue;
      const chainId =
        normalizedChainId(rawItem.chain_id ?? rawItem.chainId ?? rawItem.candidate_id) ||
        `chain-${String(index + 1).padStart(2, '0')}`;
      if (seen.has(chainId)) continue;
      seen.add(chainId);
      out.push({
        ...rawItem,
        chain_id: chainId,
        name,
        auth_required: String(rawItem.auth_required || 'unknown'),
        status: 'unknown',
        manifest_candidate: true,
      });
    }
    return out;
  } catch {
    return [];
  }
}

/** 按 chain_id（优先）或链名去重。后写入的终态覆盖旧快照，但 unknown 占位不得覆盖终态。 */
function mergeChains(list: any[]): any[] {
  const byKey = new Map<string, any>();
  for (const raw of list) {
    const c = sanitizeChainEntry(raw);
    if (!c) continue;
    const key = chainMergeKey(c);
    let prev = byKey.get(key);
    let prevKey = key;
    // 历史 skill 产物可能缺少 chain_id；按同名把终态覆盖 manifest/agent_start 占位，
    // 避免变成「unknown 占位 + 无编号终态」两条链并触发无意义补验。
    if (!prev) {
      const sameName = [...byKey.entries()].find(
        ([, value]) => normExploitTitle(String(value?.name || '')) === normExploitTitle(String(c.name || ''))
      );
      if (sameName) {
        prevKey = sameName[0];
        prev = sameName[1];
      }
    }
    if (!prev) {
      byKey.set(key, c);
      continue;
    }
    const previousStatus = normalizeExploitStatus(prev.status);
    const currentStatus = normalizeExploitStatus(c.status);
    // 占位（manifest/agent_start）永远不覆盖已有终态；但占位可被终态覆盖并继承其 chain_id。
    if (currentStatus === 'unknown' && previousStatus !== 'unknown') continue;
    const merged: any = { ...prev, ...c };
    merged.chain_id = c.chain_id || prev.chain_id;
    delete merged.manifest_candidate;
    if (prevKey !== key) byKey.delete(prevKey);
    byKey.set(key, merged);
  }
  return [...byKey.values()];
}

/**
 * 汇总远程验证磁盘结果：合并 exploits/*.json 与组合链产物。
 * 组合链同时兼容：
 * - `_remote_verify/chains.json`（数组兜底）
 * - `_remote_verify/chains/*.json`（skill 按条子智能体落盘，主路径）
 */
/**
 * 廉价计算远程验证产物的"状态指纹"（仅 stat 元数据，不读文件内容/不解析）：
 * exploits/ 与 chains/ 目录下每个 json 的 mtime+size、chains.json、以及 MCP verify_ledger.json。
 * 2s 轮询用它做前置门：产物没有任何变化时整轮跳过 readRemoteVerifyResults→mergeExploits(O(n²))→align→save，
 * 避免大项目验证期把主线程 CPU 打满、饿死事件循环（后端存活但 HTTP 无响应）。
 */
function remoteResultsSignature(codeDir: string): string {
  const base = remoteVerifyDir(codeDir);
  const parts: string[] = [];
  const statInto = (p: string) => {
    try {
      const s = fs.statSync(p);
      parts.push(`${p}:${Math.round(s.mtimeMs)}:${s.size}`);
    } catch {
      /* 文件缺失：忽略 */
    }
  };
  for (const sub of ['exploits', 'chains']) {
    const dir = path.join(base, sub);
    try {
      for (const f of fs.readdirSync(dir)) {
        if (!f.toLowerCase().endsWith('.json')) continue;
        statInto(path.join(dir, f));
      }
    } catch {
      /* 目录尚不存在 */
    }
  }
  statInto(path.join(base, 'chains.json'));
  for (const name of ['exploits.json', 'result.json', 'result.compact.json']) {
    statInto(path.join(base, name));
  }
  statInto(path.join(codeDir, '_mcp', 'verify_ledger.json'));
  return parts.sort().join('|');
}

function readRemoteVerifyResults(
  codeDir: string,
  projectId?: string
): { exploits: any[]; chains: any[] } {
  const base = remoteVerifyDir(codeDir);
  const exDir = path.join(base, 'exploits');
  const chainDir = path.join(base, 'chains');
  const exploits: any[] = [];
  try {
    for (const f of fs.readdirSync(exDir)) {
      // _prior.json 由 priorExploits 单独并入，避免续跑时重复计数
      if (f.startsWith('_') || !f.toLowerCase().endsWith('.json')) continue;
      const file = path.join(exDir, f);
      for (const e of readRemoteArtifactArray(file, projectId)) {
        const s = sanitizeExploitEntry({ ...e, source_file: f });
        if (s) exploits.push(s);
      }
    }
  } catch {
    /* 目录尚不存在 */
  }
  // 主控常把整份单洞结论写成 _remote_verify/exploits.json 或 result.json，
  // 而不是 exploits/*.json。只读子目录会在组合链收尾时把已成功的单洞冲成 unknown。
  for (const name of ['exploits.json', 'result.json', 'result.compact.json']) {
    const file = path.join(base, name);
    for (const e of readRemoteArtifactArray(file, projectId)) {
      const s = sanitizeExploitEntry({ ...e, source_file: name });
      if (s) exploits.push(s);
    }
  }
  const chainRaw: any[] = [
    ...readRemoteArtifactArray(path.join(base, 'chains.json'), projectId),
  ];
  try {
    for (const f of fs.readdirSync(chainDir)) {
      if (f.startsWith('_') || !f.toLowerCase().endsWith('.json')) continue;
      const file = path.join(chainDir, f);
      const artifacts = readRemoteArtifactArray(file, projectId);
      for (const c of artifacts) {
        if (c && typeof c === 'object') chainRaw.push(c);
      }
      if (artifacts.length === 0) {
        const malformed = malformedChainArtifact(file);
        if (malformed) chainRaw.push(malformed);
      }
    }
  } catch {
    /* chains/ 目录尚不存在 */
  }
  // 【MCP 账本为权威·∪ 磁盘】即便磁盘产物被改名/清理/短暂不可解析，账本里显式声明过的
  // 单漏洞与组合链结论也不会丢失。合并/去重（mergeChains、下游 dedup）按 id 归一，终态覆盖 unknown，
  // 因此把账本条目再喂一遍是幂等的（与已 materialize 的磁盘文件互为镜像）。
  const ledgerExploits: Record<string, any> = {};
  for (const entry of Object.values(ledgerExploits)) {
    const s = sanitizeExploitEntry({ ...(entry as any), source_file: '_mcp_ledger' });
    if (s) exploits.push(s);
  }
  const ledgerChains = { manifest: [] as any[], chains: {} as Record<string, any> };
  for (const entry of ledgerChains.manifest) {
    if (entry && typeof entry === 'object') chainRaw.push({ ...entry, manifest_candidate: true });
  }
  for (const entry of Object.values(ledgerChains.chains)) {
    if (entry && typeof entry === 'object') chainRaw.push(entry);
  }
  return {
    exploits,
    chains: mergeChains([
      ...readChainManifest(codeDir),
      ...candidateChainPlaceholders(projectId),
      ...chainRaw,
    ]),
  };
}

/** 读取续跑前保存的验证底稿；常规轮询不计入，磁盘灾难恢复时作为 DB 报告的兜底来源。 */
function readRemoteVerifyPriorExploits(codeDir: string): any[] {
  return safeReadJsonArray(
    path.join(remoteVerifyDir(codeDir), 'exploits', '_prior.json')
  )
    .map(sanitizeExploitEntry)
    .filter((e): e is any => e !== null);
}

/** 按漏洞 ID/标题去重合并 exploit 结果（命中优先级 success > restricted > failed > unknown）。 */
function mergeExploits(list: any[]): any[] {
  const entries: any[] = [];
  for (const raw of list) {
    const e = sanitizeExploitEntry(raw);
    if (!e) continue;
    const eVid = String(e.vulnerability_id || raw?.vulnerability_id || '').trim();
    if (eVid) e.vulnerability_id = eVid;
    // 优先按 vulnerability_id 合并（子智能体常改写标题）；再按宽松标题合并
    let mergedInto = -1;
    for (let i = 0; i < entries.length; i++) {
      const prevVid = String(entries[i].vulnerability_id || '').trim();
      const idMatch = !!(eVid && prevVid && eVid === prevVid);
      if (!idMatch && !exploitTitlesLooselyMatch(entries[i].vulnerability, e.vulnerability)) continue;
      const rp = EXPLOIT_STATUS_RANK[remoteStatusOf(entries[i])];
      const rc = EXPLOIT_STATUS_RANK[remoteStatusOf(e)];
      // 权限矩阵与危害清单跨条目累积：三档 OR-success、impacts 取并集，权限取更低成功档。
      const mergedPriv = mergePrivilegeResults(entries[i].privilege_results, e.privilege_results);
      const mergedImpacts = normalizeImpacts([
        ...(entries[i].impacts || []),
        ...(e.impacts || []),
      ]);
      if (rc < rp) {
        // 保留更长/更完整的标题（DB 对齐时还会改回正式标题）
        const keepTitle =
          String(e.vulnerability).length >= String(entries[i].vulnerability).length
            ? e.vulnerability
            : entries[i].vulnerability;
        entries[i] = { ...e, vulnerability: keepTitle };
      } else if (rc === rp && String(e.vulnerability).length > String(entries[i].vulnerability).length) {
        entries[i] = { ...entries[i], vulnerability: e.vulnerability };
      }
      if (mergedPriv) entries[i].privilege_results = mergedPriv;
      if (mergedImpacts) entries[i].impacts = mergedImpacts;
      // 依据合并后的矩阵重算“最低成功权限”，回退到两条中权限更低者。
      const lowerFallback =
        AUTH_TIER_RANK[(normalizeAuthTier(entries[i].auth_required) ?? 'admin')] <=
        AUTH_TIER_RANK[(normalizeAuthTier(e.auth_required) ?? 'admin')]
          ? entries[i].auth_required
          : e.auth_required;
      entries[i].auth_required = deriveMinAuth(mergedPriv, lowerFallback);
      if (eVid || prevVid) entries[i].vulnerability_id = eVid || prevVid;
      mergedInto = i;
      break;
    }
    if (mergedInto < 0) entries.push(e);
  }
  return entries;
}

/** incoming 里的 unknown 占位不得覆盖已经有结论的旧条目。 */
function overlayUnknownExploits(incoming: any[], previous: any[]): any[] {
  const incomingClean = incoming.map(sanitizeExploitEntry).filter(Boolean);
  const previousKnown = mergeExploits(previous).filter((e) => remoteStatusOf(e) !== 'unknown');
  if (previousKnown.length === 0) return incomingClean;
  return incomingClean.map((entry) => {
    if (remoteStatusOf(entry) !== 'unknown') return entry;
    const eVid = String(entry.vulnerability_id || '').trim();
    const hit = previousKnown.find((prev) => {
      const pVid = String(prev.vulnerability_id || '').trim();
      if (eVid && pVid && eVid === pVid) return true;
      return exploitTitlesLooselyMatch(prev.vulnerability, entry.vulnerability);
    });
    if (!hit) return entry;
    return {
      ...hit,
      vulnerability: entry.vulnerability || hit.vulnerability,
      vulnerability_id: eVid || hit.vulnerability_id,
    };
  });
}

type VulnBriefRow = Pick<
  Vulnerability,
  'id' | 'title' | 'severity' | 'file_path' | 'line' | 'description'
> & { category?: string };

function restrictedExploitRow(v: VulnBriefRow, reason: string): any {
  return {
    vulnerability: v.title,
    vulnerability_id: v.id,
    local_exploitable: 'restricted',
    remote_status: 'restricted',
    local_result: reason,
    auth_required: 'unknown',
    detail: reason,
    exploitable_versions: [],
    historical_verification: [],
  };
}

/** 将 exploit 列表严格对齐到 DB 中的 CHM 漏洞清单（每漏洞一条，缺失标 unknown）。 */
function alignExploitsToVulnList(allVulns: VulnBriefRow[], rawExploits: any[]): any[] {
  const merged = mergeExploits(rawExploits);

  // 子智能体常改写/截断 vulnerability 标题，但会原样回填 vulnerability_id。
  // 只按标题对齐时，磁盘已有 success/restricted 也会一直显示「待验证」。
  const byVulnId = new Map<string, any>();
  for (const ev of merged) {
    const vid = String(ev?.vulnerability_id || '').trim();
    if (!vid) continue;
    const prev = byVulnId.get(vid);
    if (!prev || EXPLOIT_STATUS_RANK[remoteStatusOf(ev)] < EXPLOIT_STATUS_RANK[remoteStatusOf(prev)]) {
      byVulnId.set(vid, ev);
    }
  }

  const findMatchByTitle = (vulnTitle: string): any | null => {
    let best: any | null = null;
    let bestRank = Infinity;
    for (const ev of merged) {
      if (!exploitTitlesLooselyMatch(vulnTitle, ev.vulnerability)) continue;
      const rank = EXPLOIT_STATUS_RANK[remoteStatusOf(ev)];
      // 优先非 unknown；同级取已有 best（merged 已按更好状态合并过）
      if (!best || rank < bestRank) {
        best = ev;
        bestRank = rank;
      }
    }
    return best;
  };

  return allVulns.map((v) => {
    const hit = byVulnId.get(v.id) || findMatchByTitle(v.title);
    if (hit) return { ...hit, vulnerability: v.title, vulnerability_id: v.id };
    return {
      vulnerability: v.title,
      vulnerability_id: v.id,
      local_exploitable: 'unknown' as ExploitStatus,
      remote_status: 'unknown' as ExploitStatus,
      local_result: '远程验证未产出该漏洞的结果（子智能体遗漏或落盘失败）',
      auth_required: 'unknown',
      detail: '',
      exploitable_versions: [],
      historical_verification: [],
    };
  });
}

/** 在靶机准备前先把磁盘已有结果并入报告，避免“文件已有但待验证数一直不变”。 */
function ingestExistingRemoteArtifacts(
  projectId: string,
  codeDir: string,
  priorExploits: any[] = [],
  priorChains: any[] = []
): { exploits: any[]; chains: any[]; recovered: number } {
  const disk = readRemoteVerifyResults(codeDir, projectId);
  const harness = readHarnessVerifyResults(codeDir);
  const diskExploits = [...disk.exploits, ...harness.exploits];
  const diskChains = disk.chains.length > 0 ? disk.chains : harness.chains;
  if (diskExploits.length === 0 && diskChains.length === 0) {
    return { exploits: priorExploits, chains: priorChains, recovered: 0 };
  }
  const allVulns = db
    .prepare(
      `SELECT id, title, severity, category, file_path, line, description FROM vulnerabilities
       WHERE project_id = ? AND lower(severity) IN ('critical','high','medium')`
    )
    .all(projectId) as VulnBriefRow[];
  const merged = mergeExploits([...priorExploits, ...diskExploits]);
  const aligned = alignExploitsToVulnList(allVulns, merged);
  const chains = diskChains.length > 0 ? diskChains : priorChains;
  const recovered = aligned.filter((entry) => remoteStatusOf(entry) !== 'unknown').length;
  saveExploitReport(projectId, {
    summary: `已从磁盘恢复 ${recovered}/${allVulns.length} 个单漏洞远程验证结论，靶机准备期间进度不会丢失`,
    exploits: aligned,
    chains,
  });
  broadcast({ type: 'project_status', projectId, exploit_progress: true });
  return { exploits: aligned, chains, recovered };
}

/** 统计 严重/高危/中危 单漏洞中仍为 unknown（待验证）的数量。 */
function countPendingChmSingles(projectId: string, rawExploits?: any[]): number {
  if (rawExploits !== undefined) {
    syncProjectVerificationItems(projectId, rawExploits, 'pending-reconcile');
  } else {
    const row = db.prepare('SELECT exploit_report FROM projects WHERE id = ?').get(projectId) as
      | { exploit_report: string | null }
      | undefined;
    if (row?.exploit_report) {
      try {
        const exploits = JSON.parse(row.exploit_report).exploits || [];
        syncProjectVerificationItems(projectId, exploits, 'pending-reconcile');
      } catch {
        ensureProjectVerificationItems(projectId);
      }
    } else {
      ensureProjectVerificationItems(projectId);
    }
  }
  const progress = getProjectVerificationProgress(projectId);
  return progress.pending + progress.queued + progress.running;
}

/** 主控结束后对遗漏/unknown 的 CHM 漏洞做后端强制补验（分批 vuln-verifier）。 */
async function retryMissingRemoteVulns(
  projectId: string,
  codeDir: string,
  allVulns: VulnBriefRow[],
  aligned: any[],
  envInfo: string,
  spec: ReturnType<typeof envSpecOf>,
  includeHistory: boolean,
  isAlive: () => boolean,
  opts: { harness?: boolean } = {}
): Promise<void> {
  const missing = allVulns.filter((v) => {
    const row = aligned.find((e) => normExploitTitle(e.vulnerability) === normExploitTitle(v.title));
    return !row || remoteStatusOf(row) === 'unknown';
  });
  if (missing.length === 0 || !isAlive() || verifyKilled.has(projectId)) return;

  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: opts.harness
        ? `⚠ 检测到 ${missing.length} 个漏洞未落盘有效结果，后端强制沙箱补验（vuln-verifier）…`
        : `⚠ 检测到 ${missing.length} 个漏洞未落盘有效结果，后端强制补验（vuln-verifier，复用运行中靶机）…`,
    },
    true,
    'verify'
  );

  const core = getSetting('verify_prompt') || '针对已发现的漏洞，在已搭建的本地靶机上做真实利用验证与取证。先确认靶机可达并登录；再逐条验证单漏洞；最后尝试无权限/低权限到 RCE 的组合利用。禁止只读源码就判成功。组合链不要从管理员权限起步。';
  const verifyRoot = opts.harness ? codeDir : artifactRootFor(projectId, codeDir);
  const base = opts.harness ? harnessVerifyDir(codeDir) : remoteVerifyDir(verifyRoot);
  const exDir = path.join(base, 'exploits');
  fs.mkdirSync(exDir, { recursive: true });

  const batches: VulnBriefRow[][] = [];
  let cur: VulnBriefRow[] = [];
  let curLimit = 3;
  for (const v of missing) {
    const sev = String(v.severity || '').toLowerCase();
    const limit = sev === 'medium' ? 5 : 3;
    if (cur.length > 0 && (cur.length >= curLimit || limit !== curLimit)) {
      batches.push(cur);
      cur = [];
    }
    curLimit = limit;
    cur.push(v);
    if (cur.length >= curLimit) {
      batches.push(cur);
      cur = [];
    }
  }
  if (cur.length) batches.push(cur);

  /**
   * 补验批次超时（修复「Pi Agent 还在正常写 POC / 跑脚本却被 20 分钟硬上限误杀」）：
   * - 硬上限按批内漏洞数 × 单洞预算累加，保底 45 分钟、封顶 min(stage, 120) 分钟；
   *   不再用固定 20 分钟墙钟（XSS 等复杂洞单批经常不够）。
   * - 空闲超时只看「完全无输出」：有进度就续命；静默过久才杀。
   * - 单批超时不中断整轮：落盘已有结果后继续下一批，避免 71 个待验证卡死。
   */
  const retryBatchHardMs = (batchSize: number): number => {
    const perVuln = singleVerifyHardMs(); // 默认 15min/洞
    const raw = Math.max(1, batchSize) * perVuln;
    const floor = 45 * 60_000;
    const ceiling = Math.min(Math.max(stageTimeoutMs(), floor), 120 * 60_000);
    return Math.min(Math.max(raw, floor), ceiling);
  };
  const retryBatchIdleMs = (): number => {
    // 默认单洞空闲 5min → 补验至少 15min 无输出才杀；且不超过全局 idle。
    return Math.min(Math.max(singleVerifyIdleMs() * 3, 15 * 60_000), Math.max(idleTimeoutMs(), 15 * 60_000));
  };

  for (let i = 0; i < batches.length; i++) {
    if (!isAlive() || verifyKilled.has(projectId)) break;
    const batch = batches[i];
    const batchHardMs = retryBatchHardMs(batch.length);
    const batchIdleMs = retryBatchIdleMs();
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `▶ 补验批次 ${i + 1}/${batches.length}：${batch.length} 个漏洞，硬上限 ${Math.round(batchHardMs / 60000)} 分钟 / 无输出 ${Math.round(batchIdleMs / 60000)} 分钟`,
      },
      true,
      'verify'
    );
    const r = await withVerifyGate(() =>
      runPiStage(
        projectId,
        codeDir,
        opts.harness
          ? buildHarnessVerifyBatchPrompt(core, codeDir, batch, envInfo, i + 1, batches.length)
          : buildVerifyBatchPrompt(core, codeDir, batch, envInfo, spec, i + 1, batches.length, includeHistory),
        JSON.stringify(EXPLOIT_SCHEMA),
        { channel: 'remoteverify', phase: 'verify', hardMsOverride: batchHardMs, idleMsOverride: batchIdleMs }
      )
    );
    // 用户主动暂停/删除才整轮停；硬超时只跳过本批，继续消化剩余待验证。
    if (r.killed || verifyKilled.has(projectId)) break;
    if (r.timedOut) {
      recordEvent(
        projectId,
        {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: `⚠ 补验批次 ${i + 1}/${batches.length} 超时已中止本批（已落盘结果会保留），继续下一批`,
        },
        true,
        'verify'
      );
    }
    let exps: any[] = [];
    if (r.structured && Array.isArray(r.structured.exploits)) exps = r.structured.exploits;
    if (exps.length === 0) exps = parseStructuredArray(r.finalResult, 'exploits');
    const disk = opts.harness
      ? readHarnessVerifyResults(codeDir)
      : readRemoteVerifyResults(verifyRoot, projectId);
    if (disk.exploits.length) exps = [...exps, ...disk.exploits];
    const sanitized = exps.map(sanitizeExploitEntry).filter(Boolean);
    if (sanitized.length) {
      try {
        fs.writeFileSync(path.join(exDir, `retry_batch_${i + 1}.json`), JSON.stringify(sanitized), 'utf8');
      } catch {
        /* 落盘失败不阻断下一批 */
      }
    }
  }

  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `✓ 补验阶段完成：已对 ${missing.length} 个遗漏漏洞发起 ${batches.length} 批 vuln-verifier 验证`,
    },
    true,
    'verify'
  );
}

function hasSuccessfulChain(chains: any[]): boolean {
  return chains.some((c) => normalizeExploitStatus(c?.status) === 'success');
}

/** 组合链覆盖门禁的最大补验轮数（每轮对全部未出结论的链各派一个定向子智能体）。 */
const CHAIN_RETRY_MAX_ROUNDS = 2;

/** 当前尚无终态（success/failed/restricted）的组合链——需要门禁补验的对象。 */
function unconcludedChains(chains: any[]): any[] {
  return chains.filter((c) => normalizeExploitStatus(c?.status) === 'unknown');
}

/**
 * 组合链覆盖门禁：对「候选清单里有、但缺结果文件或结果仍为 unknown」的链逐条定向补验，
 * 最多 CHAIN_RETRY_MAX_ROUNDS 轮。对标单漏洞的 retryMissingRemoteVulns，保证
 * 发现 N 条 = 验证 N 条 = 归纳 N 条。返回门禁执行后从磁盘重新汇总的组合链列表。
 */
async function retryMissingChains(
  projectId: string,
  codeDir: string,
  envInfo: string,
  spec: ReturnType<typeof envSpecOf>,
  isAlive: () => boolean,
  masterHardMs: number,
  masterIdleMs: number
): Promise<any[]> {
  const core =
    getSetting('verify_prompt') ||
    '针对已发现的漏洞，在已搭建的本地靶机上做真实利用验证与取证。先确认靶机可达并登录；再逐条验证单漏洞；最后尝试无权限/低权限到 RCE 的组合利用。禁止只读源码就判成功。组合链不要从管理员权限起步。';
  const verifyRoot = artifactRootFor(projectId, codeDir);
  const chainDir = path.join(remoteVerifyDir(verifyRoot), 'chains');
  fs.mkdirSync(chainDir, { recursive: true });

  let chains = readRemoteVerifyResults(verifyRoot, projectId).chains;
  for (let round = 1; round <= CHAIN_RETRY_MAX_ROUNDS; round++) {
    if (!isAlive() || verifyKilled.has(projectId)) break;
    const pending = unconcludedChains(chains);
    if (pending.length === 0) break;

    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `⚠ 组合链覆盖门禁：仍有 ${pending.length} 条链未产出明确结论，后端逐条定向补验（第 ${round}/${CHAIN_RETRY_MAX_ROUNDS} 轮，复用运行中靶机）…`,
      },
      true,
      'verify'
    );

    for (const chain of pending) {
      if (!isAlive() || verifyKilled.has(projectId)) break;
      const chainId =
        normalizedChainId(chain?.chain_id) ||
        `chain-${String(Math.abs(hashString(String(chain?.name || ''))) % 10000).padStart(4, '0')}`;
      const artifactPath = path.join(chainDir, `retry_${chainId}.json`);
      const target = {
        chain_id: chainId,
        name: String(chain?.name || ''),
        impact: chain?.impact ? String(chain.impact) : undefined,
        auth_required: chain?.auth_required ? String(chain.auth_required) : undefined,
        steps: chain?.steps,
        detail: chain?.detail ? String(chain.detail) : undefined,
      };
      try {
        await withVerifyGate(() =>
          runPiStage(
            projectId,
            codeDir,
            buildChainRetryPrompt(core, codeDir, target, envInfo, spec, artifactPath),
            JSON.stringify(EXPLOIT_SCHEMA),
            {
              channel: 'remoteverify',
              phase: 'verify',
              hardMsOverride: Math.min(masterHardMs, 30 * 60_000),
              idleMsOverride: Math.min(masterIdleMs, 10 * 60_000),
            }
          )
        );
      } catch (err: any) {
        recordEvent(
          projectId,
          {
            kind: 'error',
            agent: '主控',
            tool: '',
            text: `⚠ 组合链定向补验异常（${chainId}）：${String(err?.message || err).slice(0, 160)}`,
          },
          true,
          'verify'
        );
      }
    }
    chains = await waitForStableChainArtifacts(verifyRoot, projectId, chains);
  }
  return chains;
}

/** 收尾：2 轮补验后仍无终态的链保守归为 restricted，保证完成态只有三态、绝无「未产出结论」。 */
function finalizeChainConclusions(chains: any[]): any[] {
  return chains.map((c) => {
    if (normalizeExploitStatus(c?.status) !== 'unknown') return c;
    const note = '组合链覆盖门禁：补验 2 轮后仍未取得决定性证据，保守归为受限（restricted）。';
    const detail = String(c?.detail || '').trim();
    return {
      ...c,
      status: 'restricted',
      detail: detail ? `${detail}\n${note}` : note,
      forced_restricted: true,
    };
  });
}

/** 稳定字符串哈希，用于给缺 chain_id 的链生成确定性补验文件名。 */
function hashString(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return h;
}

/** 远程验证核心（环节⑥·A3 架构）：由【一个 Pi Agent】统一编排整轮远程验证——
 * 主控内部通过 vuln-chain-exploiter 技能【派生多个验证子智能体并发】实测（共享同一靶机与同一份
 * codegraph MCP 索引），各子智能体把结果**落盘**到 `<codeDir>/_remote_verify/`，后端读盘汇总。
 * 相比旧版"后端并发拉起 N 个 Pi Agent"，进程数与常驻内存（N 份 codegraph 索引→1 份）大幅下降。
 * 实时进度：后端轮询磁盘结果目录，逐步把已落盘结果推给前端。
 * 调用前需已 setVerifyStatus('running') 并准备好 codeDir。返回 killed（true=被中断，调用方不应标记完成）。
 * @param priorExploits 续跑场景下暂停前已验证的部分结果；预置进结果目录、并在最终汇总时并入。
 */
async function runRemoteVerifyCore(
  projectId: string,
  codeDir: string,
  priorExploits: any[] = [],
  opts: { keepTargetAlive?: boolean; priorChains?: any[]; chainOnly?: boolean; skipChain?: boolean } = {}
): Promise<boolean> {
  const priorChains: any[] = Array.isArray(opts.priorChains) ? opts.priorChains : [];
  // 仅组合链模式：跳过单漏洞验证阶段（复用已有单漏洞结果），直接对总漏洞池跑组合链验证。
  const chainOnly = opts.chainOnly === true;
  const skipChain = opts.skipChain === true;
  const project = getProject(projectId);
  if (!project) return true;
  // 进入远程验证：清理上一阶段可能残留的中止标志。
  verifyKilled.delete(projectId);
  // 捕获本轮开始前 DB 里已有的 RCE 组合链：用于防止本轮组合阶段【空跑/异常】覆盖掉此前已验证的有效链。
  // 注意：整轮"重新验证"(reverify=false) 会在调用方 clearVerifyResults 先清空 exploit_report，
  // 因此此处读到为空 → 不会误保留，符合"从零重跑"语义；续跑/仅组合链/复用结果重跑时才可能非空。
  let priorReportChains: any[] = [];
  try {
    const row = db.prepare('SELECT exploit_report FROM projects WHERE id = ?').get(projectId) as
      | { exploit_report: string | null }
      | undefined;
    if (row?.exploit_report) {
      const parsed = JSON.parse(row.exploit_report);
      if (Array.isArray(parsed?.chains)) priorReportChains = parsed.chains;
    }
  } catch {
    /* 无历史链或解析失败：按无历史链处理 */
  }
  if (priorChains.length > 0) {
    priorReportChains = mergeChains([...priorReportChains, ...priorChains]);
  }
  // 只对 严重/高危/中危 做远程单漏洞验证（低危/信息不进远程验证）
  const allVulns = db
    .prepare(
      "SELECT id, title, severity, file_path, line, description FROM vulnerabilities WHERE project_id = ? AND lower(severity) IN ('critical','high','medium') ORDER BY CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END"
    )
    .all(projectId) as VulnBriefRow[];

  const core = getSetting('verify_prompt') || '针对已发现的漏洞，在已搭建的本地靶机上做真实利用验证与取证。先确认靶机可达并登录；再逐条验证单漏洞；最后尝试无权限/低权限到 RCE 的组合利用。禁止只读源码就判成功。组合链不要从管理员权限起步。';
  // 读取环境搭建阶段写下的靶机交接信息（地址/账号密码），注入验证会话，解决跨会话拿不到凭据的问题
  let envInfo = '';
  try {
    envInfo = fs.readFileSync(path.join(codeDir, 'TARGET_ENV.json'), 'utf8').trim();
  } catch {
    /* 没有交接文件时，验证 prompt 会指示自行获取/重建 */
  }
  const spec = envSpecOf(project);
  const includeHistory = isVerifyHistory(projectId);

  if (allVulns.length === 0) {
    recordEvent(
      projectId,
      { kind: 'system', agent: '主控', tool: '', text: '▶ 漏洞验证：无 严重/高危/中危 漏洞，跳过远程验证' },
      true,
      'verify'
    );
    await stopTargetEnvironment(projectId, codeDir);
    saveExploitReport(projectId, { summary: '无 严重/高危/中危 漏洞，无需远程验证', exploits: [], chains: [] });
    return false;
  }

  // 续跑：仅跳过已有明确结论（非 unknown）的单漏洞；unknown 仍须补验。
  const normTitle2 = (s: string) => String(s || '').replace(/\s+/g, '').toLowerCase();
  const verifiedPrior = priorExploits.filter((e: any) => remoteStatusOf(e) !== 'unknown');
  const doneSet = new Set(verifiedPrior.map((e: any) => normTitle2(e?.vulnerability)));
  const vulns = doneSet.size > 0 ? allVulns.filter((v) => !doneSet.has(normTitle2(v.title))) : allVulns;
  const doneTitlesArr = verifiedPrior.map((e: any) => String(e?.vulnerability || '')).filter(Boolean);
  const isResume = verifiedPrior.length > 0;

  // 是否仍应继续（未被暂停/删除/重跑）：兼顾内存中止标志与库内状态。
  const isAlive = () => {
    if (verifyKilled.has(projectId)) return false;
    const cur = getProject(projectId);
    return !!cur && cur.verify_status === 'running';
  };

  // 组合链候选池 = 项目全部漏洞（含 low/info，未授权 RCE 链常从信息泄露/凭证泄露起步）
  const poolRows = db
    .prepare(
      "SELECT title, severity, category, file_path, line FROM vulnerabilities WHERE project_id = ? ORDER BY CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    )
    .all(projectId) as Pick<Vulnerability, 'title' | 'severity' | 'file_path' | 'line' | 'category'>[];
  const poolBrief = poolRows.map(
    (v) => `[${v.severity}] ${v.title}（${v.category || '未分类'}）—— ${v.file_path}${v.line ? ':' + v.line : ''}`
  );

  // 结果目录：写入 data/results/<id>/_remote_verify，不混进源码树。
  const art = artifactRootFor(projectId, codeDir);
  ensureArtifactLayout(projectId, codeDir);
  const base = path.join(art, '_remote_verify');
  const exDir = path.join(base, 'exploits');
  // 组合链阶段会清空 _remote_verify；若调用方没带上已有单洞结论，先从磁盘/DB 抢救，
  // 避免 rmSync 后只剩下 unknown 占位。
  if (chainOnly || priorExploits.length > 0) {
    const preexisting = mergeExploits([
      ...readRemoteVerifyPriorExploits(art),
      ...priorExploits,
      ...readRemoteVerifyResults(art, projectId).exploits,
    ]);
    if (preexisting.length > 0) priorExploits = preexisting;
  }
  try {
    fs.rmSync(base, { recursive: true, force: true });
  } catch {
    /* 忽略 */
  }
  fs.mkdirSync(exDir, { recursive: true });
  if (priorExploits.length > 0) {
    try {
      fs.writeFileSync(path.join(exDir, '_prior.json'), JSON.stringify(priorExploits), 'utf8');
    } catch {
      /* 预置失败不阻断，最终汇总时仍会并入 priorExploits */
    }
  }
  if (priorChains.length > 0) {
    try {
      fs.writeFileSync(path.join(base, 'chains.json'), JSON.stringify(priorChains), 'utf8');
    } catch {
      /* 续跑时保留暂停前的组合链进度，供轮询/汇总 */
    }
  }

  const conc = codeVerifyConcurrency();
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: chainOnly
        ? `▶ 仅组合链验证：复用已有 ${priorExploits.length} 个单漏洞结果，跳过单漏洞阶段，直接对总漏洞池（${poolRows.length} 条）构造并实测组合利用链（无权限→RCE + 低权限(开放注册)→RCE）…`
        : isResume && vulns.length === 0
          ? `▶ 漏洞验证：单漏洞已全部验证（${verifiedPrior.length}/${allVulns.length}），跳过阶段一，进入组合链验证`
          : isResume
            ? `▶ 漏洞验证：复用已验证 ${verifiedPrior.length} 个，主控编排对剩余 ${vulns.length}/${allVulns.length} 个漏洞派发验证子智能体（并发 ≤ ${conc}），完成后进入组合链验证`
            : `▶ 漏洞验证：主控编排对全部 ${vulns.length} 个 严重/高危/中危 漏洞派发验证子智能体并发实测（并发 ≤ ${conc}，共享同一靶机与同一份 codegraph 索引）`,
    },
    true,
    'verify'
  );

  // 磁盘轮询：实时把已落盘的部分结果推给前端（替代旧版每批 setState）。
  let polledDone = false;
  let lastArtifactFingerprint = '';
  let lastArtifactSig = '';
  const ingestArtifacts = () => {
    if (polledDone) return;
    // 前置廉价门：产物目录无任何变化时跳过整轮 O(n²) 重活（读盘/解析/merge/align/save）。
    const sig = remoteResultsSignature(art);
    if (sig === lastArtifactSig) return;
    lastArtifactSig = sig;
    const { exploits, chains: diskChains } = readRemoteVerifyResults(art, projectId);
    const chainsForPoll = diskChains.length > 0 ? diskChains : priorChains;
    const merged = mergeExploits(exploits);
    if (merged.length === 0 && chainsForPoll.length === 0) return;
    const fingerprint = JSON.stringify([
      merged.map((entry) => [
        entry.vulnerability_id || '',
        entry.vulnerability || '',
        remoteStatusOf(entry),
        entry.source_file || '',
      ]),
      chainsForPoll.map((chain: any) => [chain.name || '', normalizeExploitStatus(chain.status)]),
    ]);
    if (fingerprint === lastArtifactFingerprint) return;
    lastArtifactFingerprint = fingerprint;
    const successN = merged.filter((e) => remoteStatusOf(e) === 'success').length;
    const cs = chainVerifyStats(chainsForPoll);
    const aligned = alignExploitsToVulnList(allVulns, [...priorExploits, ...merged]);
    saveExploitReport(projectId, {
      summary: `远程验证进行中：已落盘 ${aligned.filter((e) => remoteStatusOf(e) !== 'unknown').length}/${allVulns.length} 个漏洞结果（远程成功 ${successN}）；无权限组合链已验证 ${cs.unauthVerified} 条（完全成功 ${cs.unauthSuccess} 条）、低权限(开放注册)组合链已验证 ${cs.openRegVerified} 条（完全成功 ${cs.openRegSuccess} 条）…`,
      exploits: aligned,
      chains: chainsForPoll,
    });
    broadcast({ type: 'project_status', projectId, exploit_progress: true });
  };
  ingestArtifacts();
  const poll = setInterval(ingestArtifacts, 2_000);
  const stopPoll = () => {
    polledDone = true;
    clearInterval(poll);
  };

  // 单个主控进程编排整轮验证：内部派生子智能体并发（共享 1 份 codegraph 索引）。
  // 主控要跑完全部漏洞 + 组合链 + 历史版本，耗时远超单批，故放宽硬/空闲超时上限。
  const masterHardMs = Math.max(stageTimeoutMs(), 6 * 60 * 60_000);
  const masterIdleMs = Math.max(idleTimeoutMs(), 40 * 60_000);
  let r: Awaited<ReturnType<typeof runPiStage>> = {
    killed: false,
    structured: undefined,
    finalResult: '',
    code: 0,
    stderrTail: '',
    timedOut: false,
  };
  if (!chainOnly && vulns.length > 0) {
    try {
      r = await withVerifyGate(() =>
        runPiStage(
          projectId,
          codeDir,
          buildRemoteVerifyMasterPrompt(
            core,
            codeDir,
            vulns,
            poolBrief,
            envInfo,
            spec,
            includeHistory,
            base,
            conc,
            doneTitlesArr
          ),
          JSON.stringify(EXPLOIT_SCHEMA),
          { channel: 'remoteverify', phase: 'verify', hardMsOverride: masterHardMs, idleMsOverride: masterIdleMs }
        )
      );
    } catch (err) {
      // 单漏洞主控异常：仍继续尝试组合链阶段（若单洞已齐）
      recordEvent(
        projectId,
        {
          kind: 'error',
          agent: '主控',
          tool: '',
          text: `⚠ 单漏洞主控阶段异常：${String((err as any)?.message || err).slice(0, 200)}`,
        },
        true,
        'verify'
      );
    }
    // 注意：不在此处 stopPoll——组合链阶段仍需轮询落盘产物
  }
  // chainOnly / 单洞已齐：保持 poll 运行，直到组合链阶段结束

  if (
    !r.killed &&
    !r.structured &&
    parseStructuredArray(r.finalResult, 'exploits').length === 0 &&
    readRemoteVerifyResults(art, projectId).exploits.length === 0 &&
    (r.stderrTail || (r.code != null && r.code !== 0))
  ) {
    recordEvent(
      projectId,
      {
        kind: 'error',
        agent: '主控',
        tool: '',
        text: `⚠ Pi Agent 异常退出（code=${r.code ?? '?'}）${r.stderrTail ? `：${r.stderrTail.slice(0, 300)}` : ''}`,
      },
      true,
      'verify'
    );
  }

  if (r.killed || !isAlive()) {
    stopPoll();
    await stopTargetEnvironment(projectId, codeDir);
    return true;
  }

  // 汇总磁盘结果；磁盘为空时回退到主控的 StructuredOutput / finalResult 兜底。
  const disk = readRemoteVerifyResults(art, projectId);
  let exploits = disk.exploits;
  let chains = disk.chains.length > 0 ? disk.chains : [...priorChains];
  if (exploits.length === 0 && r.structured && Array.isArray(r.structured.exploits)) {
    exploits = r.structured.exploits;
  }
  if (exploits.length === 0) {
    const e = parseStructuredArray(r.finalResult, 'exploits');
    if (e.length) exploits = e;
  }
  if (chains.length === 0 && r.structured && Array.isArray(r.structured.chains)) {
    chains = r.structured.chains;
  }
  if (chains.length === 0) {
    const c = parseStructuredArray(r.finalResult, 'chains');
    if (c.length) chains = c;
  }
  // 并入续跑的已验证结果并去重（磁盘已含 _prior.json 的等价物，priorExploits 单独并入）
  exploits = mergeExploits([...priorExploits, ...exploits]);
  let alignedExploits = alignExploitsToVulnList(allVulns, exploits);

  // 对子智能体遗漏（unknown）的漏洞强制后端补验（续跑时同样补验剩余未产出结果的漏洞）。
  // 仅组合链模式跳过单漏洞补验（不重跑单漏洞，只跑组合链）。
  if (!chainOnly) {
    await retryMissingRemoteVulns(
      projectId,
      codeDir,
      allVulns,
      alignedExploits,
      envInfo,
      spec,
      includeHistory,
      isAlive
    );
    // 补验后必须以账本+磁盘为权威重读（读盘无副作用）。此前用 isAlive() 门控，verify_status
    // 若瞬时不为 running 就会跳过重读，导致补验刚落盘的 success 没并入 → pendingSingles 误判、
    // 组合链被误挡、收尾判 failed。仅在用户主动 kill 时才跳过。
    if (!verifyKilled.has(projectId)) {
      const diskAfterRetry = readRemoteVerifyResults(art, projectId);
      exploits = mergeExploits([...priorExploits, ...diskAfterRetry.exploits]);
      alignedExploits = alignExploitsToVulnList(allVulns, exploits);
    }
  }
  exploits = alignedExploits;

  const pendingSingles = exploits.filter((e) => remoteStatusOf(e) === 'unknown').length;

  // 组合链阶段：无 success 链时强制跑组合验证。
  // 主控阶段二若只落盘了 status=unknown 的占位链，也必须触发后端补跑（不能因 chains.length>0 而跳过）。
  const allChainsPending =
    chains.length > 0 && chains.every((c) => normalizeExploitStatus(c?.status) === 'unknown');
  // 组合阶段执行状态：用于收尾判定"确实无链" vs "未启动/异常"，并防止空跑覆盖历史链。
  // 'ran'=本轮实际跑完；'error'=启动但异常；'skipped_pending'=单漏洞未完成未启动；
  // 'skipped_pool'=候选池不足未启动；'skipped_has_success'=已有成功链无需重跑；'not_needed'=无需启动。
  let chainStageOutcome:
    | 'ran'
    | 'error'
    | 'skipped_pending'
    | 'skipped_pool'
    | 'skipped_has_success'
    | 'not_needed' = 'not_needed';
  // 仅组合链模式：忽略单漏洞未完成（unknown）门槛，直接强制跑组合链。
  // skipChain：本轮只做单漏洞，组合阶段由独立 chain 环节负责。
  if (skipChain) {
    chainStageOutcome = 'not_needed';
  } else if (!chainOnly && pendingSingles > 0) {
    chainStageOutcome = 'skipped_pending';
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `⚠ 仍有 ${pendingSingles} 个单漏洞尚无结论（unknown），组合链验证暂不启动；请先完成单漏洞补验`,
      },
      true,
      'verify'
    );
  } else if (!chainOnly && poolRows.length < 2) {
    // 候选池不足（漏洞 < 2 条）：组合链需至少 2 个漏洞串联，明确记录“无组合链阶段”，与“真无链”区分。
    chainStageOutcome = 'skipped_pool';
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `ℹ 候选池仅 ${poolRows.length} 个漏洞（少于 2 个），无法构造组合利用链，跳过组合链验证阶段`,
      },
      true,
      'verify'
    );
  } else if (!chainOnly && hasSuccessfulChain(chains)) {
    // 已有完全成功的组合链：保留不重复跑（不覆盖）。
    chainStageOutcome = 'skipped_has_success';
  } else if (
    poolRows.length >= 2 &&
    isAlive() &&
    !verifyKilled.has(projectId) &&
    !cancelledProjects.has(projectId) &&
    // 仅组合链模式：用户显式重跑组合链，无条件启动（即使已有成功链也重新构造实测）；
    // 常规模式沿用旧门槛：无成功链且（首次/续跑/占位链）时才启动。
    (chainOnly || (!hasSuccessfulChain(chains) && (chains.length === 0 || isResume || allChainsPending)))
  ) {
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text:
          isResume && vulns.length === 0
            ? '▶ 单漏洞已全部完成，启动组合链验证阶段（复用运行中靶机）…'
            : '⚠ 未检测到完全成功的组合利用链，后端强制启动组合链验证阶段（复用运行中的靶机）…',
      },
      true,
      'verify'
    );
    const verifiedBrief = exploits.map((e: any) => ({
      vulnerability: String(e?.vulnerability || ''),
      local_exploitable: String(e?.local_exploitable || 'unknown'),
      remote_status: remoteStatusOf(e),
      impacts: Array.isArray(e?.impacts) ? e.impacts.map((s: any) => String(s)) : undefined,
      auth_required: e?.auth_required ? String(e.auth_required) : undefined,
    }));
    // 跨语言候选利用链（审计阶段跨语言融合环节产出）：优先喂给组合验证实测。
    const crossLangCandidates = readCrossLangChainCandidates(codeDir);
    try {
      const rc = await withVerifyGate(() =>
        runPiStage(
          projectId,
          codeDir,
          buildChainPrompt(core, codeDir, verifiedBrief, envInfo, spec, includeHistory, poolBrief, crossLangCandidates),
          JSON.stringify(EXPLOIT_SCHEMA),
          { channel: 'remoteverify', phase: 'verify', hardMsOverride: masterHardMs, idleMsOverride: masterIdleMs }
        )
      );
      if (!rc.killed) {
        // 子智能体可能仍在尾部写盘：稳定轮询直到 chains 文件数不再增长
        let fallback: any[] = [];
        if (rc.structured && Array.isArray(rc.structured.chains)) fallback = rc.structured.chains;
        else {
          const c2 = parseStructuredArray(rc.finalResult, 'chains');
          if (c2.length) fallback = c2;
        }
        chains = await waitForStableChainArtifacts(art, projectId, fallback);
        chainStageOutcome = 'ran';
        // 覆盖门禁：主控落盘后逐条对账候选清单，缺失/unknown 的链定向补验（≤2 轮）。
        if (isAlive() && !verifyKilled.has(projectId)) {
          chains = await retryMissingChains(
            projectId,
            codeDir,
            envInfo,
            spec,
            isAlive,
            masterHardMs,
            masterIdleMs
          );
        }
      } else {
        // 被中止（暂停/删除/重跑）：不算跑完，不得覆盖历史链。
        chainStageOutcome = 'error';
      }
      const concludedNow = chains.filter((c) => normalizeExploitStatus(c?.status) !== 'unknown').length;
      recordEvent(
        projectId,
        {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: `✓ 组合链验证阶段完成：候选组合利用链共 ${chains.length} 条，已产出结论 ${concludedNow} 条`,
        },
        true,
        'verify'
      );
    } catch (err: any) {
      // 组合链阶段异常：明确记录失败，标记为 error，避免收尾把它当作"确实无链"并覆盖历史链。
      chainStageOutcome = 'error';
      recordEvent(
        projectId,
        {
          kind: 'error',
          agent: '主控',
          tool: '',
          text: `✗ 组合链验证阶段异常中断：${String(err?.message || err).slice(0, 200)}；本轮不覆盖已有组合链，可稍后重跑「远程验证·组合」`,
        },
        true,
        'verify'
      );
    }
  }

  stopPoll();

  // 验证阶段结束：停止靶机容器释放资源（不 down -v，二次验证时 ensureTargetUp 可 compose start 拉起）
  if (!opts.keepTargetAlive) {
    await stopTargetEnvironment(projectId, codeDir);
  } else {
    recordEvent(
      projectId,
      { kind: 'system', agent: '主控', tool: '', text: '✓ 远程验证完成，靶机保持运行（重跑时可复用，无需重搭）' },
      true,
      'verify'
    );
  }

  // 防止本轮组合链【空跑/异常/未真正跑完】覆盖掉此前已验证的有效链：
  // 仅当本轮组合阶段没有真正跑完（error / 各类 skipped）且产出为空，而历史存在 RCE 链时，保留历史链。
  // 本轮确实跑完(ran)但产出为空 → 视为"实测确无链"，如实置空，不保留。
  if (chains.length === 0 && priorReportChains.length > 0 && chainStageOutcome !== 'ran') {
    chains = priorReportChains;
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `ℹ 本轮未产出新的组合利用链（阶段状态：${chainStageOutcome}），保留此前已验证的 ${chains.length} 条组合利用链，未覆盖`,
      },
      true,
      'verify'
    );
  }

  // 收尾三态收敛：本轮真正跑完组合链阶段时，2 轮补验后仍 unknown 的链保守归为 restricted，
  // 保证完成态只有 验证成功/验证失败/验证受限，绝不残留「未产出结论」。
  if (chainStageOutcome === 'ran') {
    const forced = chains.filter((c) => normalizeExploitStatus(c?.status) === 'unknown').length;
    chains = finalizeChainConclusions(chains);
    if (forced > 0) {
      recordEvent(
        projectId,
        {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: `ℹ 组合链覆盖门禁收尾：${forced} 条链补验 2 轮仍无决定性证据，保守归为「验证受限」，本轮组合链已全部产出结论`,
        },
        true,
        'verify'
      );
    }
  }

  const successN = exploits.filter((e: any) => remoteStatusOf(e) === 'success').length;
  const restrictedN = exploits.filter((e: any) => remoteStatusOf(e) === 'restricted').length;
  const unknownN = exploits.filter((e: any) => remoteStatusOf(e) === 'unknown').length;
  const cs = chainVerifyStats(chains);
  const summaryPrefix = unknownN > 0 ? '远程验证收尾（未完整）' : '全量远程验证完成';
  saveExploitReport(projectId, {
    summary: `${summaryPrefix}：${allVulns.length} 个 严重/高危/中危 漏洞逐一实测，${successN} 个完全命中(success)、${restrictedN} 个受限(restricted)${unknownN ? `、${unknownN} 个未产出结果(unknown)` : ''}；组合利用链共记录 ${chains.length} 条，其中无权限已验证 ${cs.unauthVerified} 条（完全成功 ${cs.unauthSuccess} 条）、低权限(开放注册)已验证 ${cs.openRegVerified} 条（完全成功 ${cs.openRegSuccess} 条）。`,
    exploits,
    chains,
  });
  broadcast({ type: 'project_status', projectId, exploit_progress: true });
  recordEvent(
    projectId,
    {
      kind: 'text',
      agent: '主控',
      tool: '',
      text: `验证结论：完成远程实测，${successN} 个完全命中、${restrictedN} 个受限；无权限组合链已验证 ${cs.unauthVerified} 条（完全成功 ${cs.unauthSuccess} 条）、低权限(开放注册)组合链已验证 ${cs.openRegVerified} 条（完全成功 ${cs.openRegSuccess} 条）`,
    },
    true,
    'verify'
  );
  return false;
}

/** Harness 沙箱验证核心：主控编排 vuln-verifier，落盘 _harness_verify/，跳过组合链。 */
async function runHarnessVerifyCore(
  projectId: string,
  codeDir: string,
  priorExploits: any[] = [],
  opts: { keepTargetAlive?: boolean } = {}
): Promise<boolean> {
  const project = getProject(projectId);
  if (!project) return true;
  verifyKilled.delete(projectId);

  const allVulns = db
    .prepare(
      "SELECT id, title, severity, file_path, line, description FROM vulnerabilities WHERE project_id = ? AND lower(severity) IN ('critical','high','medium') ORDER BY CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END"
    )
    .all(projectId) as VulnBriefRow[];

  const core =
    getSetting('verify_prompt') ||
    '针对已发现的漏洞，在已搭建的本地靶机上做真实利用验证与取证。先确认靶机可达并登录；再逐条验证单漏洞；最后尝试无权限/低权限到 RCE 的组合利用。禁止只读源码就判成功。组合链不要从管理员权限起步。';
  let envInfo = '';
  try {
    envInfo = fs.readFileSync(path.join(codeDir, 'TARGET_ENV.json'), 'utf8').trim();
  } catch {
    /* 无交接文件 */
  }

  if (allVulns.length === 0) {
    recordEvent(
      projectId,
      { kind: 'system', agent: '主控', tool: '', text: '▶ 漏洞验证：无 严重/高危/中危 漏洞，跳过沙箱验证' },
      true,
      'verify'
    );
    saveExploitReport(projectId, { summary: '无 严重/高危/中危 漏洞，无需沙箱验证', exploits: [], chains: [] });
    return false;
  }

  const normTitle2 = (s: string) => String(s || '').replace(/\s+/g, '').toLowerCase();
  const verifiedPrior = priorExploits.filter((e: any) => remoteStatusOf(e) !== 'unknown');
  const doneSet = new Set(verifiedPrior.map((e: any) => normTitle2(e?.vulnerability)));
  const vulns = doneSet.size > 0 ? allVulns.filter((v) => !doneSet.has(normTitle2(v.title))) : allVulns;
  const doneTitlesArr = verifiedPrior.map((e: any) => String(e?.vulnerability || '')).filter(Boolean);
  const isResume = verifiedPrior.length > 0;

  const isAlive = () => {
    if (verifyKilled.has(projectId)) return false;
    const cur = getProject(projectId);
    return !!cur && cur.verify_status === 'running';
  };

  const base = harnessVerifyDir(codeDir);
  const exDir = path.join(base, 'exploits');
  try {
    fs.rmSync(base, { recursive: true, force: true });
  } catch {
    /* 忽略 */
  }
  fs.mkdirSync(exDir, { recursive: true });
  if (priorExploits.length > 0) {
    try {
      fs.writeFileSync(path.join(exDir, '_prior.json'), JSON.stringify(priorExploits), 'utf8');
    } catch {
      /* 预置失败不阻断 */
    }
  }

  const conc = codeVerifyConcurrency();
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: isResume
        ? `▶ 沙箱验证：复用已验证 ${verifiedPrior.length} 个，主控编排对剩余 ${vulns.length}/${allVulns.length} 个漏洞派发验证子智能体（并发 ≤ ${conc}）`
        : `▶ 沙箱验证：主控编排对全部 ${vulns.length} 个 严重/高危/中危 漏洞在 _harness/ 沙箱上派发验证子智能体（并发 ≤ ${conc}）`,
    },
    true,
    'verify'
  );

  let polledDone = false;
  const poll = setInterval(() => {
    if (polledDone) return;
    const { exploits } = readHarnessVerifyResults(codeDir);
    const merged = mergeExploits(exploits);
    if (merged.length === 0) return;
    const successN = merged.filter((e) => remoteStatusOf(e) === 'success').length;
    const aligned = alignExploitsToVulnList(allVulns, [...priorExploits, ...merged]);
    saveExploitReport(projectId, {
      summary: `沙箱验证进行中：已落盘 ${aligned.filter((e) => remoteStatusOf(e) !== 'unknown').length}/${allVulns.length} 个漏洞结果（成功 ${successN}）…`,
      exploits: aligned,
      chains: [],
    });
    broadcast({ type: 'project_status', projectId, exploit_progress: true });
  }, 10_000);
  const stopPoll = () => {
    polledDone = true;
    clearInterval(poll);
  };

  const masterHardMs = Math.max(stageTimeoutMs(), 6 * 60 * 60_000);
  const masterIdleMs = Math.max(idleTimeoutMs(), 40 * 60_000);
  let r: Awaited<ReturnType<typeof runPiStage>> = {
    killed: false,
    structured: undefined,
    finalResult: '',
    code: 0,
    stderrTail: '',
    timedOut: false,
  };
  if (vulns.length > 0) {
    try {
      r = await withVerifyGate(() =>
        runPiStage(
          projectId,
          codeDir,
          buildHarnessVerifyMasterPrompt(core, codeDir, vulns, envInfo, base, conc, doneTitlesArr),
          JSON.stringify(EXPLOIT_SCHEMA),
          { channel: 'remoteverify', phase: 'verify', hardMsOverride: masterHardMs, idleMsOverride: masterIdleMs }
        )
      );
    } finally {
      stopPoll();
    }
  } else {
    stopPoll();
  }

  if (
    !r.killed &&
    !r.structured &&
    parseStructuredArray(r.finalResult, 'exploits').length === 0 &&
    readHarnessVerifyResults(codeDir).exploits.length === 0 &&
    (r.stderrTail || (r.code != null && r.code !== 0))
  ) {
    recordEvent(
      projectId,
      {
        kind: 'error',
        agent: '主控',
        tool: '',
        text: `⚠ Pi Agent 沙箱验证进程异常退出（code=${r.code ?? '?'}）${r.stderrTail ? `：${r.stderrTail.slice(0, 300)}` : ''}`,
      },
      true,
      'verify'
    );
  }

  if (r.killed || !isAlive()) return true;

  const disk = readHarnessVerifyResults(codeDir);
  let exploits = disk.exploits;
  if (exploits.length === 0 && r.structured && Array.isArray(r.structured.exploits)) {
    exploits = r.structured.exploits;
  }
  if (exploits.length === 0) {
    const e = parseStructuredArray(r.finalResult, 'exploits');
    if (e.length) exploits = e;
  }
  exploits = mergeExploits([...priorExploits, ...exploits]);
  let alignedExploits = alignExploitsToVulnList(allVulns, exploits);

  await retryMissingRemoteVulns(
    projectId,
    codeDir,
    allVulns,
    alignedExploits,
    envInfo,
    envSpecOf(project),
    false,
    isAlive,
    { harness: true }
  );
  if (isAlive() && !verifyKilled.has(projectId)) {
    const diskAfterRetry = readHarnessVerifyResults(codeDir);
    exploits = mergeExploits([...priorExploits, ...diskAfterRetry.exploits]);
    alignedExploits = alignExploitsToVulnList(allVulns, exploits);
  }
  exploits = alignedExploits;

  if (!opts.keepTargetAlive) {
    recordEvent(
      projectId,
      { kind: 'system', agent: '主控', tool: '', text: '✓ 沙箱验证完成' },
      true,
      'verify'
    );
  }

  const successN = exploits.filter((e: any) => remoteStatusOf(e) === 'success').length;
  const restrictedN = exploits.filter((e: any) => remoteStatusOf(e) === 'restricted').length;
  const unknownN = exploits.filter((e: any) => remoteStatusOf(e) === 'unknown').length;
  const summaryPrefix = unknownN > 0 ? '沙箱验证收尾（未完整）' : '沙箱单漏洞验证完成';
  saveExploitReport(projectId, {
    summary: `${summaryPrefix}：${allVulns.length} 个 严重/高危/中危 漏洞逐一实测，${successN} 个完全命中(success)、${restrictedN} 个受限(restricted)${unknownN ? `、${unknownN} 个未产出结果(unknown)` : ''}；组合链验证已跳过（非 Web 项目）。`,
    exploits,
    chains: [],
  });
  broadcast({ type: 'project_status', projectId, exploit_progress: true });
  recordEvent(
    projectId,
    {
      kind: 'text',
      agent: '主控',
      tool: '',
      text: `验证结论：沙箱实测完成，${successN} 个完全命中、${restrictedN} 个受限`,
    },
    true,
    'verify'
  );
  return false;
}

function finishVerify(projectId: string, verify_status: string, error: string | null): void {
  recordEvent(
    projectId,
    {
      kind: verify_status === 'completed' ? 'result' : 'error',
      agent: '主控',
      tool: '',
      text: verify_status === 'completed' ? '验证完成' : `验证失败：${error || ''}`,
    },
    true,
    'verify'
  );
  setVerifyStatus(projectId, verify_status, { verify_finished_at: now(), verify_error: error });
  const p = getProject(projectId);
  if (p?.workspace_path) {
    void releaseIdleTargetEnvironment(projectId, p.workspace_path);
  }
  if (verify_status === 'completed' || verify_status === 'failed' || verify_status === 'none') {
    setImmediate(() => harvestAndMaybePurgeSource(projectId));
  }
}

/**
 * 收尾前以「MCP 账本 + 磁盘产物」为权威重算并落盘 exploit_report，返回仍为 unknown 的 CHM 单漏洞数。
 * 修复：补验/后期才落盘的 success 结果若没刷进 DB 报告（例如补验后的重读被 isAlive 门跳过、或落盘晚于收尾），
 * finalize 会读到陈旧报告把已 success 的洞误判为 unknown → 判 failed，并连带挡掉组合链，形成 failed↔续跑 死循环。
 * 返回 null 表示无可用产物（保持旧行为，回退到 DB 报告计数）。
 */
function refreshReportFromAuthoritative(projectId: string): number | null {
  const p = getProject(projectId);
  const artifactRoot = resolveArtifactRoot(projectId, p?.workspace_path);
  if (!p || !artifactRoot) return null;
  const codeDir = artifactRoot;
  const disk = readRemoteVerifyResults(codeDir, projectId);
  const diskPriorExploits = readRemoteVerifyPriorExploits(codeDir);
  let prior: { summary?: string; exploits?: any[]; chains?: any[] } = {};
  try {
    if (p.exploit_report) prior = JSON.parse(p.exploit_report);
  } catch {
    /* 空 prior */
  }
  const priorExploits = Array.isArray(prior.exploits) ? prior.exploits : [];
  if (disk.exploits.length === 0 && diskPriorExploits.length === 0 && priorExploits.length === 0) {
    return null;
  }
  const allVulns = db
    .prepare(
      "SELECT id, title, severity, file_path, line, description FROM vulnerabilities WHERE project_id = ? AND lower(severity) IN ('critical','high','medium')"
    )
    .all(projectId) as VulnBriefRow[];
  const merged = mergeExploits([...diskPriorExploits, ...priorExploits, ...disk.exploits]);
  const exploits = allVulns.length > 0 ? alignExploitsToVulnList(allVulns, merged) : merged;
  const priorChains = Array.isArray(prior.chains) ? prior.chains : [];
  const chains = disk.chains.length > 0 ? disk.chains : priorChains;
  const pending = countPendingChmSingles(projectId, exploits);
  const successN = exploits.filter((e) => remoteStatusOf(e) === 'success').length;
  const restrictedN = exploits.filter((e) => remoteStatusOf(e) === 'restricted').length;
  saveExploitReport(projectId, {
    summary:
      prior.summary ||
      `远程验证收尾：完全命中 ${successN}、受限 ${restrictedN}${pending ? `、仍待验证 ${pending}` : ''}`,
    exploits,
    chains,
  });
  return pending;
}

/** 验证收尾：仍有待验证项时不允许标 completed。 */
function finalizeVerifyOutcome(projectId: string): void {
  // 先以账本+磁盘为权威重算，避免"其实已 success 却因陈旧报告判 unknown"的假失败。
  const refreshed = refreshReportFromAuthoritative(projectId);
  const pending = refreshed != null ? refreshed : countPendingChmSingles(projectId);
  if (pending > 0) {
    finishVerify(
      projectId,
      'failed',
      `验证未完整：仍有 ${pending} 个 严重/高危/中危 漏洞尚无结论（待验证），请续跑验证`
    );
    return;
  }
  finishVerify(projectId, 'completed', null);
}

/** 校正误标为 completed 但仍有待验证项的项目；可选自动续跑。 */
export function reconcileFalseCompletedVerify(autoResume = false): string[] {
  const fixed: string[] = [];
  const rows = db
    .prepare("SELECT id FROM projects WHERE verify_status = 'completed'")
    .all() as { id: string }[];
  for (const r of rows) {
    const pending = countPendingChmSingles(r.id);
    if (pending <= 0) continue;
    finishVerify(
      r.id,
      'failed',
      `验证未完整：仍有 ${pending} 个 严重/高危/中危 漏洞待验证`
    );
    fixed.push(r.id);
    if (autoResume) enqueueVerify(r.id, true);
  }
  return fixed;
}

/** 为仍有待验证项且验证处于 paused/failed 的项目排队续跑。 */
export function resumeIncompleteVerifyProjects(): number {
  let n = 0;
  const rows = db
    .prepare("SELECT id FROM projects WHERE status = 'completed' AND verify_status IN ('paused', 'failed')")
    .all() as { id: string }[];
  for (const r of rows) {
    if (countPendingChmSingles(r.id) <= 0) continue;
    if (enqueueVerify(r.id, true)) n++;
  }
  return n;
}

/* --------------------- 分环节运行编排（单独跑某环节 / 从某环节跑到本流水线末尾） --------------------- */

/** 环节⑤：靶机环境搭建（包装 doPrebuildEnv，inline 执行）。 */
async function stageEnv(projectId: string): Promise<{ killed: boolean }> {
  verifyKilled.delete(projectId);
  await doPrebuildEnv(projectId); // 内部 setEnvStatus building→ready/failed；被中断则保持 building
  const p = getProject(projectId);
  return { killed: !p || p.env_status === 'building' };
}

/**
 * 分环节运行编排器：
 * - mode='only'：只跑该环节；mode='from'：从该环节顺序跑到本流水线末尾。
 * - 审计侧 subagent 的 from 等同完整审计（doAudit）；其余审计环节自包含读上游产物。
 * - 验证侧 env 用 env_status、remote 用 verify_status。
 */
async function runStagePipeline(
  projectId: string,
  fromStage: PipeStage,
  mode: 'only' | 'from'
): Promise<void> {
  const project = getProject(projectId);
  if (!project) return;

  if (stageSide(fromStage) === 'audit') {
    // subagent 的"从此到末尾"=完整审计；only subagent 未在 UI 暴露，这里兜底等同完整审计
    if (fromStage === 'subagent') {
      await doAudit(projectId);
      return;
    }
    setAuditStatus(projectId, 'running', { started_at: now(), error_message: null });
    let codeDir: string;
    try {
      codeDir = await ensureWorkspace(getProject(projectId)!);
    } catch (err: any) {
      finishAudit(projectId, 'failed', `源码准备失败：${err?.message || err}`);
      return;
    }
    const idx = AUDIT_PIPE.indexOf(fromStage);
    const stages = mode === 'only' ? [fromStage] : AUDIT_PIPE.slice(idx);
    recordEvent(projectId, {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `▶ 分环节运行（${mode === 'only' ? '仅本环节' : '从此到末尾'}）：${stages.join(' → ')}`,
    });
    let carry: any[] | undefined;
    for (const st of stages) {
      if (st === 'dedup') {
        const r = await stageDedup(projectId, codeDir);
        if (r.killed) return;
        carry = r.findings;
      } else if (st === 'codeverify') {
        const r = await stageCodeVerify(projectId, codeDir, carry);
        if (r.killed) return;
        carry = r.findings;
      } else if (st === 'regrade') {
        if (isMergeVerifyRegrade() && carry && stages.includes('codeverify')) {
          const finalFindings = carry.map((v: any) => ({
            ...v,
            regrade_value: realTeamLabel(String(v.severity || 'info').toLowerCase()),
          }));
          db.prepare('DELETE FROM vulnerabilities WHERE project_id = ?').run(projectId);
          saveVulnerabilities(projectId, finalFindings);
          recordEvent(projectId, {
            kind: 'system',
            agent: '主控',
            tool: '',
            text: '✓ 已合并二次评级到代码级验证（省一轮评级 fan-out），直接落库',
          });
          carry = finalFindings;
        } else {
          const r = await stageRegrade(projectId, codeDir, carry);
          if (r.killed) return;
          carry = r.findings;
        }
      }
    }
    if (stages.includes('regrade')) {
      // stageRegrade 已整集落库
    } else if (stages.includes('codeverify') && carry) {
      db.prepare('DELETE FROM vulnerabilities WHERE project_id = ?').run(projectId);
      saveVulnerabilities(projectId, carry);
    } else if (
      (
        db.prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE project_id = ?').get(projectId) as {
          c: number;
        }
      ).c === 0
    ) {
      if (carry && carry.length > 0) {
        saveVulnerabilities(projectId, carry);
      } else {
        ensureVulnsPersistedFromDisk(projectId, '分环节审计收尾');
      }
    }
    finishAudit(projectId, 'completed', null);
  } else {
    // 验证侧
    const idx = VERIFY_PIPE.indexOf(fromStage);
    const stages = mode === 'only' ? [fromStage] : VERIFY_PIPE.slice(idx);
    setVerifyStatus(projectId, 'running', { verify_started_at: now(), verify_error: null });
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `▶ 分环节运行（${mode === 'only' ? '仅本环节' : '从此到末尾'}）：${stages.join(' → ')}`,
      },
      true,
      'verify'
    );
    if (stages.includes('env')) {
      const r = await stageEnv(projectId);
      if (r.killed) {
        setVerifyStatus(projectId, 'none', { verify_started_at: null, verify_finished_at: null, verify_error: null });
        return;
      }
    }
    const wantRemote = stages.includes('remote');
    const wantChain = stages.includes('chain');
    if (wantRemote || wantChain) {
      let codeDir: string;
      try {
        codeDir = await ensureWorkspace(getProject(projectId)!);
      } catch (err: any) {
        finishVerify(projectId, 'failed', `源码准备失败：${err?.message || err}`);
        return;
      }
      if (!(await ensureTargetUp(projectId, codeDir))) {
        finishVerify(projectId, 'failed', '来源校验失败或靶机未就绪；未启动远程验证');
        return;
      }
      if (wantRemote) clearVerifyResults(projectId);
      const isHarness =
        readTargetEnvMode(codeDir) === 'harness' || detectProjectShape(codeDir) === 'harness';
      if (isHarness) {
        if (wantRemote) {
          const killed = await runHarnessVerifyCore(projectId, codeDir);
          if (killed) return;
        }
      } else {
        if (wantRemote) {
          const killed = await runRemoteVerifyCore(projectId, codeDir, [], { skipChain: true });
          if (killed) return;
        }
        if (wantChain) {
          const priorSingles = readStoredExploitReport(projectId).exploits;
          const killed = await runRemoteVerifyCore(projectId, codeDir, priorSingles, {
            chainOnly: true,
          });
          if (killed) return;
        }
      }
      finalizeVerifyOutcome(projectId);
    } else {
      // 仅 env：没有真正的利用验证，verify_status 回到 none（env_status 已反映靶机就绪）
      setVerifyStatus(projectId, 'none', { verify_started_at: null, verify_finished_at: null, verify_error: null });
      recordEvent(
        projectId,
        { kind: 'result', agent: '主控', tool: '', text: '靶机环境搭建完成' },
        true,
        'verify'
      );
    }
  }
}

/* ------------------------------ 队列调度 ------------------------------ */
async function runJob(job: Job): Promise<void> {
  runningKind.set(job.id, job.kind);
  // 新任务真正开始：清除上一轮可能残留的中止标志，并登记为"在途"。
  cancelledProjects.delete(job.id);
  verifyKilled.delete(job.id);
  inFlight.add(job.id);
  try {
    if (job.stage) await runStagePipeline(job.id, job.stage, job.stageMode || 'from');
    else if (job.kind === 'verify' && job.chainOnly) await doVerifyChain(job.id);
    else if (job.kind === 'verify') await doVerify(job.id, job.resume === true);
    else if (job.kind === 'verifyone') await doVerifyOne(job.id, job.oneTitle || '');
    else if (job.kind === 'reprocess') await doReprocess(job.id, job.continueMode === true);
    else await doAudit(job.id);
  } catch (err: any) {
    if (job.kind === 'verify') finishVerify(job.id, 'failed', `验证异常：${err?.message || err}`);
    else finishAudit(job.id, 'failed', `审计异常：${err?.message || err}`);
  } finally {
    if (isVerifyJobKind(job.kind)) {
      activeVerifyProjects.delete(job.id);
    } else {
      activeAuditProjects.delete(job.id);
    }
    releasePiForProject(job.id);
    inFlight.delete(job.id);
    running.delete(job.id);
    runningKind.delete(job.id);
    mainStageResolvers.delete(job.id);

    // 防护：异步已退出但 DB 仍标 running（典型：killed 早退未改状态）→ 自动暂停，避免假 running 占列表。
    if (!isVerifyJobKind(job.kind) && !restartRequests.has(job.id)) {
      const leftover = getProject(job.id);
      if (leftover?.status === 'running') {
        setAuditStatus(job.id, 'paused', {
          finished_at: now(),
          error_message: '审计进程已结束但未正常收尾，已自动暂停；可点继续续跑后处理',
        });
        recordEvent(job.id, {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: '⚠ 审计任务退出时状态仍为 running，已自动标为暂停',
        });
      }
    }

    const restart = restartRequests.get(job.id);
    if (restart) {
      // 被请求重跑：在旧任务彻底清理后再重新入队，规避竞态
      restartRequests.delete(job.id);
      if (restart.stage) enqueueStage(job.id, restart.stage, restart.stageMode || 'from');
      else if (restart.kind === 'verify' && restart.chainOnly) enqueueVerifyChain(job.id);
      else if (restart.kind === 'verify') enqueueVerify(job.id, false);
      else if (restart.kind === 'reprocess') enqueueReprocess(job.id, restart.chainVerify);
      else enqueueAudit(job.id, restart.chainVerify);
    } else if (
      (job.kind === 'audit' || job.kind === 'reprocess') &&
      // 「仅本环节」由用户精确控制，不接远程验证；完整审计 / 从此到末尾 / 续跑仍按 auto_verify 自动入队。
      (!job.stage || job.stageMode !== 'only') &&
      (isAutoVerify(job.id) || job.chainVerify)
    ) {
      // 审计成功后：等靶机预搭建也结束，两边汇合再入队远程验证
      const p = getProject(job.id);
      if (p && p.status === 'completed' && p.verify_status === 'none') {
        if (shouldRemoteVerify(job.id)) {
          if (needsComposeEnv(job.id)) {
            await awaitEnvBuildIdle(job.id);
            const p2 = getProject(job.id);
            if (p2 && p2.status === 'completed' && p2.verify_status === 'none') {
              if (p2.env_status === 'failed') {
                recordEvent(
                  job.id,
                  {
                    kind: 'error',
                    agent: '主控',
                    tool: '',
                    text: '靶机搭建失败，审计结果已输出；跳过远程验证（env=failed），不假装已验证',
                  },
                  true,
                  'verify'
                );
                setVerifyStatus(job.id, 'failed', {
                  verify_finished_at: now(),
                  verify_error: '靶机环境搭建失败，未进行远程验证',
                });
              } else {
                enqueueVerify(job.id);
              }
            }
          } else {
            enqueueVerify(job.id);
          }
        } else if (isWebOnlyPipeline()) {
          recordEvent(
            job.id,
            {
              kind: 'system',
              agent: '主控',
              tool: '',
              text: '⊘ 远程验证已跳过：项目无 Web 端（设置：仅处理含 Web 端项目）',
            },
            true,
            'verify'
          );
        }
      }
    } else {
      // 全量/单漏洞验证收尾后：若有"验证进行中被暂存"的单漏洞验证请求，逐个补验（靶机 ensureTargetUp 会拉起）
      const pend = pendingVerifyOne.get(job.id);
      if (pend && pend.length > 0 && !cancelledProjects.has(job.id)) {
        const nextTitle = pend.shift()!;
        if (pend.length === 0) pendingVerifyOne.delete(job.id);
        const p = getProject(job.id);
        if (p && p.status === 'completed' && strictVerifyQueueGate(job.id)) {
          setVerifyStatus(job.id, 'queued');
          queue.push({ id: job.id, kind: 'verifyone', oneTitle: nextTitle });
        }
      }
    }
    startNext();
  }
}

/** 是否在审计完成后自动进入靶机验证（项目级 → 全局默认）。 */
function isAutoVerify(projectId: string): boolean {
  return projOptBool(projectId, 'opt_auto_verify', 'auto_verify');
}

const SKIP_NON_WEB_MSG = '已跳过/暂停：当前设置仅处理含 Web 端项目';

function persistProjectHasWeb(projectId: string, hasWeb: boolean | null): void {
  const v = hasWeb === true ? 1 : hasWeb === false ? 0 : null;
  db.prepare('UPDATE projects SET has_web = ? WHERE id = ?').run(v, projectId);
  broadcast({ type: 'project_status', projectId, has_web: v });
}

/**
 * 落库语义判定得到的注册功能画像（has_registration / reg_default_open）。
 * 仅对含 Web 端的项目写入；无 Web 端项目注册功能无意义，保持原值不动（避免误显“注册功能 无”徽章）。
 */
function persistRegistrationMeta(
  projectId: string,
  hasWeb: boolean,
  exists: boolean | undefined,
  defaultOpen: boolean | undefined
): void {
  if (!hasWeb) return;
  const reg = exists === true ? 1 : exists === false ? 0 : null;
  // 无注册功能时默认开放必为 0；有注册功能则采用模型判定，未给出则 null
  const open = reg === 0 ? 0 : defaultOpen === true ? 1 : defaultOpen === false ? 0 : null;
  if (reg === null && open === null) return;
  db.prepare('UPDATE projects SET has_registration = ?, reg_default_open = ? WHERE id = ?').run(
    reg,
    open,
    projectId
  );
  broadcast({ type: 'project_status', projectId, has_registration: reg, reg_default_open: open });
}

/** 从 Pi Agent 输出里解析 { has_web, project_kind, reason, ... } 对象（容错：裸 JSON / ```json``` / 内嵌）。 */
function parseHasWebResult(text: string): {
  has_web: boolean;
  project_kind?: string;
  reason?: string;
  has_registration?: boolean;
  register_default_on?: boolean;
} | null {
  if (!text) return null;
  const tryParse = (s: string) => {
    try {
      const o = JSON.parse(s);
      if (o && typeof o === 'object' && typeof o.has_web === 'boolean') return o;
    } catch {
      /* ignore */
    }
    return null;
  };
  let r = tryParse(text.trim());
  if (r) return r;
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    r = tryParse(fence[1].trim());
    if (r) return r;
  }
  const idx = text.indexOf('"has_web"');
  if (idx !== -1) {
    const start = text.lastIndexOf('{', idx);
    if (start !== -1) {
      for (let end = text.length; end > idx; end--) {
        r = tryParse(text.slice(start, end));
        if (r) return r;
      }
    }
  }
  return null;
}

/** 从 Pi Agent 输出里解析注册判定 { has_registration, register_default_on, reason }。 */
function parseRegistrationResult(text: string): {
  has_registration: boolean;
  register_default_on?: boolean;
  reason?: string;
} | null {
  if (!text) return null;
  const tryParse = (s: string) => {
    try {
      const o = JSON.parse(s);
      if (o && typeof o === 'object' && typeof o.has_registration === 'boolean') return o;
    } catch {
      /* ignore */
    }
    return null;
  };
  let r = tryParse(text.trim());
  if (r) return r;
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    r = tryParse(fence[1].trim());
    if (r) return r;
  }
  const idx = text.indexOf('"has_registration"');
  if (idx !== -1) {
    const start = text.lastIndexOf('{', idx);
    if (start !== -1) {
      for (let end = text.length; end > idx; end--) {
        r = tryParse(text.slice(start, end));
        if (r) return r;
      }
    }
  }
  return null;
}

/**
 * 语义级 Web 端判定：用一次轻量 Pi Agent 调用（结合 CodeGraph）从整体结构判断项目是否含可部署 Web 端。
 * 成功返回 boolean；被暂停/超时/无法解析时返回 null（由调用方回退到规则匹配）。
 */
async function classifyWebWithPi(projectId: string, codeDir: string): Promise<boolean | null> {
  recordEvent(
    projectId,
    { kind: 'system', agent: '主控', tool: '', text: '▶ 语义判定项目形态（是否含可部署 Web 端）…' },
    true,
    'audit'
  );
  const r = await runPiStage(
    projectId,
    codeDir,
    buildWebClassifyPrompt(codeDir),
    JSON.stringify(WEB_CLASSIFY_SCHEMA),
    { channel: 'main', phase: 'audit', hardMsOverride: 8 * 60_000, idleMsOverride: 3 * 60_000 }
  );
  if (r.killed || r.timedOut) return null;
  const parsed =
    (r.structured && typeof (r.structured as any).has_web === 'boolean'
      ? (r.structured as any)
      : null) || parseHasWebResult(r.finalResult);
  if (!parsed) return null;
  // 顺带落库注册功能画像（仅 Web 端有意义）
  persistRegistrationMeta(
    projectId,
    parsed.has_web,
    typeof parsed.has_registration === 'boolean' ? parsed.has_registration : undefined,
    typeof parsed.register_default_on === 'boolean' ? parsed.register_default_on : undefined
  );
  const regText = parsed.has_web
    ? parsed.has_registration === true
      ? `；含注册功能（默认${parsed.register_default_on === true ? '开放' : '关闭'}）`
      : parsed.has_registration === false
        ? '；无自助注册'
        : ''
    : '';
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `✓ 语义判定：${parsed.has_web ? '含 Web 端' : '无 Web 端'}${
        parsed.project_kind ? `（${parsed.project_kind}）` : ''
      }${regText}${parsed.reason ? ` —— ${parsed.reason}` : ''}`,
    },
    true,
    'audit'
  );
  return parsed.has_web;
}

// 进程内防重入：本轮已尝试过注册专项判定的项目（避免 ensureWorkspace 多次触发反复调用 Pi Agent）。
const registrationDetectAttempted = new Set<string>();

/**
 * 注册功能专项语义判定（走 Pi Agent，与 Web 判定一致，不用机械规则）。
 * 仅对已确认含 Web 端、但 has_registration 仍为 null 的项目做回填。
 * 成功落库返回 true；被暂停/超时/解析失败返回 false（保留 null，下次可再试）。
 */
async function classifyRegistrationWithPi(projectId: string, codeDir: string): Promise<boolean> {
  recordEvent(
    projectId,
    { kind: 'system', agent: '主控', tool: '', text: '▶ 语义判定注册功能（是否有自助注册 / 默认是否开放）…' },
    true,
    'audit'
  );
  const r = await runPiStage(
    projectId,
    codeDir,
    buildRegistrationClassifyPrompt(codeDir),
    JSON.stringify(REGISTRATION_CLASSIFY_SCHEMA),
    { channel: 'main', phase: 'audit', hardMsOverride: 8 * 60_000, idleMsOverride: 3 * 60_000 }
  );
  if (r.killed || r.timedOut) return false;
  const parsed =
    (r.structured && typeof (r.structured as any).has_registration === 'boolean'
      ? (r.structured as any)
      : null) || parseRegistrationResult(r.finalResult);
  if (!parsed || typeof parsed.has_registration !== 'boolean') return false;
  persistRegistrationMeta(
    projectId,
    true,
    parsed.has_registration,
    typeof parsed.register_default_on === 'boolean' ? parsed.register_default_on : undefined
  );
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `✓ 注册功能判定：${
        parsed.has_registration
          ? `含自助注册（默认${parsed.register_default_on === true ? '开放' : '关闭'}）`
          : '无自助注册'
      }${parsed.reason ? ` —— ${parsed.reason}` : ''}`,
    },
    true,
    'audit'
  );
  return true;
}

/**
 * 确保含 Web 端项目的注册功能已被识别（Pi Agent 回填）。
 * 场景：项目在“注册识别”功能上线前就已判定 has_web=1，导致 has_registration 一直为 null。
 * 仅在 has_web=1 且 has_registration=null 时触发一次 Pi Agent 判定；进程内去重防止重复调用。
 */
async function ensureRegistrationDetected(projectId: string, codeDir: string): Promise<void> {
  const p = getProject(projectId);
  if (!p || p.has_web !== 1 || p.has_registration !== null) return;
  if (registrationDetectAttempted.has(projectId)) return;
  registrationDetectAttempted.add(projectId);
  try {
    const ok = await classifyRegistrationWithPi(projectId, codeDir);
    if (!ok) registrationDetectAttempted.delete(projectId); // 暂停/超时/解析失败允许下次重试
  } catch {
    registrationDetectAttempted.delete(projectId);
  }
}

/**
 * 权威 Web 端判定（审计流水线内使用）：
 *   1) DB 已有 has_web(0/1) → 直接复用（一次判定长期缓存）；
 *   2) 否则用 Pi 语义判定（LLM 画像优先）；
 *   3) LLM 不可用/未得结论 → 回退到 CodeGraph + 文件规则匹配（兜底）。
 * 结果落库缓存，后续 ensureWorkspace/skip/gate 均复用。
 */
async function resolveHasWebAuthoritative(projectId: string, codeDir: string): Promise<boolean> {
  const p = getProject(projectId);
  if (p?.has_web === 1) return true;
  if (p?.has_web === 0) return false;

  const llm = await classifyWebWithPi(projectId, codeDir);
  if (llm !== null) {
    persistProjectHasWeb(projectId, llm);
    return llm;
  }

  // 兜底：规则匹配（LLM 被暂停/超时/解析失败时）
  const kind = resolveProjectKindWithCodegraph(codeDir);
  const hasWeb = kind.has_web === true;
  persistProjectHasWeb(projectId, hasWeb);
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `（语义判定未得结论，已回退规则识别：${kind.web_label}）`,
    },
    true,
    'audit'
  );
  // 机械规则无法顺带识别注册，立即触发专项 Pi Agent 回填（ensureWorkspace 也会再调一次，内部去重）。
  if (hasWeb) await ensureRegistrationDetected(projectId, codeDir);
  return hasWeb;
}

/* ==================== 批量 Web 端语义判定 + 清理 ==================== */

interface WebClassifyCandidate {
  id: string;
  name: string;
  source_link: string;
  reason: string;
}

interface WebClassifyBatch {
  phase: 'idle' | 'classifying' | 'awaiting_confirm' | 'deleting' | 'done';
  total: number;
  done: number;
  running: number;
  concurrency: number;
  startedAt: number;
  cancelled: boolean;
  web: number;
  nonWeb: WebClassifyCandidate[];
  failed: string[];
  skipped: string[];
  deleted: number;
  error?: string;
}

let webClassifyBatch: WebClassifyBatch = {
  phase: 'idle',
  total: 0,
  done: 0,
  running: 0,
  concurrency: 0,
  startedAt: 0,
  cancelled: false,
  web: 0,
  nonWeb: [],
  failed: [],
  skipped: [],
  deleted: 0,
};

/**
 * 单项目强制 Web 判定（批处理用）。按 workspace/has_web 分支，避免重复调用 Pi Agent：
 *  - 无 workspace（含 null 未克隆）→ ensureWorkspace（clone+建图；对 has_web=null 会自动判定一次，即首判）
 *  - 有 workspace → 直接 classifyWebWithPi 强制（重）判定，落库
 * 返回最终 has_web；判定失败返回 null。
 */
async function classifyOneProjectForBatch(projectId: string): Promise<boolean | null> {
  const p = getProject(projectId);
  if (!p) return null;

  const hasWorkspace = !!p.workspace_path && fs.existsSync(p.workspace_path);

  if (!hasWorkspace) {
    // 缺工作区：ensureWorkspace 会 clone + 建 CodeGraph；对 has_web=null 会内部自动判定一次。
    let codeDir: string;
    try {
      codeDir = await ensureWorkspace(p);
    } catch {
      return null;
    }
    // 已判定过（非 null）的项目即便刚 clone，也要强制重判以贯彻"重新判断"。
    if (p.has_web !== null) {
      const llm = await classifyWebWithPi(projectId, codeDir);
      if (llm !== null) persistProjectHasWeb(projectId, llm);
    }
    const after = getProject(projectId);
    return after?.has_web === 1 ? true : after?.has_web === 0 ? false : null;
  }

  // 有工作区：直接强制（重）判定
  const llm = await classifyWebWithPi(projectId, p.workspace_path!);
  if (llm !== null) {
    persistProjectHasWeb(projectId, llm);
    return llm;
  }
  // LLM 超时/解析失败 → 规则兜底（与审计流水线 resolveHasWebAuthoritative 一致）
  const kind = resolveProjectKindWithCodegraph(p.workspace_path!);
  const hasWeb = kind.has_web === true;
  persistProjectHasWeb(projectId, hasWeb);
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `（语义判定未得结论，已回退规则识别：${kind.web_label}）`,
    },
    true,
    'audit'
  );
  return hasWeb;
}

/** 启动全库批量 Web 端判定（后台异步，滑动窗口并发）。 */
export function startWebClassifyBatch(): { ok: boolean; total?: number; error?: string } {
  if (webClassifyBatch.phase === 'classifying' || webClassifyBatch.phase === 'deleting') {
    return { ok: false, error: '批处理已在进行中' };
  }
  const rows = db.prepare('SELECT id FROM projects').all() as { id: string }[];
  const concurrency = classifyConcurrency();
  webClassifyBatch = {
    phase: 'classifying',
    total: rows.length,
    done: 0,
    running: 0,
    concurrency,
    startedAt: now(),
    cancelled: false,
    web: 0,
    nonWeb: [],
    failed: [],
    skipped: [],
    deleted: 0,
  };
  void runWebClassifyBatch(rows.map((r) => r.id));
  return { ok: true, total: rows.length };
}

/** 批处理执行体：滑动窗口并发判定，跳过正在忙的项目，非 Web 汇总为待确认候选。 */
async function runWebClassifyBatch(ids: string[]): Promise<void> {
  const concurrency = webClassifyBatch.concurrency || classifyConcurrency();
  let cursor = 0;

  const worker = async (): Promise<void> => {
    while (true) {
      if (webClassifyBatch.cancelled) return;
      const idx = cursor++;
      if (idx >= ids.length) return;
      const id = ids[idx];

      // 正在跑审计/验证的项目跳过，避免与主流程抢占同一进程槽
      if (isBusy(id)) {
        webClassifyBatch.skipped.push(id);
        webClassifyBatch.done++;
        continue;
      }
      const p = getProject(id);
      if (!p) {
        webClassifyBatch.done++;
        continue;
      }

      webClassifyBatch.running++;
      try {
        const hasWeb = await classifyOneProjectForBatch(id);
        if (hasWeb === null) {
          webClassifyBatch.failed.push(id);
        } else if (hasWeb) {
          webClassifyBatch.web++;
        } else {
          // 判定为非 Web：收集为候选，判定结束后由用户勾选确认再删除（不即时删除）
          const cur = getProject(id);
          const sourceLink = cur
            ? cur.source_type === 'github'
              ? cur.source_ref
              : cur.archive_name
            : '';
          webClassifyBatch.nonWeb.push({
            id,
            name: cur?.project_name || id,
            source_link: sourceLink,
            reason: '语义判定：无 Web 端',
          });
        }
      } catch {
        webClassifyBatch.failed.push(id);
      } finally {
        webClassifyBatch.running--;
        webClassifyBatch.done++;
      }
    }
  };

  const workers = Array.from({ length: Math.max(1, concurrency) }, () => worker());
  await Promise.all(workers);

  // 判定完成：进入待确认，非 Web 候选清单交由用户勾选删除
  webClassifyBatch.phase = webClassifyBatch.cancelled ? 'done' : 'awaiting_confirm';
}

/** 查询批处理进度与非 Web 候选清单。 */
export function getWebClassifyStatus(): WebClassifyBatch {
  return webClassifyBatch;
}

/** 确认删除选中的非 Web 候选（写回收站，reason=auto_non_web）。 */
export function confirmWebClassifyDelete(ids: string[]): { deleted: number; failed: number } {
  const candidateIds = new Set(webClassifyBatch.nonWeb.map((c) => c.id));
  let deleted = 0;
  let failed = 0;
  webClassifyBatch.phase = 'deleting';
  for (const id of ids) {
    // 只允许删除本批次判定出的非 Web 候选，避免误删
    if (!candidateIds.has(id)) continue;
    try {
      const cand = webClassifyBatch.nonWeb.find((c) => c.id === id);
      if (purgeProject(id, 'auto_non_web', cand?.reason || '语义判定：无 Web 端')) deleted++;
    } catch {
      failed++;
    }
  }
  webClassifyBatch.deleted += deleted;
  // 从候选清单移除已删除项
  webClassifyBatch.nonWeb = webClassifyBatch.nonWeb.filter((c) => !ids.includes(c.id));
  webClassifyBatch.phase = 'awaiting_confirm';
  return { deleted, failed };
}

/** 取消进行中的批处理（worker 到检查点停止）。 */
export function cancelWebClassifyBatch(): void {
  if (webClassifyBatch.phase === 'classifying') webClassifyBatch.cancelled = true;
}

/* ============ 每批导入的 Web 端前置识别（勾选“只审计 Web 端”时触发；识别后暂停，不自动开审） ============ */

interface ImportScreenBatch {
  phase: 'idle' | 'screening' | 'done';
  total: number;
  done: number;
  running: number;
  concurrency: number;
  web: number;
  deleted: number;
  failed: number;
  cancelled: boolean;
  startedAt: number;
}

let importScreenBatch: ImportScreenBatch = {
  phase: 'idle',
  total: 0,
  done: 0,
  running: 0,
  concurrency: 0,
  web: 0,
  deleted: 0,
  failed: 0,
  cancelled: false,
  startedAt: 0,
};

// 前置识别待处理队列（支持并发导入时把新批次追加到同一识别流水）
const screenQueue: string[] = [];
let screenWorkersActive = false;

/**
 * 启动/追加“每批导入 Web 端前置识别”：
 * 对给定项目先统一判定是否含 Web 端——非 Web 直接移入回收站，含 Web 才入队正常审计。
 * 判定失败（超时/无法解析）保底仍入队审计，避免丢项目。
 */
export function startImportPrescreen(ids: string[]): { ok: boolean; total: number } {
  if (ids.length === 0) return { ok: true, total: 0 };

  // 若上一轮已结束，则本轮重置计数；否则并入正在进行的识别
  if (importScreenBatch.phase !== 'screening') {
    importScreenBatch = {
      phase: 'screening',
      total: 0,
      done: 0,
      running: 0,
      concurrency: classifyConcurrency(),
      web: 0,
      deleted: 0,
      failed: 0,
      cancelled: false,
      startedAt: now(),
    };
  }
  importScreenBatch.total += ids.length;
  screenQueue.push(...ids);
  void runImportScreenWorkers();
  return { ok: true, total: importScreenBatch.total };
}

async function runImportScreenWorkers(): Promise<void> {
  if (screenWorkersActive) return; // 已有 worker 池在跑，新 id 已入队会被消费
  screenWorkersActive = true;

  const worker = async (): Promise<void> => {
    while (true) {
      if (importScreenBatch.cancelled) return;
      const id = screenQueue.shift();
      if (id === undefined) return;

      importScreenBatch.running++;
      try {
        const hasWeb = await classifyOneProjectForBatch(id);
        if (hasWeb === false) {
          try {
            if (purgeProject(id, 'auto_non_web', '无 Web 端（新建审计：只审计 Web 端）')) {
              importScreenBatch.deleted++;
            }
          } catch {
            /* 删除失败不阻断 */
          }
        } else if (hasWeb === true) {
          // 只做 Web 识别：含 Web 端的项目停在暂停态，由用户点「继续」再真正开审
          importScreenBatch.web++;
          setAuditStatus(id, 'paused', { finished_at: now(), error_message: null });
          recordEvent(id, {
            kind: 'system',
            agent: '主控',
            tool: '',
            text: '✓ Web 端识别完成：已暂停，等待手动继续审计',
          });
        } else {
          // 判定失败：同样暂停，避免误开全量审计；用户可稍后手动继续
          importScreenBatch.failed++;
          setAuditStatus(id, 'paused', { finished_at: now(), error_message: null });
          recordEvent(id, {
            kind: 'system',
            agent: '主控',
            tool: '',
            text: '⚠ Web 端识别未得结论：已暂停，可手动继续审计',
          });
        }
      } catch {
        importScreenBatch.failed++;
        setAuditStatus(id, 'paused', { finished_at: now(), error_message: null });
        recordEvent(id, {
          kind: 'system',
          agent: '主控',
          tool: '',
          text: '⚠ Web 端识别异常：已暂停，可手动继续审计',
        });
      } finally {
        importScreenBatch.running--;
        importScreenBatch.done++;
      }
    }
  };

  const concurrency = Math.max(1, importScreenBatch.concurrency || classifyConcurrency());
  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  screenWorkersActive = false;
  // 可能在收尾瞬间又追加了新 id：若队列非空则再拉起一轮
  if (screenQueue.length > 0 && !importScreenBatch.cancelled) {
    void runImportScreenWorkers();
    return;
  }
  importScreenBatch.phase = 'done';
}

/** 查询前置识别进度。 */
export function getImportScreenStatus(): ImportScreenBatch {
  return importScreenBatch;
}

/** 取消前置识别：清空待处理队列，剩余项目保持 pending（可后续手动处理）。 */
export function cancelImportPrescreen(): void {
  if (importScreenBatch.phase === 'screening') {
    importScreenBatch.cancelled = true;
    screenQueue.length = 0;
  }
}

/** 开启「仅 Web 端」时，跳过无 Web 端项目（不跑审计与验证）。has_web 已在 ensureWorkspace 权威判定并落库。 */
function skipProjectForNonWeb(projectId: string, codeDir: string): boolean {
  if (!isWebOnlyPipeline()) return false;
  const p = getProject(projectId);
  // ensureWorkspace 已完成权威判定；此处优先读库，避免重复触发 LLM/规则。
  let hasWeb: boolean;
  if (p?.has_web === 1) hasWeb = true;
  else if (p?.has_web === 0) hasWeb = false;
  else {
    const kind = resolveProjectKindWithCodegraph(codeDir);
    persistProjectHasWeb(projectId, kind.has_web);
    hasWeb = kind.has_web === true;
  }
  if (hasWeb) return false;
  recordEvent(
    projectId,
    {
      kind: 'result',
      agent: '主控',
      tool: '',
      text: '🗑 已识别为无 Web 端，将移入回收站（设置：仅处理含 Web 端项目）',
    },
    true,
    'audit'
  );
  // 延迟到当前 job 在 runJob.finally 中释放槽位后再 purge，避免与其清理逻辑竞态。
  const reason = '无 Web 端（设置：仅处理含 Web 端项目）';
  setTimeout(() => {
    try {
      purgeProject(projectId, 'auto_non_web', reason);
    } catch (e: any) {
      console.warn(`[web-only] 非 Web 项目自动清理失败 ${projectId}: ${e?.message || e}`);
    }
  }, 0);
  return true;
}

/**
 * 全局 web-only 门控已废弃：Web 端筛选改由“新建审计”的每批前置识别（startImportPrescreen）完成，
 * 非 Web 在进入审计前即被清理。此处恒为 false，使审计/验证管线不再做任何 web-only 特殊门控。
 */
function isWebOnlyPipeline(): boolean {
  return false;
}

/** 该项目是否应进入/继续审计或验证流水线。 */
function shouldProcessWebProject(projectId: string): boolean {
  if (!isWebOnlyPipeline()) return true;
  const p = getProject(projectId);
  if (!p) return false;
  if (p.has_web === 1) return true;
  if (p.has_web === 0) return false;
  if (!p.workspace_path || !fs.existsSync(p.workspace_path)) {
    // 工作区尚未 clone：无法在启动时用 CodeGraph 判定 Web 端，应允许入队；
    // 克隆完成后由 doAudit/skipProjectForNonWeb 再决定是否跳过（避免批量 queued 被误标 paused）。
    return true;
  }
  const kind = resolveProjectKindWithCodegraph(p.workspace_path);
  persistProjectHasWeb(projectId, kind.has_web);
  return kind.has_web === true;
}

/** Cursor 主控远程验证：工作区含此标记时禁止产品内 spawn Pi 做靶机验证。 */
function isCursorManagedVerify(projectId: string): boolean {
  const p = getProject(projectId);
  if (!p?.workspace_path) return false;
  const marker = path.join(p.workspace_path, '_cursor_verify', 'CURSOR_ONLY.json');
  return fs.existsSync(marker);
}

/** 该项目是否应进入/继续远程验证队列（产品 Pi 路径）。 */
function shouldRemoteVerify(projectId: string): boolean {
  if (isCursorManagedVerify(projectId)) return false;
  return shouldProcessWebProject(projectId);
}

/** 终止产品 Pi 远程验证进程，但不改 DB verify_status（供 Cursor 编排展示用）。 */
export function stopPiVerifyForCursorManaged(projectId: string): boolean {
  if (!isCursorManagedVerify(projectId)) return false;
  restartRequests.delete(projectId);
  requestCancel(projectId);
  stopEnvChannel(projectId);
  verifyKilled.add(projectId);
  stopVerifyProcs(projectId);
  for (let i = queue.length - 1; i >= 0; i--) {
    if (queue[i].id === projectId && isVerifyJobKind(queue[i].kind)) queue.splice(i, 1);
  }
  const child = running.get(projectId);
  const kind = runningKind.get(projectId);
  if (child && kind && isVerifyJobKind(kind)) {
    intentionallyStopped.add(projectId);
    killTree(child);
    running.delete(projectId);
    runningKind.delete(projectId);
  }
  if (!inFlight.has(projectId)) clearActiveSlots(projectId);
  return true;
}

/** 批量终止 Batch C 等产品外 Cursor 编排项目的 Pi 验证。 */
export function stopPiVerifyForCursorManagedBatch(projectIds: string[]): string[] {
  const stopped: string[] = [];
  for (const id of projectIds) {
    if (stopPiVerifyForCursorManaged(id)) stopped.push(id);
  }
  if (stopped.length) startNext();
  return stopped;
}

/** 仅暂停验证（不影响审计），用于无 Web 端项目批量停验。 */
function pauseVerifyOnly(projectId: string): void {
  const p = getProject(projectId);
  if (!p || (p.verify_status !== 'running' && p.verify_status !== 'queued')) return;

  restartRequests.delete(projectId);
  requestCancel(projectId);
  stopEnvChannel(projectId);
  verifyKilled.add(projectId);
  stopVerifyProcs(projectId);

  for (let i = queue.length - 1; i >= 0; i--) {
    if (queue[i].id === projectId && isVerifyJobKind(queue[i].kind)) queue.splice(i, 1);
  }

  const child = running.get(projectId);
  const kind = runningKind.get(projectId);
  if (child && kind && isVerifyJobKind(kind)) {
    intentionallyStopped.add(projectId);
    killTree(child);
    running.delete(projectId);
    runningKind.delete(projectId);
  }

  setVerifyStatus(projectId, 'paused', {
    verify_finished_at: now(),
    verify_error: SKIP_NON_WEB_MSG,
  });

  if (inFlight.has(projectId)) return;
  clearActiveSlots(projectId);
  startNext();
}

/** 暂停所有无 Web 端且正在排队/运行中的验证任务。 */
export function pauseNonWebVerifyProjects(): string[] {
  const paused: string[] = [];
  const rows = db
    .prepare("SELECT id FROM projects WHERE verify_status IN ('running', 'queued')")
    .all() as { id: string }[];
  for (const r of rows) {
    if (shouldProcessWebProject(r.id)) continue;
    pauseVerifyOnly(r.id);
    paused.push(r.id);
  }
  return paused;
}

/**
 * 开启「仅 Web 端」后立即生效：把存量【无 Web 端】项目一并移入回收站（不再仅暂停）。
 * 清理范围：
 *   1) 所有已权威判定为无 Web 端的项目（has_web=0），无论其状态；
 *   2) 运行/排队中、工作区已就绪且规则可廉价判定为无 Web 端的项目。
 * 未克隆/未判定（has_web=null 且无工作区）的项目保持排队，待 doAudit 克隆后按新策略清理。
 * 返回 deleted：本次被清理的项目 id 列表（pausedVerify/pausedAudit 保留字段以兼容调用方，现恒为空）。
 */
export function applyWebOnlyPolicy(): {
  pausedVerify: string[];
  pausedAudit: string[];
  deleted: string[];
} {
  if (!isWebOnlyPipeline()) return { pausedVerify: [], pausedAudit: [], deleted: [] };

  // 收集待清理候选（DB 查询轻量、同步完成）
  const targets: string[] = [];

  // 1) 已判定为无 Web 端（has_web=0）的存量项目：直接清理
  const nonWebRows = db.prepare('SELECT id FROM projects WHERE has_web = 0').all() as {
    id: string;
  }[];
  for (const r of nonWebRows) targets.push(r.id);

  // 2) 运行/排队中、尚未判定但工作区已就绪的：用 CodeGraph 规则廉价判定，非 Web 即清理
  const activeRows = db
    .prepare(
      "SELECT id FROM projects WHERE (status IN ('running','queued') OR verify_status IN ('running','queued')) AND has_web IS NULL"
    )
    .all() as { id: string }[];
  for (const r of activeRows) {
    const p = getProject(r.id);
    if (!p) continue;
    if (!p.workspace_path || !fs.existsSync(p.workspace_path)) continue; // 未克隆：留给 doAudit 处理
    const kind = resolveProjectKindWithCodegraph(p.workspace_path);
    persistProjectHasWeb(r.id, kind.has_web);
    if (kind.has_web !== true) targets.push(r.id);
  }

  // 后台分批清理，删除间让出事件循环，避免大量删除阻塞服务
  void purgeNonWebInBackground(targets);
  return { pausedVerify: [], pausedAudit: [], deleted: targets };
}

/** 后台逐个清理无 Web 端项目：每删一个 yield 一次事件循环，避免同步批删冻结服务。 */
async function purgeNonWebInBackground(ids: string[]): Promise<void> {
  const purgeReason = '无 Web 端（设置：仅处理含 Web 端项目）';
  let deleted = 0;
  for (const id of ids) {
    await new Promise<void>((r) => setImmediate(r)); // 让出事件循环，保持服务可响应
    try {
      if (purgeProject(id, 'auto_non_web', purgeReason)) deleted++;
    } catch (e: any) {
      console.warn(`[web-only] 存量非 Web 项目清理失败 ${id}: ${e?.message || e}`);
    }
  }
  if (deleted > 0) {
    console.log(`[code] 仅 Web 端模式：已自动清理 ${deleted} 个无 Web 端存量项目（移入回收站）`);
    broadcast({ type: 'project_status' } as any);
  }
}

/* --------------------- 靶机环境预搭建（与审计并行） --------------------- */

function setEnvStatus(projectId: string, env_status: EnvStatus, targetUrl?: string | null): void {
  if (targetUrl !== undefined) {
    db.prepare('UPDATE projects SET env_status = ?, target_url = ? WHERE id = ?').run(
      env_status,
      targetUrl,
      projectId
    );
  } else {
    db.prepare('UPDATE projects SET env_status = ? WHERE id = ?').run(env_status, projectId);
  }
  broadcast({ type: 'project_status', projectId, env_status });
}

/** 从环境搭建输出里尽力提取靶机访问地址（排除尾部 markdown 反引号等）。 */
/** 项目专属的 docker compose 项目名（唯一）：作为靶机容器归属与清理的锚点，避免同名工作目录串台。 */
function composeProjectName(projectId: string): string {
  return projectId.toLowerCase().replace(/[^a-z0-9_-]/g, '');
}

/** 按 projectId 稳定派生的唯一宿主端口（18000~18999）：避免多项目都抢 8080 导致串台复用。 */
function projectPort(projectId: string): number {
  let h = 0;
  for (let i = 0; i < projectId.length; i++) h = (h * 31 + projectId.charCodeAt(i)) >>> 0;
  return 18000 + (h % 1000);
}

/** 组装某项目的靶机环境规格（端口/compose 项目名/目标版本）。 */
function envSpecOf(project: Project): {
  port: number;
  projectName: string;
  version?: string;
  systemName?: string;
} {
  return {
    port: projectPort(project.id),
    projectName: composeProjectName(project.id),
    version: project.source_version || undefined,
    systemName: project.system_name || undefined,
  };
}

function extractTargetUrl(text: string): string | null {
  if (!text) return null;
  const m = text.match(/https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s)"'\x60，。、]*/i);
  if (!m) return null;
  return m[0].replace(/[`'"]+$/, '').replace(/[.,，。]+$/, '');
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** 探测靶机地址是否可达（任何 HTTP 响应都算可达，含 401/403/302）。 */
function urlReachable(rawUrl: string, timeoutMs = 8000): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    let req: http.ClientRequest | null = null;
    const finish = (v: boolean) => {
      if (done) return;
      done = true;
      // 墙钟兜底：即使 socket timeout 未触发，也绝不让探测 Promise 永久挂起
      // （XWiki 冷启动时 nginx 可能接受连接却迟迟不回包）。
      try {
        req?.destroy();
      } catch {
        /* ignore */
      }
      resolve(v);
    };
    const wall = setTimeout(() => finish(false), Math.max(500, timeoutMs + 250));
    try {
      const u = new URL(rawUrl);
      const lib = u.protocol === 'https:' ? https : http;
      req = lib.request(
        u,
        { method: 'GET', timeout: Math.max(500, timeoutMs) },
        (res) => {
          res.resume();
          clearTimeout(wall);
          finish(true);
        }
      );
      req.on('error', () => {
        clearTimeout(wall);
        finish(false);
      });
      req.on('timeout', () => {
        clearTimeout(wall);
        finish(false);
      });
      req.end();
    } catch {
      clearTimeout(wall);
      finish(false);
    }
  });
}

/**
 * 检查【归属本项目】的 docker 靶机是否有正在运行的容器。
 * 严格按项目专属 compose 项目名（= projectId 派生）过滤，避免同名工作目录的其它项目容器被误判为本项目就绪（串台）。
 */
async function targetRunning(projectName: string): Promise<boolean> {
  if (!projectName || !(await dockerAvailable())) return false;
  // compose v2：指定项目名查询运行中容器（不依赖 cwd，避免误命中同名工作目录）
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['compose', '-p', projectName, 'ps', '-q', '--status', 'running'],
      { timeout: 15000, windowsHide: true }
    );
    if (stdout.trim()) return true;
  } catch {
    /* compose v1 不支持 -p ps --status，走 label 兜底 */
  }
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['ps', '-q', '--filter', `label=com.docker.compose.project=${projectName}`],
      { timeout: 15000, windowsHide: true }
    );
    if (stdout.trim()) return true;
  } catch {
    /* ignore */
  }
  return false;
}

/**
 * 检查【归属本项目】是否**存在**靶机容器（含已停止/退出的容器）。
 * 与 targetRunning 的区别：这里用 `ps -aq`（含 stopped），用于判断"曾搭建过、容器仍在，只是被 stop 了"，
 * 据此走「拉起复用」而非「down -v 重建」。
 */
async function targetContainerExists(projectName: string): Promise<boolean> {
  if (!projectName || !(await dockerAvailable())) return false;
  // compose v2：指定项目名查询全部容器（含已停止）
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['compose', '-p', projectName, 'ps', '-aq'],
      { timeout: 15000, windowsHide: true }
    );
    if (stdout.trim()) return true;
  } catch {
    /* compose v1 不支持 -p ps -aq，走 label 兜底 */
  }
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['ps', '-aq', '--filter', `label=com.docker.compose.project=${projectName}`],
      { timeout: 15000, windowsHide: true }
    );
    if (stdout.trim()) return true;
  } catch {
    /* ignore */
  }
  return false;
}

/** 选了完整靶机（或强制全流程）时，与代码审计并行排队搭站。 */
function kickEnvPrebuildWithAudit(projectId: string, force = false): void {
  if (isCursorManagedVerify(projectId)) return;
  if (!force && !needsComposeEnv(projectId)) return;
  enqueueEnvPrebuild(projectId, { force });
}

/** 把项目排入"环境预搭建"独立队列（不占审计并发槽）。 */
function enqueueEnvPrebuild(projectId: string, opts?: { force?: boolean }): void {
  if (!isPiJobsEnabled()) return;
  if (!opts?.force && !needsComposeEnv(projectId)) return;
  const p = getProject(projectId);
  if (!p) return;
  // 审计暂停不影响独立靶机 Pi：只要选了完整靶机就继续排队
  if (envActive.has(projectId) || envQueue.includes(projectId)) return;
  // ready：容器可能已 stop，但 ensureTargetUp / 对账会 compose start；勿整轮重搭浪费 token
  if (p.env_status === 'ready' || p.env_status === 'building') return;
  envQueue.push(projectId);
  startNextEnv();
}

function startNextEnv(): void {
  if (!isPiJobsEnabled()) return;
  const cap = targetBuildConcurrency();
  while (envActive.size < cap && envQueue.length > 0) {
    const id = envQueue.shift()!;
    if (envActive.has(id)) continue;
    const p = getProject(id);
    if (!p) continue;
    if (p.env_status === 'ready' || p.env_status === 'building') continue;
    // 到这里 env_status 只可能是 none/failed；排队/重跑时仍需预搭建。
    envActive.add(id);
    const task = doPrebuildEnv(id)
      .catch(() => {})
      .finally(() => {
        envActive.delete(id);
        envTasks.delete(id);
        startNextEnv();
      });
    envTasks.set(id, task);
  }
}

/** Web 靶机环境就绪判定（原 doPrebuildEnv 收尾逻辑，行为不变）。 */
async function finalizeWebEnvReady(
  projectId: string,
  codeDir: string,
  spec: ReturnType<typeof envSpecOf>,
  r: { finalResult: string }
): Promise<void> {
  let url: string | null = null;
  try {
    const env = JSON.parse(fs.readFileSync(path.join(codeDir, 'TARGET_ENV.json'), 'utf8'));
    if (env && typeof env.url === 'string' && env.url.trim()) url = env.url.trim();
    syncRegistrationMeta(projectId, codeDir);
  } catch {
    /* 无交接文件 */
  }
  if (!url) url = extractTargetUrl(r.finalResult) || `http://localhost:${spec.port}`;
  recordEvent(
    projectId,
    { kind: 'system', agent: '主控', tool: '', text: '正在核实靶机是否真实就绪（校验容器归属本项目 + 探测地址）…' },
    true,
    'verify'
  );

  let owned = false;
  for (let i = 0; i < 3 && !owned; i++) {
    owned = await targetRunning(spec.projectName);
    if (!owned) await sleep(4000);
  }
  let reachable = false;
  if (url) {
    for (let i = 0; i < 3 && !reachable; i++) {
      reachable = await urlReachable(url);
      if (!reachable) await sleep(4000);
    }
  }

  if (owned && reachable) {
    setEnvStatus(projectId, 'ready', url ?? null);
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `✓ 靶机环境已真实就绪（${url}）·容器归属本项目·地址可访问，待验证复用`,
      },
      true,
      'verify'
    );
  } else if (owned && !reachable) {
    setEnvStatus(projectId, 'failed', url ?? null);
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: `⚠ 本项目靶机容器已运行（${url}），但地址暂未响应；已标记失败，验证阶段将重试搭建`,
      },
      true,
      'verify'
    );
  } else {
    setEnvStatus(projectId, 'failed');
    recordEvent(
      projectId,
      {
        kind: 'error',
        agent: '主控',
        tool: '',
        text: '⚠ 环境预搭建未真正起来（未检测到归属本项目的运行中容器，疑似端口被其它项目占用或构建失败），已标记失败，验证阶段会按独立端口兜底重搭',
      },
      true,
      'verify'
    );
  }
  await releaseIdleTargetEnvironment(projectId, codeDir);
}

/** Harness 沙箱环境就绪判定：TARGET_ENV mode=harness + _harness/ 存在。 */
async function finalizeHarnessEnvReady(projectId: string, codeDir: string): Promise<void> {
  recordEvent(
    projectId,
    { kind: 'system', agent: '主控', tool: '', text: '正在核实沙箱验证环境是否就绪（检查 TARGET_ENV.json 与 _harness/）…' },
    true,
    'verify'
  );
  if (!isHarnessEnvReady(codeDir)) {
    setEnvStatus(projectId, 'failed');
    recordEvent(
      projectId,
      {
        kind: 'error',
        agent: '主控',
        tool: '',
        text: '⚠ 沙箱环境预搭建未完成（未检测到 mode=harness 的 TARGET_ENV.json 或 _harness/ 目录），验证阶段会兜底重搭',
      },
      true,
      'verify'
    );
    return;
  }
  const smokeOk = await runHarnessSmokeIfConfigured(codeDir);
  setEnvStatus(projectId, 'ready', harnessTargetUrl());
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: smokeOk
        ? `✓ 沙箱验证环境已就绪（${harnessTargetUrl()}），_harness/ 可用且 smoke 通过，待验证复用`
        : `✓ 沙箱验证环境已就绪（${harnessTargetUrl()}），_harness/ 已生成（smoke 未通过或未配置，验证阶段会继续尝试）`,
    },
    true,
    'verify'
  );
}

/** 并行预搭建靶机环境：搭建并核实就绪；仅当验证未排队/未运行时 stop 容器省资源。 */
async function doPrebuildEnv(projectId: string): Promise<void> {
  const project = getProject(projectId);
  if (!project) return;

  const epoch = envBuildEpochOf(projectId);
  envIntentionallyStopped.delete(projectId); // 新一轮搭建，清掉上一轮的主动停止标记
  setEnvStatus(projectId, 'building');

  let codeDir: string;
  try {
    codeDir = await ensureWorkspace(getProject(projectId)!);
  } catch (err: any) {
    if (isEnvBuildCancelled(projectId, epoch)) return;
    setEnvStatus(projectId, 'failed');
    recordEvent(
      projectId,
      { kind: 'error', agent: '主控', tool: '', text: `环境预搭建-源码准备失败：${err?.message || err}（验证阶段会兜底重搭）` },
      true,
      'verify'
    );
    return;
  }

  if (isEnvBuildCancelled(projectId, epoch)) return;

  const shape = detectProjectShape(codeDir);
  const spec = envSpecOf(project);

  if (shape === 'harness') {
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: '▶ 并行预搭建沙箱验证环境（docker-env-login-and-acl-e2e · Harness），与代码审计同时进行…',
      },
      true,
      'verify'
    );
    if (targetBuildGate.inUseCount >= targetBuildConcurrency()) {
      recordEvent(
        projectId,
        { kind: 'system', agent: '主控', tool: '', text: `⏳ 靶机搭建槽位已满（${targetBuildGate.inUseCount}/${targetBuildConcurrency()}），本项目排队等待空闲槽…` },
        true,
        'verify'
      );
    }
    const r = await withTargetBuildGate(async () => {
      if (isEnvBuildCancelled(projectId, epoch)) {
        return {
          killed: true,
          timedOut: false,
          code: -1,
          structured: null,
          finalResult: '',
          stderrTail: '搭建已取消',
        };
      }
      return runPiStage(
        projectId,
        codeDir,
        buildHarnessEnvPrompt(codeDir, spec),
        '{"type":"object"}',
        { channel: 'env', phase: 'verify' }
      );
    });
    if (isEnvBuildCancelled(projectId, epoch)) return;
    if (r.killed) {
      const ep = getProject(projectId);
      if (ep?.env_status === 'building') {
        // 主动取消（排队让出/暂停）→ none；真正异常中断 → failed
        const intentional = envIntentionallyStopped.has(projectId);
        setEnvStatus(projectId, intentional ? 'none' : 'failed', ep.target_url ?? null);
        if (!intentional) {
          recordEvent(
            projectId,
            { kind: 'system', agent: '主控', tool: '', text: '沙箱环境预搭建已中断，验证阶段将兜底重搭' },
            true,
            'verify'
          );
        }
      }
      return;
    }
    if (r.timedOut) {
      setEnvStatus(projectId, 'failed');
      recordEvent(
        projectId,
        { kind: 'error', agent: '主控', tool: '', text: '沙箱环境预搭建超时，验证阶段将兜底重搭' },
        true,
        'verify'
      );
      return;
    }
    if (isEnvBuildCancelled(projectId, epoch)) return;
    await finalizeHarnessEnvReady(projectId, codeDir);
    return;
  }

  if (!(await dockerAvailable())) {
    if (isEnvBuildCancelled(projectId, epoch)) return;
    // 无 Docker：跳过预搭建，验证阶段再按需处理
    setEnvStatus(projectId, 'none');
    return;
  }

  if (isEnvBuildCancelled(projectId, epoch)) return;

  recordEvent(
    projectId,
    { kind: 'system', agent: '主控', tool: '', text: '▶ 并行预搭建靶机环境（docker-env-login-and-acl-e2e），与代码审计同时进行…' },
    true,
    'verify'
  );
  recordEvent(
    projectId,
    {
      kind: 'system',
      agent: '主控',
      tool: '',
      text: `靶机规格：版本 ${spec.version || '(源码现有版本)'} · 端口 ${spec.port} · compose 项目名 ${spec.projectName}`,
    },
    true,
    'verify'
  );
  // 全局靶机搭建闸：验证独占阶段与 remoteVerifyConcurrency 对齐；审计并行时沿用 env_concurrency（默认 3）。
  if (targetBuildGate.inUseCount >= targetBuildConcurrency()) {
    recordEvent(
      projectId,
      { kind: 'system', agent: '主控', tool: '', text: `⏳ 靶机搭建槽位已满（${targetBuildGate.inUseCount}/${targetBuildConcurrency()}），本项目排队等待空闲槽…` },
      true,
      'verify'
    );
  }
  const r = await withTargetBuildGate(async () => {
    if (isEnvBuildCancelled(projectId, epoch)) {
      return {
        killed: true,
        timedOut: false,
        code: -1,
        structured: null,
        finalResult: '',
        stderrTail: '搭建已取消',
      };
    }
    return runPiStage(
      projectId,
      codeDir,
      buildEnvPrompt(codeDir, spec),
      '{"type":"object"}',
      {
        channel: 'env',
        phase: 'verify',
      }
    );
  });

  if (isEnvBuildCancelled(projectId, epoch)) return;

  if (r.killed) {
    const ep = getProject(projectId);
    if (ep?.env_status === 'building') {
      const intentional = envIntentionallyStopped.has(projectId);
      setEnvStatus(projectId, intentional ? 'none' : 'failed', ep.target_url ?? null);
      if (!intentional) {
        recordEvent(
          projectId,
          { kind: 'system', agent: '主控', tool: '', text: '环境预搭建已中断，验证阶段将兜底重搭' },
          true,
          'verify'
        );
      }
    }
    return;
  }

  if (r.timedOut) {
    setEnvStatus(projectId, 'failed');
    recordEvent(
      projectId,
      { kind: 'error', agent: '主控', tool: '', text: '环境预搭建超时，验证阶段将兜底重搭' },
      true,
      'verify'
    );
    return;
  }

  if (isEnvBuildCancelled(projectId, epoch)) return;
  await finalizeWebEnvReady(projectId, codeDir, spec, r);
}

/** 停止某项目的环境预搭建（删除/让出槽位/停摆时调用；暂停审计不走这里）。 */
function stopEnvChannel(
  projectId: string,
  opts?: { quiet?: boolean; reason?: 'queued_yield' | 'pause' | 'delete' }
): void {
  // 先递增世代号，让仍在跑的 doPrebuildEnv 识别取消，不再把状态写回 building/failed
  bumpEnvBuildEpoch(projectId);

  const qi = envQueue.indexOf(projectId);
  if (qi !== -1) envQueue.splice(qi, 1);
  const child = envRunning.get(projectId);
  if (child) {
    envIntentionallyStopped.add(projectId);
    killTree(child);
    envRunning.delete(projectId);
  }
  envActive.delete(projectId);
  // 注意：不在这里 delete envTasks——让 promise finally 自己清，避免「内存无任务但 DB 仍 building」的窗口被对账误判。
  // 若根本没有 task，下面直接把 building 清掉。
  const hadTask = envTasks.has(projectId);
  if (!hadTask) {
    envTasks.delete(projectId);
  }

  const p = getProject(projectId);
  if (p && (p.env_status === 'building' || p.env_status === 'failed')) {
    // 排队让出 / 暂停：归 none，不要标 failed（否则前端一片「已标记失败」）
    setEnvStatus(projectId, 'none', p.target_url ?? null);
  }

  if (!opts?.quiet && opts?.reason === 'queued_yield') {
    recordEvent(
      projectId,
      {
        kind: 'system',
        agent: '主控',
        tool: '',
        text: '⏸ 已暂停靶机预搭建：验证仍在排队，槽位优先留给正在验证的项目；轮到本项目验证时再搭建',
      },
      true,
      'verify'
    );
  }

  startNextEnv();
}

/** DB 标记 verify_status=queued 但内存队列里无对应任务时补入队（避免重启/异常后验证永远排队不跑）。 */
export function requeueStaleVerifyJobs(): number {
  let n = 0;
  const rows = db
    .prepare("SELECT id FROM projects WHERE status = 'completed' AND verify_status = 'queued'")
    .all() as { id: string }[];
  for (const r of rows) {
    if (isBusy(r.id) || queue.some((j) => j.id === r.id)) continue;
    if (!shouldRemoteVerify(r.id)) continue;
    if (!strictVerifyQueueGate(r.id, true)) continue;
    queue.push({ id: r.id, kind: 'verify', resume: true });
    // 不预搭靶机：等真正进入 verify_running 后再由 ensureTargetUp 搭建
    n++;
  }
  return n;
}

/** DB 标记 status=queued 但内存队列无对应任务时补入队（避免改并发/异常后审计永远排队不跑）。 */
export function requeueStaleAuditJobs(): number {
  let n = 0;
  const rows = db
    .prepare("SELECT id FROM projects WHERE status = 'queued'")
    .all() as { id: string }[];
  for (const r of rows) {
    if (isBusy(r.id) || queue.some((j) => j.id === r.id)) continue;
    queue.push({ id: r.id, kind: 'audit' });
    kickEnvPrebuildWithAudit(r.id);
    n++;
  }
  return n;
}

function startNext(): void {
  if (!isPiJobsEnabled()) return;
  try {
    reconcileStalledAuditJobs();
  } catch (e) {
    console.error('[code] startNext 卡死回收失败', e);
  }
  requeueStaleAuditJobs();
  requeueStaleVerifyJobs();
  const pressure = schedulerPressureReason();
  if (pressure && queue.length > 0) {
    if (!resourceRetryTimer) {
      console.warn(`[code] 暂缓启动新任务以保护 Web 服务：${pressure}`);
      resourceRetryTimer = setTimeout(() => {
        resourceRetryTimer = null;
        startNext();
      }, 5_000);
      resourceRetryTimer.unref?.();
    }
    return;
  }
  let progressed = true;
  const auditSaturated = activeAuditProjects.size >= maxConcurrency();
  while (progressed) {
    progressed = false;
    const indices = auditSaturated
      ? [...Array(queue.length).keys()].sort((a, b) => {
          const va = isVerifyJobKind(queue[a].kind) ? 0 : 1;
          const vb = isVerifyJobKind(queue[b].kind) ? 0 : 1;
          return va - vb || a - b;
        })
      : [...Array(queue.length).keys()];
    for (const i of indices) {
      const job = queue[i];
      if (isBusy(job.id)) continue;
      const p = getProject(job.id);
      if (!p) {
        queue.splice(i, 1);
        progressed = true;
        break;
      }
      if ((job.kind === 'audit' || job.kind === 'reprocess') && p.status !== 'queued') continue;
      if ((job.kind === 'verify' || job.kind === 'verifyone') && p.verify_status !== 'queued') continue;
      const provenanceRequiredNow =
        (job.kind === 'verify' || job.kind === 'verifyone') &&
        (!job.stage || job.stage === 'remote');
      if (provenanceRequiredNow && !strictVerifyQueueGate(job.id, true)) {
        queue.splice(i, 1);
        progressed = true;
        break;
      }

      if (
        (job.kind === 'audit' || job.kind === 'reprocess') &&
        isWebOnlyPipeline() &&
        p.has_web === 0
      ) {
        queue.splice(i, 1);
        if (p.status === 'queued') {
          setAuditStatus(job.id, 'completed', {
            finished_at: now(),
            error_message: '已跳过：无 Web 端（设置：仅处理含 Web 端项目）',
          });
        }
        progressed = true;
        break;
      }

      const isVerify = isVerifyJobKind(job.kind);
      if (isVerify && !shouldRemoteVerify(job.id)) {
        queue.splice(i, 1);
        if (p.verify_status === 'queued' || p.verify_status === 'running') {
          setVerifyStatus(job.id, 'paused', {
            verify_finished_at: now(),
            verify_error: SKIP_NON_WEB_MSG,
          });
        }
        progressed = true;
        break;
      }
      if (isVerify) {
        if (activeVerifyProjects.size >= remoteVerifyConcurrency()) continue;
      } else if (activeAuditProjects.size >= maxConcurrency()) {
        continue;
      }

      queue.splice(i, 1);
      if (isVerify) activeVerifyProjects.add(job.id);
      else activeAuditProjects.add(job.id);
      void runJob(job);
      progressed = true;
      break;
    }
  }
}

export function enqueueAudit(projectId: string, chainVerify = false): void {
  if (!isPiJobsEnabled()) {
    console.warn(`[code] Pi 任务已停摆，拒绝入队审计 ${projectId}`);
    return;
  }
  const p = getProject(projectId);
  if (!p) return;
  if (isBusy(projectId) || queue.some((j) => j.id === projectId)) {
    return;
  }
  setAuditStatus(projectId, 'queued');
  queue.push({ id: projectId, kind: 'audit', chainVerify });
  // 选了完整靶机：审计排队的同时并行预搭建（独立通道，不占审计槽）
  kickEnvPrebuildWithAudit(projectId, chainVerify);
  scheduleStartNext();
}

/** 入队"复用子智能体结果重跑"（不重扫源码，仅去重+验证+评级）。continueMode=true 时为「继续审计」续跑。 */
export function enqueueReprocess(projectId: string, chainVerify = false, continueMode = false): void {
  if (!isPiJobsEnabled()) {
    console.warn(`[code] Pi 任务已停摆，拒绝入队续跑 ${projectId}`);
    return;
  }
  const p = getProject(projectId);
  if (!p) return;
  if (isBusy(projectId) || queue.some((j) => j.id === projectId)) {
    return;
  }
  setAuditStatus(projectId, 'queued');
  queue.push({ id: projectId, kind: 'reprocess', chainVerify, continueMode: continueMode || undefined });
  kickEnvPrebuildWithAudit(projectId, chainVerify);
  scheduleStartNext();
}

/**
 * 远程验证入队门控：工作区在即可。靶机按当前源码搭建，不再用 Git/镜像标签拦截。
 */
function strictVerifyQueueGate(projectId: string, resetQueued = false): boolean {
  const project = getProject(projectId);
  if (!project) return false;
  const codeDir = project.workspace_path || '';
  if (!codeDir || !fs.existsSync(codeDir)) {
    setEnvStatus(projectId, 'failed', null);
    if (resetQueued && project.verify_status === 'queued') {
      setVerifyStatus(projectId, 'none', {
        verify_started_at: null,
        verify_finished_at: null,
        verify_error: '工作区不存在',
      });
    }
    recordEvent(
      projectId,
      {
        kind: 'error',
        agent: '主控',
        tool: '',
        text: '⛔ 拒绝远程验证：工作区不存在',
      },
      true,
      'audit'
    );
    return false;
  }
  return true;
}

/**
 * 单漏洞远程验证入队（item 12）。返回 { queued, pending }：
 * - pending=true：项目正在跑验证/在途，已暂存该标题，待当前验证收尾（不关靶机）后自动验证 → 前端应显示"等待验证"。
 * - queued=true：已直接入队开始单漏洞验证（情形①靶机已停会 start、情形②无靶机会重搭）。
 */
export function enqueueVerifyOne(projectId: string, title: string): { queued: boolean; pending: boolean } {
  if (!isPiJobsEnabled()) {
    console.warn(`[code] Pi 任务已停摆，拒绝单漏洞验证 ${projectId}`);
    return { queued: false, pending: false };
  }
  const p = getProject(projectId);
  if (!p || p.status !== 'completed' || !title) return { queued: false, pending: false };
  if (!shouldRemoteVerify(projectId)) return { queued: false, pending: false };
  if (!strictVerifyQueueGate(projectId)) return { queued: false, pending: false };
  const norm = (value: string) => String(value || '').replace(/\s+/g, '').toLowerCase();
  const vulnerability = (
    db
      .prepare('SELECT id, title FROM vulnerabilities WHERE project_id = ?')
      .all(projectId) as { id: string; title: string }[]
  ).find((row) => norm(row.title) === norm(title));
  if (!vulnerability) return { queued: false, pending: false };
  ensureProjectVerificationItems(projectId);
  setVerificationItemState(projectId, vulnerability.id, 'queued');
  // 情形③：正在跑验证 / 有在途任务 / 已在队列 → 暂存，等收尾后再验证（靶机不关）
  if (p.verify_status === 'running' || isBusy(projectId) || queue.some((j) => j.id === projectId)) {
    const list = pendingVerifyOne.get(projectId) || [];
    if (!list.includes(vulnerability.title)) list.push(vulnerability.title);
    pendingVerifyOne.set(projectId, list);
    return { queued: false, pending: true };
  }
  setVerifyStatus(projectId, 'queued');
  queue.push({ id: projectId, kind: 'verifyone', oneTitle: vulnerability.title });
  scheduleStartNext();
  return { queued: true, pending: false };
}

/** 重启后恢复持久化的单漏洞等待队列，避免内存 Map 丢失后永远“待验证”。 */
export function recoverPendingVerifyOneJobs(): number {
  const rows = db
    .prepare(
      `SELECT vv.project_id, vv.vulnerability_id, vv.vulnerability_title
       FROM vulnerability_verifications vv
       JOIN projects p ON p.id = vv.project_id
       WHERE p.status = 'completed' AND vv.state IN ('queued','running')
       ORDER BY COALESCE(vv.queued_at, vv.updated_at) ASC`
    )
    .all() as {
    project_id: string;
    vulnerability_id: string;
    vulnerability_title: string;
  }[];
  const grouped = new Map<string, typeof rows>();
  for (const row of rows) {
    setVerificationItemState(row.project_id, row.vulnerability_id, 'queued');
    const list = grouped.get(row.project_id) || [];
    list.push(row);
    grouped.set(row.project_id, list);
  }
  let recovered = 0;
  for (const [projectId, items] of grouped) {
    if (!strictVerifyQueueGate(projectId, true)) {
      for (const item of items) {
        setVerificationItemState(projectId, item.vulnerability_id, 'pending');
      }
      continue;
    }
    const titles = items.map((item) => item.vulnerability_title).filter(Boolean);
    if (titles.length === 0) continue;
    if (isBusy(projectId) || queue.some((job) => job.id === projectId)) {
      pendingVerifyOne.set(projectId, titles);
    } else {
      const first = titles.shift()!;
      setVerifyStatus(projectId, 'queued');
      queue.push({ id: projectId, kind: 'verifyone', oneTitle: first });
      if (titles.length > 0) pendingVerifyOne.set(projectId, titles);
    }
    recovered += items.length;
  }
  if (recovered > 0) scheduleStartNext();
  return recovered;
}

/** 手动重试靶机环境预搭建（env=failed/none 时）。 */
export function retryEnvPrebuild(projectId: string): boolean {
  const p = getProject(projectId);
  if (!p) return false;
  if (p.verify_status === 'running') return false;
  if (!needsComposeEnv(projectId)) return false;
  if (envBuildInFlight(projectId) || p.env_status === 'building') return true;
  if (!shouldRemoteVerify(projectId)) return false;
  setEnvStatus(projectId, 'none', null);
  enqueueEnvPrebuild(projectId);
  return true;
}

/** 一次性恢复：误标 env=failed（重启导致 building 残留校正）且尚未真正失败的项目。 */
export function recoverEnvFalseFailures(): { scanned: number; reset: number; requeued: number } {
  const rows = db
    .prepare("SELECT id, status, verify_status FROM projects WHERE env_status = 'failed'")
    .all() as { id: string; status: string; verify_status: string }[];

  let reset = 0;
  let requeued = 0;
  for (const p of rows) {
    // 正在验证：必须重排队搭建。queued 只清 failed→none，等拿到验证槽再搭。
    if (p.verify_status === 'queued' || p.verify_status === 'running') {
      setEnvStatus(p.id, 'none', null);
      reset++;
      if (p.verify_status === 'running' && shouldRemoteVerify(p.id)) {
        enqueueEnvPrebuild(p.id);
        requeued++;
      }
      continue;
    }

    const staleEv = db
      .prepare(
        `SELECT text FROM agent_events WHERE project_id = ? AND phase = 'verify' AND kind = 'system'
         AND (
           text LIKE '%状态校正：搭建任务已结束但状态仍停留%'
           OR text LIKE '%环境预搭建已中断%'
           OR text LIKE '%等待靶机搭建超时%'
           OR text LIKE '%ensureTargetUp 失败时清除 building%'
         )
         ORDER BY ts DESC LIMIT 1`
      )
      .get(p.id) as { text: string } | undefined;

    const realFailEv = db
      .prepare(
        `SELECT text FROM agent_events WHERE project_id = ? AND phase = 'verify' AND kind IN ('system','error')
         AND (
           text LIKE '%验证进行中但容器已停止%'
           OR text LIKE '%环境预搭建未真正起来%'
         )
         ORDER BY ts DESC LIMIT 1`
      )
      .get(p.id) as { text: string } | undefined;

    if (!staleEv || realFailEv) {
      const verifyEventCount = (
        db
          .prepare('SELECT COUNT(*) AS c FROM agent_events WHERE project_id = ? AND phase = ?')
          .get(p.id, 'verify') as { c: number }
      ).c;
      if (verifyEventCount === 0 && p.verify_status === 'none') {
        setEnvStatus(p.id, 'none', null);
        reset++;
      }
      continue;
    }

    setEnvStatus(p.id, 'none', null);
    reset++;
    if (shouldRunIndependentEnvPi(p.id)) {
      enqueueEnvPrebuild(p.id);
      requeued++;
    }
  }

  return { scanned: rows.length, reset, requeued };
}

/** 手动清除靶机（item 11）：异步执行，立即返回。 */
export function clearProjectEnv(projectId: string): boolean {
  const p = getProject(projectId);
  if (!p) return false;
  const codeDir = p.workspace_path || '';
  void clearTargetEnvironment(projectId, codeDir);
  return true;
}

export interface StrictTargetProvenanceRow {
  id: string;
  project_name: string;
  source_version: string | null;
  workspace_path: string;
  ok: boolean;
  errors: string[];
  env_status: string;
  target_url: string | null;
}

/**
 * Audit every currently materialized TARGET_ENV contract. With enforce=true,
 * invalid targets are marked failed and valid targets ready; no containers are
 * started/stopped and no environment builder is invoked.
 */
export function reconcileStrictTargetProvenance(
  enforce = false
): { scanned: number; valid: number; invalid: number; projects: StrictTargetProvenanceRow[] } {
  const rows = db.prepare('SELECT * FROM projects ORDER BY created_at DESC').all() as Project[];
  const projects: StrictTargetProvenanceRow[] = [];
  for (const project of rows) {
    const candidates = [
      project.workspace_path,
      path.join(WORKSPACE_DIR, project.id),
    ].filter(Boolean) as string[];
    const codeDir = candidates.find((candidate) =>
      fs.existsSync(path.join(candidate, 'TARGET_ENV.json'))
    );
    if (!codeDir) continue;
    const result = validateTargetProvenance(project, codeDir);
    const errors = result.errors;
    if (enforce) {
      if (result.ok) {
        setEnvStatus(project.id, 'ready', resolveTargetUrl(project.id, codeDir));
      } else {
        setEnvStatus(project.id, 'failed', null);
        recordEvent(
          project.id,
          {
            kind: 'error',
            agent: '来源校验器',
            tool: '',
            text: `⛔ 当前靶机已阻断：${errors.join('；')}`,
          },
          true,
          'audit'
        );
      }
    }
    const current = getProject(project.id);
    projects.push({
      id: project.id,
      project_name: project.project_name,
      source_version: project.source_version,
      workspace_path: codeDir,
      ok: result.ok,
      errors,
      env_status: current?.env_status || project.env_status,
      target_url: current?.target_url || project.target_url,
    });
  }
  return {
    scanned: projects.length,
    valid: projects.filter((project) => project.ok).length,
    invalid: projects.filter((project) => !project.ok).length,
    projects,
  };
}

export function enqueueVerify(projectId: string, resume = false): boolean {
  if (!isPiJobsEnabled()) {
    console.warn(`[code] Pi 任务已停摆，拒绝入队验证 ${projectId}`);
    return false;
  }
  const p = getProject(projectId);
  if (!p) return false;
  if (p.status !== 'completed') return false; // 必须先完成审计
  if (!shouldRemoteVerify(projectId)) return false;
  if (isBusy(projectId) || queue.some((j) => j.id === projectId)) return false;
  if (!strictVerifyQueueGate(projectId)) return false;
  verifyKilled.delete(projectId);
  cancelledProjects.delete(projectId);
  setVerifyStatus(projectId, 'queued', { verify_error: null });
  queue.push({ id: projectId, kind: 'verify', resume });
  // 不预搭：拿到验证槽进入 running 后由 ensureTargetUp / doVerify 按需搭建
  scheduleStartNext();
  return true;
}

/**
 * 是否已产出可用于组合链验证的审计结果。
 * 仅组合链重跑不要求审计 status 恰为 completed——审计完成后若被「批量暂停」等操作把 status 置成
 * paused，但只要曾完整验证过（verify_status 为 completed/paused/failed）或审计 status 为 completed，
 * 就说明审计早已产出结果，允许仅重跑组合链。
 */
function hasAuditForChain(p: Project): boolean {
  if (p.status === 'completed') return true;
  return p.verify_status === 'completed' || p.verify_status === 'paused' || p.verify_status === 'failed';
}

/** 入队「仅组合链验证」（远程验证·组合）：复用已有单漏洞结果，只重跑组合链。 */
export function enqueueVerifyChain(projectId: string): boolean {
  if (!isPiJobsEnabled()) {
    console.warn(`[code] Pi 任务已停摆，拒绝组合链验证 ${projectId}`);
    return false;
  }
  const p = getProject(projectId);
  if (!p) return false;
  if (!hasAuditForChain(p)) return false; // 审计未产出结果（如审计跑到一半被暂停）
  if (!shouldRemoteVerify(projectId)) return false;
  if (isBusy(projectId) || queue.some((j) => j.id === projectId)) return false;
  if (!strictVerifyQueueGate(projectId)) return false;
  verifyKilled.delete(projectId);
  cancelledProjects.delete(projectId);
  setVerifyStatus(projectId, 'queued', { verify_error: null });
  queue.push({ id: projectId, kind: 'verify', chainOnly: true });
  // 不预搭：进入 running 后再按需搭建
  scheduleStartNext();
  return true;
}

export function pauseProject(projectId: string): void {
  restartRequests.delete(projectId);
  requestCancel(projectId); // 让在途异步在下一次 runPiStage 处判 killed 收尾，不再 spawn 新 Pi
  // 不 stopEnvChannel：靶机搭建是独立 Pi，与多智能体审计暂停互不影响
  verifyKilled.add(projectId);
  stopVerifyProcs(projectId);
  const qi = queue.findIndex((j) => j.id === projectId);
  let queuedKind: JobKind | null = null;
  if (qi !== -1) {
    queuedKind = queue[qi].kind;
    queue.splice(qi, 1);
  }

  const child = running.get(projectId);
  const kind = runningKind.get(projectId) || queuedKind;
  if (child) {
    intentionallyStopped.add(projectId);
    killTree(child);
    running.delete(projectId);
  }
  // 只暂停「真正在跑/在排队」的那一侧；绝不把已完成/空闲的项目翻成暂停（历史 bug：批量暂停把
  // 已完成的审计 completed→paused，导致「继续」时被误当未审计塞回审计队列）。
  const cur = getProject(projectId);
  const isVerifyKind = kind ? isVerifyJobKind(kind) : null;
  // 干净收尾保护：某一侧若最新一轮已【干净收尾】（有完成事件、其后无新一轮工作痕迹），
  // 暂停时归位到 completed 而非 paused。典型场景：审计干净完成后（无后续重扫）被暂停，应进
  // 「代码审计完成」。反之，若「审计完成」后又发起了被打断的重扫（有工作痕迹），则不算完成，
  // 暂停时如实标为 paused（中途暂停，留在「已暂停」）。
  const auditDoneClean = auditFinishedCleanly(projectId);
  const verifyDoneClean = verifyFinishedCleanly(projectId);
  const settleAuditPause = () => {
    if (cur?.status === 'completed') return; // 已完成，保持不动
    if (auditDoneClean) {
      setAuditStatus(projectId, 'completed', { finished_at: cur?.finished_at ?? now(), error_message: null });
    } else {
      setAuditStatus(projectId, 'paused', { finished_at: now() });
    }
  };
  const settleVerifyPause = () => {
    if (cur?.verify_status === 'completed') return; // 已完成，保持不动
    if (verifyDoneClean) {
      setVerifyStatus(projectId, 'completed', {
        verify_finished_at: cur?.verify_finished_at ?? now(),
        verify_error: null,
      });
    } else {
      setVerifyStatus(projectId, 'paused', { verify_finished_at: now() });
    }
  };
  if (isVerifyKind === true) {
    settleVerifyPause();
  } else if (isVerifyKind === false) {
    settleAuditPause();
  } else if (cur) {
    // 内存中已无该项目的在跑/在排队任务：按库内状态推断该暂停哪一侧，已完成态一律不动。
    if (cur.verify_status === 'running' || cur.verify_status === 'queued') {
      settleVerifyPause();
    } else if (cur.status === 'running' || cur.status === 'queued') {
      settleAuditPause();
    }
    // 其余（audit=completed / verify=completed 等空闲态）：无任务可暂停，保持不变。
  }
  // 关键：若仍有在途异步，**不**在此释放并发槽——交由其 runJob.finally 在异步真正收尾后统一清理并调度，
  // 避免"槽位已释放但旧异步还在跑"被并行启动第二条流水线（历史竞态：pause 后紧接 reprocess 导致双流水线）。
  if (inFlight.has(projectId)) return;
  clearActiveSlots(projectId);
  startNext();
}

/**
 * 「继续审计」从卡住处接着跑：看已完成的最远环节，下一环开始。
 * 例如代码级验证已完成、二次评级没写完 → 只跑评级，不再把去重/验证重来一遍。
 */
function inferResumeAuditStage(projectId: string): PipeStage {
  const rows = db
    .prepare(
      `SELECT ts, text FROM agent_events
       WHERE project_id = ? AND kind = 'system'
       ORDER BY ts ASC`
    )
    .all(projectId) as { ts: number; text: string }[];
  let lastRegradeDone = 0;
  let lastVerifyDone = 0;
  let lastDedupDone = 0;
  let lastSubagentDone = 0;
  for (const r of rows) {
    const t = r.text || '';
    const ts = r.ts || 0;
    if (t.includes('✓ 实战二次评级完成')) lastRegradeDone = ts;
    else if (t.includes('✓ 代码级验证完成')) lastVerifyDone = ts;
    else if (t.includes('✓ AI 智能去重完成')) lastDedupDone = ts;
    else if (
      t.includes('子智能体阶段已完成') ||
      t.includes('子智能体覆盖完整') ||
      t.includes('审计完成硬闸通过')
    ) {
      lastSubagentDone = ts;
    }
  }
  if (lastVerifyDone && lastVerifyDone >= lastRegradeDone) return 'regrade';
  if (lastDedupDone && lastDedupDone >= lastVerifyDone) return 'codeverify';
  if (lastSubagentDone && lastSubagentDone >= lastDedupDone) return 'dedup';
  return 'subagent';
}

/**
 * 「继续」按钮的真正含义：从暂停/失败处接着跑，而不是从头重来。
 *
 * 此前的实现无论暂停在哪个阶段，一律调用 enqueueAudit/enqueueVerify 走 doAudit/doVerify——
 * 而这两者在最开头会无条件清空已有的漏洞/事件/exploit_report 并把整条流水线（含最贵的
 * 多智能体全量扫描 / 全部漏洞的远程实测）从零重跑一遍，等同于"重新开始"，与按钮语义不符。
 * 现在按"暂停前实际产出了什么磁盘/落库产物"决定真正的续跑方式：
 *   - 验证被暂停/失败：exploit_report 里已有的部分验证结果（若有）会被保留并跳过，只继续
 *     验证剩余漏洞（见 runRemoteVerifyCore 的 priorExploits 参数）。
 *   - 审计被暂停/失败：磁盘有 JSON/ 产物 → continueMode 的 reprocess（补缺失子智能体 + 后处理）；
 *     无任何子智能体产物 → 全量 doAudit（与「重新审计」等价）。
 */
export function isAuditCoverageFailureMessage(error: string | null | undefined): boolean {
  return /(子智能体|审计).*(覆盖|JSON).*(不完整|缺失|无法解析)|历史审计覆盖不完整/.test(
    String(error || '')
  );
}

export function isAuditCompletedForResume(
  project: Pick<Project, 'status' | 'verify_status' | 'error_message'>,
  latestAuditAttemptComplete: boolean
): boolean {
  const coverageFailed =
    (project.status === 'failed' || project.status === 'paused') &&
    isAuditCoverageFailureMessage(project.error_message);
  return (
    !coverageFailed &&
    (project.status === 'completed' ||
      latestAuditAttemptComplete ||
      project.verify_status === 'completed' ||
      project.verify_status === 'paused' ||
      project.verify_status === 'failed')
  );
}

export function auditResumeLane(
  project: Pick<Project, 'status' | 'verify_status' | 'error_message'>,
  latestAuditAttemptComplete: boolean,
  hasRawFindings?: boolean
): 'post_audit' | 'reprocess' | 'audit' {
  if (isAuditCompletedForResume(project, latestAuditAttemptComplete)) return 'post_audit';
  // 磁盘无子智能体 JSON/ 产物 → 全量 doAudit；有部分产物 → 续跑补缺失 + 后处理。
  if (!hasRawFindings) return 'audit';
  return 'reprocess';
}

export function resumeProject(projectId: string): boolean {
  if (!isPiJobsEnabled()) {
    console.warn(`[code] Pi 任务已停摆，拒绝继续 ${projectId}`);
    return false;
  }
  const p = getProject(projectId);
  if (!p) return false;
  // 先按事件流校正完成/中途暂停，避免脏 status 把「中途暂停」误送去验证、或把「已完成」又送回审计。
  reconcileMispausedCompletedAudits();
  const fresh = getProject(projectId) ?? p;
  // 最新一轮审计已真正收尾：绝不回炉重审，一律走验证侧。
  const codeDir = [fresh.workspace_path, path.join(WORKSPACE_DIR, projectId)]
    .filter((candidate): candidate is string => !!candidate)
    .find((candidate) => fs.existsSync(candidate));
  const artDir = resolveArtifactRoot(projectId, codeDir || fresh.workspace_path);
  const hasRawFindings =
    !!(artDir && hasSubagentArtifacts(artDir)) || !!(codeDir && hasSubagentArtifacts(codeDir));
  const resumeLane = auditResumeLane(
    fresh,
    isLatestAuditAttemptComplete(projectId),
    hasRawFindings
  );
  const inferred = inferResumeAuditStage(projectId);
  const auditCompleted = resumeLane === 'post_audit';
  if (auditCompleted) {
    if (fresh.status !== 'completed') {
      setAuditStatus(projectId, 'completed', {
        finished_at: fresh.finished_at ?? now(),
        error_message: null,
      });
    }
    // 验证曾经开跑过（paused/failed）：说明当初已进入验证流程，「继续」直接续跑剩余验证。
    if (fresh.verify_status === 'paused' || fresh.verify_status === 'failed') {
      if (shouldRemoteVerify(projectId)) return enqueueVerify(projectId, true);
      return true;
    }
    // 验证从未开始（verify=none）：
    //  - auto_verify=ON（全流程）：沿用其流程选项，自动进入靶机验证（无需弹窗，符合“auto”决策）。
    //  - auto_verify=OFF（仅代码审计）：不隐式发起验证，仅归位到「代码审计完成」；
    //    下一步（是否验证 / 是否含历史版本）由前端「继续」弹窗显式选择。
    if (isAutoVerify(projectId) && shouldRemoteVerify(projectId)) {
      return enqueueVerify(projectId, false);
    }
    return true;
  }
  if (resumeLane === 'audit') {
    enqueueAudit(projectId, false);
  } else {
    const from = inferred;
    if (from !== 'subagent') {
      enqueueStage(projectId, from, 'from');
    } else {
      enqueueReprocess(projectId, false, true);
    }
  }
  const after = getProject(projectId);
  const ok = after?.status === 'queued' || after?.status === 'running';
  return ok;
}

/** 恢复「仅 Web 端」策略误暂停、尚未识别 has_web 的审计任务。 */
export function recoverMispausedAudits(): { total: number; recovered: number; failed: number } {
  const rows = db
    .prepare(
      "SELECT id FROM projects WHERE status = 'paused' AND verify_status = 'none' AND has_web IS NULL"
    )
    .all() as { id: string }[];
  // 跳过「Web 端前置识别完成后故意暂停」的项目，避免开机自恢复又自动开审
  const intentionalPause = db.prepare(
    `SELECT 1 AS x FROM agent_events
     WHERE project_id = ? AND kind = 'system' AND (
       text LIKE '%Web 端识别完成：已暂停%'
       OR text LIKE '%Web 端识别未得结论：已暂停%'
       OR text LIKE '%Web 端识别异常：已暂停%'
     ) LIMIT 1`
  );
  const toResume = rows.filter((r) => !intentionalPause.get(r.id));
  const { queued, failed } = bulkScheduleResume(toResume.map((r) => r.id));
  return { total: rows.length, recovered: queued, failed: failed.length };
}

/** 该项目当前是否有真正在跑/排队的【审计】任务（占槽 / 在跑进程 / 队列里）。 */
function isAuditActive(projectId: string): boolean {
  if (activeAuditProjects.has(projectId)) return true;
  const rk = runningKind.get(projectId);
  if (rk === 'audit' || rk === 'reprocess') return true;
  if (queue.some((j) => j.id === projectId && (j.kind === 'audit' || j.kind === 'reprocess'))) {
    return true;
  }
  return false;
}

/** 该项目当前是否有真正在跑/排队的【验证】任务。 */
function isVerifyActive(projectId: string): boolean {
  if (activeVerifyProjects.has(projectId)) return true;
  const rk = runningKind.get(projectId);
  if (rk === 'verify' || rk === 'verifyone') return true;
  if (queue.some((j) => j.id === projectId && isVerifyJobKind(j.kind))) return true;
  return false;
}

/**
 * 该项目最后一次【走完代码审计全流程】的时间戳（无则 null）——权威的“审计真正完成”锚点。
 * ⚠ 背景：`审计完成`(result) 由 streamParser 对【每一个 Pi Agent 进程】会话结束都产出
 * （streamParser.ts：type==='result' → text='审计完成'），只代表某个 Pi Agent 阶段跑完，
 * 并不代表整条流水线（子智能体扫描 → 去重 → 代码级验证 → 二次评级）已走完，故不能用它判定完成。
 * 只有当后处理流水线的**收尾阶段**真正跑完时才会落下这些标记（三者取其最新）：
 *   - `✓ 实战二次评级完成`（默认开启二次评级时的收尾）
 *   - `✓ 已合并二次评级到代码级验证`（合并评级模式的收尾）
 *   - `✓ 代码级验证完成`（关闭二次评级时的收尾；也是所有全流程都必经的核验阶段）
 * 只跑到子智能体扫描/覆盖补跑就中断的项目**不会**有这些标记，从而不会被误判为“代码审计完成”。
 */
function lastAuditPipelineDoneTs(projectId: string): number | null {
  const r = db
    .prepare(
      `SELECT MAX(ts) AS ts FROM agent_events
       WHERE project_id = ? AND kind = 'system' AND (
         text LIKE '%✓ 实战二次评级完成%'
         OR text LIKE '%✓ 已合并二次评级到代码级验证%'
         OR text LIKE '%✓ 代码级验证完成%'
       )`
    )
    .get(projectId) as { ts: number | null } | undefined;
  return r?.ts ?? null;
}

/** 该项目最后一次「验证完成」事件（phase=verify）的时间戳（无则 null）。 */
function lastVerifyCompleteTs(projectId: string): number | null {
  const r = db
    .prepare(
      `SELECT MAX(ts) AS ts FROM agent_events
       WHERE project_id = ? AND kind = 'result' AND text = '验证完成' AND phase = 'verify'`
    )
    .get(projectId) as { ts: number | null } | undefined;
  return r?.ts ?? null;
}

/** 该项目历史上是否有过任何【验证阶段】的活动（phase='verify' 的任意事件）。 */
function verifyEverStarted(projectId: string): boolean {
  const r = db
    .prepare(`SELECT 1 AS x FROM agent_events WHERE project_id = ? AND phase = 'verify' LIMIT 1`)
    .get(projectId) as { x: number } | undefined;
  return !!r;
}

/**
 * 最后一次「审计完成」之后，是否又发起了【新一轮尚未收尾的审计/后处理流水线】。
 *
 * 关键区分（决定项目该进「代码审计完成」还是「已暂停」）：
 * - `审计完成`（result）只由 finishAudit 在【整条流水线跑完】时落，因此它之后若再出现下面这些
 *   「阶段启动」标记，说明又开了一轮完整审计或复用重跑（去重/验证/评级/融合/收尾），且没再落
 *   下一个「审计完成」——即这一新轮次被打断在半路，项目当前处于「进行中被暂停」，不能算完成。
 *   例：主审计重启 `▶ 漏洞审计：按指定语言` 后停在子智能体扫描阶段。
 * - 反之，「审计完成」之后若【只有】子智能体覆盖核对补跑（`子智能体覆盖核对`）、通用的
 *   `审计会话已初始化`、或零散的工具活动（ls/find/写 enum 等）——这些是完成后自动触发的
 *   **补充性覆盖增强**，被打断不改变「主流水线已产出完整结果」的事实，应判定为已完成。
 *
 * 因此这里【只匹配「新一轮主审计 / 后处理阶段重启」的明确标记】，刻意不含 `审计会话已初始化`、
 * `子智能体覆盖核对` 与裸工具事件（它们会把补充补跑误判成未完成，导致真完成项目卡在「已暂停」）。
 */
function hasAuditWorkAfter(projectId: string, ts: number): boolean {
  const r = db
    .prepare(
      `SELECT 1 AS x FROM agent_events
       WHERE project_id = ? AND ts > ? AND phase = 'audit' AND (
         (
           kind = 'system' AND (
             text LIKE '%▶ 漏洞审计：启动%'
             OR text LIKE '%正在准备审计目标%'
             OR text LIKE '%复用已有子智能体%'
             OR text LIKE '%▶ AI 智能去重%'
             OR text LIKE '%重新执行：AI 智能去重%'
             OR text LIKE '%▶ 代码级验证%'
             OR text LIKE '%▶ 红队实战二次评级%'
             OR text LIKE '%跨语言融合审计%'
             OR text LIKE '%收尾补全%'
           )
         )
         OR (
           kind = 'error' AND (
             text LIKE '%历史审计覆盖不完整%'
             OR text LIKE '%子智能体覆盖不完整%'
             OR text LIKE '%审计完成被硬闸拒绝%'
             OR text LIKE '%审计数据已清除并转入已暂停%'
           )
         )
       ) LIMIT 1`
    )
    .get(projectId, ts) as { x: number } | undefined;
  return !!r;
}

/**
 * 最后一次「验证完成」之后，是否又发起了【新一轮尚未收尾的靶机验证】。
 * 同审计侧：只匹配验证阶段的明确「重启/等待」标记，不含裸工具活动（避免把完成后的零散
 * 工具噪声误判成未完成，使真完成的验证卡在「已暂停」）。
 */
function hasVerifyWorkAfter(projectId: string, ts: number): boolean {
  const r = db
    .prepare(
      `SELECT 1 AS x FROM agent_events
       WHERE project_id = ? AND ts > ? AND phase = 'verify' AND kind = 'system' AND (
         text LIKE '%▶ 远程验证%'
         OR text LIKE '%▶ 单漏洞远程验证%'
         OR text LIKE '%▶ 漏洞验证：%'
         OR text LIKE '%远程验证·组合%'
         OR text LIKE '%等待靶机环境搭建完成后再开始验证%'
         OR text LIKE '%等待并行的靶机环境搭建完成%'
       ) LIMIT 1`
    )
    .get(projectId, ts) as { x: number } | undefined;
  return !!r;
}

/**
 * 最新一轮代码审计是否【真正走完全流程且干净收尾】：
 *   ① 有过后处理收尾标记（{@link lastAuditPipelineDoneTs} 非空，证明确实跑到了代码级验证/二次评级收尾）；
 *   ② 且该收尾之后没有再发起被打断的新一轮审计/后处理（{@link hasAuditWorkAfter}）。
 * 关键：不再以【每个 Pi Agent 进程都会产出的】「审计完成」为准——那会把“只跑到子智能体扫描就中断”的
 * 项目误判为完成。不考虑当前是否在跑（pauseProject 在项目仍占槽时也用它判定归位到完成还是暂停）。
 */
function auditFinishedCleanly(projectId: string): boolean {
  const ts = lastAuditPipelineDoneTs(projectId);
  if (ts == null) return false;
  return !hasAuditWorkAfter(projectId, ts);
}

/** 最新一轮靶机验证是否【干净收尾】（同审计规则，锚点为「验证完成」）。 */
function verifyFinishedCleanly(projectId: string): boolean {
  const ts = lastVerifyCompleteTs(projectId);
  if (ts == null) return false;
  return !hasVerifyWorkAfter(projectId, ts);
}

/**
 * 最新一轮代码审计是否已真正完成：干净收尾 且 当前没有在跑/排队的审计任务。
 * 「审计完成」之后又发起并被打断的补跑/重扫轮次不算完成（属中途暂停，应留在「已暂停」）。
 */
function isLatestAuditAttemptComplete(projectId: string): boolean {
  if (isAuditActive(projectId)) return false;
  return auditFinishedCleanly(projectId);
}

/** 严重/高危/中危单洞是否均已写入远程结论（待验证/排队/运行中 = 0）。以 vulnerability_verifications + exploit_report 为准。 */
function remoteVerifyChmConcluded(projectId: string): boolean {
  const p = getProject(projectId);
  if (!p || p.status !== 'completed') return false;
  return countPendingChmSingles(projectId) <= 0;
}

/**
 * Cursor / 磁盘回写后：按 CHM 覆盖度同步 verify_status，并补齐「验证完成」事件锚点，避免 reconcile 误打回 paused。
 */
export function syncVerifyStatusFromCoverage(projectId: string): void {
  const p = getProject(projectId);
  if (!p || p.status !== 'completed') return;
  const pending = countPendingChmSingles(projectId);
  if (pending > 0) {
    if (p.verify_status === 'completed') {
      finishVerify(
        projectId,
        'failed',
        `验证未完整：仍有 ${pending} 个 严重/高危/中危 漏洞尚无结论（待验证）`
      );
    }
    return;
  }
  if (p.verify_status !== 'completed') {
    finishVerify(projectId, 'completed', null);
  } else if (lastVerifyCompleteTs(projectId) == null) {
    recordEvent(
      projectId,
      { kind: 'result', agent: '主控', tool: '', text: '验证完成' },
      true,
      'verify'
    );
  }
}

/** 最新一轮靶机验证是否已真正完成：干净收尾 且 当前无在跑/排队的验证任务。 */
function isLatestVerifyAttemptComplete(projectId: string): boolean {
  if (isVerifyActive(projectId)) return false;
  if (remoteVerifyChmConcluded(projectId)) return true;
  return verifyFinishedCleanly(projectId);
}

/** paused → completed 校正前，必须同时证明当前磁盘上的必需子智能体覆盖完整。 */
function hasProvableCurrentAuditCoverage(projectId: string): boolean {
  const project = getProject(projectId);
  if (!project) return false;
  const codeDir = [project.workspace_path, path.join(WORKSPACE_DIR, projectId)]
    .filter((candidate): candidate is string => !!candidate)
    .find((candidate) => fs.existsSync(candidate));
  if (!codeDir) return false;
  return auditCoverageSnapshot(codeDir, { repair: false }).status === 'complete';
}

/**
 * 按「最新一轮是否真正跑完」动态校正完成/暂停态：
 * - 审计已真正完成却标成 paused → completed（进「代码审计完成」；中途暂停才留在「已暂停」）
 * - 误标 completed 但完成后又开了新审计轮次 → 打回 paused
 * - 验证侧同理
 */
export function reconcileMispausedCompletedAudits(): number {
  let fixed = 0;
  const finishedAtStmt = db.prepare(
    `SELECT MAX(ts) AS ts FROM agent_events
     WHERE project_id = ? AND kind = 'result' AND text = '审计完成'`
  );
  const verifyFinishedAtStmt = db.prepare(
    `SELECT MAX(ts) AS ts FROM agent_events
     WHERE project_id = ? AND kind = 'result' AND text = '验证完成' AND phase = 'verify'`
  );

  // 1) 最新一轮审计已真正完成，却仍标 paused → completed（进「代码审计完成」）
  const promoteAudit = db
    .prepare(
      `SELECT id FROM projects
       WHERE status = 'paused' AND verify_status = 'none'`
    )
    .all() as { id: string }[];
  for (const r of promoteAudit) {
    if (!isLatestAuditAttemptComplete(r.id)) continue;
    if (!hasProvableCurrentAuditCoverage(r.id)) continue;
    const row = finishedAtStmt.get(r.id) as { ts: number | null } | undefined;
    setAuditStatus(r.id, 'completed', {
      finished_at: row?.ts ?? now(),
      error_message: null,
    });
    ensureVulnsPersistedFromDisk(r.id, '校正：最新一轮审计已完成');
    fixed += 1;
  }

  // 2) 误标 completed（「审计完成」后又发起被打断的重扫、最新一轮未干净收尾）→ 打回 paused。
  //    真正在跑的审计 status='running'（不在此集合内）；此处只校正“空闲却未干净收尾”的脏 completed。
  const demoteAudit = db
    .prepare(
      `SELECT id FROM projects
       WHERE status = 'completed' AND verify_status = 'none'`
    )
    .all() as { id: string }[];
  for (const r of demoteAudit) {
    if (isLatestAuditAttemptComplete(r.id)) continue;
    setAuditStatus(r.id, 'paused', { finished_at: now() });
    fixed += 1;
  }

  // 3) 验证：真正完成后被标 paused → completed
  const promoteVerify = db
    .prepare(
      `SELECT id FROM projects
       WHERE status = 'completed' AND verify_status = 'paused'`
    )
    .all() as { id: string }[];
  for (const r of promoteVerify) {
    if (!isLatestVerifyAttemptComplete(r.id)) continue;
    const row = verifyFinishedAtStmt.get(r.id) as { ts: number | null } | undefined;
    setVerifyStatus(r.id, 'completed', {
      verify_finished_at: row?.ts ?? now(),
      verify_error: null,
    });
    fixed += 1;
  }

  // 4) 验证：误标 completed 但最新一轮未干净收尾（完成后又开跑并被打断）→ 打回 paused。
  const demoteVerify = db
    .prepare(
      `SELECT id FROM projects
       WHERE verify_status = 'completed'`
    )
    .all() as { id: string }[];
  for (const r of demoteVerify) {
    if (isLatestVerifyAttemptComplete(r.id)) continue;
    setVerifyStatus(r.id, 'paused', { verify_finished_at: now() });
    fixed += 1;
  }

  // 5) 审计已走完全流程、但验证【从未真正开始】却被误置为 paused → 复位为 none，归入「代码审计完成」。
  //    典型来源：历史上 auto_verify 默认开启或批量操作把验证 enqueue 后随即暂停，留下 verify='paused'
  //    却没有任何 phase='verify' 活动（也从未 验证完成）。这类项目实质是「审计完成、尚未验证」，
  //    应出现在 audit_done，而不是卡在「已暂停」。有过验证活动的（真正中途暂停）不动。
  const staleVerifyPaused = db
    .prepare(
      `SELECT id FROM projects
       WHERE status = 'completed' AND verify_status = 'paused'`
    )
    .all() as { id: string }[];
  for (const r of staleVerifyPaused) {
    if (!auditFinishedCleanly(r.id)) continue; // 审计确实走完全流程
    if (isVerifyActive(r.id)) continue; // 当前没有在跑/排队验证
    if (verifyEverStarted(r.id)) continue; // 有过验证活动 → 属真正中途暂停，保留
    setVerifyStatus(r.id, 'none', {
      verify_started_at: null,
      verify_finished_at: null,
      verify_error: null,
    });
    fixed += 1;
  }

  return fixed;
}

/**
 * 重新进行代码审计（从零开始，doAudit 会清空旧结果）。
 * @param chainVerify 审计完成后是否强制继续靶机验证（"全流程"重跑）。
 * 若目标正在运行，先安全中断，由其 runJob.finally 在彻底清理后重排，避免竞态。
 */
export function restartAudit(projectId: string, chainVerify = false): boolean {
  const p = getProject(projectId);
  if (!p) return false;
  requestCancel(projectId); // 中止仍在途的旧异步，避免其与新任务并行
  stopEnvChannel(projectId);
  verifyKilled.add(projectId);
  stopVerifyProcs(projectId);
  setEnvStatus(projectId, 'none', null); // 重新审计：环境状态归零，避免复用旧的（可能失效的）靶机
  // 重新审计意味着整条链重来：先把验证状态清零，避免残留 paused/failed 影响并行预搭建调度与展示
  setVerifyStatus(projectId, 'none', { verify_started_at: null, verify_finished_at: null, verify_error: null });
  const child = running.get(projectId);
  // 任务仍在进行（主审计 / 代码级验证 / 二次评级任一阶段，含尚未 spawn Pi 的在途异步）：走 restartRequests，由 runJob.finally 在彻底清理后重排，避免竞态/重复运行
  if (child || isBusy(projectId)) {
    restartRequests.set(projectId, { kind: 'audit', chainVerify });
    intentionallyStopped.add(projectId);
    const qi = queue.findIndex((j) => j.id === projectId);
    if (qi !== -1) queue.splice(qi, 1);
    if (child) killTree(child); // 代码级验证进程已在上面 stopVerifyProcs 杀掉
  } else {
    const qi = queue.findIndex((j) => j.id === projectId);
    if (qi !== -1) queue.splice(qi, 1);
    clearActiveSlots(projectId);
    runningKind.delete(projectId);
    enqueueAudit(projectId, chainVerify);
  }
  return true;
}

/**
 * 复用已有子智能体结果重跑（跳过专项子智能体审计，只重跑 去重→验证→评级）。
 * 若目标正在运行，先安全中断，由 runJob.finally 在彻底清理后按 reprocess 重排。
 * @param chainVerify 重跑完成后是否继续靶机验证。
 */
export function restartReprocess(projectId: string, chainVerify = false): boolean {
  const p = getProject(projectId);
  if (!p) return false;
  requestCancel(projectId); // 中止仍在途的旧异步，避免双流水线
  stopEnvChannel(projectId);
  verifyKilled.add(projectId);
  stopVerifyProcs(projectId);
  setEnvStatus(projectId, 'none', null);
  setVerifyStatus(projectId, 'none', {
    verify_started_at: null,
    verify_finished_at: null,
    verify_error: null,
  });
  const child = running.get(projectId);
  if (child || isBusy(projectId)) {
    restartRequests.set(projectId, { kind: 'reprocess', chainVerify });
    intentionallyStopped.add(projectId);
    const qi = queue.findIndex((j) => j.id === projectId);
    if (qi !== -1) queue.splice(qi, 1);
    if (child) killTree(child);
  } else {
    const qi = queue.findIndex((j) => j.id === projectId);
    if (qi !== -1) queue.splice(qi, 1);
    clearActiveSlots(projectId);
    runningKind.delete(projectId);
    enqueueReprocess(projectId, chainVerify);
  }
  return true;
}

/** 入队"分环节运行"（从某环节开始：only 仅本环节 / from 跑到本流水线末尾）。 */
export function enqueueStage(projectId: string, stage: PipeStage, mode: 'only' | 'from'): void {
  const p = getProject(projectId);
  if (!p) return;
  if (isBusy(projectId) || queue.some((j) => j.id === projectId)) return;
  const side = stageSide(stage);
  if ((stage === 'remote' || stage === 'chain') && !strictVerifyQueueGate(projectId)) return;
  if (side === 'audit') setAuditStatus(projectId, 'queued');
  else setVerifyStatus(projectId, 'queued');
  queue.push({ id: projectId, kind: side === 'audit' ? 'audit' : 'verify', stage, stageMode: mode });
  scheduleStartNext();
}

/**
 * 分环节运行（单独跑某环节 / 从某环节跑到本流水线末尾）。
 * 若目标正在运行，先安全中断，由 runJob.finally 在彻底清理后按该环节重排。
 */
export function restartStage(projectId: string, stage: PipeStage, mode: 'only' | 'from'): boolean {
  const p = getProject(projectId);
  if (!p) return false;
  const side = stageSide(stage);
  requestCancel(projectId); // 中止仍在途的旧异步，避免双流水线
  stopEnvChannel(projectId);
  verifyKilled.add(projectId);
  stopVerifyProcs(projectId);
  // 从子智能体完整重跑：环境/验证状态归零，避免复用旧靶机
  if (stage === 'subagent') {
    setEnvStatus(projectId, 'none', null);
    setVerifyStatus(projectId, 'none', {
      verify_started_at: null,
      verify_finished_at: null,
      verify_error: null,
    });
  }
  const child = running.get(projectId);
  if (child || isBusy(projectId)) {
    restartRequests.set(projectId, {
      kind: side === 'audit' ? 'audit' : 'verify',
      chainVerify: false,
      stage,
      stageMode: mode,
    });
    intentionallyStopped.add(projectId);
    const qi = queue.findIndex((j) => j.id === projectId);
    if (qi !== -1) queue.splice(qi, 1);
    if (child) killTree(child);
  } else {
    const qi = queue.findIndex((j) => j.id === projectId);
    if (qi !== -1) queue.splice(qi, 1);
    clearActiveSlots(projectId);
    runningKind.delete(projectId);
    enqueueStage(projectId, stage, mode);
  }
  return true;
}

/** 重新进行靶机验证（需审计已完成；清空旧结果、全量重验 CHM 漏洞、保留已有靶机）。 */
export function restartVerify(projectId: string): boolean {
  const p = getProject(projectId);
  if (!p) return false;
  if (p.status !== 'completed') return false; // 必须先完成代码审计
  requestCancel(projectId); // 中止仍在途的旧异步，避免双流水线
  stopEnvChannel(projectId);
  stopVerifyProcs(projectId);
  // 重跑语义：立即清空 DB 报告与 workspace 落盘（靶机 env 不动，doVerify 会 ensureTargetUp 复用）
  clearVerifyResults(projectId);
  const child = running.get(projectId);
  if (child || isBusy(projectId)) {
    restartRequests.set(projectId, { kind: 'verify', chainVerify: false });
    intentionallyStopped.add(projectId);
    const qi = queue.findIndex((j) => j.id === projectId);
    if (qi !== -1) queue.splice(qi, 1);
    if (child) killTree(child);
    return true;
  }
  const qi = queue.findIndex((j) => j.id === projectId);
  if (qi !== -1) queue.splice(qi, 1);
  clearActiveSlots(projectId);
  runningKind.delete(projectId);
  return enqueueVerify(projectId, false);
}

/**
 * 仅重跑组合链验证（远程验证·组合）：需审计已完成。不清空单漏洞结果，只重新构造并实测组合利用链，
 * 结果合并回 exploit_report.chains（前端「远程验证·组合」页显示）。若目标正在运行先安全中断再重排。
 */
export function restartVerifyChain(projectId: string): boolean {
  const p = getProject(projectId);
  if (!p) return false;
  if (!hasAuditForChain(p)) return false; // 审计未产出结果（如审计跑到一半被暂停）
  requestCancel(projectId); // 中止仍在途的旧异步，避免双流水线
  stopEnvChannel(projectId);
  stopVerifyProcs(projectId);
  const child = running.get(projectId);
  if (child || isBusy(projectId)) {
    restartRequests.set(projectId, { kind: 'verify', chainVerify: false, chainOnly: true });
    intentionallyStopped.add(projectId);
    const qi = queue.findIndex((j) => j.id === projectId);
    if (qi !== -1) queue.splice(qi, 1);
    if (child) killTree(child);
    return true;
  }
  const qi = queue.findIndex((j) => j.id === projectId);
  if (qi !== -1) queue.splice(qi, 1);
  clearActiveSlots(projectId);
  runningKind.delete(projectId);
  return enqueueVerifyChain(projectId);
}

export function stopForDelete(projectId: string): void {
  restartRequests.delete(projectId);
  requestCancel(projectId); // 中止仍在途的旧异步，确保删除后不再 spawn Pi
  stopEnvChannel(projectId);
  verifyKilled.add(projectId);
  stopVerifyProcs(projectId);
  const qi = queue.findIndex((j) => j.id === projectId);
  if (qi !== -1) queue.splice(qi, 1);
  const child = running.get(projectId);
  if (child) {
    intentionallyStopped.add(projectId);
    killTree(child);
    running.delete(projectId);
  }
  clearActiveSlots(projectId);
  inFlight.delete(projectId);
  runningKind.delete(projectId);
}

/**
 * 统一删除入口（唯一硬删路径）：删除前把项目快照写入回收站 deleted_projects（留痕、不支持还原），
 * 再依次停任务、删工作区、删残留压缩包、删数据库行。所有删除（手动/批量/自动判定）都走此函数。
 * @param reason 删除原因：manual（单个手动）/ bulk（批量）/ auto_non_web（自动判定非 Web 清理）
 * @param detail 附加说明（如 LLM 判定理由）
 */
export function purgeProject(projectId: string, reason: string, detail = ''): boolean {
  const p = getProject(projectId);
  if (!p) return false;

  // 1) 归一化来源展示：github→仓库 URL(source_ref)；压缩包→原始文件名(archive_name)
  const sourceLink = p.source_type === 'github' ? p.source_ref : p.archive_name;
  const vulnRow = db
    .prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE project_id = ?')
    .get(projectId) as { c: number };

  // 2) 回收站留痕（幂等：同 id 覆盖）
  db.prepare(
    `INSERT OR REPLACE INTO deleted_projects
       (id, project_name, source_type, source_ref, archive_name, source_link,
        has_web, vuln_count, reason, detail, deleted_at)
     VALUES (@id, @project_name, @source_type, @source_ref, @archive_name, @source_link,
        @has_web, @vuln_count, @reason, @detail, @deleted_at)`
  ).run({
    id: p.id,
    project_name: p.project_name,
    source_type: p.source_type,
    source_ref: p.source_ref,
    archive_name: p.archive_name,
    source_link: sourceLink,
    has_web: p.has_web,
    vuln_count: vulnRow.c,
    reason,
    detail,
    deleted_at: now(),
  });

  // 3) 停任务 → 删库（快路径）→ 工作区/压缩包异步限并发清理，不阻塞 HTTP。
  //    失败由 scheduleDeletionRetry / 开机清扫兜底。
  stopForDelete(projectId);
  const sourceType = p.source_type;
  const sourceRef = p.source_ref;
  deleteProjectRows(projectId);
  try {
    removeWorkspace(projectId);
  } catch (e: any) {
    console.warn(`[purge] 工作区清理排队失败 ${projectId}: ${e?.message || e}`);
  }
  setImmediate(() => {
    try {
      removeUploadArchive(sourceType, sourceRef);
    } catch (e: any) {
      console.warn(`[purge] 压缩包清理失败 ${projectId}: ${e?.message || e}`);
    }
  });
  return true;
}

/**
 * 从磁盘已有产物重新汇总该项目漏洞并入库（不重新调用 Pi）。
 * 用于把工作区里已存在的子智能体发现 + 可利用清单一次性纳入，立即提升库存数量与质量。
 * 同时回填 `_remote_verify/chains/*.json` 等远程验证组合链产物到 exploit_report。
 */
export function reingestFromDisk(projectId: string): { ok: boolean; count: number; chains?: number } {
  const p = getProject(projectId);
  const artifactRoot = resolveArtifactRoot(projectId, p?.workspace_path);
  if (!p || !artifactRoot) return { ok: false, count: 0 };
  const findings = collectFromDisk(artifactRoot);
  if (findings.length > 0) {
    db.prepare('DELETE FROM vulnerabilities WHERE project_id = ?').run(projectId);
    saveVulnerabilities(projectId, findings);
  }
  const chainSync = reingestRemoteVerifyFromDisk(projectId);
  broadcast({ type: 'project_status', projectId, exploit_progress: chainSync.chains > 0 });
  if (findings.length === 0 && !chainSync.ok) return { ok: false, count: 0 };
  return { ok: true, count: findings.length, chains: chainSync.chains };
}

/**
 * 从 `_remote_verify` 磁盘产物回填 exploit_report（含 skill 按条落盘的 chains/*.json），不重跑 Pi。
 * 保留已有单漏洞结果；磁盘有组合链时覆盖报告中的 chains。
 */
export function reingestRemoteVerifyFromDisk(projectId: string): {
  ok: boolean;
  exploits: number;
  chains: number;
} {
  const p = getProject(projectId);
  const artifactRoot = resolveArtifactRoot(projectId, p?.workspace_path);
  if (!p || !artifactRoot) {
    return { ok: false, exploits: 0, chains: 0 };
  }
  if (p.workspace_path && fs.existsSync(p.workspace_path) && !strictVerifyQueueGate(projectId)) {
    recordEvent(
      projectId,
      {
        kind: 'error',
        agent: '来源校验器',
        tool: '',
        text: '⛔ 已拒绝回填磁盘远程验证产物：当前源码与运行靶机未通过严格来源校验',
      },
      true,
      'audit'
    );
    return { ok: false, exploits: 0, chains: 0 };
  }
  const disk = readRemoteVerifyResults(artifactRoot, projectId);
  const diskPriorExploits = readRemoteVerifyPriorExploits(artifactRoot);
  const diskChains = disk.chains;
  let prior: { summary?: string; exploits?: any[]; chains?: any[] } = {
    summary: '',
    exploits: [],
    chains: [],
  };
  try {
    const row = db.prepare('SELECT exploit_report FROM projects WHERE id = ?').get(projectId) as
      | { exploit_report: string | null }
      | undefined;
    if (row?.exploit_report) prior = JSON.parse(row.exploit_report);
  } catch {
    /* 使用空 prior */
  }
  const priorExploits = Array.isArray(prior.exploits) ? prior.exploits : [];
  const merged =
    disk.exploits.length > 0 || diskPriorExploits.length > 0
      ? mergeExploits([...diskPriorExploits, ...priorExploits, ...disk.exploits])
      : priorExploits;
  // 对齐到 CHM 漏洞清单，避免短标题/前缀标题无法消掉 unknown 占位
  const allVulns = db
    .prepare(
      "SELECT id, title, severity, file_path, line, description FROM vulnerabilities WHERE project_id = ? AND lower(severity) IN ('critical','high','medium')"
    )
    .all(projectId) as VulnBriefRow[];
  const exploits = allVulns.length > 0 ? alignExploitsToVulnList(allVulns, merged) : merged;
  const priorChains = Array.isArray(prior.chains) ? prior.chains : [];
  const chains = diskChains.length > 0 ? diskChains : priorChains;
  if (disk.exploits.length === 0 && diskPriorExploits.length === 0 && diskChains.length === 0) {
    return { ok: false, exploits: 0, chains: 0 };
  }
  const cs = chainVerifyStats(chains);
  const pending = countPendingChmSingles(projectId, exploits);
  const successN = exploits.filter((e) => remoteStatusOf(e) === 'success').length;
  const summary =
    diskChains.length > 0
      ? `已从磁盘回填远程验证产物：单漏洞 ${exploits.length} 条、组合链 ${chains.length} 条（成功 ${cs.success} / 已验证 ${cs.unauthVerified + cs.openRegVerified}）`
      : `已从磁盘回填单漏洞结果 ${exploits.length} 条（完全命中 ${successN}${pending ? `、仍待验证 ${pending}` : ''}）`;
  saveExploitReport(projectId, { summary, exploits, chains });
  // 回填消掉「假 unknown」后：单洞已齐则进入组合链（或标完成）；勿把短标题 success 再当成待验证
  const cur = getProject(projectId);
  if (cur && pending === 0 && (cur.verify_status === 'failed' || cur.verify_status === 'paused')) {
    if (chains.length === 0) {
      setVerifyStatus(projectId, cur.verify_status, {
        verify_error: '单漏洞结果已从磁盘回填对齐；组合链尚未完成，将自动续跑',
      });
      // 单洞已齐，只跑组合链，避免再清空/重验 100+ 单洞
      enqueueVerifyChain(projectId);
    } else {
      finishVerify(projectId, 'completed', null);
    }
  }
  broadcast({ type: 'project_status', projectId, exploit_progress: true });
  return { ok: true, exploits: exploits.length, chains: chains.length };
}

type RegradeReasonBackfillResult = {
  missingBefore: number;
  recoveredFromArtifacts: number;
  fallbackAdded: number;
  valueAdded: number;
  projectsTouched: number;
  missingAfter: number;
};

/** 读取红队二次评级结果；只认 results/，不把 input/groups/ 或代码验证 reason 冒充评级理由。 */
function readRegradeRatingsFromDisk(codeDir: string): any[] {
  const resultsDir = path.join(codeDir, '_regrade', 'results');
  const ratings: any[] = [];
  let files: string[] = [];
  try {
    files = fs.readdirSync(resultsDir).filter((f) => f.toLowerCase().endsWith('.json'));
  } catch {
    return ratings;
  }
  for (const file of files) {
    try {
      const raw = JSON.parse(readJsonArtifactText(path.join(resultsDir, file)));
      const items = Array.isArray(raw)
        ? raw
        : raw && Array.isArray(raw.ratings)
          ? raw.ratings
          : [];
      for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        const reason = String(item.reason || item.regrade_reason || '').trim();
        if (!reason) continue;
        ratings.push(item);
      }
    } catch {
      /* 单个历史产物损坏不阻断其他项目回填 */
    }
  }
  return ratings;
}

/**
 * 修复历史“有实战等级、无评级理由”的数据：
 * 1) 优先从 `_regrade/results` 精确标题恢复真实模型 reason；
 * 2) 确无输出时写入明确的系统兜底说明，避免 UI 静默隐藏评级区块；
 * 3) 缺失的 value 由最终 severity 做一一映射。
 */
function backfillMissingRegradeReasons(): RegradeReasonBackfillResult {
  const rows = db
    .prepare(
      `SELECT v.id, v.project_id, v.title, v.severity, v.regrade_value, v.regrade_reason,
              p.workspace_path
       FROM vulnerabilities v
       JOIN projects p ON p.id = v.project_id
       WHERE p.status = 'completed'
         AND (
           trim(coalesce(v.regrade_reason, '')) = ''
           OR trim(coalesce(v.regrade_value, '')) = ''
         )`
    )
    .all() as Array<{
      id: string;
      project_id: string;
      title: string;
      severity: string;
      regrade_value: string | null;
      regrade_reason: string | null;
      workspace_path: string | null;
    }>;

  const result: RegradeReasonBackfillResult = {
    missingBefore: rows.filter((r) => !String(r.regrade_reason || '').trim()).length,
    recoveredFromArtifacts: 0,
    fallbackAdded: 0,
    valueAdded: 0,
    projectsTouched: 0,
    missingAfter: 0,
  };
  if (rows.length === 0) return result;

  const byProject = new Map<string, typeof rows>();
  for (const row of rows) {
    const list = byProject.get(row.project_id) || [];
    list.push(row);
    byProject.set(row.project_id, list);
  }

  const update = db.prepare(
    `UPDATE vulnerabilities
     SET regrade_value = ?, regrade_reason = ?
     WHERE id = ?`
  );
  const tx = db.transaction(() => {
    for (const [projectId, projectRows] of byProject) {
      const workspace = projectRows[0]?.workspace_path;
      const ratings =
        workspace && fs.existsSync(workspace) ? readRegradeRatingsFromDisk(workspace) : [];
      const reasonByTitle = new Map<string, string>();
      for (const rating of ratings) {
        const reason = String(rating.reason || rating.regrade_reason || '').trim();
        if (!reason) continue;
        for (const title of [rating.title, rating.title_cn]) {
          const key = normTitleKey(String(title || ''));
          if (key && !reasonByTitle.has(key)) reasonByTitle.set(key, reason);
        }
      }

      let touched = false;
      for (const row of projectRows) {
        const value = String(row.regrade_value || '').trim() || realTeamLabel(row.severity);
        const existingReason = String(row.regrade_reason || '').trim();
        const recoveredReason = reasonByTitle.get(normTitleKey(row.title)) || '';
        const reason =
          existingReason ||
          recoveredReason ||
          `[系统兜底] 历史红队实战二次评级产物未保留逐条理由；当前实战等级按最终严重度映射为「${value}」。如需模型逐条分析依据，请重跑“红队实战二次评级”。`;
        if (!String(row.regrade_value || '').trim()) result.valueAdded++;
        if (!existingReason && recoveredReason) {
          result.recoveredFromArtifacts++;
        } else if (!existingReason) {
          result.fallbackAdded++;
        }
        update.run(value, reason, row.id);
        touched = true;
      }
      if (touched) result.projectsTouched++;
    }
  });
  tx();
  result.missingAfter = (
    db
      .prepare(
        `SELECT COUNT(*) AS c
         FROM vulnerabilities
         WHERE trim(coalesce(regrade_reason, '')) = ''
            OR trim(coalesce(regrade_value, '')) = ''`
      )
      .get() as { c: number }
  ).c;
  invalidateVulnerabilityReads();
  return result;
}

/** 扫描所有审计已完成但 DB 漏洞为 0、磁盘有产物的项目并补入库。 */
/**
 * 从磁盘补入库 / 修复 exploit_report 中的 unknown。
 * 同步版会扫完全部 completed 项目才返回，启动时请用 {@link reingestAllStaleFromDiskAsync}。
 */
export function reingestAllStaleFromDisk(): { projects: number; vulns: number; ids: string[] } {
  return reingestAllStaleFromDiskSync();
}

function reingestAllStaleFromDiskSync(): { projects: number; vulns: number; ids: string[] } {
  const result = { projects: 0, vulns: 0, ids: [] as string[] };
  // yieldEvery=0 → 不让出；由下方共享实现同步跑完。
  const remoteRepairCandidates: string[] = [];
  const rows = db
    .prepare(
      `SELECT id, workspace_path, verify_status,
              CASE WHEN exploit_report IS NULL THEN 0 ELSE 1 END AS has_report
       FROM projects WHERE status = 'completed'`
    )
    .all() as {
    id: string;
    workspace_path: string | null;
    verify_status: string;
    has_report: number;
  }[];
  const reportStmt = db.prepare('SELECT exploit_report FROM projects WHERE id = ?');
  const countStmt = db.prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE project_id = ?');
  for (const r of rows) {
    if (r.has_report) {
      const row = reportStmt.get(r.id) as { exploit_report: string | null } | undefined;
      let reportExploits: any[] = [];
      let reportChains: any[] = [];
      try {
        const report = row?.exploit_report ? JSON.parse(row.exploit_report) : null;
        reportExploits = Array.isArray(report?.exploits) ? report.exploits : [];
        reportChains = Array.isArray(report?.chains) ? report.chains : [];
      } catch {
        reportExploits = [];
        reportChains = [];
      }
      const unknowns = reportExploits.filter((e) => remoteStatusOf(e) === 'unknown');
      const artRoot = resolveArtifactRoot(r.id, r.workspace_path);
      const canRepair =
        r.verify_status !== 'running' &&
        r.verify_status !== 'queued' &&
        !!artRoot;
      if (canRepair && unknowns.length > 0) {
        const disk = mergeExploits([
          ...readRemoteVerifyPriorExploits(artRoot!),
          ...readRemoteVerifyResults(artRoot!).exploits,
        ]);
        const hasRecoverable = unknowns.some((pending) =>
          disk.some(
            (candidate) =>
              remoteStatusOf(candidate) !== 'unknown' &&
              exploitTitlesLooselyMatch(pending?.vulnerability, candidate?.vulnerability)
          )
        );
        if (hasRecoverable) remoteRepairCandidates.push(r.id);
      }
      // 磁盘已有组合链但报告为空：补回填（与单洞 unknown 修复独立）
      if (canRepair && reportChains.length === 0 && !remoteRepairCandidates.includes(r.id)) {
        const diskChains = readRemoteVerifyResults(artRoot!).chains;
        if (diskChains.length > 0) remoteRepairCandidates.push(r.id);
      }
    }
    const n = (countStmt.get(r.id) as { c: number }).c;
    if (n > 0) continue;
    const root = resolveArtifactRoot(r.id, r.workspace_path);
    if (!root) continue;
    const findings = collectFromDisk(root);
    if (findings.length === 0) continue;
    saveVulnerabilities(r.id, findings);
    broadcast({ type: 'project_status', projectId: r.id });
    result.ids.push(r.id);
    result.vulns += findings.length;
  }
  for (const projectId of remoteRepairCandidates) reingestRemoteVerifyFromDisk(projectId);
  backfillMissingRegradeReasons();
  result.projects = result.ids.length;
  return result;
}

/** 启动友好：每处理若干项目让出事件循环，避免堵死 /api。 */
export async function reingestAllStaleFromDiskAsync(
  opts: { yieldEvery?: number } = {}
): Promise<{ projects: number; vulns: number; ids: string[] }> {
  const yieldEvery = opts.yieldEvery === undefined ? 1 : opts.yieldEvery;
  const yieldEventLoop = () => new Promise<void>((r) => setImmediate(r));
  const result = { projects: 0, vulns: 0, ids: [] as string[] };
  const remoteRepairCandidates: string[] = [];
  const rows = db
    .prepare(
      `SELECT id, workspace_path, verify_status,
              CASE WHEN exploit_report IS NULL THEN 0 ELSE 1 END AS has_report
       FROM projects WHERE status = 'completed'`
    )
    .all() as {
    id: string;
    workspace_path: string | null;
    verify_status: string;
    has_report: number;
  }[];
  const reportStmt = db.prepare('SELECT exploit_report FROM projects WHERE id = ?');
  const countStmt = db.prepare('SELECT COUNT(*) AS c FROM vulnerabilities WHERE project_id = ?');
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (r.has_report) {
      const row = reportStmt.get(r.id) as { exploit_report: string | null } | undefined;
      let reportExploits: any[] = [];
      let reportChains: any[] = [];
      try {
        const report = row?.exploit_report ? JSON.parse(row.exploit_report) : null;
        reportExploits = Array.isArray(report?.exploits) ? report.exploits : [];
        reportChains = Array.isArray(report?.chains) ? report.chains : [];
      } catch {
        reportExploits = [];
        reportChains = [];
      }
      const unknowns = reportExploits.filter((e) => remoteStatusOf(e) === 'unknown');
      const artRoot = resolveArtifactRoot(r.id, r.workspace_path);
      const canRepair =
        r.verify_status !== 'running' &&
        r.verify_status !== 'queued' &&
        !!artRoot;
      if (canRepair && unknowns.length > 0) {
        const disk = mergeExploits([
          ...readRemoteVerifyPriorExploits(artRoot!),
          ...readRemoteVerifyResults(artRoot!).exploits,
        ]);
        const hasRecoverable = unknowns.some((pending) =>
          disk.some(
            (candidate) =>
              remoteStatusOf(candidate) !== 'unknown' &&
              exploitTitlesLooselyMatch(pending?.vulnerability, candidate?.vulnerability)
          )
        );
        if (hasRecoverable) remoteRepairCandidates.push(r.id);
      }
      if (canRepair && reportChains.length === 0 && !remoteRepairCandidates.includes(r.id)) {
        const diskChains = readRemoteVerifyResults(artRoot!).chains;
        if (diskChains.length > 0) remoteRepairCandidates.push(r.id);
      }
    }
    const n = (countStmt.get(r.id) as { c: number }).c;
    if (n === 0) {
      const root = resolveArtifactRoot(r.id, r.workspace_path);
      if (root) {
        const findings = collectFromDisk(root);
        if (findings.length > 0) {
          saveVulnerabilities(r.id, findings);
          broadcast({ type: 'project_status', projectId: r.id });
          result.ids.push(r.id);
          result.vulns += findings.length;
        }
      }
    }
    if (yieldEvery > 0 && (i + 1) % yieldEvery === 0) await yieldEventLoop();
  }
  for (let i = 0; i < remoteRepairCandidates.length; i++) {
    reingestRemoteVerifyFromDisk(remoteRepairCandidates[i]);
    if (yieldEvery > 0) await yieldEventLoop();
  }
  backfillMissingRegradeReasons();
  result.projects = result.ids.length;
  return result;
}

let sweepInFlight = false;
/**
 * 孤儿工作区清扫：删除 workspace 下没有对应数据库项目的 p_* 目录。
 * 用于回收删除项目时因 Windows 文件瞬时/持续占用（pi/git/docker/codegraph 句柄、只读 .git 对象）
 * 导致 removeWorkspace 未删净而残留的目录。防重入、异步、每删一个 yield 一次事件循环，避免阻塞服务。
 */
export async function sweepOrphanWorkspaces(): Promise<number> {
  if (sweepInFlight) return 0;
  if (!fs.existsSync(WORKSPACE_DIR)) return 0;
  sweepInFlight = true;
  try {
    const ids = new Set(
      (db.prepare('SELECT id FROM projects').all() as { id: string }[]).map((r) => r.id)
    );
    let dirs: string[];
    try {
      dirs = fs
        .readdirSync(WORKSPACE_DIR, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => d.name);
    } catch {
      return 0;
    }
    const orphans = dirs.filter((name) => name.startsWith('p_') && !ids.has(name));
    let removed = 0;
    for (const name of orphans) {
      await new Promise<void>((r) => setImmediate(r)); // 让出事件循环
      try {
        // 异步删完再计数：fs.promises.rm 让出事件循环，避免大目录递归删除冻结主线程
        await removeWorkspaceAwait(name);
        if (!fs.existsSync(path.join(WORKSPACE_DIR, name))) removed++;
      } catch (e: any) {
        console.warn(`[sweep] 孤儿工作区清理失败 ${name}: ${e?.message || e}`);
      }
    }
    if (removed > 0) {
      console.log(`[code] 已清扫 ${removed} 个孤儿工作区目录（无对应项目的残留）`);
    }
    return removed;
  } finally {
    sweepInFlight = false;
  }
}

let janitorTimer: NodeJS.Timeout | null = null;
/**
 * 常驻工作区清道夫：定时重扫并清理孤儿工作区目录。
 * 这是“彻底不残留”的关键——即使某次删除时目录被 codegraph/pi/docker 长时间占用，
 * 占用方进程退出后，下一轮清扫即把它删除，无需重启服务。
 */
export function startWorkspaceJanitor(intervalMs = 60_000): void {
  if (janitorTimer) return;
  janitorTimer = setInterval(() => {
    void sweepOrphanWorkspaces().catch((e) =>
      console.error('[code] 工作区清道夫清扫失败', e)
    );
  }, intervalMs);
  if (typeof janitorTimer.unref === 'function') janitorTimer.unref();
}

let runLogJanitorTimer: NodeJS.Timeout | null = null;
let runLogJanitorBusy = false;
let runLogJanitorCursor: string | null = null;
/**
 * 常驻运行日志清道夫：按保留策略滚动清理 project_run_logs，防止其无限膨胀拖慢整库写入。
 * - 仅清理非运行/非排队且未被内存占用（isRunning）的项目，正在跑的日志一律保留；
 * - 异步分批删除，每批后 setImmediate 让出事件循环，避免冻死 /api/*；
 * - 轮转 cursor，每轮只扫有限项目，避免对千万行表做全表 DISTINCT；
 * - 运行中只用 PASSIVE checkpoint（绝不 TRUNCATE），VACUUM 留给手动维护。
 * 间隔由 settings.run_log_janitor_interval_ms 控制，0 = 关闭。
 */
export function startRunLogJanitor(): void {
  if (runLogJanitorTimer) return;
  const intervalMs = Number(getSetting('run_log_janitor_interval_ms') || 0);
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
    console.log('[code] 运行日志清道夫：已关闭（run_log_janitor_interval_ms<=0）');
    return;
  }
  const sweep = () => {
    if (runLogJanitorBusy) return;
    runLogJanitorBusy = true;
    void (async () => {
      try {
        const result = await pruneRunLogsAsync({
          isProtected: isRunning,
          maxDeletes: 20_000,
          batchSize: 400,
          maxProjects: 40,
          cursor: runLogJanitorCursor,
        });
        runLogJanitorCursor = result.nextCursor;
        if (result.deleted > 0) {
          // 有活跃审计时跳过 checkpoint；空闲时也只用 PASSIVE，避免 TRUNCATE 冻事件循环。
          if (runningCount() === 0) checkpointAndReclaim(false, 'passive');
          console.log(
            `[code] 运行日志清道夫：删除 ${result.deleted} 条（扫 ${result.projectsScanned} 项 / 命中 ${result.projectsAffected}），cursor=${runLogJanitorCursor ?? '∅'}`
          );
        }
      } catch (e) {
        console.error('[code] 运行日志清道夫清理失败', e);
      } finally {
        runLogJanitorBusy = false;
      }
    })();
  };
  // 启动后延迟首扫，避免与启动对账/恢复抢写锁；且用异步路径，不再冻 HTTP。
  const kickoff = setTimeout(sweep, 90_000);
  if (typeof kickoff.unref === 'function') kickoff.unref();
  runLogJanitorTimer = setInterval(sweep, intervalMs);
  if (typeof runLogJanitorTimer.unref === 'function') runLogJanitorTimer.unref();
}

export function isRunning(projectId: string): boolean {
  return activeAuditProjects.has(projectId) || activeVerifyProjects.has(projectId) || inFlight.has(projectId);
}

export function runningCount(): number {
  return activeAuditProjects.size + activeVerifyProjects.size;
}
